"""Publication, root scope, and recovery tests for the Agent file reader."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from peters_mcp import agent_file_admin as admin
from peters_mcp.agent_file_policy import (
    ACTIVE_NAME, PENDING_NAME, WATERMARK_NAME, AgentFilePolicy, collect_root_records,
    credential_binding, initialize_agent_file_policy,
)
from peters_mcp.catalog import AccessError
from peters_mcp.workspaces import RepositoryRegistry

TEAM = "https://sample-team.cloudflareaccess.com"


def agent(name, *, credential=None, enabled=True):
    return {"id": name, "enabled": enabled, "issuer": TEAM, "audience": "a" * 64,
            "client_id": credential or name + ".access"}


def projects(*rows):
    return json.dumps({"projects": [{"id": name, "name": name.title(), "root": str(path), **extra}
                                   for name, path, extra in rows]}).encode()


@unittest.skipUnless(sys.platform == "darwin", "published root proofs use Darwin persistent identities")
class AgentFilePolicyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.space = Path(self.temp.name).resolve()
        self.shared = self.space / "projects-active.json"
        self.state = self.space / "policy"
        self.initial_root = self.space / "alpha"
        self.initial_root.mkdir()
        (self.initial_root / "sample.txt").write_text("Synthetic scope")
        self.second_root = self.space / "beta"
        self.second_root.mkdir()
        self.legacy = projects(("alpha", self.initial_root, {}))
        self.shared.write_bytes(self.legacy)
        self.shared.chmod(0o600)
        self.policy = initialize_agent_file_policy(self.shared, self.state)

    def publish(self, kind, proposed=None):
        proposal, approval = admin.preview(self.policy, kind, proposed=proposed)
        return admin.apply(self.policy, proposal, approval)

    def init_repository(self):
        root = self.initial_root
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

        def git(*args):
            return subprocess.run(["/usr/bin/git", "-C", str(root), "-c", "user.name=Test",
                                   "-c", "user.email=test@example.com", *args], env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)

        git("init")
        git("add", "sample.txt")
        git("commit", "-m", "fixture")
        return git

    def test_initialize_empty_and_add_agent_without_replacing_shared_file(self):
        first = self.policy.snapshot()
        self.assertFalse(first.principals)
        inode = self.shared.stat().st_ino
        codex = agent("codex")
        current = self.publish("agents", [codex])
        result = self.policy.snapshot()
        self.assertEqual(result.revision, current)
        self.assertNotEqual(result.revision, first.revision)
        self.assertEqual(result.principals, {credential_binding(codex): "codex"})
        self.assertEqual(result.roots, first.roots)
        self.assertEqual(self.shared.read_bytes(), self.legacy)
        self.assertEqual(self.shared.stat().st_ino, inode)

    def test_project_publish_is_shared_and_explicit_empty_revokes_last_project(self):
        codex, deepseek = agent("codex"), agent("deepseek")
        self.publish("agents", [codex, deepseek])
        previous = self.policy.snapshot()
        second = projects(("alpha", self.initial_root, {}), ("beta", self.second_root, {}))
        self.publish("projects", second)
        expanded = self.policy.snapshot()
        self.assertEqual(expanded.principals, previous.principals)
        self.assertEqual(self.shared.read_bytes(), second)
        self.assertEqual({row["id"] for row in self.policy.catalog_for(expanded).list_projects()["projects"]},
                         {"alpha", "beta"})
        self.publish("projects", projects())
        empty = self.policy.snapshot()
        self.assertEqual(empty.principals, previous.principals)
        self.assertEqual(self.policy.catalog_for(empty).list_projects()["projects"], [])
        with self.assertRaises(AccessError):
            self.policy.catalog_for(empty).read_file("alpha", "sample.txt")

    def test_agent_only_retires_old_assertion_even_if_readded_or_renamed(self):
        original, remaining = agent("codex"), agent("dsh")
        self.publish("agents", [original, remaining])
        authorized = self.policy.snapshot()
        self.publish("agents", [agent("codex", enabled=False), remaining])
        current = self.policy.snapshot()
        self.assertNotIn(credential_binding(original), current.principals)
        self.assertIn(credential_binding(remaining), current.principals)
        self.assertEqual(self.shared.read_bytes(), self.legacy)
        with self.assertRaises(AccessError):
            with self.policy.commit_guard(authorized.revision):
                self.fail("Old revision admitted")
        for target in (original, agent("renamed", credential=original["client_id"])):
            with self.assertRaisesRegex(AccessError, "policy"):
                admin.preview(self.policy, "agents", proposed=[remaining, target])
        rotated = agent("codex", credential="different.access")
        self.publish("agents", [rotated, remaining])
        self.assertIn(credential_binding(rotated), self.policy.snapshot().principals)

    def test_stale_preview_and_out_of_band_project_edit_fail_closed(self):
        target = projects(("beta", self.second_root, {}))
        stale, approval = admin.preview(self.policy, "projects", proposed=target)
        self.publish("agents", [agent("codex")])
        with self.assertRaises(AccessError):
            admin.apply(self.policy, stale, approval)
        self.shared.write_bytes(target)
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        proposal, approval = admin.preview(self.policy, "projects", proposed=target)
        admin.apply(self.policy, proposal, approval)
        self.assertEqual(self.policy.snapshot().projects, json.loads(target))

    def test_project_and_active_replay_cannot_rewind_watermark(self):
        active = (self.state / ACTIVE_NAME).read_bytes()
        matrix = projects(("beta", self.second_root, {}))
        self.publish("projects", matrix)
        mark = (self.state / WATERMARK_NAME).read_bytes()
        self.shared.write_bytes(self.legacy)
        (self.state / ACTIVE_NAME).write_bytes(active)
        self.assertEqual((self.state / WATERMARK_NAME).read_bytes(), mark)
        with self.assertRaises(AccessError):
            AgentFilePolicy(self.shared, self.state).snapshot()

    def test_replaying_complete_state_backup_does_not_restore_revoked_agent_on_restart(self):
        codex = agent("codex")
        self.publish("agents", [codex])
        backup = {path.name: path.read_bytes() for path in self.state.iterdir()}
        self.publish("agents", [])
        self.assertFalse(self.policy.snapshot().principals)
        later_anchor = self.state.parent / self.policy.anchor_name
        latest = later_anchor.read_bytes()
        for name, content in backup.items():
            (self.state / name).write_bytes(content)
        self.assertEqual(later_anchor.read_bytes(), latest)
        process = subprocess.run([sys.executable, "-B", "-c",
                                  "from peters_mcp.agent_file_policy import AgentFilePolicy; "
                                  "import sys; AgentFilePolicy(*sys.argv[1:]).snapshot()",
                                  str(self.shared), str(self.state)], capture_output=True, timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"policy is unavailable", process.stderr)
        with self.assertRaises(AccessError):
            admin.recover(AgentFilePolicy(self.shared, self.state), "a" * 64)

    def test_missing_anchor_is_not_recreated_by_recovery_or_initialization(self):
        anchor = self.state.parent / self.policy.anchor_name
        anchor.unlink()
        with self.assertRaises(AccessError):
            admin.recover(self.policy, "a" * 64)
        self.assertFalse(anchor.exists())
        with self.assertRaises(FileExistsError):
            initialize_agent_file_policy(self.shared, self.state)
        self.assertFalse(anchor.exists())

    def test_existing_anchor_prevents_initialization_over_removed_state(self):
        anchor = self.state.parent / self.policy.anchor_name
        data = anchor.read_bytes()
        self.state.rename(self.space / "old-state")
        with self.assertRaises(AccessError):
            initialize_agent_file_policy(self.shared, self.state)
        self.assertEqual(anchor.read_bytes(), data)
        self.assertFalse(self.state.exists())

    def test_identical_out_of_band_replacement_needs_an_explicit_publish(self):
        prior = self.policy.snapshot()
        replacement = self.space / "replacement.json"
        replacement.write_bytes(self.legacy)
        replacement.chmod(0o600)
        replacement.replace(self.shared)
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        self.publish("projects", self.legacy)
        with self.assertRaises(AccessError):
            with self.policy.commit_guard(prior.revision):
                self.fail("Uncoordinated project-file replacement preserved old admission")

    def test_publication_faults_fail_closed_then_only_complete_exact_intent(self):
        target = projects(("beta", self.second_root, {}))
        real_write = admin.atomic_write
        for interrupt_after in (PENDING_NAME, ACTIVE_NAME, self.shared.name,
                                WATERMARK_NAME, self.policy.anchor_name):
            with self.subTest(interrupt_after=interrupt_after):
                proposal, approval = admin.preview(self.policy, "projects", proposed=target)

                def write_then_interrupt(directory, name, raw, *args, **kwargs):
                    real_write(directory, name, raw, *args, **kwargs)
                    if name == interrupt_after:
                        raise OSError("synthetic publication interruption")

                with patch.object(admin, "atomic_write", side_effect=write_then_interrupt), self.assertRaises(AccessError):
                    admin.apply(self.policy, proposal, approval)
                with self.assertRaises(AccessError):
                    self.policy.snapshot()
                with self.assertRaises(AccessError):
                    admin.recover(self.policy, "f" * 64)
                active = admin.recover(self.policy, approval)
                self.assertEqual(admin.recover(self.policy, approval), active)
                self.assertEqual(self.shared.read_bytes(), target)
                self.assertEqual(self.policy.snapshot().revision, active)
                target = self.legacy if target != self.legacy else projects(("beta", self.second_root, {}))

    def test_pending_target_cannot_be_changed_even_with_the_original_approval(self):
        proposal, approval = admin.preview(self.policy, "agents", proposed=[agent("codex")])
        real_write = admin.atomic_write

        def write_then_stop(directory, name, raw, *args):
            real_write(directory, name, raw, *args)
            raise OSError("synthetic publication interruption")

        with patch.object(admin, "atomic_write", side_effect=write_then_stop), self.assertRaises(AccessError):
            admin.apply(self.policy, proposal, approval)
        intent = self.state / PENDING_NAME
        value = json.loads(intent.read_bytes())
        value["target"]["agents"].append(agent("different"))
        intent.write_text(json.dumps(value))
        with self.assertRaises(AccessError):
            admin.recover(self.policy, approval)
        with self.assertRaises(AccessError):
            self.policy.snapshot()

    def test_recovery_rechecks_protected_scope_and_uses_exact_checked_intent(self):
        proposal, approval = admin.preview(self.policy, "agents", proposed=[agent("codex")])
        real_write = admin.atomic_write

        def write_then_stop(directory, name, raw, *args):
            real_write(directory, name, raw, *args)
            raise OSError("synthetic publication interruption")

        with patch.object(admin, "atomic_write", side_effect=write_then_stop), self.assertRaises(AccessError):
            admin.apply(self.policy, proposal, approval)
        intent = self.state / PENDING_NAME

        def drift(path):
            self.assertEqual(path, self.initial_root)
            with self.policy.locked(exclusive=True, timeout=0.1):
                intent.write_bytes(intent.read_bytes() + b"\n")

        with self.assertRaises(AccessError):
            admin.recover(self.policy, approval, check_path=drift)
        with self.assertRaises(AccessError):
            self.policy.snapshot()

    def test_recover_never_forwards_replaced_root_to_legacy_reader(self):
        target = projects(("beta", self.second_root, {}))
        proposal, approval = admin.preview(self.policy, "projects", proposed=target)
        real_write = admin.atomic_write

        def write_then_stop(directory, name, raw, *args, **kwargs):
            real_write(directory, name, raw, *args, **kwargs)
            if name == PENDING_NAME:
                raise OSError("synthetic publication interruption")

        with patch.object(admin, "atomic_write", side_effect=write_then_stop), self.assertRaises(AccessError):
            admin.apply(self.policy, proposal, approval)
        self.second_root.rename(self.space / "reviewed-beta")
        self.second_root.mkdir()
        (self.second_root / "sample.txt").write_text("Unapproved replacement")
        with self.assertRaises(AccessError):
            admin.recover(self.policy, approval)
        self.assertEqual(self.shared.read_bytes(), self.legacy)
        with self.assertRaises(AccessError):
            self.policy.snapshot()

    def test_project_replace_rechecks_roots_after_expensive_review_and_durable_intent(self):
        target = projects(("beta", self.second_root, {}))
        proposal, approval = admin.preview(self.policy, "projects", proposed=target)
        real_write = admin.atomic_write

        def replace_before_rename(directory, name, raw, *args, **kwargs):
            if name == self.shared.name:
                self.second_root.rename(self.space / "reviewed-beta")
                self.second_root.mkdir()
            real_write(directory, name, raw, *args, **kwargs)

        with patch.object(admin, "atomic_write", side_effect=replace_before_rename), self.assertRaises(AccessError):
            admin.apply(self.policy, proposal, approval)
        self.assertEqual(self.shared.read_bytes(), self.legacy)
        self.assertTrue((self.state / PENDING_NAME).is_file())

    def test_new_worktree_registration_cannot_ride_on_a_legacy_project_publish(self):
        git = self.init_repository()
        target = projects(("alpha", self.initial_root, {"repository_id": RepositoryRegistry.identity(self.initial_root)}))
        proposal, approval = admin.preview(self.policy, "projects", proposed=target)
        real_write = admin.atomic_write

        def register_before_rename(directory, name, raw, *args, **kwargs):
            if name == self.shared.name:
                git("worktree", "add", "--detach", str(self.space / "unreviewed-tree"))
            real_write(directory, name, raw, *args, **kwargs)

        with patch.object(admin, "atomic_write", side_effect=register_before_rename), self.assertRaises(AccessError):
            admin.apply(self.policy, proposal, approval)
        self.assertEqual(self.shared.read_bytes(), self.legacy)
        with self.assertRaises(AccessError):
            admin.recover(self.policy, approval)
        self.assertEqual(self.shared.read_bytes(), self.legacy)

    def test_namespace_overlap_and_moved_root_are_refused(self):
        inner = self.initial_root / "nested"
        inner.mkdir()
        with self.assertRaises(AccessError):
            collect_root_records(json.loads(projects(("alpha", self.initial_root, {}), ("nested", inner, {}))))
        self.publish("projects", projects(("alpha", self.initial_root, {}), ("beta", self.second_root, {})))
        snapshot = self.policy.snapshot()
        old = self.policy.catalog_for(snapshot).read_file("alpha", "sample.txt")
        receipt = self.policy.capture_roots(snapshot, "read_file", "alpha", old)
        self.policy.verify_delivery_roots(snapshot, receipt, deadline=time.monotonic() + 2)
        self.initial_root.rename(self.space / "retired-alpha")
        self.initial_root.mkdir()
        (self.initial_root / "sample.txt").write_text("Unapproved replacement")
        with self.assertRaises(AccessError):
            self.policy.verify_delivery_roots(snapshot, receipt)
        with self.assertRaises(AccessError):
            self.policy.catalog_for(snapshot).read_file("alpha", "sample.txt")
        self.assertEqual(self.policy.catalog_for(snapshot).list_projects()["projects"], [{"id": "beta", "name": "Beta"}])

    def test_scope_diff_reveals_changes_without_a_root_or_membership_change(self):
        target = projects(("alpha", self.initial_root, {"exclude": ["restricted/**"]}))
        proposal, approval = admin.preview(self.policy, "projects", proposed=target)
        self.assertEqual(proposal["summary"]["project_fields_changed"], {"alpha": ["exclude"]})
        self.assertFalse(proposal["summary"]["projects"]["added"])
        self.assertFalse(proposal["summary"]["worktrees"]["changed"])
        admin.apply(self.policy, proposal, approval)
        self.assertEqual(self.policy.snapshot().projects, json.loads(target))

    def test_worktree_publication_is_separate_from_agent_changes(self):
        root = self.initial_root
        git = self.init_repository()
        self.publish("projects", projects(("alpha", root, {"repository_id": RepositoryRegistry.identity(root)})))
        external = self.space / "external-tree"
        git("worktree", "add", "--detach", str(external))
        self.publish("agents", [agent("codex")])
        snapshot = self.policy.snapshot()
        self.assertEqual(len(self.policy.catalog_for(snapshot).list_worktrees("alpha")["worktrees"]), 1)
        self.publish("worktrees")
        snapshot = self.policy.snapshot()
        catalog = self.policy.catalog_for(snapshot)
        worktrees = catalog.list_worktrees("alpha")
        self.assertEqual(len(worktrees["worktrees"]), 2)
        receipt = self.policy.capture_roots(snapshot, "list_worktrees", "alpha", worktrees)
        with patch("peters_mcp.workspaces._git", side_effect=AssertionError("egress must not launch Git")):
            self.policy.verify_delivery_roots(snapshot, receipt)
        git("worktree", "remove", str(external))
        with self.assertRaises(AccessError):
            self.policy.verify_delivery_roots(snapshot, receipt)
