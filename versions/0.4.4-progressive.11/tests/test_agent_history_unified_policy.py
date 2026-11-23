from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.agent_history_admin import (activate_preview, compile_generation,
                                            approve_migration_scope, preview_activation,
                                            preview_migration, write_descriptor)
from peters_mcp.agent_history_generation import GenerationStore, canonical_bytes, initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.workspaces import repository_pin_v2


def _activate_child(path, document, token, ready, done):
    store = GenerationStore(path)
    ready.set()
    store.activate(document, expected_digest=token)
    done.set()


class UnifiedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "public.txt").write_text("visible text")
        self.source = self.base / "source"
        self.source.mkdir()
        self.actor = "a" * 64
        self.document = compile_generation({
            "version": 2, "projects": [{"id": "main", "name": "Main", "root": str(self.project)}],
            "sources": {"sample": {
                "adapter": "codeg", "root": str(self.source), "format": "0.45.0",
                "enabled": True, "instance_id": "sample-profile"}}, "legacy_history": None})
        self.store = initialize_store(self.private / "generations")
        self.token = self.store.activate(self.document, initial=True)
        self.descriptor = self.private / "agent-history.json"
        write_descriptor(self.descriptor, self.store)
        self.policy = AgentPolicy(self.descriptor, mode="v2")

    def test_global_actor_and_one_live_project_allowlist(self):
        catalog = Catalog.from_policy(self.policy)
        sources, token = self.policy.config()
        self.assertEqual(token, self.token)
        self.assertTrue(sources["sample"].allows(self.actor, "main"))
        self.assertTrue(sources["sample"].allows("b" * 64, "main"))
        self.policy.require_actor(self.actor)
        with self.assertRaises(AccessError):
            self.policy.require_actor("unverified")
        second = self.base / "second"
        second.mkdir()
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "second", "name": "Second", "root": str(second)})
        updated = compile_generation(updated)
        self.store.activate(updated, expected_digest=self.token)
        catalog.refresh()
        self.assertEqual(set(catalog.projects), {"main", "second"})
        current, _ = self.policy.config()
        self.assertEqual(current["sample"].immutable(), sources["sample"].immutable())
        self.assertTrue(current["sample"].allows(self.actor, "second"))

    def test_activation_epoch_prevents_revoke_restore_aba(self):
        original_token = self.policy.project_token("main")
        denied = deepcopy(self.document)
        denied["projects"] = []
        revoked = self.store.activate(denied, expected_digest=self.token)
        restored = self.store.activate(self.document, expected_digest=revoked)
        self.assertNotEqual(restored, self.token)
        self.assertEqual(self.policy.snapshot(), (self.document, restored))
        with self.assertRaises(AccessError) as rejected:
            with self.policy.commit_guard(self.token):
                self.fail("An old prepared response passed the restored policy.")
        self.assertEqual(rejected.exception.code, "restart_required")
        with self.assertRaises(AccessError) as rejected:
            with self.policy.commit_guard(project_id="main", expected_project_token=original_token):
                self.fail("A previous project capability survived withdrawal and re-addition.")
        self.assertEqual(rejected.exception.code, "scope_revoked")

    def test_unrelated_project_change_keeps_existing_admission(self):
        original_token = self.policy.project_token("main")
        second = self.base / "second"
        second.mkdir()
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "second", "name": "Second", "root": str(second)})
        self.store.activate(compile_generation(updated), expected_digest=self.token)
        with self.policy.commit_guard(project_id="main", expected_project_token=original_token) as current:
            self.assertEqual(self.policy.project_token("main", current), original_token)
        reopened = AgentPolicy(self.descriptor, mode="v2")
        self.assertEqual(reopened.project_token("main"), original_token)

    def test_project_admission_changes_with_effective_operation_policy(self):
        current = deepcopy(self.document)
        original_token = self.policy.project_token("main")
        current["projects"][0].update(name="New project label", candidate_directory="docs/candidates/chatgpt")
        epoch = self.store.activate(current, expected_digest=self.token)
        self.assertEqual(self.policy.project_token("main"), original_token)
        for setting, value in (("exclude", ["formerly-visible.txt"]), ("allow_hidden", [".worktree"]),
                               ("candidate_directory", "docs/candidates/local")):
            with self.subTest(setting=setting):
                previous = self.policy.project_token("main")
                current["projects"][0][setting] = value
                epoch = self.store.activate(current, expected_digest=epoch)
                self.assertNotEqual(self.policy.project_token("main"), previous)
                with self.assertRaises(AccessError) as rejected:
                    with self.policy.commit_guard(project_id="main", expected_project_token=previous):
                        self.fail("The superseded operation policy still granted delivery.")
                self.assertEqual(rejected.exception.code, "scope_revoked")

    def test_old_pointer_restore_is_closed_on_new_process(self):
        path = self.store.path / "active.json"
        old = path.read_bytes()
        revoked = deepcopy(self.document)
        revoked["projects"] = []
        latest = self.store.activate(revoked, expected_digest=self.token)
        path.write_bytes(old)
        self.assertNotEqual(path.read_bytes(), self.store.anchor_path.read_bytes())
        with self.assertRaises(AccessError):
            AgentPolicy(self.descriptor, mode="v2")
        with self.assertRaises(AccessError):
            self.store.recover(self.document)
        self.assertEqual(self.store.recover(revoked), latest)
        self.assertEqual(self.policy.snapshot()[0]["projects"], [])

    def test_interrupted_pointer_write_finishes_only_current_approved_intent(self):
        from peters_mcp import agent_history_generation

        revoked = deepcopy(self.document)
        revoked["projects"] = []
        original_replace = agent_history_generation._replace

        def interrupted(directory, filename, raw):
            if filename == "active.json":
                raise OSError("simulated power loss")
            original_replace(directory, filename, raw)

        with patch.object(agent_history_generation, "_replace", side_effect=interrupted):
            with self.assertRaises(AccessError):
                self.store.activate(revoked, expected_digest=self.token)
        with self.assertRaises(AccessError):
            self.store.snapshot()
        with self.assertRaises(AccessError):
            self.store.recover(self.document)
        self.store.recover(revoked)
        self.assertEqual(self.store.snapshot()[0]["projects"], [])

    def test_activation_rechecks_approved_root_under_lock(self):
        added = self.base / "added"
        added.mkdir()
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "added", "name": "Added", "root": str(added)})
        preview, digest = preview_activation(updated, previous=self.policy.snapshot())
        original_locked = self.store.locked

        @contextmanager
        def replaced(*args, **kwargs):
            added.rename(self.base / "formerly-added")
            added.mkdir()
            with original_locked(*args, **kwargs) as directory:
                yield directory

        with patch.object(self.store, "locked", side_effect=replaced):
            with self.assertRaisesRegex(AccessError, "evidence changed"):
                activate_preview(self.store, preview, digest)
        self.assertEqual(self.policy.snapshot()[1], self.token)

    def test_external_worktree_overlapping_another_project_is_rejected(self):
        repo = self.base / "repo"
        repo.mkdir()
        worktree = self.project / "worktree"
        subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.org",
                        "commit", "--allow-empty", "-m", "test"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", "second", str(worktree)],
                       check=True, capture_output=True)
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "repo", "name": "Git", "root": str(repo),
                                    "repository_id": repository_pin_v2(repo)})
        with self.assertRaises(AccessError) as rejected:
            preview_activation(updated, previous=self.policy.snapshot())
        self.assertEqual(rejected.exception.code, "project_scope_overlap")

    def test_worktree_registration_added_during_activation_does_not_publish(self):
        repo = self.base / "other"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.org",
                        "commit", "--allow-empty", "-m", "test"], check=True, capture_output=True)
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "repo", "name": "Git", "root": str(repo),
                                    "repository_id": repository_pin_v2(repo)})
        preview, digest = preview_activation(updated, previous=self.policy.snapshot())
        original_activate = self.store.activate

        def registration_changed(*args, **kwargs):
            subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", "late", str(self.project / "late")],
                           check=True, capture_output=True)
            return original_activate(*args, **kwargs)

        with patch.object(self.store, "activate", side_effect=registration_changed):
            with self.assertRaisesRegex(AccessError, "evidence changed"):
                activate_preview(self.store, preview, digest)
        self.assertEqual(self.policy.snapshot()[1], self.token)

    def test_retired_source_roots_stay_excluded_across_restart(self):
        removed = deepcopy(self.document)
        removed["sources"] = {}
        preview, digest = preview_activation(removed, previous=self.policy.snapshot())
        activate_preview(self.store, preview, digest)
        moved = self.base / "old_source"
        self.source.rename(moved)
        after = AgentPolicy(self.descriptor, mode="v2")
        self.assertTrue(after.excludes(self.source / "raw.jsonl"))
        self.assertTrue(after.excludes(moved / "raw.jsonl"))

    def test_disabling_source_does_not_require_access_to_missing_original(self):
        self.source.rename(self.base / "disconnected")
        updated = deepcopy(self.document)
        updated["sources"]["sample"]["enabled"] = False
        preview, digest = preview_activation(updated, previous=self.policy.snapshot())
        activate_preview(self.store, preview, digest)
        self.assertFalse(self.policy.config()[0]["sample"].enabled)
        with self.assertRaises(AccessError):
            preview_activation(self.document, previous=self.policy.snapshot())

    def test_old_codex_binding_requires_native_proof_or_an_explicit_exclusion(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "v1.json"
        old.write_text(json.dumps({"version": 1, "sources": {}}))
        home = self.base / "codex"
        (home / "sessions").mkdir(parents=True)
        legacy = self.private / "legacy.json"
        retained = "c14584e8-ab98-4404-a949-a9fb275d7173"
        excluded = "909e7151-a3ce-4c1b-ac17-17575c1d49bf"
        legacy.write_text(json.dumps({"version": 2, "codex_home": str(home), "state_db": "state_5.sqlite",
                                      "threads": [{"id": retained, "allow_tool_results": True,
                                                   "mcp_tools": ["test/read"]}, {"id": excluded}],
                                      "inherit_projects": False, "denied_threads": []}))
        rollout = home / "sessions" / f"rollout-test-{retained}.jsonl"
        rollout.write_text(json.dumps({"type": "session_meta", "payload": {"id": retained,
                                                                           "cwd": str(self.project)}}) + "\n")
        with sqlite3.connect(home / "state_5.sqlite") as db:
            db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, title TEXT,"
                       "updated_at INTEGER, archived INTEGER)")
            db.execute("INSERT INTO threads VALUES (?,?,?,?,?,?)",
                       (retained, str(rollout), str(self.project), "Verified history", 100, 0))
        preview, _ = preview_migration(projects, old, legacy, [self.actor])
        self.assertEqual(len(preview["unresolved"]), 2)
        preview, digest = preview_migration(projects, old, legacy, [self.actor],
                                            dispositions={retained: "main", excluded: "exclude"})
        self.assertEqual(preview["unresolved"], [])
        self.assertEqual(preview["document"]["sources"]["codex"]["denied_threads"], [excluded])
        self.assertEqual(preview["document"]["legacy_history"]["tool_evidence"][0]["id"], retained)
        preview, digest = approve_migration_scope(preview, self.actor, "codex", digest)
        target = initialize_store(self.private / "legacy-target")
        activate_preview(target, preview, digest, initial=True)

    def test_shared_delivery_lock_serializes_cross_process_activation(self):
        context = multiprocessing.get_context("spawn")
        ready, done = context.Event(), context.Event()
        updated = deepcopy(self.document)
        updated["projects"] = []
        process = context.Process(target=_activate_child,
                                  args=(self.store.path, updated, self.token, ready, done))
        try:
            with self.policy.commit_guard(self.token) as snapshot:
                self.assertEqual(snapshot[1], self.token)
                process.start()
                self.assertTrue(ready.wait(5))
                self.assertFalse(done.wait(0.15))
            self.assertTrue(done.wait(5))
            process.join(5)
            self.assertEqual(process.exitcode, 0)
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)

    def test_loss_corruption_and_permissions_never_fall_back(self):
        pointer = self.store.path / "active.json"
        original = pointer.read_bytes()
        for value in (b"{", b'{"version":1}', b'{}'):
            with self.subTest(value=value):
                pointer.write_bytes(value)
                with self.assertRaises(AccessError):
                    self.policy.snapshot()
        pointer.write_bytes(original)
        pointer.unlink()
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        pointer.write_bytes(original)
        pointer.chmod(0o644)
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        pointer.chmod(0o600)
        pointer_document = json.loads(original)
        generation = self.store.path / "generations" / (pointer_document["sha256"] + ".json")
        generation.write_text("{}")
        with self.assertRaises(AccessError):
            self.policy.snapshot()

    def test_v2_descriptor_requires_explicit_mode_and_private_file(self):
        with self.assertRaises(AccessError):
            AgentPolicy(self.descriptor)
        with self.assertRaises(AccessError):
            AgentPolicy(None, mode="v2")
        self.descriptor.chmod(0o644)
        with self.assertRaises(AccessError):
            AgentPolicy(self.descriptor, mode="v2")

    def test_root_replacement_rejected_across_new_runtime_and_catalog_reads(self):
        catalog = Catalog.from_policy(self.policy)
        self.project.rename(self.base / "old-project")
        self.project.mkdir()
        (self.project / "public.txt").write_text("replacement")
        restarted = Catalog.from_policy(AgentPolicy(self.descriptor, mode="v2"))
        for current in (catalog, restarted):
            entry = current.repositories.discover("main")["worktrees"][0]
            self.assertEqual(entry["state"], "identity_mismatch")
            with self.assertRaises(AccessError):
                current.read_file("main", "public.txt")
        self.source.rename(self.base / "old-source")
        self.source.mkdir()
        restarted_policy = AgentPolicy(self.descriptor, mode="v2")
        source = restarted_policy.config()[0]["sample"]
        with self.assertRaises(AccessError) as rejected:
            restarted_policy.make_root("sample", source)
        self.assertEqual(rejected.exception.code, "source_unavailable")
        self.assertTrue(restarted_policy.excludes(self.base / "old-source" / "raw.jsonl"))

    def test_empty_allowlist_is_a_valid_revocation(self):
        catalog = Catalog.from_policy(self.policy)
        updated = deepcopy(self.document)
        updated["projects"] = []
        self.store.activate(updated, expected_digest=self.token)
        catalog.refresh()
        self.assertEqual(catalog.list_projects()["projects"], [])
        with self.assertRaises(AccessError):
            catalog.read_file("main", "public.txt")

    def test_project_removal_needs_no_source_exception_edit(self):
        updated = deepcopy(self.document)
        updated["sources"]["sample"]["exceptions"] = {"old-thread": {
            "project_id": "main", "source_identity": "1:2:3", "source_revision": "a" * 64,
            "project_fingerprint": "b" * 64}}
        updated["projects"] = []
        prepared = compile_generation(updated)
        self.assertEqual(prepared["sources"]["sample"], updated["sources"]["sample"])
        self.store.activate(prepared, expected_digest=self.token)
        self.assertEqual(Catalog.from_policy(self.policy).list_projects()["projects"], [])

    def test_disabled_codex_keeps_storage_and_tool_evidence_independent(self):
        updated = deepcopy(self.document)
        updated["sources"] = {"codex": {
            "adapter": "codex", "root": str(self.source), "format": "local", "enabled": False,
            "instance_id": "native-codex", "denied_threads": ["c14584e8-ab98-4404-a949-a9fb275d7173"]}}
        updated["legacy_history"] = {"codex_home": str(self.source), "state_db": "state_5.sqlite",
                                     "tool_evidence": [{"id": "909e7151-a3ce-4c1b-ac17-17575c1d49bf", "allow_tool_results": True,
                                                        "mcp_tools": ["example/read"]}]}
        updated = compile_generation(updated)
        token = self.store.activate(updated, expected_digest=self.token)
        restarted = AgentPolicy(self.descriptor, mode="v2")
        snapshot = restarted.snapshot()
        self.assertEqual(snapshot[1], token)
        source = restarted.config(snapshot)[0]["codex"]
        self.assertFalse(source.allows(self.actor, ""))
        legacy = restarted.legacy_document(snapshot)
        self.assertEqual(legacy["codex_home"], str(self.source))
        self.assertEqual(legacy["denied_threads"], ["c14584e8-ab98-4404-a949-a9fb275d7173"])
        self.assertEqual(legacy["threads"][0]["mcp_tools"], ["example/read"])

    def test_native_links_bind_exact_registered_instance(self):
        updated = deepcopy(self.document)
        deepseek = self.base / "deepseek"
        deepseek.mkdir()
        updated["sources"]["native"] = {"adapter": "deepseek_harness", "root": str(deepseek),
                                           "format": "0.2.2-rc.3", "enabled": True,
                                           "instance_id": "dsh-profile"}
        updated["sources"]["sample"]["links"] = {"deepseek_harness": "native"}
        with self.assertRaises(AccessError):
            compile_generation(updated)
        updated["sources"]["sample"]["link_instances"] = {"deepseek_harness": "wrong-profile"}
        with self.assertRaises(AccessError):
            compile_generation(updated)
        updated["sources"]["sample"]["link_instances"] = {"deepseek_harness": "dsh-profile"}
        prepared = compile_generation(updated)
        self.assertEqual(prepared["sources"]["sample"]["links"], {"deepseek_harness": "native"})

    def test_preview_bound_to_inputs_generation_and_pins(self):
        draft = self.private / "draft.json"
        draft.write_text(json.dumps(self.document))
        preview, digest = preview_activation(self.document, inputs=[{
            "path": str(draft), "sha256": hashlib.sha256(draft.read_bytes()).hexdigest()}],
                                             previous=self.policy.snapshot())
        changed = deepcopy(preview)
        changed["document"]["projects"][0]["name"] = "Drifted Name"
        with self.assertRaises(AccessError):
            activate_preview(self.store, changed, digest)
        draft.write_text("{}")
        with self.assertRaises(AccessError):
            activate_preview(self.store, preview, digest)
        self.project.rename(self.base / "old-project")
        self.project.mkdir()
        with self.assertRaises(AccessError):
            compile_generation(self.document)

    def test_source_registration_change_requires_restart_and_stays_protected(self):
        updated = deepcopy(self.document)
        updated["sources"]["sample"]["instance_id"] = "different-profile"
        self.store.activate(updated, expected_digest=self.token)
        with self.assertRaises(AccessError) as rejected:
            self.policy.config()
        self.assertEqual(rejected.exception.code, "restart_required")
        self.assertTrue(self.policy.excludes(self.source / "secret.jsonl"))
        self.assertTrue(self.policy.excludes(self.store.path / "active.json"))

    def test_migration_preview_preserves_denials_and_requires_verified_exceptions(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "v1.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {"old-thread": "main"},
            "denied_threads": ["denied-thread"]}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor])
        self.assertEqual(preview["document"]["sources"]["sample"]["denied_threads"], ["denied-thread"])
        self.assertEqual(preview["unresolved"][0]["reason"], "snapshot_binding_requires_verification")
        with self.assertRaises(AccessError):
            activate_preview(self.store, preview, digest)
        with self.assertRaises(AccessError):
            compile_generation({**self.document, "principals": ["not-a-verified-principal"]})

    def test_heterogeneous_migration_needs_exact_scope_approval_for_each_actor(self):
        second = self.base / "second"
        second.mkdir()
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [
            {"id": "main", "name": "Main", "root": str(self.project)},
            {"id": "second", "name": "Second", "root": str(second)}]}))
        other = "b" * 64
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": True, "actors": {self.actor: ["main"], other: ["second"]},
            "threads": {}, "denied_threads": []}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor, other])
        self.assertEqual(preview["unresolved"], [])
        self.assertEqual(len(preview["required_scope_approvals"]), 2)
        target_store = initialize_store(self.private / "migration-target")
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, preview, digest, initial=True)
        preview, digest = approve_migration_scope(preview, self.actor, "sample", digest)
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, preview, digest, initial=True)
        preview, digest = approve_migration_scope(preview, other, "sample", digest)
        corrupted = deepcopy(preview)
        corrupted["document"]["projects"][0]["name"] = "Renamed"
        corrupted_digest = hashlib.sha256(canonical_bytes(corrupted)).hexdigest()
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, corrupted, corrupted_digest, initial=True)
        active = activate_preview(target_store, preview, digest, initial=True)
        self.assertEqual(target_store.snapshot()[1], active)

    def test_migration_to_automatic_inheritance_needs_explicit_scope_decision(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {}, "denied_threads": []}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor])
        self.assertEqual(preview["changes"][0]["added_projects"], [])
        self.assertFalse(preview["changes"][0]["old_inherit_projects"])
        self.assertEqual(len(preview["required_scope_approvals"]), 1)
        approved, approved_digest = approve_migration_scope(preview, self.actor, "sample", digest)
        old.write_text("{}")
        with self.assertRaisesRegex(AccessError, "input changed"):
            activate_preview(self.store, approved, approved_digest)

    def test_cli_migration_preserves_optional_antigravity_format_without_activation(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "antigravity", "root": str(self.source), "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {}, "denied_threads": []}}}))
        result = subprocess.run([sys.executable, "-m", "peters_mcp.agent_history_admin", "preview-migration",
                                 "--projects", str(projects), "--agent-v1", str(old),
                                 "--principal", self.actor], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        preview = json.loads(result.stdout)
        self.assertIsNone(preview["preview"]["document"]["sources"]["sample"]["format"])
        self.assertEqual(preview["preview"]["scope_approvals"], [])
        self.assertEqual(self.store.snapshot()[1], self.token)
        wrong = deepcopy(preview["preview"]["document"])
        wrong["sources"]["sample"]["adapter"] = "codeg"
        with self.assertRaises(AccessError):
            compile_generation(wrong)


if __name__ == "__main__":
    unittest.main()
