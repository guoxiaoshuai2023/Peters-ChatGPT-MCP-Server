import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp import workspaces
from peters_mcp.workspaces import (RepositoryRegistry, repository_pin_v1,
                                    repository_pin_v2, repository_probe)


def device_drift_fstat(original, delta=17):
    """Model one new runtime device mapping while preserving every other field."""
    def changed(*args, **kwargs):
        info = original(*args, **kwargs)
        return SimpleNamespace(**{key: getattr(info, key) for key in dir(info)
                                  if key.startswith("st_") and key != "st_dev"},
                               st_dev=info.st_dev + delta)
    return changed


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "repo"
        self.init_repo(self.root)
        self.project = SimpleNamespace(id="demo", name="Demo", root=self.root,
                                       repository_id=RepositoryRegistry.identity(self.root))
        self.registry = RepositoryRegistry({"demo": self.project})

    def git(self, root, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        return subprocess.run(["/usr/bin/git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True, env=env).stdout

    def init_repo(self, root):
        root.mkdir(parents=True)
        self.git(root, "init", "-b", "main")
        (root / "README.md").write_text("fixture\n")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "Fixture")

    def add_worktree(self, name="external", inside=False):
        path = self.root / ".worktree" / name if inside else self.base / name
        self.git(self.root, "worktree", "add", "-b", name, str(path))
        return path

    def test_external_and_hidden_worktrees_discovered_with_sources(self):
        external = self.add_worktree()
        hidden = self.add_worktree("hidden", inside=True)
        snapshot = self.registry.discover("demo")
        self.assertEqual(snapshot["mode"], "repository")
        self.assertEqual({item["root"] for item in snapshot["worktrees"]},
                         {str(self.root), str(external), str(hidden)})
        self.assertTrue(all(item["state"] == "valid" for item in snapshot["worktrees"]))
        self.assertEqual(snapshot["worktrees"][0]["id"], "main")
        self.assertEqual(snapshot["worktrees"][0]["branch"], "main")
        self.assertEqual(snapshot["worktrees"][0]["head"], self.git(self.root, "rev-parse", "HEAD").strip())
        for item in snapshot["worktrees"]:
            self.assertEqual(self.registry.resolve("demo", item["id"])["root"], item["root"])

    def test_add_remove_dynamic_and_scope_fingerprint(self):
        before = self.registry.discover("demo")
        path = self.add_worktree()
        added = self.registry.discover("demo")
        self.assertNotEqual(before["fingerprint"], added["fingerprint"])
        entry = next(item for item in added["worktrees"] if item["root"] == str(path))
        self.git(self.root, "worktree", "remove", str(path))
        after = self.registry.discover("demo")
        self.assertEqual(before["fingerprint"], after["fingerprint"])
        with self.assertRaisesRegex(AccessError, "not discovered"):
            self.registry.resolve("demo", entry["id"])
        self.assertEqual(self.registry.associate(str(path))["state"], "pending")

    def test_commits_and_branch_names_do_not_invalidate_scope(self):
        before = self.registry.discover("demo")
        (self.root / "README.md").write_text("new contents\n")
        self.git(self.root, "commit", "-am", "Change")
        self.git(self.root, "branch", "-m", "renamed")
        after = self.registry.discover("demo")
        self.assertEqual(before["fingerprint"], after["fingerprint"])
        self.assertNotEqual(before["worktrees"][0]["head"], after["worktrees"][0]["head"])
        self.assertEqual(after["worktrees"][0]["branch"], "renamed")

    def test_linked_configuration_uses_main_for_configured_root(self):
        path = self.add_worktree()
        project = SimpleNamespace(id="linked", name="Linked", root=path,
                                  repository_id=self.project.repository_id)
        registry = RepositoryRegistry({"linked": project})
        entries = registry.discover("linked")["worktrees"]
        self.assertEqual(entries[0]["root"], str(path))
        self.assertEqual(entries[0]["id"], "main")
        self.assertEqual({entry["root"] for entry in entries}, {str(path), str(self.root)})

    def test_subdirectories_and_new_worktree_association(self):
        for root in (self.root, self.add_worktree()):
            child = root / ".hidden" / "subdir"
            child.mkdir(parents=True)
            result = self.registry.associate(str(child))
            self.assertEqual(result["state"], "matched")
            self.assertEqual(result["root"], str(root))
            self.assertEqual(result["project_id"], "demo")
            self.assertEqual(result["repository_id"], self.project.repository_id)

    def test_nested_other_repository_and_unrelated_directory_are_not_inherited(self):
        nested = self.root / "vendor" / "unrelated"
        self.init_repo(nested)
        self.assertEqual(self.registry.associate(str(nested))["state"], "outside")
        ordinary = self.base / "ordinary"
        ordinary.mkdir()
        self.assertEqual(self.registry.associate(str(ordinary))["state"], "pending")
        self.assertEqual(self.registry.associate(None)["state"], "pending")
        self.assertEqual(self.registry.associate("relative/path")["state"], "pending")

    def test_fake_worktree_pointer_and_git_symlink_rejected(self):
        actual = self.add_worktree()
        fake = self.base / "fake"
        fake.mkdir()
        shutil.copyfile(actual / ".git", fake / ".git")
        self.assertEqual(self.registry.associate(str(fake))["state"], "pending")
        with self.assertRaises(AccessError):
            RepositoryRegistry.identity(fake)
        (fake / ".git").unlink()
        (fake / ".git").symlink_to(self.root / ".git", target_is_directory=True)
        self.assertEqual(self.registry.associate(str(fake))["state"], "pending")
        with self.assertRaises(AccessError):
            RepositoryRegistry.identity(fake)

    def test_symbolic_link_to_an_authorized_worktree_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.registry.associate(str(alias))["state"], "pending")
        with self.assertRaises(AccessError):
            RepositoryRegistry.identity(alias)

    def test_missing_registered_directory_is_not_readable(self):
        path = self.add_worktree()
        before = self.registry.discover("demo")
        entry = next(item for item in before["worktrees"] if item["root"] == str(path))
        shutil.rmtree(path)
        after = self.registry.discover("demo")
        missing = next(item for item in after["worktrees"] if item["id"] == entry["id"])
        self.assertEqual(missing["state"], "missing")
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        with self.assertRaisesRegex(AccessError, "missing"):
            self.registry.resolve("demo", entry["id"])

    def test_replaced_worktree_different_repository_fails_closed(self):
        path = self.add_worktree()
        entry = next(item for item in self.registry.discover("demo")["worktrees"]
                     if item["root"] == str(path))
        shutil.rmtree(path)
        self.init_repo(path)
        current = next(item for item in self.registry.discover("demo")["worktrees"]
                       if item["root"] == str(path))
        self.assertEqual(current["state"], "identity_mismatch")
        self.assertEqual(self.registry.associate(str(path))["state"], "outside")
        with self.assertRaisesRegex(AccessError, "identity_mismatch"):
            self.registry.resolve("demo", entry["id"])

    def test_pin_mismatch_disables_all_worktrees(self):
        self.add_worktree()
        self.project.repository_id = "git-incorrect-pin"
        snapshot = self.registry.discover("demo")
        self.assertEqual(len(snapshot["worktrees"]), 1)
        self.assertEqual(snapshot["worktrees"][0]["state"], "identity_mismatch")
        with self.assertRaisesRegex(AccessError, "identity_mismatch"):
            self.registry.resolve("demo")
        self.assertNotEqual(self.registry.associate(str(self.root))["state"], "matched")

    def test_replaced_common_git_directory_changes_identity(self):
        original = self.project.repository_id
        (self.root / ".git").rename(self.root / ".git-old")
        shutil.copytree(self.root / ".git-old", self.root / ".git")
        self.assertNotEqual(RepositoryRegistry.identity(self.root), original)
        with self.assertRaisesRegex(AccessError, "identity_mismatch"):
            self.registry.resolve("demo")

    def test_directory_mode_is_not_implicit_repository_history_authorization(self):
        self.add_worktree()
        self.project.repository_id = None
        snapshot = self.registry.discover("demo")
        self.assertEqual(snapshot["mode"], "directory")
        self.assertEqual(len(snapshot["worktrees"]), 1)
        self.assertEqual(self.registry.resolve("demo")["root"], str(self.root))
        self.assertEqual(self.registry.associate(str(self.root))["state"], "outside")

    def test_duplicate_repository_configuration_is_ambiguous(self):
        duplicate = SimpleNamespace(id="duplicate", name="Duplicate", root=self.root,
                                    repository_id=self.project.repository_id)
        registry = RepositoryRegistry({"demo": self.project, "duplicate": duplicate})
        self.assertEqual(registry.associate(str(self.root))["state"], "ambiguous")

    def test_new_pins_are_v2_and_legacy_algorithm_remains_exact(self):
        probe = repository_probe(self.root)
        common_info = probe["common"].stat()
        self.assertTrue(self.project.repository_id.startswith("git-v2-"))
        self.assertEqual(repository_pin_v2(self.root), self.project.repository_id)
        self.assertEqual(probe["common_runtime_identity"], [common_info.st_dev, common_info.st_ino])
        self.assertEqual(probe["legacy_repository_id"], repository_pin_v1(
            probe["common"], common_info.st_dev, common_info.st_ino))
        self.project.repository_id = probe["legacy_repository_id"]
        path = self.add_worktree()
        snapshot = self.registry.discover("demo")
        self.assertTrue(all(entry["state"] == "valid" for entry in snapshot["worktrees"]))
        self.assertTrue(all(entry["repository_id"] == self.project.repository_id
                            for entry in snapshot["worktrees"]))
        self.assertEqual(self.registry.associate(path)["repository_id"], self.project.repository_id)

    def test_v2_pin_survives_device_drift_and_worktree_ids_stay_unchanged(self):
        path = self.add_worktree()
        before = self.registry.discover("demo")
        configured = self.project.repository_id
        with patch("peters_mcp.workspaces.os.fstat", side_effect=device_drift_fstat(os.fstat)):
            self.assertEqual(RepositoryRegistry.identity(self.root), configured)
            after = self.registry.discover("demo")
            self.assertEqual({entry["root"]: entry["id"] for entry in before["worktrees"]},
                             {entry["root"]: entry["id"] for entry in after["worktrees"]})
            self.assertTrue(all(entry["state"] == "valid" for entry in after["worktrees"]))
            self.assertEqual(self.registry.associate(path)["state"], "matched")
        self.assertEqual(self.project.repository_id, configured)

    def test_legacy_device_drift_is_rejected_without_automatic_repinning(self):
        self.project.repository_id = repository_probe(self.root)["legacy_repository_id"]
        configured = self.project.repository_id
        with patch("peters_mcp.workspaces.os.fstat", side_effect=device_drift_fstat(os.fstat)):
            snapshot = self.registry.discover("demo")
            self.assertEqual(snapshot["worktrees"][0]["state"], "identity_mismatch")
            self.assertNotEqual(self.registry.associate(self.root)["state"], "matched")
        self.assertEqual(self.project.repository_id, configured)

    def test_same_inode_changed_volume_or_birthtime_does_not_inherit(self):
        original = workspaces.persistent_identity_fd
        for change in ({"volume_uuid": "11111111-1111-4111-8111-111111111111"},
                       {"birthtime_ns": 1}):
            with self.subTest(change=change):
                def changed(fd):
                    return {**original(fd), **change}
                with patch("peters_mcp.workspaces.persistent_identity_fd", side_effect=changed), \
                     patch("peters_mcp.workspaces.os.fstat", side_effect=device_drift_fstat(os.fstat)):
                    self.assertNotEqual(RepositoryRegistry.identity(self.root), self.project.repository_id)
                    self.assertEqual(self.registry.discover("demo")["worktrees"][0]["state"],
                                     "identity_mismatch")
                    self.assertNotEqual(self.registry.associate(self.root)["state"], "matched")

    def test_mixed_legacy_and_v2_same_repository_is_ambiguous(self):
        path = self.add_worktree()
        legacy = SimpleNamespace(id="legacy", name="Legacy", root=path,
                                 repository_id=repository_probe(path)["legacy_repository_id"])
        registry = RepositoryRegistry({"demo": self.project, "legacy": legacy})
        self.assertTrue(all(entry["state"] == "valid" for snapshot in registry.discover_all().values()
                            for entry in snapshot["worktrees"]))
        for root in (self.root, path):
            self.assertEqual(registry.associate(root)["state"], "ambiguous")

    def test_symbolic_link_ancestor_is_rejected(self):
        alias = self.base / "parent-alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(AccessError):
            RepositoryRegistry.identity(alias / self.root.name)
        self.assertNotEqual(self.registry.associate(alias / self.root.name)["state"], "matched")

    def test_common_replacement_during_probe_is_rejected(self):
        original = workspaces.persistent_identity_fd
        changed = False
        def replace(fd):
            nonlocal changed
            result = original(fd)
            if not changed:
                changed = True
                (self.root / ".git").rename(self.root / ".git-original")
                shutil.copytree(self.root / ".git-original", self.root / ".git")
            return result
        with patch("peters_mcp.workspaces.persistent_identity_fd", side_effect=replace):
            with self.assertRaisesRegex(AccessError, "replaced"):
                RepositoryRegistry.identity(self.root)

    def test_pointer_or_backlink_replacement_during_probe_is_rejected(self):
        linked = self.add_worktree()
        for target in (linked / ".git", repository_probe(linked)["common"] / "worktrees/external/gitdir"):
            with self.subTest(target=target):
                original = workspaces.persistent_identity_fd
                changed = False
                def replace(fd):
                    nonlocal changed
                    result = original(fd)
                    if not changed:
                        changed = True
                        content = target.read_bytes()
                        target.rename(target.with_name(target.name + ".original"))
                        target.write_bytes(content)
                    return result
                with patch("peters_mcp.workspaces.persistent_identity_fd", side_effect=replace):
                    with self.assertRaisesRegex(AccessError, "replaced"):
                        RepositoryRegistry.identity(linked)

    def test_snapshot_root_identity_is_bound_to_the_verified_worktree(self):
        foreign = self.base / "foreign"
        self.init_repo(foreign)
        hold = self.base / "verified-root"
        original = self.registry._entry
        swapped = False
        def replace_after_probe(*args, **kwargs):
            nonlocal swapped
            entry = original(*args, **kwargs)
            if entry["state"] == "valid" and not swapped:
                swapped = True
                self.root.rename(hold)
                foreign.rename(self.root)
            return entry
        try:
            with patch.object(self.registry, "_entry", side_effect=replace_after_probe):
                snapshot = self.registry.discover("demo")
            self.assertEqual(snapshot["worktrees"][0]["state"], "unavailable")
            self.assertNotIn("root_identity", snapshot["worktrees"][0])
        finally:
            if swapped:
                self.root.rename(foreign)
                hold.rename(self.root)

    def test_inherited_git_environment_cannot_redirect_or_trace(self):
        other = self.base / "other"
        self.init_repo(other)
        trace = self.base / "trace-output"
        with patch.dict(os.environ, {"GIT_DIR": str(other / ".git"),
                                    "GIT_WORK_TREE": str(other), "GIT_TRACE": str(trace),
                                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                                    "GIT_CONFIG_VALUE_0": "malicious-monitor"}):
            self.assertEqual(RepositoryRegistry.identity(self.root), self.project.repository_id)
            self.assertEqual(self.registry.resolve("demo")["root"], str(self.root))
        self.assertFalse(trace.exists())

    def test_read_only_commands_do_not_refresh_index_or_run_fsmonitor(self):
        script = self.base / "monitor.sh"
        marker = self.base / "executed"
        script.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        script.chmod(0o755)
        self.git(self.root, "config", "core.fsmonitor", str(script))
        index = self.root / ".git" / "index"
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        self.registry.discover_all()
        self.registry.associate(str(self.root))
        self.assertEqual(before, (index.read_bytes(), index.stat().st_mtime_ns))
        self.assertFalse(marker.exists())

    def test_bad_project_and_worktree_identifiers(self):
        for method in (self.registry.discover, self.registry.resolve):
            with self.assertRaisesRegex(AccessError, "Unknown project"):
                method("unknown")
        for identifier in ("../../outside", "wt-invented"):
            with self.assertRaisesRegex(AccessError, "not discovered"):
                self.registry.resolve("demo", identifier)
        with self.assertRaisesRegex(AccessError, "Invalid worktree"):
            self.registry.resolve("demo", [])


if __name__ == "__main__":
    unittest.main()
