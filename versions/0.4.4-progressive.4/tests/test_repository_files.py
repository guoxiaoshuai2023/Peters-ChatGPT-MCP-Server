import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.candidates import CandidateDelivery
from peters_mcp.workspaces import RepositoryRegistry
from tests import test_workspaces


class RepositoryFileTests(unittest.TestCase):
    git = test_workspaces.WorkspaceTests.git
    init_repo = test_workspaces.WorkspaceTests.init_repo
    add_worktree = test_workspaces.WorkspaceTests.add_worktree

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "repo"
        self.init_repo(self.root)
        self.pin = RepositoryRegistry.identity(self.root)
        self.catalog = Catalog([Project("repo", "Repo", self.root, repository_id=self.pin)])

    def test_main_relative_hidden_worktree_path_and_named_worktree(self):
        wt = self.add_worktree("preheat", inside=True)
        (wt / "审核包.md").write_text("worktree current bytes\n")
        result = self.catalog.read_file("repo", ".worktree/preheat/审核包.md")
        source = result["working_directory"]
        self.assertEqual(source["root"], str(wt))
        self.assertEqual(source["branch"], "preheat")
        self.assertFalse(source["head_is_content_identity"])
        self.assertEqual(result["sha256"], hashlib.sha256((wt / "审核包.md").read_bytes()).hexdigest())
        by_id = self.catalog.read_file("repo", "审核包.md", worktree_id=source["id"])
        self.assertEqual(by_id["text"], result["text"])
        listing = self.catalog.list_files("repo", worktree_id=source["id"])
        self.assertIn("审核包.md", [r["path"] for r in listing["entries"]])
        self.assertEqual(self.catalog.search("repo", "current bytes", worktree_id=source["id"])["matches"][0]["path"], "审核包.md")

    def test_external_worktree_dynamic_appearance_and_removal(self):
        wt = self.add_worktree("outside")
        entry = next(w for w in self.catalog.list_worktrees("repo")["worktrees"] if w["root"] == str(wt))
        self.assertEqual(self.catalog.read_file("repo", "README.md", worktree_id=entry["id"])["text"], "fixture\n")
        self.git(self.root, "worktree", "remove", str(wt))
        with self.assertRaisesRegex(AccessError, "worktree_not_found"):
            self.catalog.read_file("repo", "README.md", worktree_id=entry["id"])

    def test_stable_repository_authorization_reads_after_device_drift(self):
        wt = self.add_worktree("drift")
        entry = next(w for w in self.catalog.list_worktrees("repo")["worktrees"] if w["root"] == str(wt))
        with patch("peters_mcp.workspaces.os.fstat",
                   side_effect=test_workspaces.device_drift_fstat(os.fstat)), \
             patch("peters_mcp.workspaces.os.stat",
                   side_effect=test_workspaces.device_drift_fstat(os.stat)):
            # Source FDs and their path observations belong to the same new
            # runtime. Do not simulate drift only on one side of a source check.
            self.assertEqual(self.catalog.read_file("repo", "README.md", worktree_id=entry["id"])["text"],
                             "fixture\n")

    def test_hidden_untracked_ignored_and_documentation_names_are_readable(self):
        (self.root / ".gitignore").write_text("ignored/\n")
        for relative in (".research/note.md", "ignored/evidence.json", "docs/credentials.md", "docs/secrets-guide.md", ".env.example"):
            p = self.root / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("ordinary evidence")
            self.assertEqual(self.catalog.read_file("repo", relative)["text"], "ordinary evidence")
        matches = self.catalog.search("repo", "ordinary evidence")["matches"]
        self.assertEqual({m["path"] for m in matches}, {".research/note.md", "ignored/evidence.json", "docs/credentials.md", "docs/secrets-guide.md", ".env.example"})

    def test_cache_skipping_is_not_read_denial(self):
        p = self.root / "node_modules/pkg/info.md"
        p.parent.mkdir(parents=True)
        p.write_text("cache marker")
        self.assertEqual(self.catalog.read_file("repo", "node_modules/pkg/info.md")["text"], "cache marker")
        default = self.catalog.search("repo", "cache marker")
        self.assertEqual(default["matches"], [])
        self.assertEqual(default["default_cache_directories_skipped"], 1)
        self.assertTrue(self.catalog.search("repo", "cache marker", include_caches=True)["matches"])

    def test_targeted_authentication_sources_are_blocked(self):
        for relative in (".env", ".env.local", ".docker/config.json", ".config/gcloud/application_default_credentials.json",
                         ".config/gh/hosts.yml", ".ssh/id_rsa"):
            p = self.root / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("sensitive marker")
            with self.subTest(path=relative), self.assertRaisesRegex(AccessError, "sensitive_source"):
                self.catalog.read_file("repo", relative)
        self.assertEqual(self.catalog.search("repo", "sensitive marker")["matches"], [])

    def test_foreign_nested_repo_and_fake_worktree_are_not_readable(self):
        foreign = self.root / "vendor/foreign"
        self.init_repo(foreign)
        with self.assertRaisesRegex(AccessError, "repository_boundary"):
            self.catalog.read_file("repo", "vendor/foreign/README.md")
        wt = self.add_worktree("real", inside=True)
        fake = self.root / ".worktree/fake"
        fake.mkdir()
        (fake / ".git").write_text((wt / ".git").read_text())
        (fake / "README.md").write_text("fake")
        with self.assertRaises(AccessError):
            self.catalog.read_file("repo", ".worktree/fake/README.md")
        (self.root / "link").symlink_to(foreign)
        with self.assertRaises(AccessError):
            self.catalog.read_file("repo", "link/README.md")

    def test_root_fd_is_bound_even_if_path_swap_is_restored(self):
        foreign = self.base / "foreign"
        self.init_repo(foreign)
        (foreign / "README.md").write_text("foreign secret")
        original = os.open
        swapped = False
        def swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.root and not swapped:
                swapped = True
                hold = self.base / "hold"
                self.root.rename(hold)
                foreign.rename(self.root)
                try:
                    fd = original(path, flags, *args, **kwargs)
                finally:
                    self.root.rename(foreign)
                    hold.rename(self.root)
                return fd
            return original(path, flags, *args, **kwargs)
        with patch("peters_mcp.catalog.os.open", side_effect=swapping_open):
            with self.assertRaisesRegex(AccessError, "verified identity"):
                self.catalog.read_file("repo", "README.md")

    def test_project_configuration_changes_are_hot_and_invalidate_file_scope(self):
        config = self.base / "projects.json"
        data = {"projects":[{"id":"repo","name":"Repo","root":str(self.root),"repository_id":self.pin}]}
        config.write_text(json.dumps(data))
        c = Catalog.from_config(config)
        self.assertEqual(c.read_file("repo", "README.md")["text"], "fixture\n")
        data["projects"][0]["exclude"]=["README.md"]
        config.write_text(json.dumps(data))
        with self.assertRaisesRegex(AccessError,"configured_exclusion"):
            c.read_file("repo", "README.md")

    def test_candidates_cannot_target_worktrees_or_survive_policy_revocation(self):
        (self.root / "docs/candidates/chatgpt").mkdir(parents=True)
        config = self.base / "projects.json"
        data = {"projects":[{"id":"repo","name":"Repo","root":str(self.root),"repository_id":self.pin,
                             "candidate_directory":"docs/candidates/chatgpt"}]}
        config.write_text(json.dumps(data))
        c=Catalog.from_config(config);delivery=CandidateDelivery(c)
        args=delivery.prepare_candidate("repo","plan.md","# Candidate")["save_arguments"]
        with self.assertRaises(AccessError):
            delivery.save_candidate(**{**args,"path":".worktree/any/docs/candidates/chatgpt/plan.md"})
        original=os.fsync; changed=False
        def revoke(fd):
            nonlocal changed
            if not changed:
                changed=True
                data["projects"][0]["candidate_directory"]=None
                config.write_text(json.dumps(data))
            return original(fd)
        with patch("peters_mcp.candidates.os.fsync",side_effect=revoke):
            with self.assertRaises(AccessError):delivery.save_candidate(**args)
        self.assertFalse((self.root / "docs/candidates/chatgpt/plan.md").exists())


if __name__ == "__main__":
    unittest.main()
