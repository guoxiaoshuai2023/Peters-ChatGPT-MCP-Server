"""A fresh checkout has no implicit project or history bindings."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


BASE = Path(__file__).resolve().parent.parent


class PortableSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        shutil.copytree(BASE / "peters_mcp", self.checkout / "peters_mcp",
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.project = self.root / "project"
        self.project.mkdir()
        self.config = self.checkout / "projects.json"
        self.config.write_text(json.dumps({"projects": [{
            "id": "example", "name": "Example", "root": str(self.project),
        }]}))
        self.access = self.checkout / "access.local.json"
        self.access.write_text(json.dumps({
            "team_domain": "https://test-team.cloudflareaccess.com", "audience": "a" * 64,
            "public_hostname": "mcp.example.com", "allowed_emails": ["owner@example.com"],
        }))

    def check(self, remote=False, extra=()):
        args = [sys.executable, "-m", "peters_mcp.cloudflare" if remote else "peters_mcp"]
        if remote:
            args += ["--access-config", str(self.access), "--config", str(self.config)]
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        return subprocess.run(args + ["--check", *extra], cwd=self.checkout, env=env,
                              capture_output=True, text=True, timeout=10)

    def test_fresh_checkout_requires_local_project_configuration(self):
        self.config.unlink()
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("projects.example.json", result.stderr)

    def test_project_only_setup_needs_no_codex_installation(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                result = self.check(remote)
                self.assertEqual(result.returncode, 0, result.stderr)
                if not remote:
                    self.assertIn("History policy: disabled", result.stdout)

    def test_explicit_missing_history_policy_does_not_fall_back(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                result = self.check(remote, ["--history-config", str(self.root / "missing.json")])
                self.assertNotEqual(result.returncode, 0)

    def test_invalid_default_history_policy_fails_closed(self):
        (self.checkout / "history-access.json").write_text("{invalid")
        for remote in (False, True):
            with self.subTest(remote=remote):
                self.assertNotEqual(self.check(remote).returncode, 0)

    def test_existing_local_history_policy_is_preserved(self):
        (self.checkout / "history-access.json").write_text(json.dumps({
            "version": 2, "codex_home": str(self.project), "state_db": "state_5.sqlite",
            "inherit_projects": False, "threads": [], "denied_threads": [],
        }))
        for remote in (False, True):
            with self.subTest(remote=remote):
                result = self.check(remote)
                self.assertEqual(result.returncode, 0, result.stderr)
                if not remote:
                    self.assertIn("History policy: configured", result.stdout)


if __name__ == "__main__":
    unittest.main()
