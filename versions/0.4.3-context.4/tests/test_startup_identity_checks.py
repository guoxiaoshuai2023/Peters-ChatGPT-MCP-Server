"""Check mode diagnoses failed authorization pins before constructing workers."""
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.cloudflare import main


class StartupIdentityTests(unittest.TestCase):
    def test_check_rejects_wrong_repository_pin_without_runtime_writes(self):
        with tempfile.TemporaryDirectory(prefix='startup-identity-') as name:
            root = Path(name).resolve()
            project = root / 'project'
            project.mkdir()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(project)], check=True, capture_output=True)
            access = root / 'access.json'
            access.write_text(json.dumps({'team_domain': 'https://test-team.cloudflareaccess.com',
                'audience': 'a' * 64, 'public_hostname': 'mcp.example.com', 'allowed_emails': ['owner@example.com']}))
            projects = root / 'projects.json'
            projects.write_text(json.dumps({'projects': [{'id': 'synthetic', 'name': 'Synthetic',
                'root': str(project), 'repository_id': 'git-v2-' + '0' * 64}]}))
            before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in root.rglob('*') if p.is_file()}
            error = io.StringIO()
            with patch.object(sys, 'argv', ['check', '--access-config', str(access), '--config', str(projects), '--check']), redirect_stderr(error):
                with self.assertRaises(SystemExit) as caught:
                    main()
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('repository_pin_mismatch', error.getvalue())
            self.assertIn('"stage": "catalog"', error.getvalue())
            self.assertNotIn('owner@example.com', error.getvalue())
            after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
