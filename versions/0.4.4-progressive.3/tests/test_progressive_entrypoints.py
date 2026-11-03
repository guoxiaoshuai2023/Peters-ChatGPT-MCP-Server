"""Entry point boundaries for a disabled-by-default authenticated-only channel."""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class ProgressiveEntrypointTests(unittest.TestCase):
    def test_unauthenticated_local_entry_refuses_enabled_chunked_policy(self):
        from peters_mcp.__main__ import main
        for transport in ('stdio', 'http'):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                repo = root / 'repo'
                repo.mkdir()
                projects = root / 'projects.json'
                projects.write_text(json.dumps({'projects': [{'id': 'synthetic', 'name': 'Synthetic',
                                                               'root': str(repo)}]}))
                policy = root / 'chunked.json'
                policy.write_text(json.dumps({'version': 1, 'enabled': True, 'max_file_bytes': 30_000_000,
                                              'min_free_bytes': 1_073_741_824,
                                              'protocol_version': 'raw-parts-v1'}))
                policy.chmod(0o600)
                error = io.StringIO()
                with patch.object(sys, 'argv', ['local', '--config', str(projects), '--transport', transport,
                                               '--chunked-export-config', str(policy)]), redirect_stderr(error):
                    with self.assertRaises(SystemExit) as caught:
                        main()
                self.assertEqual(caught.exception.code, 2)
                self.assertIn('Invalid or inaccessible configuration', error.getvalue())
                self.assertEqual(sorted(p.name for p in root.iterdir()), ['chunked.json', 'projects.json', 'repo'])

    def test_private_chunked_config_is_validated_even_in_local_check(self):
        from peters_mcp.__main__ import main
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            projects = root / 'projects.json'
            projects.write_text(json.dumps({'projects': [{'id': 'synthetic', 'name': 'Synthetic', 'root': str(root)}]}))
            policy = root / 'chunked.json'
            policy.write_text('{"version":1,"enabled":false,"unexpected":"invalid"}')
            policy.chmod(0o600)
            with patch.object(sys, 'argv', ['check', '--config', str(projects), '--check',
                                           '--chunked-export-config', str(policy)]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main()
            self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
