"""Portable release builder tests use synthetic source trees only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.build_file_release import BuildError, REQUIRED, MARKER, build, verify


class FileReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='file-release-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.selection = sorted(REQUIRED)
        for name in self.selection:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# synthetic portable fixture\n' if name.endswith('.py') else 'Portable documentation\n')
        (self.source / 'peters_mcp/file_jobs.py').write_text('class FileSaveInspector:\n    inspection_only = True\n')
        (self.source / 'peters_mcp/file_config.py').write_text(
            'from ._file_release_mode import INSPECTION_ONLY, REQUIRE_PRIVATE_CONFIG\n'
            'from .file_jobs import FileSaveInspector\n'
            'def load_file_service(path, *, inspection_only=False):\n'
            '    if REQUIRE_PRIVATE_CONFIG and not path:\n'
            '        raise ValueError("explicit_file_config_required")\n'
            '    return FileSaveInspector() if INSPECTION_ONLY or inspection_only else None\n')
        entry = (
            'import argparse, json\n'
            'from .file_config import load_file_service\n'
            'parser = argparse.ArgumentParser()\n'
            'parser.add_argument("--file-config")\n'
            'parser.add_argument("--file-inspection-only", action="store_true")\n'
            'args = parser.parse_args()\n'
            'service = load_file_service(args.file_config, inspection_only=args.file_inspection_only)\n'
            'print(json.dumps({"inspection_only": service is not None}))\n')
        for name in ('__main__.py', 'cloudflare.py'):
            (self.source / 'peters_mcp' / name).write_text(entry)

    def build(self, destination='release', selection=None, **kwargs):
        return build(self.source, self.root / destination, selection or self.selection,
                     snapshot_id='synthetic-1', **kwargs)

    def test_manifest_deterministic_and_modes_have_distinct_complete_fingerprints(self):
        first = self.build('first')
        second = self.build('second')
        self.assertEqual(first, second)
        self.assertNotEqual(first['candidate']['content_fingerprint'], first['rollback']['content_fingerprint'])
        self.assertEqual(first['candidate']['source_content_fingerprint'], first['rollback']['source_content_fingerprint'])
        self.assertEqual(first['rollback']['rollback_mode'], 'inspection-only')
        self.assertFalse(first['rollback']['background_writer_enabled'])
        self.assertTrue(first['rollback']['require_private_config'])
        for mode in first:
            self.assertEqual(verify(self.root / 'first' / mode), first[mode])
            self.assertNotIn(str(self.source), json.dumps(first[mode]))

    def test_runtime_design_tests_and_actual_configs_are_never_copied(self):
        for name in ('ORIGINAL_FILE_SAVE_DESIGN.md', 'projects.json', 'history-access.json',
                     'work/private.json', '.venv/secret', '.git/config', 'tests/private.py'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('PRIVATE_SENTINEL')
        self.build()
        for path in (self.root / 'release').rglob('*'):
            if path.is_file(): self.assertNotIn(b'PRIVATE_SENTINEL', path.read_bytes())
        for name in ('ORIGINAL_FILE_SAVE_DESIGN.md', 'projects.json', 'work/private.json', '.git/config'):
            with self.subTest(name=name), self.assertRaises(BuildError):
                self.build('denied', self.selection + [name])

    def test_traversal_absolute_and_duplicate_selection_are_rejected(self):
        for name in ('../outside.py', '/absolute/file', 'peters_mcp/../file_jobs.py',
                     'peters_mcp//file_jobs.py', 'peters_mcp\\file_jobs.py', MARKER):
            with self.subTest(name=name), self.assertRaises(BuildError):
                self.build(selection=self.selection + [name])
        with self.assertRaises(BuildError): self.build(selection=self.selection + [self.selection[0]])

    def test_selected_symlink_and_hardlink_are_rejected(self):
        target = self.source / 'README.md'
        outside = self.root / 'outside'
        outside.write_text('not portable')
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(BuildError): self.build()
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(BuildError): self.build()

    def test_secrets_personal_paths_and_operator_project_words_fail_without_echo(self):
        secrets = (
            '/Users/synthetic-person/private-repo', '/home/synthetic-person/project',
            '11111111-1111-4111-8111-111111111111',
            'https://synthetic.trycloudflare.com/mcp',
            '-----BEGIN PRIVATE KEY-----', 'ghp_' + 'a' * 32,
            'client_secret = "SYNTHETIC_PRIVATE_VALUE"',
            'https://files.example.invalid/a?sig=SYNTHETIC_PRIVATE_SIGNATURE',
        )
        for value in secrets:
            (self.source / 'README.md').write_text(value)
            with self.subTest(value=value), self.assertRaises(BuildError) as error:
                self.build()
            self.assertNotIn(value, str(error.exception))
            self.assertFalse((self.root / 'release').exists())
        (self.source / 'README.md').write_text('Synthetic Confidential Project')
        with self.assertRaises(BuildError):
            self.build(denied_text=['Synthetic Confidential Project'])

    def test_only_selected_portable_example_is_included(self):
        name = 'original-files.example.json'
        (self.source / name).write_text('{"enabled": false, "control_directory":"/absolute/path/to/service-control"}')
        result = self.build(selection=self.selection + [name])
        self.assertIn(name, [row['path'] for row in result['rollback']['files']])

    def test_inspector_marker_consumer_and_entrypoints_are_required(self):
        cases = [('peters_mcp/file_jobs.py', '# missing inspector\n'),
                 ('peters_mcp/file_config.py', '# missing enforcement\n'),
                 ('peters_mcp/cloudflare.py', '# missing loader\n'),
                 ('peters_mcp/__main__.py', '# missing loader\n')]
        for name, content in cases:
            original = (self.source / name).read_text()
            (self.source / name).write_text(content)
            with self.subTest(name=name), self.assertRaises(BuildError): self.build()
            (self.source / name).write_text(original)

    def test_missing_local_import_must_be_explicitly_selected(self):
        (self.source / 'peters_mcp/private_roots.py').write_text('from .unselected import value\n')
        with self.assertRaises(BuildError): self.build()

    def test_tampering_extra_files_and_removing_protection_module_fail(self):
        self.build()
        root = self.root / 'release' / 'rollback'
        path = root / 'peters_mcp/private_roots.py'
        original = path.read_bytes()
        path.write_text('changed')
        with self.assertRaises(BuildError): verify(root)
        path.write_bytes(original)
        extra = root / 'local-config.json'
        extra.write_text('{}')
        with self.assertRaises(BuildError): verify(root)
        extra.unlink()
        path.unlink()
        with self.assertRaises(BuildError): verify(root)

    def test_build_never_replaces_existing_destination(self):
        self.build()
        before = (self.root / 'release/rollback/manifest.json').read_bytes()
        with self.assertRaises(BuildError): self.build()
        self.assertEqual((self.root / 'release/rollback/manifest.json').read_bytes(), before)

    def test_direct_rollback_entrypoint_cannot_enable_writes_or_omit_protection(self):
        self.build()
        for module in ('peters_mcp', 'peters_mcp.cloudflare'):
            result = subprocess.run([sys.executable, '-B', '-m', module, '--file-config', 'synthetic.json'],
                                    cwd=self.root / 'release/rollback', capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'inspection_only': True})
            result = subprocess.run([sys.executable, '-B', '-m', module],
                                    cwd=self.root / 'release/rollback', capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        result = subprocess.run([sys.executable, '-B', 'run_release.py', '--file-config', 'synthetic.json'],
                                cwd=self.root / 'release/rollback', capture_output=True, text=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {'inspection_only': True})


if __name__ == '__main__':
    unittest.main()
