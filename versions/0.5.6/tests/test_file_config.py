"""Synthetic configuration/bootstrap boundaries; never load real local config."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_config import load_file_service, read_file_config
from peters_mcp.file_setup import bootstrap_file_service
from peters_mcp.workspaces import RepositoryRegistry


class FileConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-config-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'; self.repo.mkdir()
        self.catalog = Catalog([Project('demo', 'Synthetic', self.repo)])
        self.path = self.base / 'files.json'
        self.control, self.spool = self.base / 'control', self.base / 'spool'
        self.data = {'version': 1, 'enabled': False, 'control_directory': str(self.control),
                     'spool_roots': [str(self.spool)], 'sources': {'files.example.test': ['8.8.8.8']},
                     'special_exceptions': [], 'min_free_bytes': 1048576, 'max_workers': 2}
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)

    def bootstrap(self):
        return bootstrap_file_service(self.path, self.catalog)

    def snapshot(self):
        return {str(p.relative_to(self.base)): (stat.S_IMODE(p.lstat().st_mode),
                hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                for p in self.base.rglob('*')}

    def test_development_no_path_does_not_discover_defaults_or_construct_service(self):
        (self.base / 'delivery-access.json').write_text('not enabled by discovery')
        with patch('peters_mcp.file_config._release_mode', return_value=(False, False)), \
             patch('peters_mcp.file_config._make_writer') as writer, \
             patch('peters_mcp.file_config._make_inspector') as inspector:
            self.assertEqual(load_file_service(None, self.catalog), (None, None))
            writer.assert_not_called(); inspector.assert_not_called()
        self.assertFalse(self.control.exists())

    def test_config_inside_history_home_rejected_before_bootstrap_mutation(self):
        home=self.base/'synthetic-history';home.mkdir()
        self.path=home/'files.json';self.save()
        history=SimpleNamespace(_configuration=lambda:{'home':home})
        with self.assertRaisesRegex(AccessError,'private_root_overlap'):
            bootstrap_file_service(self.path,self.catalog,history)
        self.assertFalse(self.control.exists())
        self.assertFalse(self.spool.exists())

    def test_configured_history_tree_is_not_a_new_file_write_target(self):
        home=self.repo/'custom-history-data';home.mkdir()
        history=SimpleNamespace(_configuration=lambda:{'home':home},config_path=self.base/'history.json')
        bootstrap_file_service(self.path,self.catalog,history)
        registry,service=load_file_service(self.path,self.catalog,history,inspection_only=True)
        self.addCleanup(service.close)
        with registry.read_guard(), self.assertRaisesRegex(AccessError,'protected_path'):
            service.targets.inspect('demo','main','custom-history-data/new-record.jsonl')

    def test_release_requires_private_configuration_even_when_inspection_requested(self):
        for inspection in (True, False):
            with self.subTest(inspection=inspection), \
                 patch('peters_mcp.file_config._release_mode', return_value=(inspection, True)), \
                 self.assertRaisesRegex(AccessError, 'private_config_required'):
                load_file_service(None, self.catalog, inspection_only=True)

    def test_unknown_fields_and_write_slot_lists_are_not_configuration(self):
        for name in ('targets', 'write_worktrees', 'allow_any_url', 'access_token', 'legacy_zip'):
            self.data[name] = []
            self.save()
            with self.subTest(name=name), self.assertRaises(AccessError):
                read_file_config(self.path)
            del self.data[name]
        self.assertFalse(self.control.exists())

    def test_duplicate_json_fields_are_rejected(self):
        self.path.write_text(json.dumps(self.data)[:-1] + ',"enabled":true}')
        with self.assertRaises(AccessError): read_file_config(self.path)

    def test_strict_types_sources_and_no_private_or_wildcard_policy(self):
        invalid = [('* .example.test', None), ('*.example.test', None),
                   ('https://files.example.test', None), ('files.example.test', ['127.0.0.1']),
                   ('files.example.test', ['8.8.8.8', '198.18.0.1']),
                   ('files.example.test', ['169.254.169.254']),
                   ('files.example.test', ['::ffff:8.8.8.8']), ('files.example.test', [134744072])]
        for host, addresses in invalid:
            self.data['sources'] = {host: addresses}; self.save()
            with self.subTest(host=host, addresses=addresses), self.assertRaises(AccessError):
                read_file_config(self.path)
        self.data['sources'] = {'files.example.test': None}
        for field, value in [('version', True), ('enabled', 1), ('max_workers', True),
                             ('max_workers', 5), ('min_free_bytes', -1), ('spool_roots', 'a')]:
            original = self.data[field]; self.data[field] = value; self.save()
            with self.subTest(field=field), self.assertRaises(AccessError):
                read_file_config(self.path)
            self.data[field] = original

    def test_special_exceptions_are_exact_triples_not_scope_grants(self):
        self.data['special_exceptions'] = [{'project_id': 'demo', 'worktree_id': 'main', 'path': 'AGENTS.md'}]
        self.save()
        self.assertEqual(read_file_config(self.path).special_exceptions, (('demo', 'main', 'AGENTS.md'),))
        self.data['special_exceptions'][0]['path'] = '../AGENTS.md'; self.save()
        with self.assertRaises(AccessError): read_file_config(self.path)

    def test_runtime_load_missing_state_never_mkdir_or_initialize(self):
        for enabled in (False, True):
            self.data['enabled'] = enabled; self.save()
            before = self.snapshot()
            with self.subTest(enabled=enabled), patch('peters_mcp.file_config._make_writer') as writer, \
                 self.assertRaises(AccessError):
                load_file_service(self.path, self.catalog)
            writer.assert_not_called()
            self.assertEqual(self.snapshot(), before)

    def test_bootstrap_creates_only_configured_roots_and_never_jobs_database(self):
        registry = self.bootstrap()
        self.assertEqual(stat.S_IMODE(self.control.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.spool.stat().st_mode), 0o700)
        self.assertEqual({p.name for p in self.control.iterdir()}, {'private-roots.json', 'private-roots.lock'})
        with registry.read_guard() as guard:
            self.assertEqual(guard._manifest['roots'][0]['status'], 'active')
        with self.assertRaises(AccessError):
            registry.register_pending(self.base / 'unconfigured', read_roots=[])
        self.assertFalse((self.base / 'unconfigured').exists())

    def test_disabled_inspector_retains_protection_without_writer_or_mkdir(self):
        self.bootstrap()
        before = self.snapshot()
        with patch('peters_mcp.file_config._make_writer') as writer, patch('os.mkdir', side_effect=AssertionError('mkdir')):
            registry, inspector = load_file_service(self.path, self.catalog)
            try:
                self.assertTrue(inspector.inspection_only)
                self.assertFalse(inspector.capabilities('a' * 64)['write_enabled'])
                with self.assertRaisesRegex(AccessError, 'job_not_found'):
                    inspector.status('a' * 64, request_key='unknown')
            finally:
                inspector.close()
            writer.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertIs(self.catalog._private_registry, registry)
        with registry.read_guard() as guard:
            for path in (self.control / 'unknown', self.spool / 'unknown', self.path):
                with self.assertRaises(AccessError): guard.check_path(path)

    def test_inspection_flag_and_release_marker_cannot_construct_writer(self):
        self.bootstrap(); self.data['enabled'] = True; self.save()
        for marker, flag in ((True, False), (False, True)):
            with self.subTest(marker=marker, flag=flag), \
                 patch('peters_mcp.file_config._release_mode', return_value=(marker, True)), \
                 patch('peters_mcp.file_config._make_writer') as writer:
                _, inspector = load_file_service(self.path, self.catalog, inspection_only=flag)
                self.assertTrue(inspector.inspection_only); inspector.close()
                writer.assert_not_called()

    def test_enabled_factory_receives_hot_sources_and_scope_is_inherited(self):
        self.bootstrap(); self.data['enabled'] = True; self.save()
        with patch('peters_mcp.file_config._make_writer', return_value=SimpleNamespace()) as writer:
            registry, service = load_file_service(self.path, self.catalog)
        args, kwargs = writer.call_args
        self.assertIs(args[0], self.catalog)
        self.assertIs(args[1], registry)
        self.assertEqual(args[3](), {'files.example.test': ['8.8.8.8']})
        self.assertNotIn('targets', kwargs)
        self.data['sources']['extra.example.test'] = None; self.save()
        self.assertIn('extra.example.test', args[3]())
        self.data['sources']['extra.example.test'] = ['127.0.0.1']; self.save()
        with self.assertRaises(AccessError): args[3]()
        self.data['sources']['extra.example.test'] = None
        self.data['enabled'] = False; self.save()
        with self.assertRaisesRegex(AccessError, 'write_not_enabled'): args[3]()
        self.data['enabled'] = True; self.data['special_exceptions'] = [
            {'project_id': 'demo', 'worktree_id': 'main', 'path': 'AGENTS.md'}]
        self.save()
        with self.assertRaisesRegex(AccessError, 'file_config_changed'): args[3]()

    def test_config_file_itself_hidden_from_later_generic_project_reads(self):
        self.bootstrap()
        self.catalog.projects['broader'] = Project('broader', 'Later root', self.base)
        self.catalog.repositories.projects = self.catalog.projects
        with self.assertRaisesRegex(AccessError, 'private_path'):
            self.catalog.read_file('broader', 'files.json')
        listing = self.catalog.list_files('broader')
        self.assertNotIn('files.json', [entry['path'] for entry in listing['entries']])
        self.assertFalse(self.catalog.search('broader', 'sources')['matches'])

    def test_control_and_spools_cannot_overlap_repo_or_each_other(self):
        for control, spool in ((self.repo / 'control', self.spool), (self.control, self.repo / 'spool'),
                               (self.base, self.spool), (self.control, self.control / 'nested')):
            self.data.update(control_directory=str(control), spool_roots=[str(spool)]); self.save()
            with self.subTest(control=control, spool=spool), self.assertRaises(AccessError):
                bootstrap_file_service(self.path, self.catalog)
        self.assertFalse((self.repo / 'control').exists())
        self.assertFalse((self.repo / 'spool').exists())

    def test_external_worktree_blocks_spool_bootstrap(self):
        def git(*args):
            subprocess.run(['/usr/bin/git', '-C', str(self.repo), '-c', 'core.hooksPath=/dev/null',
                            '-c', 'commit.gpgsign=false', '-c', 'user.name=Synthetic',
                            '-c', 'user.email=synthetic@example.test', *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git('init', '-q'); git('commit', '--allow-empty', '-qm', 'fixture')
        external = self.base / 'external'; git('worktree', 'add', '-q', '--detach', str(external))
        self.catalog = Catalog([Project('demo', 'Synthetic', self.repo,
                                       repository_id=RepositoryRegistry.identity(self.repo))])
        self.data['spool_roots'] = [str(external / 'spool')]; self.save()
        with self.assertRaisesRegex(AccessError, 'private_root_overlap'):
            bootstrap_file_service(self.path, self.catalog)
        self.assertFalse(self.control.exists()); self.assertFalse((external / 'spool').exists())

    def test_history_home_bidirectional_overlap_refused_before_mutation(self):
        home = self.base / 'synthetic-codex'; home.mkdir()
        history = SimpleNamespace(_configuration=lambda: {'home': home})
        for root in (home, home / 'spool', self.base):
            self.data['spool_roots'] = [str(root)]; self.save()
            with self.subTest(root=root), self.assertRaises(AccessError):
                bootstrap_file_service(self.path, self.catalog, history)
        self.assertFalse(self.control.exists())

    def test_existing_broad_or_incomplete_state_is_not_chmoded_or_reset(self):
        self.control.mkdir(mode=0o755)
        with self.assertRaises(AccessError): self.bootstrap()
        self.assertEqual(stat.S_IMODE(self.control.stat().st_mode), 0o755)
        self.control.chmod(0o700)
        with self.assertRaises(AccessError): self.bootstrap()
        self.assertEqual(list(self.control.iterdir()), [])
        marker = self.control / 'private-roots.lock'; marker.write_bytes(b'prior')
        before = self.snapshot()
        with self.assertRaises(AccessError): self.bootstrap()
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_existing_manifest_is_never_reinitialized(self):
        self.bootstrap()
        manifest = self.control / 'private-roots.json'; manifest.write_text('{broken')
        before = self.snapshot()
        with self.assertRaises(AccessError): self.bootstrap()
        with self.assertRaises(AccessError): load_file_service(self.path, self.catalog)
        self.assertEqual(self.snapshot(), before)

    def test_existing_initialized_setup_is_idempotent(self):
        first = self.bootstrap()
        before = self.snapshot()
        self.assertIs(self.bootstrap(), first)
        self.assertEqual(self.snapshot(), before)

    def test_retained_roots_cannot_hide_history_overlap_after_config_removal(self):
        self.bootstrap()
        self.data['spool_roots'] = []; self.save()
        fresh_catalog = Catalog([Project('demo', 'Synthetic', self.repo)])
        history = SimpleNamespace(_configuration=lambda: {'home': self.spool})
        before = self.snapshot()
        with self.assertRaisesRegex(AccessError, 'private_root_overlap'):
            bootstrap_file_service(self.path, fresh_catalog, history)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
