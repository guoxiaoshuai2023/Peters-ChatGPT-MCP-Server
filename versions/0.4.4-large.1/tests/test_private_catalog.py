"""Private filesystem protection remains active independently of write features."""
from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.workspaces import RepositoryRegistry


def _late_catalog(control, spool, parent_root, channel):
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    catalog = Catalog([Project('parent', 'Parent', Path(parent_root))], private_registry=registry)
    catalog.list_projects()
    channel.send('started')
    channel.recv()
    try:
        catalog.read_file('parent', 'spool/synthetic.txt')
    except AccessError as error:
        channel.send(error.code)
    else:
        channel.send('unsafe')
    channel.close()


class PrivateCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='private-catalog-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.base / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        self.registry.initialize()
        (self.base / 'ordinary.txt').write_text('ordinary synthetic content')
        self.catalog = Catalog([Project('parent', 'Parent', self.base)], private_registry=self.registry)

    def activate(self):
        # Activation precedes the grants used below; read_roots is service-side.
        self.registry.register_pending(self.spool, read_roots=[])
        self.registry.activate(self.spool, read_roots=[])
        (self.spool / 'synthetic.txt').write_text('PRIVATE_SYNTHETIC_CONTENT')

    def assert_private(self, fn):
        with self.assertRaises(AccessError) as error:
            fn()
        self.assertEqual(error.exception.code, 'private_path')

    def test_later_grant_of_parent_cannot_list_search_or_read_private_root(self):
        self.activate()
        catalog = Catalog([Project('parent', 'Parent', self.base),
                           Project('direct', 'PRIVATE_PROJECT_NAME', self.spool)], private_registry=self.registry)
        listing = catalog.list_files('parent')
        self.assertNotIn('spool', json.dumps(listing))
        self.assertNotIn('control', json.dumps(listing))
        self.assertEqual(catalog.search('parent', 'PRIVATE_SYNTHETIC_CONTENT')['matches'], [])
        self.assertNotIn('PRIVATE_PROJECT_NAME', json.dumps(catalog.list_projects()))
        self.assert_private(lambda: catalog.read_file('parent', 'spool/synthetic.txt'))
        self.assert_private(lambda: catalog.list_files('direct'))
        self.assert_private(lambda: catalog.list_worktrees('direct'))
        self.assertIn('ordinary', catalog.read_file('parent', 'ordinary.txt')['text'])

    def test_refresh_retains_registry_binding_and_new_direct_grant_is_hidden(self):
        self.activate()
        config = self.base / 'projects.json'
        def save(root):
            config.write_text(json.dumps({'projects': [{'id': 'selected', 'name': 'Synthetic', 'root': str(root)}]}))
        save(self.base)
        catalog = Catalog.from_config(config, private_registry=self.registry)
        self.assertEqual(len(catalog.list_projects()['projects']), 1)
        save(self.spool)
        self.assertEqual(catalog.list_projects()['projects'], [])
        self.assertIs(catalog._private_registry, self.registry)
        self.assert_private(lambda: catalog.read_file('selected', 'synthetic.txt'))

    def test_unknown_or_corrupt_manifest_closes_all_generic_tools(self):
        manifest = self.control / 'private-roots.json'
        for raw in ('not-json', ''):
            manifest.write_text(raw)
            for fn in (self.catalog.list_projects,
                       lambda: self.catalog.list_worktrees('parent'),
                       lambda: self.catalog.list_files('parent'),
                       lambda: self.catalog.search('parent', 'ordinary'),
                       lambda: self.catalog.read_file('parent', 'ordinary.txt')):
                with self.assertRaises(AccessError) as error:
                    fn()
                self.assertEqual(error.exception.code, 'private_protection_unavailable')
        manifest.unlink()
        with self.assertRaises(AccessError): self.catalog.list_projects()

    def test_parts_and_open_path_hold_standalone_guards(self):
        self.activate()
        project = self.catalog.project('parent')
        self.assertEqual(self.catalog.parts(project, 'ordinary.txt'), ('ordinary.txt',))
        self.assert_private(lambda: self.catalog.parts(project, 'spool/synthetic.txt'))
        with self.assertRaises(AccessError) as error:
            with self.catalog.open_path(project, ('spool', 'synthetic.txt')): pass
        self.assertEqual(error.exception.code, 'private_path')
        with self.catalog.open_path(project, ('ordinary.txt',)) as fd:
            self.registry.check_path(self.base / 'ordinary.txt')
            self.assertTrue(os.read(fd, 10))
        with self.assertRaises(AccessError): self.registry.check_path(self.base / 'ordinary.txt')
        with self.registry.read_guard():
            self.assertIn('ordinary', self.catalog.read_file('parent', 'ordinary.txt')['text'])

    def test_result_building_is_guarded_in_actual_executor_thread(self):
        original = self.catalog._readback_scope
        observed = []
        def finish(*args):
            self.registry.check_path(self.base / 'ordinary.txt')
            observed.append(threading.get_ident())
            return original(*args)
        with patch.object(self.catalog, '_readback_scope', side_effect=finish):
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(self.catalog.read_file, 'parent', 'ordinary.txt').result(timeout=5)
        self.assertIn('ordinary', result['text'])
        self.assertNotEqual(observed[0], threading.get_ident())
        self.assertIsNone(getattr(self.registry._local, 'guard', None))

    def test_private_identity_replacement_before_and_after_read_fails_closed(self):
        self.activate()
        original = self.catalog._readback_scope
        def replace_root(*args):
            result = original(*args)
            self.spool.rename(self.base / 'held-spool')
            self.spool.mkdir(mode=0o700)
            return result
        with patch.object(self.catalog, '_readback_scope', side_effect=replace_root):
            with self.assertRaises(AccessError) as error:
                self.catalog.read_file('parent', 'ordinary.txt')
        self.assertEqual(error.exception.code, 'private_protection_unavailable')
        with self.assertRaises(AccessError): self.catalog.list_files('parent')

    def test_direct_protected_root_open_rejected_even_with_empty_parts(self):
        self.activate()
        project = Project('private', 'Private', self.spool)
        self.assert_private(lambda: self.catalog.parts(project, '', allow_root=True))
        with self.assertRaises(AccessError):
            with self.catalog.open_path(project, (), directory=True): pass

    def test_registry_cannot_be_detached_or_replaced(self):
        self.catalog.set_private_registry(self.registry)
        with self.assertRaises(AccessError): self.catalog.set_private_registry(None)
        other = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        with self.assertRaises(AccessError): self.catalog.set_private_registry(other)

    def test_unbound_catalog_keeps_existing_behavior(self):
        self.activate()
        catalog = Catalog([Project('parent', 'Parent', self.base)])
        self.assertIn('PRIVATE_SYNTHETIC_CONTENT', catalog.read_file('parent', 'spool/synthetic.txt')['text'])

    def test_external_registered_worktree_uses_its_actual_root_for_protection(self):
        repo = self.base / 'repo'
        repo.mkdir()
        def git(*args):
            subprocess.run(['/usr/bin/git', '-C', str(repo), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        git('init', '-q')
        git('-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
            'commit', '--allow-empty', '-qm', 'fixture')
        external = self.base / 'external'
        git('worktree', 'add', '--detach', '-q', str(external), 'HEAD')
        private = external / 'private'
        registry = PrivateRootRegistry(self.control, allowed_roots=[private])
        registry.register_pending(private, read_roots=[])
        registry.activate(private, read_roots=[])
        (private / 'synthetic.txt').write_text('PRIVATE_SYNTHETIC_CONTENT')
        (external / 'ordinary.txt').write_text('external normal')
        catalog = Catalog([Project('repo', 'Repo', repo, repository_id=RepositoryRegistry.identity(repo))], private_registry=registry)
        member = next(row['id'] for row in catalog.list_worktrees('repo')['worktrees'] if not row['is_default'])
        self.assert_private(lambda: catalog.read_file('repo', 'private/synthetic.txt', worktree_id=member))
        self.assertNotIn('private', json.dumps(catalog.list_files('repo', worktree_id=member)['entries']))
        self.assertEqual(catalog.search('repo', 'PRIVATE', worktree_id=member)['matches'], [])
        self.assertEqual(catalog.read_file('repo', 'ordinary.txt', worktree_id=member)['text'], 'external normal')

    def test_new_registered_worktree_root_inside_protection_is_not_disclosed(self):
        self.registry.register_pending(self.spool, read_roots=[])
        self.registry.activate(self.spool, read_roots=[])
        repo = self.base / 'repo'
        repo.mkdir()
        def git(*args):
            subprocess.run(['/usr/bin/git', '-C', str(repo), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        git('init', '-q')
        git('-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
            'commit', '--allow-empty', '-qm', 'fixture')
        # Simulate a subsequently registered worktree containing a retained
        # protected root. Generic discovery must not publish its path or ID.
        git('worktree', 'add', '--detach', '-q', str(self.spool), 'HEAD')
        catalog = Catalog([Project('repo', 'Repo', repo, repository_id=RepositoryRegistry.identity(repo))],
                          private_registry=self.registry)
        raw = catalog.repositories.discover('repo')
        member = next(row['id'] for row in raw['worktrees'] if not row['is_default'])
        result = catalog.list_worktrees('repo')
        self.assertEqual([row['id'] for row in result['worktrees']], ['main'])
        self.assertNotIn(member, json.dumps(result))
        self.assertNotIn(str(self.spool), json.dumps(result))
        self.assert_private(lambda: catalog.list_files('repo', worktree_id=member))

    def test_late_process_reloads_protection_before_next_generic_read(self):
        parent, child = multiprocessing.get_context('spawn').Pipe()
        process = multiprocessing.get_context('spawn').Process(target=_late_catalog,
                         args=(self.control, self.spool, self.base, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(5))
            self.assertEqual(parent.recv(), 'started')
            self.activate()
            parent.send('next')
            self.assertTrue(parent.poll(5))
            self.assertEqual(parent.recv(), 'private_path')
        finally:
            parent.close()
            process.join(5)
            if process.is_alive(): process.terminate(); process.join(5)
            self.assertFalse(process.is_alive())
            process.close()

    def test_activation_waits_through_complete_result_construction(self):
        reached = threading.Event()
        release = threading.Event()
        attempted = threading.Event()
        activated = threading.Event()
        original = self.catalog._readback_scope
        def finish(*args):
            result = original(*args)
            reached.set()
            if not release.wait(3): raise AssertionError('Synthetic barrier not released')
            return result
        def activate():
            attempted.set()
            self.activate()
            activated.set()
        with patch.object(self.catalog, '_readback_scope', side_effect=finish):
            with ThreadPoolExecutor(max_workers=2) as pool:
                reader = pool.submit(self.catalog.read_file, 'parent', 'ordinary.txt')
                self.assertTrue(reached.wait(3))
                publisher = pool.submit(activate)
                self.assertTrue(attempted.wait(3))
                self.assertFalse(activated.wait(.1))
                release.set()
                self.assertIn('ordinary', reader.result(timeout=5)['text'])
                publisher.result(timeout=5)
        self.assertTrue(activated.is_set())
        self.assert_private(lambda: self.catalog.read_file('parent', 'spool/synthetic.txt'))


if __name__ == '__main__':
    unittest.main()
