"""Synthetic source, worktree and bounded-cache behavioral regressions."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import replace
import hashlib
import errno
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_context import ExportActor
from peters_mcp.file_discovery import FileDiscovery, FileSources, SourceScope
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.workspaces import RepositoryRegistry
from tests import test_workspaces


class Clock:
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-discovery-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'project'
        self.root.mkdir()
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.base / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        self.registry.initialize()
        self.registry.register_pending(self.spool, read_roots=[self.root])
        self.registry.activate(self.spool, read_roots=[self.root])
        self.catalog = Catalog([Project('project', 'Synthetic', self.root)], private_registry=self.registry)
        self.wall, self.mono = Clock(1000), Clock()
        self.actor = ExportActor(hashlib.sha256(b'actor-a').hexdigest(), 2000, 1000)
        self.lock = threading.RLock()
        self.policy = 'enabled-profile-1'
        self.sources = FileSources(self.catalog, wall_clock=self.wall, monotonic=self.mono,
                                   policy_check=self.check_policy)
        self.discovery = self.discover()

    def check_policy(self):
        self.assertFalse(self.lock._is_owned(), 'Policy IO must not hold the manager lock')
        return self.policy

    def discover(self, **kwargs):
        return FileDiscovery(self.sources, lock=self.lock, instance_id='synthetic-instance',
                             monotonic=self.mono, **kwargs)

    def write(self, relative, data=b'opaque synthetic original'):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def find(self, **kwargs):
        return self.discovery.find(self.actor, 'project', 'main', **kwargs)

    def populate(self, count=4):
        for n in range(count):
            self.write(f'file-{n}.zip')

    def test_binary_and_readable_rules_are_shared_without_write_only_denies(self):
        ordinary = {'build/result.zip', 'dist/scene.png', 'data/app.db', 'data/app.db-wal',
                    'unknown.asset', 'AGENTS.md', '.github/workflows/ci.yml', '.codex/settings.json'}
        blocked = {'.codex/state_5.sqlite', '.codex/state_5.sqlite-wal', '.codex/state_5.sqlite-shm',
                   '.codex/state_5.sqlite-journal', '.codex/sessions/raw.jsonl',
                   '.config/gcloud/credentials.db-wal', '.config/gcloud/access_tokens.db-shm',
                   '.config/gcloud/credentials.db-journal', '.env', '.ssh/id_rsa'}
        for name in ordinary | blocked:
            self.write(name)
        result = self.find()
        self.assertEqual({r['path'] for r in result['files']}, ordinary)
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            for name in blocked:
                with self.subTest(path=name), self.assertRaises(AccessError):
                    scope.inspect(name)
            ref = scope.inspect('unknown.asset')
            self.assertEqual(ref.mime_basis, 'filename_guess')
            self.assertEqual(ref.mime_type, 'application/octet-stream')
            self.assertNotIn(str(self.base), json.dumps(ref.public()))

    def test_no_private_registry_no_reads_and_expired_actor_no_metadata(self):
        self.write('public.zip')
        no_registry = FileSources(Catalog([Project('p', 'Synthetic', self.root)]),
                                  wall_clock=self.wall, monotonic=self.mono)
        with self.assertRaisesRegex(AccessError, 'private_protection_unavailable'):
            with no_registry.scope(self.actor, 'p', 'main'):
                pass
        expired = replace(self.actor, deadline=0)
        with self.assertRaisesRegex(AccessError, 'authentication_required'):
            self.discovery.find(expired, 'project', 'main')

    def test_fixed_startup_paths_and_symlink_alias_are_not_discovered(self):
        private = self.write('private/state.bin')
        alias = self.base / 'trusted-alias'
        alias.symlink_to(private.parent, target_is_directory=True)
        sources = FileSources(self.catalog, protected_paths=[alias], wall_clock=self.wall, monotonic=self.mono)
        discovery = FileDiscovery(sources, lock=self.lock, instance_id='protected', monotonic=self.mono)
        self.write('ordinary.db')
        self.assertEqual([r['path'] for r in discovery.find(self.actor, 'project', 'main')['files']], ['ordinary.db'])
        with sources.scope(self.actor, 'project', 'main') as scope:
            with self.assertRaisesRegex(AccessError, 'private_path'):
                scope.inspect('private/state.bin')

    def test_regular_single_link_and_component_no_follow(self):
        original = self.write('one.zip')
        os.link(original, self.root / 'hard.zip')
        (self.root / 'link.zip').symlink_to(original)
        self.write('dir/body.zip')
        (self.root / 'alias-dir').symlink_to(self.root / 'dir', target_is_directory=True)
        os.mkfifo(self.root / 'fifo.zip')
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            for name in ('one.zip', 'hard.zip', 'link.zip', 'fifo.zip', 'alias-dir/body.zip'):
                with self.subTest(path=name), self.assertRaises(AccessError):
                    with scope.open_file(name):
                        pass
            for name in ('../body.zip', '/etc/passwd', 'a\\b', 'dir/../body.zip'):
                with self.subTest(path=name), self.assertRaises(AccessError):
                    scope.inspect(name)

    def test_source_scope_does_not_treat_changed_bytes_as_revocation(self):
        source = self.write('plain.bin', b'first')
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            before = scope.inspect('plain.bin')
            source.write_bytes(b'new ordinary bytes')
            self.assertEqual(scope.revalidate(), before.scope_key)
            self.assertNotEqual(scope.inspect('plain.bin').version, before.version)
            with scope.open_file('plain.bin') as fd:
                self.assertEqual(os.read(fd, 64), b'new ordinary bytes')

    def test_close_failure_is_fixed_pending_and_never_retries_descriptor(self):
        self.write('nested/original.zip')
        original_close = os.close
        borrowed, calls = [None], []
        def closing(fd):
            if fd == borrowed[0]:
                calls.append(fd)
                original_close(fd)
                raise OSError(errno.EIO, 'synthetic-private-raw-error')
            return original_close(fd)
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            with patch('os.close', closing):
                with self.assertRaisesRegex(AccessError, 'source_cleanup_pending') as error:
                    with scope.open_file('nested/original.zip') as fd:
                        borrowed[0] = fd
            self.assertEqual(calls, borrowed)
            self.assertNotIn('synthetic-private-raw-error', str(error.exception))

    def test_intermediate_parent_close_error_still_closes_known_child(self):
        self.write('nested/original.zip')
        from peters_mcp import file_discovery
        original = file_discovery._close_owned
        calls = []
        def failing(fd):
            calls.append(fd)
            if len(calls) == 1:
                original(fd)
                raise AccessError('Fixed cleanup failure.', code='source_cleanup_pending')
            original(fd)
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            with patch('peters_mcp.file_discovery._close_owned', failing):
                with self.assertRaisesRegex(AccessError, 'source_cleanup_pending'):
                    with scope.open_file('nested/original.zip'):
                        pass
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0], calls[1])

    def test_discovery_does_not_omit_cleanup_failure_as_policy_exclusion(self):
        self.write('original.zip')
        from peters_mcp import file_discovery
        original = file_discovery._close_owned
        calls = []
        def failing(fd):
            calls.append(fd)
            original(fd)
            if len(calls) == 2:
                raise AccessError('Fixed cleanup failure.', code='source_cleanup_pending')
        with patch('peters_mcp.file_discovery._close_owned', failing):
            with self.assertRaisesRegex(AccessError, 'source_cleanup_pending'):
                self.find()
        self.assertEqual(self.discovery.diagnostics()['cache_count'], 0)

    def test_guard_ownership_and_final_revalidation(self):
        self.write('one.zip')
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            with ThreadPoolExecutor(max_workers=1) as pool:
                error = pool.submit(scope.inspect, 'one.zip').exception()
            self.assertIsInstance(error, AccessError)
            self.assertEqual(error.code, 'private_protection_unavailable')
        with self.assertRaises(AccessError):
            scope.inspect('one.zip')
        with self.assertRaisesRegex(AccessError, 'scope_changed'):
            with self.sources.scope(self.actor, 'project', 'main'):
                self.policy = 'disabled-profile'

    def test_root_replacement_and_rogue_manifest_update_close_scope(self):
        self.write('one.zip')
        with self.assertRaisesRegex(AccessError, 'scope_changed'):
            with self.sources.scope(self.actor, 'project', 'main') as scope:
                self.root.rename(self.base / 'old-root')
                self.root.mkdir()
                self.write('one.zip', b'replacement')
                scope.revalidate()
        manifest = self.control / 'private-roots.json'
        with self.assertRaisesRegex(AccessError, 'private_protection_unavailable'):
            with self.sources.scope(self.actor, 'project', 'main') as scope:
                manifest.write_text('corrupt synthetic manifest')
                scope.revalidate()

    def test_discovery_never_opens_file_bodies(self):
        self.write('archive.zip', b'\x00\xffbinary')
        with patch.object(SourceScope, 'open_file', side_effect=AssertionError('no body opens')):
            found = self.find(name_pattern='*.zip', extensions=['.ZIP'])
        self.assertEqual(found['files'][0]['bytes'], 8)

    def test_root_alias_and_cursor_input_types(self):
        self.write('original.zip')
        self.assertEqual(self.find(directory='.')['files'], self.find(directory='')['files'])
        for cursor in (0, [], None):
            with self.subTest(cursor=cursor), self.assertRaises(AccessError):
                self.find(cursor=cursor)

    def test_source_guard_drains_before_coordinated_root_activation(self):
        self.write('ordinary.zip')
        additional = self.base / 'additional-private'
        coordinator = PrivateRootRegistry(self.control, allowed_roots=[self.spool, additional])
        entered = threading.Event()
        def register():
            entered.set()
            coordinator.register_pending(additional, read_roots=[self.root])
            return coordinator.activate(additional, read_roots=[self.root])
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.sources.scope(self.actor, 'project', 'main') as scope:
                future = pool.submit(register)
                self.assertTrue(entered.wait(2))
                with self.assertRaises(TimeoutError):
                    future.result(timeout=0.1)
                self.assertEqual(scope.inspect('ordinary.zip').size, len(b'opaque synthetic original'))
            self.assertEqual(future.result(timeout=2)['status'], 'active')

    def test_pagination_binding_replay_and_non_sliding_ttl(self):
        self.populate()
        first = self.find(limit=1)
        cursor = first['next_cursor']
        other = replace(self.actor, key=hashlib.sha256(b'actor-b').hexdigest())
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            self.discovery.find(other, 'project', 'main', limit=1, cursor=cursor)
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            self.find(name_pattern='*.zip', limit=1, cursor=cursor)
        second = self.find(limit=1, cursor=cursor)
        self.assertEqual(second, self.find(limit=1, cursor=cursor))
        self.mono.value = 100
        self.find(limit=1, cursor=cursor)
        self.mono.value = 121
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            self.find(limit=1, cursor=cursor)
        self.assertEqual(self.discovery.diagnostics()['cache_count'], 0)
        restarted = self.discover()
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            restarted.find(self.actor, 'project', 'main', limit=1, cursor=cursor)

    def test_hot_exclusion_and_cached_link_never_return_old_metadata(self):
        config = self.base / 'projects.json'
        data = {'projects': [{'id': 'project', 'name': 'Synthetic', 'root': str(self.root)}]}
        config.write_text(json.dumps(data))
        catalog = Catalog.from_config(config, private_registry=self.registry)
        sources = FileSources(catalog, wall_clock=self.wall, monotonic=self.mono)
        discovery = FileDiscovery(sources, lock=self.lock, instance_id='hot', monotonic=self.mono)
        self.populate()
        args = (self.actor, 'project', 'main')
        first = discovery.find(*args, limit=1)
        data['projects'][0]['exclude'] = ['*.zip']
        config.write_text(json.dumps(data))
        with self.assertRaises(AccessError) as error:
            discovery.find(*args, limit=1, cursor=first['next_cursor'])
        self.assertNotIn('file-', str(error.exception))
        data['projects'][0].pop('exclude')
        config.write_text(json.dumps(data))
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            discovery.find(*args, limit=1, cursor=first['next_cursor'])
        fresh = self.find(limit=1)
        for name in list(self.root.glob('*.zip')):
            name.unlink()
            name.symlink_to(self.spool / 'private.bin')
        with self.assertRaises(AccessError):
            self.find(limit=1, cursor=fresh['next_cursor'])
        self.assertEqual(self.discovery.diagnostics()['cache_count'], 0)

    def test_corrupt_protection_invalidates_cache_without_revival(self):
        self.populate()
        first = self.find(limit=1)
        manifest = self.control / 'private-roots.json'
        previous = manifest.read_bytes()
        manifest.write_text('invalid')
        with self.assertRaisesRegex(AccessError, 'private_protection_unavailable'):
            self.find(limit=1, cursor=first['next_cursor'])
        manifest.write_bytes(previous)
        with self.assertRaisesRegex(AccessError, 'discovery_cursor_unavailable'):
            self.find(limit=1, cursor=first['next_cursor'])

    def test_partial_last_page_does_not_claim_full_scan(self):
        self.populate(8)
        discovery = self.discover(max_entries=3)
        result = discovery.find(self.actor, 'project', 'main', limit=1)
        seen = 0
        while True:
            self.assertFalse(result['scan_complete'])
            self.assertEqual(result['stopped_reason'], 'entry_limit')
            seen += len(result['files'])
            if not result['next_cursor']:
                break
            result = discovery.find(self.actor, 'project', 'main', limit=1, cursor=result['next_cursor'])
        self.assertEqual(seen, 3)
        self.assertFalse(result['has_more'])

    def test_dependencies_skipped_but_build_and_dist_are_covered(self):
        for name in ('node_modules/a/file.zip', '.cache/file.zip', 'dist/ship.zip', 'build/result.zip'):
            self.write(name)
        result = self.find(name_pattern='*.zip')
        self.assertEqual({r['path'] for r in result['files']}, {'dist/ship.zip', 'build/result.zip'})
        self.assertFalse(result['scan_complete'])
        self.assertEqual(result['skipped_reasons']['dependency_cache'], 2)

    def test_cache_slot_and_byte_budgets_recover_after_expiry(self):
        self.populate(20)
        discovery = self.discover(max_cache_bytes=4096, max_total_bytes=16384)
        first = discovery.find(self.actor, 'project', 'main', limit=1)
        self.assertEqual(first['stopped_reason'], 'cache_byte_limit')
        self.assertFalse(first['scan_complete'])
        discovery.find(self.actor, 'project', 'main', limit=1)
        with self.assertRaisesRegex(AccessError, 'busy'):
            discovery.find(self.actor, 'project', 'main', limit=1)
        other = replace(self.actor, key=hashlib.sha256(b'actor-b').hexdigest())
        for _ in range(2):
            discovery.find(other, 'project', 'main', limit=1)
        self.assertEqual(discovery.diagnostics()['cache_count'], 4)
        self.assertLessEqual(discovery.diagnostics()['cache_bytes'], 16384)
        self.mono.value = 121
        discovery.reap()
        self.assertEqual(discovery.diagnostics()['cache_bytes'], 0)
        self.assertTrue(discovery.find(self.actor, 'project', 'main', limit=1)['files'])

    def test_cooperative_time_limit_stays_partial(self):
        self.populate()
        discovery = self.discover(max_seconds=2)
        original = SourceScope.inspect
        def slow(scope, name):
            self.mono.value += 3
            return original(scope, name)
        with patch.object(SourceScope, 'inspect', slow):
            result = discovery.find(self.actor, 'project', 'main', limit=1)
        self.assertFalse(result['scan_complete'])
        self.assertEqual(result['stopped_reason'], 'time_limit')

    def test_close_during_page_owner_retains_budget_until_exit(self):
        self.populate()
        first = self.find(limit=1)
        entered, leave = threading.Event(), threading.Event()
        original = SourceScope.inspect
        def held(scope, name):
            entered.set()
            self.assertTrue(leave.wait(3))
            return original(scope, name)
        with patch.object(SourceScope, 'inspect', held), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.find, limit=1, cursor=first['next_cursor'])
            self.assertTrue(entered.wait(3))
            state = self.discovery.close()
            self.assertEqual(state['cache_owners'], 1)
            self.assertGreater(state['cache_bytes'], 0)
            leave.set()
            self.assertIsInstance(future.exception(), AccessError)
        self.assertEqual(self.discovery.diagnostics()['cache_bytes'], 0)


class GitDiscoveryTests(unittest.TestCase):
    git = test_workspaces.WorkspaceTests.git
    init_repo = test_workspaces.WorkspaceTests.init_repo
    add_worktree = test_workspaces.WorkspaceTests.add_worktree
    check_policy = DiscoveryTests.check_policy
    discover = DiscoveryTests.discover
    write = DiscoveryTests.write
    find = DiscoveryTests.find

    def setUp(self):
        DiscoveryTests.setUp(self)
        self.root.rmdir()
        self.init_repo(self.root)
        self.catalog.projects['project'] = replace(self.catalog.projects['project'],
                                                   repository_id=RepositoryRegistry.identity(self.root))

    def test_nested_member_requires_explicit_id_and_external_member_works(self):
        nested = self.add_worktree('nested', inside=True)
        external = self.add_worktree('external')
        (nested / 'original.bin').write_bytes(b'nested original')
        (external / 'external.zip').write_bytes(b'external original')
        with self.sources.scope(self.actor, 'project', 'main') as scope:
            with self.assertRaisesRegex(AccessError, 'nested_member_required'):
                scope.inspect('.worktree/nested/original.bin')
        members = self.catalog.repositories.discover('project')['worktrees']
        for root, name in ((nested, 'original.bin'), (external, 'external.zip')):
            member = next(m for m in members if m['root'] == str(root))
            with self.sources.scope(self.actor, 'project', member['id']) as scope:
                self.assertEqual(scope.inspect(name).worktree_id, member['id'])
        main = self.find()
        self.assertNotIn('.worktree/nested/original.bin', {r['path'] for r in main['files']})
        self.assertGreater(main['skipped_reasons']['repository_boundary'], 0)

    def test_real_git_and_directory_auxiliary_fd_peak_and_cleanup(self):
        if not Path('/dev/fd').is_dir():
            self.skipTest('POSIX descriptor census is required')
        self.write('original.zip')
        def count():
            return len(os.listdir('/dev/fd'))
        baseline = count()
        peak = baseline
        original_open, original_pipe = os.open, os.pipe
        def observe():
            nonlocal peak
            peak = max(peak, count())
        def opening(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            observe()
            return fd
        def piping(*args, **kwargs):
            pair = original_pipe(*args, **kwargs)
            observe()
            return pair
        with patch('os.open', opening), patch('os.pipe', piping):
            self.find()
            with self.sources.scope(self.actor, 'project', 'main') as scope:
                with scope.open_file('original.zip'):
                    scope.revalidate()
            self.assertEqual(count(), baseline)
        self.assertLessEqual(peak - baseline, 10)


if __name__ == '__main__':
    unittest.main()
