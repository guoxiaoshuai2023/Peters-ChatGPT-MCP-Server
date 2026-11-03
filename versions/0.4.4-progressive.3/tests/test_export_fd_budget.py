"""Exporter-added FD census and uncertain-close regressions on synthetic roots."""
import asyncio
from dataclasses import replace
import errno
import io
import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog
from peters_mcp import fs_identity
from peters_mcp.file_export import ExportConfig, FileExportService, PROFILE_ID, MAX_ORIGINAL_BYTES
from peters_mcp.workspaces import RepositoryRegistry
from tests import test_file_export, test_workspaces


def live_fds():
    """Count live descriptors only, excluding the census's closed directory FD."""
    result = {}
    for name in os.listdir('/dev/fd'):
        try:
            fd = int(name)
            info = os.fstat(fd)
        except (ValueError, OSError):
            continue
        result[fd] = (info.st_dev, info.st_ino, info.st_mode)
    return result


class Census:
    """Attribute new descriptors to exporter owners; never label baseline as export."""
    def __init__(self):
        self.baseline = live_fds()
        self.owned = {}
        self.peak_aux = {}
        self.peak_total = 0
        self.lock = threading.RLock()
        self.original_open, self.original_pipe, self.original_io = os.open, os.pipe, io.open
        self.original_scandir = os.scandir

    def observe(self, descriptors=(), snapshot=False):
        with self.lock:
            owner = threading.current_thread().name
            now = live_fds()
            for fd in descriptors:
                if fd not in now:
                    continue
                existing = self.owned.get(fd)
                is_snapshot = snapshot or (existing is not None and existing[2])
                self.owned[fd] = (now[fd], owner, is_snapshot)
            self.owned = {fd: value for fd, value in self.owned.items()
                          if fd in now and value[0] == now[fd]}
            counts = {}
            for identity, thread, is_snapshot in self.owned.values():
                if thread.startswith('original-export-') and not is_snapshot:
                    counts[thread] = counts.get(thread, 0) + 1
            for thread, count in counts.items():
                self.peak_aux[thread] = max(self.peak_aux.get(thread, 0), count)
            self.peak_total = max(self.peak_total, sum(v[1].startswith('original-export-') for v in self.owned.values()))

    def opening(self, name, flags, *args, **kwargs):
        fd = self.original_open(name, flags, *args, **kwargs)
        self.observe((fd,), snapshot=isinstance(name, str) and name.startswith('.original-export-'))
        return fd

    def piping(self, *args, **kwargs):
        result = self.original_pipe(*args, **kwargs)
        self.observe(result)
        return result

    def file_opening(self, *args, **kwargs):
        result = self.original_io(*args, **kwargs)
        self.observe((result.fileno(),))
        return result

    def scanning(self, *args, **kwargs):
        before = live_fds()
        result = self.original_scandir(*args, **kwargs)
        # scandir(fd) owns a C-level duplicate, not another os.open call.
        self.observe(tuple(set(live_fds()) - set(before)))
        return result


class ExportFDBudgetTests(unittest.IsolatedAsyncioTestCase):
    setUp = test_file_export.ExportTests.setUp
    asyncTearDown = test_file_export.ExportTests.asyncTearDown
    actor_for = test_file_export.ExportTests.actor_for
    make_service = test_file_export.ExportTests.make_service
    write = test_file_export.ExportTests.write
    wait_until = test_file_export.ExportTests.wait_until
    accepted = test_file_export.ExportTests.accepted
    status = test_file_export.ExportTests.status
    ready = test_file_export.ExportTests.ready
    fake_transport = test_file_export.ExportTests.fake_transport
    git = test_workspaces.WorkspaceTests.git
    init_repo = test_workspaces.WorkspaceTests.init_repo

    def git_fixture(self):
        self.root.rmdir()
        self.init_repo(self.root)
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'],
                                                     repository_id=RepositoryRegistry.identity(self.root))
        linked = self.base / 'linked-worktree'
        self.git(self.root, 'worktree', 'add', '-b', 'linked', str(linked))
        members = self.catalog.repositories.discover('synthetic')['worktrees']
        member = next(m for m in members if m['root'] == str(linked))
        admin = Path((linked / '.git').read_text().strip().removeprefix('gitdir: '))
        return linked, member['id'], admin / 'gitdir'

    def close_before_syscall(self, target):
        identity = (target.stat().st_dev, target.stat().st_ino)
        original = os.close
        intercepted = []
        def closing(fd):
            try:
                info = os.fstat(fd)
            except OSError:
                return original(fd)
            if not intercepted and (info.st_dev, info.st_ino) == identity:
                intercepted.append(fd)
                self.known_unclosed.append(fd)
                # Deliberately before the real syscall: the actual synthetic FD
                # stays open and must not be falsely refunded by the product.
                raise OSError(errno.EIO, 'synthetic unconfirmed close')
            return original(fd)
        return closing, intercepted

    async def test_linked_worktree_backlink_unknown_close_is_not_refunded(self):
        linked, worktree_id, backlink = self.git_fixture()
        closing, intercepted = self.close_before_syscall(backlink)
        baseline = live_fds()
        def operation():
            with self.service.sources.scope(self.actor, 'synthetic', worktree_id) as scope:
                return scope.inspect('README.md').public()
        with patch('os.close', closing):
            with self.assertRaises(AccessError):
                await self.service.metadata(self.actor, operation)
        self.assertEqual(len(intercepted), 1)
        self.assertNotIn(intercepted[0], baseline)
        self.assertIn(intercepted[0], live_fds(), 'The fault retains a real additional descriptor')
        observed = self.service.diagnostics()
        self.assertGreater(observed['pending_auxiliary_owners'], 0,
                           f'Unconfirmed backlink close lost its pending owner: {observed}')
        self.assertGreaterEqual(observed['auxiliary_fd_reservations'], 10)

    async def test_hot_catalog_candidate_close_unknown_outcome_is_not_refunded(self):
        candidate = self.root / 'work/candidates'
        candidate.mkdir(parents=True)
        config = self.base / 'synthetic-projects.json'
        data = {'projects': [{'id': 'synthetic', 'name': 'before', 'root': str(self.root),
                              'candidate_directory': 'work/candidates'}]}
        config.write_text(json.dumps(data))
        catalog = Catalog.from_config(config, private_registry=self.catalog._private_registry)
        service = FileExportService(catalog, ExportConfig(True, self.spool, min_free_bytes=0),
            monotonic=self.clock.monotonic, wall_clock=self.clock.wall)
        service.start(); self.services.append(service)
        data['projects'][0]['name'] = 'after'
        config.write_text(json.dumps(data))
        closing, intercepted = self.close_before_syscall(candidate)
        baseline = live_fds()
        def operation():
            with service.sources.scope(self.actor, 'synthetic', 'main') as scope:
                return scope.root_identity
        with patch('os.close', closing):
            with self.assertRaises(AccessError):
                await service.metadata(self.actor, operation)
        self.assertEqual(len(intercepted), 1)
        self.assertNotIn(intercepted[0], baseline)
        self.assertIn(intercepted[0], live_fds())
        observed = service.diagnostics()
        self.assertGreater(observed['pending_auxiliary_owners'], 0,
                           f'Catalog refresh washed close uncertainty into a normal denial: {observed}')

    async def test_private_stable_identity_unknown_close_keeps_guard_fd_reservation(self):
        original_identity_close, original_close = fs_identity._close, os.close
        identity = (self.control.stat().st_dev, self.control.stat().st_ino)
        local = threading.local()
        intercepted = []
        def identity_close(fd):
            local.identity_close = True
            try:
                return original_identity_close(fd)
            finally:
                local.identity_close = False
        def closing(fd):
            info = os.fstat(fd)
            if (getattr(local, 'identity_close', False) and not intercepted
                    and (info.st_dev, info.st_ino) == identity):
                intercepted.append(fd)
                self.known_unclosed.append(fd)
                # No syscall: retain a real FD and verify its reservation survives
                # fs_identity -> private guard -> source scope -> exporter worker.
                raise OSError(errno.EIO, 'synthetic native identity close uncertainty')
            return original_close(fd)
        baseline = live_fds()
        def operation():
            with self.service.sources.scope(self.actor, 'synthetic', 'main') as scope:
                return scope.root_identity
        with patch('peters_mcp.fs_identity._close', identity_close), patch('os.close', closing):
            with self.assertRaises(AccessError) as error:
                await self.service.metadata(self.actor, operation)
        self.assertEqual(error.exception.code, 'protection_cleanup_pending')
        self.assertEqual(len(intercepted), 1)
        self.assertNotIn(intercepted[0], baseline)
        self.assertIn(intercepted[0], live_fds(), 'The synthetic fault must retain its actual FD')
        observed = self.service.diagnostics()
        self.assertGreater(observed['pending_auxiliary_owners'], 0, observed)
        self.assertGreaterEqual(observed['auxiliary_fd_reservations'], 10, observed)
        with self.assertRaises(AccessError) as stopped:
            await self.service.metadata(self.actor, lambda: 'must remain stopped')
        self.assertEqual(stopped.exception.code, 'resource_stop_pending')
        self.assertIn(intercepted[0], live_fds(), 'Later admission must not retry an uncertain close')

    async def test_normal_git_config_source_and_snapshot_closures_fit_tickets(self):
        linked, worktree_id, backlink = self.git_fixture()
        path = self.write(data=os.urandom(100000))
        project_config = self.base / 'synthetic-projects.json'
        project_data = {'projects': [{'id': 'synthetic', 'name': 'Synthetic', 'root': str(self.root),
                                     'repository_id': self.catalog.projects['synthetic'].repository_id}]}
        project_config.write_text(json.dumps(project_data))
        catalog = Catalog.from_config(project_config, private_registry=self.catalog._private_registry)
        export_config = self.base / 'synthetic-export.json'
        export_config.write_text(json.dumps({'version': 1, 'enabled': True, 'spool_root': str(self.spool),
            'profile_id': PROFILE_ID, 'max_file_bytes': MAX_ORIGINAL_BYTES, 'min_free_bytes': 0}))
        export_config.chmod(0o600)
        service = FileExportService(catalog, ExportConfig(True, self.spool, min_free_bytes=0, path=export_config),
            monotonic=self.clock.monotonic, wall_clock=self.clock.wall)
        service.start(); self.services.append(service)
        census = Census()
        with (patch('os.open', census.opening), patch('os.pipe', census.piping),
              patch('io.open', census.file_opening), patch('os.scandir', census.scanning)):
            first = await self.ready(service=service)
            await service.find_files(self.actor, 'synthetic', 'main')
            await service.find_files(self.actor, 'synthetic', worktree_id)
            body, lease = await self.fake_transport(first['export_id'], service=service)
            self.assertEqual(body, path.read_bytes())
            census.observe()
            self.assertTrue(census.peak_aux)
            self.assertLessEqual(max(census.peak_aux.values()), 10, census.peak_aux)
            self.assertLessEqual(census.peak_total, 64)
            closed = await asyncio.to_thread(service.close, 1)
            self.assertEqual(closed['state'], 'stopped')
            census.observe()
        self.assertFalse(census.owned, 'The normal owner closures return to the baseline')
        print('SYNTHETIC_FD_CENSUS', {'baseline': len(census.baseline), 'peak_aux': census.peak_aux,
                                     'peak_added_export': census.peak_total})


if __name__ == '__main__':
    unittest.main()
