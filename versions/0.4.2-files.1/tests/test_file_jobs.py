"""Durable jobs against temporary synthetic repositories only."""
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_jobs import FileSaveService, FileSaveInspector
from peters_mcp import file_jobs
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.workspaces import RepositoryRegistry
from peters_mcp.file_source import receive_file
from tests.test_file_receiver import synthetic_receive

ACTOR = 'a' * 64


def wire_error_receive(file, output, sources, **kwargs):
    """Run the real receiver/framing/error code using a controlled wire only."""
    from tests.test_file_source import WireConnection, WireSocket, wire
    kind = file['file_id']
    response = wire(b'', [('Content-Length', '32')])
    if kind == 'temporary-http':
        response = wire(status=503)

    def connector(host, address, timeout, progress):
        if kind == 'io':
            raise ConnectionResetError('synthetic transport interruption')
        return WireConnection(WireSocket(response, delay=.015 if kind == 'idle' else 0), progress)

    options = {'_connector': connector, 'idle_timeout': .003 if kind == 'idle' else 20}
    if kind == 'dns':
        def resolver(*args, **kw):
            time.sleep(.03)
            return []
        sources = {'files.example.invalid': None}
        options.update(_resolver=resolver, connect_timeout=.005)
    return receive_file(file, output, sources, **kwargs, **options)


def orphan_job_coordinator(root, connection):
    root = Path(root)
    catalog = Catalog([Project('repo', 'Synthetic', root / 'repo',
                               repository_id=RepositoryRegistry.identity(root / 'repo'))])
    registry = PrivateRootRegistry(root / 'control', allowed_roots=[root / 'spool'])
    service = FileSaveService(catalog, registry, root / 'control', {}, min_free_bytes=0,
                              _receiver=synthetic_receive)
    inspected = service.inspect(ACTOR, 'repo', 'main', 'orphan.bin')
    result = service.submit(ACTOR, {'file_id': 'slow', 'download_url': 'https://files.example.invalid/data'},
                            'repo', 'main', 'orphan.bin', inspected['target_version'],
                            inspected['destination_display'], 'orphan-request', expected_size_bytes=1024 * 1024)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        row = service._get(result['job_id'])
        if row.get('receiver') and Path(row['attempt_directory'], 'payload').stat().st_size > 0:
            connection.send({'job_id': result['job_id'], 'receiver': row['receiver']})
            connection.close()
            os._exit(41)
        time.sleep(.02)
    os._exit(42)


class FileJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        subprocess.run(['/usr/bin/git', '-C', str(self.repo), 'init', '-q'], check=True, capture_output=True)
        self.catalog = Catalog([Project('repo', 'Synthetic', self.repo,
                                       repository_id=RepositoryRegistry.identity(self.repo))])
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        self.registry.initialize()
        self.registry.register_pending(self.spool, read_roots=[self.repo])
        self.registry.activate(self.spool, read_roots=[self.repo])
        self.services = []
        self.addCleanup(self.close_services)

    def close_services(self):
        for service in self.services:
            service.close(timeout=5)

    def service(self, **options):
        service = FileSaveService(self.catalog, self.registry, self.control,
                                  {'files.example.invalid': ['8.8.8.8']}, autostart=False,
                                  min_free_bytes=options.pop('min_free_bytes', 0), _receiver=synthetic_receive, **options)
        self.services.append(service)
        return service

    def arguments(self, service, *, name='nested/file.bin', identity='normal', key='request-one', size=32, expected=None):
        inspected = service.inspect(ACTOR, 'repo', 'main', name)
        return dict(actor=ACTOR, file={'download_url': 'https://files.example.invalid/object?token=DO_NOT_PERSIST',
                    'file_id': identity}, project_id='repo', worktree_id='main', path=name,
                    target_version=inspected['target_version'], destination_display=inspected['destination_display'],
                    request_key=key, expected_sha256=expected, expected_size_bytes=size)

    def wait(self, service, job, states=('completed',), timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = service.status(ACTOR, job_id=job)
            if row['state'] in states:
                return row
            time.sleep(.03)
        self.fail(f'Job did not reach {states}: {row}')

    def test_normal_large_binary_restart_and_idempotent_missing_target(self):
        service = self.service()
        args = self.arguments(service, size=9 * 1024 * 1024)
        accepted = service.submit(**args)
        self.assertFalse(accepted['saved'])
        self.assertEqual(service.submit(**args)['job_id'], accepted['job_id'])
        service.start()
        result = self.wait(service, accepted['job_id'])
        destination = self.repo / args['path']
        self.assertEqual(destination.stat().st_size, 9 * 1024 * 1024)
        self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), result['download_sha256'])
        self.assertEqual(result['destination_sha256'], result['download_sha256'])
        self.assertEqual(service.close()['state'], 'stopped')
        restarted = self.service()
        self.assertEqual(restarted.status(ACTOR, request_key=args['request_key'])['state'], 'completed')
        destination.unlink()
        self.assertEqual(restarted.submit(**args)['state'], 'completed')
        restarted.start()
        time.sleep(.1)
        self.assertFalse(destination.exists())
        with self.assertRaisesRegex(AccessError, 'idempotency_conflict'):
            restarted.submit(**{**args, 'expected_size_bytes': 1})
        with self.assertRaisesRegex(AccessError, 'not_found'):
            restarted.status('b' * 64, job_id=accepted['job_id'])
        self.assertNotIn(b'DO_NOT_PERSIST', (self.control / 'file-jobs.sqlite3').read_bytes())

    def test_cancel_before_and_during_receive_and_after_publish(self):
        service = self.service()
        first = service.submit(**self.arguments(service))
        self.assertEqual(service.cancel(ACTOR, first['job_id'])['state'], 'cancelled')
        args = self.arguments(service, key='slow', identity='slow', size=20 * 1024 * 1024)
        second = service.submit(**args)
        service.start()
        self.wait(service, second['job_id'], ('receiving',))
        service.cancel(ACTOR, second['job_id'])
        cancelled = self.wait(service, second['job_id'], ('cancelled',))
        self.assertEqual(cancelled['cancel_effect'], 'prevented_publish')
        self.assertFalse((self.repo / args['path']).exists())
        third = service.submit(**self.arguments(service, key='third'))
        self.wait(service, third['job_id'])
        self.assertEqual(service.cancel(ACTOR, third['job_id'])['cancel_effect'], 'too_late')
        self.assertTrue((self.repo / args['path']).exists())

    def test_complete_receipt_then_restart_publishes_without_redownload(self):
        service = self.service()
        def stop_after_complete(phase, _):
            if phase == 'receive_complete':
                service._stop.set()
                raise SystemExit()
        service.fault_hook = stop_after_complete
        accepted = service.submit(**self.arguments(service))
        service.start()
        self.wait(service, accepted['job_id'], ('ready_to_publish',))
        self.assertFalse((self.repo / 'nested/file.bin').exists())
        service.close()
        restarted = self.service()
        restarted.start()
        self.assertTrue(self.wait(restarted, accepted['job_id'])['saved'])

    def test_corrupt_complete_spool_is_never_published(self):
        service = self.service()
        def stop(phase, _):
            if phase == 'receive_complete':
                service._stop.set()
                raise SystemExit()
        service.fault_hook = stop
        accepted = service.submit(**self.arguments(service))
        service.start()
        self.wait(service, accepted['job_id'], ('ready_to_publish',))
        row = service._get(accepted['job_id'])
        service.close()
        Path(row['attempt_directory'], 'payload').write_bytes(b'corrupted')
        restarted = self.service()
        restarted.start()
        self.assertEqual(self.wait(restarted, accepted['job_id'], ('failed',))['error_code'], 'hash_mismatch')
        self.assertFalse((self.repo / 'nested/file.bin').exists())

    def test_reference_refresh_requires_bound_hash_and_revision(self):
        pattern = (b'\x00\xffsynthetic\r\n' * 6000)[:32]
        expected = hashlib.sha256(pattern).hexdigest()
        service = self.service()
        accepted = service.submit(**self.arguments(service, identity='expired', expected=expected))
        service.start()
        self.wait(service, accepted['job_id'], ('needs_file_reference',))
        with self.assertRaisesRegex(AccessError, 'source_revision_changed'):
            service.refresh_source(ACTOR, accepted['job_id'], 0,
                                   {'file_id': 'normal', 'download_url': 'https://files.example.invalid/new'})
        refreshed = service.refresh_source(ACTOR, accepted['job_id'], 1,
                                           {'file_id': 'normal', 'download_url': 'https://files.example.invalid/new'})
        self.assertEqual(refreshed['source_revision'], 2)
        self.assertTrue(self.wait(service, accepted['job_id'])['saved'])

    def test_observed_revoke_does_not_revive_after_project_returns(self):
        service = self.service()
        accepted = service.submit(**self.arguments(service))
        project = self.catalog.projects.pop('repo')
        service.start()
        self.wait(service, accepted['job_id'], ('authorization_blocked',))
        self.catalog.projects['repo'] = project
        time.sleep(.15)
        self.assertEqual(service.status(ACTOR, job_id=accepted['job_id'])['state'], 'authorization_blocked')
        self.assertFalse((self.repo / 'nested/file.bin').exists())

    def test_control_failure_before_accept_and_unique_coordinator(self):
        service = self.service()
        with self.assertRaisesRegex(AccessError, 'coordinator_busy'):
            self.service()
        def fail(phase, _):
            if phase == 'before_job_commit':
                raise OSError(28, 'synthetic disk full')
        service.fault_hook = fail
        with self.assertRaisesRegex(AccessError, 'metadata_unavailable'):
            service.submit(**self.arguments(service))
        self.assertEqual(list(self.spool.iterdir()), [])
        self.assertTrue(service._storage_failed.is_set())
        self.assertFalse(service._reserve_path.exists())

    def test_post_rename_crash_is_unknown_never_republished(self):
        service = self.service()
        def crash(phase, _):
            if phase == 'renamed':
                service._stop.set()
                raise SystemExit()
        service.fault_hook = crash
        accepted = service.submit(**self.arguments(service))
        service.start()
        self.wait(service, accepted['job_id'], ('publishing',))
        service.close()
        original = (self.repo / 'nested/file.bin').read_bytes()
        restarted = self.service()
        restarted.start()
        result = self.wait(restarted, accepted['job_id'], ('publication_unverified',))
        self.assertEqual(result['published'], 'unknown')
        self.assertEqual((self.repo / 'nested/file.bin').read_bytes(), original)

    def test_real_coordinator_crash_orphan_writer_is_adopted_and_published(self):
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=orphan_job_coordinator, args=(str(self.root), child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(10))
            info = parent.recv()
            process.join(5)
            self.assertEqual(process.exitcode, 41)
            with self.assertRaises(ChildProcessError):
                os.waitpid(info['receiver']['identity']['pid'], os.WNOHANG)
            replacement = self.service()
            replacement.start()
            result = self.wait(replacement, info['job_id'])
            self.assertTrue(result['saved'])
            self.assertEqual((self.repo / 'orphan.bin').stat().st_size, 1024 * 1024)
            self.assertEqual(result['bytes'], 1024 * 1024)
        finally:
            parent.close()
            if process.is_alive():
                process.terminate()
                process.join(3)
            process.close()

    def test_readonly_inspector_missing_database_and_existing_jobs_never_mutates(self):
        before = set(self.control.iterdir())
        inspector = FileSaveInspector(self.catalog, self.registry, self.control)
        self.assertFalse(inspector.capabilities(ACTOR)['write_enabled'])
        with self.assertRaisesRegex(AccessError, 'job_not_found'):
            inspector.status(ACTOR, request_key='missing')
        inspector.close()
        self.assertEqual(set(self.control.iterdir()), before)
        service = self.service()
        accepted = service.submit(**self.arguments(service))
        database = self.control / 'file-jobs.sqlite3'
        original = database.read_bytes()
        inspector = FileSaveInspector(self.catalog, self.registry, self.control)
        self.assertEqual(inspector.status(ACTOR, job_id=accepted['job_id'])['state'], 'queued')
        inspector.close()
        self.assertEqual(database.read_bytes(), original)
        self.assertFalse((self.repo / 'nested/file.bin').exists())

    def test_empty_original_and_platform_not_ready(self):
        service = self.service()
        accepted = service.submit(**self.arguments(service, size=0))
        service.start()
        result = self.wait(service, accepted['job_id'])
        self.assertEqual(result['bytes'], 0)
        self.assertEqual(result['download_sha256'], hashlib.sha256(b'').hexdigest())

    def test_space_pause_with_hash_can_resume_after_capacity_returns(self):
        expected = hashlib.sha256((b'\x00\xffsynthetic\r\n' * 10)[:32]).hexdigest()
        service = self.service(min_free_bytes=2**62)
        accepted = service.submit(**self.arguments(service, expected=expected))
        service.start()
        self.wait(service, accepted['job_id'], ('paused_space',))
        self.assertFalse((self.repo / 'nested/file.bin').exists())
        service.min_free_bytes = 0
        self.assertTrue(self.wait(service, accepted['job_id'], timeout=12)['saved'])

    def test_observed_config_disable_blocks_existing_job(self):
        service = self.service()
        accepted = service.submit(**self.arguments(service))
        def disabled():
            raise AccessError('Writes disabled.', code='write_not_enabled')
        service.sources = disabled
        service.start()
        self.wait(service, accepted['job_id'], ('authorization_blocked',))
        service.sources = {}
        time.sleep(.1)
        self.assertEqual(service.status(ACTOR, job_id=accepted['job_id'])['state'], 'authorization_blocked')

    def test_crash_after_durable_publication_recovers_completed(self):
        service = self.service()
        def crash(phase, _):
            if phase == 'published_durable':
                service._stop.set()
                raise SystemExit()
        service.fault_hook = crash
        accepted = service.submit(**self.arguments(service))
        service.start()
        self.wait(service, accepted['job_id'], ('verifying_destination',))
        service.close()
        restarted = self.service()
        restarted.start()
        self.assertTrue(self.wait(restarted, accepted['job_id'])['saved'])

    def test_cancel_returns_pending_while_real_publish_call_is_delayed(self):
        service = self.service()
        entered, release = threading.Event(), threading.Event()
        original = file_jobs.publish_exclusive
        def delayed(*args):
            entered.set()
            if not release.wait(8):
                raise RuntimeError('synthetic barrier timed out')
            return original(*args)
        accepted = service.submit(**self.arguments(service))
        with patch.object(file_jobs, 'publish_exclusive', delayed):
            try:
                service.start()
                self.assertTrue(entered.wait(5))
                started = time.monotonic()
                response = service.cancel(ACTOR, accepted['job_id'])
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(response['cancel_requested'])
                self.assertEqual(response['cancel_effect'], 'pending')
                self.assertFalse(response['published'])
                release.set()
                completed = self.wait(service, accepted['job_id'])
                self.assertEqual(completed['cancel_effect'], 'too_late')
            finally:
                release.set()

    def test_cancel_does_not_wait_for_real_directory_fsync(self):
        service = self.service()
        entered, release = threading.Event(), threading.Event()
        original = os.fsync
        identity = self.repo.stat().st_ino
        def delayed(fd):
            if os.fstat(fd).st_ino == identity:
                entered.set()
                if not release.wait(8):
                    raise RuntimeError('synthetic fsync barrier timed out')
            return original(fd)  # The actual fsync still runs.
        accepted = service.submit(**self.arguments(service, name='file.bin'))
        with patch.object(file_jobs.os, 'fsync', delayed):
            try:
                service.start()
                self.assertTrue(entered.wait(5))
                started = time.monotonic()
                response = service.cancel(ACTOR, accepted['job_id'])
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(response['published'])
                self.assertEqual(response['cancel_effect'], 'too_late')
                release.set()
                self.wait(service, accepted['job_id'])
            finally:
                release.set()

    def test_precise_stale_worker_update_cannot_erase_durable_cancel_or_published_fact(self):
        service = self.service()
        accepted = service.submit(**self.arguments(service))
        stale = service._get(accepted['job_id'])
        stale['state'] = 'receiving'
        entered, release = threading.Event(), threading.Event()
        def barrier(phase, _):
            if phase == 'before_job_commit' and threading.current_thread().name == 'stale-worker':
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('synthetic stale barrier timed out')
        service.fault_hook = barrier
        thread = threading.Thread(target=service._put, args=(stale,), name='stale-worker')
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            response = service.cancel(ACTOR, accepted['job_id'])
            self.assertTrue(response['cancel_requested'])
            release.set()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            current = service._get(accepted['job_id'])
            self.assertTrue(current['cancel_requested'])
            self.assertEqual(current['state'], 'cancelled')
            self.assertEqual(service.db.execute('SELECT cancel_requested FROM requests WHERE job=?',
                                               (accepted['job_id'],)).fetchone(), (1,))
        finally:
            release.set()
            thread.join(3)
        # Separate immutable fact check: an old unpublished snapshot cannot retract publication.
        second = service.submit(**self.arguments(service, key='second', name='second.bin'))
        stale = service._get(second['job_id'])
        current = dict(stale, published=True, durability='confirmed', state='verifying_destination',
                       publish_intent={'synthetic': True})
        service._put(current)
        service._put(stale)
        self.assertTrue(service._get(second['job_id'])['published'])
        self.assertEqual(service._get(second['job_id'])['durability'], 'confirmed')
        self.assertEqual(service._get(second['job_id'])['publish_intent'], {'synthetic': True})

    def test_reserve_rejects_sparse_or_partial_existing_file_and_failed_creation_releases_lease(self):
        reserve = self.control / 'file-control.reserve'
        for size in (0, 100, 1024 * 1024):
            with self.subTest(size=size):
                with reserve.open('wb') as stream:
                    stream.truncate(size)
                reserve.chmod(0o600)
                with self.assertRaisesRegex(AccessError, 'metadata_unavailable'):
                    self.service()
                self.assertTrue(reserve.exists())
                reserve.unlink()  # This test's own synthetic unowned fixture only.
        with patch.object(file_jobs.os, 'write', side_effect=OSError(28, 'synthetic full')):
            with self.assertRaises(OSError):
                self.service()
        self.assertFalse(reserve.exists())
        service = self.service()
        self.assertEqual(reserve.stat().st_size, 1024 * 1024)
        self.assertGreaterEqual(reserve.stat().st_blocks * 512, 1024 * 1024)
        self.assertEqual(service.close()['state'], 'stopped')

    def test_waiting_for_reference_still_observes_background_revocation(self):
        expected = hashlib.sha256((b'\x00\xffsynthetic\r\n' * 10)[:32]).hexdigest()
        service = self.service()
        accepted = service.submit(**self.arguments(service, identity='expired', expected=expected))
        service.start()
        self.wait(service, accepted['job_id'], ('needs_file_reference',))
        project = self.catalog.projects.pop('repo')
        # Read the durable row directly: no status query is used to cause observation.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and service._get(accepted['job_id'])['state'] != 'authorization_blocked':
            time.sleep(.03)
        self.assertEqual(service._get(accepted['job_id'])['state'], 'authorization_blocked')
        self.catalog.projects['repo'] = project
        with self.assertRaises(AccessError):
            service.refresh_source(ACTOR, accepted['job_id'], 1,
                                   {'file_id': 'normal', 'download_url': 'https://files.example.invalid/new'})
        self.assertFalse((self.repo / 'nested/file.bin').exists())

    def test_target_created_at_publication_is_known_conflict_and_cancel_can_clean_spool(self):
        service = self.service()
        def race(phase, _):
            if phase == 'publish_intent':
                (self.repo / 'nested/file.bin').write_bytes(b'external-new-file')
        service.fault_hook = race
        accepted = service.submit(**self.arguments(service))
        service.start()
        result = self.wait(service, accepted['job_id'], ('conflict',))
        self.assertFalse(result['published'])
        self.assertEqual(result['error_code'], 'target_exists')
        self.assertEqual((self.repo / 'nested/file.bin').read_bytes(), b'external-new-file')
        service.cancel(ACTOR, accepted['job_id'])
        self.wait(service, accepted['job_id'], ('cancelled',))
        self.assertEqual((self.repo / 'nested/file.bin').read_bytes(), b'external-new-file')

    def test_refresh_cannot_overtake_an_already_claimed_worker_before_spawn(self):
        service = self.service()
        expected = hashlib.sha256((b'\x00\xffsynthetic\r\n' * 10)[:32]).hexdigest()
        job = service.submit(**self.arguments(service, expected=expected))['job_id']
        with patch.object(service, '_authorize', side_effect=AccessError('scope unknown', code='paused_scope_unverifiable')):
            service._run(job)
        entered, resume = threading.Event(), threading.Event()
        original = service._authorize

        def blocked(row):
            result = original(row)
            if threading.current_thread().name == 'claimed-worker' and not entered.is_set():
                entered.set()
                self.assertTrue(resume.wait(8))
            return result

        with patch.object(service, '_authorize', side_effect=blocked):
            worker = threading.Thread(target=service._run, args=(job,), name='claimed-worker')
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaisesRegex(AccessError, 'refresh_not_ready'):
                    service.refresh_source(ACTOR, job, 1, {'file_id': 'normal',
                        'download_url': 'https://files.example.invalid/new'})
                self.assertEqual(service._get(job)['source_revision'], 1)
            finally:
                resume.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(service.status(ACTOR, job_id=job)['state'], 'completed')

    def test_successful_refresh_rejects_stale_revision_and_attempt_commits(self):
        service = self.service()
        expected = hashlib.sha256((b'\x00\xffsynthetic\r\n' * 10)[:32]).hexdigest()
        job = service.submit(**self.arguments(service, expected=expected))['job_id']
        with patch.object(service, '_authorize', side_effect=AccessError('scope unknown', code='paused_scope_unverifiable')):
            service._run(job)
        stale = service._get(job)
        refreshed = service.refresh_source(ACTOR, job, 1, {'file_id': 'normal',
            'download_url': 'https://files.example.invalid/new'})
        self.assertEqual(refreshed['source_revision'], 2)
        with self.assertRaisesRegex(AccessError, 'stale_file_snapshot'):
            service._put(stale)
        service._run(job)
        final = service._get(job)
        self.assertEqual((final['state'], final['source_revision']), ('completed', 2))
        old_attempt = dict(final, attempt_number=0)
        with self.assertRaisesRegex(AccessError, 'stale_file_snapshot'):
            service._put(old_attempt)
        wrong_receiver = dict(final, receiver={**final['receiver'], 'attempt': 'different-attempt'})
        with self.assertRaisesRegex(AccessError, 'stale_file_snapshot'):
            service._put(wrong_receiver)
        self.assertTrue(service._get(job)['published'])

    def test_real_wire_error_classes_pause_without_claiming_complete(self):
        service = self.service(); service._receiver = wire_error_receive
        expected = hashlib.sha256((b'\x00\xffsynthetic\r\n' * 10)[:32]).hexdigest()
        cases = [('dns', 'source_dns_timeout', 'paused_network'),
                 ('idle', 'transfer_idle_timeout', 'paused_network'),
                 ('truncated', 'transfer_incomplete', 'paused_network'),
                 ('temporary-http', 'source_temporarily_unavailable', 'paused_network'),
                 ('io', 'source_or_output_io_failed', 'paused_io')]
        for kind, code, state in cases:
            job = service.submit(**self.arguments(service, identity=kind, expected=expected,
                                                  name=kind+'.bin', key=kind))['job_id']
            service._run(job)
            row = service._get(job)
            with self.subTest(kind=kind):
                self.assertEqual((row['error_code'], row['state']), (code, state))
                self.assertTrue(row['writer_exited'])
                self.assertNotIn('complete', row)
                self.assertFalse((self.repo / (kind+'.bin')).exists())
        service._receiver = receive_file
        job = service.submit(**self.arguments(service, expected=expected, name='space.bin', key='space'))['job_id']
        service.min_free_bytes = 2 ** 63
        service._run(job)
        row = service._get(job)
        self.assertEqual((row['error_code'], row['state']), ('insufficient_space', 'paused_space'))
        self.assertTrue(row['writer_exited']); self.assertNotIn('complete', row)

    def test_temporary_policy_unavailable_resumes_but_does_not_revoke(self):
        from peters_mcp.file_config import read_file_config
        service = self.service()
        config = self.root / 'synthetic-files.json'
        raw = json.dumps({'version': 1, 'enabled': True, 'control_directory': str(self.control),
                          'spool_roots': [str(self.spool)], 'sources': {'files.example.invalid': ['8.8.8.8']},
                          'special_exceptions': [], 'min_free_bytes': 0, 'max_workers': 2})
        config.write_text(raw); config.chmod(0o600)
        service.sources = read_file_config(config).sources
        job = service.submit(**self.arguments(service))['job_id']
        config.write_text('{incomplete')
        service.start()
        self.wait(service, job, ('paused_scope_unverifiable',))
        self.assertFalse((self.repo / 'nested/file.bin').exists())
        config.write_text(raw)
        self.assertTrue(self.wait(service, job)['saved'])

    def test_revocation_arbitration_precedes_publication_when_it_wins(self):
        service = self.service()
        enabled = [True]
        def policy():
            if not enabled[0]:
                raise AccessError('Synthetic disabled', code='write_not_enabled')
            return {'files.example.invalid': ['8.8.8.8']}
        service.sources = policy
        entered, resume = threading.Event(), threading.Event()
        def fault(phase, _):
            if phase == 'receive_complete':
                entered.set(); self.assertTrue(resume.wait(8))
        service.fault_hook = fault
        job = service.submit(**self.arguments(service))['job_id']; service.start()
        try:
            self.assertTrue(entered.wait(5))
            enabled[0] = False
            with self.assertRaisesRegex(AccessError, 'authorization_blocked'):
                service._authorize(service._get(job))
            self.assertEqual(service.db.execute("SELECT valid FROM ledger WHERE key=':file-service'").fetchone(), (0,))
        finally:
            resume.set()
        self.wait(service, job, ('authorization_blocked',))
        self.assertFalse((self.repo / 'nested/file.bin').exists())

    def test_revocation_does_not_claim_effective_while_publisher_owns_arbitration(self):
        service = self.service()
        enabled = [True]
        def policy():
            if not enabled[0]:
                raise AccessError('Synthetic disabled', code='write_not_enabled')
            return {'files.example.invalid': ['8.8.8.8']}
        service.sources = policy
        entered, resume, observation_started, observation_done = (threading.Event() for _ in range(4))
        def fault(phase, _):
            if phase == 'publish_intent':
                entered.set(); self.assertTrue(resume.wait(8))
        service.fault_hook = fault
        job = service.submit(**self.arguments(service))['job_id']; service.start()
        observed = []
        def observe():
            observation_started.set()
            try:
                service._authorize(service._get(job))
            except AccessError as exc:
                observed.append(exc.code)
            finally:
                observation_done.set()
        thread = threading.Thread(target=observe)
        try:
            self.assertTrue(entered.wait(5)); enabled[0] = False
            thread.start(); self.assertTrue(observation_started.wait(2))
            self.assertFalse(observation_done.wait(.1))
            self.assertEqual(service.db.execute("SELECT valid FROM ledger WHERE key=':file-service'").fetchone(), (1,))
            self.assertFalse(service.status(ACTOR, job_id=job)['published'])
        finally:
            resume.set()
            if thread.ident is not None: thread.join(8)
        self.assertEqual(observed, ['authorization_blocked'])
        result = self.wait(service, job)
        self.assertTrue(result['published'])

    def test_cancel_cleans_owned_empty_parents_or_reports_retained_counts(self):
        for variant in ('empty', 'occupied', 'revoked'):
            occupied, revoked = variant == 'occupied', variant == 'revoked'
            with self.subTest(variant=variant):
                service = self.service()
                entered, resume = threading.Event(), threading.Event()
                def fault(phase, _):
                    if phase == 'publish_intent':
                        entered.set(); self.assertTrue(resume.wait(8))
                service.fault_hook = fault
                folder = variant
                job = service.submit(**self.arguments(service, name=folder+'/sub/file.bin', key=folder))['job_id']
                service.start()
                try:
                    self.assertTrue(entered.wait(5))
                    if occupied:
                        (self.repo/folder/'sub/external.txt').write_bytes(b'external')
                    pending = service.cancel(ACTOR, job)
                    self.assertTrue(pending['cancel_requested'])
                    self.assertEqual(pending['cancel_effect'], 'pending')
                    if revoked:
                        self.catalog.projects.pop('repo')
                finally:
                    resume.set()
                self.wait(service, job, ('cancelled',))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    row = service.status(ACTOR, job_id=job)
                    if row.get('cleanup', {}).get('project_directories'):
                        break
                    time.sleep(.01)
                summary = row['cleanup']['project_directories']
                self.assertEqual(row['cleanup']['private_state'], 'completed')
                self.assertEqual(summary['removed_count'], 0 if occupied or revoked else 2)
                self.assertEqual(summary['retained_or_unverified_count'], 2 if occupied or revoked else 0)
                self.assertEqual((self.repo/folder).exists(), occupied or revoked)
                if revoked:
                    self.assertEqual(summary['state'], 'retained_scope_unavailable')
                    self.assertNotIn('path', row)
                    self.assertNotIn('destination_display', row)
                service.close()

    def test_repeated_close_preserves_isolated_writer_unknown_fact(self):
        service = self.service()
        job = service.submit(**self.arguments(service))['job_id']
        service._handles[job] = SimpleNamespace(process=None, stop=lambda *args, **kwargs: False)
        first = service.close(timeout=.01)
        self.assertEqual(first, {'state': 'shutdown_pending', 'isolated_receivers': 1,
                                 'coordinator_released': True})
        self.assertIsNone(service._lease)
        self.assertEqual(service.close(timeout=.01), first)
if __name__ == '__main__':
    unittest.main()
