"""Real synthetic snapshot-manager regressions, not SDK transport acceptance.

The transport helper explicitly simulates construction/ASGI/SDK termination.
Actual SDK serialization and task ownership are tested separately by integration.
"""
import asyncio
from dataclasses import replace
import errno
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_context import ExportActor
from peters_mcp.file_export import (ExportConfig, ExportLimits, FileExportService,
                                    SERIALIZATION_BYTES, STREAM_CHUNK)
from peters_mcp.private_roots import PrivateRootRegistry


class Clock:
    def __init__(self):
        self.value = 0.0
        self.lock = threading.Lock()

    def monotonic(self):
        with self.lock:
            return self.value

    def wall(self):
        return 1_800_000_000 + self.monotonic()

    def advance(self, seconds):
        with self.lock:
            self.value += seconds


class ExportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='original-export-manager-')
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'project'
        self.root.mkdir()
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.base / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        registry.initialize()
        registry.register_pending(self.spool, read_roots=[self.root])
        registry.activate(self.spool, read_roots=[self.root])
        self.catalog = Catalog([Project('synthetic', 'Synthetic', self.root)], private_registry=registry)
        self.clock, self.services, self.gates = Clock(), [], []
        self.known_unclosed = []
        self.actor = self.actor_for('owner-a')
        self.service = self.make_service()

    def actor_for(self, label):
        return ExportActor(hashlib.sha256(label.encode()).hexdigest(), self.clock.wall() + 5000,
                           self.clock.monotonic() + 5000)

    def make_service(self, *, limits=None, hook=None, max_file_bytes=None, external_reserved=None):
        config = ExportConfig(True, self.spool, min_free_bytes=0)
        if max_file_bytes is not None:
            config = replace(config, max_file_bytes=max_file_bytes)
        service = FileExportService(self.catalog, config, limits=limits or ExportLimits(close_seconds=.2),
            monotonic=self.clock.monotonic, wall_clock=self.clock.wall,
            fault_hook=hook, external_reserved=external_reserved)
        service.start()
        self.services.append(service)
        return service

    async def asyncTearDown(self):
        for gate in self.gates:
            gate.set()
        for service in self.services:
            # All simulated transport consumers have ended at test teardown.
            for lease in list(service._leases.values()):
                lease.finish_construction(failed=True)
                lease.mark_transport(asgi=True, sdk=True)
            await asyncio.to_thread(service.close, 2)
        # Only synthetic faults deliberately raised before os.close get this
        # explicit test-only cleanup; the product must keep them uncertain.
        for fd in self.known_unclosed:
            try:
                os.close(fd)
            except OSError:
                pass
        self.temp.cleanup()

    def write(self, name='original.bin', data=b'first synthetic bytes'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    async def wait_until(self, predicate, seconds=3):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            await asyncio.sleep(.005)
        self.fail('Synthetic manager operation did not settle within the test budget')

    async def accepted(self, name='original.bin', key='request-1', actor=None, service=None,
                       expected=None, capability=None):
        service, actor = service or self.service, actor or self.actor
        capability = capability or service.capabilities(actor)
        return await service.export_file(actor, 'synthetic', 'main', name,
            capability['service_instance_id'], capability['request_window_id'], key, expected,
            wait_seconds=0)

    async def status(self, export_id, actor=None, service=None, states=('ready', 'failed', 'revoked', 'expired')):
        service, actor = service or self.service, actor or self.actor
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = await service.get_status(actor, export_id)
            if result['state'] in states:
                return result
            await asyncio.sleep(.005)
        self.fail('Synthetic export did not reach an expected state')

    async def ready(self, name='original.bin', key='request-1', **kwargs):
        accepted = await self.accepted(name, key, **kwargs)
        result = await self.status(accepted['export_id'], actor=kwargs.get('actor'), service=kwargs.get('service'))
        self.assertEqual(result['state'], 'ready', result)
        return result

    async def fake_transport(self, export_id, *, service=None, actor=None):
        """Actual owner IO with simulated SDK/ASGI termination, for small fixtures."""
        service, actor = service or self.service, actor or self.actor
        delivery = await service.materialize(actor, export_id)
        self.assertEqual(delivery['state'], 'ready')
        lease = service.open_resource(actor, delivery['delivery_id'], asyncio.get_running_loop())
        marker = await asyncio.wait_for(lease.bytes_ready(), 2)
        self.assertEqual(marker, lease.marker)
        self.assertEqual(len(marker), 24)
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 2)
        body = bytearray()
        while len(body) < delivery['bytes']:
            await asyncio.wait_for(lease.before_send(), 2)
            block = await asyncio.wait_for(lease.next_chunk(len(body)), 2)
            self.assertTrue(block)
            self.assertLessEqual(len(block), STREAM_CHUNK)
            body.extend(block)
            lease.sent()
            block = None
        await asyncio.wait_for(lease.finish_stream(), 2)
        await asyncio.wait_for(lease.before_send(), 2)
        lease.sent()
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released and lease.owner_complete)
        return bytes(body), lease

    def assert_hidden(self, result):
        for name in ('source', 'bytes', 'sha256', 'resource_uri', 'captured_at'):
            self.assertNotIn(name, result)

    async def test_actual_copy_hash_unlink_and_cached_pin_ownership(self):
        data = os.urandom(150000)
        self.write(data=data)
        observed = []
        def hook(stage, value):
            if stage == 'anonymous_unlinked':
                record, fd = value
                observed.append((os.fstat(fd).st_nlink, os.fstat(fd).st_size, list(self.spool.iterdir())))
        self.service.fault_hook = hook
        result = await self.ready(expected=hashlib.sha256(data).hexdigest())
        self.assertEqual(observed, [(0, 0, [])])
        self.assertEqual(result['bytes'], len(data))
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        fd = self.service._records[result['export_id']].snapshot.fd
        for _ in range(2):
            body, lease = await self.fake_transport(result['export_id'])
            self.assertEqual(body, data)
            self.assertEqual(os.fstat(fd).st_nlink, 0)
            self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
            self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 1)
        after = await self.service.get_status(self.actor, result['export_id'])
        self.assertTrue(after['server_stream_finished'])
        self.assertEqual(after['client_received'], 'not_observed')

    async def test_same_key_fixed_intent_conflict_and_other_owner_denied(self):
        self.write()
        self.write('other.bin', b'other')
        first = await self.ready()
        replay = await self.accepted()
        self.assertEqual(replay['export_id'], first['export_id'])
        self.assertEqual(self.service.diagnostics()['keys'], 1)
        with self.assertRaisesRegex(AccessError, 'idempotency_conflict'):
            await self.accepted('other.bin')
        other = self.actor_for('owner-b')
        with self.assertRaisesRegex(AccessError, 'export_unavailable'):
            await self.service.get_status(other, first['export_id'])
        delivery = await self.service.materialize(self.actor, first['export_id'])
        with self.assertRaisesRegex(AccessError, 'export_unavailable'):
            self.service.open_resource(other, delivery['delivery_id'], asyncio.get_running_loop())

    async def test_failed_hash_same_key_never_rebuilds_and_new_key_recovers(self):
        self.write()
        first = await self.accepted(expected='0' * 64)
        failed = await self.status(first['export_id'])
        self.assertEqual(failed['error_code'], 'expected_hash_mismatch')
        self.assert_hidden(failed)
        replay = await self.accepted(expected='0' * 64)
        self.assertEqual(replay['export_id'], first['export_id'])
        self.assertEqual(replay['state'], 'failed')
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 0)
        self.assertEqual((await self.ready(key='fresh-key'))['state'], 'ready')

    async def test_copy_change_fails_without_ready_and_next_request_recovers(self):
        path = self.write(data=os.urandom(100000))
        changed = []
        def hook(stage, record):
            if stage == 'copy_chunk' and not changed:
                changed.append(True)
                with path.open('ab') as stream:
                    stream.write(b'changed during real copy')
        self.service.fault_hook = hook
        accepted = await self.accepted()
        failed = await self.status(accepted['export_id'])
        self.assertEqual(failed['state'], 'failed')
        self.assertEqual(failed['error_code'], 'source_changed')
        self.assert_hidden(failed)
        self.assertEqual(self.service.diagnostics()['snapshot_fds'], 0)
        self.service.fault_hook = None
        recovered = await self.ready(key='current-version')
        self.assertEqual(recovered['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    async def test_ready_bytes_change_keeps_old_snapshot_and_old_hash(self):
        path = self.write(data=b'captured original')
        ready = await self.ready()
        path.write_bytes(b'changed ordinary source contents')
        status = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(status['sha256'], ready['sha256'])
        body, _ = await self.fake_transport(ready['export_id'])
        self.assertEqual(body, b'captured original')
        self.assertEqual((await self.accepted())['export_id'], ready['export_id'])

    async def test_ready_replay_does_not_apply_new_source_size_to_old_snapshot(self):
        service = self.make_service(max_file_bytes=64)
        path = self.write(data=b'captured small original')
        ready = await self.ready(service=service)
        path.write_bytes(b'n' * 100)
        replay = await self.accepted(service=service)
        self.assertEqual(replay['state'], 'ready')
        self.assertEqual(replay['export_id'], ready['export_id'])
        body, _ = await self.fake_transport(ready['export_id'], service=service)
        self.assertEqual(body, b'captured small original')

    async def test_current_exclusion_and_link_change_hide_old_ready(self):
        path = self.write()
        ready = await self.ready()
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=('original.bin',))
        revoked = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(revoked['state'], 'revoked')
        self.assert_hidden(revoked)
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=())
        self.assertEqual((await self.service.get_status(self.actor, ready['export_id']))['state'], 'revoked')
        newer = await self.ready(key='new-grant')
        path.unlink()
        path.symlink_to(self.spool / 'private-file')
        self.assert_hidden(await self.service.get_status(self.actor, newer['export_id']))

    async def test_observed_resource_link_denial_does_not_revive_old_export(self):
        path = self.write()
        ready = await self.ready()
        delivery = await self.service.materialize(self.actor, ready['export_id'])
        outside = self.base / 'ungranted-synthetic-file'
        outside.write_bytes(b'outside source')
        path.unlink()
        path.symlink_to(outside)
        lease = self.service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        with self.assertRaises(AccessError):
            await asyncio.wait_for(lease.bytes_ready(), 2)
        lease.finish_construction(failed=True)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        path.unlink()
        path.write_bytes(b'first synthetic bytes')
        status = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(status['state'], 'revoked')
        self.assert_hidden(status)

    async def test_status_close_uncertainty_retains_auxiliary_owner(self):
        self.write()
        ready = await self.ready()
        from peters_mcp import file_discovery
        original = file_discovery._close_owned
        def failing(fd):
            original(fd)
            raise AccessError('Fixed cleanup failure.', code='source_cleanup_pending')
        with patch('peters_mcp.file_discovery._close_owned', failing):
            try:
                await self.service.get_status(self.actor, ready['export_id'])
            except AccessError as error:
                self.assertEqual(error.code, 'source_cleanup_pending')
        self.assertGreater(self.service.diagnostics()['pending_auxiliary_owners'], 0)
        self.assertEqual((await asyncio.to_thread(self.service.close, .5))['state'], 'shutdown_pending')

    async def test_window_boundary_retains_queued_owner_and_old_window_rejects(self):
        self.write('first.bin', b'first')
        self.write('queued.bin', b'queued')
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def hook(stage, record):
            if stage == 'before_prepare' and record.source.path == 'first.bin':
                entered.set()
                release.wait(3)
        self.service.fault_hook = hook
        self.clock.advance(898)
        first = await self.accepted('first.bin')
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        self.clock.advance(1)
        other = self.actor_for('owner-b')
        capability = self.service.capabilities(other)
        queued = await self.accepted('queued.bin', 'queued-key', actor=other, capability=capability)
        self.assertEqual(queued['state'], 'queued')
        self.clock.advance(1)
        fresh = self.service.capabilities(other)
        self.assertNotEqual(capability['request_window_id'], fresh['request_window_id'])
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 2)
        with self.assertRaisesRegex(AccessError, 'request_window_expired'):
            await self.accepted('queued.bin', 'queued-key', actor=other, capability=capability)
        release.set()
        self.assertEqual((await self.status(first['export_id']))['state'], 'ready')
        self.assertEqual((await self.status(queued['export_id'], actor=other))['state'], 'ready')
        body, _ = await self.fake_transport(queued['export_id'], actor=other)
        self.assertEqual(body, b'queued')

    async def test_eviction_closes_actual_fd_but_old_key_is_fixed_expired(self):
        self.write('one.bin', b'one')
        self.write('two.bin', b'two')
        service = self.make_service(limits=ExportLimits(snapshots=1, actor_snapshots=1, close_seconds=.2))
        first = await self.ready('one.bin', service=service)
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.accepted('two.bin', 'second', service=service)
        await self.wait_until(lambda: service.diagnostics()['snapshot_reservations'] == 0)
        replay = await self.accepted('one.bin', service=service)
        self.assertEqual(replay['export_id'], first['export_id'])
        self.assertEqual(replay['state'], 'expired')
        self.assertEqual((await self.ready('two.bin', 'second', service=service))['state'], 'ready')

    async def test_metadata_two_owners_one_per_actor_and_cancel_waiter_is_not_exit(self):
        entered_a, entered_b, release = threading.Event(), threading.Event(), threading.Event()
        self.gates.append(release)
        def held(entered):
            entered.set()
            release.wait(3)
            return 'finished'
        first = asyncio.create_task(self.service.metadata(self.actor, lambda: held(entered_a)))
        self.assertTrue(await asyncio.to_thread(entered_a.wait, 2))
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.service.metadata(self.actor, lambda: None)
        other = self.actor_for('owner-b')
        second = asyncio.create_task(self.service.metadata(other, lambda: held(entered_b)))
        self.assertTrue(await asyncio.to_thread(entered_b.wait, 2))
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.service.metadata(self.actor_for('owner-c'), lambda: None)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assertEqual(self.service.diagnostics()['metadata_owners'], 2)
        release.set()
        self.assertEqual(await second, 'finished')
        await self.wait_until(lambda: self.service.diagnostics()['metadata_owners'] == 0)

    async def test_key_record_metadata_and_byte_budgets_are_real_admission(self):
        self.write('one.bin', b'12345678')
        self.write('two.bin', b'abcdefgh')
        for limits in (ExportLimits(keys=1), ExportLimits(actor_keys=1), ExportLimits(records=1),
                       ExportLimits(actor_records=1)):
            service = self.make_service(limits=replace(limits, close_seconds=.2))
            await self.ready('one.bin', service=service)
            with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
                await self.accepted('two.bin', 'second', service=service)
            self.assertEqual(service.diagnostics()['keys'], 1)
        tiny = self.make_service(limits=ExportLimits(metadata_bytes=1, close_seconds=.2))
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await self.accepted('one.bin', service=tiny)
        self.assertEqual(tiny.diagnostics()['snapshot_reservations'], 0)
        for limits in (ExportLimits(snapshot_bytes=4), ExportLimits(actor_snapshot_bytes=4)):
            bytes_limit = self.make_service(limits=replace(limits, close_seconds=.2))
            with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
                await self.accepted('one.bin', service=bytes_limit)
            self.assertEqual(bytes_limit.diagnostics()['keys'], 0)

    async def test_actor_snapshot_quota_does_not_consume_other_actors_quota(self):
        self.write('one.bin', b'one')
        self.write('two.bin', b'two')
        service = self.make_service(limits=ExportLimits(actor_snapshots=1, close_seconds=.2))
        ready = await self.ready('one.bin', service=service)
        delivery = await service.materialize(self.actor, ready['export_id'])
        lease = service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        self.assertEqual(await asyncio.wait_for(lease.bytes_ready(), 2), lease.marker)
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await self.accepted('two.bin', 'actor-overflow', service=service)
        other = self.actor_for('owner-b')
        self.assertEqual((await self.ready('two.bin', 'other-actor', actor=other, service=service))['state'], 'ready')
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 2)
        self.assertEqual(await lease.next_chunk(0), b'one')
        await lease.finish_stream()
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released)

    async def test_queue_full_and_actor_preparing_recover_after_owner_finishes(self):
        for name in ('one.bin', 'two.bin', 'three.bin', 'four.bin'):
            self.write(name)
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def hook(stage, record):
            if stage == 'before_prepare' and record.source.path == 'one.bin':
                entered.set()
                release.wait(3)
        self.service.fault_hook = hook
        await self.accepted('one.bin')
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.accepted('four.bin', 'same-actor-new')
        actors = [self.actor_for('queue-owner-' + str(i)) for i in range(3)]
        for actor, name in zip(actors, ('two.bin', 'three.bin')):
            await self.accepted(name, name, actor=actor)
        self.assertEqual(self.service.diagnostics()['queued'], 2)
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.accepted('four.bin', 'queue-overflow', actor=actors[2])
        release.set()
        await self.wait_until(lambda: self.service.diagnostics()['prepare_owners'] == 0 and self.service.diagnostics()['queued'] == 0)
        self.assertEqual((await self.ready('four.bin', 'queue-overflow', actor=actors[2]))['state'], 'ready')

    async def test_queued_source_version_change_and_queue_timeout_are_not_rebuilt(self):
        self.write('blocking.bin', b'blocking')
        queued_path = self.write('queued.bin', b'accepted version')
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def hook(stage, record):
            if stage == 'before_prepare' and record.source.path == 'blocking.bin':
                entered.set()
                release.wait(3)
        self.service.fault_hook = hook
        await self.accepted('blocking.bin')
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        other = self.actor_for('owner-b')
        queued = await self.accepted('queued.bin', 'queued-change', actor=other)
        queued_path.write_bytes(b'changed after acceptance')
        release.set()
        failed = await self.status(queued['export_id'], actor=other)
        self.assertEqual(failed['error_code'], 'source_changed')
        self.assert_hidden(failed)
        self.assertEqual((await self.accepted('queued.bin', 'queued-change', actor=other))['state'], 'failed')

        entered.clear(); release.clear()
        service = self.make_service(limits=ExportLimits(queue_seconds=.5, idle_seconds=100, close_seconds=.2), hook=hook)
        await self.accepted('blocking.bin', service=service)
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        timed = await self.accepted('queued.bin', 'queue-deadline', actor=other, service=service)
        self.clock.advance(1)
        service.reap()
        status = await service.get_status(other, timed['export_id'])
        self.assertEqual(status['state'], 'failed')
        self.assertEqual(status['error_code'], 'preparation_timeout')
        self.assertEqual(service.diagnostics()['snapshot_reservations'], 1)
        release.set()

    async def test_enospc_and_unavailable_external_space_can_recover_new_request(self):
        self.write()
        triggered = []
        def hook(stage, record):
            if stage == 'copy_chunk' and not triggered:
                triggered.append(True)
                raise OSError(errno.ENOSPC, 'synthetic space failure')
        self.service.fault_hook = hook
        accepted = await self.accepted()
        failed = await self.status(accepted['export_id'])
        self.assertEqual(failed['error_code'], 'insufficient_space')
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 0)
        self.service.fault_hook = None
        self.assertEqual((await self.ready(key='recovered-space'))['state'], 'ready')
        external = [None]
        service = self.make_service(external_reserved=lambda: external[0])
        with self.assertRaisesRegex(AccessError, 'busy'):
            await self.accepted(service=service)
        external[0] = 0
        self.assertEqual((await self.ready(service=service))['state'], 'ready')

    async def test_retired_pin_prevents_close_until_owner_and_transport_end(self):
        data = b'old immutable snapshot'
        self.write(data=data)
        ready = await self.ready()
        record = self.service._records[ready['export_id']]
        fd = record.snapshot.fd
        delivery = await self.service.materialize(self.actor, ready['export_id'])
        lease = self.service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        received = await asyncio.wait_for(lease.bytes_ready(), 2)
        self.assertEqual(received, lease.marker)
        cancelled = await self.service.cancel(self.actor, ready['export_id'])
        self.assertEqual(cancelled['state'], 'cancelling')
        self.assertFalse(cancelled['resources_released'])
        self.assertEqual(os.fstat(fd).st_nlink, 0)
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 1)
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], SERIALIZATION_BYTES)
        lease.finish_construction(failed=True)
        lease.mark_transport(asgi=True)
        self.assertFalse(lease.released)
        lease.mark_transport(sdk=True)
        await self.wait_until(lambda: lease.released and record.snapshot.fd == -1)
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 0)
        with self.assertRaises(OSError):
            os.fstat(fd)
        replacement = self.base / 'replacement-descriptor-target'
        replacement.write_bytes(b'new unrelated synthetic descriptor data')
        new_fd = os.open(replacement, os.O_RDONLY)
        try:
            if new_fd != fd:
                os.dup2(new_fd, fd)
            self.assertEqual(os.pread(fd, 64, 0), b'new unrelated synthetic descriptor data')
            with self.assertRaisesRegex(AccessError, 'export_unavailable'):
                self.service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        finally:
            os.close(new_fd)
            if new_fd != fd:
                os.close(fd)

    async def test_cooperative_shutdown_and_unconfirmed_io_stays_pending(self):
        self.write()
        ready = await self.ready()
        stopped = await asyncio.to_thread(self.service.close, 1)
        self.assertEqual(stopped['state'], 'stopped')
        self.assertEqual(stopped['snapshot_reservations'], 0)
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def hook(stage, record):
            if stage == 'before_snapshot_sync':
                entered.set()
                release.wait(3)
        service = self.make_service(hook=hook)
        await self.accepted(service=service)
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        pending = await asyncio.to_thread(service.close, .02)
        self.assertEqual(pending['state'], 'shutdown_pending')
        self.assertEqual(pending['prepare_owners'], 1)
        self.assertEqual(pending['snapshot_reservations'], 1)
        release.set()
        await self.wait_until(lambda: service.diagnostics()['prepare_owners'] == 0)
        self.assertEqual((await asyncio.to_thread(service.close, 1))['state'], 'stopped')

    async def test_unconfirmed_transport_retains_pin_and_encoding_until_both_ends(self):
        self.write()
        ready = await self.ready()
        delivery = await self.service.materialize(self.actor, ready['export_id'])
        lease = self.service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        await asyncio.wait_for(lease.bytes_ready(), 2)
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 2)
        pending = await asyncio.to_thread(self.service.close, .02)
        self.assertEqual(pending['state'], 'shutdown_pending')
        self.assertEqual(pending['encoding_bytes_reserved'], SERIALIZATION_BYTES)
        self.assertEqual(pending['snapshot_reservations'], 1)
        lease.mark_transport(asgi=True)
        self.assertFalse(lease.released)
        lease.mark_transport(sdk=True)
        await self.wait_until(lambda: lease.released)
        self.assertEqual((await asyncio.to_thread(self.service.close, 1))['state'], 'stopped')

    async def test_snapshot_close_failure_never_reports_refund_or_retries(self):
        self.write()
        ready = await self.ready()
        fd = self.service._records[ready['export_id']].snapshot.fd
        self.known_unclosed.append(fd)
        calls = []
        def hook(stage, value):
            if stage == 'before_snapshot_close':
                calls.append(value)
                raise OSError(errno.EIO, 'synthetic error before the close syscall')
        self.service.fault_hook = hook
        self.clock.advance(self.service.limits.ready_seconds + 1)
        self.service.reap()
        await self.wait_until(lambda: self.service.diagnostics()['uncertain_snapshot_close'])
        pending = await asyncio.to_thread(self.service.close, .5)
        self.assertEqual(pending['state'], 'shutdown_pending')
        self.assertEqual(pending['snapshot_reservations'], 1)
        self.assertEqual(calls, [fd])
        self.assertEqual(os.fstat(fd).st_nlink, 0)
        with self.assertRaisesRegex(AccessError, 'export_disabled'):
            await self.accepted(key='no-new-admission')


if __name__ == '__main__':
    unittest.main()
