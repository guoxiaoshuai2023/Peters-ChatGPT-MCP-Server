"""Independent-clock regressions with real synthetic snapshots and owners.

These are manager tests, not real sleep or native ChatGPT receipt evidence.
Transport-end markers, where used, simulate the test consumer's actual exit.
"""
import asyncio
import errno
import hashlib
import os
import threading
import unittest
from unittest.mock import patch

import test_chunked_export_service as fixture
from peters_mcp.catalog import AccessError


class IndependentClock:
    def __init__(self):
        self.mono = 0.0
        self.epoch = 1_800_000_000.0
        self.lock = threading.Lock()

    def monotonic(self):
        with self.lock:
            return self.mono

    def wall(self):
        with self.lock:
            return self.epoch

    def advance(self, *, wall=0.0, monotonic=0.0):
        with self.lock:
            self.epoch += wall
            self.mono += monotonic


class ChunkedExpiryTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixture.ChunkedManagerTests.asyncSetUp
    asyncTearDown = fixture.ChunkedManagerTests.asyncTearDown
    actor_for = fixture.ChunkedManagerTests.actor_for
    make_service = fixture.ChunkedManagerTests.make_service
    new_service = fixture.ChunkedManagerTests.new_service
    write = fixture.ChunkedManagerTests.write
    wait_until = fixture.ChunkedManagerTests.wait_until
    chunk_ready = fixture.ChunkedManagerTests.chunk_ready

    def setUp(self):
        fixture.ChunkedManagerTests.setUp(self)
        self.clock = IndependentClock()
        self.actor = self.actor_for('owner-a')

    def arguments(self, service, actor, *, key='original', expected=None):
        capability = service.capabilities(actor)
        return dict(actor=actor, project_id='synthetic', worktree_id='main', path='original.bin',
                    service_instance_id=capability['service_instance_id'],
                    request_window_id=capability['request_window_id'], request_key=key,
                    expected_sha256=expected, wait_seconds=0)

    async def assert_closed(self, record, fd=None):
        await self.wait_until(lambda: not record.reserved and not record.owner)
        if record.snapshot is not None:
            self.assertEqual(record.snapshot.fd, -1)
        if fd is not None:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def gate(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        return entered, release

    def pause(self, entered, release):
        entered.set()
        if not release.wait(5):
            raise RuntimeError('synthetic expiry gate timed out')

    async def end_transport(self, service, lease, record, fd):
        # The test consumer has now stopped. A single endpoint ending is not
        # sufficient evidence that the shared response and pin can be released.
        self.assertFalse(lease.released)
        self.assertTrue(record.reserved)
        self.assertEqual(record.snapshot.pins, 1)
        self.assertEqual(os.fstat(fd).st_nlink, 0)
        lease.finish_construction(failed=True)
        lease.mark_transport(asgi=True)
        self.assertFalse(lease.released)
        self.assertEqual(record.snapshot.pins, 1)
        lease.mark_transport(sdk=True)
        await self.wait_until(lambda: lease.released and lease.owner_complete)
        await self.assert_closed(record, fd)
        self.assertEqual(service.diagnostics()['active_responses'], 0)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], 0)

    async def test_sleep_expiry_releases_real_fd_then_admits_new_key(self):
        ready = await self.chunk_ready(key='before-sleep')
        record = self.chunked._records[ready['export_id']]
        fd = record.snapshot.fd
        plan = (await self.chunked.get_chunked_export_plan(self.actor, record.export_id))['plan']
        self.clock.advance(wall=3700, monotonic=100)
        self.assertLess(self.clock.wall(), self.actor.expires_at)
        self.assertGreaterEqual(self.clock.wall(), plan['expires_at_unix'])
        self.assertLess(self.clock.monotonic(), record.expires)

        self.chunked.reap()
        self.assertEqual(record.state, 'expired', 'Sleeping past the declared deadline must expire the parent')
        await self.wait_until(lambda: not record.reserved)
        self.assertEqual(record.snapshot.fd, -1)
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        status = await self.chunked.get_chunked_export_status(self.actor, record.export_id)
        self.assertTrue(status['resources_released'])
        capability = self.chunked.capabilities(self.actor)
        new = await self.chunked.prepare_chunked_export(
            self.actor, 'synthetic', 'main', 'original.bin', capability['service_instance_id'],
            capability['request_window_id'], 'after-sleep', wait_seconds=0)
        self.assertIn(new['state'], {'queued', 'preparing', 'ready'})
        self.assertNotEqual(new['export_id'], record.export_id)

    async def test_each_ready_entry_observes_wall_expiry_without_prior_reap(self):
        body = b'independent entry expiry'
        for entry in ('same-key', 'new-key', 'status', 'plan', 'helper', 'part', 'read'):
            with self.subTest(entry=entry):
                service, actor = self.new_service(), self.actor_for('owner-a')
                ready = await self.chunk_ready(body, key='original', service=service, actor=actor)
                record = service._records[ready['export_id']]
                fd = record.snapshot.fd
                original = self.arguments(service, actor, expected=hashlib.sha256(body).hexdigest())
                item = None
                if entry == 'read':
                    item = await service.materialize_chunked_export_part(actor, record.export_id, 0)
                self.clock.advance(wall=3700, monotonic=.1)
                self.assertLess(self.clock.wall(), actor.expires_at)
                if entry in ('same-key', 'new-key'):
                    if entry == 'new-key':
                        original['request_key'] = 'after-sleep'
                    try:
                        result = await service.prepare_chunked_export(**original)
                    except AccessError as error:
                        self.assertEqual(entry, 'new-key')
                        self.assertIn(error.code, {'busy', 'resource_stop_pending'})
                        result = None
                    if entry == 'same-key':
                        self.assertEqual(result['export_id'], record.export_id)
                        self.assertEqual(result['state'], 'expired')
                    elif result is not None:
                        self.assertIn(result['state'], {'queued', 'preparing', 'ready'})
                        self.assertNotEqual(result['export_id'], record.export_id)
                elif entry in ('status', 'plan'):
                    operation = (service.get_chunked_export_status if entry == 'status'
                                 else service.get_chunked_export_plan)
                    self.assertEqual((await operation(actor, record.export_id))['state'], 'expired')
                elif entry == 'read':
                    with self.assertRaises(AccessError) as denied:
                        service.open_chunked_resource(actor, item['resource_uri'].split('://')[1],
                                                      asyncio.get_running_loop())
                    self.assertEqual(denied.exception.code, 'export_unavailable')
                else:
                    with self.assertRaises(AccessError) as denied:
                        if entry == 'helper':
                            await service.materialize_chunked_export_receiver(actor, record.export_id)
                        else:
                            await service.materialize_chunked_export_part(actor, record.export_id, 0)
                    self.assertEqual(denied.exception.code, 'export_unavailable')
                self.assertEqual(record.state, 'expired')
                self.assertEqual(sum(slot.actual_reads for slot in record.slots.values()), 0)
                self.assertEqual(len(service._leases), 0)
                await self.assert_closed(record, fd)
                if entry == 'new-key' and result is None:
                    recovered = await service.prepare_chunked_export(**original)
                    self.assertIn(recovered['state'], {'queued', 'preparing', 'ready'})

    async def test_foreign_actor_cannot_use_expired_parent_or_trigger_its_cleanup(self):
        ready = await self.chunk_ready()
        record = self.chunked._records[ready['export_id']]
        self.clock.advance(wall=3700, monotonic=.1)
        foreign = self.actor_for('other')
        for operation in (self.chunked.get_chunked_export_status, self.chunked.get_chunked_export_plan):
            with self.assertRaises(AccessError) as denied:
                await operation(foreign, record.export_id)
            self.assertEqual(denied.exception.code, 'export_unavailable')
        self.assertEqual(record.state, 'ready')
        self.assertTrue(record.reserved)
        self.assertEqual((await self.chunked.get_chunked_export_status(self.actor, record.export_id))['state'], 'expired')
        await self.assert_closed(record)

    async def lease_for(self, service, actor):
        ready = await self.chunk_ready(service=service, actor=actor)
        record = service._records[ready['export_id']]
        item = await service.materialize_chunked_export_part(actor, record.export_id, 0)
        lease = service.open_chunked_resource(actor, item['resource_uri'].split('://')[1],
                                             asyncio.get_running_loop())
        self.assertEqual(await asyncio.wait_for(lease.bytes_ready(), 2), b'synthetic original')
        return record, lease

    async def test_before_send_rejects_wall_expiry_while_owner_is_paused_and_cache_is_fresh(self):
        service, actor = self.chunked, self.actor
        record, lease = await self.lease_for(service, actor)
        fd = record.snapshot.fd
        entered, release = self.gate()
        original_wait = lease.transport_done.wait
        def paused_transport_wait(timeout=None):
            self.pause(entered, release)
            return original_wait(timeout)
        lease.transport_done.wait = paused_transport_wait
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 2)
        await self.wait_until(entered.is_set)
        self.clock.advance(wall=3700, monotonic=.1)
        self.assertTrue(lease.owner_checked)
        self.assertGreater(lease.valid_until, self.clock.monotonic())
        self.assertLess(self.clock.wall(), actor.expires_at)
        with self.assertRaises(AccessError):
            await asyncio.wait_for(lease.before_send(), 1)
        self.assertEqual(record.state, 'expired')
        release.set()
        await self.end_transport(service, lease, record, fd)

    async def test_owner_check_rejects_wall_expiry_inside_health_cache(self):
        service, actor = self.chunked, self.actor
        entered, release = self.gate()
        original_check = service._lease_check
        def paused_check(lease, scope, *, force=False):
            if not force and lease.payload is not None and not entered.is_set():
                self.pause(entered, release)
            return original_check(lease, scope, force=force)
        service._lease_check = paused_check
        record, lease = await self.lease_for(service, actor)
        fd = record.snapshot.fd
        await self.wait_until(entered.is_set)
        self.clock.advance(wall=3700, monotonic=.1)
        self.assertGreater(lease.valid_until, self.clock.monotonic())
        release.set()
        await self.wait_until(lambda: lease.error_code is not None)
        self.assertEqual(record.state, 'expired')
        await self.end_transport(service, lease, record, fd)

    async def test_transport_wait_observes_wall_expiry_without_monotonic_cache_refresh(self):
        service, actor = self.chunked, self.actor
        record, lease = await self.lease_for(service, actor)
        fd = record.snapshot.fd
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 2)
        self.clock.advance(wall=3700, monotonic=.1)
        self.assertGreater(lease.valid_until, self.clock.monotonic())
        self.assertTrue(lease.owner_checked)
        await self.wait_until(lambda: lease.error_code is not None)
        self.assertEqual(record.state, 'expired')
        await self.end_transport(service, lease, record, fd)

    async def test_queued_parent_expires_before_prepare_owner_takes_it(self):
        self.write()
        capability = self.chunked.capabilities(self.actor)
        # Keep the real preparation worker outside the queue until the record
        # has crossed its deadline. No synthetic state or FD is fabricated.
        with self.chunked.lock:
            value = self.chunked._accept(self.actor, 'synthetic', 'main', 'original.bin',
                capability['service_instance_id'], capability['request_window_id'], 'queued',
                None, chunked=True)
            record = self.chunked._records[value['export_id']]
            self.assertEqual(record.state, 'queued')
            self.clock.advance(wall=3700, monotonic=.1)
            self.chunked.reap()
            self.assertEqual(record.state, 'expired')
        await self.assert_closed(record)
        self.assertIsNone(record.snapshot)
        self.assertIsNone(record.candidate_fd)
        self.assertEqual(record.prepared_bytes, 0)

    async def test_prepare_start_and_final_handoff_refuse_wall_expiry(self):
        for stage in ('before_prepare', 'before_ready'):
            with self.subTest(stage=stage):
                service, actor = self.new_service(), self.actor_for('owner-a')
                entered, release = self.gate()
                observed = {}
                def hook(current, value):
                    if current == 'anonymous_unlinked':
                        observed['fd'] = value[1]
                    if current == stage:
                        self.pause(entered, release)
                service.fault_hook = hook
                self.write(data=b'preparation wall expiry')
                value = await service.prepare_chunked_export(**self.arguments(service, actor))
                record = service._records[value['export_id']]
                await self.wait_until(entered.is_set)
                self.clock.advance(wall=3700, monotonic=.1)
                self.assertLess(self.clock.wall(), actor.expires_at)
                release.set()
                await self.wait_until(lambda: not record.owner)
                self.assertEqual(record.state, 'expired')
                self.assertEqual(record.error_code, 'export_expired')
                await self.assert_closed(record, observed.get('fd'))
                self.assertIsNone(record.snapshot)
                self.assertIsNone(record.plan)
                self.assertIsNone(record.candidate_fd)

    async def test_real_copy_reread_and_hash_progress_do_not_renew_crossed_parent(self):
        body = b'real expiry progress' * 100
        for phase in ('copy', 'reread', 'part-hash'):
            with self.subTest(phase=phase):
                service, actor = self.new_service(), self.actor_for('owner-a')
                observed = {'phase': 'copy', 'crossed': False}
                def hook(stage, value):
                    if stage == 'anonymous_unlinked':
                        observed['fd'] = value[1]
                        observed['record'] = value[0]
                    elif stage == 'before_snapshot_sync':
                        observed['phase'] = 'reread'
                service.fault_hook = hook
                original_hashes = service._part_hashes
                def hash_phase(*args, **kwargs):
                    observed['phase'] = 'part-hash'
                    return original_hashes(*args, **kwargs)
                service._part_hashes = hash_phase
                original_pread = os.pread
                def crossing_pread(fd, size, offset):
                    block = original_pread(fd, size, offset)
                    target_fd = observed.get('fd')
                    target = (target_fd is not None and
                              (fd != target_fd if phase == 'copy' else fd == target_fd))
                    if block and target and observed['phase'] == phase and not observed['crossed']:
                        observed['crossed'] = True
                        observed['progress_before'] = observed['record'].progress_at
                        self.clock.advance(wall=3700, monotonic=.1)
                    return block
                self.write(data=body)
                with patch.object(os, 'pread', side_effect=crossing_pread):
                    value = await service.prepare_chunked_export(**self.arguments(service, actor))
                    record = service._records[value['export_id']]
                    await self.wait_until(lambda: not record.owner and record.state not in {'queued', 'preparing'})
                self.assertTrue(observed['crossed'])
                self.assertEqual(record.state, 'expired')
                self.assertEqual(record.error_code, 'export_expired')
                self.assertEqual(record.progress_at, observed['progress_before'])
                if phase == 'copy':
                    self.assertEqual(service._written_total, 0)
                    self.assertEqual(record.prepared_bytes, 0)
                await self.assert_closed(record, observed['fd'])
                self.assertIsNone(record.snapshot)
                self.assertIsNone(record.plan)

    async def test_integer_unix_boundary_and_remaining_use_fixed_plan_without_sliding(self):
        for position in ('before', 'exact', 'after'):
            with self.subTest(position=position):
                self.clock.advance(wall=.75)
                service, actor = self.new_service(), self.actor_for('owner-a')
                ready = await self.chunk_ready(service=service, actor=actor)
                record = service._records[ready['export_id']]
                plan = (await service.get_chunked_export_plan(actor, record.export_id))['plan']
                self.clock.advance(wall=600, monotonic=.1)
                midway = await service.get_chunked_export_status(actor, record.export_id)
                self.assertEqual(midway['expires_in_seconds'],
                                 int(plan['expires_at_unix'] - self.clock.wall()))
                self.assertEqual((await service.get_chunked_export_plan(actor, record.export_id))['plan'], plan)
                delta = {'before': -.25, 'exact': 0, 'after': .25}[position]
                self.clock.advance(wall=plan['expires_at_unix'] - self.clock.wall() + delta)
                value = await service.get_chunked_export_status(actor, record.export_id)
                self.assertEqual(value['state'], 'ready' if position == 'before' else 'expired')
                if position == 'before':
                    self.assertEqual(value['expires_in_seconds'], 0)
                    self.assertEqual((await service.get_chunked_export_plan(actor, record.export_id))['plan'], plan)
                else:
                    await self.assert_closed(record)

    async def test_monotonic_ceiling_and_observed_expiry_survive_wall_rollback(self):
        for trigger in ('wall', 'monotonic'):
            with self.subTest(trigger=trigger):
                service, actor = self.new_service(), self.actor_for('owner-a')
                ready = await self.chunk_ready(service=service, actor=actor)
                record = service._records[ready['export_id']]
                self.clock.advance(wall=3700 if trigger == 'wall' else -100,
                                   monotonic=.1 if trigger == 'wall' else 3600)
                self.assertEqual((await service.get_chunked_export_status(actor, record.export_id))['state'], 'expired')
                await self.assert_closed(record)
                self.clock.advance(wall=-4000)
                fresh = self.actor_for('owner-a')
                self.assertEqual((await service.get_chunked_export_status(fresh, record.export_id))['state'], 'expired')
                with self.assertRaises(AccessError) as denied:
                    await service.materialize_chunked_export_part(fresh, record.export_id, 0)
                self.assertEqual(denied.exception.code, 'export_unavailable')
                self.assertFalse(record.reserved)
                self.assertEqual(record.snapshot.fd, -1)


if __name__ == '__main__':
    unittest.main()
