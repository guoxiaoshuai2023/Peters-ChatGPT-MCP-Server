"""Actual owner IO/guard exit barriers, with explicit simulated transport facts."""
import asyncio
from contextlib import contextmanager
import hashlib
import os
import threading
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.file_export import ExportLimits, STREAM_CHUNK, SERIALIZATION_BYTES
from tests.test_large_export_service import LargeExportFixture


class LargeExportStreamOwnerTests(LargeExportFixture):
    async def test_snapshot_change_after_prehash_never_releases_last_bad_chunk_and_recovers(self):
        changed = False
        def fault(stage, lease):
            nonlocal changed
            if stage == 'construction_finished' and not changed:
                changed = True
                os.pwrite(lease.record.snapshot.fd, b'X', lease.record.snapshot.size - 1)
        service = self.make_service(hook=fault)
        path = self.write(data=b'A' * (STREAM_CHUNK * 2 + 200))
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        ready = await self.ready(service=service, expected=expected)
        lease, ref = await self.opened(ready['export_id'], service=service)
        self.assertEqual(len(await lease.next_chunk(0)), STREAM_CHUNK)
        self.assertEqual(len(await lease.next_chunk(STREAM_CHUNK)), STREAM_CHUNK)
        with self.assertRaises(AccessError) as observed:
            await lease.next_chunk(STREAM_CHUNK * 2)
        self.assertEqual(observed.exception.code, 'snapshot_hash_mismatch')
        self.assertFalse(lease.stream_finished)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        self.assertFalse((await service.get_status(self.actor, ready['export_id']))['server_stream_finished'])
        await service.cancel(self.actor, ready['export_id'])
        await self.final_status(ready['export_id'], service=service, states=('cancelled',))
        recovered = await self.ready(key='snapshot-corruption-recovery', service=service, expected=expected)
        _, actual, _ = await self.streamed(recovered['export_id'], service=service)
        self.assertEqual(actual, expected)

    async def test_stream_offset_must_be_contiguous_and_chunk_limit_cannot_be_bypassed(self):
        self.write(data=os.urandom(100_000))
        ready = await self.ready()
        lease, _ = await self.opened(ready['export_id'])
        for offset, size in ((True, 1), (0, STREAM_CHUNK + 1), (-1, 1)):
            with self.assertRaises(AccessError):
                await lease.next_chunk(offset, size)
        with self.assertRaises(AccessError) as observed:
            await lease.next_chunk(1, 1000)
        self.assertEqual(observed.exception.code, 'invalid_stream_offset')
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        _, actual, _ = await self.streamed(ready['export_id'])
        self.assertEqual(actual, ready['sha256'])

    async def test_early_finish_cannot_produce_a_complete_stream_then_same_snapshot_recovers(self):
        self.write(data=os.urandom(100_000))
        ready = await self.ready()
        lease, _ = await self.opened(ready['export_id'])
        await lease.next_chunk(0, 1000)
        with self.assertRaises(AccessError):
            await lease.finish_stream()
        self.assertFalse(lease.stream_finished)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        _, actual, _ = await self.streamed(ready['export_id'])
        self.assertEqual(actual, ready['sha256'])

    async def test_cancelled_chunk_waiter_keeps_actual_blocked_owner_pin_and_budget_then_recovers(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        blocked = False
        def fault(stage, value):
            nonlocal blocked
            if stage == 'resource_chunk' and not blocked:
                blocked = True
                entered.set()
                release.wait()
        service = self.make_service(hook=fault)
        self.write(data=os.urandom(100_000))
        ready = await self.ready(service=service)
        lease, _ = await self.opened(ready['export_id'], service=service)
        task = asyncio.create_task(lease.next_chunk(0, 1000))
        await self.wait_until(entered.is_set)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        lease.mark_transport(asgi=True, sdk=True)
        await asyncio.sleep(.05)
        self.assertFalse(lease.owner_complete)
        self.assertFalse(lease.released)
        self.assertEqual(service.diagnostics()['active_responses'], 1)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], SERIALIZATION_BYTES)
        release.set()
        await self.wait_until(lambda: lease.owner_complete and lease.released)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], 0)
        _, actual, _ = await self.streamed(ready['export_id'], service=service)
        self.assertEqual(actual, ready['sha256'])

    async def test_cancel_export_during_actual_read_defers_close_then_new_key_full_recovery_succeeds(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        blocked = False
        def fault(stage, value):
            nonlocal blocked
            if stage == 'resource_chunk' and not blocked:
                blocked = True
                entered.set()
                release.wait()
        service = self.make_service(hook=fault)
        self.write(data=os.urandom(500_000))
        ready = await self.ready(service=service)
        lease, _ = await self.opened(ready['export_id'], service=service)
        task = asyncio.create_task(lease.next_chunk(0))
        await self.wait_until(entered.is_set)
        cancelled = await service.cancel(self.actor, ready['export_id'])
        self.assertEqual(cancelled['state'], 'cancelling')
        self.assertFalse(cancelled['resources_released'])
        self.assertEqual(service.diagnostics()['delivery_pins'], 0)
        self.assertEqual(service.diagnostics()['snapshot_fds'], 1)
        lease.mark_transport(asgi=True, sdk=True)
        self.assertFalse(lease.released)
        release.set()
        with self.assertRaises(AccessError):
            await task
        await self.wait_until(lambda: lease.released)
        final = await self.final_status(ready['export_id'], service=service, states=('cancelled',))
        self.assertTrue(final['resources_released'])
        self.assertEqual(service.diagnostics()['snapshot_fds'], 0)
        recovered = await self.ready(key='read-cancel-recovery', service=service, expected=ready['sha256'])
        size, actual, _ = await self.streamed(recovered['export_id'], service=service)
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(actual, ready['sha256'])

    async def test_active_stream_crosses_ordinary_ready_expiry_but_not_absolute_age(self):
        self.write(data=os.urandom(100_000))
        service = self.make_service(limits=ExportLimits(ready_seconds=30, delivery_seconds=10,
            absolute_seconds=120, transfer_seconds=100, idle_seconds=90, close_seconds=.2))
        ready = await self.ready(service=service)
        lease, _ = await self.opened(ready['export_id'], service=service)
        self.clock.advance(40)
        service.reap()
        self.assertEqual(service.diagnostics()['delivery_pins'], 0)
        self.assertEqual((await service.get_status(self.actor, ready['export_id']))['state'], 'ready')
        block = await lease.next_chunk(0)
        self.assertEqual(hashlib.sha256(block).hexdigest(), ready['sha256'])
        lease.sent()
        await lease.finish_stream()
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released)
        service.reap()
        await self.wait_until(lambda: service.diagnostics()['snapshot_fds'] == 0)

    async def test_final_owner_guard_barrier_precedes_finish_ack_and_actual_transport_termination(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def fault(stage, lease):
            if stage == 'before_stream_finish':
                entered.set()
                release.wait()
        service = self.make_service(hook=fault)
        self.write(data=os.urandom(100_000))
        ready = await self.ready(service=service)
        lease, _ = await self.opened(ready['export_id'], service=service)
        await lease.next_chunk(0)
        finish = asyncio.create_task(lease.finish_stream())
        await self.wait_until(entered.is_set)
        self.assertFalse(finish.done())
        self.assertFalse(lease.stream_finished)
        self.assertFalse(lease.owner_complete)
        release.set()
        await finish
        self.assertTrue(lease.stream_finished)
        self.assertFalse(lease.owner_complete)
        lease.mark_transport(asgi=True)
        await asyncio.sleep(.05)
        self.assertFalse(lease.released)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], SERIALIZATION_BYTES)
        lease.mark_transport(sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released and lease.owner_complete)
        with self.assertRaises(AccessError):
            await lease.next_chunk(0)

    async def test_actual_owner_scope_exit_failure_withholds_final_finish_ack_then_new_request_recovers(self):
        service = self.make_service()
        self.write(data=os.urandom(200_000))
        ready = await self.ready(service=service)
        original_scope = service.sources.scope
        failed = False
        @contextmanager
        def scope_with_exit_failure(*args, **kwargs):
            nonlocal failed
            with original_scope(*args, **kwargs) as scope:
                yield scope
            if threading.current_thread().name == 'original-export-3' and not failed:
                failed = True
                raise AccessError('Synthetic post-guard-exit failure.', code='private_protection_unavailable')
        service.sources.scope = scope_with_exit_failure
        lease, _ = await self.opened(ready['export_id'], service=service)
        await lease.next_chunk(0)
        await lease.next_chunk(STREAM_CHUNK)
        with self.assertRaises(AccessError):
            await lease.finish_stream()
        self.assertFalse(lease.stream_finished)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        revoked = await service.get_status(self.actor, ready['export_id'])
        self.assertEqual(revoked['state'], 'revoked')
        self.assertNotIn('sha256', revoked)
        await self.wait_until(lambda: service.diagnostics()['snapshot_fds'] == 0)
        recovered = await self.ready(key='guard-exit-recovery', service=service, expected=ready['sha256'])
        _, actual, _ = await self.streamed(recovered['export_id'], service=service)
        self.assertEqual(actual, ready['sha256'])

    async def test_empty_file_finishes_with_independent_empty_hash(self):
        self.write(data=b'')
        ready = await self.ready()
        size, actual, _ = await self.streamed(ready['export_id'])
        self.assertEqual(size, 0)
        self.assertEqual(actual, hashlib.sha256(b'').hexdigest())


if __name__ == '__main__':
    unittest.main()
