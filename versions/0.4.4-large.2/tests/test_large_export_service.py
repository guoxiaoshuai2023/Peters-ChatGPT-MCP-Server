"""200 MB manager budgets, reference lifetime and actual synthetic cleanup.

These exercise real source/snapshot IO. SDK and ChatGPT consumption are separate.
"""
import asyncio
from dataclasses import replace
import hashlib
import os
import queue
import threading
import time
import tracemalloc
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.file_export import (ExportConfig, ExportLimits, MAX_ORIGINAL_BYTES,
    LEGACY_PROFILE_ID, SERIALIZATION_BYTES, STREAM_CHUNK)
from tests import test_file_export


class LargeExportFixture(unittest.IsolatedAsyncioTestCase):
    setUp = test_file_export.ExportTests.setUp
    asyncTearDown = test_file_export.ExportTests.asyncTearDown
    actor_for = test_file_export.ExportTests.actor_for
    make_service = test_file_export.ExportTests.make_service
    write = test_file_export.ExportTests.write
    wait_until = test_file_export.ExportTests.wait_until
    accepted = test_file_export.ExportTests.accepted

    async def final_status(self, export_id, *, service=None, actor=None,
                           states=('ready', 'failed', 'revoked', 'expired', 'cancelled')):
        service, actor = service or self.service, actor or self.actor
        result = None
        for _ in range(400):
            result = await service.get_status(actor, export_id)
            if result['state'] in states:
                return result
            await asyncio.sleep(.01)
        self.fail('Synthetic manager did not settle: ' + str(result))

    async def ready(self, name='original.bin', key='request-1', **kwargs):
        result = await self.accepted(name, key, **kwargs)
        result = await self.final_status(result['export_id'], service=kwargs.get('service'), actor=kwargs.get('actor'))
        self.assertEqual(result['state'], 'ready', result)
        return result

    async def opened(self, export_id, *, service=None, actor=None):
        service, actor = service or self.service, actor or self.actor
        materialized = await service.materialize(actor, export_id)
        self.assertEqual(materialized['state'], 'ready')
        lease = service.open_resource(actor, materialized['delivery_id'], asyncio.get_running_loop())
        marker = await asyncio.wait_for(lease.bytes_ready(), 4)
        self.assertEqual(marker, lease.marker)
        self.assertEqual(len(marker), 24)
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 4)
        return lease, materialized

    async def streamed(self, export_id, *, service=None, actor=None):
        service, actor = service or self.service, actor or self.actor
        lease, materialized = await self.opened(export_id, service=service, actor=actor)
        digest, offset = hashlib.sha256(), 0
        while offset < materialized['bytes']:
            block = await asyncio.wait_for(lease.next_chunk(offset), 4)
            self.assertTrue(block)
            self.assertLessEqual(len(block), STREAM_CHUNK)
            digest.update(block)
            offset += len(block)
            lease.sent()
            block = None
        await asyncio.wait_for(lease.finish_stream(), 4)
        self.assertTrue(lease.stream_finished)
        # Explicit manager fixture: actual SDK/ASGI completion is tested separately.
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.owner_complete and lease.released)
        self.assertEqual(service.diagnostics()['active_responses'], 0)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], 0)
        return offset, digest.hexdigest(), lease

    def generate(self, size, name='original.bin'):
        path = self.root / name
        block = os.urandom(64 * 1024)
        digest, offset = hashlib.sha256(), 0
        with path.open('xb') as output:
            while offset < size:
                chunk = block[:min(len(block), size - offset)]
                output.write(chunk)
                digest.update(chunk)
                offset += len(chunk)
        return path, digest.hexdigest()


class LargeExportServiceTests(LargeExportFixture):
    def test_engineering_config_budget_and_legacy_profile_acceptance(self):
        self.assertEqual(MAX_ORIGINAL_BYTES, 200_000_000)
        self.assertEqual(SERIALIZATION_BYTES, 4 * 1024 * 1024)
        self.assertEqual(ExportLimits().actor_snapshot_bytes, 256 * 1024 * 1024)
        self.assertEqual(ExportLimits().snapshot_bytes, 512 * 1024 * 1024)
        self.assertEqual(ExportLimits().ready_seconds, 3600)
        self.assertEqual(ExportLimits().absolute_seconds, 7200)
        self.assertEqual(ExportLimits().delivery_seconds, 1800)
        self.assertEqual(ExportLimits().transfer_seconds, 3600)
        self.assertEqual(ExportLimits().idle_seconds, 60)
        replace(self.service.config, profile_id=LEGACY_PROFILE_ID).validate()
        with self.assertRaises(AccessError):
            replace(self.service.config, max_file_bytes=200_000_001).validate()
        with self.assertRaises(AccessError):
            replace(self.service.config, max_file_bytes=True).validate()
        for profile in (None, {}, [], 42, 'unknown-profile'):
            with self.assertRaises(AccessError):
                replace(self.service.config, profile_id=profile).validate()
        self.assertEqual(self.service.capabilities(self.actor)['client_ingestion']['validation'],
                         'requires_native_evidence')

    async def test_200mb_actual_copy_and_stream_hash_stay_under_encoding_budget(self):
        _, expected = self.generate(MAX_ORIGINAL_BYTES)
        measured_start = time.monotonic()
        tracemalloc.start(1)
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            ready = await self.ready(expected=expected)
            self.assertEqual(ready['bytes'], MAX_ORIGINAL_BYTES)
            self.assertEqual(ready['sha256'], expected)
            self.assertNotIn('resource_uri', ready)
            replay = await self.accepted(expected=expected)
            self.assertEqual(replay['export_id'], ready['export_id'])
            self.assertNotIn('resource_uri', replay)
            for _ in range(3):
                status = await self.service.get_status(self.actor, ready['export_id'])
                self.assertNotIn('resource_uri', status)
            size, received_hash, _ = await self.streamed(ready['export_id'])
            self.assertEqual(size, MAX_ORIGINAL_BYTES)
            self.assertEqual(received_hash, expected)
            self.assertLess(tracemalloc.get_traced_memory()[1] - baseline, SERIALIZATION_BYTES)
            cancelled = await self.service.cancel(self.actor, ready['export_id'])
            self.assertIn(cancelled['state'], ('cancelling', 'cancelled'))
            final = await self.final_status(ready['export_id'], states=('cancelled',))
            self.assertTrue(final['resources_released'])
            self.assertEqual(self.service.diagnostics()['snapshot_fds'], 0)
            self.assertEqual(self.service.diagnostics()['snapshot_bytes_reserved'], 0)
            recovered = await self.ready(key='actual-200mb-post-cancel', expected=expected)
            self.assertNotEqual(recovered['export_id'], ready['export_id'])
            size, received_hash, _ = await self.streamed(recovered['export_id'])
            self.assertEqual(size, MAX_ORIGINAL_BYTES)
            self.assertEqual(received_hash, expected)
            await self.service.cancel(self.actor, recovered['export_id'])
            final = await self.final_status(recovered['export_id'], states=('cancelled',))
            self.assertTrue(final['resources_released'])
            peak = tracemalloc.get_traced_memory()[1] - baseline
            self.assertLess(peak, SERIALIZATION_BYTES)
            print('SYNTHETIC_200MB_OWNER_EVIDENCE', {'original_bytes': MAX_ORIGINAL_BYTES,
                'full_streams_including_cancel_recovery': 2, 'traced_peak_delta_bytes': peak,
                'duration_seconds': round(time.monotonic() - measured_start, 6),
                'snapshot_fds_after_actual_close': self.service.diagnostics()['snapshot_fds'],
                'encoding_bytes_reserved_after': self.service.diagnostics()['encoding_bytes_reserved']})
        finally:
            tracemalloc.stop()

    async def test_over_limit_rejected_before_any_accepted_record_or_disk_copy(self):
        with (self.root / 'oversize.bin').open('xb') as source:
            source.truncate(MAX_ORIGINAL_BYTES + 1)
        with self.assertRaises(AccessError) as observed:
            await self.accepted('oversize.bin')
        self.assertEqual(observed.exception.code, 'client_ingestion_unverified')
        self.assertEqual(self.service.diagnostics()['records'], 0)
        self.assertEqual(self.service.diagnostics()['snapshot_bytes_reserved'], 0)
        self.assertEqual(list(self.spool.iterdir()), [])

    async def test_materialization_is_separate_repeatable_and_actor_bound(self):
        self.write(data=os.urandom(200_000))
        ready = await self.ready()
        first = await self.service.materialize(self.actor, ready['export_id'])
        self.clock.advance(20)
        second = await self.service.materialize(self.actor, ready['export_id'])
        self.assertEqual(first['delivery_id'], second['delivery_id'])
        self.assertEqual(first['materialization_expires_at'], second['materialization_expires_at'])
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 1)
        other = self.actor_for('different-owner')
        with self.assertRaises(AccessError):
            await self.service.materialize(other, ready['export_id'])
        with self.assertRaises(AccessError):
            self.service.open_resource(other, first['delivery_id'], asyncio.get_running_loop())
        self.assertEqual(self.service.diagnostics()['active_responses'], 0)
        size, digest, _ = await self.streamed(ready['export_id'])
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(digest, ready['sha256'])

    async def test_confirmed_handoff_releases_wait_pin_and_explicit_reclaim_does_not_slide_expiry(self):
        self.write(data=os.urandom(100_000))
        ready = await self.ready()
        first = await self.service.materialize(self.actor, ready['export_id'])
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 1)
        lease, handed_off = await self.opened(ready['export_id'])
        self.assertEqual(handed_off['delivery_id'], first['delivery_id'])
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 0)
        self.assertEqual(self.service.diagnostics()['snapshot_pins'], 1)
        block = await lease.next_chunk(0)
        self.assertEqual(hashlib.sha256(block).hexdigest(), ready['sha256'])
        await lease.finish_stream()
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released)
        self.assertEqual(self.service.diagnostics()['snapshot_pins'], 0)
        self.clock.advance(20)
        status = await self.service.get_status(self.actor, ready['export_id'])
        self.assertTrue(status['may_expire_early'])
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 0)
        reclaimed = await self.service.materialize(self.actor, ready['export_id'])
        self.assertEqual(reclaimed['delivery_id'], first['delivery_id'])
        self.assertEqual(reclaimed['materialization_expires_at'], first['materialization_expires_at'])
        self.assertEqual(reclaimed['materialization_expires_in_seconds'], 1780)
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 1)
        _, actual, _ = await self.streamed(ready['export_id'])
        self.assertEqual(actual, ready['sha256'])
        self.assertEqual(self.service.diagnostics()['snapshot_pins'], 0)

    async def test_failed_resource_queue_handoff_preserves_confirmation_pin(self):
        self.write(data=os.urandom(10_000))
        ready = await self.ready()
        delivery = await self.service.materialize(self.actor, ready['export_id'])
        with patch.object(self.service._resource_queue, 'put_nowait', side_effect=queue.Full):
            with self.assertRaises(AccessError) as observed:
                self.service.open_resource(self.actor, delivery['delivery_id'], asyncio.get_running_loop())
        self.assertEqual(observed.exception.code, 'busy')
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 1)
        self.assertEqual(self.service.diagnostics()['snapshot_pins'], 1)
        self.assertEqual(self.service.diagnostics()['active_responses'], 0)
        _, actual, _ = await self.streamed(ready['export_id'])
        self.assertEqual(actual, ready['sha256'])
        self.assertEqual(self.service.diagnostics()['delivery_pins'], 0)

    async def test_nine_normal_new_exports_succeed_with_cache_eviction_after_consumption(self):
        self.write(data=os.urandom(50_000))
        first = None
        for index in range(9):
            for attempt in range(400):
                try:
                    ready = await self.ready(key='normal-' + str(index))
                    break
                except AccessError as observed:
                    if observed.code != 'busy':
                        raise
                    await asyncio.sleep(.005)
            else:
                self.fail('Normal cache eviction did not complete')
            if first is None:
                first = ready
            size, actual, _ = await self.streamed(ready['export_id'])
            self.assertEqual(size, ready['bytes'])
            self.assertEqual(actual, ready['sha256'])
            self.assertEqual(self.service.diagnostics()['delivery_pins'], 0)
            self.assertEqual(self.service.diagnostics()['snapshot_pins'], 0)
            self.assertLessEqual(self.service.diagnostics()['snapshot_reservations'], 4)
        expired = await self.service.get_status(self.actor, first['export_id'])
        self.assertEqual(expired['state'], 'expired')
        self.assertNotIn('sha256', expired)
        self.assertNotIn('resource_uri', expired)

    async def test_confirmation_pin_prevents_pressure_eviction_then_expired_reference_recovers(self):
        self.write(data=os.urandom(10_000))
        self.write('second.bin', data=os.urandom(10_000))
        service = self.make_service(limits=ExportLimits(snapshots=1, actor_snapshots=1, close_seconds=.2))
        ready = await self.ready(service=service)
        first = await service.materialize(self.actor, ready['export_id'])
        with self.assertRaises(AccessError) as observed:
            await self.accepted('second.bin', key='pressure', service=service)
        self.assertEqual(observed.exception.code, 'resource_budget_exhausted')
        self.assertEqual((await service.get_status(self.actor, ready['export_id']))['state'], 'ready')
        self.clock.advance(1801)
        service.reap()
        self.assertEqual(service.diagnostics()['delivery_pins'], 0)
        with self.assertRaises(AccessError):
            service.open_resource(self.actor, first['delivery_id'], asyncio.get_running_loop())
        self.assertEqual((await service.get_status(self.actor, ready['export_id']))['state'], 'ready')
        refreshed = await service.materialize(self.actor, ready['export_id'])
        self.assertNotEqual(refreshed['delivery_id'], first['delivery_id'])
        size, digest, _ = await self.streamed(ready['export_id'], service=service)
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(digest, ready['sha256'])

    async def test_late_confirmation_extends_retention_and_new_key_same_hash_recovers(self):
        self.write(data=os.urandom(10_000))
        ready = await self.ready()
        self.clock.advance(3500)
        delivered = await self.service.materialize(self.actor, ready['export_id'])
        self.assertEqual(delivered['expires_in_seconds'], 1800)
        self.clock.advance(600)
        self.assertEqual((await self.service.get_status(self.actor, ready['export_id']))['state'], 'ready')
        size, digest, _ = await self.streamed(ready['export_id'])
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(digest, ready['sha256'])
        self.clock.advance(1201)
        actor = self.actor_for('owner-a')
        self.service.reap()
        await self.wait_until(lambda: self.service.diagnostics()['snapshot_fds'] == 0)
        recovered = await self.ready(key='new-hash-constrained-recovery', actor=actor, expected=ready['sha256'])
        self.assertNotEqual(recovered['export_id'], ready['export_id'])
        size, digest, _ = await self.streamed(recovered['export_id'], actor=actor)
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(digest, ready['sha256'])

    async def test_materialization_retention_cannot_cross_absolute_age(self):
        self.write(data=os.urandom(10_000))
        service = self.make_service(limits=ExportLimits(ready_seconds=7200, close_seconds=.2))
        ready = await self.ready(service=service)
        self.clock.advance(7000)
        actor = self.actor_for('owner-a')
        ref = await service.materialize(actor, ready['export_id'])
        self.assertEqual(ref['materialization_expires_in_seconds'], 200)
        self.assertEqual(ref['expires_in_seconds'], 200)
        self.clock.advance(201)
        service.reap()
        await self.wait_until(lambda: service.diagnostics()['snapshot_fds'] == 0)
        self.assertEqual(service.diagnostics()['delivery_pins'], 0)

    async def test_cancel_blocked_prepare_keeps_owner_then_actual_close_and_new_request_succeeds(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def fault(stage, value):
            if stage == 'copy_chunk':
                entered.set()
                release.wait()
        service = self.make_service(hook=fault)
        path = self.write(data=os.urandom(100_000))
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        accepted = await self.accepted(service=service, expected=expected)
        await self.wait_until(entered.is_set)
        cancelled = await service.cancel(self.actor, accepted['export_id'])
        self.assertEqual(cancelled['state'], 'cancelling')
        self.assertFalse(cancelled['resources_released'])
        self.assertEqual(service.diagnostics()['prepare_owners'], 1)
        self.assertEqual(service.diagnostics()['snapshot_reservations'], 1)
        release.set()
        final = await self.final_status(accepted['export_id'], service=service, states=('cancelled',))
        self.assertTrue(final['resources_released'])
        repeated = await self.accepted(service=service, expected=expected)
        self.assertEqual(repeated['state'], 'cancelled')
        recovered = await self.ready(key='cancel-recovery', service=service, expected=expected)
        _, actual, _ = await self.streamed(recovered['export_id'], service=service)
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
