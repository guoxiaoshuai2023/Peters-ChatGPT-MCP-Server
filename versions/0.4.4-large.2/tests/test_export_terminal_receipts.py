"""Finite cancellation receipts after rotated keys and actual descriptor release."""
import asyncio
from dataclasses import replace
from datetime import datetime
import hashlib
import os
import threading
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.file_export import ExportLimits
from tests.test_large_export_service import LargeExportFixture


class TerminalReceiptTests(LargeExportFixture):
    def rotate_window(self, service=None):
        service = service or self.service
        old = service.capabilities(self.actor)
        self.clock.advance(service.limits.window_seconds + 1)
        new = service.capabilities(self.actor)
        self.assertNotEqual(old['request_window_id'], new['request_window_id'])
        self.assertEqual(service.diagnostics()['keys'], 0)
        return old, new

    async def cancel_and_close(self, export_id, service=None):
        service = service or self.service
        await service.cancel(self.actor, export_id)
        await self.wait_until(lambda: service.diagnostics()['snapshot_fds'] == 0)
        result = await service.get_status(self.actor, export_id)
        self.assertEqual(result['state'], 'cancelled')
        self.assertTrue(result['resources_released'])
        for field in ('source', 'bytes', 'sha256', 'resource_uri', 'delivery_id'):
            self.assertNotIn(field, result)
        self.assertEqual(service.diagnostics()['encoding_bytes_reserved'], 0)
        self.assertEqual(service.diagnostics()['snapshot_bytes_reserved'], 0)
        self.assertEqual(service.diagnostics()['delivery_pins'], 0)
        return result

    async def test_late_cancel_after_key_window_rotation_has_observable_released_terminal(self):
        path = self.write(data=os.urandom(100_000))
        ready = await self.ready(expected=hashlib.sha256(path.read_bytes()).hexdigest())
        old, _ = self.rotate_window()
        result = await self.cancel_and_close(ready['export_id'])
        self.assertEqual(result['terminal_receipt_expires_in_seconds'], 900)
        self.assertEqual(self.service.diagnostics()['records'], 1)
        with self.assertRaisesRegex(AccessError, 'request_window_expired'):
            await self.accepted(capability=old)
        repeated = await self.service.cancel(self.actor, ready['export_id'])
        self.assertEqual(repeated['state'], 'cancelled')
        self.assertTrue(repeated['resources_released'])

    async def test_terminal_retention_starts_after_actual_close_not_cancel_or_window(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)

        def block_close(stage, value):
            if stage == 'before_snapshot_close':
                entered.set()
                release.wait()

        service = self.make_service(hook=block_close)
        self.write(data=os.urandom(100_000))
        ready = await self.ready(service=service)
        self.rotate_window(service)
        cancelled = await service.cancel(self.actor, ready['export_id'])
        await self.wait_until(entered.is_set)
        self.assertEqual(cancelled['state'], 'cancelling')
        self.assertFalse(cancelled['resources_released'])
        self.assertNotIn('terminal_receipt_expires_in_seconds', cancelled)
        # Stay within the existing actual-close deadline. Crossing that bound
        # legitimately closes new admission as resource_stop_pending.
        self.clock.advance(.1)
        service.reap()
        pending = await service.get_status(self.actor, ready['export_id'])
        self.assertEqual(pending['state'], 'cancelling')
        self.assertFalse(pending['resources_released'])
        self.assertEqual(service.diagnostics()['snapshot_fds'], 1)
        release.set()
        await self.wait_until(lambda: service.diagnostics()['snapshot_fds'] == 0)
        final = await service.get_status(self.actor, ready['export_id'])
        self.assertEqual(final['state'], 'cancelled')
        self.assertTrue(final['resources_released'])
        self.assertIn(final['terminal_receipt_expires_in_seconds'], (899, 900))
        self.assertAlmostEqual(datetime.fromisoformat(final['terminal_receipt_expires_at']).timestamp(),
                               self.clock.wall() + 900, places=5)

    async def test_poll_and_repeat_cancel_do_not_slide_receipt_expiry(self):
        self.write()
        ready = await self.ready()
        self.rotate_window()
        first = await self.cancel_and_close(ready['export_id'])
        expires = first['terminal_receipt_expires_at']
        self.clock.advance(450)
        for _ in range(3):
            result = await self.service.get_status(self.actor, ready['export_id'])
            self.assertEqual(result['terminal_receipt_expires_at'], expires)
            self.assertEqual(result['terminal_receipt_expires_in_seconds'], 450)
        result = await self.service.cancel(self.actor, ready['export_id'])
        self.assertEqual(result['terminal_receipt_expires_at'], expires)
        self.clock.advance(449)
        result = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(result['terminal_receipt_expires_in_seconds'], 1)
        self.clock.advance(1)
        with self.assertRaisesRegex(AccessError, 'export_unavailable'):
            await self.service.get_status(self.actor, ready['export_id'])
        self.service.reap()
        self.assertEqual(self.service.diagnostics()['records'], 0)
        self.assertEqual(self.service.diagnostics()['metadata_bytes'], 0)

    async def test_terminal_receipts_use_existing_record_budget_until_finite_expiry(self):
        limits = replace(ExportLimits(), records=1, actor_records=1, close_seconds=.2)
        service = self.make_service(limits=limits)
        self.write('one.bin', b'first')
        self.write('two.bin', b'second')
        ready = await self.ready('one.bin', service=service)
        self.rotate_window(service)
        await self.cancel_and_close(ready['export_id'], service)
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await self.accepted('two.bin', key='new-while-receipt-retained', service=service)
        self.assertEqual(service.diagnostics()['records'], 1)
        self.assertGreater(service.diagnostics()['metadata_bytes'], 0)
        self.assertEqual(service.diagnostics()['snapshot_fds'], 0)
        self.clock.advance(900)
        service.reap()
        recovered = await self.ready('two.bin', key='after-receipt-expiry', service=service)
        self.assertNotEqual(recovered['export_id'], ready['export_id'])
        _, actual, _ = await self.streamed(recovered['export_id'], service=service)
        self.assertEqual(actual, hashlib.sha256(b'second').hexdigest())

    async def test_completed_stream_then_late_cancel_preserves_valid_identity_terminal(self):
        self.write(data=os.urandom(300_000))
        ready = await self.ready()
        size, digest, _ = await self.streamed(ready['export_id'])
        self.assertEqual(size, ready['bytes'])
        self.assertEqual(digest, ready['sha256'])
        self.assertTrue((await self.service.get_status(self.actor, ready['export_id']))['server_stream_finished'])
        self.rotate_window()
        final = await self.cancel_and_close(ready['export_id'])
        self.assertEqual(final['state'], 'cancelled')
        self.assertLess(self.clock.monotonic(), self.actor.deadline)
        with self.assertRaises(AccessError):
            self.service.open_resource(self.actor, '0' * 32, asyncio.get_running_loop())

    async def test_other_actor_denial_and_current_scope_revocation_do_not_revive_terminal(self):
        self.write()
        ready = await self.ready()
        self.rotate_window()
        final = await self.cancel_and_close(ready['export_id'])
        with self.assertRaisesRegex(AccessError, 'export_unavailable'):
            await self.service.get_status(self.actor_for('other-owner'), ready['export_id'])
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=('original.bin',))
        self.clock.advance(10)
        revoked = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(revoked['state'], 'revoked')
        self.assertEqual(revoked['terminal_receipt_expires_at'], final['terminal_receipt_expires_at'])
        for field in ('source', 'bytes', 'sha256', 'resource_uri', 'delivery_id'):
            self.assertNotIn(field, revoked)
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=())
        restored = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(restored['state'], 'revoked')
        denied = await self.service.materialize(self.actor, ready['export_id'])
        self.assertEqual(denied['state'], 'revoked')
        self.assertNotIn('resource_uri', denied)


if __name__ == '__main__':
    unittest.main()
