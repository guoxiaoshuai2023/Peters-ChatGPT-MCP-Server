"""Preparation ownership and time boundaries found by independent review.

Only synthetic fixture descriptors/clocks are faulted. The FD-reuse regression
uses ordinary OS allocation, never dup2 or a descriptor owned by the service.
"""
import asyncio
import errno
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import test_chunked_export_service as fixture


class ChunkedPreparationOwnershipTests(unittest.IsolatedAsyncioTestCase):
    setUp = fixture.ChunkedManagerTests.setUp
    asyncSetUp = fixture.ChunkedManagerTests.asyncSetUp
    asyncTearDown = fixture.ChunkedManagerTests.asyncTearDown
    actor_for = fixture.ChunkedManagerTests.actor_for
    make_service = fixture.ChunkedManagerTests.make_service
    new_service = fixture.ChunkedManagerTests.new_service
    write = fixture.ChunkedManagerTests.write
    wait_until = fixture.ChunkedManagerTests.wait_until

    async def accepted_parent(self, data=b'owned bytes'):
        self.write(data=data)
        c = self.chunked.capabilities(self.actor)
        result = await self.chunked.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin',
            c['service_instance_id'], c['request_window_id'], 'ownership', wait_seconds=0)
        return self.chunked._records[result['export_id']]

    async def test_parent_expiry_before_handoff_cannot_close_reused_unrelated_fd(self):
        observed = {}
        def hook(stage, value):
            if stage == 'anonymous_unlinked':
                observed['fd'] = value[1]
            elif stage == 'before_ready':
                self.clock.advance(3601)
        self.chunked.fault_hook = hook
        record = await self.accepted_parent()
        await self.wait_until(lambda: not record.owner and record.state == 'failed')
        self.assertEqual(record.error_code, 'export_expired')
        fd = observed['fd']
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        snapshot_before, reserved_before = record.snapshot, record.reserved
        cancel = await self.chunked.cancel_chunked_export(self.actor, record.export_id)
        other_fds = []
        try:
            # Fill only currently free numbers until the OS naturally reuses
            # the confirmed-closed candidate. This is a test's unrelated file.
            for index in range(fd + 32):
                other = os.open(self.base / ('unrelated-' + str(index)),
                                os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                other_fds.append(other)
                if other == fd:
                    break
            self.assertIn(fd, other_fds, 'fixture did not naturally reuse the confirmed-closed FD')
            await asyncio.to_thread(self.chunked.close, 2)
            unexpectedly_closed = []
            for other in other_fds:
                try:
                    os.fstat(other)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                    unexpectedly_closed.append(other)
            self.assertEqual(unexpectedly_closed, [], 'service closed unrelated naturally reused descriptor')
            self.assertIsNone(snapshot_before)
            self.assertFalse(reserved_before)
            self.assertTrue(cancel['resources_released'])
            self.assertEqual(self.chunked.diagnostics()['snapshot_fds'], 0)
        finally:
            for other in other_fds:
                try:
                    os.close(other)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise

    async def cancellation_at(self, stage, *, uncertain_close=False):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        def hook(current, value):
            if current == stage:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('synthetic preparation gate timed out')
            elif current == 'before_snapshot_close' and uncertain_close:
                self.known_unclosed.append(value)
                raise OSError('synthetic close uncertainty')
        self.chunked.fault_hook = hook
        record = await self.accepted_parent(b'cancel during preparation' * 5000)
        await self.wait_until(entered.is_set)
        initial = await self.chunked.cancel_chunked_export(self.actor, record.export_id)
        self.assertEqual(initial['state'], 'cancelled')
        self.assertFalse(initial['resources_released'])
        release.set()
        await self.wait_until(lambda: not record.owner)
        settled = await self.chunked.get_chunked_export_status(self.actor, record.export_id)
        self.assertEqual(settled['state'], 'cancelled')
        self.assertEqual(settled['error_code'], 'cancelled')
        self.assertEqual(settled['resources_released'], not uncertain_close)
        repeated = await self.chunked.cancel_chunked_export(self.actor, record.export_id)
        self.assertEqual(repeated['state'], 'cancelled')
        self.assertEqual(repeated['resources_released'], settled['resources_released'])
        if uncertain_close:
            self.assertEqual(settled['cleanup']['error_code'], 'snapshot_close_pending')
            self.assertTrue(record.reserved)
        else:
            self.assertIsNone(record.snapshot)
            self.assertFalse(record.reserved)

    async def test_cancel_during_copy_retains_cancelled_after_actual_cleanup(self):
        await self.cancellation_at('copy_chunk')

    async def test_cancel_before_handoff_retains_cancelled_after_actual_cleanup(self):
        await self.cancellation_at('before_ready')

    async def test_cancel_with_unknown_close_keeps_terminal_fact_and_reservation(self):
        await self.cancellation_at('copy_chunk', uncertain_close=True)

    async def hash_phase(self, seconds_per_block):
        original = self.chunked._part_hashes
        real_pread = os.pread
        reads = []
        def progress_hash(*args, **kwargs):
            # v1's static method starts with fd; the fixed owner-aware method
            # starts with record. This permits the same regression on both.
            fd = args[0] if type(args[0]) is int else args[1]
            def timed_pread(current_fd, size, offset):
                data = real_pread(current_fd, size, offset)
                if current_fd == fd and data:
                    reads.append(len(data))
                    self.clock.advance(seconds_per_block)
                return data
            with patch.object(os, 'pread', side_effect=timed_pread):
                return original(*args, **kwargs)
        self.chunked._part_hashes = progress_hash
        record = await self.accepted_parent(b'h' * 3_000_000)
        await self.wait_until(lambda: not record.owner and record.state in {'ready', 'failed'})
        return record, reads

    async def test_continuous_slow_part_hash_reports_each_real_read_progress(self):
        record, reads = await self.hash_phase(1)
        self.assertEqual(record.state, 'ready', record.error_code)
        self.assertEqual(sum(reads), 3_000_000)
        self.assertGreater(len(reads), 30)
        self.assertEqual(record.progress_at, self.clock.monotonic())

    async def test_part_hash_true_idle_stall_is_rejected(self):
        record, reads = await self.hash_phase(31)
        self.assertEqual(record.state, 'failed')
        self.assertEqual(record.error_code, 'preparation_timeout')
        self.assertEqual(len(reads), 1)
        self.assertFalse(record.reserved)
        self.assertIsNone(record.snapshot)

    async def test_part_hash_absolute_total_limit_survives_progress_updates(self):
        record, reads = await self.hash_phase(14)
        self.assertEqual(record.state, 'failed')
        self.assertEqual(record.error_code, 'preparation_timeout')
        self.assertGreater(self.clock.monotonic() - record.started, 600)
        self.assertFalse(record.reserved)
        self.assertIsNone(record.snapshot)
