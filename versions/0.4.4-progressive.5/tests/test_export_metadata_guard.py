"""Policy changes during real metadata-owner result construction stay hidden."""
import asyncio
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from tests import test_file_export


class ExportMetadataGuardTests(unittest.IsolatedAsyncioTestCase):
    setUp = test_file_export.ExportTests.setUp
    asyncTearDown = test_file_export.ExportTests.asyncTearDown
    actor_for = test_file_export.ExportTests.actor_for
    make_service = test_file_export.ExportTests.make_service
    write = test_file_export.ExportTests.write
    wait_until = test_file_export.ExportTests.wait_until
    accepted = test_file_export.ExportTests.accepted
    status = test_file_export.ExportTests.status
    ready = test_file_export.ExportTests.ready
    assert_hidden = test_file_export.ExportTests.assert_hidden

    async def check_result_construction_race(self, *, replay):
        self.write()
        ready = await self.ready()
        original_project = self.catalog.projects['synthetic']
        entered, resume = threading.Event(), threading.Event()
        self.gates.append(resume)
        observations = []
        original_status = self.service._status_locked

        def pause_before_result(record):
            if not observations:
                observations.append(getattr(self.service.registry._local, 'guard', None) is not None)
                entered.set()
                if not resume.wait(3):
                    raise RuntimeError('Synthetic result-construction barrier timed out.')
            return original_status(record)

        result = error = None
        try:
            with patch.object(self.service, '_status_locked', pause_before_result):
                operation = self.accepted() if replay else self.service.get_status(self.actor, ready['export_id'])
                task = asyncio.create_task(operation)
                try:
                    self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                    # The policy update does not take the export manager lock;
                    # real configuration refresh uses this independent lock too.
                    with self.catalog._refresh_lock:
                        self.catalog.projects['synthetic'] = replace(original_project,
                            exclude=('original.bin',))
                finally:
                    resume.set()
                try:
                    result = await asyncio.wait_for(task, 3)
                except AccessError as observed:
                    error = observed
            if error is not None:
                self.assertIn(error.code, {'scope_changed', 'access_denied', 'sensitive_source'})
            else:
                self.assertEqual(result['state'], 'revoked',
                    'Metadata returned a ready reference after revocation during result construction.')
                self.assert_hidden(result)
            self.assertEqual(observations, [True],
                'Source guard ended before the actual owner built response metadata.')
        finally:
            self.catalog.projects['synthetic'] = original_project
            resume.set()

        restored = await self.service.get_status(self.actor, ready['export_id'])
        self.assertEqual(restored['state'], 'revoked')
        self.assert_hidden(restored)
        replayed = await self.accepted()
        self.assertEqual(replayed['export_id'], ready['export_id'])
        self.assertEqual(replayed['state'], 'revoked')
        self.assert_hidden(replayed)

    async def test_status_keeps_guard_through_result_and_late_revocation_is_terminal(self):
        await self.check_result_construction_race(replay=False)

    async def test_same_key_replay_keeps_guard_through_result_and_late_revocation_is_terminal(self):
        await self.check_result_construction_race(replay=True)

    async def test_same_key_replay_observes_ready_expiry_without_waiting_for_reaper(self):
        self.write()
        before = await self.ready()
        self.clock.advance(self.service.limits.ready_seconds + .01)
        # No reap() or status call runs before this same-window replay.
        expired = await self.accepted()
        self.assertEqual(expired['export_id'], before['export_id'])
        self.assertEqual(expired['state'], 'expired')
        self.assert_hidden(expired)
        fresh = await self.ready(key='fresh-after-ttl')
        self.assertNotEqual(fresh['export_id'], before['export_id'])
        self.assertEqual(fresh['sha256'], before['sha256'])


if __name__ == '__main__':
    unittest.main()
