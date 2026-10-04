"""Fixed transport failure enums from real SDK operations; no secret diagnostics."""
import asyncio
from dataclasses import replace
import errno
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_export_tools import _transport_failure_category
from tests import test_export_lifecycle as lifecycle
from tests import test_export_protocol as protocol
from tests.test_streamed_resource_boundaries import SDKOutputMutation


class FixedCategoryTests(unittest.TestCase):
    def test_timeout_classification_requires_actual_send_stage(self):
        error = TimeoutError('unretained source path/token/body')
        self.assertEqual(_transport_failure_category(error, 'send'), 'send_idle_timeout')
        self.assertEqual(_transport_failure_category(error, 'owner_read'), 'owner_read_failure')
        self.assertEqual(_transport_failure_category(error, 'guard'), 'unknown_fixed')
        self.assertEqual(_transport_failure_category(error, 'template'), 'unknown_fixed')

    def test_categories_are_fixed_and_supported_by_type_and_stage(self):
        self.assertEqual(_transport_failure_category(AccessError('not retained', code='scope_changed'),
                                                     'owner_read'), 'source_guard_rejected')
        self.assertEqual(_transport_failure_category(AccessError('not retained', code='transfer_interrupted'),
                                                     'guard'), 'unknown_fixed')
        self.assertEqual(_transport_failure_category(OSError(errno.EIO, 'not retained'), 'send'),
                         'transport_os_error')
        self.assertEqual(_transport_failure_category(ValueError('not retained'), 'payload'),
                         'resource_payload_rejected')
        self.assertEqual(_transport_failure_category(ValueError('not retained'), 'template'),
                         'resource_template_rejected')
        self.assertEqual(_transport_failure_category(TypeError('not retained'), 'send'), 'unknown_fixed')


class RealFailureDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = lifecycle.ExportLifecycleTests.asyncSetUp
    cleanup_requests = lifecycle.ExportLifecycleTests.cleanup_requests
    cleanup_lifespan = lifecycle.ExportLifecycleTests.cleanup_lifespan
    track = lifecycle.ExportLifecycleTests.track
    rpc_raw = lifecycle.ExportLifecycleTests.rpc_raw
    response = staticmethod(lifecycle.ExportLifecycleTests.response)
    call = lifecycle.ExportLifecycleTests.call
    exported = lifecycle.ExportLifecycleTests.exported
    wait_for = lifecycle.ExportLifecycleTests.wait_for
    released = lifecycle.ExportLifecycleTests.released
    begin_blocked_read = lifecycle.ExportLifecycleTests.begin_blocked_read
    assert_original = lifecycle.ExportLifecycleTests.assert_original

    def install_sink(self, *, throw=False, inner=None):
        protected = AccessMiddleware(self.service.protocol.wrap(inner or self.inner), protocol.SyntheticVerifier())
        self.events = []
        def hook(event):
            self.events.append(event)
            if throw:
                raise RuntimeError('unretained diagnostic sink exception/body/token')
        async def observed(scope, receive, send):
            if scope['type'] == 'http':
                scope = {**scope, 'peters_original_transport_diagnostic': hook}
            return await protected(scope, receive, send)
        self.app = observed

    def assert_events(self, stage, category):
        self.assertEqual(self.events, ['transport_failure_stage_' + stage, 'transport_failure_' + category])
        self.assertFalse(any('unretained' in value or 'token' in value for value in self.events))

    async def test_actual_awaited_send_stall_is_send_idle_timeout_and_recovers(self):
        _, uri = await self.exported('diagnostic-send-stall')
        self.install_sink()
        self.service.limits = replace(self.service.limits, idle_seconds=.15)
        task, gate = await self.begin_blocked_read(uri)
        messages = await asyncio.wait_for(task, 3)
        self.assert_events('send', 'send_idle_timeout')
        self.assertFalse(any(m['type'] == 'http.response.body' and not m.get('more_body', False)
                             for m in messages))
        await self.released()
        self.service.limits = replace(self.service.limits, idle_seconds=2)
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()
        self.assert_events('send', 'send_idle_timeout')

    async def test_real_sdk_bad_template_reports_before_fixed_error_and_can_recover(self):
        _, uri = await self.exported('diagnostic-template')
        mutation = SDKOutputMutation(self.inner, 'wrong_length')
        self.install_sink(inner=mutation)
        messages = await self.rpc_raw('resources/read', {'uri': uri})
        self.assertEqual(messages[0]['status'], 403)
        self.assert_events('template', 'resource_template_rejected')
        await self.released()
        mutation.enabled = False
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()

    async def test_observed_scope_revocation_reports_guard_without_source_details(self):
        parent, uri = await self.exported('diagnostic-source-revocation')
        self.install_sink()
        task, gate = await self.begin_blocked_read(uri)
        self.catalog.projects['repo'] = replace(self.catalog.projects['repo'], exclude=('original.zip',))
        await self.wait_for(lambda: self.service._records[parent['export_id']].state == 'revoked',
                            'Actual resource owner did not observe exclusion')
        gate.release.set()
        messages = await asyncio.wait_for(task, 3)
        self.assert_events('guard', 'source_guard_rejected')
        self.assertFalse(any(m['type'] == 'http.response.body' and not m.get('more_body', False)
                             for m in messages))
        await self.released()

    async def test_actual_owner_io_failure_reports_owner_stage_and_same_snapshot_recovers(self):
        _, uri = await self.exported('diagnostic-owner-read')
        self.install_sink()
        def fail_read(stage, value):
            if stage == 'resource_chunk':
                raise OSError(errno.EIO, 'unretained read path/body/token')
        self.service.fault_hook = fail_read
        messages = await self.rpc_raw('resources/read', {'uri': uri})
        self.assert_events('owner_read', 'owner_read_failure')
        self.assertFalse(any(m['type'] == 'http.response.body' and not m.get('more_body', False)
                             for m in messages))
        await self.released()
        self.service.fault_hook = None
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()

    async def test_throwing_hook_cannot_change_real_stall_response_or_ownership(self):
        _, uri = await self.exported('diagnostic-sink-failure')
        self.install_sink(throw=True)
        self.service.limits = replace(self.service.limits, idle_seconds=.15)
        task, gate = await self.begin_blocked_read(uri)
        messages = await asyncio.wait_for(task, 3)
        self.assert_events('send', 'send_idle_timeout')
        self.assertFalse(any(m['type'] == 'http.response.body' and not m.get('more_body', False)
                             for m in messages))
        await self.released()
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
        self.service.limits = replace(self.service.limits, idle_seconds=2)
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()


if __name__ == '__main__':
    unittest.main()
