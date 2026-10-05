"""Real SDK response mutations and the final streamed-JSON completion barrier."""
import asyncio
import base64
import errno
import json
import unittest

from peters_mcp.cloudflare import AccessMiddleware
from tests import test_export_lifecycle as lifecycle
from tests import test_export_protocol as protocol


class SDKOutputMutation:
    """Change only the real SDK's outgoing ASGI message, never its dispatch."""

    def __init__(self, app, mode=None):
        self.app = app
        self.mode = mode
        self.enabled = True
        self.mutated = 0
        self.actual_task = None

    async def __call__(self, scope, receive, send):
        self.actual_task = asyncio.current_task()

        async def mutate(message):
            if not self.enabled:
                return await send(message)
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                if self.mode == 'compressed':
                    headers.append((b'content-encoding', b'gzip'))
                elif self.mode == 'duplicate_length':
                    length = next(v for k, v in headers if k.lower() == b'content-length')
                    headers.append((b'content-length', length))
                elif self.mode == 'wrong_length':
                    headers = [(k, b'1' if k.lower() == b'content-length' else v)
                               for k, v in headers]
                elif self.mode == 'duplicate_start':
                    await send(message)
                    self.mutated += 1
                    return await send(dict(message))
                else:
                    return await send(message)
                self.mutated += 1
                return await send({**message, 'headers': headers})
            if message['type'] == 'http.response.body' and self.mode == 'multiple_body':
                self.mutated += 1
                return await send({**message, 'more_body': True})
            return await send(message)

        return await self.app(scope, receive, mutate)


class StreamedResourceBoundaryTests(unittest.IsolatedAsyncioTestCase):
    # Reuse the actual SDK/ASGI fixture and helpers without inheriting/rerunning
    # its unrelated test methods in this narrowly scoped regression module.
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
    assert_original = lifecycle.ExportLifecycleTests.assert_original

    def observe_lease(self, stage, value):
        if stage == 'construction_finished':
            self.observed_leases.append(value)

    def install_mutation(self, mode=None):
        self.mutation = SDKOutputMutation(self.inner, mode)
        self.app = AccessMiddleware(self.service.protocol.wrap(self.mutation),
                                    protocol.SyntheticVerifier())
        self.observed_leases = []
        self.service.fault_hook = self.observe_lease

    async def assert_actual_release(self, export_id):
        await self.released()
        self.assertTrue(self.mutation.actual_task.done())
        self.assertEqual(len(self.observed_leases), 1)
        lease = self.observed_leases[0]
        self.assertTrue(lease.asgi_done)
        self.assertTrue(lease.sdk_done)
        self.assertTrue(lease.owner_complete)
        self.assertTrue(lease.released)
        with self.service.lock:
            record = self.service._records[export_id]
            self.assertEqual(record.state, 'ready')
            self.assertEqual(record.snapshot.pins, 0)
            self.assertGreaterEqual(record.snapshot.fd, 0)
            self.assertFalse(record.server_stream_finished)
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 1)

    async def rejected_template_recovers(self, mode):
        metadata, uri = await self.exported('sdk-template-' + mode)
        self.install_mutation(mode)
        messages = await self.rpc_raw('resources/read', {'uri': uri})
        self.assertEqual(self.mutation.mutated, 1)
        starts = [m for m in messages if m['type'] == 'http.response.start']
        self.assertEqual([m['status'] for m in starts], [403],
                         'SDK headers escaped before response-template validation')
        body = b''.join(m.get('body', b'') for m in messages
                        if m['type'] == 'http.response.body')
        self.assertEqual(json.loads(body), {'error': 'Original export is unavailable.'})
        lease = self.observed_leases[0]
        self.assertNotIn(base64.b64encode(lease.marker), body)
        self.assertNotIn(base64.b64encode(self.body[:48]), body)
        self.assertEqual(lease.stream_bytes_read, 0)
        await self.assert_actual_release(metadata['export_id'])
        # This is the same still-authorized snapshot/reference, without a new
        # export, replacement file, raised limit, or fabricated completion flag.
        self.mutation.enabled = False
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()
        with self.service.lock:
            self.assertTrue(self.service._records[metadata['export_id']].server_stream_finished)

    async def test_compressed_sdk_template_rejects_before_headers_and_recovers(self):
        await self.rejected_template_recovers('compressed')

    async def test_duplicate_length_rejects_before_headers_and_recovers(self):
        await self.rejected_template_recovers('duplicate_length')

    async def test_wrong_length_rejects_before_headers_and_recovers(self):
        await self.rejected_template_recovers('wrong_length')

    async def test_multiple_sdk_body_rejects_before_headers_and_recovers(self):
        await self.rejected_template_recovers('multiple_body')

    async def test_duplicate_start_rejects_before_headers_and_recovers(self):
        await self.rejected_template_recovers('duplicate_start')

    async def test_final_owner_failure_omits_json_suffix_and_same_snapshot_recovers(self):
        metadata, uri = await self.exported('sdk-final-owner-barrier')
        self.install_mutation()
        barrier_failures = []

        def fail_final_barrier(stage, value):
            self.observe_lease(stage, value)
            if stage == 'before_stream_finish':
                barrier_failures.append(value)
                raise OSError(errno.EIO, 'synthetic final-stream barrier failure')

        self.service.fault_hook = fail_final_barrier
        messages = await self.rpc_raw('resources/read', {'uri': uri})
        self.assertEqual(len(barrier_failures), 1)
        self.assertEqual(messages[0]['status'], 200)
        bodies = [m for m in messages if m['type'] == 'http.response.body']
        self.assertGreater(len(bodies), 1)
        self.assertTrue(all(m.get('more_body', False) for m in bodies),
                        'Failed final owner barrier produced a complete JSON response')
        with self.assertRaises(json.JSONDecodeError):
            json.loads(b''.join(m['body'] for m in bodies))
        lease = self.observed_leases[0]
        self.assertEqual(lease.stream_bytes_read, len(self.body))
        self.assertFalse(lease.stream_finished)
        self.assertFalse(lease.final_body_forwarded)
        await self.assert_actual_release(metadata['export_id'])
        self.service.fault_hook = None
        self.mutation.enabled = False
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()
        with self.service.lock:
            self.assertTrue(self.service._records[metadata['export_id']].server_stream_finished)


if __name__ == '__main__':
    unittest.main()
