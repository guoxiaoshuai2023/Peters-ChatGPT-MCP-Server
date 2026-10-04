"""Real modern SDK/ASGI failures; no fabricated transport completion events."""
import asyncio
import base64
from contextlib import suppress
from dataclasses import replace
import gc
import hashlib
import json
from pathlib import Path
import tempfile
import time
import tracemalloc
import unittest

from mcp.server.transport_security import TransportSecuritySettings

from tests import test_export_protocol as protocol_fixtures
from peters_mcp.catalog import Catalog, Project
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_export import ExportConfig, ExportLimits, FileExportService, SERIALIZATION_BYTES
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.server import create_server


class BodyGate:
    """A real awaited ASGI send that can block, fail, or delay cancellation."""
    def __init__(self, *, fail=False, delay_cancel=False):
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.cancel_requested = asyncio.Event()
        self.fail = fail
        self.delay_cancel = delay_cancel
        self.messages = []
        self.blocked = False

    async def send(self, message):
        if message['type'] == 'http.response.body' and message.get('body') and not self.blocked:
            self.blocked = True
            self.entered.set()
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancel_requested.set()
                if not self.delay_cancel:
                    raise
                await self.release.wait()
            if self.fail:
                raise OSError('synthetic ASGI send failure')
        self.messages.append(dict(message))


class ExportLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-lifecycle-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.body = b'synthetic unchanged original\x00' * 24000
        self.original = self.repo / 'original.zip'
        self.original.write_bytes(self.body)
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        registry.initialize()
        registry.register_pending(self.spool, read_roots=[self.repo])
        registry.activate(self.spool, read_roots=[self.repo])
        self.catalog = Catalog([Project('repo', 'Synthetic', self.repo)], private_registry=registry)
        limits = replace(ExportLimits(), health_seconds=.025, reap_seconds=.025,
                         idle_seconds=2, close_seconds=.15)
        self.service = FileExportService(self.catalog, ExportConfig(True, self.spool, min_free_bytes=0),
                                         limits=limits)
        self.server = create_server(self.catalog, exports=self.service)
        self.inner = self.server.streamable_http_app(stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        self.app = AccessMiddleware(self.service.protocol.wrap(self.inner), protocol_fixtures.SyntheticVerifier())
        self.lifespan_started = asyncio.Event()
        self.lifespan_stop = asyncio.Event()

        async def run_lifespan():
            async with self.inner.router.lifespan_context(self.inner):
                self.lifespan_started.set()
                await self.lifespan_stop.wait()

        self.lifespan_task = asyncio.create_task(run_lifespan())
        await asyncio.wait_for(self.lifespan_started.wait(), timeout=3)
        self.addAsyncCleanup(self.cleanup_lifespan)
        self.tasks = set()
        self.gates = []
        self.addAsyncCleanup(self.cleanup_requests)

    async def cleanup_requests(self):
        for gate in self.gates:
            gate.release.set()
        for task in tuple(self.tasks):
            if not task.done():
                task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, timeout=3)

    async def cleanup_lifespan(self):
        self.lifespan_stop.set()
        await asyncio.wait_for(self.lifespan_task, timeout=4)

    def track(self, task):
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def rpc_raw(self, method, params, *, gate=None):
        protocol = '2026-07-28'
        params = {**params, '_meta': {'io.modelcontextprotocol/protocolVersion': protocol,
                                    'io.modelcontextprotocol/clientCapabilities': {}}}
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        headers = [(b'cf-access-jwt-assertion', b'synthetic-a'),
                   (b'mcp-protocol-version', protocol.encode()),
                   (b'mcp-method', method.encode()),
                   (b'accept', b'application/json, text/event-stream'),
                   (b'content-type', b'application/json'),
                   (b'content-length', str(len(body)).encode())]
        if method in ('tools/call', 'resources/read'):
            name = params['name' if method == 'tools/call' else 'uri']
            headers.append((b'mcp-name', name.encode()))
        scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'},
                 'http_version': '1.1', 'method': 'POST', 'scheme': 'http',
                 'path': '/mcp', 'raw_path': b'/mcp', 'query_string': b'',
                 'headers': headers, 'client': ('127.0.0.1', 1234),
                 'server': ('127.0.0.1', 80)}
        delivered = False
        disconnected = asyncio.Event()
        messages = []

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            await disconnected.wait()
            return {'type': 'http.disconnect'}

        async def send(message):
            messages.append(dict(message))

        async def exchange():
            await self.app(scope, receive, gate.send if gate is not None else send)
            return gate.messages if gate is not None else messages

        # Each actual HTTP exchange has its own Task, just as the ASGI server
        # does. The unittest Task remains free to observe real completion.
        task = self.track(asyncio.create_task(exchange()))
        return await task

    @staticmethod
    def response(messages):
        return json.loads(b''.join(m.get('body', b'') for m in messages
                                  if m['type'] == 'http.response.body'))

    async def call(self, name, arguments=None):
        messages = await self.rpc_raw('tools/call', {'name': name, 'arguments': arguments or {}})
        result = self.response(messages)['result']
        self.assertFalse(result.get('isError'), str(result)[:300])
        return result

    async def exported(self, key):
        result = await self.call('list_projects')
        capability = json.loads(result['content'][0]['text'])['original_export']
        arguments = {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip',
                     'service_instance_id': capability['service_instance_id'],
                     'request_window_id': capability['request_window_id'], 'request_key': key}
        deadline = time.monotonic() + 3
        while True:
            messages = await self.rpc_raw('tools/call', {'name': 'export_file', 'arguments': arguments})
            result = self.response(messages)['result']
            if not result.get('isError'):
                break
            text = str(result)
            if ('[busy]' not in text and '[resource_budget_exhausted]' not in text) or time.monotonic() >= deadline:
                self.fail(text[:300])
            # Ready eviction closes asynchronously. A rejected request has not
            # been accepted; repeat the same key after bounded resource recovery.
            await asyncio.sleep(.02)
        metadata = json.loads(result['content'][0]['text'])
        self.assertEqual(metadata['state'], 'ready')
        self.assertEqual([entry['type'] for entry in result['content']], ['text'])
        delivery = await self.call('materialize_file_export', {'export_id': metadata['export_id']})
        return json.loads(delivery['content'][0]['text']), delivery['content'][1]['uri']

    async def wait_for(self, predicate, message, seconds=3):
        deadline = time.monotonic() + seconds
        while not predicate() and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        self.assertTrue(predicate(), message)

    async def released(self):
        await self.wait_for(lambda: self.service.diagnostics()['active_responses'] == 0,
                            'Real SDK/ASGI completion did not release the resource lease')
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)

    async def begin_blocked_read(self, uri, *, fail=False, delay_cancel=False):
        gate = BodyGate(fail=fail, delay_cancel=delay_cancel)
        self.gates.append(gate)
        task = self.track(asyncio.create_task(self.rpc_raw('resources/read', {'uri': uri}, gate=gate)))
        await asyncio.wait_for(gate.entered.wait(), timeout=3)
        return task, gate

    def assert_pinned(self, export_id, task):
        diagnostics = self.service.diagnostics()
        self.assertEqual(diagnostics['active_responses'], 1)
        self.assertEqual(diagnostics['encoding_bytes_reserved'], SERIALIZATION_BYTES)
        self.assertFalse(task.done())
        with self.service.lock:
            snapshot = self.service._records[export_id].snapshot
            record = self.service._records[export_id]
            self.assertEqual(snapshot.pins, 1 + sum(d.pinned for d in self.service._deliveries.values()
                                                  if d.record is record))
            self.assertGreaterEqual(snapshot.fd, 0)

    def assert_original(self, messages):
        self.assertEqual(messages[0]['status'], 200)
        contents = self.response(messages)['result']['contents']
        received = base64.b64decode(contents[0]['blob'])
        self.assertEqual(received, self.body)
        self.assertEqual(hashlib.sha256(received).hexdigest(), hashlib.sha256(self.body).hexdigest())
        self.assertFalse(messages[-1].get('more_body', False))

    async def test_slow_send_retains_encoding_and_pin_until_real_asgi_task_finishes(self):
        metadata, uri = await self.exported('slow-success')
        task, gate = await self.begin_blocked_read(uri)
        await asyncio.sleep(.08)
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        self.assert_original(await asyncio.wait_for(task, timeout=3))
        await self.released()
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 1)

    async def test_actual_send_failure_releases_and_same_snapshot_can_be_read_again(self):
        metadata, uri = await self.exported('send-failure')
        task, gate = await self.begin_blocked_read(uri, fail=True)
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        messages = await asyncio.wait_for(task, timeout=3)
        self.assertFalse(any(m['type'] == 'http.response.body' and m.get('body') for m in messages))
        await self.released()
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()

    async def test_cancellation_keeps_pin_until_actual_send_cancellation_exits(self):
        metadata, uri = await self.exported('cancelled-send')
        task, gate = await self.begin_blocked_read(uri, delay_cancel=True)
        task.cancel()
        await asyncio.wait_for(gate.cancel_requested.wait(), timeout=2)
        await asyncio.sleep(.05)
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        try:
            await asyncio.wait_for(task, timeout=3)
        except asyncio.CancelledError:
            pass
        chunks = [m for m in gate.messages if m['type'] == 'http.response.body' and m.get('body')]
        self.assertLessEqual(len(chunks), 1, 'Cancelled ASGI task continued sending later original chunks')
        self.assertFalse(any(not m.get('more_body', False) for m in chunks),
                         'Cancelled exchange sent a complete original response')
        await self.released()
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()

    async def test_idle_timeout_retains_budget_until_real_send_returns_then_recovers(self):
        metadata, uri = await self.exported('idle-timeout')
        self.service.limits = replace(self.service.limits, idle_seconds=.15)
        task, gate = await self.begin_blocked_read(uri, delay_cancel=True)
        await asyncio.wait_for(gate.cancel_requested.wait(), timeout=2)
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        messages = await asyncio.wait_for(task, timeout=3)
        chunks = [m for m in messages if m['type'] == 'http.response.body' and m.get('body')]
        self.assertLessEqual(len(chunks), 1)
        self.assertFalse(any(not m.get('more_body', False) for m in chunks))
        await self.released()
        self.service.limits = replace(self.service.limits, idle_seconds=2)
        self.assert_original(await self.rpc_raw('resources/read', {'uri': uri}))
        await self.released()

    async def test_observed_source_revocation_stops_after_inflight_chunk_and_requires_new_export(self):
        metadata, uri = await self.exported('revoked-send')
        task, gate = await self.begin_blocked_read(uri)
        self.original.unlink()
        await self.wait_for(lambda: self.service._records[metadata['export_id']].state == 'revoked',
                            'Resource owner did not observe source revocation')
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        messages = await asyncio.wait_for(task, timeout=3)
        chunks = [m for m in messages if m['type'] == 'http.response.body' and m.get('body')]
        self.assertLessEqual(len(chunks), 1, 'Stale chunks continued after observed revocation')
        self.assertFalse(any(not m.get('more_body', False) for m in chunks))
        await self.released()
        self.original.write_bytes(self.body)
        denied = self.response(await self.rpc_raw('resources/read', {'uri': uri}))
        self.assertIn('error', denied, 'Restored source revived a retired export')
        _, fresh_uri = await self.exported('fresh-after-revocation')
        self.assert_original(await self.rpc_raw('resources/read', {'uri': fresh_uri}))
        await self.released()

    async def test_close_is_pending_until_blocked_real_send_exits_then_stops(self):
        metadata, uri = await self.exported('close-during-send')
        task, gate = await self.begin_blocked_read(uri)
        stopped = await asyncio.to_thread(self.service.close, .05)
        self.assertEqual(stopped['state'], 'shutdown_pending')
        self.assert_pinned(metadata['export_id'], task)
        gate.release.set()
        await asyncio.wait_for(task, timeout=3)
        await self.released()
        await self.wait_for(lambda: self.service.diagnostics()['snapshot_fds'] == 0,
                            'Retired pinned snapshot was not closed after actual completion')
        stopped = await asyncio.to_thread(self.service.close, 2)
        self.assertEqual(stopped['state'], 'stopped')

    async def test_repeated_real_resource_reads_do_not_grow_uri_cache_or_retained_body_memory(self):
        _, uri = await self.exported('memory-warmup')
        messages = await self.rpc_raw('resources/read', {'uri': uri})
        self.assert_original(messages)
        del messages
        await self.released()
        before_resources = len(await self.server.list_resources())
        tracemalloc.start(1)
        try:
            gc.collect()
            baseline, _ = tracemalloc.get_traced_memory()
            for index in range(8):
                _, uri = await self.exported('memory-' + str(index))
                messages = await self.rpc_raw('resources/read', {'uri': uri})
                self.assert_original(messages)
                del messages
                await self.released()
            await asyncio.sleep(.05)
            gc.collect()
            current, peak = tracemalloc.get_traced_memory()
            self.assertLess(current - baseline, len(self.body) * 2,
                            'Repeated SDK requests retained whole original/encoded bodies')
            self.assertLess(peak - baseline, SERIALIZATION_BYTES)
            self.assertEqual(len(await self.server.list_resources()), before_resources)
            self.assertEqual(self.service.diagnostics()['active_responses'], 0)
        finally:
            tracemalloc.stop()


if __name__ == '__main__':
    unittest.main()
