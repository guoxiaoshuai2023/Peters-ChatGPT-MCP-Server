"""Real Uvicorn TCP disconnects, normal completion and same-snapshot recovery."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest

from mcp.server.transport_security import TransportSecuritySettings
import uvicorn

from peters_mcp.catalog import Catalog, Project
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_export import ExportConfig, FileExportService
from peters_mcp.file_export_tools import _EXCHANGE
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.server import create_server
from tests.test_export_protocol import SyntheticVerifier


class RealDisconnectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-disconnect-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        repo = root / 'repo'
        repo.mkdir()
        self.size = 32 * 1024 * 1024
        self.expected = hashlib.sha256()
        block = os.urandom(65536)
        with (repo / 'original.bin').open('xb') as output:
            for _ in range(self.size // len(block)):
                output.write(block)
                self.expected.update(block)
        self.expected = self.expected.hexdigest()
        control, spool = root / 'control', root / 'spool'
        control.mkdir(mode=0o700)
        registry = PrivateRootRegistry(control, allowed_roots=[spool])
        registry.initialize()
        registry.register_pending(spool, read_roots=[repo])
        registry.activate(spool, read_roots=[repo])
        catalog = Catalog([Project('repo', 'Synthetic', repo)], private_registry=registry)
        self.service = FileExportService(catalog, ExportConfig(True, spool, min_free_bytes=0))
        self.resource_exchanges = []
        self.metadata_exchanges = []
        self.disconnect_events = []
        self.throw_diagnostic = False

        async def observe_exchange(context, call_next):
            exchange = context.request.scope.get(_EXCHANGE)
            if context.method == 'resources/read':
                self.resource_exchanges.append((exchange, asyncio.current_task()))
            elif context.method == 'tools/call':
                self.metadata_exchanges.append(exchange)
            return await call_next(context)

        server = create_server(catalog, exports=self.service,
                               server_options={'middleware': [observe_exchange]})
        inner = server.streamable_http_app(stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        protected = AccessMiddleware(self.service.protocol.wrap(inner), SyntheticVerifier())

        def diagnostic(event):
            self.disconnect_events.append(event)
            if self.throw_diagnostic:
                raise RuntimeError('synthetic diagnostic sink failure')

        async def app(scope, receive, send):
            if scope['type'] == 'http':
                scope = {**scope, 'peters_original_transport_diagnostic': diagnostic}
            return await protected(scope, receive, send)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(128)
        self.socket.setblocking(False)
        self.addCleanup(self.socket.close)
        self.port = self.socket.getsockname()[1]
        self.http_server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False,
            lifespan='on', timeout_graceful_shutdown=3, timeout_keep_alive=1))
        self.server_task = asyncio.create_task(self.http_server.serve(sockets=[self.socket]))
        self.addAsyncCleanup(self.stop_server)
        await self.until(lambda: self.http_server.started)

    async def stop_server(self):
        self.http_server.should_exit = True
        await asyncio.wait_for(self.server_task, 5)
        self.assertEqual(self.service.close()['state'], 'stopped')

    async def until(self, predicate, seconds=5):
        deadline = time.monotonic() + seconds
        while not predicate() and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        self.assertTrue(predicate(), 'Actual synthetic TCP/owner lifecycle did not settle')

    async def request(self, method, params):
        params = {**params, '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                                    'io.modelcontextprotocol/clientCapabilities': {}}}
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        headers = ['POST /mcp HTTP/1.1', f'Host: 127.0.0.1:{self.port}',
                   'Accept: application/json, text/event-stream', 'Content-Type: application/json',
                   'MCP-Protocol-Version: 2026-07-28', f'mcp-method: {method}',
                   'cf-access-jwt-assertion: synthetic-a', 'Connection: close',
                   f'Content-Length: {len(body)}']
        if method in ('tools/call', 'resources/read'):
            headers.append('mcp-name: ' + params['name' if method == 'tools/call' else 'uri'])
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(('\r\n'.join(headers) + '\r\n\r\n').encode() + body)
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        lines = head.split(b'\r\n')
        self.assertEqual(int(lines[0].split()[1]), 200, head[:200])
        values = dict(line.split(b':', 1) for line in lines[1:] if b':' in line)
        length = int(next(value for name, value in values.items() if name.lower() == b'content-length'))
        return reader, writer, length

    async def call(self, name, arguments=None):
        reader, writer, length = await self.request('tools/call',
            {'name': name, 'arguments': arguments or {}})
        try:
            response = json.loads(await asyncio.wait_for(reader.readexactly(length), 5))['result']
            self.assertFalse(response.get('isError'), str(response)[:200])
            return response
        finally:
            writer.close()
            await writer.wait_closed()

    async def exported(self):
        listing = await self.call('list_projects')
        capability = json.loads(listing['content'][0]['text'])['original_export']
        result = await self.call('export_file', {'project_id': 'repo', 'worktree_id': 'main',
            'path': 'original.bin', 'service_instance_id': capability['service_instance_id'],
            'request_window_id': capability['request_window_id'], 'request_key': 'tcp-disconnect',
            'expected_sha256': self.expected})
        metadata = json.loads(result['content'][0]['text'])
        while metadata['state'] in ('queued', 'preparing'):
            await asyncio.sleep(.01)
            result = await self.call('get_file_export_status', {'export_id': metadata['export_id']})
            metadata = json.loads(result['content'][0]['text'])
        self.assertEqual(metadata['state'], 'ready')
        result = await self.call('materialize_file_export', {'export_id': metadata['export_id']})
        return metadata, result['content'][1]['uri']

    async def complete_stream(self, uri):
        reader, writer, length = await self.request('resources/read', {'uri': uri})
        try:
            prefix = bytearray()
            while not prefix.endswith(b'"blob":"'):
                prefix.extend(await asyncio.wait_for(reader.readexactly(1), 5))
                self.assertLess(len(prefix), 16384)
            digest, raw_bytes = hashlib.sha256(), 0
            encoded_length = 4 * ((self.size + 2) // 3)
            remaining = encoded_length
            while remaining:
                chunk = await asyncio.wait_for(reader.readexactly(min(65536, remaining)), 5)
                remaining -= len(chunk)
                decoded = base64.b64decode(chunk, validate=True)
                digest.update(decoded)
                raw_bytes += len(decoded)
            suffix = await asyncio.wait_for(reader.readexactly(length - len(prefix) - encoded_length), 5)
            template = json.loads(bytes(prefix) + suffix)
            self.assertEqual(template['id'], 1)
            self.assertEqual(template['result']['contents'][0]['blob'], '')
            self.assertEqual(raw_bytes, self.size)
            self.assertEqual(digest.hexdigest(), self.expected)
        finally:
            writer.close()
            await writer.wait_closed()
        await self.until(lambda: self.service.diagnostics()['active_responses'] == 0)

    async def interrupted_then_recovers(self, *, diagnostic_failure=False):
        metadata, uri = await self.exported()
        self.throw_diagnostic = diagnostic_failure
        reader, writer, _ = await self.request('resources/read', {'uri': uri})
        await asyncio.wait_for(reader.readexactly(16384), 5)
        # A real peer TCP abort wakes Uvicorn.receive. No fabricated send
        # exception, task cancellation or private protocol flags are injected.
        writer.transport.abort()
        await asyncio.wait_for(writer.wait_closed(), 3)
        await self.until(lambda: self.service.diagnostics()['active_responses'] == 0)
        self.assertEqual(self.disconnect_events, ['disconnect_guard_observed'])
        exchange, task = self.resource_exchanges[0]
        self.assertTrue(task.done())
        self.assertTrue(exchange.disconnected)
        self.assertIsNone(exchange.disconnect_task)
        self.assertTrue(exchange.lease.owner_complete)
        self.assertTrue(exchange.lease.asgi_done)
        self.assertTrue(exchange.lease.sdk_done)
        self.assertTrue(exchange.lease.released)
        self.assertFalse(exchange.final_data_body)
        self.assertFalse(exchange.lease.final_body_forwarded)
        self.assertEqual(exchange.lease.error_code, 'transfer_interrupted')
        self.assertLess(exchange.lease.stream_bytes_read, self.size)
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
        with self.service.lock:
            record = self.service._records[metadata['export_id']]
            self.assertEqual(record.state, 'ready')
            self.assertFalse(record.server_stream_finished)
            self.assertEqual(record.snapshot.pins, 0)
        self.throw_diagnostic = False
        await self.complete_stream(uri)
        # Successful final response_complete may wake receive, but must not be
        # confused with an earlier peer abort or invalidate a completed stream.
        self.assertEqual(self.disconnect_events, ['disconnect_guard_observed'])
        recovered, task = self.resource_exchanges[1]
        self.assertTrue(task.done())
        self.assertFalse(recovered.disconnected)
        self.assertTrue(recovered.final_send_returned)
        self.assertTrue(recovered.final_data_body)
        self.assertIsNone(recovered.disconnect_task)
        with self.service.lock:
            self.assertTrue(self.service._records[metadata['export_id']].server_stream_finished)

    async def test_actual_tcp_abort_stops_owner_without_false_finish_then_full_recovery(self):
        await self.interrupted_then_recovers()

    async def test_diagnostic_failure_cannot_undo_actual_disconnect_protection(self):
        await self.interrupted_then_recovers(diagnostic_failure=True)

    async def test_normal_completion_and_metadata_have_no_disconnect_watcher(self):
        metadata, uri = await self.exported()
        for _ in range(3):
            result = await self.call('get_file_export_status', {'export_id': metadata['export_id']})
            self.assertEqual([item['type'] for item in result['content']], ['text'])
        self.assertTrue(self.metadata_exchanges)
        self.assertTrue(all(exchange.disconnect_task is None and exchange.lease is None
                            for exchange in self.metadata_exchanges))
        await self.complete_stream(uri)
        exchange, task = self.resource_exchanges[0]
        self.assertTrue(task.done())
        self.assertTrue(exchange.final_send_returned)
        self.assertTrue(exchange.final_data_body)
        self.assertIsNone(exchange.disconnect_task)
        self.assertFalse(exchange.disconnected)
        self.assertEqual(self.disconnect_events, [])
        with self.service.lock:
            self.assertTrue(self.service._records[metadata['export_id']].server_stream_finished)
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)


if __name__ == '__main__':
    unittest.main()
