"""Raw snapshot ranges through real SDK JSON, bounded assembly and actual TCP."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import time
import unittest
import zipfile
import zlib

from peters_mcp.catalog import AccessError
from peters_mcp.file_export import ExportLimits, FileExportService, PART_MAX_BYTES, STREAM_CHUNK
from tests import test_export_protocol as protocol
from tests import test_streamed_resource_disconnect as tcp
from tests.test_large_export_service import LargeExportFixture


def tiny_png():
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    width, height = 4, 3
    pixels = bytes((41, 173, 92)) * width
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress((b'\x00' + pixels) * height)) + chunk(b'IEND', b''))


def create_external_zip(path, size):
    """The independent producer finishes before any receiving SDK call."""
    image = tiny_png()
    probe = io.BytesIO()
    with zipfile.ZipFile(probe, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('visual.png', image)
        archive.writestr('payload.bin', b'')
    payload_bytes = size - len(probe.getvalue())
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('visual.png', image)
        with archive.open('payload.bin', 'w') as output:
            block = os.urandom(65536)
            while payload_bytes:
                count = min(len(block), payload_bytes)
                output.write(block[:count])
                payload_bytes -= count
    assert path.stat().st_size == size
    digest = hashlib.sha256()
    with path.open('rb') as original:
        for block in iter(lambda: original.read(65536), b''):
            digest.update(block)
    return digest.hexdigest(), image


class RangeManagerTests(LargeExportFixture):
    def range_service(self, part_max=64, limits=None):
        service = FileExportService(self.catalog, self.service.config, limits=limits or ExportLimits(close_seconds=.2),
            monotonic=self.clock.monotonic, wall_clock=self.clock.wall, part_max_bytes=part_max)
        service.start()
        self.services.append(service)
        return service

    async def read_part(self, service, export_id, part_index):
        part = await service.materialize_part(self.actor, export_id, part_index)
        lease = service.open_resource(self.actor, part['delivery_id'], asyncio.get_running_loop())
        await lease.bytes_ready()
        lease.finish_construction()
        await lease.wait_checked()
        received = bytearray()
        while len(received) < part['bytes']:
            received.extend(await lease.next_chunk(len(received)))
            lease.sent()
        await lease.finish_stream()
        # This manager fixture explicitly simulates transport termination.
        # Real SDK/TCP completion is covered by the classes below.
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released)
        return part, bytes(received)

    async def test_plan_is_metadata_only_no_capture_or_pin_and_parts_use_same_snapshot(self):
        data = os.urandom(257)
        path = self.write(data=data)
        service = self.range_service()
        ready = await self.ready(service=service)
        plan = await service.get_transport_plan(self.actor, ready['export_id'])
        self.assertEqual(plan['part_max_bytes'], 64)
        self.assertEqual([p['offset'] for p in plan['parts']], [0, 64, 128, 192, 256])
        self.assertEqual([p['bytes'] for p in plan['parts']], [64, 64, 64, 64, 1])
        self.assertNotIn('resource_uri', plan)
        self.assertEqual(service.diagnostics()['part_plan_pins'], 0)
        self.assertEqual(service.diagnostics()['materialization_references'], 0)
        before = service._records[ready['export_id']].snapshot.fd
        path.write_bytes(b'changed current source' * 30)
        result = bytearray()
        for index, metadata in enumerate(plan['parts']):
            part, raw = await self.read_part(service, ready['export_id'], index)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), metadata['sha256'])
            self.assertEqual(part['parent_sha256'], ready['sha256'])
            self.assertEqual(part['bytes'], len(raw))
            self.assertEqual(service._records[ready['export_id']].snapshot.fd, before)
            result.extend(raw)
        self.assertEqual(bytes(result), data)
        self.assertEqual(list(self.spool.iterdir()), [])
        status = await service.get_status(self.actor, ready['export_id'])
        self.assertFalse(status['server_stream_finished'])
        self.assertEqual(status['part_streams_finished'], list(range(5)))
        self.assertEqual(status['client_received'], 'not_observed')

    async def test_repeat_bounds_actor_and_metadata_reservations_are_finite(self):
        self.write(data=os.urandom(257))
        service = self.range_service(limits=ExportLimits(records=1, actor_records=1, close_seconds=.2))
        ready = await self.ready(service=service)
        for index in (-1, True, '0', 5, 10**100):
            with self.assertRaises(AccessError):
                await service.materialize_part(self.actor, ready['export_id'], index)
        first = await service.materialize_part(self.actor, ready['export_id'], 0)
        repeated = await service.materialize_part(self.actor, ready['export_id'], 0)
        self.assertEqual(first['delivery_id'], repeated['delivery_id'])
        self.assertEqual(first['materialization_expires_at'], repeated['materialization_expires_at'])
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await service.materialize_part(self.actor, ready['export_id'], 1)
        with self.assertRaisesRegex(AccessError, 'export_unavailable'):
            await service.get_transport_plan(self.actor_for('wrong-owner'), ready['export_id'])
        self.assertEqual(service.diagnostics()['materialization_references'], 1)
        self.assertEqual(service.diagnostics()['snapshot_reservations'], 1)
        too_many = self.range_service(part_max=1)
        self.write('huge-description.bin', os.urandom(5000))
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await self.accepted('huge-description.bin', service=too_many)
        self.assertEqual(too_many.diagnostics()['snapshot_fds'], 0)
        with self.assertRaises(AccessError):
            self.range_service(part_max=PART_MAX_BYTES + 1)

    async def test_parent_cancel_stops_all_parts_releases_hold_and_new_key_recovers(self):
        data = os.urandom(257)
        self.write(data=data)
        service = self.range_service()
        ready = await self.ready(service=service)
        first = await service.materialize_part(self.actor, ready['export_id'], 0)
        await service.materialize_part(self.actor, ready['export_id'], 1)
        lease = service.open_resource(self.actor, first['delivery_id'], asyncio.get_running_loop())
        await lease.bytes_ready()
        lease.finish_construction()
        await lease.wait_checked()
        self.assertEqual(await lease.next_chunk(0), data[:64])
        cancelled = await service.cancel(self.actor, ready['export_id'])
        self.assertEqual(cancelled['state'], 'cancelling')
        self.assertFalse(cancelled['resources_released'])
        self.assertEqual(service.diagnostics()['part_plan_pins'], 0)
        self.assertEqual(service.diagnostics()['materialization_references'], 0)
        self.assertGreater(service.diagnostics()['encoding_bytes_reserved'], 0)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released and service.diagnostics()['snapshot_fds'] == 0)
        final = await service.get_status(self.actor, ready['export_id'])
        self.assertEqual(final['state'], 'cancelled')
        self.assertTrue(final['resources_released'])
        with self.assertRaises(AccessError):
            service.open_resource(self.actor, first['delivery_id'], asyncio.get_running_loop())
        restored = await self.ready(key='new-after-part-cancel', service=service, expected=ready['sha256'])
        result = bytearray()
        plan = await service.get_transport_plan(self.actor, restored['export_id'])
        for index in range(plan['part_count']):
            _, raw = await self.read_part(service, restored['export_id'], index)
            result.extend(raw)
        self.assertEqual(hashlib.sha256(result).hexdigest(), ready['sha256'])

    async def test_scope_revocation_hides_plan_and_part_references_without_revival(self):
        self.write(data=os.urandom(257))
        ready = await self.ready()
        await self.service.materialize_part(self.actor, ready['export_id'], 0)
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=('original.bin',))
        with self.assertRaises(AccessError):
            await self.service.get_transport_plan(self.actor, ready['export_id'])
        await self.wait_until(lambda: self.service.diagnostics()['snapshot_fds'] == 0)
        self.assertEqual(self.service.diagnostics()['part_plan_pins'], 0)
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=())
        status = await self.service.get_transport_plan(self.actor, ready['export_id'])
        self.assertEqual(status['state'], 'revoked')
        self.assertNotIn('parts', status)
        self.assertNotIn('sha256', status)


class RealRangeSDKTests(unittest.TestCase):
    setUp = protocol.ExportProtocolTests.setUp
    rpc = protocol.ExportProtocolTests.rpc
    call = protocol.ExportProtocolTests.call
    wait_released = protocol.ExportProtocolTests.wait_released

    def prepare(self):
        listing = json.loads(self.call('list_projects')['content'][0]['text'])['original_export']
        result = self.call('export_file', {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip',
            'service_instance_id': listing['service_instance_id'], 'request_window_id': listing['request_window_id'],
            'request_key': 'actual-raw-range-source'})
        metadata = json.loads(result['content'][0]['text'])
        self.assertEqual(metadata['state'], 'ready')
        return metadata

    def test_three_actual_sdk_raw_parts_assemble_external_24m_zip_and_png(self):
        expected, image = create_external_zip(self.repo / 'original.zip', 24_000_000)
        metadata = self.prepare()
        plan_result = self.call('get_file_export_transport_plan', {'export_id': metadata['export_id']})
        self.assertEqual([item['type'] for item in plan_result['content']], ['text'])
        plan = json.loads(plan_result['content'][0]['text'])
        self.assertEqual(plan['part_count'], 3)
        self.assertFalse(plan['single_attachment_primitive_verified'])
        self.assertFalse(plan['native_assembled_original_verified'])
        target = self.root / 'independent-receiver.zip'
        self.assertFalse(target.exists())
        actual = hashlib.sha256()
        with target.open('xb') as receiver:
            for info in plan['parts']:
                delivered = self.call('materialize_file_export_part',
                    {'export_id': metadata['export_id'], 'part_index': info['part_index']})
                value = json.loads(delivered['content'][0]['text'])
                link = delivered['content'][1]
                self.assertEqual(link['size'], 8_000_000)
                self.assertTrue(link['name'].endswith('.samplebin'))
                self.assertEqual(link['mimeType'], 'application/octet-stream')
                self.assertEqual(value['parent_bytes'], 24_000_000)
                response = self.rpc('resources/read', {'uri': link['uri']})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(int(response.headers['content-length']), len(response.content))
                raw = base64.b64decode(response.json()['result']['contents'][0]['blob'], validate=True)
                self.assertEqual(len(raw), info['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), info['sha256'])
                self.assertEqual(receiver.tell(), info['offset'])
                receiver.write(raw)
                actual.update(raw)
                del raw, response
                self.wait_released()
            receiver.flush()
            os.fsync(receiver.fileno())
        self.assertEqual(target.stat().st_size, 24_000_000)
        self.assertEqual(actual.hexdigest(), expected)
        reread = hashlib.sha256()
        with target.open('rb') as receiver:
            for chunk in iter(lambda: receiver.read(65536), b''):
                reread.update(chunk)
        self.assertEqual(reread.hexdigest(), expected)
        with zipfile.ZipFile(target) as received:
            self.assertIsNone(received.testzip())
            self.assertEqual(received.read('visual.png'), image)
            png = received.read('visual.png')
            self.assertEqual(struct.unpack('!2I', png[16:24]), (4, 3))
            offset, compressed = 8, bytearray()
            while offset < len(png):
                size = struct.unpack('!I', png[offset:offset + 4])[0]
                kind, body = png[offset + 4:offset + 8], png[offset + 8:offset + 8 + size]
                self.assertEqual(zlib.crc32(kind + body), struct.unpack('!I', png[offset + 8 + size:offset + 12 + size])[0])
                if kind == b'IDAT':
                    compressed.extend(body)
                offset += size + 12
            self.assertEqual(zlib.decompress(compressed), (b'\x00' + bytes((41, 173, 92)) * 4) * 3)
        status = json.loads(self.call('get_file_export_status', {'export_id': metadata['export_id']})['content'][0]['text'])
        self.assertFalse(status['server_stream_finished'])
        self.assertEqual(status['part_streams_finished'], [0, 1, 2])
        self.assertEqual(status['client_received'], 'not_observed')
        self.call('cancel_file_export', {'export_id': metadata['export_id']})
        deadline = time.monotonic() + 3
        while self.service.diagnostics()['snapshot_fds'] and time.monotonic() < deadline:
            time.sleep(.01)
        final = json.loads(self.call('get_file_export_status', {'export_id': metadata['export_id']})['content'][0]['text'])
        self.assertEqual(final['state'], 'cancelled')
        self.assertTrue(final['resources_released'])
        self.assertEqual(self.service.diagnostics()['part_plan_pins'], 0)
        self.assertEqual(list(self.spool.iterdir()), [])
        with self.assertRaises(FileExistsError):
            target.open('xb')

    def test_actual_sdk_rejects_bool_and_string_part_indices(self):
        metadata = self.prepare()
        for index in (True, '0', -1, 1):
            response = self.rpc('tools/call', {'name': 'materialize_file_export_part',
                'arguments': {'export_id': metadata['export_id'], 'part_index': index}}).json()
            self.assertTrue(response.get('error') or response.get('result', {}).get('isError'), response)
        self.assertEqual(self.service.diagnostics()['materialization_references'], 0)


class ActualPartTCPTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = tcp.RealDisconnectTests.asyncSetUp
    stop_server = tcp.RealDisconnectTests.stop_server
    until = tcp.RealDisconnectTests.until
    request = tcp.RealDisconnectTests.request
    call = tcp.RealDisconnectTests.call
    exported = tcp.RealDisconnectTests.exported

    async def test_actual_part_tcp_abort_and_same_reference_full_recovery(self):
        metadata, _ = await self.exported()
        plan = json.loads((await self.call('get_file_export_transport_plan',
            {'export_id': metadata['export_id']}))['content'][0]['text'])
        result = await self.call('materialize_file_export_part', {'export_id': metadata['export_id'], 'part_index': 1})
        value = json.loads(result['content'][0]['text'])
        uri = result['content'][1]['uri']
        reader, writer, _ = await self.request('resources/read', {'uri': uri})
        await reader.readexactly(16384)
        writer.transport.abort()
        await writer.wait_closed()
        await self.until(lambda: self.service.diagnostics()['active_responses'] == 0)
        exchange, task = self.resource_exchanges[0]
        self.assertTrue(task.done())
        self.assertTrue(exchange.disconnected)
        self.assertFalse(exchange.final_data_body)
        self.assertLess(exchange.lease.stream_bytes_read, value['bytes'])
        self.assertEqual(self.service.diagnostics()['part_plan_pins'], 1)
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
        reader, writer, length = await self.request('resources/read', {'uri': uri})
        try:
            received = json.loads(await asyncio.wait_for(reader.readexactly(length), 5))
        finally:
            writer.close()
            await writer.wait_closed()
        raw = base64.b64decode(received['result']['contents'][0]['blob'], validate=True)
        self.assertEqual(len(raw), 8_000_000)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), plan['parts'][1]['sha256'])
        await self.until(lambda: self.service.diagnostics()['active_responses'] == 0)
        status = json.loads((await self.call('get_file_export_status', {'export_id': metadata['export_id']}))['content'][0]['text'])
        self.assertFalse(status['server_stream_finished'])
        self.assertEqual(status['part_streams_finished'], [1])
        await self.call('cancel_file_export', {'export_id': metadata['export_id']})
        await self.until(lambda: self.service.diagnostics()['snapshot_fds'] == 0)
        final = json.loads((await self.call('get_file_export_status', {'export_id': metadata['export_id']}))['content'][0]['text'])
        self.assertEqual(final['state'], 'cancelled')
        self.assertTrue(final['resources_released'])


if __name__ == '__main__':
    unittest.main()
