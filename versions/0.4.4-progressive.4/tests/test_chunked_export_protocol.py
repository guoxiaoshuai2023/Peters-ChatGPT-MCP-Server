"""Actual standard SDK/ASGI round trips with synthetic verified principals."""
import base64
import hashlib
import json
import time
import unittest
from unittest.mock import patch

import test_export_protocol as baseline
from peters_mcp.chunked_export_config import ChunkedExportConfig
from peters_mcp.file_export import FileExportService
from peters_mcp.native_chunk_receiver import normalize_plan
from peters_mcp.transport_asset import load_receiver_asset


class ChunkedProtocolTests(unittest.TestCase):
    rpc = baseline.ExportProtocolTests.rpc
    call = baseline.ExportProtocolTests.call
    exported = baseline.ExportProtocolTests.exported
    wait_released = baseline.ExportProtocolTests.wait_released

    def setUp(self):
        def factory(*args, **kwargs):
            return FileExportService(*args, **kwargs,
                chunked_config=ChunkedExportConfig(True, min_free_bytes=0))
        with patch.object(baseline, 'FileExportService', side_effect=factory):
            baseline.ExportProtocolTests.setUp(self)
        self.rows = []
        class Log:
            def info(inner, raw): self.rows.append(json.loads(raw))
        self.service.protocol.audit = Log()

    def prepared(self, key='chunked-sdk'):
        projects = json.loads(self.call('list_projects')['content'][0]['text'])
        self.assertTrue(projects['chunked_export']['enabled'])
        self.assertEqual(projects['original_export']['max_original_bytes'], 12_659_780)
        c = projects['original_export']
        arguments = {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip',
                     'service_instance_id': c['service_instance_id'], 'request_window_id': c['request_window_id'],
                     'request_key': key}
        raw = self.call('prepare_chunked_export', arguments)
        self.assertEqual(len(raw['content']), 1)
        value = json.loads(raw['content'][0]['text'])
        self.assertEqual(value['state'], 'ready', value)
        plan = self.call('get_chunked_export_plan', {'export_id': value['export_id']})
        self.assertEqual(len(plan['content']), 1)
        return value, normalize_plan(json.loads(plan['content'][0]['text'])['plan'])

    def received(self, name, arguments):
        result = self.call(name, arguments)
        self.assertFalse(result.get('isError'), result)
        self.assertEqual(result['content'][1]['type'], 'resource_link')
        link = result['content'][1]
        self.assertTrue(link['uri'].startswith('peters-chunk://'))
        response = self.rpc('resources/read', {'uri': link['uri']})
        self.assertEqual(response.status_code, 200)
        data = response.json()['result']['contents'][0]
        self.assertEqual(data['uri'], link['uri'])
        self.assertEqual(data['mimeType'], 'application/octet-stream')
        self.assertIn('no-store', response.headers['cache-control'])
        self.wait_released()
        return base64.b64decode(data['blob']), link

    def test_helper_and_part_use_actual_standard_sdk_then_source_release(self):
        ready, plan = self.prepared()
        asset, _ = self.received('materialize_chunked_export_receiver', {'export_id': ready['export_id']})
        self.assertEqual(asset, load_receiver_asset())
        self.assertEqual(hashlib.sha256(asset).hexdigest(), plan['receiver_asset']['sha256'])
        body, _ = self.received('materialize_chunked_export_part', {'export_id': ready['export_id'], 'part_index': 0})
        self.assertEqual(body, self.body)
        self.assertEqual(hashlib.sha256(body).hexdigest(), plan['total_sha256'])
        self.call('cancel_chunked_export', {'export_id': ready['export_id']})
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status = json.loads(self.call('get_chunked_export_status', {'export_id': ready['export_id']})['content'][0]['text'])
            if status['resources_released']: break
            time.sleep(.01)
        self.assertTrue(status['resources_released'])
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
        finished = [r for r in self.rows if r['tool'] == 'chunked_resource_finished']
        self.assertEqual(len(finished), 2)
        self.assertTrue(all(r['server_stream_finished'] is True for r in finished))
        self.assertTrue(any(r['tool'] == 'chunked_snapshot_closed' and r['resources_released'] for r in self.rows))
        encoded = json.dumps(self.rows)
        for field in ('resource_uri', 'resource_name', 'request_key', 'path', 'source', 'token'):
            self.assertNotIn('"' + field + '"', encoded)

    def test_foreign_actor_and_cross_namespace_ids_expose_no_payload(self):
        ready, plan = self.prepared()
        result = self.call('materialize_chunked_export_part', {'export_id': ready['export_id'], 'part_index': 0})
        link = result['content'][1]
        denied = self.rpc('resources/read', {'uri': link['uri']}, actor='synthetic-b')
        self.assertIn('error', denied.json())
        self.assertNotIn(plan['total_sha256'], denied.text)
        self.assertTrue(self.call('get_chunked_export_status', {'export_id': ready['export_id']}, actor='synthetic-b').get('isError'))
        self.assertTrue(self.call('get_file_export_status', {'export_id': ready['export_id']}).get('isError'))
        legacy, _ = self.exported()
        self.assertTrue(self.call('get_chunked_export_status', {'export_id': legacy['export_id']}).get('isError'))

    def test_strict_part_schema_cannot_coerce_bool_float_or_string(self):
        ready, _ = self.prepared()
        for index in (True, 0.0, '0'):
            result = self.call('materialize_chunked_export_part', {'export_id': ready['export_id'], 'part_index': index})
            self.assertTrue(result.get('isError'), result)
        self.assertEqual(self.service.diagnostics()['active_responses'], 0)

    def test_existing_legacy_resource_shape_and_bytes_remain(self):
        metadata, link = self.exported()
        self.assertTrue(link['uri'].startswith('peters-export://'))
        result = self.rpc('resources/read', {'uri': link['uri']}).json()['result']['contents'][0]
        self.assertEqual(base64.b64decode(result['blob']), self.body)
        self.wait_released()
        status = json.loads(self.call('get_file_export_status', {'export_id': metadata['export_id']})['content'][0]['text'])
        self.assertEqual(status['resource_uri'], link['uri'])
        self.assertEqual(status['delivery_profile_id'], 'chatgpt-web-gpt56sol-high-mcp-resource-20261003-v1')
