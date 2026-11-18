"""Real SDK/ASGI original-resource round trips with synthetic verified principals."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest

import jwt
from mcp.server.transport_security import TransportSecuritySettings
from starlette.testclient import TestClient

from peters_mcp.catalog import Catalog, Project
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_export import FileExportService, ExportConfig
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.server import create_server


class SyntheticVerifier:
    def verify(self, token):
        if token not in ('synthetic-a', 'synthetic-b'):
            raise jwt.InvalidTokenError('synthetic rejection')
        return {'iss': 'https://synthetic.example.invalid', 'sub': token,
                'exp': time.time() + 3600}


class ExportProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.body = b'synthetic original\x00' * 4000
        (self.repo / 'original.zip').write_bytes(self.body)
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        registry.initialize()
        registry.register_pending(self.spool, read_roots=[self.repo])
        registry.activate(self.spool, read_roots=[self.repo])
        self.catalog = Catalog([Project('repo', 'Synthetic', self.repo)], private_registry=registry)
        self.service = FileExportService(self.catalog, ExportConfig(True, self.spool, min_free_bytes=0))
        self.server = create_server(self.catalog, exports=self.service)
        inner = self.server.streamable_http_app(stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        self.app = AccessMiddleware(self.service.protocol.wrap(inner), SyntheticVerifier())
        self.http = TestClient(self.app)
        self.http.__enter__()
        self.addCleanup(self.http.__exit__, None, None, None)

    def rpc(self, method, params, actor='synthetic-a', protocol='2026-07-28'):
        headers = {'cf-access-jwt-assertion': actor, 'MCP-Protocol-Version': protocol,
                   'Accept': 'application/json, text/event-stream'}
        if protocol == '2026-07-28':
            headers['mcp-method'] = method
            if method in ('tools/call', 'resources/read'):
                headers['mcp-name'] = params['name' if method == 'tools/call' else 'uri']
            params = {**params, '_meta': {'io.modelcontextprotocol/protocolVersion': protocol,
                'io.modelcontextprotocol/clientCapabilities': {}}}
        return self.http.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})

    def call(self, name, arguments=None, **options):
        response = self.rpc('tools/call', {'name': name, 'arguments': arguments or {}}, **options)
        self.assertEqual(response.status_code, 200, response.text[:300])
        return response.json()['result']

    def exported(self, key='protocol-first'):
        projects = self.call('list_projects')
        listing = json.loads(next(x['text'] for x in projects['content'] if x['type'] == 'text'))
        capability = listing['original_export']
        self.arguments = {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip',
            'service_instance_id': capability['service_instance_id'],
            'request_window_id': capability['request_window_id'], 'request_key': key}
        result = self.call('export_file', self.arguments)
        metadata = json.loads(result['content'][0]['text'])
        self.assertEqual(metadata['state'], 'ready')
        return metadata, result['content'][1]

    def wait_released(self):
        deadline = time.monotonic() + 2
        while self.service.diagnostics()['active_responses'] and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(self.service.diagnostics()['active_responses'], 0)

    def test_original_bytes_through_real_sdk_and_cached_snapshot_survives_send(self):
        metadata, link = self.exported()
        self.assertEqual(link['type'], 'resource_link')
        response = self.rpc('resources/read', {'uri': link['uri']})
        self.assertEqual(response.status_code, 200, response.text[:300])
        resource = response.json()['result']['contents'][0]
        self.assertEqual(base64.b64decode(resource['blob']), self.body)
        self.assertEqual(resource['mimeType'], 'application/octet-stream')
        self.assertIn('no-store', response.headers['cache-control'])
        self.wait_released()
        self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 1)
        self.assertEqual(self.service.diagnostics()['encoding_bytes_reserved'], 0)
        status = self.call('get_file_export_status', {'export_id': metadata['export_id']})
        actual = json.loads(status['content'][0]['text'])
        self.assertEqual(actual['sha256'], hashlib.sha256(self.body).hexdigest())
        self.assertTrue(actual['server_stream_finished'])
        self.assertEqual(actual['client_received'], 'not_observed')

    def test_same_actor_replay_and_other_owner_cannot_read_or_query(self):
        metadata, link = self.exported()
        replay = self.call('export_file', self.arguments)
        self.assertEqual(json.loads(replay['content'][0]['text'])['export_id'], metadata['export_id'])
        wrong = self.rpc('resources/read', {'uri': link['uri']}, actor='synthetic-b')
        self.assertIn('error', wrong.json())
        self.assertNotIn(metadata['sha256'], wrong.text)
        self.assertNotIn('original.zip', wrong.text)
        denied_status = self.call('get_file_export_status', {'export_id': metadata['export_id']},
                                 actor='synthetic-b')
        self.assertTrue(denied_status.get('isError'))
        self.assertNotIn(metadata['sha256'], str(denied_status))
        self.assertEqual(self.rpc('resources/read', {'uri': link['uri']}, actor='invalid').status_code, 401)

    def test_legacy_protocol_keeps_legacy_tools_but_does_not_issue_export_window(self):
        old = self.call('list_projects', protocol='2025-03-26')
        result = json.loads(old['content'][0]['text'])
        self.assertEqual(result['projects'][0]['id'], 'repo')
        self.assertNotIn('original_export', result)
        self.assertFalse(result['read_capabilities']['original_export_supported'])
        denied = self.call('find_files', {'project_id': 'repo', 'worktree_id': 'main'},
                           protocol='2025-03-26')
        self.assertTrue(denied.get('isError'))
        self.assertEqual(self.service.diagnostics()['records'], 0)


if __name__ == '__main__':
    unittest.main()
