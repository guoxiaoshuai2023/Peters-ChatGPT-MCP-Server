"""Authenticated HTTP lifecycle smoke test for the history-only release."""

import json
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from mcp.client import Client  # Load the installed SDK runtime before Starlette.
from starlette.testclient import TestClient

from peters_mcp.catalog import Catalog, Project
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.history_process import IsolatedHistory
from tests import test_history as historical


class HistoryReleaseTests(unittest.TestCase):
    def test_authenticated_http_continuation_views_and_worker_shutdown(self):
        fixture = historical.HistoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.path.write_bytes(historical.encode([
            historical.record('session_meta', {'id': historical.FIRST}),
            historical.record('event_msg', {'type': 'task_started', 'turn_id': 'initial'}),
            historical.message('first public message', native_id='first'),
            historical.message('second public message', native_id='second'),
            historical.record('event_msg', {'type': 'task_complete', 'turn_id': 'initial'}),
            historical.record('event_msg', {'type': 'task_started', 'turn_id': 'latest'}),
            historical.message('latest public message', native_id='third'),
        ]))
        instances = []

        class BriefWaitHistory(IsolatedHistory):
            def __init__(self, history):
                super().__init__(history, wait_seconds=0.02)
                instances.append(self)

        settings = AccessSettings('https://test-team.cloudflareaccess.com', 'a' * 64,
                                  'mcp.example.com', ('owner@example.com',))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        claims = {'iss': settings.team_domain, 'aud': [settings.audience],
                  'exp': now + 300, 'iat': now - 10, 'sub': 'synthetic-subject',
                  'email': 'owner@example.com'}

        def token(email):
            return jwt.encode({**claims, 'email': email}, key, algorithm='RS256',
                              headers={'kid': 'synthetic-key'})

        catalog = Catalog([Project('project', 'Synthetic', fixture.home)])
        with patch('peters_mcp.history_process.IsolatedHistory', BriefWaitHistory):
            app = build_app(catalog, settings, history=fixture.history)
            app.verifier.keys = Mock()
            app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
            self.addCleanup(instances[0].close)
            with TestClient(app, base_url='https://mcp.example.com') as client:
                headers = {'Accept': 'application/json, text/event-stream',
                           'MCP-Protocol-Version': '2025-03-26'}
                payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
                self.assertEqual(client.post('/mcp', json=payload, headers=headers).status_code, 401)
                wrong = {**headers, 'cf-access-jwt-assertion': token('stranger@example.com')}
                self.assertEqual(client.post('/mcp', json=payload, headers=wrong).status_code, 401)
                self.assertIsNone(instances[0]._process)
                headers['cf-access-jwt-assertion'] = token('owner@example.com')
                counter = 0

                def rpc(method, params):
                    nonlocal counter
                    counter += 1
                    response = client.post('/mcp', headers=headers, json={
                        'jsonrpc': '2.0', 'id': counter, 'method': method, 'params': params})
                    self.assertEqual(response.status_code, 200, response.text)
                    body = response.json()
                    self.assertNotIn('error', body)
                    return body['result']

                rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                   'clientInfo': {'name': 'synthetic-release-test', 'version': '1'}})
                listing = rpc('tools/list', {})['tools']
                self.assertEqual({tool['name'] for tool in listing}, {
                    'list_projects', 'list_worktrees', 'list_files', 'search', 'read_file',
                    'prepare_candidate', 'save_candidate', 'find_codex_threads',
                    'read_codex_thread', 'read_codex_thread_item'})
                for tool in listing:
                    self.assertEqual(tool['annotations']['readOnlyHint'], tool['name'] != 'save_candidate')
                read_schema = next(tool['inputSchema'] for tool in listing
                                   if tool['name'] == 'read_codex_thread')
                self.assertIn('view', read_schema['properties'])
                self.assertIn('turn_id', read_schema['properties'])

                def complete(operation, arguments):
                    pending = 0
                    for _ in range(200):
                        result = rpc('tools/call', {'name': operation, 'arguments': arguments})
                        self.assertFalse(result.get('isError'), result)
                        page = json.loads(result['content'][0]['text'])
                        if page.get('status', 'ready') == 'ready':
                            return page, pending
                        self.assertEqual(page['status'], 'processing', page)
                        self.assertNotIn('entries', page)
                        self.assertNotIn('has_more', page)
                        arguments = {**arguments, 'cursor': page['next_cursor']}
                        pending += 1
                        time.sleep(0.01)
                    self.fail('History did not finish bounded continuation')

                first, pending = complete('read_codex_thread', {'thread_id': historical.FIRST, 'limit': 1})
                self.assertGreater(pending, 0)
                self.assertEqual(first['entries'][0]['text'], 'first public message')
                second, _ = complete('read_codex_thread', {'thread_id': historical.FIRST, 'limit': 1,
                                                         'cursor': first['next_cursor']})
                self.assertEqual(second['entries'][0]['text'], 'second public message')
                self.assertEqual(second['snapshot'], first['snapshot'])
                latest, _ = complete('read_codex_thread', {'thread_id': historical.FIRST, 'view': 'latest_turn'})
                self.assertEqual(latest['selected_turn_id'], 'latest')
                self.assertEqual([entry['text'] for entry in latest['entries']], ['latest public message'])
                selected, _ = complete('read_codex_thread', {'thread_id': historical.FIRST,
                                                          'view': 'turn', 'turn_id': 'initial'})
                self.assertEqual([entry['text'] for entry in selected['entries']],
                                 ['first public message', 'second public message'])
                projects, _ = complete('list_projects', {})
                self.assertEqual(projects['projects'][0]['id'], 'project')
                worker = instances[0]._process
                self.assertIsNotNone(worker)
                self.assertTrue(worker.is_alive())
                worker_pid = worker.pid
                self.assertTrue(app.verifier.keys.get_signing_key_from_jwt.called)
            self.assertTrue(instances[0]._closed)
            self.assertTrue(worker._closed)
            with self.assertRaises(ProcessLookupError):
                os.kill(worker_pid, 0)
            self.assertIsNone(instances[0]._socket)
            self.assertFalse(instances[0]._monitor.is_alive())
