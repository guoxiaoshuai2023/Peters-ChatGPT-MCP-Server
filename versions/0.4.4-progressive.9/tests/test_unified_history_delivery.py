"""Unified policy behavior through the authenticated MCP worker and delivery."""

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.testclient import TestClient

from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import actor_digest
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.history_process import IsolatedHistory
from tests.test_history import encode, message, record


THREAD = 'ab123456-1234-1234-1234-123456789abc'
OWNER = 'synthetic-owner'
VISITOR = 'synthetic-visitor'
FIRST_TEXT = 'public synthetic prompt'
SECOND_TEXT = 'public synthetic answer'


class UnifiedDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(self.tmp).resolve()
        project = root / 'project'
        project.mkdir()
        home = root / 'codex'
        (home / 'sessions').mkdir(parents=True)
        rollout = home / 'sessions' / f'rollout-synthetic-{THREAD}.jsonl'
        rollout.write_bytes(encode([
            record('session_meta', {'id': THREAD, 'cwd': str(project)}),
            message(FIRST_TEXT), message(SECOND_TEXT, 'assistant', 'final', native_id='synthetic-answer'),
        ]))
        with sqlite3.connect(home / 'state_5.sqlite') as db:
            db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, '
                       'title TEXT, updated_at INTEGER, archived INTEGER)')
            db.execute('INSERT INTO threads VALUES (?,?,?,?,?,?)',
                       (THREAD, str(rollout), str(project), 'Synthetic thread', 100, 0))
        settings = AccessSettings('https://test-team.cloudflareaccess.com', 'a' * 64, 'mcp.example.com',
                                  (f'{OWNER}@example.com', f'{VISITOR}@example.com'))
        self.document = {
            'version': 2,
            'projects': [{'id': 'synthetic', 'name': 'Synthetic', 'root': str(project),
                          'directory_identity': persistent_identity(project)}],
            'principals': [actor_digest(settings.team_domain, OWNER)],
            'sources': {'codex': {
                'adapter': 'codex', 'root': str(home), 'format': 'state_5', 'enabled': True,
                'instance_id': 'synthetic-codex', 'root_identity': persistent_identity(home),
            }},
            'legacy_history': {'codex_home': str(home), 'state_db': 'state_5.sqlite',
                               'tool_evidence': []},
        }
        self.store = initialize_store(root / 'policy-generations')
        self.epoch = self.store.activate(self.document, initial=True)
        descriptor = root / 'history-v2.json'
        descriptor.write_text(json.dumps({'version': 2, 'generation_directory': str(self.store.path)}))
        descriptor.chmod(0o600)
        self.policy = AgentPolicy(descriptor, mode='v2')
        app = build_app(Catalog.from_policy(self.policy), settings, agent_policy=self.policy)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        self.headers = {}
        for subject in (OWNER, VISITOR):
            token = jwt.encode({'iss': settings.team_domain, 'aud': [settings.audience], 'iat': now-1,
                                'exp': now+300, 'email': f'{subject}@example.com', 'sub': subject},
                               key, algorithm='RS256', headers={'kid': 'synthetic'})
            self.headers[subject] = {
                'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-03-26',
                'cf-access-jwt-assertion': token,
            }
        self.client = self.enterContext(TestClient(app, base_url='https://mcp.example.com'))
        self.serial = 0

    def call(self, name, arguments, *, subject=OWNER):
        self.serial += 1
        response = self.client.post('/mcp', headers=self.headers[subject], json={
            'jsonrpc': '2.0', 'id': self.serial, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments},
        })
        self.assertEqual(response.status_code, 200)
        result = response.json()['result']
        return result.get('isError', False), result['content'][0]['text']

    def complete(self, name, arguments, *, subject=OWNER):
        for _ in range(30):
            error, text = self.call(name, arguments, subject=subject)
            if error:
                return error, text
            page = json.loads(text)
            if page.get('status') not in ('processing', 'waiting_source_stable'):
                return error, page
            arguments = {**arguments, 'cursor': page['next_cursor']}
        self.fail('Worker did not finish the bounded test request')

    def test_legacy_and_new_tools_share_caller_source_and_page_revocation(self):
        for name, args in (
            ('find_codex_threads', {}),
            ('read_codex_thread', {'thread_id': THREAD}),
            ('read_codex_thread_item', {'thread_id': THREAD, 'item_id': 'unknown'}),
            ('find_agent_threads', {'project_id': 'synthetic', 'source_id': 'codex'}),
        ):
            with self.subTest(name=name):
                denied, summary = self.complete(name, args, subject=VISITOR)
                self.assertTrue(denied, summary)
                self.assertIn('unauthorized', summary)
        error, old = self.complete('find_codex_threads', {})
        self.assertFalse(error, old)
        self.assertEqual([hit['thread_id'] for hit in old['threads']], [THREAD])
        error, new = self.complete('find_agent_threads', {'project_id': 'synthetic', 'source_id': 'codex'})
        self.assertFalse(error, new)
        ref = new['threads'][0]['thread_ref']
        error, page = self.complete('read_codex_thread', {'thread_id': THREAD, 'limit': 1})
        self.assertFalse(error, page)
        self.assertEqual(page['entries'][0]['text'], FIRST_TEXT)
        self.assertTrue(page['next_cursor'])
        disabled = deepcopy(self.document)
        disabled['sources']['codex']['enabled'] = False
        self.epoch = self.store.activate(disabled, expected_digest=self.epoch)
        for name, args in (
            ('find_codex_threads', {}),
            ('read_codex_thread', {'thread_id': THREAD, 'limit': 1, 'cursor': page['next_cursor']}),
            ('read_codex_thread_item', {'thread_id': THREAD, 'item_id': 'unknown'}),
            ('read_agent_thread', {'thread_ref': ref}),
        ):
            with self.subTest(name=name):
                denied, detail = self.complete(name, args)
                self.assertTrue(denied, detail)
                self.assertNotIn(FIRST_TEXT, detail)

    def test_prepared_legacy_page_does_not_cross_revocation_boundary(self):
        unmodified_call = IsolatedHistory._call
        revoked = False
        fixture = self

        def revoke_between_worker_and_delivery(worker, operation, arguments):
            nonlocal revoked
            result = unmodified_call(worker, operation, arguments)
            if not revoked and operation == 'read_codex_thread' and result.get('status') == 'ready':
                revoked = True
                after = deepcopy(fixture.document)
                after['projects'] = []
                fixture.store.activate(after, expected_digest=fixture.epoch)
            return result

        with patch.object(IsolatedHistory, '_call', revoke_between_worker_and_delivery):
            denied, detail = self.complete('read_codex_thread', {'thread_id': THREAD})
        self.assertTrue(revoked)
        self.assertTrue(denied, detail)
        self.assertIn('restart_required', detail)
        self.assertNotIn(FIRST_TEXT, detail)
