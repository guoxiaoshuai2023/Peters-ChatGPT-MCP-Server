"""Unified policy behavior through the authenticated MCP worker and delivery."""

from copy import deepcopy
from datetime import datetime, timezone
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
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.history_process import IsolatedHistory
from tests.test_history import encode, message, record
from tests.test_workspaces import fixture_git, fixture_registered_worktree


THREAD = 'ab123456-1234-1234-1234-123456789abc'
OWNER = 'synthetic-owner'
VISITOR = 'synthetic-visitor'
UNLISTED = 'synthetic-unlisted'
FIRST_TEXT = 'public synthetic prompt'
SECOND_TEXT = 'public synthetic answer'


def migrated_desktop(test, control, existing=None):
    from peters_mcp.agent_history_admin import activate_preview, preview_path_migration, write_descriptor
    from tests import test_agent_history_antigravity_native as native

    fixture = native.AntigravityNativeTests()
    fixture.setUp()
    test.addCleanup(fixture.doCleanups)
    old = fixture.project
    current = old.with_name('migrated-root')
    old.rename(current)
    (current / 'visible.txt').write_text('ordinary current project file')
    document = deepcopy(existing or {'version': 2, 'projects': [], 'sources': {}, 'legacy_history': None})
    document['projects'].append({'id': 'moved', 'name': 'Migrated', 'root': str(current)})
    document['sources']['desktop'] = {'adapter': 'antigravity', 'format': '2.33.0', 'enabled': True,
        'instance_id': 'desktop-profile', 'root': str(fixture.reader.root.path), 'path_aliases': [{
            'source_instance': 'desktop-profile', 'native_project_id': native.PROJECT, 'old_root': str(old),
            'project_id': 'moved', 'target_root': str(current)}]}
    control = control.resolve()
    control.mkdir(mode=0o700)
    store = initialize_store(control / 'generations')
    cutoff = datetime.fromtimestamp(native.SECONDS + 1, timezone.utc).isoformat()
    preview, digest = preview_path_migration(document, 'desktop', str(old), cutoff)
    test.assertEqual(preview['path_migration']['proposed'], [native.SESSION])
    activate_preview(store, preview, digest, initial=True)
    descriptor = control / 'policy.json'
    write_descriptor(descriptor, store)
    return AgentPolicy(descriptor, mode='v2'), old


class UnifiedDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(self.tmp).resolve()
        control = root / 'control'
        control.mkdir(mode=0o700)
        project = root / 'project'
        project.mkdir()
        home = root / 'codex'
        (home / 'sessions').mkdir(parents=True)
        rollout = home / 'sessions' / f'rollout-synthetic-{THREAD}.jsonl'
        recorded = datetime.now(timezone.utc).isoformat()
        rollout.write_bytes(encode([{**item, "timestamp": recorded} for item in (
            record('session_meta', {'id': THREAD, 'cwd': str(project), 'timestamp': recorded}),
            message(FIRST_TEXT), message(SECOND_TEXT, 'assistant', 'final', native_id='synthetic-answer'),
        )]))
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
            'sources': {'codex': {
                'adapter': 'codex', 'root': str(home), 'format': 'state_5', 'enabled': True,
                'instance_id': 'synthetic-codex', 'root_identity': persistent_identity(home),
            }},
            'legacy_history': {'codex_home': str(home), 'state_db': 'state_5.sqlite',
                               'tool_evidence': []},
        }
        self.store = initialize_store(control / 'policy-generations')
        self.epoch = self.store.activate(self.document, initial=True)
        descriptor = control / 'history-v2.json'
        descriptor.write_text(json.dumps({'version': 2, 'generation_directory': str(self.store.path)}))
        descriptor.chmod(0o600)
        self.policy = AgentPolicy(descriptor, mode='v2')
        app = build_app(Catalog.from_policy(self.policy), settings, agent_policy=self.policy)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        protocol_headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-03-26'}
        self.headers = {None: protocol_headers}
        for subject in (OWNER, VISITOR, UNLISTED):
            token = jwt.encode({'iss': settings.team_domain, 'aud': [settings.audience], 'iat': now-1,
                                'exp': now+300, 'email': f'{subject}@example.com', 'sub': subject},
                               key, algorithm='RS256', headers={'kid': 'synthetic'})
            self.headers[subject] = {**protocol_headers, 'cf-access-jwt-assertion': token}
        self.client = self.enterContext(TestClient(app, base_url='https://mcp.example.com'))
        self.serial = 0

    def post_tool(self, name, arguments, *, subject=OWNER):
        self.serial += 1
        return self.client.post('/mcp', headers=self.headers[subject], json={
            'jsonrpc': '2.0', 'id': self.serial, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments},
        })

    def call(self, name, arguments, *, subject=OWNER):
        response = self.post_tool(name, arguments, subject=subject)
        self.assertEqual(response.status_code, 200)
        envelope = response.json()
        self.assertEqual(envelope['jsonrpc'], '2.0')
        self.assertEqual(envelope['id'], self.serial)
        if 'error' in envelope:
            error = envelope['error']
            self.assertNotIn('result', envelope)
            self.assertNotIn('data', error)
            self.assertIsInstance(error['message'], str)
            return True, error['message']
        result = envelope['result']
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

    def test_access_gate_denies_missing_assertion_and_unlisted_identity(self):
        for subject in (None, UNLISTED):
            with self.subTest(subject=subject):
                response = self.post_tool('find_agent_threads', {'project_id': 'synthetic'}, subject=subject)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {'error': 'Cloudflare Access authentication required.'})

    def test_only_returned_migrated_native_hits_require_the_former_root_at_http_delivery(self):
        policy, old = migrated_desktop(self, Path(self.tmp) / 'migration', self.document)
        previous = self.client.app.verifier
        app = build_app(Catalog.from_policy(policy), previous.settings, agent_policy=policy)
        app.verifier.keys = previous.keys
        self.client = self.enterContext(TestClient(app, base_url='https://mcp.example.com'))
        home = Path(self.document['sources']['codex']['root'])
        other_id = 'bb123456-1234-1234-1234-123456789abc'
        recorded = datetime.now(timezone.utc).isoformat()
        rollout = home / 'sessions' / f'rollout-control-{other_id}.jsonl'
        project = self.document['projects'][0]['root']
        rollout.write_bytes(encode([{**row, 'timestamp': recorded} for row in (
            record('session_meta', {'id': other_id, 'cwd': project, 'timestamp': recorded}),
            message('Independent Codex control'))]))
        with sqlite3.connect(home / 'state_5.sqlite') as db:
            db.execute('INSERT INTO threads VALUES (?,?,?,?,?,?)',
                       (other_id, str(rollout), project, 'Independent Codex control', int(time.time()), 0))
        query = {'project_id': 'moved', 'source_id': 'desktop'}
        error, found = self.complete('find_agent_threads', query)
        self.assertFalse(error, found)
        arguments = {'thread_ref': found['threads'][0]['thread_ref']}
        error, page = self.complete('read_agent_thread', arguments)
        self.assertFalse(error, page)
        self.assertIn('Visible Gemini answer 1', str(page['entries']))
        self.assertNotIn('delivery_aliases', page)
        self.assertNotIn(str(old), str(page))
        from peters_mcp.catalog import AccessError
        from peters_mcp.project_guard import verify_worker_aliases
        catalog = Catalog.from_policy(policy)
        for invalid in ([str(old)], [{'old_root': str(old)}], ['0' * 64]):
            with self.subTest(invalid_type=type(invalid[0])), self.assertRaises(AccessError):
                verify_worker_aliases(catalog, 'moved', invalid)

        real_call = IsolatedHistory._call
        for requested, args, validated in (
                ('read_agent_thread', arguments, 'read_agent_thread'),
                ('find_agent_threads', {'project_id': 'moved'}, 'validate_agent_hits')):
            changed = []
            def reuse_after_worker_reply(worker, operation, params):
                value = real_call(worker, operation, params)
                if not changed and operation == validated and value.get('status') == 'ready':
                    old.mkdir()
                    changed.append(True)
                return value

            with patch.object(IsolatedHistory, '_call', reuse_after_worker_reply):
                error, refused = self.complete(requested, args)
            self.assertTrue(changed)
            self.assertTrue(error, refused)
            self.assertIn('restart_required', refused)
            self.assertNotIn('Visible Gemini answer', refused)
            error, data = self.call('read_file', {'project_id': 'moved', 'path': 'visible.txt'})
            self.assertFalse(error, data)
            self.assertIn('ordinary current project file', data)
            error, other = self.complete('find_agent_threads', {'source_id': 'codex', 'project_id': 'synthetic'})
            self.assertFalse(error, other)
            self.assertIn('Independent Codex control', {row['title'] for row in other['threads']})
            old.rmdir()
        error, restored = self.complete('read_agent_thread', arguments)
        self.assertFalse(error, restored)
        self.assertIn('Visible Gemini answer 1', str(restored['entries']))

    def test_replacement_directory_cannot_read_historical_codex_via_either_api(self):
        old = self.document['projects'][0]
        root = Path(old['root'])
        revoked = self.store.activate({**self.document, 'projects': []}, expected_digest=self.epoch)
        root.rename(root.with_name('previous-repository'))
        root.mkdir()
        replacement = {**old, 'id': 'replacement', 'directory_identity': persistent_identity(root)}
        self.store.activate({**self.document, 'projects': [replacement]}, expected_digest=revoked)
        for name, kwargs in (('find_agent_threads', {'source_id': 'codex'}), ('find_codex_threads', {})):
            with self.subTest(name=name):
                error, found = self.complete(name, {'project_id': 'replacement', **kwargs})
                self.assertFalse(error, found)
                self.assertEqual(found['threads'], [])
                if name == 'find_agent_threads':
                    self.assertEqual(found['coverage'][0]['state'], 'association_unverified')
                else:
                    self.assertIn('coverage_unverified', str(found['warnings']))
                self.assertNotIn('Synthetic thread', str(found))
        error, denied = self.complete('read_codex_thread', {'thread_id': THREAD})
        self.assertTrue(error, denied)
        self.assertNotIn(FIRST_TEXT, str(denied))

    def test_historical_symlink_beneath_a_project_cannot_reenter_either_codex_api(self):
        root = Path(self.document['projects'][0]['root'])
        home = Path(self.document['sources']['codex']['root'])
        outside = root.parent / 'outside-history'
        outside.mkdir()
        real = root.parent / 'staging' / 'other-directory'
        real.mkdir(parents=True)
        logical = root / 'nested'
        logical.symlink_to(outside, target_is_directory=True)
        stamp = datetime.now(timezone.utc).isoformat()
        rollout = home / 'sessions' / f'rollout-synthetic-{THREAD}.jsonl'
        rows = (record('session_meta', {'id': THREAD, 'cwd': str(logical), 'timestamp': stamp}), message(FIRST_TEXT))
        rollout.write_bytes(encode([{**row, 'timestamp': stamp} for row in rows]))
        with sqlite3.connect(home / 'state_5.sqlite') as db:
            db.execute('UPDATE threads SET cwd=? WHERE id=?', (str(logical), THREAD))
        logical.unlink()
        real.rename(logical)
        for name in ('find_agent_threads', 'find_codex_threads'):
            error, page = self.complete(name, {'project_id': 'synthetic'})
            self.assertFalse(error, page)
            self.assertEqual(page['threads'], [])
        error, detail = self.complete('read_codex_thread', {'thread_id': THREAD})
        self.assertTrue(error, detail)
        self.assertNotIn(FIRST_TEXT, str(detail))

    def test_legacy_and_new_tools_share_caller_source_and_page_revocation(self):
        references = {}
        for subject in (OWNER, VISITOR):
            with self.subTest(subject=subject):
                error, old = self.complete('find_codex_threads', {}, subject=subject)
                self.assertFalse(error, old)
                self.assertEqual([hit['thread_id'] for hit in old['threads']], [THREAD])
                error, new = self.complete('find_agent_threads',
                                           {'project_id': 'synthetic', 'source_id': 'codex'}, subject=subject)
                self.assertFalse(error, new)
                self.assertEqual(len(new['threads']), 1)
                references[subject] = new['threads'][0]['thread_ref']
                error, page = self.complete('read_agent_thread', {'thread_ref': references[subject]}, subject=subject)
                self.assertFalse(error, page)
                self.assertEqual(page['entries'][0]['text'], FIRST_TEXT)
        self.assertNotEqual(references[OWNER], references[VISITOR])
        denied, detail = self.complete('read_agent_thread', {'thread_ref': references[OWNER]}, subject=VISITOR)
        self.assertTrue(denied, detail)
        self.assertIn('unauthorized', detail)
        self.assertNotIn(FIRST_TEXT, detail)
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
            ('read_agent_thread', {'thread_ref': references[OWNER]}),
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

    def read_during_worktree_move(self, name, arguments, *, overlaps):
        project = Path(self.document['projects'][0]['root'])
        foreign = project.parent / 'foreign'
        side = project.parent / 'side'
        revised = deepcopy(self.document)
        revised['projects'].append(fixture_registered_worktree(foreign, side))
        self.epoch = self.store.activate(revised, expected_digest=self.epoch)
        original = IsolatedHistory._verify_delivery_topology
        observed = []

        def change_after_child_validation(worker, digest, project_id):
            observed.append((digest, project_id))
            destination = (project if overlaps else project.parent) / 'moved-side'
            fixture_git(foreign, 'worktree', 'move', str(side), str(destination))
            return original(worker, digest, project_id)

        with patch.object(IsolatedHistory, '_verify_delivery_topology', change_after_child_validation):
            denied, detail = self.complete(name, arguments)
        self.assertEqual(len(observed), 1)
        self.assertRegex(observed[0][0], r'^[0-9a-f]{64}$')
        return denied, detail, observed[0][1]

    def test_child_validated_topology_must_match_parent_before_body_delivery(self):
        denied, detail, scope = self.read_during_worktree_move('read_codex_thread', {'thread_id': THREAD}, overlaps=True)
        self.assertEqual(scope, 'synthetic')
        self.assertTrue(denied, detail)
        self.assertIn('restart_required', detail)
        self.assertNotIn(FIRST_TEXT, detail)
        self.assertNotIn(SECOND_TEXT, detail)

    def test_unrelated_move_preserves_single_thread_worker_and_transport_delivery(self):
        denied, page, scope = self.read_during_worktree_move('read_codex_thread', {'thread_id': THREAD}, overlaps=False)
        self.assertFalse(denied, page)
        self.assertEqual(scope, 'synthetic')
        self.assertEqual(page['entries'][1]['text'], SECOND_TEXT)

    def test_unfiltered_legacy_project_search_still_requires_global_scope(self):
        denied, detail, scope = self.read_during_worktree_move('find_codex_threads', {}, overlaps=False)
        self.assertIsNone(scope)
        self.assertTrue(denied, detail)
        self.assertIn('restart_required', detail)
        self.assertNotIn('Synthetic thread', detail)
