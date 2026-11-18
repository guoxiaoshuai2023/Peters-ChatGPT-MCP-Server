"""Cross-agent history through the stdio and authenticated HTTP MCP entrypoints."""

import asyncio
from contextlib import closing, contextmanager
import json
from pathlib import Path
import sqlite3
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from mcp import StdioServerParameters
from mcp.client import Client
from starlette.testclient import TestClient

from peters_mcp.agent_history_deepseek import _project_key
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import actor_digest
from tests import test_agent_history_antigravity as synthetic
from tests import test_agent_history_codeg as codeg
from tests import test_agent_history_deepseek as deepseek


BASE = Path(__file__).resolve().parent.parent
SOURCE = 'gravity-fixture'
VISIBLE = 'Native Markdown question 中文\n' * 12
HIDDEN = 'Reasoning content canary for source search'
UNGRANTED = 'Unapproved native conversation canary'


class AgentHistoryMCPTests(unittest.TestCase):
    def setUp(self):
        fixture = synthetic.AntigravityAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root.parent
        self.project_config = self.root / 'projects.json'
        self.project_config.write_text(json.dumps({'projects': [
            {'id': 'example', 'name': 'Example', 'root': str(fixture.project)},
            {'id': 'wide', 'name': 'Wide', 'root': str(self.root)},
        ]}))
        self.policy_path = self.root / 'agent-history-policy.json'
        self.audit_path = self.root / 'audit.jsonl'
        fixture.add_thread(synthetic.FIRST)
        fixture.add_thread(synthetic.SECOND)
        fixture.add_thread(synthetic.THIRD)  # Not granted, and no transcript yet.
        self.transcript = fixture.transcript(synthetic.FIRST)
        self.transcript_bytes = synthetic.write_steps(self.transcript, [
            synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', VISIBLE),
            synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', 'Visible response', thinking=HIDDEN),
        ])
        synthetic.write_steps(fixture.transcript(synthetic.SECOND), [
            synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', UNGRANTED),
        ])
        (fixture.root / 'looks-readable.txt').write_text('Raw-source root canary')

    def write_policy(self, actors, *, denied=(), inherit=False, sources=None):
        data = {'version': 1, 'sources': {SOURCE: {
            'adapter': 'antigravity', 'format': '2.32.1', 'root': str(self.fixture.root),
            'enabled': True, 'inherit_projects': inherit, 'actors': actors,
            'threads': {synthetic.FIRST: 'example'}, 'denied_threads': list(denied),
        }}}
        for name, source in (sources or {}).items():
            data['sources'][name] = {**source, 'actors': actors}
        temporary = self.policy_path.with_name('next-agent-history-policy.json')
        temporary.write_text(json.dumps(data))
        temporary.replace(self.policy_path)

    def test_stdio_search_snapshot_paging_and_project_file_exclusion(self):
        self.write_policy({'local': ['example']}, inherit=True)

        async def run():
            params = StdioServerParameters(command=sys.executable, cwd=str(BASE), args=[
                '-m', 'peters_mcp', '--config', str(self.project_config),
                '--agent-history-config', str(self.policy_path), '--audit-log', str(self.audit_path),
            ])
            async with Client(params) as client:
                listing = await client.list_tools()
                tools = {tool.name: tool for tool in listing.tools}
                for name in ('find_agent_threads', 'read_agent_thread'):
                    self.assertTrue(tools[name].annotations.model_dump(by_alias=True)['readOnlyHint'])

                async def complete(name, arguments):
                    for _ in range(100):
                        result = await client.call_tool(name, arguments)
                        self.assertFalse(result.is_error, result.content)
                        page = json.loads(result.content[0].text)
                        if page.get('status') != 'processing':
                            self.assertEqual(page.get('status'), 'ready', page)
                            return page
                        self.assertNotIn('entries', page)
                        arguments = {**arguments, 'cursor': page['next_cursor']}
                        await asyncio.sleep(0.01)
                    self.fail('Stdio Agent history did not finish its bounded continuation')

                search = {'project_id': 'example', 'source_id': SOURCE}
                for canary in (HIDDEN, UNGRANTED):
                    no_match = await complete('find_agent_threads', {**search, 'query': canary})
                    self.assertEqual(no_match['threads'], [])
                    self.assertTrue(no_match['coverage_complete'])
                found = await complete('find_agent_threads', {**search, 'query': 'Native Markdown question'})
                thread, = found['threads']
                self.assertEqual((thread['agent'], thread['surface'], thread['source_id']),
                                 ('antigravity', 'desktop', SOURCE))
                self.assertEqual(thread['match']['in'], 'visible_message')
                read = {'thread_ref': thread['thread_ref'], 'limit': 1, 'max_chars': 105}
                page = await complete('read_agent_thread', read)
                fingerprint = page['snapshot_sha256']
                first, = page['entries']
                self.assertTrue(first['has_more_text'])
                self.assertEqual(first['message_id'], thread['match']['message_id'])
                collected = [first]

                appended = synthetic.step(2, 'USER_INPUT', 'USER_EXPLICIT', 'Arrived after the frozen read')
                new_bytes = json.dumps(appended).encode() + b'\n'
                with self.transcript.open('ab') as stream:
                    stream.write(new_bytes)
                while page['has_more']:
                    page = await complete('read_agent_thread', {**read, 'cursor': page['next_cursor']})
                    self.assertEqual(page['snapshot_sha256'], fingerprint)
                    collected.extend(page['entries'])
                self.assertEqual(''.join(item['text'] for item in collected), VISIBLE + 'Visible response')
                fresh = await complete('read_agent_thread', {'thread_ref': thread['thread_ref']})
                self.assertEqual(fresh['entries'][-1]['text'], 'Arrived after the frozen read')
                self.assertNotIn(HIDDEN, json.dumps(fresh))
                self.assertEqual(self.transcript.read_bytes(), self.transcript_bytes + new_bytes)

                raw = await client.call_tool('read_file', {'project_id': 'wide', 'path': 'app-data/looks-readable.txt'})
                self.assertTrue(raw.is_error, raw.content)
                listing = await client.call_tool('list_files', {'project_id': 'wide'})
                self.assertFalse(listing.is_error, listing.content)
                paths = [entry['path'] for entry in json.loads(listing.content[0].text)['entries']]
                self.assertNotIn('app-data', paths)
                self.assertNotIn(self.policy_path.name, paths)

        asyncio.run(run())
        audit = self.audit_path.read_text()
        self.assertNotIn(HIDDEN, audit)
        self.assertNotIn('Native Markdown question', audit)

    @contextmanager
    def authenticated(self, subjects, *, sources=None):
        settings = AccessSettings('https://test-team.cloudflareaccess.com', 'a' * 64,
                                  'mcp.example.com', tuple(f'{subject}@example.com' for subject in subjects))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        claims = {'iss': settings.team_domain, 'aud': [settings.audience], 'iat': now - 1, 'exp': now + 300}

        def token(subject):
            return jwt.encode({**claims, 'email': f'{subject}@example.com', 'sub': subject}, key,
                              algorithm='RS256', headers={'kid': 'synthetic-key'})

        actors = {actor_digest(settings.team_domain, subject): ['example'] for subject in subjects}
        self.write_policy(actors, sources=sources)
        app = build_app(Catalog.from_config(self.project_config), settings,
                        agent_policy=AgentPolicy(self.policy_path))
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        with TestClient(app, base_url='https://mcp.example.com') as client:
            counter = 0

            def rpc(subject, method, parameters):
                nonlocal counter
                counter += 1
                headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-03-26',
                           'cf-access-jwt-assertion': token(subject)}
                response = client.post('/mcp', headers=headers, json={
                    'jsonrpc': '2.0', 'id': counter, 'method': method, 'params': parameters,
                })
                self.assertEqual(response.status_code, 200, response.text)
                body = response.json()
                self.assertNotIn('error', body)
                return body['result']

            def call(subject, name, arguments):
                return rpc(subject, 'tools/call', {'name': name, 'arguments': arguments})

            def ready(subject, name, arguments):
                for _ in range(100):
                    result = call(subject, name, arguments)
                    self.assertFalse(result.get('isError'), result)
                    page = json.loads(result['content'][0]['text'])
                    if page['status'] != 'processing':
                        self.assertEqual(page['status'], 'ready', page)
                        return page
                    arguments = {**arguments, 'cursor': page['next_cursor']}
                    time.sleep(0.01)
                self.fail('Authenticated Agent history did not finish its bounded continuation')

            for subject in subjects:
                rpc(subject, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                            'clientInfo': {'name': 'synthetic-auth-test', 'version': '1'}})
            yield actors, call, ready

    def test_authenticated_http_thread_refs_are_principal_bound_and_revoked(self):
        with self.authenticated(('first', 'second')) as (actors, call, ready):
            search = {'project_id': 'example', 'source_id': SOURCE}
            first_ref = ready('first', 'find_agent_threads', search)['threads'][0]['thread_ref']
            second_ref = ready('second', 'find_agent_threads', search)['threads'][0]['thread_ref']
            self.assertNotEqual(first_ref, second_ref)
            first = ready('first', 'read_agent_thread', {'thread_ref': first_ref, 'limit': 1})
            self.assertTrue(first['has_more'])

            def assert_no_page(subject, arguments):
                for _ in range(100):
                    denied = call(subject, 'read_agent_thread', arguments)
                    self.assertNotIn('Native Markdown question', json.dumps(denied))
                    if denied.get('isError'):
                        return
                    status = json.loads(denied['content'][0]['text'])
                    if status['status'] != 'processing':
                        self.assertIn(status['status'], ('unauthorized', 'restart_required', 'invalid_cursor'))
                        self.assertNotIn('entries', status)
                        return
                    arguments = {**arguments, 'cursor': status['next_cursor']}
                    time.sleep(0.01)
                self.fail('Denied authenticated continuation did not terminate')

            next_page = {'thread_ref': first_ref, 'limit': 1, 'cursor': first['next_cursor']}
            assert_no_page('second', next_page)
            self.write_policy(actors, denied=(synthetic.FIRST,))
            assert_no_page('first', next_page)
            self.assertEqual(ready('first', 'find_agent_threads', search)['threads'], [])

    def test_authenticated_http_recovers_full_reply_across_gap_and_rejects_rewritten_snapshot(self):
        head, tail = 'Visible response starts. ', ' Visible response ends.'
        omitted = '中文 original'
        revised = '中文 modified'
        marker = f'\n<truncated {len(omitted.encode("utf-8"))} bytes>\n'
        prompt = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', VISIBLE)
        compact_reply = synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', head + marker + tail,
                                       truncated_fields=['content'])
        later = synthetic.step(3, 'GENERIC', 'MODEL', HIDDEN)
        synthetic.write_steps(self.transcript, [prompt, compact_reply, later])
        companion = self.transcript.with_name('transcript_full.jsonl')

        def write_companion(text):
            reply = synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', head + text + tail, thinking=HIDDEN)
            synthetic.write_steps(companion, [prompt, reply, later])

        write_companion(omitted)
        with self.authenticated(('first',)) as (_, call, ready):
            search = {'project_id': 'example', 'source_id': SOURCE, 'query': 'Test dialog 10'}
            thread, = ready('first', 'find_agent_threads', search)['threads']
            read = {'thread_ref': thread['thread_ref']}
            recovered = ready('first', 'read_agent_thread', read)
            self.assertFalse(recovered['coverage_complete'], recovered)
            self.assertEqual(recovered['warnings'], ['missing_steps'])
            self.assertFalse(recovered['has_more'])
            self.assertEqual([(item['role'], item['text']) for item in recovered['entries']],
                             [('user', VISIBLE), ('assistant', head + omitted + tail)])
            self.assertNotIn(HIDDEN, json.dumps(recovered))

            paged = {**read, 'limit': 1}
            first = ready('first', 'read_agent_thread', paged)
            self.assertTrue(first['has_more'])
            write_companion(revised)  # Overwrite the existing companion in place.
            arguments = {**paged, 'cursor': first['next_cursor']}
            for _ in range(100):
                result = call('first', 'read_agent_thread', arguments)
                if result.get('isError'):
                    self.assertIn('start a fresh search or read', result['content'][0]['text'])
                    break
                page = json.loads(result['content'][0]['text'])
                self.assertEqual(page['status'], 'processing', page)
                arguments = {**arguments, 'cursor': page['next_cursor']}
                time.sleep(0.01)
            else:
                self.fail('Rewritten Antigravity companion did not invalidate the old read cursor')

            fresh = ready('first', 'read_agent_thread', read)
            self.assertFalse(fresh['coverage_complete'], fresh)
            self.assertEqual(fresh['warnings'], ['missing_steps'])
            self.assertNotEqual(fresh['snapshot_sha256'], recovered['snapshot_sha256'])
            self.assertEqual(fresh['entries'][-1]['text'], head + revised + tail)

    def test_authenticated_http_aggregates_three_sources_and_reports_an_offline_source(self):
        codeg_root = self.root / 'codeg-data'
        harness_root = self.root / 'harness-data'
        offline = self.root / 'offline-data'
        for path in (codeg_root, harness_root, offline):
            path.mkdir()
        project = str(self.fixture.project)
        with closing(sqlite3.connect(codeg_root / 'codeg.db')) as db:
            db.executescript(codeg._SCHEMA)
            db.execute("INSERT INTO folder VALUES (1, ?, 'regular', NULL, NULL)", (project,))
            db.execute('INSERT INTO conversation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (
                1, 'Codeg fixture', synthetic.TIME, 'custom:goose', 'fixture-codeg', project,
                1, 'regular', None, None,
            ))
            db.execute('INSERT INTO conversation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (
                2, 'Imported Harness fixture', synthetic.TIME, 'deepseek', 'fixture-harness', project,
                1, 'regular', None, None,
            ))
            db.commit()
        transcript = codeg_root / 'acp-transcripts' / 'goose' / 'fixture-codeg.jsonl'
        transcript.parent.mkdir(parents=True)
        header = {'v': 1, 'kind': 'header', 'agent': 'custom:goose', 'session_id': 'fixture-codeg',
                  'cwd': project, 'started_at_ms': 1000}
        transcript.write_bytes(deepseek.records(header, codeg.prompt('Codeg public fixture'),
                                                codeg.answer('Codeg response'), codeg.end()))

        log = harness_root / _project_key(project) / 'fixture-harness' / 'session.v4.jsonl.zstd'
        log.parent.mkdir(parents=True)
        log.write_bytes(deepseek.frame(deepseek.header('fixture-harness', project)) + deepseek.frame(
            deepseek.event(0, 'turn/start', {'turn': 1}), deepseek.user(1, 'DeepSeek public fixture'),
            deepseek.assistant(2, 'DeepSeek response'),
        ))

        def source(adapter, root, version):
            return {'adapter': adapter, 'format': version, 'root': str(root), 'enabled': True,
                    'inherit_projects': True, 'threads': {}, 'denied_threads': []}

        additional = {'codeg-fixture': source('codeg', codeg_root, '0.45.0'),
                      'deepseek-fixture': source('deepseek_harness', harness_root, '0.2.2-rc.3'),
                      'optional-fixture': source('deepseek_harness', offline, '0.2.2-rc.3')}
        additional['codeg-fixture']['links'] = {'deepseek_harness': 'deepseek-fixture'}
        expected = {SOURCE: ('antigravity', VISIBLE, 'Visible response'),
                    'codeg-fixture': ('custom:goose', 'Codeg public fixture', 'Codeg response'),
                    'deepseek-fixture': ('deepseek_harness', 'DeepSeek public fixture', 'DeepSeek response')}

        with self.authenticated(('first',), sources=additional) as (_, _, ready):
            search = {'project_id': 'example', 'limit': 2}
            first = ready('first', 'find_agent_threads', search)
            self.assertTrue(first['coverage_complete'], first)
            self.assertTrue(first['has_more'])
            second = ready('first', 'find_agent_threads', {**search, 'cursor': first['next_cursor']})
            self.assertFalse(second['has_more'])
            threads = first['threads'] + second['threads']
            self.assertEqual(len(threads), len(expected))
            self.assertEqual({row['source_id'] for row in threads}, set(expected))
            native = next(row for row in threads if row['source_id'] == 'deepseek-fixture')
            self.assertEqual(native['matched_sources'], ['codeg-fixture', 'deepseek-fixture'])
            self.assertEqual({row['source_id'] for row in first['coverage']}, set(expected) | {'optional-fixture'})
            for thread in threads:
                page = ready('first', 'read_agent_thread', {'thread_ref': thread['thread_ref']})
                agent, prompt, reply = expected[thread['source_id']]
                self.assertEqual(thread['agent'], agent)
                self.assertEqual([(entry['role'], entry['text']) for entry in page['entries']],
                                 [('user', prompt), ('assistant', reply)])

            offline.rmdir()
            fresh = ready('first', 'find_agent_threads', {'project_id': 'example'})
            self.assertFalse(fresh['coverage_complete'])
            self.assertEqual({row['source_id'] for row in fresh['threads']}, set(expected))
            by_source = {entry['source_id']: entry for entry in fresh['coverage']}
            self.assertFalse(by_source['optional-fixture']['coverage_complete'])
            self.assertIn('source_unavailable', by_source['optional-fixture']['warnings'])
            self.assertTrue(all(by_source[name]['coverage_complete'] for name in expected))
