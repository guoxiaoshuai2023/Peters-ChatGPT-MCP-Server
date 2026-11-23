"""The isolated matrix exercises the actual MCP transport and signed identity gate."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import anyio
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.testclient import TestClient

from peters_mcp.agent_file_access import create_agent_file_app
from peters_mcp.agent_file_admin import apply, preview
from peters_mcp.agent_file_auth import MachineAccessVerifier
from peters_mcp.agent_file_policy import initialize_agent_file_policy
from peters_mcp.catalog import Catalog
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.workspaces import repository_probe


ISSUER = 'https://synthetic-agent-team.cloudflareaccess.com'
AUDIENCE = 'a' * 64
HOST = 'agent.example.com'
CLIENTS = ('codex', 'antigravity', 'codeg', 'deepseek')
TOOLS = {'list_projects', 'list_worktrees', 'list_files', 'search', 'read_file'}


def credential(idx):
    return f'{idx + 1:032x}.access'


class AgentFileAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.context = self.enterContext(ExitStack())
        root = Path(self.context.enter_context(TemporaryDirectory())).resolve()
        self.projects = []
        self.text = {}
        for n in range(7):
            project = root / f'project-{n}'
            project.mkdir()
            worktree = project
            data = {'id': f'project-{n}', 'name': f'Project {n}', 'root': str(project)}
            if n == 0:
                def git(*args):
                    return subprocess.run(['git', '-C', str(project), *args], check=True, capture_output=True)

                git('init', '-b', 'main')
                git('-c', 'user.name=Synthetic', '-c', 'user.email=test@example.com',
                    'commit', '--allow-empty', '-m', 'synthetic test')
                worktree = root / 'registered-worktree'
                git('worktree', 'add', '-b', 'fixture', str(worktree))
                data['repository_id'] = repository_probe(project)['repository_id']
            self.projects.append(data)
            self.text[n] = 'Synthetic project 中文 ' + str(n)
            (worktree / 'sample.txt').write_text(self.text[n])
        self.outside = root / 'outside'
        self.outside.mkdir()
        (self.outside / 'canary.txt').write_text('OUTSIDE PROTECTED FILE')
        (root / 'project-1' / 'link.txt').symlink_to(self.outside / 'canary.txt')
        self.control = root / 'control'
        self.control.mkdir(mode=0o700)
        self.registry = PrivateRootRegistry(self.control, allowed_roots=())
        self.registry.initialize()
        self.projects_path = root / 'projects.json'
        self.projects_path.write_bytes(self.project_bytes(6))
        self.projects_path.chmod(0o600)
        self.policy = initialize_agent_file_policy(self.projects_path, self.control / 'agent-read')
        self.verifier = MachineAccessVerifier(ISSUER, AUDIENCE)
        self.context.enter_context(patch.object(self.verifier.keys, 'get_signing_key_from_jwt',
                                               return_value=SimpleNamespace(key=self.rsa_key.public_key())))
        self.app = create_agent_file_app(self.policy, self.verifier, HOST, registry=self.registry)
        self.client = self.context.enter_context(TestClient(self.app, base_url=f'https://{HOST}'))
        self.serial = 0

    def project_bytes(self, number):
        return json.dumps({'projects': self.projects[:number]}).encode()

    def grant(self, active):
        records = [{'id': name, 'issuer': ISSUER, 'audience': AUDIENCE, 'client_id': credential(i),
                    'enabled': i in active}
                   for i, name in enumerate(CLIENTS) if i in active or i < 3]
        return self.publish('agents', records)

    def publish(self, kind, data):
        document, approval = preview(self.policy, kind, proposed=data)
        return apply(self.policy, document, approval)

    def token(self, actor, **claims):
        now = int(time.time())
        return jwt.encode({'iss': ISSUER, 'aud': [AUDIENCE], 'iat': now-1, 'exp': now+300,
                           'sub': '', 'type': 'app', 'common_name': credential(actor), **claims},
                          self.rsa_key, algorithm='RS256', headers={'kid': 'synthetic-key'})

    def request(self, actor, method, params, *, token=None, version='2025-11-25'):
        self.serial += 1
        return self.client.post('/mcp', headers={'Accept': 'application/json, text/event-stream',
                                'MCP-Protocol-Version': version, 'Mcp-Method': method,
                                'Cf-Access-Jwt-Assertion': token or self.token(actor)},
                                json={'jsonrpc': '2.0', 'id': self.serial, 'method': method, 'params': params})

    def call(self, actor, name, **args):
        return self.request(actor, 'tools/call', {'name': name, 'arguments': args})

    def result(self, response):
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(response.headers['cache-control'], 'no-store')
        result = response.json()['result']
        self.assertFalse(result.get('isError'), result)
        if 'structuredContent' in result:
            return result['structuredContent']
        return json.loads(result['content'][0]['text'])

    def file(self, actor, n, **args):
        if n == 0 and 'worktree_id' not in args:
            rows = self.result(self.call(actor, 'list_worktrees', project_id='project-0'))['worktrees']
            args['worktree_id'] = next(row['id'] for row in rows if row['branch'] == 'fixture')
        return self.call(actor, 'read_file', project_id=f'project-{n}', path='sample.txt', **args)

    def assert_reads(self, actors, projects):
        for actor in actors:
            for n in projects:
                with self.subTest(actor=CLIENTS[actor], project=n):
                    result = self.result(self.file(actor, n))
                    self.assertEqual(result['text'], self.text[n])
                    self.assertEqual(result['sha256'], hashlib.sha256(self.text[n].encode()).hexdigest())

    def test_18_then_24_reads_over_same_project_file(self):
        self.grant({0, 1, 2})
        self.assert_reads(range(3), range(6))
        before = (self.projects_path.read_bytes(), self.projects_path.stat().st_ino)
        self.grant({0, 1, 2, 3})
        self.assertEqual(before, (self.projects_path.read_bytes(), self.projects_path.stat().st_ino))
        self.assert_reads(range(4), range(6))

    def test_live_project_add_and_both_revocations(self):
        self.grant({0, 1, 2, 3})
        identities = dict(self.policy.snapshot().principals)
        self.publish('projects', self.project_bytes(7))
        self.assertEqual(identities, self.policy.snapshot().principals)
        self.assert_reads(range(4), [6])
        first = self.result(self.file(0, 6, limit=5))
        self.publish('projects', self.project_bytes(6))
        for actor in range(4):
            response = self.file(actor, 6, offset=first['next_offset'], expected_sha256=first['sha256'])
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(self.text[6], response.text)
        old_token = self.token(0)
        self.grant({1, 2, 3})
        denied = self.request(0, 'tools/list', {}, token=old_token)
        self.assertEqual(denied.status_code, 403)
        self.assert_reads(range(1, 4), [1])

    def test_tool_surface_machine_assertions_and_protected_paths(self):
        self.grant({0, 1, 2})
        listed = self.request(0, 'tools/list', {}).json()['result']['tools']
        self.assertEqual({x['name'] for x in listed}, TOOLS)
        discovery = self.request(0, 'server/discover', {'_meta': {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
        }}, version='2026-07-28')
        self.assertEqual(discovery.status_code, 200, discovery.text)
        self.assertIn('result', discovery.json())
        self.assertEqual(self.call(0, 'save_candidate').status_code, 403)
        self.assertEqual(self.request(0, 'resources/read', {'uri': 'file:///tmp/fake'}).status_code, 403)
        self.assertEqual(self.request(3, 'tools/list', {}).status_code, 403)
        fake_human = self.token(0, sub='same-user', email='same@example.com')
        self.assertEqual(self.request(0, 'tools/list', {}, token=fake_human).status_code, 401)
        self.assertEqual(self.request(0, 'tools/list', {}, token=self.token(0, aud=['b'*64])).status_code, 401)
        for path in ('link.txt', '../outside/canary.txt'):
            denied = self.call(0, 'read_file', project_id='project-1', path=path)
            self.assertIn('isError', denied.json()['result'])
            self.assertNotIn('OUTSIDE PROTECTED FILE', denied.text)
        old = Catalog.from_config(self.projects_path)
        self.assertEqual(len(old.list_projects()['projects']), 6)

    def test_revocation_prevents_already_prepared_body(self):
        self.grant({0, 1, 2})
        prepared = threading.Event()
        resume = threading.Event()
        commit = self.app._commit

        def block(request, deadline, deliver):
            prepared.set()
            self.assertTrue(resume.wait(8))
            return commit(request, deadline, deliver)

        with patch.object(self.app, '_commit', side_effect=block), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.file, 0, 1)
            try:
                self.assertTrue(prepared.wait(8))
                self.grant({1, 2})
            finally:
                resume.set()
            response = future.result(timeout=10)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'error': 'agent_file_policy_changed'})
        self.assertNotIn(self.text[1], response.text)

    def test_slow_delivery_root_check_does_not_lock_out_agent_revocation(self):
        self.grant({0, 1, 2})
        checking = threading.Event()
        resume = threading.Event()
        verify = self.policy.verify_delivery_roots

        def delay(snapshot, receipt, *, deadline):
            checking.set()
            self.assertTrue(resume.wait(8))
            return verify(snapshot, receipt, deadline=deadline)

        with patch.object(self.policy, 'verify_delivery_roots', side_effect=delay), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.file, 0, 1)
            try:
                self.assertTrue(checking.wait(8))
                self.grant({1, 2})
            finally:
                resume.set()
            response = future.result(timeout=10)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'error': 'agent_file_policy_changed'})
        self.assertNotIn(self.text[1], response.text)

    def test_request_deadline_abandons_a_slow_probe_without_delivering_late(self):
        self.grant({0, 1, 2})
        self.app.commit_timeout = 0.25
        checking = threading.Event()
        resume = threading.Event()
        exited = threading.Event()
        verify = self.policy.verify_delivery_roots

        def delay(snapshot, receipt, *, deadline):
            checking.set()
            try:
                self.assertTrue(resume.wait(8))
                return verify(snapshot, receipt, deadline=deadline)
            finally:
                exited.set()

        with patch.object(self.policy, 'verify_delivery_roots', side_effect=delay), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.file, 0, 1)
            try:
                self.assertTrue(checking.wait(8))
                response = future.result(timeout=2)
                self.assertFalse(exited.is_set())
                self.grant({1, 2})
            finally:
                resume.set()
            self.assertTrue(exited.wait(8))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'error': 'commit_timeout'})
        self.assertNotIn(self.text[1], response.text)

    def test_cancelled_request_never_delivers_from_an_abandoned_worker(self):
        self.grant({0, 1, 2})
        entered = threading.Event()
        resume = threading.Event()
        exited = threading.Event()
        events = []
        commit = self.app._commit

        def block(request, deadline, deliver):
            entered.set()
            try:
                self.assertTrue(resume.wait(8))
                return commit(request, deadline, deliver)
            finally:
                exited.set()

        async def probe():
            scope = {
                'type': 'http', 'path': '/mcp', 'root_path': '', 'method': 'POST', 'scheme': 'https',
                'headers': [(b'host', HOST.encode()), (b'accept', b'application/json, text/event-stream'),
                            (b'content-type', b'application/json'),
                            (b'cf-access-jwt-assertion', self.token(0).encode())],
                'query_string': b'',
            }
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                'name': 'read_file', 'arguments': {'project_id': 'project-1', 'path': 'sample.txt'},
            }}).encode()
            consumed = False

            async def receive():
                nonlocal consumed
                if consumed:
                    await anyio.sleep_forever()
                consumed = True
                return {'type': 'http.request', 'body': body, 'more_body': False}

            async def send(event):
                events.append(event)

            finished = anyio.Event()

            async def request(*, task_status=anyio.TASK_STATUS_IGNORED):
                try:
                    with anyio.CancelScope() as cancel_scope:
                        task_status.started(cancel_scope)
                        await self.app(scope, receive, send)
                finally:
                    finished.set()

            async with anyio.create_task_group() as group:
                try:
                    cancel_request = await group.start(request)
                    self.assertTrue(await anyio.to_thread.run_sync(entered.wait, 8))
                    cancel_request.cancel()
                    with anyio.fail_after(2):
                        await finished.wait()
                finally:
                    resume.set()
                self.assertTrue(await anyio.to_thread.run_sync(exited.wait, 8))

        with patch.object(self.app, '_commit', side_effect=block):
            self.client.portal.call(probe)
        self.assertEqual(events, [])
