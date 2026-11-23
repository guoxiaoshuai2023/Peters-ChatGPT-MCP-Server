"""Repo grant withdrawal at actual file publication and resource delivery."""
import asyncio
from contextlib import asynccontextmanager, contextmanager
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mcp.server.transport_security import TransportSecuritySettings
from starlette.testclient import TestClient

from peters_mcp import file_export_tools, file_jobs
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.chunked_export_config import ChunkedExportConfig
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_export import CHUNK, ExportConfig, FileExportService
from peters_mcp.file_jobs import FileSaveService
from peters_mcp.file_receiver import ReceiverHandle
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.project_guard import ProjectResponseGate
from peters_mcp.server import create_server
from peters_mcp.workspaces import RepositoryRegistry
from tests import test_export_protocol as protocol_fixture
from tests.test_file_receiver import synthetic_receive


OWNER = 'a' * 64


class UnifiedOriginalFileTests(unittest.TestCase):
    rpc = protocol_fixture.ExportProtocolTests.rpc
    call = protocol_fixture.ExportProtocolTests.call
    exported = protocol_fixture.ExportProtocolTests.exported
    wait_released = protocol_fixture.ExportProtocolTests.wait_released

    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.repo, self.other = self.base / 'repo', self.base / 'other'
        for root in self.repo, self.other:
            root.mkdir()
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.base / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        self.registry.initialize()
        self.registry.register_pending(self.spool, read_roots=[self.repo, self.other])
        self.registry.activate(self.spool, read_roots=[self.repo, self.other])
        self.document = {'version': 2, 'sources': {}, 'legacy_history': None,
            'projects': [{'id': root.name, 'name': root.name, 'root': str(root),
                          'directory_identity': persistent_identity(root)}
                         for root in (self.repo, self.other)]}
        self.store = initialize_store(self.base / 'generations')
        self.digest = self.store.activate(self.document, initial=True)
        descriptor = self.base / 'policy.json'
        descriptor.write_text(json.dumps({'version': 2, 'generation_directory': str(self.store.path)}))
        descriptor.chmod(0o600)
        self.policy = AgentPolicy(descriptor, mode='v2')
        self.catalog = Catalog.from_policy(self.policy, private_registry=self.registry)

    def apply(self, document):
        self.digest = self.store.activate(document, expected_digest=self.digest)

    def revoke(self):
        self.apply({**self.document, 'projects': self.document['projects'][1:]})

    def writer(self, **options):
        service = FileSaveService(self.catalog, self.registry, self.control,
            {'files.example.invalid': ['8.8.8.8']}, min_free_bytes=0, autostart=False,
            _receiver=synthetic_receive, **options)
        self.addCleanup(service.close)
        return service

    @staticmethod
    def save_args(writer, project='repo', target='new/file.bin', key='original'):
        view = writer.inspect(OWNER, project, 'main', target)
        return dict(actor=OWNER, project_id=project, worktree_id='main', path=target,
                    target_version=view['target_version'], destination_display=view['destination_display'],
                    file={'file_id': 'synthetic', 'download_url': 'https://files.example.invalid/data'},
                    request_key=key, expected_size_bytes=32)

    def wait_for(self, predicate):
        end = time.monotonic() + 7
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.02)
        self.fail('Synchronized test state did not settle.')

    def test_original_job_is_fenced_after_revoke_and_readd_while_unrelated_job_completes(self):
        writer = self.writer()
        args = self.save_args(writer)
        with self.assertRaises(AccessError) as foreign_review:
            writer.submit(**{**args, 'actor': 'b' * 64})
        self.assertEqual(foreign_review.exception.code, 'target_version_changed')
        revoked_id = writer.submit(**args)['job_id']
        other_id = writer.submit(**self.save_args(writer, project='other', key='other'))['job_id']
        self.revoke()
        self.apply(self.document)
        for action in (
            lambda: writer.status(OWNER, job_id=revoked_id),
            lambda: writer.status(OWNER, request_key=args['request_key']),
            lambda: writer.submit(**args),
            lambda: writer.cancel(OWNER, revoked_id),
            lambda: writer.refresh_source(OWNER, revoked_id, 1, args['file']),
        ):
            with self.assertRaises(AccessError) as denied:
                action()
            self.assertEqual(denied.exception.code, 'not_found')
        writer.start()
        self.wait_for(lambda: writer._get(revoked_id)['state'] == 'authorization_blocked'
                      and writer._get(other_id)['state'] == 'completed')
        self.assertFalse((self.repo / 'new').exists())
        self.assertTrue((self.other / 'new/file.bin').is_file())
        with self.assertRaises(AccessError) as stale_destination:
            writer.submit(**{**args, 'request_key': 'new-grant'})
        self.assertEqual(stale_destination.exception.code, 'target_version_changed')
        self.assertEqual(writer.submit(**self.save_args(writer, key='new-grant'))['state'], 'queued')

    def test_revocation_during_private_spool_verification_prevents_mkdir_and_publication(self):
        writer = self.writer()
        args = self.save_args(writer)
        job = writer.submit(**args)['job_id']
        waiting, advance = threading.Event(), threading.Event()
        verified = writer._verify_spool

        def intercept(row):
            result = verified(row)
            if row['state'] == 'ready_to_publish':
                waiting.set()
                if not advance.wait(5):
                    raise TimeoutError()
            return result

        with patch.object(writer, '_verify_spool', side_effect=intercept):
            writer.start()
            try:
                self.assertTrue(waiting.wait(5))
                self.revoke()
                self.apply(self.document)
            finally:
                advance.set()
            self.wait_for(lambda: writer._get(job)['state'] == 'authorization_blocked')
            self.wait_for(lambda: writer._get(job).get('cleanup', {}).get('private_state') == 'completed')
        self.assertFalse((self.repo / 'new').exists())
        self.assertFalse(writer._get(job)['published'])

    def test_committed_original_remains_when_withdrawal_waits_for_publication(self):
        publishing, resume, withdrawn = threading.Event(), threading.Event(), threading.Event()
        errors = []

        def wait_before_rename(phase, _job):
            if phase == 'publish_intent':
                publishing.set()
                if not resume.wait(5):
                    raise TimeoutError()

        def revoke():
            try:
                self.revoke()
            except BaseException as error:
                errors.append(error)
            finally:
                withdrawn.set()

        writer = self.writer(fault_hook=wait_before_rename)
        job = writer.submit(**self.save_args(writer))['job_id']
        writer.start()
        self.assertTrue(publishing.wait(5))
        revoker = threading.Thread(target=revoke)
        revoker.start()
        try:
            self.assertFalse(withdrawn.wait(.05))
        finally:
            resume.set()
            revoker.join(5)
        self.assertFalse(revoker.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(withdrawn.is_set())
        self.assertTrue(writer._get(job)['published'])
        self.assertEqual((self.repo / 'new/file.bin').stat().st_size, 32)
        with self.assertRaises(AccessError) as hidden_receipt:
            writer.status(OWNER, job_id=job)
        self.assertEqual(hidden_receipt.exception.code, 'not_found')

    def external_worktree(self):
        external = self.base / 'external-worktree'
        for args in (
            ('init', '-q'),
            ('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
             'commit', '--allow-empty', '-qm', 'root'),
            ('worktree', 'add', '-qb', 'side', str(external)),
        ):
            subprocess.run(['/usr/bin/git', '-C', str(self.repo), *args],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        repo_row = {'id': 'repo', 'name': 'repo', 'root': str(self.repo),
                    'repository_id': RepositoryRegistry.identity(self.repo)}
        self.apply({**self.document, 'projects': [repo_row, self.document['projects'][1]]})
        member = next(row for row in self.catalog.list_worktrees('repo')['worktrees']
                      if row['root'] == str(external))
        return external, member

    def test_external_worktree_late_proof_checks_replaced_configured_root(self):
        external, member = self.external_worktree()
        writer = self.writer()
        with self.registry.read_guard():
            target = writer.targets._target('repo', member['id'], 'proposed/new.bin')
            verify = writer.targets.publication_proof(target)
            verify()
            old = self.base / 'old-configured-root'
            self.repo.rename(old)
            self.repo.mkdir()
            (old / '.git').rename(self.repo / '.git')
            self.assertTrue((external / '.git').is_file())
            self.assertEqual(RepositoryRegistry.identity(external), member['repository_id'])
            with self.assertRaises(AccessError):
                verify()
        self.assertFalse((external / 'proposed').exists())

    def test_revoked_receiver_is_reaped_even_if_first_stop_attempt_is_unconfirmed(self):
        writer = self.writer()
        args = self.save_args(writer)
        args['expected_size_bytes'] = 6 * 1024 * 1024
        args['file']['file_id'] = 'slow'
        job = writer.submit(**args)['job_id']
        actual_stop = ReceiverHandle.stop
        first_failure = threading.Event()

        def stop_once_unconfirmed(receiver, *args, **kwargs):
            if not first_failure.is_set():
                first_failure.set()
                return False
            return actual_stop(receiver, *args, **kwargs)

        def receiver_started():
            row = writer._get(job)
            return row.get('receiver') and (Path(row['attempt_directory']) / 'payload').stat().st_size > 0

        with patch.object(ReceiverHandle, 'stop', autospec=True, side_effect=stop_once_unconfirmed):
            writer.start()
            self.wait_for(receiver_started)
            self.revoke()
            self.assertTrue(first_failure.wait(5))
            self.wait_for(lambda: writer._get(job).get('cleanup', {}).get('private_state') == 'completed')
        self.assertTrue(writer._get(job)['writer_exited'])
        self.assertFalse((self.repo / 'new').exists())

    def test_permit_gate_timeout_retries_receiver_cleanup_without_resuming(self):
        writer = self.writer()
        job = writer.submit(**self.save_args(writer))['job_id']
        reserve = file_jobs.commit_project
        entered, first_stop = threading.Event(), threading.Event()
        actual_stop = ReceiverHandle.stop

        @contextmanager
        def fail_first_worker_reservation(catalog, project_id, token):
            if threading.current_thread().name.startswith('file-coordinator') and not entered.is_set():
                entered.set()
                raise AccessError('Fixture permit gate timed out.', code='restart_required')
            with reserve(catalog, project_id, token):
                yield

        def stop_once_unconfirmed(receiver, *args, **kwargs):
            if not first_stop.is_set():
                first_stop.set()
                return False
            return actual_stop(receiver, *args, **kwargs)

        with patch.object(file_jobs, 'commit_project', fail_first_worker_reservation), patch.object(
                ReceiverHandle, 'stop', autospec=True, side_effect=stop_once_unconfirmed):
            writer.start()
            self.assertTrue(entered.wait(5))
            self.assertTrue(first_stop.wait(5))
            self.wait_for(lambda: writer._get(job).get('cleanup', {}).get('private_state') == 'completed')
        recorded = writer._get(job)
        self.assertTrue(recorded['writer_exited'])
        self.assertTrue(recorded.get('receiver'))
        self.assertEqual(recorded['state'], 'failed')
        self.assertEqual(recorded['error_code'], 'restart_required')
        self.assertFalse((self.repo / 'new').exists())

    def exporter(self, sink=None):
        self.body = b'synthetic original\x00' * 9000
        (self.repo / 'original.zip').write_bytes(self.body)
        self.service = FileExportService(self.catalog, ExportConfig(True, self.spool, min_free_bytes=0),
            chunked_config=ChunkedExportConfig(True, min_free_bytes=0))
        server = create_server(self.catalog, exports=self.service, agent_policy=self.policy)
        inner = server.streamable_http_app(stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        app = AccessMiddleware(ProjectResponseGate(self.service.protocol.wrap(inner), self.policy),
                               protocol_fixture.SyntheticVerifier())

        async def observe(scope, receive, send):
            if scope['type'] != 'http' or sink is None:
                return await app(scope, receive, send)

            async def capture(event):
                if event['type'] == 'http.response.body':
                    sink.append((len(event.get('body', b'')), event.get('more_body')))
                await send(event)

            await app(scope, receive, capture)

        self.http = self.enterContext(TestClient(observe))

    def chunked(self):
        capability = json.loads(self.call('list_projects')['content'][0]['text'])['original_export']
        args = {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip', 'request_key': 'chunked',
                'service_instance_id': capability['service_instance_id'],
                'request_window_id': capability['request_window_id']}
        ready = json.loads(self.call('prepare_chunked_export', args)['content'][0]['text'])
        self.assertEqual(ready['state'], 'ready')
        link = self.call('materialize_chunked_export_part',
                         {'export_id': ready['export_id'], 'part_index': 0})['content'][1]
        return ready, link

    def test_replayed_export_and_delivery_handles_stay_dead_after_readd(self):
        self.exporter()
        whole, whole_link = self.exported()
        chunked, chunk_link = self.chunked()
        self.revoke()
        self.apply(self.document)
        for tool, handle in (
            ('get_file_export_status', whole),
            ('get_chunked_export_status', chunked),
            ('get_chunked_export_plan', chunked),
            ('cancel_chunked_export', chunked),
        ):
            value = self.call(tool, {'export_id': handle['export_id']})
            self.assertTrue(value.get('isError'), value)
            self.assertNotIn('original.zip', json.dumps(value))
        for link in whole_link, chunk_link:
            denied = self.rpc('resources/read', {'uri': link['uri']})
            self.assertNotIn('blob', denied.text)
        self.assertTrue(self.call('export_file', self.arguments).get('isError'))
        self.wait_for(lambda: self.service.diagnostics()['snapshot_reservations'] == 0)

    def test_native_json_rechecks_selected_external_worktree_during_handoff(self):
        external, member = self.external_worktree()
        self.exporter()
        canary = 'stale-worktree-result.bin'
        (external / canary).write_bytes(b'not a public result after physical change')
        prepared = self.service.discovery.find

        def replace_after_preparation(*args, **kwargs):
            result = prepared(*args, **kwargs)
            self.assertIn(canary, json.dumps(result))
            older = self.base / 'old-selected-worktree'
            external.rename(older)
            external.mkdir()
            (older / '.git').rename(external / '.git')
            return result

        with patch.object(self.service.discovery, 'find', side_effect=replace_after_preparation):
            response = self.rpc('tools/call', {'name': 'find_files', 'arguments': {
                'project_id': 'repo', 'worktree_id': member['id']}})
        self.assertIn('error', response.json())
        self.assertNotIn(canary, response.text)

    def test_whole_resource_withdrawal_between_actual_body_frames(self):
        sink = []
        self.exporter(sink)
        _, link = self.exported()
        self.assert_partial_delivery_fenced(link, sink)

    def test_chunk_resource_withdrawal_between_actual_body_frames(self):
        sink = []
        self.exporter(sink)
        _, link = self.chunked()
        self.assert_partial_delivery_fenced(link, sink)

    def assert_partial_delivery_fenced(self, link, sink):
        sink.clear()
        armed, advance = threading.Event(), threading.Event()
        reservation = file_export_tools.async_commit_project
        attempts = 0

        @asynccontextmanager
        async def pause_before_second_body(catalog, project_id, token):
            nonlocal attempts
            attempts += 1
            if attempts == 3:  # Real header, first body frame, second body frame.
                armed.set()
                if not await asyncio.to_thread(advance.wait, 5):
                    raise TimeoutError()
            async with reservation(catalog, project_id, token):
                yield

        def read_resource():
            try:
                self.rpc('resources/read', {'uri': link['uri']})
            except AssertionError as error:
                # TestClient has no terminal body to return when the server
                # stops a response after sending its first data frame.
                if 'did not receive any response' not in str(error):
                    failure.append(error)
            except BaseException as error:
                failure.append(error)

        failure = []
        with patch.object(file_export_tools, 'async_commit_project', pause_before_second_body):
            reader = threading.Thread(target=read_resource)
            reader.start()
            try:
                self.assertTrue(armed.wait(5))
                self.assertEqual(sink, [(CHUNK, True)])
                self.revoke()
            finally:
                advance.set()
                reader.join(5)
        self.assertFalse(reader.is_alive())
        self.assertEqual(failure, [])
        self.assertEqual(sink, [(CHUNK, True)])
        self.wait_released()
