import asyncio
import io
import json
import logging
from types import SimpleNamespace
import unittest

from mcp import Client
from mcp.server.mcpserver import MCPServer

from peters_mcp.catalog import AccessError
from peters_mcp.file_context import verified_file_actor
from peters_mcp.file_tools import register_file_tools


ACTOR = 'a' * 64
JOB_ID = 'b' * 32
DIAGNOSTICS = ('selection_changed', 'nonselection_intent_matches', 'completed_bound_hash_matches')
NATIVE_URL = 'https://native.example.test/artifact?sig=SYNTHETIC_SIGNED_SECRET'
NATIVE_ID = 'SYNTHETIC_NATIVE_FILE_ID_SECRET'


class FileReplayToolAuditTests(unittest.TestCase):
    def call_tool(self, service, name='save_generated_file', arguments=None):
        stream = io.StringIO()
        logger = logging.Logger('test.file.replay.audit')
        logger.addHandler(logging.StreamHandler(stream))
        server = MCPServer('synthetic replay audit', log_level='CRITICAL')
        register_file_tools(server, service, audit=logger)
        if arguments is None:
            arguments = {'file': {'download_url': NATIVE_URL, 'file_id': NATIVE_ID},
                         'project_id': 'demo', 'worktree_id': 'main', 'path': 'artifact.zip',
                         'target_version': 'version', 'destination_display': 'demo/artifact.zip',
                         'request_key': 'original-key', 'expected_sha256': 'c' * 64,
                         'expected_size_bytes': 8192}

        async def run():
            token = verified_file_actor.set(ACTOR)
            try:
                async with Client(server) as client:
                    return await client.call_tool(name, arguments)
            finally:
                verified_file_actor.reset(token)

        result = asyncio.run(run())
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertNotIn(NATIVE_URL, stream.getvalue())
        self.assertNotIn(NATIVE_ID, stream.getvalue())
        self.assertNotIn('SYNTHETIC_SIGNED_SECRET', stream.getvalue())
        return result, records[0], stream.getvalue()

    def test_completed_receipt_audit_scopes_success_to_original_job(self):
        receipt = {'operation': 'receipt_lookup', 'subject': 'original_job',
                   'match_kind': 'completed_bound_hash', 'job_id': JOB_ID,
                   'original_job_status': {'job_id': JOB_ID, 'state': 'completed', 'published': True,
                                           'saved': True, 'bytes': 8192, 'download_sha256': 'c' * 64,
                                           'path': 'artifact.zip'},
                   'submitted_reference': {'received': False, 'content_verified': False,
                                           'source_policy': 'not_evaluated_no_transfer'},
                   'new_job_created': False}

        def submit(actor, **arguments):
            self.assertEqual(actor, ACTOR)
            self.assertEqual(arguments['file'].file_id, NATIVE_ID)
            return receipt

        result, record, audit_text = self.call_tool(SimpleNamespace(submit=submit))
        self.assertFalse(result.is_error, result.content)
        public = json.loads(result.content[0].text)
        self.assertEqual(public.pop('trace_id'), record['trace_id'])
        self.assertEqual(public, receipt)
        self.assertEqual(record['operation'], 'submit')
        self.assertEqual(record['result_operation'], 'receipt_lookup')
        self.assertEqual(record['subject'], 'original_job')
        self.assertEqual(record['match_kind'], 'completed_bound_hash')
        self.assertEqual(record['job_id'], JOB_ID)
        self.assertEqual(record['original_job_status'],
                         {'job_id': JOB_ID, 'state': 'completed', 'published': True})
        self.assertTrue(all(record[key] is True for key in DIAGNOSTICS))
        self.assertNotIn('state', record)
        self.assertNotIn('published', record)
        self.assertNotIn('artifact.zip', audit_text)
        self.assertNotIn('c' * 64, audit_text)

    def test_conflict_audit_keeps_only_literal_boolean_diagnostics(self):
        diagnostics = {'selection_changed': True, 'nonselection_intent_matches': False,
                       'completed_bound_hash_matches': False, 'download_url': NATIVE_URL,
                       NATIVE_ID: True, 'native_file': {'file_id': NATIVE_ID},
                       'exception': RuntimeError(NATIVE_URL)}

        def submit(actor, **arguments):
            exc = AccessError('Request key is already bound to a different file or target.',
                              code='idempotency_conflict')
            exc.idempotency_diagnostics = diagnostics
            raise exc

        result, record, _ = self.call_tool(SimpleNamespace(submit=submit))
        self.assertTrue(result.is_error)
        public_error = str(result.content)
        self.assertIn('idempotency_conflict', public_error)
        for key in DIAGNOSTICS:
            self.assertIs(record[key], diagnostics[key])
            self.assertNotIn(key, public_error)
        self.assertFalse(record['ok'])
        self.assertEqual(record['error_code'], 'idempotency_conflict')
        self.assertNotIn('download_url', record)
        self.assertNotIn('native_file', record)
        self.assertNotIn('exception', record)
        for secret in (NATIVE_URL, NATIVE_ID, 'SYNTHETIC_SIGNED_SECRET'):
            self.assertNotIn(secret, public_error)

    def test_receipt_audit_does_not_copy_unrecognized_original_status_values(self):
        receipt = {'operation': 'receipt_lookup', 'subject': 'original_job',
                   'match_kind': 'completed_bound_hash', 'job_id': JOB_ID,
                   'original_job_status': {'job_id': JOB_ID, 'state': 'paused_network',
                                           'published': 'unknown', 'bytes': 8192}}
        result, record, audit_text = self.call_tool(
            SimpleNamespace(submit=lambda actor, **arguments: receipt))
        self.assertFalse(result.is_error, result.content)
        self.assertEqual(record['original_job_status'], {'job_id': JOB_ID})
        self.assertNotIn('paused_network', audit_text)
        self.assertNotIn('unknown', audit_text)
        self.assertNotIn('bytes', record['original_job_status'])

    def test_nonboolean_and_unknown_diagnostics_are_not_serialized(self):
        variants = ({'selection_changed': NATIVE_URL, 'nonselection_intent_matches': 1,
                     'completed_bound_hash_matches': {'file_id': NATIVE_ID}, NATIVE_ID: True},
                    [NATIVE_URL, NATIVE_ID], RuntimeError(NATIVE_URL))
        for diagnostics in variants:
            with self.subTest(kind=type(diagnostics).__name__):
                def submit(actor, **arguments):
                    exc = AccessError('Request key is already bound to a different file or target.',
                                      code='idempotency_conflict')
                    exc.idempotency_diagnostics = diagnostics
                    raise exc

                result, record, audit_text = self.call_tool(SimpleNamespace(submit=submit))
                self.assertTrue(result.is_error)
                for key in DIAGNOSTICS:
                    self.assertNotIn(key, record)
                for secret in (NATIVE_URL, NATIVE_ID, 'SYNTHETIC_SIGNED_SECRET'):
                    self.assertNotIn(secret, audit_text)
                    self.assertNotIn(secret, str(result.content))

    def test_strict_retry_and_status_keep_flat_public_response_and_audit(self):
        status = {'job_id': JOB_ID, 'state': 'completed', 'published': True, 'saved': True}
        service = SimpleNamespace(submit=lambda actor, **arguments: status,
                                  status=lambda actor, **arguments: status)
        for name, arguments in (('save_generated_file', None),
                                ('get_file_save_status', {'request_key': 'original-key'})):
            with self.subTest(name=name):
                result, record, _ = self.call_tool(service, name, arguments)
                self.assertFalse(result.is_error, result.content)
                public = json.loads(result.content[0].text)
                self.assertEqual(public.pop('trace_id'), record['trace_id'])
                self.assertEqual(public, status)
                self.assertEqual(record['state'], 'completed')
                self.assertIs(record['published'], True)
                self.assertNotIn('subject', record)
                self.assertNotIn('match_kind', record)
                for key in DIAGNOSTICS:
                    self.assertNotIn(key, record)


if __name__ == '__main__':
    unittest.main()
