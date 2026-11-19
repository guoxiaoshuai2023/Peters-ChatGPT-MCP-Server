"""Strict source proofs for records above the former 8 MiB parsing limit."""

import hashlib
import json
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from tests import test_history_inheritance as inherited


MIB = 1024 * 1024


class HistoryRecordCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = inherited.InheritanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.history.close)

    def large_record(self, kind, payload, padding_bytes=9 * MIB):
        raw = (json.dumps(inherited.record(kind, {**payload, 'padding': 'x' * padding_bytes}))
               + '\n').encode()
        self.assertGreater(len(raw), 8 * MIB)
        return raw

    def append(self, path, raw):
        with path.open('ab') as stream:
            stream.write(raw)

    def rejected(self, raw, reason):
        path = self.fixture.thread()
        self.append(path, raw)
        with self.assertRaises(AccessError) as failure:
            self.fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(failure.exception.code, 'unverifiable_source')
        self.assertEqual(failure.exception.association_reason, reason)
        self.assertFalse(self.fixture.history._snapshots)

    def test_response_item_between_eight_and_twelve_mib_has_full_source_proof(self):
        path = self.fixture.thread(contexts=[self.fixture.repo, self.fixture.repo])
        raw = self.large_record('response_item', {'type': 'function_call_output', 'output': 'omitted'})
        self.assertLess(len(raw), 12 * MIB)
        self.append(path, raw)
        page = self.fixture.history.read_codex_thread(
            inherited.FIRST, view='latest_turn', limit=2, max_chars=3000, include_tool_refs=False)
        self.assertEqual(page['selected_turn_id'], 't-0')
        self.assertEqual([entry['text'] for entry in page['entries']],
                         ['first public request', 'public final answer'])
        self.assertEqual(page['snapshot']['bytes'], path.stat().st_size)
        self.assertEqual(page['snapshot']['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(page['thread']['association']['source'], 'repository_inheritance')
        self.assertFalse(page['tool_refs_included'])

    def test_foreign_context_between_eight_and_twelve_mib_is_still_rejected(self):
        self.rejected(self.large_record('turn_context', {'cwd': str(self.fixture.foreign)}),
                      'recorded_context_missing_foreign_or_cross_project')

    def test_missing_context_between_eight_and_twelve_mib_is_still_rejected(self):
        self.rejected(self.large_record('turn_context', {}), 'missing_recorded_working_directory')

    def test_unknown_record_between_eight_and_twelve_mib_is_still_rejected(self):
        self.rejected(self.large_record('future_private_record', {}),
                      'unknown_record_type_cannot_prove_association')

    def test_malformed_record_between_eight_and_twelve_mib_is_still_rejected(self):
        raw = self.large_record('response_item', {'type': 'function_call_output'})
        self.rejected(raw[:-1] + b'invalid-json\n', 'malformed_record_cannot_prove_association')

    def test_large_known_record_envelope_preserves_inheritance(self):
        raw = self.large_record('response_item', {'type': 'function_call_output'}, 12 * MIB)
        self.assertGreater(len(raw), 12 * MIB)
        path = self.fixture.thread()
        self.append(path, raw)
        page = self.fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(page['thread']['association']['source'], 'repository_inheritance')
        self.assertEqual(page['warnings']['oversized_record_excluded'], 1)
        self.assertFalse(page['complete_public_projection'])

    def test_record_beyond_envelope_budget_is_still_rejected(self):
        with patch('peters_mcp.history_scan.PROOF_RECORD_BYTES', 13 * MIB):
            self.rejected(self.large_record('response_item', {}, 14 * MIB),
                          'oversized_record_cannot_prove_association')

    def test_large_foreign_context_after_padding_is_not_skipped(self):
        raw = json.dumps(inherited.record('turn_context', {
            'padding': 'x' * (13 * MIB), 'cwd': str(self.fixture.foreign)})).encode() + b'\n'
        self.rejected(raw, 'recorded_context_missing_foreign_or_cross_project')

    def test_large_unknown_record_remains_unverifiable(self):
        self.rejected(self.large_record('future_unknown', {}, 13 * MIB),
                      'unknown_record_type_cannot_prove_association')

    def test_large_malformed_ignored_content_remains_unverifiable(self):
        raw = self.large_record('response_item', {}, 13 * MIB)
        self.rejected(raw[:-2] + b',"invalid": [1,]}\n',
                      'malformed_record_cannot_prove_association')

    def test_large_context_keeps_turn_boundary(self):
        path = self.fixture.thread()
        self.append(path, self.large_record('turn_context', {
            'cwd': str(self.fixture.repo), 'turn_id': 'large-turn'}, 13 * MIB))
        self.append(path, inherited.encoded([inherited.message('after large context')]).encode())
        page = self.fixture.history.read_codex_thread(inherited.FIRST, view='latest_turn')
        self.assertEqual(page['selected_turn_id'], 'large-turn')
        self.assertEqual([e['text'] for e in page['entries']], ['after large context'])

    def test_large_undeclared_ancestor_still_fails_identity(self):
        path = self.fixture.thread()
        self.append(path, self.large_record('session_meta', {
            'id': inherited.SECOND, 'cwd': str(self.fixture.repo)}, 13 * MIB))
        with self.assertRaises(AccessError):
            self.fixture.history.read_codex_thread(inherited.FIRST)

    def test_duplicate_type_keys_cannot_hide_foreign_context(self):
        raw = (b'{"type":"response_item","payload":{"padding":"' + b'x' * (13 * MIB)
               + b'","cwd":' + json.dumps(str(self.fixture.foreign)).encode()
               + b'},"type":"turn_context"}\n')
        self.rejected(raw, 'recorded_context_missing_foreign_or_cross_project')

    def test_large_undeclared_session_header_cannot_bypass_fork_identity(self):
        path = self.fixture.thread()
        self.append(path, self.large_record('session_meta', {
            'id': inherited.SECOND, 'cwd': str(self.fixture.repo)}))
        with self.assertRaises(AccessError):
            self.fixture.history.read_codex_thread(inherited.FIRST)
        self.assertFalse(self.fixture.history._snapshots)

    def test_deep_json_still_fails_with_resource_exhausted(self):
        path = self.fixture.thread()
        self.append(path, b'[' * 10000 + b'0' + b']' * 10000 + b'\n')
        with self.assertRaises(AccessError) as failure:
            self.fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(failure.exception.code, 'resource_exhausted')
        self.assertFalse(self.fixture.history._snapshots)


if __name__ == '__main__':
    unittest.main()
