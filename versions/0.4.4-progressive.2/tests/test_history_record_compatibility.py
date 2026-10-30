"""Strict source proofs for records above the former 8 MiB parsing limit."""

import hashlib
import json
import unittest

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

    def test_record_above_twelve_mib_is_still_rejected(self):
        raw = self.large_record('response_item', {'type': 'function_call_output'}, 12 * MIB)
        self.assertGreater(len(raw), 12 * MIB)
        self.rejected(raw, 'oversized_record_cannot_prove_association')

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
