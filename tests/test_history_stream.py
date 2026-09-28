"""Regression cases for streaming proof, cached pages and final delivery checks."""

import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from tests import test_history as explicit
from tests import test_history_inheritance as inherited


class HistoryStreamTests(unittest.TestCase):
    def test_mutation_between_scan_slices_discards_partial_proof(self):
        fixture = self.fixture(explicit.HistoryTests)
        payload = explicit.encode([explicit.record('response_item', {
            'type':'function_call_output','output':'x'*(1024*1024)})])
        with fixture.path.open('ab') as stream:
            for _ in range(17):
                stream.write(payload)
        iterator = fixture.history.operation_iter('read_codex_thread', {'thread_id':explicit.FIRST})
        self.addCleanup(iterator.close)
        self.assertEqual(next(iterator), {'phase':'scanning'})
        with fixture.path.open('r+b') as stream:
            prefix = stream.read(512)
            self.assertIn(b'test', prefix)
            stream.seek(0)
            stream.write(prefix.replace(b'test', b'TEST', 1))
        with self.assertRaises(AccessError) as failure:
            fixture.history._drain(iterator)
        self.assertEqual(failure.exception.code,'waiting_source_stable')
        self.assertFalse(fixture.history._snapshots)

    def fixture(self, kind=inherited.InheritanceTests):
        fixture = kind()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addCleanup(fixture.history.close)
        return fixture

    def pending_delivery(self, fixture, thread_id):
        result = fixture.history.read_codex_thread(thread_id)
        iterator = fixture.history.revalidate_result_iter('read_codex_thread', {}, result)
        self.addCleanup(iterator.close)
        self.assertEqual(next(iterator), {'phase': 'authorization_check'})
        return iterator

    def test_final_delivery_rejects_foreign_append_after_last_yield(self):
        fixture = self.fixture()
        path = fixture.thread()
        iterator = self.pending_delivery(fixture, inherited.FIRST)
        with path.open('a') as stream:
            stream.write(inherited.encoded([inherited.record('turn_context', {
                'cwd': str(fixture.foreign), 'turn_id': 'foreign-turn'})]))
        with self.assertRaises(AccessError) as failure:
            next(iterator)
        self.assertEqual(failure.exception.code, 'waiting_source_stable')

    def test_final_delivery_rejects_same_inode_same_size_rewrite(self):
        fixture = self.fixture()
        path = fixture.thread()
        iterator = self.pending_delivery(fixture, inherited.FIRST)
        before = path.stat()
        raw = path.read_bytes()
        changed = raw.replace(b'first public request', b'other public request')
        self.assertNotEqual(raw, changed)
        self.assertEqual(len(raw), len(changed))
        path.write_bytes(changed)
        self.assertEqual(path.stat().st_ino, before.st_ino)
        with self.assertRaises(AccessError) as failure:
            next(iterator)
        self.assertEqual(failure.exception.code, 'waiting_source_stable')

    def test_final_delivery_rejects_identical_content_replacement(self):
        fixture = self.fixture()
        path = fixture.thread()
        iterator = self.pending_delivery(fixture, inherited.FIRST)
        before = path.stat()
        replacement = path.with_suffix('.replacement')
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
        self.assertNotEqual(path.stat().st_ino, before.st_ino)
        with self.assertRaises(AccessError) as failure:
            next(iterator)
        self.assertEqual(failure.exception.code, 'waiting_source_stable')

    def test_authorized_worktree_append_preserves_original_next_page(self):
        fixture = self.fixture()
        path = fixture.thread()
        first = fixture.history.read_codex_thread(inherited.FIRST, limit=1)
        with path.open('a') as stream:
            stream.write(inherited.encoded([
                inherited.record('turn_context', {'cwd': str(fixture.worktree), 'turn_id': 'new-turn'}),
                inherited.message('newly appended public request'),
            ]))
        second = fixture.history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(second['snapshot'], first['snapshot'])
        self.assertEqual([row['text'] for row in second['entries']], ['public final answer'])
        self.assertFalse(second['has_more'])
        self.assertTrue(second['appended_since_snapshot'])
        current = fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(current['entries'][-1]['text'], 'newly appended public request')

    def test_unverified_candidates_disclose_no_reason_count_title_or_identifier(self):
        fixture = self.fixture()
        fixture.thread(extra=[inherited.record('future_private_record', {'private': 'UNAUTHORIZED_BODY'})])
        fixture.thread(inherited.SECOND, extra=[inherited.record('different_unknown_record', {})])
        result = fixture.history.find_codex_threads(query='not-matching', project_id='repo')
        self.assertEqual(result['threads'], [])
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['warnings'], [{'reason': 'coverage_unverified'}])
        serialized = json.dumps(result, ensure_ascii=False)
        for private in (inherited.FIRST, inherited.SECOND, '同名任务', 'UNAUTHORIZED_BODY',
                        'unknown_record_type', str(fixture.repo)):
            self.assertNotIn(private, serialized)

    def test_unique_metadata_query_recovers_from_candidate_limit(self):
        fixture = self.fixture()
        fixture.thread()
        fixture.thread(inherited.SECOND)
        fixture.thread(inherited.THIRD)
        with sqlite3.connect(fixture.db) as connection:
            connection.execute('UPDATE threads SET title=? WHERE id=?', ('unique-review-target', inherited.THIRD))
        with patch('peters_mcp.history.MAX_CANDIDATES', 2):
            with self.assertRaises(AccessError) as failure:
                fixture.history.find_codex_threads(project_id='repo')
            self.assertEqual(failure.exception.code, 'narrow_query_required')
            result = fixture.history.find_codex_threads(query='unique-review-target', project_id='repo')
        self.assertEqual([row['thread_id'] for row in result['threads']], [inherited.THIRD])
        self.assertTrue(result['scan_complete'])
        self.assertFalse(result['coverage_complete'])
        self.assertIn('candidate_budget_metadata_only_search', [row['reason'] for row in result['warnings']])
        self.assertEqual(result['threads'][0]['match']['in'], 'metadata')

    def test_latest_declared_empty_turn_does_not_return_previous_turn(self):
        fixture = self.fixture(explicit.HistoryTests)
        with fixture.path.open('ab') as stream:
            stream.write(explicit.encode([explicit.record('event_msg', {'type': 'task_started', 'turn_id': 'empty-turn'})]))
        result = fixture.history.read_codex_thread(explicit.FIRST, view='latest_turn')
        self.assertEqual(result['selected_turn_id'], 'empty-turn')
        self.assertEqual(result['entries'], [])
        self.assertFalse(result['has_more'])
        self.assertEqual(result['last_recorded_status'], 'recorded_in_progress')
        self.assertIsNone(result['is_running'])

    def test_explicit_cached_fork_is_denied_when_parent_is_revoked(self):
        fixture = self.fixture()
        path = fixture.thread(inherited.SECOND)
        path.write_text(inherited.encoded([
            inherited.record('session_meta', {'id': inherited.SECOND, 'cwd': str(fixture.repo),
                                              'forked_from_id': inherited.FIRST}),
            inherited.record('session_meta', {'id': inherited.FIRST, 'cwd': str(fixture.repo)}),
            inherited.message('copied parent message'), inherited.message('child message'),
        ]))
        fixture.settings['threads'] = [{'id': inherited.SECOND, 'project_id': 'repo', 'allow_tool_results': False}]
        fixture.save()
        page = fixture.history.read_codex_thread(inherited.SECOND, limit=1)
        self.assertEqual(page['entries'][0]['text'], 'copied parent message')
        fixture.settings['denied_threads'] = [inherited.FIRST]
        fixture.save()
        for arguments in ({}, {'limit': 1, 'cursor': page['next_cursor']}):
            with self.subTest(arguments=arguments):
                with self.assertRaises(AccessError):
                    fixture.history.read_codex_thread(inherited.SECOND, **arguments)

    def test_enabling_tool_permission_rebuilds_same_source_reference_cache(self):
        fixture = self.fixture(explicit.HistoryTests)
        initial = fixture.history.read_codex_thread(explicit.FIRST)
        source = fixture.path.read_bytes()
        self.assertFalse(any(row['kind'] == 'tool_reference' for row in initial['entries']))
        fixture.tool_enabled()
        result = fixture.history.read_codex_thread(explicit.FIRST, include_tool_refs=True)
        references = [row for row in result['entries'] if row['kind'] == 'tool_reference']
        self.assertEqual(len(references), 1)
        item = fixture.history.read_codex_thread_item(explicit.FIRST, references[0]['item_id'])
        self.assertIn('PASSED', item['text'])
        self.assertNotIn('TOPSECRET', item['text'])
        self.assertEqual(fixture.path.read_bytes(), source)

    def test_appended_denied_ancestor_cannot_use_explicit_cached_snapshot(self):
        fixture = self.fixture()
        path = fixture.thread(inherited.SECOND)
        path.write_text(inherited.encoded([
            inherited.record('session_meta', {'id': inherited.SECOND, 'cwd': str(fixture.repo),
                                              'forked_from_id': inherited.FIRST}),
            inherited.message('child first'), inherited.message('child second'),
        ]))
        fixture.settings['threads'] = [{'id': inherited.SECOND, 'project_id': 'repo', 'allow_tool_results': False}]
        fixture.settings['denied_threads'] = [inherited.FIRST]
        fixture.save()
        page = fixture.history.read_codex_thread(inherited.SECOND, limit=1)
        with path.open('a') as stream:
            stream.write(inherited.encoded([
                inherited.record('session_meta', {'id': inherited.FIRST, 'cwd': str(fixture.repo)}),
                inherited.message('denied copied ancestor'),
            ]))
        with self.assertRaises(AccessError):
            fixture.history.read_codex_thread(inherited.SECOND, limit=1, cursor=page['next_cursor'])

    def test_incomplete_tail_is_not_unknown_complete_record(self):
        fixture = self.fixture()
        path = fixture.thread()
        baseline = fixture.history.read_codex_thread(inherited.FIRST)
        with path.open('a') as stream:
            stream.write('{"type":"future_private_record","payload":{}')
        partial = fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual([row['text'] for row in partial['entries']], [row['text'] for row in baseline['entries']])
        self.assertEqual(partial['snapshot']['bytes'], baseline['snapshot']['bytes'])
        self.assertIn('incomplete_tail_excluded', partial['warnings'])
        with path.open('a') as stream:
            stream.write('}\n')
        with self.assertRaises(AccessError) as failure:
            fixture.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(failure.exception.code, 'unverifiable_source')


if __name__ == '__main__':
    unittest.main()
