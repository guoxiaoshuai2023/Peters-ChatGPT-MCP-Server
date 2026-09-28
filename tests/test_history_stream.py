"""Regression cases for streaming proof, cached pages and final delivery checks."""

import json
import os
import sqlite3
import unittest
import gc
import weakref
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.history import HistoryAccess
from peters_mcp.history_process import _frame, RESPONSE_BYTES
from tests import test_history as explicit
from tests import test_history_inheritance as inherited


class HistoryStreamTests(unittest.TestCase):
    def test_private_recipe_is_released_with_result_and_rejected_by_other_engine(self):
        class Marker:
            pass

        owner = HistoryAccess()
        other = HistoryAccess()
        self.addCleanup(owner.close)
        self.addCleanup(other.close)
        marker = Marker()
        reference = weakref.ref(marker)
        result = owner._remember({}, {'private_marker': marker}, {})
        del marker
        gc.collect()
        self.assertIsNotNone(reference())
        with self.assertRaises(AccessError) as failure:
            other._drain(other.revalidate_result_iter('read_codex_thread', {}, result))
        self.assertEqual(failure.exception.code, 'restart_required')
        del result
        gc.collect()
        self.assertIsNone(reference())

    def test_reused_prefixes_do_not_hide_later_foreign_context(self):
        fixture = self.fixture()
        path = fixture.thread()
        history = fixture.history
        first = history.read_codex_thread(inherited.FIRST, limit=1)
        with path.open('a') as stream:
            stream.write(inherited.encoded([inherited.message('safe public append')]))
        for _ in range(12):
            old = history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
            latest = history.read_codex_thread(inherited.FIRST)
            self.assertEqual(old['snapshot'], first['snapshot'])
            self.assertEqual(latest['entries'][-1]['text'], 'safe public append')
            self.assertEqual(len(history._snapshots), 2)
        with path.open('a') as stream:
            stream.write(inherited.encoded([inherited.record('turn_context', {
                'cwd': str(fixture.foreign), 'turn_id': 'foreign-turn'})]))
        for arguments in ({'limit': 1, 'cursor': first['next_cursor']}, {}):
            with self.subTest(old_cursor=bool(arguments)):
                with self.assertRaises(AccessError) as failure:
                    history.read_codex_thread(inherited.FIRST, **arguments)
                self.assertEqual(failure.exception.code, 'unverifiable_source')

    def test_delayed_result_survives_later_pages_without_serializing_private_recipe(self):
        fixture = self.fixture(explicit.HistoryTests)
        history = fixture.history
        first = history.read_codex_thread(explicit.FIRST, limit=1)
        # Keep every result alive, as worker tasks do while processing tokens
        # remain valid. A separate 16-recipe FIFO used to invalidate first.
        retained = [history.read_codex_thread(explicit.FIRST, limit=1) for _ in range(24)]
        delivered = history._drain(history.revalidate_result_iter('read_codex_thread', {}, first))
        self.assertIs(delivered, first)
        self.assertEqual(len(retained), 24)
        self.assertEqual(delivered['entries'][0]['text'], '需求：分批读取文档。')
        serialized = _frame(delivered, RESPONSE_BYTES)[4:]
        self.assertEqual(json.loads(serialized), dict(delivered))
        for private in ('_validation_recipe', '_validation_owner', 'rollout_path',
                        str(fixture.home), str(fixture.path), str(fixture.config)):
            self.assertNotIn(private, serialized.decode())
        fixture.grants.clear()
        fixture.save_config()
        with self.assertRaises(AccessError) as failure:
            history._drain(history.revalidate_result_iter('read_codex_thread', {}, first))
        self.assertEqual(failure.exception.code, 'authorization_changed')

    def test_private_result_recipe_does_not_survive_engine_close_or_json_copy(self):
        fixture = self.fixture(explicit.HistoryTests)
        history = fixture.history
        result = history.read_codex_thread(explicit.FIRST, limit=1)
        with self.assertRaises(AccessError) as failure:
            history._drain(history.revalidate_result_iter('read_codex_thread', {}, dict(result)))
        self.assertEqual(failure.exception.code, 'restart_required')
        history.close()
        with self.assertRaises(AccessError) as failure:
            history._drain(history.revalidate_result_iter('read_codex_thread', {}, result))
        self.assertEqual(failure.exception.code, 'restart_required')

    def test_old_and_current_pages_reuse_two_snapshots_after_one_append(self):
        fixture = self.fixture(explicit.HistoryTests)
        history = fixture.history
        first = history.read_codex_thread(explicit.FIRST, limit=1)
        with fixture.path.open('ab') as stream:
            stream.write(explicit.encode([explicit.message('new public append', native_id='append-one')]))
        current_id = None
        for _ in range(12):
            older = history.read_codex_thread(explicit.FIRST, limit=1, cursor=first['next_cursor'])
            current = history.read_codex_thread(explicit.FIRST)
            self.assertEqual(older['snapshot'], first['snapshot'])
            self.assertEqual(older['entries'][0]['text'], '公开进度')
            self.assertTrue(older['appended_since_snapshot'])
            self.assertEqual(current['entries'][-1]['text'], 'new public append')
            current_id = current_id or current['snapshot']['id']
            self.assertEqual(current['snapshot']['id'], current_id)
            self.assertEqual(len(history._snapshots), 2)
        # A genuinely new source version cannot inherit the previous current
        # projection or hide another appended public message.
        with fixture.path.open('ab') as stream:
            stream.write(explicit.encode([explicit.message('second public append', native_id='append-two')]))
        latest = history.read_codex_thread(explicit.FIRST)
        self.assertNotEqual(latest['snapshot']['id'], current_id)
        self.assertEqual(latest['entries'][-1]['text'], 'second public append')
        self.assertEqual(len(history._snapshots), 3)

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
