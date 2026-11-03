"""Repository-inherited conversation permissions using isolated real Git repositories."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.history import HistoryAccess
from peters_mcp.workspaces import RepositoryRegistry, repository_probe
from tests.test_workspaces import device_drift_fstat

FIRST = '11111111-1111-4111-8111-111111111111'
SECOND = '22222222-2222-4222-8222-222222222222'
THIRD = '33333333-3333-4333-8333-333333333333'


def record(kind, payload):
    return {'timestamp': '2026-09-20T00:00:00Z', 'type': kind, 'payload': payload}


def message(text, role='user', phase=None):
    return record('response_item', {'type': 'message', 'role': role, 'phase': phase,
                  'content': [{'type': 'input_text', 'text': text}]})


def encoded(records):
    return ''.join(json.dumps(r) + '\n' for r in records)


class InheritanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        self.foreign = self.base / 'foreign'
        for root in (self.repo, self.foreign):
            root.mkdir()
            self.git(root, 'init', '-b', 'main')
            self.git(root, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-m', 'test')
        self.worktree = self.base / 'external'
        self.git(self.repo, 'worktree', 'add', '-b', 'feature', str(self.worktree))
        self.projects = self.base / 'projects.json'
        self.project_rows = [{'id': 'repo', 'name': 'Repo', 'root': str(self.repo),
                              'repository_id': RepositoryRegistry.identity(self.repo)}]
        self.projects.write_text(json.dumps({'projects': self.project_rows}))
        self.catalog = Catalog.from_config(self.projects)
        self.home = self.base / 'codex'
        (self.home / 'sessions').mkdir(parents=True)
        (self.home / 'archived_sessions').mkdir()
        self.db = self.home / 'state_5.sqlite'
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, title TEXT, updated_at INTEGER, archived INTEGER)')
        self.config = self.base / 'history.json'
        self.settings = {'version': 2, 'codex_home': str(self.home), 'state_db': 'state_5.sqlite',
                         'threads': [], 'inherit_projects': True, 'denied_threads': []}
        self.save()
        self.history = HistoryAccess(self.config, ('repo',), self.catalog)

    @staticmethod
    def git(root, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def save(self):
        self.config.write_text(json.dumps(self.settings))

    def thread(self, tid=FIRST, cwd=None, contexts=None, archived=False, extra=()):
        cwd = str(cwd or self.repo)
        contexts = [cwd] if contexts is None else [str(c) for c in contexts]
        rows = [record('session_meta', {'id': tid, 'cwd': contexts[0] if contexts else None})]
        rows += [record('turn_context', {'cwd': context, 'turn_id': f't-{n}'}) for n, context in enumerate(contexts[1:])]
        rows += [message('first public request'), message('public final answer', 'assistant', 'final_answer'), *extra]
        path = self.home / ('archived_sessions' if archived else 'sessions') / f'rollout-test-{tid}.jsonl'
        path.write_text(encoded(rows))
        with sqlite3.connect(self.db) as db:
            db.execute('INSERT INTO threads VALUES (?,?,?,?,?,?)', (tid, str(path), cwd, '同名任务', 100, int(archived)))
        return path

    def test_dynamic_main_external_hidden_and_new_threads(self):
        self.thread()
        self.thread(SECOND, self.worktree)
        result = self.history.find_codex_threads()
        self.assertEqual({t['thread_id'] for t in result['threads']}, {FIRST, SECOND})
        self.assertEqual(self.history.read_codex_thread(SECOND)['thread']['association']['source'], 'repository_inheritance')
        hidden = self.repo / '.worktree' / 'later'
        self.git(self.repo, 'worktree', 'add', '-b', 'later', str(hidden))
        subdir = hidden / 'tasks'
        subdir.mkdir()
        self.thread(THIRD, subdir)
        result = self.history.find_codex_threads(query='同名任务', project_id='repo')
        self.assertEqual(len(result['threads']), 3)
        self.assertEqual(self.history.read_codex_thread(THIRD)['entries'][0]['text'], 'first public request')
        self.assertEqual(self.settings['threads'], [])

    def test_pages_appends_and_new_thread_do_not_invalidate_target(self):
        path = self.thread()
        first = self.history.read_codex_thread(FIRST, limit=1)
        with path.open('a') as stream:
            stream.write(encoded([message('later public message')]))
        self.thread(SECOND)
        second = self.history.read_codex_thread(FIRST, cursor=first['next_cursor'], limit=1)
        self.assertEqual(second['entries'][0]['text'], 'public final answer')
        self.assertTrue(second['appended_since_snapshot'])
        self.assertFalse(second['has_more'])
        self.assertEqual(len(self.history.read_codex_thread(FIRST)['entries']), 3)

    def test_suffixed_source_inherits_without_authorizing_the_suffix(self):
        original = self.thread()
        path = original.with_name(f'rollout-test-{FIRST}_{SECOND}.jsonl')
        original.rename(path)
        with sqlite3.connect(self.db) as db:
            db.execute('UPDATE threads SET rollout_path=? WHERE id=?', (str(path), FIRST))
        self.thread(SECOND, self.foreign, extra=[message('FOREIGN_SECRET')])
        self.settings['denied_threads'] = [SECOND]
        self.save()
        found = self.history.find_codex_threads(query='同名任务', project_id='repo')
        self.assertEqual([r['thread_id'] for r in found['threads']], [FIRST])
        first = self.history.read_codex_thread(FIRST, limit=1)
        self.assertEqual(first['thread']['association']['source'], 'repository_inheritance')
        self.assertEqual(self.settings['threads'], [])
        second = self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(second['entries'][0]['text'], 'public final answer')
        self.assertEqual(first['snapshot'], second['snapshot'])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(SECOND)
        self.settings['denied_threads'] = [FIRST]
        self.save()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_suffixed_source_cannot_inherit_cross_repository_context(self):
        original = self.thread(contexts=[self.repo, self.foreign], extra=[message('CROSS_SECRET')])
        path = original.with_name(f'rollout-test-{FIRST}_{SECOND}.jsonl')
        original.rename(path)
        with sqlite3.connect(self.db) as db:
            db.execute('UPDATE threads SET rollout_path=? WHERE id=?', (str(path), FIRST))
        result = self.history.find_codex_threads()
        self.assertEqual(result['threads'], [])
        self.assertTrue(any(w['reason'] == 'coverage_unverified' for w in result['warnings']))
        for marker in (FIRST, 'CROSS_SECRET', '同名任务'):
            self.assertNotIn(marker, json.dumps(result, ensure_ascii=False))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_removed_worktree_revokes_read_and_existing_cursor(self):
        self.thread(cwd=self.worktree)
        first = self.history.read_codex_thread(FIRST, limit=1)
        self.git(self.repo, 'worktree', 'remove', str(self.worktree))
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])

    def test_cross_project_missing_metadata_and_unrelated_are_not_exported(self):
        self.thread(contexts=[self.repo, self.foreign], extra=[message('CROSS_SECRET')])
        self.thread(SECOND, self.foreign, extra=[message('FOREIGN_SECRET')])
        self.thread(THIRD, contexts=[])
        result = self.history.find_codex_threads()
        self.assertEqual(result['threads'], [])
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(any(w['reason'] == 'coverage_unverified' for w in result['warnings']))
        for marker in (FIRST, SECOND, THIRD, 'CROSS_SECRET', 'FOREIGN_SECRET', '同名任务'):
            self.assertNotIn(marker, json.dumps(result))
        for tid in (FIRST, SECOND, THIRD):
            with self.assertRaises(AccessError):
                self.history.read_codex_thread(tid)

    def test_archived_and_side_own_cwd_allowed_not_parent_chain(self):
        self.thread(archived=True)
        self.thread(SECOND, self.worktree, extra=[record('event_msg', {'type': 'task_started', 'parent_thread_id': THIRD})])
        self.thread(THIRD, self.foreign, extra=[record('event_msg', {'type': 'task_started', 'parent_thread_id': FIRST})])
        result = self.history.find_codex_threads()
        self.assertEqual({t['thread_id'] for t in result['threads']}, {FIRST, SECOND})
        self.assertTrue(self.history.read_codex_thread(FIRST)['thread']['archived'])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(THIRD)

    def test_explicit_binding_and_deny_override_hot_reload(self):
        path = self.thread(cwd=self.foreign)
        self.settings['threads'] = [{'id': FIRST, 'project_id': 'repo'}]
        self.save()
        first = self.history.read_codex_thread(FIRST, limit=1)
        self.assertEqual(first['thread']['project_association_source'], 'explicit_configuration')
        self.settings['denied_threads'] = [FIRST]
        self.save()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        self.assertTrue(path.exists())

    def test_deny_auto_and_configuration_disablement(self):
        self.thread()
        first = self.history.read_codex_thread(FIRST, limit=1)
        self.settings['denied_threads'] = [FIRST]
        self.save()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        self.settings['denied_threads'] = []
        self.settings['inherit_projects'] = False
        self.save()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])

    def test_cross_context_appended_and_index_changed_revoke_old_cursor(self):
        path = self.thread()
        first = self.history.read_codex_thread(FIRST, limit=1)
        with path.open('a') as stream:
            stream.write(encoded([record('turn_context', {'cwd': str(self.foreign)}), message('FOREIGN_NEW')]))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        self.thread(SECOND)
        second = self.history.read_codex_thread(SECOND, limit=1)
        with sqlite3.connect(self.db) as db:
            db.execute('UPDATE threads SET cwd=? WHERE id=?', (str(self.foreign), SECOND))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(SECOND, limit=1, cursor=second['next_cursor'])

    def test_search_cached_results_recheck_association(self):
        self.thread()
        path = self.thread(SECOND)
        first = self.history.find_codex_threads(limit=1)
        with path.open('a') as stream:
            stream.write(encoded([record('turn_context', {'cwd': str(self.foreign)})]))
        with self.assertRaises(AccessError):
            self.history.find_codex_threads(limit=1, cursor=first['next_cursor'])

    def test_unknown_record_and_incomplete_tail_are_explicit_missing_context_is_denied(self):
        path = self.thread(extra=[record('future_unknown', {'private': 'PRIVATE'})])
        with path.open('ab') as stream:
            stream.write(b'{"type":')
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        # A clean known-format history may have an incomplete append without
        # granting any new record; that omission is reported by the reader.
        path.write_text(encoded([record('session_meta', {'id': FIRST, 'cwd': str(self.repo)}), message('known public')]))
        with path.open('ab') as stream:
            stream.write(b'{"type":')
        page = self.history.read_codex_thread(FIRST)
        self.assertFalse(page['complete_public_projection'])
        self.assertIn('incomplete_tail_excluded', page['warnings'])
        self.assertNotIn('PRIVATE', json.dumps(page))
        path.write_text(encoded([record('session_meta', {'id': FIRST, 'cwd': str(self.repo)}),
                                 record('turn_context', {'turn_id': 'missing'}), message('not proven')]))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_identity_malformed_missing_sources_and_foreign_nested_repository_denied(self):
        path = self.thread()
        path.write_text(encoded([record('session_meta', {'id': SECOND, 'cwd': str(self.repo)}), message('wrong')]))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        path.write_text('{malformed}\n')
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        path.unlink()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        nested = self.repo / 'nested'
        nested.mkdir()
        self.git(nested, 'init')
        self.thread(SECOND, nested)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(SECOND)

    def test_declared_fork_copy_with_same_repo_cwds_inherits_without_parent_queries(self):
        path = self.thread(SECOND, self.worktree)
        rows = [record('session_meta', {'id': SECOND, 'cwd': str(self.worktree), 'forked_from_id': FIRST}),
                record('session_meta', {'id': FIRST, 'cwd': str(self.repo)}), message('copied public request'),
                record('turn_context', {'cwd': str(self.worktree), 'turn_id': 'child-turn'}),
                message('child public reply', 'assistant', 'final_answer')]
        path.write_text(encoded(rows))
        result = self.history.read_codex_thread(SECOND)
        self.assertEqual(result['inherited_context']['stored_ancestor_headers'], 1)
        self.assertFalse(result['inherited_context']['followed_other_threads'])
        self.assertEqual(result['thread']['association']['source'], 'repository_inheritance')
        self.assertEqual([m['text'] for m in result['entries']], ['copied public request', 'child public reply'])
        rows[1]['payload']['cwd'] = str(self.foreign)
        path.write_text(encoded(rows))
        with self.assertRaises(AccessError):self.history.read_codex_thread(SECOND)

    def test_undeclared_copied_metadata_still_denied(self):
        path = self.thread(SECOND)
        with path.open('a') as stream:
            stream.write(encoded([record('session_meta', {'id': FIRST, 'cwd': str(self.repo)})]))
        with self.assertRaises(AccessError):self.history.read_codex_thread(SECOND)

    def test_explicitly_denied_parent_cannot_be_read_through_fork_copy(self):
        path = self.thread(SECOND, self.worktree)
        path.write_text(encoded([
            record('session_meta', {'id': SECOND, 'cwd': str(self.worktree), 'forked_from_id': FIRST}),
            record('session_meta', {'id': FIRST, 'cwd': str(self.repo)}), message('revoked parent text')]))
        self.settings['denied_threads']=[FIRST]
        self.save()
        with self.assertRaises(AccessError):self.history.read_codex_thread(SECOND)
        self.settings['threads']=[{'id':SECOND,'project_id':'repo','allow_tool_results':False}]
        self.save()
        with self.assertRaises(AccessError):self.history.read_codex_thread(SECOND)

    def test_tools_private_messages_and_cross_thread_cursor_remain_closed(self):
        self.thread(extra=[message('PRIVATE_DEVELOPER', 'developer'), message('PRIVATE_REASONING', 'assistant', 'analysis'),
                           message('token=PRIVATE_SECRET'), record('event_msg', {'type': 'item_completed', 'item': {
                               'type': 'CommandExecution', 'command': 'test', 'stdout': 'PRIVATE_TOOL'}})])
        self.thread(SECOND)
        first = self.history.read_codex_thread(FIRST, limit=1)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(SECOND, limit=1, cursor=first['next_cursor'])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, include_tool_refs=True)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread_item(FIRST, 'forged')
        result = json.dumps(self.history.read_codex_thread(FIRST))
        for marker in ('PRIVATE_DEVELOPER', 'PRIVATE_REASONING', 'PRIVATE_TOOL', 'PRIVATE_SECRET'):
            self.assertNotIn(marker, result)

    def test_v1_remains_explicit_and_unpinned_directory_does_not_inherit(self):
        self.thread()
        self.settings = {k: v for k, v in self.settings.items() if k not in ('inherit_projects', 'denied_threads')}
        self.settings['version'] = 1
        self.save()
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        self.settings.update(version=2, inherit_projects=True, denied_threads=[])
        self.save()
        del self.project_rows[0]['repository_id']
        self.projects.write_text(json.dumps({'projects': self.project_rows}))
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_two_authorized_repositories_still_require_unambiguous_single_repo(self):
        self.project_rows.append({'id': 'second', 'name': 'Second', 'root': str(self.foreign),
                                  'repository_id': RepositoryRegistry.identity(self.foreign)})
        self.projects.write_text(json.dumps({'projects': self.project_rows}))
        self.thread(contexts=[self.repo, self.foreign])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_repository_inheritance_survives_runtime_device_drift(self):
        self.thread(cwd=self.worktree)
        with patch('peters_mcp.workspaces.os.fstat', side_effect=device_drift_fstat(os.fstat)), \
             patch('peters_mcp.workspaces.os.stat', side_effect=device_drift_fstat(os.stat)):
            found = self.history.find_codex_threads()
            self.assertEqual([item['thread_id'] for item in found['threads']], [FIRST])
            self.assertEqual(self.history.read_codex_thread(FIRST)['entries'][0]['text'],
                             'first public request')

    def test_mixed_v1_v2_duplicate_repository_does_not_inherit(self):
        self.thread()
        self.project_rows.append({'id': 'duplicate', 'name': 'Duplicate', 'root': str(self.worktree),
                                  'repository_id': repository_probe(self.worktree)['legacy_repository_id']})
        self.projects.write_text(json.dumps({'projects': self.project_rows}))
        self.assertEqual(self.history.find_codex_threads()['threads'], [])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_append_during_projection_is_revalidated_before_return(self):
        path = self.thread()
        original = self.history._snapshot
        def append_then_return(*args, **kwargs):
            projected = original(*args, **kwargs)
            with path.open('a') as stream:
                stream.write(encoded([record('turn_context', {'cwd': str(self.foreign)}),
                                      message('NEW_FOREIGN_BODY')]))
            return projected
        with patch.object(self.history, '_snapshot', side_effect=append_then_return):
            with self.assertRaisesRegex(AccessError, 'association changed'):
                self.history.read_codex_thread(FIRST)

    def test_find_content_search_revalidates_before_return(self):
        path = self.thread()
        original = self.history._snapshot
        def revoke_then_return(*args, **kwargs):
            projected = original(*args, **kwargs)
            self.settings['denied_threads'] = [FIRST]
            self.save()
            return projected
        with patch.object(self.history, '_snapshot', side_effect=revoke_then_return):
            with self.assertRaisesRegex(AccessError, 'authorization'):
                self.history.find_codex_threads('public')
        self.assertTrue(path.exists())

    def test_read_side_effect_free_sql_and_fixed_git_discovery_only(self):
        path = self.thread()
        before = {p: p.read_bytes() for p in (self.db, path, self.config, self.projects)}
        real_run = subprocess.run
        calls = []
        def checked_run(args, **kwargs):
            calls.append(args)
            self.assertEqual(args[0], '/usr/bin/git')
            self.assertTrue('rev-parse' in args or 'worktree' in args)
            if 'worktree' in args:
                self.assertEqual(args[args.index('worktree') + 1], 'list')
            return real_run(args, **kwargs)
        with patch('subprocess.run', side_effect=checked_run):
            self.history.find_codex_threads('public')
            self.history.read_codex_thread(FIRST)
        self.assertTrue(calls)
        self.assertEqual(before, {p: p.read_bytes() for p in before})


if __name__ == '__main__':
    unittest.main()
