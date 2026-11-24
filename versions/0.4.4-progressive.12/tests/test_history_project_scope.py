"""Project-wide inheritance, hot revocation and actual MCP worker routing."""

import asyncio
import json
import sqlite3
import unittest

from mcp.client import Client
from peters_mcp.catalog import AccessError
from peters_mcp.server import create_server
from tests import test_history_inheritance as fixtures

FIRST, SECOND, THIRD = fixtures.FIRST, fixtures.SECOND, fixtures.THIRD


class ProjectHistoryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.InheritanceTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.history.close)
        self.root = self.f.base / '普通项目 with trailing space '
        self.root.mkdir()
        self.f.project_rows = [{'id': 'repo', 'name': 'Directory', 'root': str(self.root)}]
        self.save_projects()
        self.history = self.f.history

    def save_projects(self):
        self.f.projects.write_text(json.dumps({'projects': self.f.project_rows}))

    def thread(self, tid=FIRST, cwd=None, **options):
        return self.f.thread(tid, cwd or self.root, **options)

    def read(self, tid=FIRST, **options):
        return self.history.read_codex_thread(tid, **options)

    def denied(self, tid=FIRST, **options):
        with self.assertRaises(AccessError):
            self.read(tid, **options)

    def test_existing_future_archived_and_subdirectory_threads_need_no_ids(self):
        self.thread()
        first = self.read(limit=1)
        self.assertEqual(first['thread']['association']['source'], 'directory_inheritance')
        child = self.root / '.local' / 'new workspace'
        child.mkdir(parents=True)
        self.thread(SECOND, child, archived=True)
        self.thread(THIRD)
        result = self.history.find_codex_threads(project_id='repo')
        self.assertEqual({r['thread_id'] for r in result['threads']}, {FIRST, SECOND, THIRD})
        self.assertTrue(self.read(SECOND)['thread']['archived'])
        self.assertEqual(self.read(limit=1, cursor=first['next_cursor'])['entries'][0]['text'],
                         'public final answer')
        self.assertEqual(self.f.settings['threads'], [])

    def test_git_directory_grant_does_not_open_external_worktree(self):
        self.f.project_rows[0]['root'] = str(self.f.repo)
        self.save_projects()
        self.thread(cwd=self.f.repo)
        self.thread(SECOND, self.f.worktree)
        self.assertEqual(self.read()['thread']['association']['source'], 'directory_inheritance')
        self.denied(SECOND)
        self.assertEqual([r['thread_id'] for r in self.history.find_codex_threads()['threads']], [FIRST])

    def test_lookalike_paths_and_symlink_aliases_cannot_inherit(self):
        sibling = self.root.with_name(self.root.name + '-outside')
        sibling.mkdir()
        linked = self.root / 'linked'
        linked.symlink_to(self.f.foreign, target_is_directory=True)
        self.thread(cwd=sibling)
        self.thread(SECOND, linked)
        alias = self.f.base / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.thread(THIRD, alias)
        for tid in (FIRST, SECOND, THIRD):
            self.denied(tid)
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_nearest_nested_project_owns_its_threads(self):
        child = self.root / 'child'
        child.mkdir()
        self.f.project_rows.append({'id': 'child', 'name': 'Child', 'root': str(child)})
        self.save_projects()
        self.thread()
        self.thread(SECOND, child)
        self.thread(THIRD, contexts=[self.root, child])
        self.assertEqual(self.read(SECOND)['thread']['project_id'], 'child')
        self.assertEqual([r['thread_id'] for r in self.history.find_codex_threads(project_id='repo')['threads']], [FIRST])
        self.denied(THIRD)

    def test_duplicate_directory_configuration_is_ambiguous(self):
        self.f.project_rows.append({'id': 'duplicate', 'name': 'Duplicate', 'root': str(self.root)})
        self.save_projects()
        self.thread()
        self.denied()
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_index_cannot_hide_foreign_recorded_context(self):
        self.thread(contexts=[self.f.foreign])
        self.denied()
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_cross_project_append_revokes_cached_read_and_search(self):
        path = self.thread()
        self.thread(SECOND)
        first = self.read(limit=1)
        found = self.history.find_codex_threads(limit=1)
        with path.open('a') as stream:
            stream.write(fixtures.encoded([fixtures.record('turn_context', {'cwd': str(self.f.foreign)})]))
        self.denied(limit=1, cursor=first['next_cursor'])
        with self.assertRaises(AccessError):
            self.history.find_codex_threads(limit=1, cursor=found['next_cursor'])

    def test_removing_project_revokes_read_search_and_prepared_delivery(self):
        self.thread()
        self.thread(SECOND)
        first = self.read(limit=1)
        found = self.history.find_codex_threads(limit=1)
        self.f.project_rows = [{'id': 'other', 'name': 'Other', 'root': str(self.f.foreign)}]
        self.save_projects()
        self.denied(limit=1, cursor=first['next_cursor'])
        self.denied()
        with self.assertRaises(AccessError):
            self.history.find_codex_threads(limit=1, cursor=found['next_cursor'])
        with self.assertRaises(AccessError):
            self.history._drain(self.history.revalidate_result_iter('read_codex_thread', {}, first))
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_directory_replacement_invalidates_old_cursor(self):
        self.thread()
        first = self.read(limit=1)
        self.root.rename(self.root.with_name('old-root'))
        self.root.mkdir()
        self.denied(limit=1, cursor=first['next_cursor'])

    def test_directory_replacement_during_delivery_is_rejected(self):
        self.thread()
        first = self.read()
        pending = self.history.revalidate_result_iter('read_codex_thread', {}, first)
        self.assertEqual(next(pending), {'phase': 'authorization_check'})
        self.root.rename(self.root.with_name('old-root'))
        self.root.mkdir()
        with self.assertRaises(AccessError):
            next(pending)

    def test_deny_and_inheritance_disable_override_directory_grants(self):
        self.thread()
        first = self.read(limit=1)
        self.f.settings['denied_threads'] = [FIRST]
        self.f.save()
        self.denied()
        self.denied(limit=1, cursor=first['next_cursor'])
        self.f.settings.update(denied_threads=[], inherit_projects=False)
        self.f.save()
        self.denied()
        self.assertEqual(self.history.find_codex_threads()['threads'], [])

    def test_new_authorized_project_is_discovered_by_running_engine(self):
        self.thread()
        self.read()
        self.thread(SECOND, self.f.foreign)
        self.denied(SECOND)
        self.f.project_rows.append({'id': 'new', 'name': 'New', 'root': str(self.f.foreign)})
        self.save_projects()
        self.assertEqual(self.read(SECOND)['thread']['project_id'], 'new')
        self.assertEqual([r['thread_id'] for r in self.history.find_codex_threads(project_id='new')['threads']], [SECOND])
        self.assertEqual(self.f.settings['threads'], [])

    def test_directory_inheritance_keeps_tool_evidence_separate(self):
        self.thread()
        self.denied(include_tool_refs=True)
        self.assertFalse(self.read()['tool_refs_included'])

    def test_missing_history_is_reported_as_source_failure_not_permission(self):
        path = self.thread()
        path.unlink()
        with self.assertRaises(AccessError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, 'source_unavailable')
        self.assertIn('cannot restore', str(caught.exception))

    def test_actual_mcp_worker_discovers_new_thread_and_revokes_old_cursor(self):
        self.thread()
        server = create_server(self.f.catalog, history=self.history)

        async def run():
            async with Client(server) as client:
                async def complete(tool, arguments):
                    for _ in range(25):
                        response = await client.call_tool(tool, arguments)
                        if response.is_error:
                            return response, None
                        data = json.loads(response.content[0].text)
                        if data['status'] != 'processing':
                            self.assertEqual(data['status'], 'ready')
                            return response, data
                        arguments = {**arguments, 'cursor': data['next_cursor']}
                    self.fail('MCP preparation did not finish')

                _, first = await complete('read_codex_thread', {'thread_id': FIRST, 'limit': 1})
                self.assertEqual(first['thread']['association']['source'], 'directory_inheritance')
                self.thread(SECOND)
                _, found = await complete('find_codex_threads', {'project_id': 'repo'})
                self.assertEqual({r['thread_id'] for r in found['threads']}, {FIRST, SECOND})
                _, future = await complete('read_codex_thread', {'thread_id': SECOND})
                self.assertEqual(future['thread']['association']['source'], 'directory_inheritance')
                self.f.project_rows = [{'id': 'other', 'name': 'Other', 'root': str(self.f.foreign)}]
                self.save_projects()
                revoked, _ = await complete('read_codex_thread', {
                    'thread_id': FIRST, 'limit': 1, 'cursor': first['next_cursor']})
                self.assertTrue(revoked.is_error)
                _, empty = await complete('find_codex_threads', {})
                self.assertEqual(empty['threads'], [])
                self.assertEqual(self.f.settings['threads'], [])

        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
