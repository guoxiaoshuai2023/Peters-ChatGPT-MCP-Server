import hashlib
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from peters_mcp.agent_history_antigravity import Adapter, INDEX
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError


FIRST = '10101010-1010-1010-1010-101010101010'
SECOND = '20202020-2020-2020-2020-202020202020'
THIRD = '30303030-3030-3030-3030-303030303030'
TIME = '2026-11-16T03:00:00Z'


def step(index, type_name, source, content, *, status='DONE', **other):
    return dict(step_index=index, type=type_name, source=source, status=status,
                content=content, created_at=TIME, **other)


def write_steps(path, events):
    raw = b''.join(json.dumps(event, ensure_ascii=False).encode() + b'\n' for event in events)
    path.write_bytes(raw)
    return raw


class AntigravityAdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        self.root = base / 'app-data'
        self.root.mkdir()
        self.scratch = base / 'scratch'
        self.scratch.mkdir(mode=0o700)
        self.project = base / 'Example Project'
        self.project.mkdir()
        self.foreign = base / 'other-project'
        self.foreign.mkdir()
        self.db = sqlite3.connect(self.root / INDEX)
        self.addCleanup(self.db.close)
        self.db.executescript('''PRAGMA user_version = 3;
            CREATE TABLE conversation_summaries (
                conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL, preview TEXT,
                last_modified_time datetime NOT NULL, workspace_uris TEXT NOT NULL,
                parent_conversation_id TEXT NOT NULL, nesting_depth INTEGER NOT NULL,
                raw_summary BLOB);
            CREATE TABLE conversation_parents (
                conversation_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL);''')
        self.reader = Adapter(SourceRoot(self.root, scratch=self.scratch), '2.32.1')

    def add_thread(self, identifier, *, parent='', workspaces=None, depth=0):
        self.db.execute('INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (identifier, f'Test dialog {identifier[:2]}', 'INDEX PREVIEW CANARY', TIME,
                         json.dumps([self.project.as_uri()] if workspaces is None else workspaces),
                         parent, depth, b'UNTRUSTED SUMMARY CANARY'))
        if parent:
            self.db.execute('INSERT INTO conversation_parents VALUES (?, ?)', (identifier, parent))
        self.db.commit()

    def transcript(self, identifier):
        path = self.root / 'brain' / identifier / '.system_generated' / 'logs' / 'transcript.jsonl'
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_version_2_33_0_reads_public_messages_from_v3_profile(self):
        self.add_thread(FIRST)
        write_steps(self.transcript(FIRST), [
            step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question'),
            step(1, 'PLANNER_RESPONSE', 'MODEL', 'Visible answer'),
        ])

        reader = Adapter(SourceRoot(self.root, scratch=self.scratch), '2.33.0')
        thread = reader.describe(FIRST)
        self.assertIsNotNone(thread)
        view = reader.snapshot(thread)
        self.assertEqual([(message.role, message.text) for message in view.messages], [
            ('user', 'Question'), ('assistant', 'Visible answer'),
        ])

    def test_unverified_app_versions_remain_unsupported(self):
        root = SourceRoot(self.root, scratch=self.scratch)
        for version in ('2.33.1', '2.34.0'):
            with self.subTest(version=version):
                with self.assertRaises(AccessError) as caught:
                    Adapter(root, version)
                self.assertEqual(caught.exception.code, 'unsupported_format')

    def test_projects_only_committed_public_steps_in_native_order(self):
        self.add_thread(FIRST)
        self.add_thread(SECOND, parent=FIRST, depth=1)
        path = self.transcript(FIRST)
        raw = write_steps(path, [
            step(0, 'USER_INPUT', 'USER_EXPLICIT', '第一轮问题'),
            step(1, 'USER_INPUT', 'SYSTEM_SDK', 'Injected hook canary'),
            step(2, 'USER_INPUT', 'USER_IMPLICIT', 'Implicit context canary'),
            step(3, 'SYSTEM_MESSAGE', 'SYSTEM', 'System canary'),
            step(4, 'PLANNER_RESPONSE', 'MODEL', 'Pending canary', status='RUNNING'),
            step(5, 'RUN_COMMAND', 'MODEL', 'Tool result canary'),
            step(6, 'PLANNER_RESPONSE', 'MODEL', 'Visible first answer',
                 thinking='Reasoning canary', tool_calls=[{'arguments': 'tool canary'}],
                 media=[{'uri': 'opaque://media-canary'}]),
            step(7, 'USER_INPUT', 'USER_EXPLICIT', 'Second turn'),
            step(8, 'PLANNER_RESPONSE', 'MODEL', 'Visible second answer',
                 truncated_fields=['thinking']),
            step(9, 'PLANNER_RESPONSE', 'MODEL', 'Truncated body canary',
                 truncated_fields=['content']),
        ])

        visible, = self.reader.discover()
        self.assertEqual(visible.native_id, FIRST)
        self.assertEqual(visible.surface, 'desktop')
        self.assertEqual(visible.updated_at, '2026-11-16T03:00:00+00:00')
        self.assertIsNone(self.reader.describe(SECOND))
        view = self.reader.snapshot(visible)
        self.assertEqual([(m.role, m.text, m.position) for m in view.messages], [
            ('user', '第一轮问题', 'step:0'), ('assistant', 'Visible first answer', 'step:6'),
            ('user', 'Second turn', 'step:7'), ('assistant', 'Visible second answer', 'step:8'),
        ])
        self.assertEqual(view.revision, hashlib.sha256(raw).hexdigest())
        self.assertEqual(view.prefix, (str(path.relative_to(self.root)), len(raw), view.revision))
        self.assertEqual(set(view.warnings), {'truncated_content_omitted', 'unfinished_messages_omitted'})

    def test_retains_known_ancestor_workspaces_without_claiming_historical_scope(self):
        self.add_thread(FIRST, workspaces=[self.foreign.as_uri()])
        self.add_thread(SECOND, parent=FIRST, workspaces=[
            self.project.as_uri(), 'file://other-host/example', 'file:///one/%2e%2e/two',
            'file:///bad%0Aline', 'vscode-remote://remote/test',
        ])
        self.add_thread(THIRD, parent=SECOND)
        thread = self.reader.describe(THIRD)
        self.assertEqual(thread.contexts, (str(self.project), str(self.foreign)))
        self.assertEqual(thread.ancestors, (SECOND, FIRST))
        self.assertFalse(thread.context_complete)
        self.assertIsNone(self.reader.describe('../../unsafe'))

    def test_companion_recovers_only_matching_visible_text_and_binds_both_files(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        companion = path.with_name('transcript_full.jsonl')
        original = [
            step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question'),
            step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head\n<truncated 6 bytes>\nTail',
                 truncated_fields=['content']),
            step(2, 'GENERIC', 'MODEL', 'Compact tool output'),
        ]
        full = [original[0], step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head中间Tail',
                                  thinking='Internal reasoning canary', tool_calls=[{'secret': 'argument canary'}]),
                step(2, 'GENERIC', 'MODEL', 'Full tool output canary')]
        write_steps(path, original)
        write_steps(companion, full)
        thread = self.reader.describe(FIRST)
        recovered = self.reader.snapshot(thread)
        self.assertEqual([(m.role, m.text, m.position) for m in recovered.messages], [
            ('user', 'Question', 'step:0'), ('assistant', 'Head中间Tail', 'step:1'),
        ])
        self.assertEqual(recovered.warnings, ())
        self.assertIsNone(recovered.prefix)
        full[1]['content'] = 'Head你好Tail'
        write_steps(companion, full)
        changed = self.reader.snapshot(thread)
        self.assertEqual(changed.identity, recovered.identity)
        self.assertNotEqual(changed.revision, recovered.revision)
        companion.unlink()
        compact = self.reader.snapshot(thread)
        self.assertNotEqual(compact.identity, recovered.identity)
        self.assertIsNotNone(compact.prefix)
        self.assertEqual(compact.warnings, ('truncated_content_omitted',))

    def test_invalid_companion_cannot_replace_or_add_visible_messages(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        companion = path.with_name('transcript_full.jsonl')
        question = step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        truncated = step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head\n<truncated 6 bytes>\nTail',
                         truncated_fields=['content'])
        answer = step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head中间Tail')
        write_steps(path, [question, truncated])
        thread = self.reader.describe(FIRST)
        for name, events in {
            'empty': [],
            'step mismatch': [question, {**answer, 'step_index': 2}],
            'timestamp mismatch': [question, {**answer, 'created_at': '2026-11-16T03:00:01Z'}],
            'source mismatch': [question, {**answer, 'source': 'SYSTEM_SDK'}],
            'status mismatch': [question, {**answer, 'status': 'RUNNING'}],
            'suffix mismatch': [question, {**answer, 'content': 'Head中间Other'}],
            'omitted byte count mismatch': [question, {**answer, 'content': 'HeadabcdefgTail'}],
            'already truncated': [question, {**answer, 'truncated_fields': ['content']}],
            'changes intact text': [{**question, 'content': 'Different question'}, answer],
            'extra message': [question, answer, step(2, 'PLANNER_RESPONSE', 'MODEL', 'Unexpected extra')],
        }.items():
            with self.subTest(name=name):
                write_steps(companion, events)
                view = self.reader.snapshot(thread)
                self.assertEqual([message.text for message in view.messages], ['Question'])
                self.assertEqual(view.warnings, ('truncated_content_omitted',))

        companion.unlink()
        outside = self.foreign / companion.name
        write_steps(outside, [question, answer])
        companion.symlink_to(outside)
        view = self.reader.snapshot(thread)
        self.assertEqual([message.text for message in view.messages], ['Question'])
        self.assertEqual(view.warnings, ('truncated_content_omitted',))

    def test_companion_recovers_verified_message_across_shared_gaps_only(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        companion = path.with_name('transcript_full.jsonl')
        question = step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        short = step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head\n<truncated 6 bytes>\nTail',
                     truncated_fields=['content'])
        answer = step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head中间Tail')
        later = step(4, 'USER_INPUT', 'USER_EXPLICIT', 'Another request')
        compact_rows = [question, short, later]
        full_rows = [question, answer, later]
        thread = self.reader.describe(FIRST)
        write_steps(path, compact_rows)
        write_steps(companion, full_rows)
        paired = self.reader.snapshot(thread)
        self.assertEqual([(m.role, m.text, m.position) for m in paired.messages], [
            ('user', 'Question', 'step:0'),
            ('assistant', 'Head中间Tail', 'step:1'),
            ('user', 'Another request', 'step:4'),
        ])
        self.assertEqual(paired.warnings, ('missing_steps',))
        self.assertIsNone(paired.prefix)

        for case in ('different gap', 'extra full step', 'partial compact', 'partial full'):
            with self.subTest(case=case):
                write_steps(path, compact_rows)
                if case == 'different gap':
                    write_steps(companion, [question, answer, {**later, 'step_index': 3}])
                elif case == 'extra full step':
                    hidden = step(2, 'PLANNER_RESPONSE', 'MODEL', 'Full-only step')
                    write_steps(companion, [question, answer, hidden, later])
                else:
                    write_steps(companion, full_rows)
                    incomplete = path if case == 'partial compact' else companion
                    with incomplete.open('ab') as stream:
                        stream.write(b'{"step_index":5')
                fallback = self.reader.snapshot(thread)
                self.assertEqual([m.text for m in fallback.messages], ['Question', 'Another request'])
                self.assertIn('missing_steps', fallback.warnings)
                self.assertIn('truncated_content_omitted', fallback.warnings)
                self.assertIsNotNone(fallback.prefix)

    def test_companion_remains_subject_to_visible_text_budget(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        question = step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        write_steps(path, [question, step(1, 'PLANNER_RESPONSE', 'MODEL',
                                          'Head\n<truncated 6 bytes>\nTail', truncated_fields=['content'])])
        write_steps(path.with_name('transcript_full.jsonl'),
                    [question, step(1, 'PLANNER_RESPONSE', 'MODEL', 'Head中间Tail')])
        with patch('peters_mcp.agent_history_antigravity.MAX_VISIBLE_CHARS', 12):
            view = self.reader.snapshot(self.reader.describe(FIRST))
        self.assertEqual([message.text for message in view.messages], ['Question'])
        self.assertEqual(view.warnings, ('truncated_content_omitted',))

    def test_ancestry_cycle_fails_closed(self):
        self.add_thread(FIRST, parent=SECOND)
        self.add_thread(SECOND, parent=FIRST)
        with self.assertRaises(AccessError) as caught:
            self.reader.describe(FIRST)
        self.assertEqual(caught.exception.code, 'unsupported_format')

    def test_partial_last_record_does_not_enter_the_committed_prefix(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        original = write_steps(path, [step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Ready')])
        first = self.reader.snapshot(self.reader.describe(FIRST))
        with path.open('ab') as stream:
            stream.write(b'{"unfinished":true')
        partial = self.reader.snapshot(self.reader.describe(FIRST))
        self.assertEqual(partial.identity, first.identity)
        self.assertEqual(partial.revision, first.revision)
        self.assertEqual(partial.prefix[1], len(original))
        self.assertEqual(partial.warnings, ('incomplete_tail_omitted',))
        with path.open('ab') as stream:
            stream.write(b'\n')
        with self.assertRaises(AccessError) as caught:
            self.reader.snapshot(self.reader.describe(FIRST))
        self.assertEqual(caught.exception.code, 'unsupported_format')

    def test_unpinned_profile_rejects_unsupported_index_version_and_duplicate_record_fields(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        path.write_bytes(b'{"step_index":0,"type":"USER_INPUT","source":"SYSTEM",'
                         b'"source":"USER_EXPLICIT","status":"DONE","content":"injected"}\n')
        reader = Adapter(SourceRoot(self.root, scratch=self.scratch), None)
        with self.assertRaises(AccessError) as caught:
            reader.snapshot(reader.describe(FIRST))
        self.assertEqual(caught.exception.code, 'unsupported_format')
        self.db.execute('PRAGMA user_version = 4')
        self.db.commit()
        with self.assertRaises(AccessError) as caught:
            reader.discover()
        self.assertEqual(caught.exception.code, 'unsupported_format')

    def test_missing_or_outside_transcript_reports_source_unavailable(self):
        self.add_thread(FIRST)
        path = self.transcript(FIRST)
        with self.assertRaises(AccessError) as caught:
            self.reader.snapshot(self.reader.describe(FIRST))
        self.assertEqual(caught.exception.code, 'source_unavailable')
        foreign = self.foreign / 'transcript.jsonl'
        write_steps(foreign, [step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Outside root')])
        path.symlink_to(foreign)
        with self.assertRaises(AccessError) as caught:
            self.reader.snapshot(self.reader.describe(FIRST))
        self.assertEqual(caught.exception.code, 'source_unavailable')
