import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import uuid

from peters_mcp.agent_history_antigravity import Adapter, INDEX
from peters_mcp.agent_history_antigravity_native import capture
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError


SESSION, TRAJECTORY, PROJECT, INIT, FIRST, SECOND = (str(uuid.UUID(int=i)) for i in range(1, 7))
SECONDS = 1767225600
TIME = '2026-01-01T00:00:00Z'


def varint(number):
    data = bytearray()
    while number >= 128:
        data.append((number & 127) | 128)
        number >>= 7
    data.append(number)
    return bytes(data)


def message(*fields):
    result = bytearray()
    for tag, value in fields:
        if isinstance(value, str):
            value = value.encode()
        if isinstance(value, int):
            result.extend(varint(tag << 3) + varint(value))
        else:
            result.extend(varint((tag << 3) | 2) + varint(len(value)) + value)
    return bytes(result)


def desktop_spec(*extra, surface=3, is_google=0):
    default = message((1, is_google), (3, 1), (5, surface))
    return message((3, message((1, default))), *extra)


class AntigravityNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        root = base / 'profile'
        self.project = base / 'Repo 普通目录'
        scratch = base / 'scratch'
        for directory in (root, self.project, scratch):
            directory.mkdir(mode=0o700)
        self.created = (SECONDS, 0)
        self.log_time = TIME
        if getattr(self, 'live_clock', False):
            self.created = divmod(time.time_ns(), 1_000_000_000)
            self.log_time = datetime.fromtimestamp(self.created[0], timezone.utc).replace(
                microsecond=self.created[1] // 1000).isoformat()
        self.db_path = root / 'conversations' / (SESSION + '.db')
        self.db_path.parent.mkdir()
        self.db = sqlite3.connect(self.db_path)
        self.addCleanup(self.db.close)
        self.db.executescript('''PRAGMA user_version=1;
            CREATE TABLE trajectory_meta(trajectory_id TEXT, cascade_id TEXT, trajectory_type INTEGER, source INTEGER);
            CREATE TABLE trajectory_metadata_blob(id TEXT, data BLOB);
            CREATE TABLE steps(idx INTEGER PRIMARY KEY, step_type INTEGER, status INTEGER,
                has_subtrajectory INTEGER, metadata BLOB, step_payload BLOB, step_format INTEGER);
            CREATE TABLE executor_metadata(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE gen_metadata(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE parent_references(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE battle_mode_infos(idx INTEGER PRIMARY KEY, data BLOB);''')
        self.db.execute('INSERT INTO trajectory_meta VALUES(?,?,4,1)', (TRAJECTORY, SESSION))
        self.db.execute("INSERT INTO trajectory_metadata_blob VALUES('main',?)", (self.header(),))
        self.index = sqlite3.connect(root / INDEX)
        self.addCleanup(self.index.close)
        self.index.executescript('''PRAGMA user_version=3;
            CREATE TABLE conversation_summaries(conversation_id TEXT PRIMARY KEY, title TEXT, last_modified_time TEXT,
                workspace_uris TEXT, parent_conversation_id TEXT, nesting_depth INTEGER, project_id TEXT,
                step_count INTEGER, not_fully_idle INTEGER, killed INTEGER, status TEXT);
            CREATE TABLE conversation_parents(conversation_id TEXT PRIMARY KEY, parent_id TEXT);''')
        self.index.execute("INSERT INTO conversation_summaries VALUES(?,?,?,?, '',0,?,4,0,0,'CASCADE_RUN_STATUS_IDLE')",
                           (SESSION, 'Synthetic two-turn UI thread', self.log_time, json.dumps([self.project.as_uri()]), PROJECT))
        self.index.commit()
        self.transcript = root / 'brain' / SESSION / '.system_generated/logs/transcript.jsonl'
        self.transcript.parent.mkdir(parents=True)
        self.logs = []
        self.executions = (FIRST, SECOND)
        for turn, key in enumerate(self.executions):
            user = '问题 ' + str(turn)
            wrapped = '<USER_REQUEST>\n' + user + '\n</USER_REQUEST>\n<ADDITIONAL_METADATA>host</ADDITIONAL_METADATA>'
            answer = 'Visible Gemini answer ' + str(turn)
            index = 2 * turn
            self.logs.extend((
                dict(step_index=index, type='USER_INPUT', source='USER_EXPLICIT',
                     status='DONE', created_at=self.log_time, content=wrapped),
                dict(step_index=index + 1, type='PLANNER_RESPONSE', source='MODEL',
                     status='DONE', created_at=self.log_time, content=answer)))
            self.write_step(index, key, turn, user)
            self.write_step(index + 1, key, turn, answer)
            self.db.execute('INSERT INTO executor_metadata VALUES(?,?)',
                            (turn, self.executor(key, index + 1)))
            self.db.execute('INSERT INTO gen_metadata VALUES(?,?)',
                            (turn, self.invocation(key, index + 1, wrapped, index)))
        self.db.commit()
        self.write_logs()
        self.reader = Adapter(SourceRoot(root, scratch=scratch), '2.33.0')
        self.thread = self.reader.describe(SESSION)

    def header(self, *, roots=None, extra=()):
        roots = [self.project.as_uri()] if roots is None else roots
        folders = [(1, message((1, uri))) for uri in roots]
        uris = [(7, uri) for uri in roots]
        return message(*folders, (2, message((1, self.created[0]), (2, self.created[1]))),
                       (3, INIT), (6, SESSION), *uris, (18, PROJECT), *extra)

    def write_logs(self):
        self.transcript.write_bytes(b''.join(json.dumps(row, ensure_ascii=False).encode() + b'\n' for row in self.logs))

    def write_step(self, index, key, invocation, body, *, original=TRAJECTORY, config=b'', created=None, spec=None,
                   finished=None, completed=None, transitions=None):
        user = index % 2 == 0
        kind, source, field = (14, 4, 19) if user else (15, 2, 20)
        origin = message((1, original), (2, index), (3, invocation), (4, SESSION))
        seconds, nanos = self.created if created is None else (created, 0)
        start = message((1, seconds), (2, nanos))
        finish = start if finished is None else message((1, finished))
        end = finish if completed is None else message((1, completed))
        if transitions is None:
            transitions = ((3, end),) if user else ((8, start), (3, end))
        lifecycle = message(*[(1, message((1, state), (2, at))) for state, at in transitions])
        phases = () if user else ((6, start), (7, finish), (8, end))
        metadata = message((1, start), (3, source), (12, key), (20, origin), (26, lifecycle), *phases)
        public = (message((2, body), (3, message((1, body))), (12, config),
                          (18, desktop_spec() if spec is None else spec)) if user else
                  message((1, body), (3, 'PRIVATE NATIVE REASONING'), (8, body)))
        payload = message((1, kind), (4, 3), (5, metadata), (field, public))
        self.db.execute('INSERT OR REPLACE INTO steps VALUES(?,?,3,0,?,?,0)', (index, kind, metadata, payload))
        self.db.commit()

    @staticmethod
    def executor(key, last, config=None, override=None, spec=None):
        configs = []
        if config is not None:
            configs.append((10, config))
        if override is not None:
            configs.append((17, override))
        resolution = message((1, desktop_spec() if spec is None else spec), (3, b''))
        return message((1, 4), (2, 1), (3, last), (9, key), (16, resolution), *configs)

    @staticmethod
    def invocation(key, idx, wrapped, prompt_position, *, prompt_source=1):
        prompt = message((2, prompt_source), (3, wrapped), (18, prompt_position))
        chat = message((1, 'PRIVATE NATIVE SYSTEM PROMPT'), (2, prompt))
        return message((1, chat), (2, varint(idx)), (4, key))

    def result(self):
        return self.reader.inspect_native(self.thread)

    def test_committed_two_turns_and_public_user_input_are_bound_to_the_desktop_trajectory(self):
        proof, bound = capture(self.reader, self.thread)
        self.assertEqual((proof.state, proof.reason, proof.steps, proof.executions, proof.invocations),
                         ('workspace_verified', 'desktop_default_agent_trajectory', 4, 2, 2))
        old = self.reader.snapshot(self.thread)
        self.assertEqual([m.text for m in bound.messages],
                         ['问题 0', 'Visible Gemini answer 0', '问题 1', 'Visible Gemini answer 1'])
        self.assertNotIn('ADDITIONAL_METADATA', repr(bound))
        self.assertIn('ADDITIONAL_METADATA', repr(old))
        self.assertTrue(bound.context_complete)
        self.assertEqual(bound.origin_ns, SECONDS * 1_000_000_000)
        self.assertIsNone(bound.prefix)
        self.assertNotEqual(bound.identity, old.identity)
        self.assertNotEqual(bound.revision, old.revision)
        self.assertEqual(proof.revision, bound.revision)
        self.assertNotIn('PRIVATE', repr(bound) + repr(proof))
        self.assertEqual(self.reader.snapshot_for_inheritance(self.thread), bound)

    def test_physical_ownership_must_cover_the_native_terminal_transition(self):
        start = message((1, SECONDS))
        end = message((1, SECONDS + 11))
        self.write_step(3, SECOND, 1, 'Visible Gemini answer 1', finished=SECONDS + 9, completed=SECONDS + 10,
                        transitions=((8, start), (3, end)))
        bound = self.reader.snapshot_for_inheritance(self.thread)
        self.assertEqual(bound.last_ns, (SECONDS + 11) * 1_000_000_000)
        for transitions in ((), ((8, start),), ((8, start), (3, start))):
            with self.subTest(transitions=len(transitions)):
                self.write_step(3, SECOND, 1, 'Visible Gemini answer 1', finished=SECONDS + 9,
                                completed=SECONDS + 10, transitions=transitions)
                self.assertEqual(self.result().state, 'unverified')

    def test_matching_snapshot_changes_with_native_revision_and_replacement(self):
        before, bound = capture(self.reader, self.thread)
        self.db.execute('UPDATE trajectory_metadata_blob SET data=?', (self.header(extra=((15, b'change'),)),))
        self.db.commit()
        changed, current = capture(self.reader, self.thread)
        self.assertNotEqual(before.revision, changed.revision)
        self.assertEqual(bound.identity, current.identity)
        self.db.close()
        replacement = self.db_path.with_suffix('.replacement')
        replacement.write_bytes(self.db_path.read_bytes())
        os.replace(replacement, self.db_path)
        identical, replaced = capture(self.reader, self.thread)
        self.assertEqual(changed.revision, identical.revision)
        self.assertNotEqual(current.identity, replaced.identity)

    def test_unrelated_index_save_during_capture_keeps_target_evidence_valid(self):
        other = str(uuid.UUID(int=97))
        self.index.execute('INSERT INTO conversation_summaries (conversation_id,title) VALUES(?,?)', (other, 'Other'))
        self.index.commit()
        original = self.reader.snapshot

        def rename_unrelated(thread):
            self.index.execute("UPDATE conversation_summaries SET title='Other update' WHERE conversation_id=?", (other,))
            self.index.commit()
            return original(thread)

        with patch.object(self.reader, 'snapshot', side_effect=rename_unrelated):
            self.assertEqual(self.result().state, 'workspace_verified')

    def test_selected_title_change_during_capture_invalidates_old_description(self):
        original = self.reader.snapshot

        def rename_target(thread):
            self.index.execute("UPDATE conversation_summaries SET title='Updated' WHERE conversation_id=?", (SESSION,))
            self.index.commit()
            return original(thread)

        with patch.object(self.reader, 'snapshot', side_effect=rename_target):
            self.assertEqual(self.result().reason, 'native_capture_changed')

    def test_wal_changes_are_seen_and_invalid_origin_remains_rejected(self):
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA wal_autocheckpoint=0')
        self.assertEqual(self.result().state, 'workspace_verified')
        self.write_step(2, SECOND, 1, '问题 1', original=FIRST)
        self.assertTrue(Path(str(self.db_path) + '-wal').exists())
        self.assertEqual(self.result().reason, 'native_step_origin_mismatch')

    def test_local_sources_and_dedicated_schema_only(self):
        self.db.execute('UPDATE trajectory_meta SET source=13')  # A native replay.
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_source_identity_mismatch')
        self.db.execute('UPDATE trajectory_meta SET source=1')
        self.db.execute('ALTER TABLE parent_references RENAME TO prior_references')
        self.db.execute('CREATE VIEW parent_references AS SELECT * FROM prior_references')
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_format_unverified')

    def test_missing_row_fork_and_latest_workspace_only_are_distinguished(self):
        self.db.execute('INSERT INTO parent_references VALUES(0,?)', (b'fork',))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_parent_history_unverified')
        self.db.execute('DELETE FROM parent_references')
        self.db.execute('UPDATE trajectory_metadata_blob SET data=?', (self.header(roots=['file:///different']),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_workspace_conflict')
        self.db.execute('DELETE FROM trajectory_metadata_blob')
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_format_unverified')
        with self.assertRaises(AccessError) as refused:
            self.reader.snapshot_for_inheritance(self.thread)
        self.assertEqual(refused.exception.code, 'association_unverified')

    def test_source_specific_overrides_surface_and_both_agent_requests(self):
        # WorkspacePaths, user_active_workspaces and alternate prompt templates
        # can alter the semantics even when CascadeConfig.dynamic_workspace_uris is absent.
        for spec in (desktop_spec((7, message((1, '/other')))), desktop_spec((6, 1)),
                     desktop_spec((9, b'replacement')), desktop_spec((11, b'override')),
                     desktop_spec((99, b'new profile')), desktop_spec(surface=2), b''):
            with self.subTest(spec=spec):
                self.write_step(0, FIRST, 0, '问题 0', spec=spec)
                self.assertEqual(self.result().state, 'unverified')
        self.write_step(0, FIRST, 0, '问题 0')
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0',
                        (self.executor(FIRST, 1, spec=desktop_spec(is_google=1)),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_desktop_agent_unverified')
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0',
                        (self.executor(FIRST, 1, override=message((1, message((41, b'custom'))))),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_prompt_override_unverified')
        for nested in (message((42, message((11, message((1, '/other')))))),
                       message((57, message((6, '/override-discovery-root')))), message((99, b'new behavior'))):
            with self.subTest(nested=nested):
                self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0',
                                (self.executor(FIRST, 1, override=message((1, nested))),))
                self.db.commit()
                self.assertEqual(self.result().state, 'unverified')

    def test_every_current_workspace_is_forwarded_to_shared_project_authorization(self):
        paths = [self.project, self.project.parent / 'another repo']
        uris = [path.as_uri() for path in paths]
        self.index.execute('UPDATE conversation_summaries SET workspace_uris=?', (json.dumps(uris),))
        self.db.execute('UPDATE trajectory_metadata_blob SET data=?', (self.header(roots=uris),))
        self.index.commit()
        self.db.commit()
        current = self.reader.describe(SESSION)
        result = self.reader.snapshot_for_inheritance(current)
        self.assertEqual(set(result.contexts), {str(path) for path in paths})
        self.assertTrue(result.context_complete)

    def test_real_mcp_tool_requires_component_registration_and_native_definition_but_is_never_projected(self):
        name = b'mcp_probe_read'
        query = self.logs[0]['content']
        self.logs[2].update(type='GENERIC', source='MODEL', content='PRIVATE TOOL OUTPUT')
        self.write_logs()
        self.write_step(3, FIRST, 1, self.logs[3]['content'])
        origin = message((1, TRAJECTORY), (2, 2), (4, SESSION))
        config = message((1, desktop_spec()))
        registered = message((1, message((1, 7), (2, 'probe'), (5, 1))))
        call = message((1, b'call'), (2, name))
        prompt = message((2, 1), (3, query), (18, 0))
        generic = message((2, message((1, 'PRIVATE TOOL OUTPUT'), (7, 'file:///private/tool-result'))))
        self.db.execute('DELETE FROM executor_metadata')

        def fixture(*, component=3, registration=registered, definition=name, body=generic):
            at = message((1, SECONDS))
            lifecycle = message(*[(1, message((1, state), (2, at))) for state in (1, 2, 3)])
            meta = message((1, at), (3, 2), (4, call), (6, at), (7, at), (8, at), (12, FIRST),
                           (20, origin), (26, lifecycle), (38, component))
            step = message((1, 132), (4, 3), (5, meta), (140, body))
            self.db.execute('INSERT OR REPLACE INTO steps VALUES(2,132,3,0,?,?,0)', (meta, step))
            executor = message((1, 4), (2, 2), (3, 3), (9, FIRST), (16, config), (18, registration))
            self.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(0,?)', (executor,))
            chat = message((2, prompt), (8, message((1, definition))))
            self.db.execute('UPDATE gen_metadata SET data=? WHERE idx=0',
                            (message((1, chat), (2, bytes([1, 2])), (4, FIRST)),))
            self.db.execute('UPDATE gen_metadata SET data=? WHERE idx=1',
                            (message((1, b''), (2, bytes([3])), (4, FIRST)),))
            self.db.commit()
        fixture()
        page = self.reader.snapshot_for_inheritance(self.thread)
        self.assertEqual(len(page.messages), 3)
        self.assertNotIn('PRIVATE', repr(page))
        self.assertNotIn('private/tool-result', repr(page))
        for options in ({'component': 1}, {'registration': b''}, {'definition': b'mcp_probe_other'},
                        {'body': message((2, message((6, 'unknown nested result'))))}):
            with self.subTest(missing=tuple(options)):
                fixture(**options)
                self.assertEqual(self.result().state, 'unverified')

    def test_unparseable_workspace_and_cross_project_override_never_disappear(self):
        self.index.execute('UPDATE conversation_summaries SET workspace_uris=?',
                           (json.dumps([self.project.as_uri(), 'vscode-remote://elsewhere/work']),))
        self.index.commit()
        self.assertEqual(self.result().reason, 'native_workspace_invalid')
        self.index.execute('UPDATE conversation_summaries SET workspace_uris=?', (json.dumps([self.project.as_uri()]),))
        self.index.commit()
        change = message((12, 'file:///different'))
        for options in ({'config': change}, {'override': change}):
            with self.subTest(options=tuple(options)):
                self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=1', (self.executor(SECOND, 3, **options),))
                self.db.commit()
                self.assertEqual(self.result().reason, 'native_dynamic_workspace_history_unverified')
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=1', (self.executor(SECOND, 3),))
        self.write_step(2, SECOND, 1, '问题 1', config=change)
        self.assertEqual(self.result().reason, 'native_dynamic_workspace_history_unverified')

    def test_invalid_step_execution_and_invocation_boundaries(self):
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=1', (self.executor(SECOND, 2),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_execution_mismatch')
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=1', (self.executor(SECOND, 3),))
        self.db.execute('UPDATE gen_metadata SET data=? WHERE idx=1',
                        (self.invocation(FIRST, 3, self.logs[2]['content'], 2),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_invocations_mismatch')
        self.write_step(2, FIRST, 1, '问题 1')
        self.assertEqual(self.result().reason, 'native_execution_mismatch')

    def test_native_transcript_gap_busy_tail_and_revision_drift_fail_closed(self):
        last = self.logs.pop(1)
        self.write_logs()
        self.assertIn('missing_steps', self.reader.snapshot(self.thread).warnings)
        self.assertEqual(self.result().reason, 'native_transcript_incomplete')
        self.logs.insert(1, last)
        self.write_logs()
        self.index.execute('UPDATE conversation_summaries SET not_fully_idle=1')
        self.index.commit()
        self.assertEqual(self.result().reason, 'native_snapshot_not_committed')
        self.index.execute('UPDATE conversation_summaries SET not_fully_idle=0')
        self.index.commit()
        old = self.reader.snapshot
        def changing(thread):
            self.logs[1]['content'] = 'replaced during capture'
            self.write_logs()
            return old(thread)
        with patch.object(self.reader, 'snapshot', changing):
            self.assertEqual(self.result().reason, 'native_capture_changed')

    def test_companion_recovers_full_bytes_before_comparing_to_database(self):
        full = [row.copy() for row in self.logs]
        self.transcript.with_name('transcript_full.jsonl').write_bytes(self.transcript.read_bytes())
        self.logs[1].update(content='Visible\n<truncated 15 bytes>\n0', truncated_fields=['content'])
        self.write_logs()
        self.assertEqual(self.result().state, 'workspace_verified')
        self.write_step(1, FIRST, 0, 'Different native answer')
        self.assertEqual(self.result().reason, 'native_visible_message_mismatch')
        self.assertEqual(self.reader.snapshot(self.thread).messages[1].text, full[1]['content'])

    def test_private_or_forged_host_footer_and_wrong_role_cannot_masquerade_as_user(self):
        self.logs[0]['content'] += 'malicious footer'
        self.write_logs()
        self.assertEqual(self.result().reason, 'native_visible_message_mismatch')
        self.db.execute('UPDATE gen_metadata SET data=? WHERE idx=0',
                        (self.invocation(FIRST, 1, self.logs[0]['content'], 0, prompt_source=2),))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_visible_message_mismatch')
        self.logs[0]['source'] = 'MODEL'
        self.write_logs()
        self.assertEqual(self.result().reason, 'native_transcript_incomplete')

    def test_version_shape_budget_and_symlink_fail_closed(self):
        self.assertEqual(Adapter(self.reader.root, '2.32.1').inspect_native(self.thread).reason, 'native_profile_unverified')
        with patch('peters_mcp.agent_history_antigravity_native.MAX_BLOB', 10):
            self.assertEqual(self.result().reason, 'resource_exhausted')
        self.db.execute('UPDATE trajectory_metadata_blob SET data=?', (b'\xff' * 12,))
        self.db.commit()
        self.assertEqual(self.result().reason, 'native_format_unverified')
        self.db.close()
        elsewhere = self.db_path.with_suffix('.elsewhere')
        self.db_path.rename(elsewhere)
        self.db_path.symlink_to(elsewhere)
        self.assertEqual(self.result().reason, 'source_unavailable')
