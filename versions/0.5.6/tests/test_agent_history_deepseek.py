import hashlib
import json
from pathlib import Path
from random import Random
import sys
import tempfile
import unittest
from unittest.mock import patch

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from peters_mcp.agent_history_deepseek import Adapter, decode_directory_id
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError


CREATED = 1712345678900


def header(native_id, cwd='/project/main', **fields):
    return {'type': 'session', 'version': 4, 'id': native_id, 'createdAt': CREATED,
            'isSeeded': False, 'delegationDepth': 0, 'cwd': cwd, **fields}


def event(seq, kind, data, **fields):
    return {'type': kind, 'seq': seq, 'time': CREATED + seq, 'data': data, **fields}


def user(seq, value, source='user', **fields):
    return event(seq, 'user/message', {'id': f'u{seq}', 'role': 'user', 'source': {'kind': source},
                                      'content': [{'type': 'text', 'text': value}]},
                 **{'surfaceOp': 'append', **fields})


def assistant(seq, value, source='model'):
    return event(seq, 'assistant/message', {'turn': 1, 'step': 1,
                                           'message': {'id': f'a{seq}', 'role': 'assistant',
                                                       'source': {'kind': source},
                                                       'content': [
                                                           {'type': 'reasoning', 'text': 'hidden thinking'},
                                                           {'type': 'text', 'text': value},
                                                           {'type': 'tool-call', 'arguments': 'hidden args'},
                                                       ]}, 'stream': [{'text': 'hidden stream'}]},
                 surfaceOp='append')


def records(*items):
    return b''.join(json.dumps(item, ensure_ascii=False, separators=(',', ':')).encode() + b'\n' for item in items)


def frame(*items):
    return zstd.compress(records(*items), options={zstd.CompressionParameter.checksum_flag: 1})


class DeepSeekHistoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve()
        self.adapter = Adapter(SourceRoot(self.root), '0.2.2-rc.3')

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def projection(self, native_id):
        thread = self.adapter.describe(native_id)
        self.assertIsNotNone(thread)
        return self.adapter.snapshot(thread)

    def test_current_frame_log_projects_only_append_user_and_model_text(self):
        native_id = 'report/🧭'
        location = '--project-Sprint~0020One--/report~002F~D83E~DDED/session.v4.jsonl.zstd'
        visible = [event(0, 'turn/start', {'turn': 1}), user(1, '用户问题'),
                   user(2, 'hidden injected prompt', 'working-directory'),
                   event(3, 'assistant/attempt', {'turn': 1, 'step': 1, 'stream': ['hidden attempt']}),
                   assistant(4, '助手回复'), user(5, 'hidden compaction', 'compact-checkpoint',
                                                 surfaceOp={'op': 'replace', 'startSeq': 1, 'endSeq': 1}),
                   event(6, 'session/title', {'title': '公开标题'}),
                   event(7, 'turn/end', {'turn': 1, 'reason': {'kind': 'completed'}})]
        first = frame(header(native_id, '/project/Sprint One'))
        whole = first + frame(*visible)
        path = self.write(location, whole)
        self.assertEqual(decode_directory_id('report~002F~D83E~DDED'), native_id)
        self.assertIsNone(decode_directory_id('report~002F~D83E'))
        self.assertIsNone(decode_directory_id('report~002f'))
        self.assertEqual([item.native_id for item in self.adapter.discover()], [native_id])
        result = self.projection(native_id)
        self.assertEqual([(x.role, x.text, x.position, x.turn_id) for x in result.messages],
                         [('user', '用户问题', 'seq:1', '1'), ('assistant', '助手回复', 'seq:4', '1')])
        self.assertEqual(result.title, '公开标题')
        self.assertEqual(result.contexts, ('/project/Sprint One',))
        self.assertTrue(result.context_complete)
        self.assertEqual(result.revision, hashlib.sha256(records(header(native_id, '/project/Sprint One'), *visible)).hexdigest())
        self.assertEqual(result.prefix, (location, len(whole), hashlib.sha256(whole).hexdigest()))
        self.assertEqual(path.read_bytes(), whole)
        self.assertEqual(tuple(path.parent.iterdir()), (path,))

    def test_project_discovery_and_direct_read_ignore_foreign_session_budgets(self):
        self.write('--project-main--/selected/session.v4.jsonl.zstd',
                   frame(header('selected')) + frame(user(0, 'Allowed user'), assistant(1, 'Allowed reply')))
        for index in range(5):
            self.write(f'--foreign-{index}--/other-{index}/session.v4.jsonl.zstd',
                       frame(header(f'other-{index}', f'/foreign/{index}')))
        with patch('peters_mcp.agent_history_deepseek._MAX_ENTRIES', 2):
            rows = tuple(self.adapter.discover_project(('/project/main',)))
            self.assertEqual([row.native_id for row in rows], ['selected'])
            self.assertEqual([message.text for message in self.adapter.snapshot(rows[0]).messages],
                             ['Allowed user', 'Allowed reply'])
            selected = self.adapter.describe_project('selected')
            self.assertEqual(selected.native_id, 'selected')
            self.assertEqual([message.text for message in self.adapter.snapshot(selected).messages],
                             ['Allowed user', 'Allowed reply'])
        self.assertEqual(self.adapter.warnings, ('association_unverified',))
        self.assertFalse(self.adapter.project_partition_complete)

    def test_torn_frame_keeps_verified_cut_then_append_preserves_identity(self):
        location = '--project-main--/session-1/session.v4.jsonl.zstd'
        committed = frame(header('session-1')) + frame(user(0, 'first'))
        later = frame(assistant(1, 'second'))
        path = self.write(location, committed + later[:-2])
        old = self.projection('session-1')
        self.assertEqual([x.text for x in old.messages], ['first'])
        self.assertIn('incomplete_tail_omitted', old.warnings)
        self.assertEqual(old.prefix, (location, len(committed), hashlib.sha256(committed).hexdigest()))
        with path.open('ab') as writer:
            writer.write(later[-2:])
        current = self.projection('session-1')
        self.assertEqual([x.text for x in current.messages], ['first', 'second'])
        self.assertEqual(current.identity, old.identity)
        self.assertNotEqual(current.revision, old.revision)
        self.assertNotIn('incomplete_tail_omitted', current.warnings)

    def test_corrupt_complete_frame_refuses_history(self):
        data = frame(header('damaged')) + frame(user(0, 'bad frame'))
        self.write('--project-main--/damaged/session.v4.jsonl.zstd', data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaises(AccessError) as raised:
            self.projection('damaged')
        self.assertEqual(raised.exception.code, 'unsupported_format')

    def test_large_multi_block_frame_retains_the_exact_physical_cut(self):
        location = '--project-main--/large/session.v4.jsonl.zstd'
        hidden = Random(1).randbytes(600_000).hex()
        body = frame(event(0, 'request/context', {'content': hidden}), user(1, 'shown'))
        self.assertGreater(len(body), 256 * 1024)
        committed = frame(header('large')) + body
        self.write(location, committed + frame(assistant(2, 'incomplete'))[:-7])
        result = self.projection('large')
        self.assertEqual([message.text for message in result.messages], ['shown'])
        self.assertEqual(result.prefix, (location, len(committed), hashlib.sha256(committed).hexdigest()))

    def test_cross_session_reference_retains_context_but_omits_injected_text(self):
        self.write('--outside-workspace--/referenced/session.v4.jsonl', records(header('referenced', '/outside/workspace'),
                                                                               user(0, 'the other session')))
        injected = user(0, 'hidden recalled workspace material')
        injected['data']['source'] = {'kind': 'session-reference', 'references': [{'sessionId': 'referenced'}]}
        self.write('--project-main--/original/session.v4.jsonl', records(header('original'), injected,
                                                                         user(1, 'the current session')))
        result = self.projection('original')
        self.assertEqual(result.contexts, ('/project/main', '/outside/workspace'))
        self.assertEqual(result.ancestors, ('referenced',))
        self.assertTrue(result.context_complete)
        self.assertEqual([message.text for message in result.messages], ['the current session'])

    def test_legacy_generation_and_malformed_visible_role_refuse_history(self):
        self.write('--project-main--/v3/session.v3.jsonl', records(header('v3', version=3)))
        malformed = assistant(0, 'role canary')
        malformed['data']['message']['role'] = 'system'
        self.write('--project-main--/bad-role/session.v4.jsonl', records(header('bad-role'), malformed))
        for native_id in ('v3', 'bad-role'):
            with self.subTest(native_id=native_id), self.assertRaises(AccessError) as raised:
                self.projection(native_id)
            self.assertEqual(raised.exception.code, 'unsupported_format')

    def test_newer_generation_refuses_old_v4_and_preserves_healthy_discovery(self):
        self.write('--project-main--/old/session.v4.jsonl', records(header('old'), user(0, 'old body')))
        self.write('--project-main--/old/session.v5.jsonl', records(header('old', version=5)))
        self.write('--project-main--/ok/session.v4.jsonl', records(header('ok'), user(0, 'ok')))
        self.assertEqual([x.native_id for x in self.adapter.discover()], ['ok'])
        self.assertEqual(self.adapter.warnings, ('unsupported_format',))
        with self.assertRaises(AccessError) as raised:
            self.adapter.describe('old')
        self.assertEqual(raised.exception.code, 'unsupported_format')

    def test_fork_reports_own_parent_and_recorded_workspaces(self):
        inherited = [user(0, 'parent says something'), event(1, 'working-directory/change', {'cwd': '/parent/fork'})]
        self.write('--parent-main--/parent/session.v4.jsonl', records(
            header('parent', '/parent/main', createdAt=CREATED - 1000), *inherited, assistant(2, 'after the fork')))
        self.write('--project-main--/child/session.v4.jsonl', records(
            header('child', parentSession='parent', isSeeded=True), *inherited,
            event(2, 'session/end-seed', {'inherited': True}), user(3, 'child opens a turn')))
        result = self.projection('child')
        self.assertEqual(result.contexts, ('/project/main', '/parent/fork', '/parent/main'))
        self.assertEqual(result.ancestors, ('parent',))
        self.assertEqual(result.origin_ns, (CREATED - 1000) * 1_000_000)
        self.assertTrue(result.context_complete)
        self.assertEqual([x.text for x in result.messages], ['parent says something', 'child opens a turn'])

    def test_unproven_fork_or_unknown_ignorable_record_blocks_inheritance(self):
        self.write('--project-main--/parent/session.v4.jsonl', records(header('parent'), user(0, 'original')))
        self.write('--project-main--/child/session.v4.jsonl', records(
            header('child', parentSession='parent', isSeeded=True), user(0, 'different copied record'),
            event(1, 'session/end-seed', {'inherited': True}),
            event(2, 'plugin:future/event', {'text': 'hidden plugin activity'}, ignorable=True),
            user(3, 'one here')))
        result = self.projection('child')
        self.assertFalse(result.context_complete)
        self.assertEqual(set(result.warnings), {'parent_unverified', 'unknown_event_skipped'})
        self.assertEqual(result.ancestors, ('parent',))
        self.assertNotIn('hidden plugin activity', [x.text for x in result.messages])

    def test_source_identity_and_policy_uncertainty_fail_closed(self):
        self.write('--project-main--/nickname/session.v4.jsonl', records(header('actual'), user(0, 'other')))
        self.write('--project-main--/needs-new-reader/session.v4.jsonl', records(
            header('needs-new-reader'), event(0, 'future/context', {'cwd': '/somewhere'})))
        self.write('--project-main--/same/session.v4.jsonl', records(header('same'), user(0, 'first')))
        self.write('--another-main--/same/session.v4.jsonl', records(header('same', '/another/main'), user(0, 'second')))
        for native_id in ('nickname', 'needs-new-reader', 'same'):
            with self.subTest(native_id=native_id), self.assertRaises(AccessError) as raised:
                self.projection(native_id)
            self.assertEqual(raised.exception.code, 'unsupported_format')

    def test_plain_prefix_excludes_unterminated_last_record(self):
        location = '--project-main--/plain/session.v4.jsonl'
        data = records(header('plain'), user(0, 'retained'))
        self.write(location, data + b'{"type":"user/message"')
        result = self.projection('plain')
        self.assertEqual(result.revision, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.prefix, (location, len(data), result.revision))
        self.assertEqual([x.text for x in result.messages], ['retained'])
        self.assertEqual(result.warnings, ('incomplete_tail_omitted',))


if __name__ == '__main__':
    unittest.main()
