"""Check discarded native tool proposals against both logs and their execution."""

import json
import unittest
from unittest.mock import patch

from peters_mcp.agent_history_antigravity_native import capture
import test_agent_history_antigravity_native as native


class CommitBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.sample = native.AntigravityNativeTests()
        self.sample.setUp()
        self.addCleanup(self.sample.doCleanups)
        self.db = self.sample.db
        self.at = native.message((1, native.SECONDS))
        self.arguments = {'Path': 'demo', 'StartLine': 1, 'EndLine': 9}
        self.call = native.message((1, 'test-call'), (2, 'read_file'), (3, json.dumps(self.arguments)))
        self.companion = self.sample.transcript.with_name('transcript_full.jsonl')
        self.db.execute('DELETE FROM steps WHERE idx > 0')
        self.db.execute('DELETE FROM executor_metadata')
        self.db.execute('DELETE FROM gen_metadata')
        self.logs = [self.sample.logs[0]]
        self.user = self.logs[0]['content']

        self.proposal = native.message(*[
            (1, native.message((1, key), (2, str(value)))) for key, value in self.arguments.items()
        ])
        self.stream_error = native.message((3, native.message((2, 'stream ended'), (6, 'error'))), (4, 1))
        self.store_step(1, 15, 3, 2, 0, native.message((7, self.call), (12, 18)), (8, 3))
        self.store_step(2, 132, 1, 2, 0, self.proposal, (1,))
        self.store_step(3, 17, 3, 5, 0, self.stream_error, (3,))
        self.store_step(4, 15, 3, 2, 1, self.final_answer(2), (8, 3))
        self.store_generation()
        spec = native.message((1, native.desktop_spec()))
        executor = native.message((1, 4), (2, 1), (3, 4), (9, native.FIRST), (16, spec))
        self.db.execute('INSERT INTO executor_metadata VALUES(0,?)', (executor,))
        self.db.commit()
        self.sample.index.execute('UPDATE conversation_summaries SET step_count=5, not_fully_idle=1')
        self.sample.index.commit()
        self.write_logs()

    @staticmethod
    def final_answer(stop_reason):
        return native.message((1, 'Visible answer'), (8, 'Visible answer'), (12, stop_reason))

    def store_step(self, index, kind, status, source, generation, body, states, *, terminal_time=None):
        completed = self.at if terminal_time is None else terminal_time
        origin = native.message((1, native.TRAJECTORY), (2, index), (3, generation), (4, native.SESSION))
        transitions = native.message(*[
            (1, native.message((1, state), (2, completed if state == 3 else self.at))) for state in states
        ])
        phases = [(6, self.at), (7, self.at)] if kind in (15, 132) else []
        if status == 3:
            phases.append((8, completed))
        tool = [(4, self.call), (38, 1)] if kind == 132 else []
        metadata = native.message((1, self.at), (3, source), (12, native.FIRST),
                                  (20, origin), (26, transitions), *phases, *tool)
        slot = {15: 20, 132: 140, 17: 24}[kind]
        payload = native.message((1, kind), (4, status), (5, metadata), (slot, body))
        self.db.execute('INSERT OR REPLACE INTO steps VALUES(?,?,?,0,?,?,0)',
                        (index, kind, status, metadata, payload))
        if status == 1:
            return
        self.logs = [row for row in self.logs if row['step_index'] != index]
        self.logs.append({
            'step_index': index,
            'type': {15: 'PLANNER_RESPONSE', 17: 'ERROR_MESSAGE'}[kind],
            'source': {2: 'MODEL', 5: 'SYSTEM'}[source],
            'status': 'DONE', 'created_at': native.TIME,
            'content': 'Visible answer' if index == 4 else '',
        })

    def store_generation(self, *, error=True):
        prompt = native.message((2, 1), (3, self.user), (18, 0))
        model = native.message((2, prompt))
        error_field = [(5, 'Test model stream failed')] if error else []
        failed = native.message((1, model), (2, bytes((1, 2, 3))), (4, native.FIRST), *error_field)
        finished = native.message((1, model), (2, bytes((4,))), (4, native.FIRST))
        self.db.executemany('INSERT OR REPLACE INTO gen_metadata VALUES(?,?)', [(0, failed), (1, finished)])
        self.db.commit()

    def write_logs(self):
        rows = sorted(self.logs, key=lambda item: item['step_index'])
        encoded = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
        self.sample.transcript.write_bytes(encoded)
        self.companion.write_bytes(encoded)

    def test_closed_failed_generated_proposal_preserves_only_public_messages_and_warns(self):
        proof, view = capture(self.sample.reader, self.sample.thread)
        self.assertEqual(proof.state, 'workspace_verified')
        self.assertEqual(view.warnings, ('missing_steps',))
        self.assertEqual([(m.role, m.text) for m in view.messages],
                         [('user', '问题 0'), ('assistant', 'Visible answer')])

    def test_an_errorless_generation_or_a_different_requested_call_cannot_close_a_pending_tool(self):
        self.store_generation(error=False)
        self.assertEqual(self.sample.result().state, 'unverified')
        self.store_generation()
        other = native.message((1, 'other-call'), (2, 'read_file'), (3, json.dumps(self.arguments)))
        self.store_step(1, 15, 3, 2, 0, native.message((7, other), (12, 18)), (8, 3))
        self.db.commit()
        self.assertEqual(self.sample.result().state, 'unverified')

    def test_a_missing_public_step_or_disagreeing_companion_never_becomes_a_verified_gap(self):
        self.companion.write_bytes(self.companion.read_bytes().replace(b'Visible answer', b'Different answer'))
        self.assertEqual(self.sample.result().state, 'unverified')
        self.logs = [row for row in self.logs if row['step_index'] != 1]
        self.write_logs()
        self.assertEqual(self.sample.result().state, 'unverified')

    def test_active_running_or_killed_thread_and_uncommitted_executor_stay_unverified(self):
        for key, value in (('status', 'CASCADE_RUN_STATUS_RUNNING'), ('killed', 1)):
            with self.subTest(key=key):
                self.sample.index.execute('UPDATE conversation_summaries SET ' + key + '=?', (value,))
                self.sample.index.commit()
                self.assertEqual(self.sample.result().state, 'unverified')
                self.sample.index.execute("UPDATE conversation_summaries SET status='CASCADE_RUN_STATUS_IDLE',killed=0")
                self.sample.index.commit()
        self.db.execute('DELETE FROM executor_metadata')
        self.db.commit()
        self.assertEqual(self.sample.result().state, 'unverified')

    def test_an_error_finishing_after_the_executor_final_reply_is_not_closed(self):
        later = native.message((1, native.SECONDS + 2))
        self.store_step(3, 17, 3, 5, 0, self.stream_error, (3,), terminal_time=later)
        self.db.commit()
        self.assertEqual(self.sample.result().state, 'unverified')
        self.store_step(3, 17, 3, 5, 0, self.stream_error, (3,))
        self.db.commit()
        self.assertEqual(self.sample.result().state, 'workspace_verified')

    def test_an_issued_or_changed_proposal_and_a_nonterminal_last_reply_are_rejected(self):
        result = native.message((2, native.message((1, 'Tool result'))))
        changes = [
            (2, 132, 1, 2, 0, self.proposal + result, (1,)),
            (2, 132, 1, 2, 0, self.proposal, (1, 2)),
            (4, 15, 3, 2, 1, self.final_answer(18), (8, 3)),
        ]
        for change in changes:
            with self.subTest(index=change[0], states=change[-1]):
                self.store_step(2, 132, 1, 2, 0, self.proposal, (1,))
                self.store_step(*change)
                self.db.commit()
                self.assertEqual(self.sample.result().state, 'unverified')

    def test_both_transcripts_are_reopened_for_the_final_capture_check(self):
        reader = self.sample.reader
        original = reader._snapshot
        runs = []

        def snapshot(thread, manifest):
            if runs:
                self.companion.write_bytes(self.companion.read_bytes().replace(b'Visible answer', b'Changed answer'))
            runs.append(True)
            return original(thread, manifest)

        with patch.object(reader, '_snapshot', side_effect=snapshot):
            self.assertEqual(self.sample.result().state, 'unverified')
        self.assertEqual(len(runs), 2)
