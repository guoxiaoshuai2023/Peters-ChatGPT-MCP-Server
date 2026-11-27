"""Synthetic regression and MCP E2E tests for verbatim replayed non-public Antigravity steps (v0.5.6)."""

import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.testclient import TestClient

from peters_mcp import agent_history_antigravity as ag
from peters_mcp.agent_history_antigravity import Adapter
from peters_mcp.agent_history_antigravity_native import capture
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import actor_digest
from peters_mcp.fs_identity import persistent_identity
from tests import test_agent_history_antigravity as synthetic
from tests import test_agent_history_antigravity_native as native


SOURCE_V1 = 'gravity-v1'
SOURCE_V2 = 'gravity-v2'
OWNER = 'synthetic-owner'
TARGET_TITLE = 'Synthetic Design Sprint Thread'
NEIGHBOR_TITLE = 'Synthetic Neighbor Thread'
UNGRANTED_TITLE = 'Synthetic Private Unapproved Thread'
HIDDEN_THINKING = 'PRIVATE REASONING CANARY DO NOT EXPOSE'
HIDDEN_TOOL = 'PRIVATE TOOL PAYLOAD CANARY'


def _encode_rows(rows):
    return b''.join(json.dumps(row, ensure_ascii=False).encode('utf-8') + b'\n' for row in rows)


class AntigravityReplayedStepAdapterTests(unittest.TestCase):
    def setUp(self):
        fixture = synthetic.AntigravityAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.fixture.add_thread(synthetic.FIRST)
        self.fixture.db.execute(
            'UPDATE conversation_summaries SET title = ? WHERE conversation_id = ?',
            (TARGET_TITLE, synthetic.FIRST),
        )
        self.fixture.db.commit()
        self.compact = self.fixture.transcript(synthetic.FIRST)
        self.full = self.compact.with_name('transcript_full.jsonl')
        self.reader = Adapter(SourceRoot(self.fixture.root, scratch=self.fixture.scratch), None)
        self.thread = self.reader.describe(synthetic.FIRST)

    def test_minimal_repro_triad_multiple_replays_gaps_and_identical_public_messages(self):
        question = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        running = synthetic.step(1, 'GENERIC', 'MODEL', '', status='RUNNING')
        answer = synthetic.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Answer')
        end = synthetic.step(3, 'GENERIC', 'MODEL', '')
        expected = [('user', 'Question'), ('assistant', 'Answer')]

        for name, rows, expected_warnings in (
            ('ordered', [question, running, answer, end], ()),
            ('forward_gap', [question, answer, end], ('missing_steps',)),
            ('replayed_old_step', [question, running, answer, running, end], ()),
            ('adjacent_replay', [question, running, running, answer, end], ()),
            ('multiple_replays', [question, running, answer, running, end, running], ()),
        ):
            with self.subTest(case=name):
                for log in (self.compact, self.full):
                    synthetic.write_steps(log, rows)
                result = self.reader.snapshot(self.thread)
                self.assertEqual([(m.role, m.text) for m in result.messages], expected)
                self.assertEqual(result.warnings, expected_warnings)

        # Forward gaps before and after a verbatim replay must still report missing_steps,
        # unfinished public messages must stay warned, and distinct step indices with identical
        # public text must both be preserved verbatim.
        gap_before = [
            question,
            synthetic.step(3, 'GENERIC', 'MODEL', '', status='RUNNING'),
            synthetic.step(4, 'PLANNER_RESPONSE', 'MODEL', 'Answer'),
            synthetic.step(3, 'GENERIC', 'MODEL', '', status='RUNNING'),
            synthetic.step(7, 'USER_INPUT', 'USER_EXPLICIT', 'Question'),
            synthetic.step(8, 'PLANNER_RESPONSE', 'MODEL', 'Draft in flight', status='RUNNING'),
        ]
        for log in (self.compact, self.full):
            synthetic.write_steps(log, gap_before)
        with_gaps = self.reader.snapshot(self.thread)
        self.assertEqual(
            [(m.role, m.text, m.position) for m in with_gaps.messages],
            [
                ('user', 'Question', 'step:0'),
                ('assistant', 'Answer', 'step:4'),
                ('user', 'Question', 'step:7'),
            ],
        )
        self.assertEqual(with_gaps.warnings, ('missing_steps', 'unfinished_messages_omitted'))

    def test_mutated_replayed_non_public_step_fails_closed(self):
        question = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        running = synthetic.step(1, 'GENERIC', 'MODEL', 'status-body', status='RUNNING')
        answer = synthetic.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Answer')

        mutations = {
            'status_changed': {**running, 'status': 'DONE'},
            'content_changed': {**running, 'content': 'mutated-body'},
            'source_changed': {**running, 'source': 'SYSTEM'},
            'type_changed': {**running, 'type': 'OTHER_NON_PUBLIC'},
            'timestamp_changed': {**running, 'created_at': '2026-11-16T03:00:59Z'},
            'extra_field_added': {**running, 'tool_calls': [{'name': 'probe'}]},
        }
        for name, mutated in mutations.items():
            with self.subTest(mutation=name):
                rows = [question, running, answer, mutated]
                for log in (self.compact, self.full):
                    synthetic.write_steps(log, rows)
                with self.assertRaises(AccessError) as caught:
                    self.reader.snapshot(self.thread)
                self.assertEqual(caught.exception.code, 'unsupported_format')
                self.assertIn('not strictly ordered', str(caught.exception))

        # Even JSON-equivalent key reordering is not byte-for-byte verbatim and must fail closed.
        reordered = {
            'status': running['status'],
            'step_index': running['step_index'],
            'type': running['type'],
            'source': running['source'],
            'created_at': running['created_at'],
            'content': running['content'],
        }
        raw_bytes = _encode_rows([question, running, answer, reordered])
        for log in (self.compact, self.full):
            log.write_bytes(raw_bytes)
        with self.assertRaises(AccessError) as caught:
            self.reader.snapshot(self.thread)
        self.assertEqual(caught.exception.code, 'unsupported_format')
        self.assertIn('not strictly ordered', str(caught.exception))

    def test_replayed_public_unrecognized_provenance_and_unseen_old_indices_fail_closed(self):
        question = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        answer_done = synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', 'Answer', status='DONE')
        answer_running = synthetic.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Halfway', status='RUNNING')
        explicit_unknown = synthetic.step(3, 'FUTURE_NON_PUBLIC', 'USER_EXPLICIT', 'Hidden')
        unknown_source = synthetic.step(4, 'USER_INPUT', 'UNKNOWN_PROVENANCE', 'Hidden')
        tail = synthetic.step(5, 'GENERIC', 'MODEL', '')

        cases = {
            'public_user_replay': [question, answer_done, question],
            'public_assistant_done_replay': [question, answer_done, tail, answer_done],
            'public_assistant_running_replay': [question, answer_running, tail, answer_running],
            'user_explicit_unknown_type_replay': [question, explicit_unknown, tail, explicit_unknown],
            'unrecognized_source_replay': [question, unknown_source, tail, unknown_source],
            'unseen_old_step_index': [
                question,
                synthetic.step(5, 'PLANNER_RESPONSE', 'MODEL', 'Answer'),
                synthetic.step(2, 'GENERIC', 'MODEL', '', status='RUNNING'),
                synthetic.step(6, 'GENERIC', 'MODEL', ''),
            ],
        }
        for name, rows in cases.items():
            with self.subTest(case=name):
                for log in (self.compact, self.full):
                    synthetic.write_steps(log, rows)
                with self.assertRaises(AccessError) as caught:
                    self.reader.snapshot(self.thread)
                self.assertEqual(caught.exception.code, 'unsupported_format')
                self.assertIn('not strictly ordered', str(caught.exception))

    def test_two_log_replay_corroboration_and_truncation_recovery(self):
        question = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        compact_running = synthetic.step(1, 'GENERIC', 'MODEL', 'compact-status', status='RUNNING')
        full_running = synthetic.step(
            1, 'GENERIC', 'MODEL', 'full-status-with-extra-payload',
            status='RUNNING', tool_calls=[{'secret': HIDDEN_TOOL}],
        )
        truncated = synthetic.step(
            2, 'PLANNER_RESPONSE', 'MODEL', 'Head\n<truncated 6 bytes>\nTail',
            truncated_fields=['content'],
        )
        recovered_answer = synthetic.step(
            2, 'PLANNER_RESPONSE', 'MODEL', 'Head中间Tail', thinking=HIDDEN_THINKING,
        )
        later = synthetic.step(5, 'USER_INPUT', 'USER_EXPLICIT', 'Follow up')

        # Both logs share the exact replay position & metadata while each log's replay
        # is byte-identical to its own earlier line (even though GENERIC content differs
        # between compact and full).
        compact_rows = [question, compact_running, truncated, compact_running, later]
        full_rows = [question, full_running, recovered_answer, full_running, later]
        synthetic.write_steps(self.compact, compact_rows)
        synthetic.write_steps(self.full, full_rows)

        paired = self.reader.snapshot(self.thread)
        self.assertEqual(
            [(m.role, m.text, m.position) for m in paired.messages],
            [
                ('user', 'Question', 'step:0'),
                ('assistant', 'Head中间Tail', 'step:2'),
                ('user', 'Follow up', 'step:5'),
            ],
        )
        self.assertEqual(paired.warnings, ('missing_steps',))
        self.assertTrue(paired.identity.startswith('paired:'))
        self.assertIsNone(paired.prefix)
        self.assertNotIn(HIDDEN_THINKING, repr(paired))
        self.assertNotIn(HIDDEN_TOOL, repr(paired))

        # Mutating the full log's non-public content (and its matching replay) updates revision
        # while preserving the paired identity.
        alt_full_running = {**full_running, 'content': 'full-status-revised'}
        synthetic.write_steps(self.full, [question, alt_full_running, recovered_answer, alt_full_running, later])
        revised = self.reader.snapshot(self.thread)
        self.assertEqual(revised.identity, paired.identity)
        self.assertNotEqual(revised.revision, paired.revision)

        # Conflicting replay evidence between compact and full must fail closed.
        disagreements = {
            'full_omits_replay': [question, full_running, recovered_answer, later],
            'full_replays_at_different_line': [question, full_running, recovered_answer, later, full_running],
            'full_empty': [],
            'full_replays_different_step': [
                question,
                full_running,
                recovered_answer,
                synthetic.step(3, 'GENERIC', 'MODEL', 'other', status='RUNNING'),
                later,
            ],
        }
        for name, bad_full in disagreements.items():
            with self.subTest(disagreement=name):
                synthetic.write_steps(self.compact, compact_rows)
                synthetic.write_steps(self.full, bad_full)
                with self.assertRaises(AccessError) as caught:
                    self.reader.snapshot(self.thread)
                self.assertEqual(caught.exception.code, 'unsupported_format')

        # Trailing incomplete line in companion while compact has a replay must fail closed.
        synthetic.write_steps(self.compact, compact_rows)
        synthetic.write_steps(self.full, full_rows)
        with self.full.open('ab') as stream:
            stream.write(b'{"step_index":6')
        with self.assertRaises(AccessError) as caught:
            self.reader.snapshot(self.thread)
        self.assertEqual(caught.exception.code, 'unsupported_format')

        # Conversely, when compact is strictly ordered (no replay) and has truncated text,
        # an unexpected replay only in full preserves existing v1 partial-coverage fallback.
        synthetic.write_steps(self.compact, [question, compact_running, truncated, later])
        synthetic.write_steps(self.full, [question, full_running, recovered_answer, full_running, later])
        fallback = self.reader.snapshot(self.thread)
        self.assertEqual([m.text for m in fallback.messages], ['Question', 'Follow up'])
        self.assertEqual(fallback.warnings, ('missing_steps', 'truncated_content_omitted'))
        self.assertIsNotNone(fallback.prefix)

    def test_raw_byte_fingerprint_single_file_prefix_and_record_budget_preserved(self):
        question = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Question')
        running = synthetic.step(1, 'GENERIC', 'MODEL', '', status='RUNNING')
        answer = synthetic.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Answer')
        rows = [question, running, answer, running]
        if self.full.exists():
            self.full.unlink()
        raw = synthetic.write_steps(self.compact, rows)

        snap = self.reader.snapshot(self.thread)
        self.assertEqual(snap.revision, hashlib.sha256(raw).hexdigest())
        self.assertIsNotNone(snap.prefix)
        self.assertEqual(snap.prefix[1], len(raw))
        self.assertEqual(snap.prefix[2], snap.revision)

        # Appending another verbatim replay updates revision while keeping the committed byte prefix intact.
        extra = _encode_rows([running])
        with self.compact.open('ab') as stream:
            stream.write(extra)
        appended = self.reader.snapshot(self.thread)
        self.assertEqual(appended.revision, hashlib.sha256(raw + extra).hexdigest())
        self.assertNotEqual(appended.revision, snap.revision)
        self.assertEqual(hashlib.sha256(self.compact.read_bytes()[:snap.prefix[1]]).hexdigest(), snap.prefix[2])

        # Replayed lines still count against MAX_RECORDS.
        with patch.object(ag, 'MAX_RECORDS', 4):
            with self.assertRaises(AccessError) as caught:
                self.reader.snapshot(self.thread)
            self.assertEqual(caught.exception.code, 'resource_exhausted')


class AntigravityReplayedStepMCPV1Tests(unittest.TestCase):
    def setUp(self):
        fixture = synthetic.AntigravityAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root.parent
        self.project_config = self.root / 'projects.json'
        self.project_config.write_text(json.dumps({'projects': [
            {'id': 'alpha-project', 'name': 'Alpha Project', 'root': str(fixture.project)},
        ]}))
        self.policy_path = self.root / 'agent-history-policy.json'
        self.audit_path = self.root / 'audit.jsonl'

        fixture.add_thread(synthetic.FIRST)
        fixture.add_thread(synthetic.SECOND)
        fixture.add_thread(synthetic.THIRD)
        for cid, title in (
            (synthetic.FIRST, TARGET_TITLE),
            (synthetic.SECOND, NEIGHBOR_TITLE),
            (synthetic.THIRD, UNGRANTED_TITLE),
        ):
            fixture.db.execute(
                'UPDATE conversation_summaries SET title = ? WHERE conversation_id = ?',
                (title, cid),
            )
        fixture.db.commit()

        # Target thread: 3 complete turns (6 visible messages), verbatim replayed non-public
        # GENERIC/RUNNING step, truncated visible reply recovered from transcript_full.jsonl,
        # a genuine forward step gap (missing_steps), and a trailing unfinished reply.
        q1 = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Turn 1: outline the architecture constraints.')
        run_status = synthetic.step(1, 'GENERIC', 'MODEL', 'compact-running-payload', status='RUNNING')
        full_run_status = synthetic.step(
            1, 'GENERIC', 'MODEL', 'full-running-payload', status='RUNNING',
            tool_calls=[{'arg': HIDDEN_TOOL}],
        )
        a1_trunc = synthetic.step(
            2, 'PLANNER_RESPONSE', 'MODEL',
            'Architecture summary:\n<truncated 18 bytes>\nAll constraints checked.',
            truncated_fields=['content'],
        )
        a1_full = synthetic.step(
            2, 'PLANNER_RESPONSE', 'MODEL',
            'Architecture summary:核心指标对齐All constraints checked.',
            thinking=HIDDEN_THINKING,
        )
        q2 = synthetic.step(5, 'USER_INPUT', 'USER_EXPLICIT', 'Turn 2: verify pagination boundaries and cursors.')
        a2 = synthetic.step(
            6, 'PLANNER_RESPONSE', 'MODEL',
            'Pagination uses opaque HMAC cursors and enforces fail-closed revocation on every page.',
        )
        q3 = synthetic.step(7, 'USER_INPUT', 'USER_EXPLICIT', 'Turn 3: confirm final delivery checklist.')
        a3 = synthetic.step(
            8, 'PLANNER_RESPONSE', 'MODEL',
            'Final checklist verified: title search, paged read, and latest_turn all match.',
        )
        unfinished = synthetic.step(9, 'PLANNER_RESPONSE', 'MODEL', 'Streaming draft', status='RUNNING')

        self.target_compact = fixture.transcript(synthetic.FIRST)
        self.target_full = self.target_compact.with_name('transcript_full.jsonl')
        synthetic.write_steps(
            self.target_compact,
            [q1, run_status, a1_trunc, q2, a2, run_status, q3, a3, unfinished],
        )
        synthetic.write_steps(
            self.target_full,
            [q1, full_run_status, a1_full, q2, a2, full_run_status, q3, a3, unfinished],
        )

        # Neighbor authorized thread remains healthy and readable.
        synthetic.write_steps(
            fixture.transcript(synthetic.SECOND),
            [
                synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Neighbor question'),
                synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', 'Neighbor answer'),
            ],
        )
        # Ungranted thread must stay invisible.
        synthetic.write_steps(
            fixture.transcript(synthetic.THIRD),
            [
                synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Ungranted private text'),
                synthetic.step(1, 'PLANNER_RESPONSE', 'MODEL', 'Ungranted reply'),
            ],
        )

        self.settings = AccessSettings(
            'https://test-team.cloudflareaccess.com', 'a' * 64,
            'mcp.example.com', (f'{OWNER}@example.com',),
        )
        self.actors = {actor_digest(self.settings.team_domain, OWNER): ['alpha-project']}
        self.write_policy()

        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        token = jwt.encode(
            {
                'iss': self.settings.team_domain,
                'aud': [self.settings.audience],
                'iat': now - 1,
                'exp': now + 300,
                'email': f'{OWNER}@example.com',
                'sub': OWNER,
            },
            self.key,
            algorithm='RS256',
            headers={'kid': 'synthetic-v1'},
        )
        self.headers = {
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-03-26',
            'cf-access-jwt-assertion': token,
        }
        app = build_app(
            Catalog.from_config(self.project_config),
            self.settings,
            agent_policy=AgentPolicy(self.policy_path),
        )
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.key.public_key())
        self.client = self.enterContext(TestClient(app, base_url='https://mcp.example.com'))
        self.serial = 0

    def write_policy(self, *, denied=()):
        data = {
            'version': 1,
            'sources': {
                SOURCE_V1: {
                    'adapter': 'antigravity',
                    'format': '2.32.1',
                    'root': str(self.fixture.root),
                    'enabled': True,
                    'inherit_projects': False,
                    'actors': self.actors,
                    'threads': {
                        synthetic.FIRST: 'alpha-project',
                        synthetic.SECOND: 'alpha-project',
                    },
                    'denied_threads': list(denied),
                },
            },
        }
        tmp = self.policy_path.with_name('next-policy.json')
        tmp.write_text(json.dumps(data))
        tmp.replace(self.policy_path)

    def call_tool(self, name, arguments):
        self.serial += 1
        response = self.client.post(
            '/mcp',
            headers=self.headers,
            json={
                'jsonrpc': '2.0',
                'id': self.serial,
                'method': 'tools/call',
                'params': {'name': name, 'arguments': arguments},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertNotIn('error', body)
        result = body['result']
        return result.get('isError', False), result['content'][0]['text']

    def complete(self, name, arguments):
        for _ in range(40):
            is_err, text = self.call_tool(name, arguments)
            if is_err:
                return True, text
            payload = json.loads(text)
            if payload.get('status') not in ('processing', 'waiting_source_stable'):
                return False, payload
            arguments = {**arguments, 'cursor': payload['next_cursor']}
        self.fail('MCP v1 request did not complete within bounded continuations')

    def test_v1_title_search_paginated_read_neighbor_isolation_and_revocation(self):
        # 1. Title search hits the replayed thread instead of returning empty threads[].
        is_err, found = self.complete('find_agent_threads', {
            'project_id': 'alpha-project',
            'source_id': SOURCE_V1,
            'query': TARGET_TITLE,
        })
        self.assertFalse(is_err, found)
        self.assertEqual(found['status'], 'ready')
        # Genuine missing_steps / unfinished_messages_omitted still mark coverage_unverified,
        # while the verbatim replay no longer fails the thread with unsupported_format.
        source_warnings = found['coverage'][0]['warnings']
        self.assertEqual(source_warnings, ['coverage_unverified'])
        self.assertNotIn('unsupported_format', source_warnings)
        self.assertEqual(len(found['threads']), 1)
        hit = found['threads'][0]
        self.assertEqual(hit['title'], TARGET_TITLE)
        self.assertEqual(hit['match'], {'in': 'title', 'mode': 'substring'})
        self.assertEqual(hit['message_count'], 6)
        self.assertEqual(hit['user_message_count'], 3)
        self.assertEqual(hit['assistant_message_count'], 3)
        thread_ref = hit['thread_ref']

        # 2. Paginated small-page reads across next_cursor recover all 6 messages in order.
        read_args = {'thread_ref': thread_ref, 'view': 'all', 'limit': 2, 'max_chars': 140}
        is_err, page = self.complete('read_agent_thread', read_args)
        self.assertFalse(is_err, page)
        self.assertEqual(page['status'], 'ready')
        self.assertTrue(page['has_more'])
        self.assertIsNotNone(page['next_cursor'])
        self.assertEqual(page['warnings'], ['missing_steps', 'unfinished_messages_omitted'])
        saved_cursor = page['next_cursor']
        snapshot_sha = page['snapshot_sha256']

        pages = 1
        chunks = list(page['entries'])
        while page['has_more']:
            is_err, page = self.complete('read_agent_thread', {**read_args, 'cursor': page['next_cursor']})
            self.assertFalse(is_err, page)
            self.assertEqual(page['snapshot_sha256'], snapshot_sha)
            pages += 1
            chunks.extend(page['entries'])
        self.assertGreaterEqual(pages, 3)
        self.assertFalse(page['has_more'])
        self.assertIsNone(page['next_cursor'])

        # Reassemble split parts by message_id preserving exact message order.
        ordered_messages = []
        for item in chunks:
            if ordered_messages and ordered_messages[-1][0] == item['message_id']:
                ordered_messages[-1][2] += item['text']
            else:
                ordered_messages.append([item['message_id'], item['role'], item['text'], item['source_position']])
        self.assertEqual(
            [(role, text, pos) for _, role, text, pos in ordered_messages],
            [
                ('user', 'Turn 1: outline the architecture constraints.', 'step:0'),
                ('assistant', 'Architecture summary:核心指标对齐All constraints checked.', 'step:2'),
                ('user', 'Turn 2: verify pagination boundaries and cursors.', 'step:5'),
                ('assistant', 'Pagination uses opaque HMAC cursors and enforces fail-closed revocation on every page.', 'step:6'),
                ('user', 'Turn 3: confirm final delivery checklist.', 'step:7'),
                ('assistant', 'Final checklist verified: title search, paged read, and latest_turn all match.', 'step:8'),
            ],
        )
        serialized = json.dumps(chunks)
        self.assertNotIn(HIDDEN_THINKING, serialized)
        self.assertNotIn(HIDDEN_TOOL, serialized)

        # 3. latest_turn view returns Turn 3 verbatim.
        is_err, latest = self.complete('read_agent_thread', {'thread_ref': thread_ref, 'view': 'latest_turn'})
        self.assertFalse(is_err, latest)
        self.assertEqual(
            [(m['role'], m['text']) for m in latest['entries']],
            [
                ('user', 'Turn 3: confirm final delivery checklist.'),
                ('assistant', 'Final checklist verified: title search, paged read, and latest_turn all match.'),
            ],
        )

        # 4. Neighbor authorized thread remains searchable & readable; ungranted thread stays denied.
        is_err, neighbor_found = self.complete('find_agent_threads', {
            'project_id': 'alpha-project',
            'source_id': SOURCE_V1,
            'query': NEIGHBOR_TITLE,
        })
        self.assertFalse(is_err, neighbor_found)
        self.assertEqual(len(neighbor_found['threads']), 1)
        is_err, neighbor_read = self.complete(
            'read_agent_thread', {'thread_ref': neighbor_found['threads'][0]['thread_ref']},
        )
        self.assertFalse(is_err, neighbor_read)
        self.assertEqual([m['text'] for m in neighbor_read['entries']], ['Neighbor question', 'Neighbor answer'])

        is_err, ungranted = self.complete('find_agent_threads', {
            'project_id': 'alpha-project',
            'source_id': SOURCE_V1,
            'query': UNGRANTED_TITLE,
        })
        self.assertFalse(is_err, ungranted)
        self.assertEqual(ungranted['threads'], [])

        # 5. Revoking the target thread immediately blocks pre-revocation thread_ref & next_cursor.
        self.write_policy(denied=[synthetic.FIRST])
        is_err, denied_read = self.complete('read_agent_thread', {'thread_ref': thread_ref})
        self.assertTrue(is_err, denied_read)
        is_err, denied_cursor = self.complete('read_agent_thread', {**read_args, 'cursor': saved_cursor})
        self.assertTrue(is_err, denied_cursor)

    def test_v1_single_file_live_append_and_rewrite_detection_with_replayed_step(self):
        # Single-file transcript (no transcript_full.jsonl) with verbatim replay preserves
        # append-only continuation across pages, and rejects earlier byte rewrites.
        self.target_full.unlink()
        q1 = synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Page 1 prompt ' * 8)
        run_status = synthetic.step(1, 'GENERIC', 'MODEL', '', status='RUNNING')
        a1 = synthetic.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Page 2 response ' * 8)
        initial_rows = [q1, run_status, a1, run_status]
        synthetic.write_steps(self.target_compact, initial_rows)

        is_err, found = self.complete('find_agent_threads', {
            'project_id': 'alpha-project',
            'source_id': SOURCE_V1,
            'query': TARGET_TITLE,
        })
        self.assertFalse(is_err, found)
        self.assertTrue(found['coverage_complete'])
        self.assertEqual(found['coverage'][0]['warnings'], [])
        thread_ref = found['threads'][0]['thread_ref']

        read_args = {'thread_ref': thread_ref, 'view': 'all', 'limit': 1, 'max_chars': 120}
        is_err, page1 = self.complete('read_agent_thread', read_args)
        self.assertFalse(is_err, page1)
        self.assertTrue(page1['has_more'])
        cursor1 = page1['next_cursor']

        # Appending another verbatim replay plus a new turn preserves the frozen snapshot cursor.
        with self.target_compact.open('ab') as stream:
            stream.write(_encode_rows([
                run_status,
                synthetic.step(3, 'USER_INPUT', 'USER_EXPLICIT', 'Appended after snapshot'),
            ]))
        is_err, page2 = self.complete('read_agent_thread', {**read_args, 'cursor': cursor1})
        self.assertFalse(is_err, page2)
        self.assertEqual(page2['snapshot_sha256'], page1['snapshot_sha256'])

        # Rewriting earlier committed bytes must trigger restart_required on the stale cursor.
        rewritten = [
            synthetic.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Tampered earlier prompt ' * 6),
            run_status,
            a1,
            run_status,
        ]
        synthetic.write_steps(self.target_compact, rewritten)
        is_err, stale = self.complete('read_agent_thread', {**read_args, 'cursor': cursor1})
        self.assertTrue(is_err, stale)
        self.assertIn('restart_required', stale)


class AntigravityReplayedStepMCPV2Tests(unittest.TestCase):
    def setUp(self):
        fixture = native.AntigravityNativeTests()
        fixture.live_clock = True
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

        # Configure step 2 as a valid registered native GENERIC (step_type=132) record
        # in SQLite (unique step indices 0..3) while both transcript.jsonl and
        # transcript_full.jsonl replay step 2 verbatim after step 3.
        tool_name = b'mcp_probe_status'
        query = fixture.logs[0]['content']
        fixture.logs[2].update(type='GENERIC', source='MODEL', status='DONE', content='compact-tool-status')
        fixture.write_step(3, native.FIRST, 1, fixture.logs[3]['content'])
        origin = native.message((1, native.TRAJECTORY), (2, 2), (4, native.SESSION))
        config = native.message((1, native.desktop_spec()))
        registered = native.message((1, native.message((1, 7), (2, 'probe'), (5, 1))))
        call = native.message((1, b'call'), (2, tool_name))
        prompt = native.message((2, 1), (3, query), (18, 0))
        generic = native.message((2, native.message((1, HIDDEN_TOOL), (7, 'file:///private/tool-result'))))
        at = native.message((1, fixture.created[0]), (2, fixture.created[1]))
        lifecycle = native.message(*[(1, native.message((1, state), (2, at))) for state in (1, 2, 3)])
        meta = native.message(
            (1, at), (3, 2), (4, call), (6, at), (7, at), (8, at), (12, native.FIRST),
            (20, origin), (26, lifecycle), (38, 3),
        )
        step_blob = native.message((1, 132), (4, 3), (5, meta), (140, generic))
        fixture.db.execute('INSERT OR REPLACE INTO steps VALUES(2,132,3,0,?,?,0)', (meta, step_blob))
        fixture.db.execute('DELETE FROM executor_metadata')
        executor = native.message(
            (1, 4), (2, 2), (3, 3), (9, native.FIRST), (16, config), (18, registered),
        )
        fixture.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(0,?)', (executor,))
        chat = native.message((2, prompt), (8, native.message((1, tool_name))))
        fixture.db.execute(
            'UPDATE gen_metadata SET data=? WHERE idx=0',
            (native.message((1, chat), (2, bytes([1, 2])), (4, native.FIRST)),),
        )
        fixture.db.execute(
            'UPDATE gen_metadata SET data=? WHERE idx=1',
            (native.message((1, b''), (2, bytes([3])), (4, native.FIRST)),),
        )
        fixture.db.commit()

        fixture.index.execute(
            'UPDATE conversation_summaries SET title=? WHERE conversation_id=?',
            (TARGET_TITLE, native.SESSION),
        )
        fixture.index.commit()
        fixture.thread = fixture.reader.describe(native.SESSION)

        self.compact_rows = [
            fixture.logs[0],
            fixture.logs[1],
            fixture.logs[2],
            fixture.logs[3],
            fixture.logs[2],  # Verbatim replay of non-public GENERIC step 2.
        ]
        full_generic = {**fixture.logs[2], 'content': 'full-tool-status-payload'}
        self.full_rows = [
            fixture.logs[0],
            fixture.logs[1],
            full_generic,
            fixture.logs[3],
            full_generic,  # Matching verbatim replay inside transcript_full.jsonl.
        ]
        self.compact_path = fixture.transcript
        self.full_path = self.compact_path.with_name('transcript_full.jsonl')
        self.compact_path.write_bytes(_encode_rows(self.compact_rows))
        self.full_path.write_bytes(_encode_rows(self.full_rows))

        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        control = Path(self.tmp).resolve() / 'control'
        control.mkdir(mode=0o700)
        self.document = {
            'version': 2,
            'projects': [{
                'id': 'v2-alpha',
                'name': 'V2 Alpha',
                'root': str(fixture.project),
                'directory_identity': persistent_identity(fixture.project),
            }],
            'sources': {
                SOURCE_V2: {
                    'adapter': 'antigravity',
                    'format': '2.33.0',
                    'enabled': True,
                    'instance_id': 'synthetic-desktop',
                    'root': str(fixture.reader.root.path),
                    'root_identity': persistent_identity(fixture.reader.root.path),
                },
            },
            'legacy_history': None,
        }
        self.store = initialize_store(control / 'generations')
        self.epoch = self.store.activate(self.document, initial=True)
        descriptor = control / 'history-v2.json'
        descriptor.write_text(json.dumps({'version': 2, 'generation_directory': str(self.store.path)}))
        descriptor.chmod(0o600)
        self.policy = AgentPolicy(descriptor, mode='v2')

        settings = AccessSettings(
            'https://test-team.cloudflareaccess.com', 'a' * 64,
            'mcp.example.com', (f'{OWNER}@example.com',),
        )
        app = build_app(Catalog.from_policy(self.policy), settings, agent_policy=self.policy)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        token = jwt.encode(
            {
                'iss': settings.team_domain,
                'aud': [settings.audience],
                'iat': now - 1,
                'exp': now + 300,
                'email': f'{OWNER}@example.com',
                'sub': OWNER,
            },
            key,
            algorithm='RS256',
            headers={'kid': 'synthetic-v2'},
        )
        self.headers = {
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-03-26',
            'cf-access-jwt-assertion': token,
        }
        self.client = self.enterContext(TestClient(app, base_url='https://mcp.example.com'))
        self.serial = 0

    def call_tool(self, name, arguments):
        self.serial += 1
        response = self.client.post(
            '/mcp',
            headers=self.headers,
            json={
                'jsonrpc': '2.0',
                'id': self.serial,
                'method': 'tools/call',
                'params': {'name': name, 'arguments': arguments},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertNotIn('error', body)
        result = body['result']
        return result.get('isError', False), result['content'][0]['text']

    def complete(self, name, arguments):
        for _ in range(40):
            is_err, text = self.call_tool(name, arguments)
            if is_err:
                return True, text
            payload = json.loads(text)
            if payload.get('status') not in ('processing', 'waiting_source_stable'):
                return False, payload
            arguments = {**arguments, 'cursor': payload['next_cursor']}
        self.fail('MCP v2 request did not complete within bounded continuations')

    def test_v2_native_sqlite_with_paired_replayed_step_and_revocation(self):
        # 1. Native SQLite 2.33.0 verification succeeds when paired logs agree on the replay.
        proof, bound = capture(self.fixture.reader, self.fixture.thread)
        self.assertEqual(proof.state, 'workspace_verified')
        self.assertEqual([m.text for m in bound.messages], ['问题 0', 'Visible Gemini answer 0', 'Visible Gemini answer 1'])
        self.assertNotIn(HIDDEN_TOOL, repr(bound))

        # 2. Full MCP v2 search by title and paginated read across next_cursor.
        is_err, found = self.complete('find_agent_threads', {
            'project_id': 'v2-alpha',
            'source_id': SOURCE_V2,
            'query': TARGET_TITLE,
        })
        self.assertFalse(is_err, found)
        self.assertTrue(found['coverage_complete'])
        self.assertEqual(len(found['threads']), 1)
        hit = found['threads'][0]
        self.assertEqual(hit['title'], TARGET_TITLE)
        self.assertEqual(hit['match'], {'in': 'title', 'mode': 'substring'})
        thread_ref = hit['thread_ref']

        read_args = {'thread_ref': thread_ref, 'view': 'all', 'limit': 1, 'max_chars': 120}
        is_err, page = self.complete('read_agent_thread', read_args)
        self.assertFalse(is_err, page)
        self.assertTrue(page['has_more'])
        saved_cursor = page['next_cursor']
        collected = list(page['entries'])
        while page['has_more']:
            is_err, page = self.complete('read_agent_thread', {**read_args, 'cursor': page['next_cursor']})
            self.assertFalse(is_err, page)
            collected.extend(page['entries'])
        self.assertEqual(
            [(m['role'], m['text']) for m in collected],
            [
                ('user', '问题 0'),
                ('assistant', 'Visible Gemini answer 0'),
                ('assistant', 'Visible Gemini answer 1'),
            ],
        )

        # 3. Companion disagreement (full drops replay) fails closed in v2 native inheritance.
        self.full_path.write_bytes(_encode_rows(self.full_rows[:-1]))
        self.assertEqual(self.fixture.reader.inspect_native(self.fixture.thread).state, 'unverified')
        with self.assertRaises(AccessError) as caught:
            self.fixture.reader.snapshot_for_inheritance(self.fixture.thread)
        self.assertEqual(caught.exception.code, 'association_unverified')

        # Restore matching companion, then revoke via v2 denied_threads generation activation.
        self.full_path.write_bytes(_encode_rows(self.full_rows))
        revoked_doc = json.loads(json.dumps(self.document))
        revoked_doc['sources'][SOURCE_V2]['denied_threads'] = [native.SESSION]
        self.store.activate(revoked_doc, expected_digest=self.epoch)
        is_err, denied_ref = self.complete('read_agent_thread', {'thread_ref': thread_ref})
        self.assertTrue(is_err, denied_ref)
        is_err, denied_cursor = self.complete('read_agent_thread', {**read_args, 'cursor': saved_cursor})
        self.assertTrue(is_err, denied_cursor)


if __name__ == '__main__':
    unittest.main()
