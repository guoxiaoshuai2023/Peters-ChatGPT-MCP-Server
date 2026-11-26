import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

from peters_mcp.agent_history_antigravity_shadow import (
    ShadowConfig, append_observation, assess_shadow, observe, verify_shadow,
)
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError
from tests import test_agent_history_antigravity as fixture


class AntigravityShadowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.AntigravityAdapterTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.add_thread(fixture.FIRST)
        self.fixture.db.execute("ALTER TABLE conversation_summaries ADD COLUMN project_id TEXT NOT NULL DEFAULT ''")
        self.fixture.db.execute('UPDATE conversation_summaries SET project_id=?', (fixture.SECOND,))
        self.fixture.db.commit()
        self.base = self.fixture.root.parent
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.ledger = self.control / 'ledger'
        self.ledger.mkdir(mode=0o700)
        self.filename = self.control / 'shadow.json'
        self.document = {'version': 1, 'source_instance_id': 'synthetic-gravity', 'epoch': secrets.token_hex(32),
                         'product_version': '2.33.0', 'profile': str(self.fixture.root),
                         'profile_identity': list(SourceRoot(self.fixture.root).identity),
                         'ledger': str(self.ledger), 'ledger_identity': list(SourceRoot(self.ledger).identity),
                         'workspaces': {str(self.fixture.project): list(SourceRoot(self.fixture.project).identity)},
                         'hmac_key': secrets.token_hex(32)}
        self.filename.write_text(json.dumps(self.document))
        self.filename.chmod(0o600)
        self.config = ShadowConfig.load(self.filename)
        self.transcript = self.fixture.transcript(fixture.FIRST)
        self.payload = {'conversationId': fixture.FIRST, 'workspacePaths': [str(self.fixture.project)],
                        'transcriptPath': str(self.transcript),
                        'artifactDirectoryPath': str(self.transcript.parents[2]),
                        'invocationNum': 0, 'initialNumSteps': 1, 'lastUserInput': 'Secret user body canary',
                        'modelName': 'Secret extra canary', 'toolCall': {'args': 'Secret tool canary'}}

    def test_shadow_metadata_is_whitelisted_and_never_grants_continuous_attribution(self):
        raw = fixture.write_steps(self.transcript, [fixture.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'private body')])
        for event in ('SessionStart', 'PreInvocation', 'PostInvocation', 'Stop'):
            payload = {**self.payload, 'fullyIdle': True}
            if event == 'PostInvocation':
                payload['invocationNum'] = 5  # Missing intermediate events cannot be waved through.
            append_observation(self.config, observe(self.config, event, payload))
        rows = verify_shadow(self.config)
        self.assertEqual([row['event'] for row in rows], ['SessionStart', 'PreInvocation', 'PostInvocation', 'Stop'])
        self.assertEqual(rows[0]['transcript']['committed_bytes'], len(raw))
        self.assertEqual(rows[0]['index']['native_project_id'], fixture.SECOND)
        self.assertNotIn('Secret', (self.ledger / 'observations.jsonl').read_text())
        self.assertNotIn('private body', json.dumps(rows))
        self.assertEqual(assess_shadow(self.config), {'state': 'shadow_only', 'observations': 4,
                         'can_authorize_history': False, 'reason': 'continuous_workspace_membership_unproven',
                         'sessions': 1, 'sessions_by_sample_issue': {'invocation_missing_or_unpaired': 1}})

    def test_coherent_samples_and_replayed_signed_prefix_cannot_authorize_history(self):
        fixture.write_steps(self.transcript, [fixture.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'synthetic')])
        for event in ('SessionStart', 'PreInvocation', 'PostInvocation', 'Stop'):
            append_observation(self.config, observe(self.config, event, {**self.payload, 'fullyIdle': True}))
        path = self.ledger / 'observations.jsonl'
        complete = path.read_bytes()
        expected = assess_shadow(self.config)
        self.assertEqual(expected['sessions_by_sample_issue'], {})
        self.assertFalse(expected['can_authorize_history'])

        interrupted = observe(self.config, 'PreInvocation', {**self.payload, 'invocationNum': 1})
        append_observation(self.config, interrupted)
        self.assertEqual(assess_shadow(self.config)['sessions_by_sample_issue'],
                         {'invocation_missing_or_unpaired': 1, 'idle_stop_not_observed_at_end': 1})

        # An otherwise intact older signed prefix cannot prove completeness.
        path.write_bytes(complete)
        self.assertEqual(assess_shadow(self.config), expected)

    def test_assessment_reports_sampled_workspace_and_transcript_drift_without_paths(self):
        self.document['workspaces'][str(self.fixture.foreign)] = list(SourceRoot(self.fixture.foreign).identity)
        self.filename.write_text(json.dumps(self.document))
        self.config = ShadowConfig.load(self.filename)
        fixture.write_steps(self.transcript, [fixture.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'original')])
        for event in ('SessionStart', 'PreInvocation'):
            append_observation(self.config, observe(self.config, event, self.payload))

        fixture.write_steps(self.transcript, [fixture.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'replaced')])
        foreign = {**self.payload, 'workspacePaths': [str(self.fixture.foreign)]}
        append_observation(self.config, observe(self.config, 'PostInvocation', foreign))
        self.transcript.rename(self.transcript.with_name('old-native-log'))
        self.transcript.write_bytes(b'{"stepIndex":0')
        append_observation(self.config, observe(self.config, 'Stop', {**self.payload, 'fullyIdle': False}))

        report = assess_shadow(self.config)
        self.assertEqual(report['sessions_by_sample_issue'], {
            'workspace_change_sampled': 1,
            'workspace_sample_differs_from_index': 1,
            'idle_stop_not_observed_at_end': 1,
            'transcript_commit_rewrite_sampled': 1,
            'transcript_identity_change_sampled': 1,
            'transcript_partial_tail_sampled': 1,
        })
        rendered = json.dumps(report)
        for forbidden in (str(self.fixture.root), str(self.fixture.foreign), fixture.FIRST, 'original', 'replaced'):
            self.assertNotIn(forbidden, rendered)

    def test_pending_transcript_and_exact_uri_path_forms(self):
        pending = observe(self.config, 'SessionStart', self.payload)
        self.assertEqual(pending['transcript'], {'state': 'pending'})
        payload = {**self.payload, 'transcriptPath': self.transcript.as_uri(),
                   'artifactDirectoryPath': self.transcript.parents[2].as_uri()}
        row = observe(self.config, 'PreInvocation', payload)
        self.assertEqual(row['reported_transcript_form'], 'file_uri')
        self.assertEqual(row['reported_artifact_form'], 'file_uri')

    def test_payload_cannot_redirect_paths_or_observe_an_unpinned_workspace(self):
        for change in ({'transcriptPath': str(self.fixture.foreign / 'transcript.jsonl')},
                       {'workspacePaths': [str(self.fixture.foreign)]},
                       {'conversationId': '../unsafe'}, {'invocationNum': True}):
            with self.subTest(change=tuple(change)), self.assertRaises(AccessError):
                observe(self.config, 'PreInvocation', {**self.payload, **change})
        with self.assertRaises(AccessError):
            observe(self.config, 'Stop', self.payload)

    def test_desktop_hook_can_report_the_canonical_full_transcript(self):
        full = self.transcript.with_name('transcript_full.jsonl')
        raw = fixture.write_steps(full, [fixture.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'synthetic')])
        observation = observe(self.config, 'PreInvocation', {**self.payload, 'transcriptPath': str(full)})
        self.assertEqual(observation['reported_transcript_form'], 'absolute')
        self.assertEqual(observation['transcript']['committed_bytes'], len(raw))
        self.assertEqual(observation['transcript']['complete_rows'], 1)

    def test_ledger_rejects_tampering_partial_rows_and_body_fields(self):
        row = observe(self.config, 'PreInvocation', self.payload)
        append_observation(self.config, row)
        path = self.ledger / 'observations.jsonl'
        raw = path.read_bytes()
        for changed in (raw.replace(b'PreInvocation', b'PostInvocation'), raw[:-1], raw + raw):
            with self.subTest(bytes=len(changed)):
                path.write_bytes(changed)
                with self.assertRaises(AccessError):
                    verify_shadow(self.config)
        path.write_bytes(raw)
        with self.assertRaises(AccessError):
            append_observation(self.config, {**row, 'lastUserInput': 'body'})
        self.assertEqual(path.read_bytes(), raw)

    def test_configuration_and_workspace_identity_changes_fail_closed(self):
        self.filename.chmod(0o644)
        with self.assertRaises(AccessError):
            ShadowConfig.load(self.filename)
        self.filename.chmod(0o600)
        original = self.fixture.project.with_name('former-project')
        self.fixture.project.rename(original)
        self.fixture.project.mkdir()
        with self.assertRaises(AccessError):
            observe(self.config, 'PreInvocation', self.payload)

    def test_collector_cli_returns_empty_hook_response_and_only_private_metadata(self):
        result = subprocess.run([sys.executable, '-m', 'peters_mcp.agent_history_antigravity_shadow',
                                 str(self.filename), 'PreInvocation'], input=json.dumps(self.payload), text=True,
                                cwd=Path(__file__).resolve().parent.parent, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '{}\n')
        self.assertEqual(result.stderr, '')
        self.assertEqual(len(verify_shadow(self.config)), 1)
        self.assertEqual(os.stat(self.ledger / 'observations.jsonl').st_mode & 0o777, 0o600)

    def test_local_assessment_command_returns_only_summary_and_failure_code(self):
        append_observation(self.config, observe(self.config, 'PreInvocation', self.payload))
        command = [sys.executable, '-m', 'peters_mcp.agent_history_antigravity_shadow', '--assess', str(self.filename)]
        env = {'cwd': Path(__file__).resolve().parent.parent, 'capture_output': True, 'text': True, 'timeout': 10}
        result = subprocess.run(command, **env)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), assess_shadow(self.config))
        self.assertEqual(result.stderr, '')
        (self.ledger / 'observations.jsonl').write_bytes(b'invalid ledger\n')
        result = subprocess.run(command, **env)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'state': 'unavailable', 'can_authorize_history': False,
                                                    'reason': 'shadow_evidence_unavailable'})
        self.assertEqual(result.stderr, '')
