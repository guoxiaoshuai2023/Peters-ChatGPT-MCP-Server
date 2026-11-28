"""v0.5.7 systematic remediation tests:
1. Antigravity 2.33-2.36 protobuf schema security classification (fail-closed redlines
   vs strictly validated harmless scalar/enum/submessage fields including 46.9
   ComponentResolutionPolicy and 2.36 response_language / inheritance_mode).
2. Unified ExecutorTerminationReason lifecycle invariants with strict gen_metadata
   invocation accounting (zero unverified skipping) and forbidden terminal reasons.
3. Transient active-write index lag (index_step_count < db_steps_count -> waiting_source_stable)
   versus truncated DB (index_step_count > db_steps_count -> association_unverified).
4. Local operator-only exact field diagnostics in inspect_native without leaking
   internal structure into snapshot_for_inheritance or MCP error responses.
5. Unified find_agent_threads two-phase search (title/metadata-first + decoupled bounded
   body scan) across v1 and v2 on 320+ thread Codex projects, non-Codex adapters,
   concurrent non-busy worker execution, forget_cursor cleanup, and revocation fail-closed.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.testclient import TestClient

from peters_mcp.agent_history import AgentHistoryCore, MAX_SEARCH
from peters_mcp.agent_history_admin import activate_preview, preview_activation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.agent_history_source import Message, Projection, Thread
from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import actor_digest
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.history import HistoryAccess
from tests import test_agent_history_antigravity_native as native
from tests.test_agent_history_antigravity_native import (
    FIRST, SECOND, SECONDS, SESSION, TRAJECTORY, desktop_spec, message, varint,
)
from tests.test_history import encode as codex_encode, message as codex_message, record as codex_record


def _finish(iterator):
    while True:
        try:
            next(iterator)
        except StopIteration as done:
            return done.value


class AntigravityNativeSchemaAndLifecycleTests(unittest.TestCase):
    def _fixture(self, *, live_clock=False):
        fx = native.AntigravityNativeTests(methodName='runTest')
        if live_clock:
            fx.live_clock = True
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        return fx

    def _set_exec_config(self, fx, config_blob, *, override=False, idx=0, key=FIRST, end=1):
        kw = {'override': config_blob} if override else {'config': config_blob}
        fx.db.execute(
            'UPDATE executor_metadata SET data=? WHERE idx=?',
            (fx.executor(key, end, **kw), idx),
        )
        fx.db.commit()

    def test_declarative_resolution_policy_46_9_accepts_valid_closed_enums_and_rejects_invalid(self):
        fx = self._fixture()
        # All valid combinations of ResolutionPolicy {0: UNSPECIFIED, 1: IGNORE, 2: ERROR} on {1, 2}.
        for unk in (None, 0, 1, 2):
            for emp in (None, 0, 1, 2):
                fields = []
                if unk is not None:
                    fields.append((1, unk))
                if emp is not None:
                    fields.append((2, emp))
                policy_blob = message(*fields)
                mixin = message((9, policy_blob), (10, 0))
                planner = message((46, mixin))
                cfg = message((1, planner))
                self._set_exec_config(fx, cfg)
                obs = fx.result()
                self.assertEqual(obs.state, 'workspace_verified', (unk, emp, obs))
                # Also verify inside USER_INPUT.12 and gen_metadata.3
                fx.write_step(0, FIRST, 0, '问题 0', config=cfg)
                self.assertEqual(fx.result().state, 'workspace_verified')

        # Invalid enum values, unknown subfield, or wrong wire type on 46.9 MUST fail closed.
        invalid_policies = [
            message((1, 3)),          # out-of-range enum on unknown_component_policy
            message((2, 3)),          # out-of-range enum on empty_component_policy
            message((1, 99)),         # unknown large enum
            message((3, 1)),          # unknown subfield 46.9.3
            message((1, b'IGNORE')),  # wrong wire type (bytes instead of varint)
        ]
        for bad_policy in invalid_policies:
            with self.subTest(bad_policy=bad_policy):
                cfg = message((1, message((46, message((9, bad_policy))))))
                self._set_exec_config(fx, cfg)
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertEqual(obs.reason, 'native_lineage_or_workspace_override')
                self.assertIn('.46.9', obs.detail)
                with self.assertRaises(AccessError) as exc:
                    fx.reader.snapshot_for_inheritance(fx.thread)
                self.assertEqual(exc.exception.code, 'association_unverified')
                self.assertNotIn('46.9', str(exc.exception))

    def test_audited_harmless_233_to_236_fields_validate_strictly(self):
        fx = self._fixture()
        # Valid audited harmless fields across CascadeConfig, CascadePlannerConfig,
        # CustomizationDiscoveryConfig (2.36 field 14 restricted to UNSPECIFIED/NONE),
        # CascadeToolConfig, and ExecutorMetadata (.exa.cortex_pb.SensitivityLevel).
        media = message((1, 2048), (2, 1048576), (3, 85), (4, 65536))
        model_or_alias = message((1, 42))
        plan_exec = message((1, 42))
        disc = message((14, 2))  # CUSTOMIZATION_INHERITANCE_MODE_NONE
        tools = message((29, 1), (43, 30), (46, 0), (49, 0), (50, 1), (51, 1))
        planner = message(
            (13, tools),
            (14, 128000),
            (15, model_or_alias),
            (25, 1),
            (46, message((9, message((1, 1))))),
            (48, 1),
            (55, 0),
            (57, disc),
            (60, plan_exec),
            (61, 'zh-CN'),
        )
        cfg = message((1, planner), (6, 1), (8, 1), (10, 1), (14, media))
        resolution = message((1, desktop_spec()), (3, b''))
        # .exa.cortex_pb.SensitivityLevel: 0 (UNSPECIFIED) and 1 (STANDARD) MUST pass!
        for safe_level in (0, 1):
            with self.subTest(sensitivity_level=safe_level):
                exec_blob = message(
                    (1, 4), (2, 1), (3, 1), (4, 1), (5, 0), (9, FIRST),
                    (10, cfg), (13, 0), (16, resolution), (19, safe_level),
                )
                fx.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0', (exec_blob,))
                fx.db.commit()
                obs = fx.result()
                self.assertEqual(obs.state, 'workspace_verified', obs)

        # Invalid scalar bounds/wire-types/oneof/org-inheritance on audited fields MUST fail closed.
        invalid_cases = [
            ('bad_bool_cc6', message((6, 2))),
            ('bad_media_extra', message((14, message((5, 1))))),
            ('bad_model_dual_oneof', message((1, message((15, message((1, 42), (2, 1))))))),
            ('bad_disc_all_1', message((1, message((57, message((14, 1))))))),
            ('bad_disc_org_3', message((1, message((57, message((14, 3))))))),
            ('bad_disc_enum_4', message((1, message((57, message((14, 4))))))),
            ('bad_lang_path', message((1, message((61, '/etc/passwd'))))),
            ('bad_lang_ctrl', message((1, message((61, 'en-US\n<SYSTEM>'))))),
            ('bad_lang_unicode_bidi', message((1, message((61, 'en-US\u202e'))))),
            ('bad_lang_long', message((1, message((61, 'a' * 65))))),
            ('bad_lang_utf8', message((1, message((61, b'\xff\xfe'))))),
            ('bad_tool_bool', message((1, message((13, message((49, 2))))))),
            ('bad_plan_exec_extra', message((1, message((60, message((2, 1))))))),
        ]
        for label, bad_cfg in invalid_cases:
            with self.subTest(case=label):
                self._set_exec_config(fx, bad_cfg)
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertTrue(obs.detail, f'expected diagnostic detail for {label}')

        # Elevated sensitivity (2=REDACTED, 3=RESTRICTED) and wrong-namespace values
        # (50, 100, 700) on ExecutorMetadata.19 MUST fail closed with zero detail leak.
        for blocked_level in (2, 3, 50, 100, 700):
            with self.subTest(blocked_sensitivity=blocked_level):
                bad_sens = message((1, 4), (2, 1), (3, 1), (9, FIRST), (16, resolution), (19, blocked_level))
                fx.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0', (bad_sens,))
                fx.db.commit()
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertIn(f'executor[0].19={blocked_level}', obs.detail)
                with self.assertRaises(AccessError) as exc:
                    fx.reader.snapshot_for_inheritance(fx.thread)
                self.assertEqual(exc.exception.code, 'association_unverified')
                self.assertNotIn('executor[0].19', str(exc.exception))

    def test_v2_http_antigravity_sensitivity_standard_reads_and_redacted_restricted_fail_closed(self):
        fx = self._fixture(live_clock=True)
        base = fx.project.parent
        control = base / 'v2-sens-control'
        control.mkdir(mode=0o700)
        ag_root = fx.db_path.parent.parent
        settings = AccessSettings(
            'https://test-team.cloudflareaccess.com', 'a' * 64,
            'mcp.example.com', ('owner@example.com',),
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        token = jwt.encode(
            {'iss': settings.team_domain, 'aud': [settings.audience], 'iat': now - 1,
             'exp': now + 300, 'email': 'owner@example.com', 'sub': 'owner'},
            key, algorithm='RS256', headers={'kid': 'v057-sens-key'},
        )
        store = initialize_store(control / 'generations')
        desc = control / 'policy.json'
        doc = {
            'version': 2,
            'projects': [
                {'id': 'alpha', 'name': 'Alpha', 'root': str(fx.project),
                 'directory_identity': persistent_identity(fx.project)},
            ],
            'sources': {
                'antigravity': {
                    'adapter': 'antigravity', 'root': str(ag_root), 'format': '2.33.0',
                    'enabled': True, 'instance_id': 'ag-inst',
                    'root_identity': persistent_identity(ag_root),
                },
            },
            'legacy_history': None,
        }
        pv, dg = preview_activation(doc)
        activate_preview(store, pv, dg, initial=True)
        write_descriptor(desc, store)
        policy = AgentPolicy(desc, mode='v2')
        scratch = control / 'scratch'
        scratch.mkdir(mode=0o700)
        policy.scratch = scratch
        app = build_app(Catalog.from_policy(policy), settings, agent_policy=policy)
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())

        def call_ready(client, name, args):
            cur = dict(args)
            for idx in range(40):
                resp = client.post(
                    '/mcp',
                    headers={
                        'Accept': 'application/json, text/event-stream',
                        'MCP-Protocol-Version': '2025-03-26',
                        'cf-access-jwt-assertion': token,
                    },
                    json={'jsonrpc': '2.0', 'id': idx + 1, 'method': 'tools/call',
                          'params': {'name': name, 'arguments': cur}},
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                res = resp.json()['result']
                page = json.loads(res['content'][0]['text'])
                if page.get('status') != 'processing':
                    return page
                cur = {**args, 'cursor': page['next_cursor']}
                time.sleep(0.01)
            self.fail(f'{name} did not finish')

        resolution = message((1, desktop_spec()), (3, b''))
        with TestClient(app, base_url='https://mcp.example.com') as client:
            # 1. STANDARD (1) on ExecutorMetadata.19 MUST find and read all 4 messages via v2 HTTP!
            fx.db.execute(
                'UPDATE executor_metadata SET data=? WHERE idx=0',
                (message((1, 4), (2, 1), (3, 1), (9, FIRST), (16, resolution), (19, 1)),),
            )
            fx.db.commit()
            found = call_ready(client, 'find_agent_threads', {
                'project_id': 'alpha', 'source_id': 'antigravity',
                'query': 'Synthetic two-turn UI thread', 'limit': 5,
            })
            self.assertEqual(found['status'], 'ready', found)
            self.assertTrue(found['coverage_complete'], found)
            self.assertEqual(len(found['threads']), 1, found)
            read = call_ready(client, 'read_agent_thread', {
                'thread_ref': found['threads'][0]['thread_ref'],
            })
            self.assertEqual(read['status'], 'ready', read)
            self.assertEqual(len(read['entries']), 4)

            # 2. REDACTED (2) and RESTRICTED (3) MUST return 0 hits + association_unverified!
            for blocked in (2, 3):
                fx.db.execute(
                    'UPDATE executor_metadata SET data=? WHERE idx=0',
                    (message((1, 4), (2, 1), (3, 1), (9, FIRST), (16, resolution), (19, blocked)),),
                )
                fx.db.commit()
                denied = call_ready(client, 'find_agent_threads', {
                    'project_id': 'alpha', 'source_id': 'antigravity',
                    'query': 'Synthetic two-turn UI thread', 'limit': 5,
                })
                self.assertEqual(denied['threads'], [], (blocked, denied))
                self.assertFalse(denied['coverage_complete'])
                self.assertEqual(denied['coverage'][0]['state'], 'association_unverified')
                self.assertNotIn('executor[0].19', json.dumps(denied))

    def test_all_redline_and_unknown_fields_remain_strictly_fail_closed_with_private_diagnostics(self):
        fx = self._fixture()
        resolution = message((1, desktop_spec()), (3, b''))
        redline_configs = [
            ('cc_dynamic_ws_12', message((12, 'file:///other')), '.12'),
            ('cc_unknown_99', message((99, 1)), '.99'),
            ('planner_conversational_2', message((1, message((2, b'alt')))), '.1.2'),
            ('planner_google_26', message((1, message((26, b'alt')))), '.1.26'),
            ('planner_model_override_27', message((1, message((27, message((11, 'https://evil')))))), '.1.27'),
            ('planner_custom_agent_39', message((1, message((39, b'agent')))), '.1.39'),
            ('planner_custom_agent_uri_40', message((1, message((40, 'file:///agent')))), '.1.40'),
            ('planner_prompt_override_41', message((1, message((41, b'prompt')))), '.1.41'),
            ('planner_customization_42', message((1, message((42, b'override')))), '.1.42'),
            ('planner_loop_msg_54', message((1, message((54, 'inject text')))), '.1.54'),
            ('planner_completion_56', message((1, message((56, message((18, 1)))))), '.1.56'),
            ('planner_unknown_99', message((1, message((99, 1)))), '.1.99'),
            ('mixin_providers_46_1', message((1, message((46, message((1, b'prov')))))), '.46.1'),
            ('mixin_resolved_46_12', message((1, message((46, message((12, b'cust')))))), '.46.12'),
            ('mixin_unknown_46_99', message((1, message((46, message((99, 1)))))), '.46.99'),
            ('disc_mcp_57_3', message((1, message((57, message((3, b'mcp')))))), '.57.3'),
            ('disc_override_ws_57_6', message((1, message((57, message((6, '/other')))))), '.57.6'),
            ('disc_agent_path_57_8', message((1, message((57, message((8, '/agent')))))), '.57.8'),
            ('disc_plugin_57_10', message((1, message((57, message((10, 'plug')))))), '.57.10'),
            ('tool_desc_override_13_22', message((1, message((13, message((22, b'desc')))))), '.13.22'),
            ('tool_ws_api_13_37', message((1, message((13, message((37, b'ws')))))), '.13.37'),
            ('tool_skill_search_13_47', message((1, message((13, message((47, b'skill')))))), '.13.47'),
        ]
        for label, bad_cfg, expected_site in redline_configs:
            with self.subTest(case=label):
                self._set_exec_config(fx, bad_cfg)
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertIn(expected_site, obs.detail)
                with self.assertRaises(AccessError) as exc:
                    fx.reader.snapshot_for_inheritance(fx.thread)
                self.assertEqual(exc.exception.code, 'association_unverified')
                self.assertNotIn(expected_site, str(exc.exception))

        # ExecutorMetadata redline fields 8 (gen_svc_request), 14/15 (snapshots), 99 (unknown).
        for field_no in (8, 14, 15, 99):
            with self.subTest(exec_field=field_no):
                bad_exec = message((1, 4), (2, 1), (3, 1), (9, FIRST), (16, resolution), (field_no, b'opaque'))
                fx.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0', (bad_exec,))
                fx.db.commit()
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertIn(f'executor[0].{field_no}', obs.detail)
                with self.assertRaises(AccessError) as exc:
                    fx.reader.snapshot_for_inheritance(fx.thread)
                self.assertEqual(exc.exception.code, 'association_unverified')
                self.assertNotIn(f'executor[0].{field_no}', str(exc.exception))

    def test_unified_executor_termination_reasons_and_strict_invocation_accounting(self):
        fx = self._fixture()
        resolution = message((1, desktop_spec()), (3, b''))

        # Add a third turn interrupted by USER_CANCELED (2) without execution_error (field 12):
        # step 4 = SYSTEM_MESSAGE (non-public), gen_metadata[2] has positions=b'' and error(5)='canceled'.
        third_exec = str(uuid.UUID(int=99))
        at = message((1, SECONDS))
        origin = message((1, TRAJECTORY), (2, 4), (3, 2), (4, SESSION))
        life = message((1, message((1, 3), (2, at))))
        s_meta = message((1, at), (3, 5), (12, third_exec), (20, origin), (26, life))
        s_payload = message((1, 101), (4, 3), (5, s_meta), (114, message((3, 'system_notice'))))
        fx.db.execute('INSERT INTO steps VALUES(4,101,3,0,?,?,0)', (s_meta, s_payload))
        fx.db.execute(
            'INSERT INTO gen_metadata VALUES(2,?)',
            (message((2, b''), (4, third_exec), (5, 'canceled')),),
        )
        fx.index.execute('UPDATE conversation_summaries SET step_count=5')
        fx.index.commit()

        # Legitimate non-normal terminal statuses {1, 2, 3, 6, 7, 8, 11} pass when every
        # invocation is accounted for by gen_metadata (counts=0, err_counts=1, exp=1).
        for status_code in (1, 2, 3, 6, 7, 8, 11):
            with self.subTest(allowed_status=status_code):
                exec_blob = message((1, status_code), (2, 1), (3, 4), (9, third_exec), (16, resolution))
                fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (exec_blob,))
                fx.db.commit()
                obs = fx.result()
                self.assertEqual(obs.state, 'workspace_verified', obs)

        # Unaccounted invocation on status=2 (exp=2 while ok=0, err=1, no field 12) MUST fail closed!
        forged_count = message((1, 2), (2, 2), (3, 4), (9, third_exec), (16, resolution))
        fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (forged_count,))
        fx.db.commit()
        obs = fx.result()
        self.assertEqual(obs.state, 'unverified')
        self.assertEqual(obs.reason, 'native_invocations_mismatch')
        self.assertIn('exp=2,ok=0,err=1', obs.detail)

        # Zero-invocation status in {3, 6, 7, 8, 11} without field 12 MUST fail closed!
        fx.db.execute('DELETE FROM gen_metadata WHERE idx=2')
        for non_zero_status in (3, 6, 7, 8, 11):
            with self.subTest(zero_inv_status=non_zero_status):
                zero_exec = message((1, non_zero_status), (2, 0), (3, 4), (9, third_exec), (16, resolution))
                fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (zero_exec,))
                fx.db.commit()
                self.assertEqual(fx.result().reason, 'native_invocations_mismatch')
        # Restore gen_metadata[2] for remaining assertions.
        fx.db.execute(
            'INSERT INTO gen_metadata VALUES(2,?)',
            (message((2, b''), (4, third_exec), (5, 'canceled')),),
        )
        fx.db.commit()

        # Status=1 (ERROR) without field 12 AND without any err_counts MUST fail closed!
        fx.db.execute('UPDATE gen_metadata SET data=? WHERE idx=2', (message((2, b''), (4, third_exec)),))
        err_no_proof = message((1, 1), (2, 1), (3, 4), (9, third_exec), (16, resolution))
        fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (err_no_proof,))
        fx.db.commit()
        self.assertEqual(fx.result().reason, 'native_invocations_mismatch')

        # Restore errored gen_metadata[2] and verify redline workspace override on status=2 STILL fails closed!
        fx.db.execute('UPDATE gen_metadata SET data=? WHERE idx=2', (message((2, b''), (4, third_exec), (5, 'canceled')),))
        canceled_with_override = message(
            (1, 2), (2, 1), (3, 4), (9, third_exec),
            (10, message((12, 'file:///other'))), (16, resolution),
        )
        fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (canceled_with_override,))
        fx.db.commit()
        self.assertEqual(fx.result().reason, 'native_dynamic_workspace_history_unverified')

        # Forbidden termination reasons (0=UNSPECIFIED, 5=invalid, 9=CUSTOM_HOOK,
        # 10=INJECTED_RESPONSE, 12=CHAINED, 99=unknown) MUST fail closed even with field 12!
        for forbidden_status in (0, 5, 9, 10, 12, 99):
            with self.subTest(forbidden_status=forbidden_status):
                bad_exec = message(
                    (1, forbidden_status), (2, 1), (3, 4), (9, third_exec),
                    (12, 'synthetic error'), (16, resolution),
                )
                fx.db.execute('INSERT OR REPLACE INTO executor_metadata VALUES(2,?)', (bad_exec,))
                fx.db.commit()
                obs = fx.result()
                self.assertEqual(obs.state, 'unverified')
                self.assertEqual(obs.reason, 'native_execution_mismatch')
                self.assertIn(f'termination_reason={forbidden_status}', obs.detail)
                with self.assertRaises(AccessError) as exc:
                    fx.reader.snapshot_for_inheritance(fx.thread)
                self.assertEqual(exc.exception.code, 'association_unverified')
                self.assertNotIn('termination_reason', str(exc.exception))

    def test_active_write_index_lag_returns_retryable_waiting_source_stable_and_truncation_fails_closed(self):
        fx = self._fixture()
        # Case 1: index_step_count (2) < actual DB step count (4) -> retryable waiting_source_stable!
        fx.index.execute('UPDATE conversation_summaries SET step_count=2')
        fx.index.commit()
        obs = fx.result()
        self.assertEqual(obs.state, 'unverified')
        self.assertEqual(obs.reason, 'native_index_lagging')
        self.assertIn('steps.count>index.step_count(index=2)', obs.detail)
        with self.assertRaises(AccessError) as exc:
            fx.reader.snapshot_for_inheritance(fx.thread)
        self.assertEqual(exc.exception.code, 'waiting_source_stable')
        self.assertNotIn('index_lag', str(exc.exception))
        with self.assertRaises(AccessError) as exc_iter:
            _finish(fx.reader.snapshot_for_inheritance_iter(fx.thread))
        self.assertEqual(exc_iter.exception.code, 'waiting_source_stable')

        # Case 2: index_step_count (6) > actual DB step count (4) -> permanent association_unverified!
        fx.index.execute('UPDATE conversation_summaries SET step_count=6')
        fx.index.commit()
        obs_trunc = fx.result()
        self.assertEqual(obs_trunc.state, 'unverified')
        self.assertEqual(obs_trunc.reason, 'native_step_sequence_mismatch')
        with self.assertRaises(AccessError) as exc_trunc:
            fx.reader.snapshot_for_inheritance(fx.thread)
        self.assertEqual(exc_trunc.exception.code, 'association_unverified')

    def test_mid_run_interrupting_user_input_validates_strictly_and_blocks_forged_backdating(self):
        fx = self._fixture()
        # Build a single-execution 4-step trajectory where step 2 is a legitimate mid-execution
        # queued/interrupting USER_INPUT created before step 1's created_at (SECONDS + 5)
        # and dequeued/committed at SECONDS + 10.
        fx.db.execute('DELETE FROM steps')
        fx.db.execute('DELETE FROM executor_metadata')
        fx.db.execute('DELETE FROM gen_metadata')
        fx.logs = []

        u0_text = 'Initial question'
        u0_wrap = f'<USER_REQUEST>\n{u0_text}\n</USER_REQUEST>\n<ADDITIONAL_METADATA>h</ADDITIONAL_METADATA>'
        a1_text = 'First partial answer'
        u2_text = 'Queued follow-up mid-run'
        u2_wrap = f'<USER_REQUEST>\n{u2_text}\n</USER_REQUEST>\n<ADDITIONAL_METADATA>h</ADDITIONAL_METADATA>'
        a3_text = 'Final answer after mid-run input'

        fx.logs = [
            dict(step_index=0, type='USER_INPUT', source='USER_EXPLICIT', status='DONE', created_at=native.TIME, content=u0_wrap),
            dict(step_index=1, type='PLANNER_RESPONSE', source='MODEL', status='DONE', created_at=native.TIME, content=a1_text),
            dict(step_index=2, type='USER_INPUT', source='USER_EXPLICIT', status='DONE', created_at=native.TIME, content=u2_wrap),
            dict(step_index=3, type='PLANNER_RESPONSE', source='MODEL', status='DONE', created_at=native.TIME, content=a3_text),
        ]
        fx.write_logs()
        fx.write_step(0, FIRST, 0, u0_text, created=SECONDS + 1)
        fx.write_step(1, FIRST, 0, a1_text, created=SECONDS + 5, finished=SECONDS + 8, completed=SECONDS + 9,
                      transitions=((8, message((1, SECONDS + 6))), (3, message((1, SECONDS + 9)))))

        def write_mid_user(*, created=SECONDS + 3, started=SECONDS + 10, completed=SECONDS + 10,
                           spec=None, config=b'', include_times=True):
            t_cr = message((1, created))
            t_st = message((1, started))
            t_co = message((1, completed))
            origin = message((1, TRAJECTORY), (2, 2), (3, 0), (4, SESSION))
            life = message((1, message((1, 3), (2, t_co))))
            extra_meta = [(8, t_co), (32, t_st), (33, 1)] if include_times else []
            meta = message((1, t_cr), (3, 4), (12, FIRST), (20, origin), (26, life), *extra_meta)
            pub = message((2, u2_text), (3, message((1, u2_text))), (12, config),
                          (18, desktop_spec() if spec is None else spec))
            pay = message((1, 14), (4, 3), (5, meta), (19, pub))
            fx.db.execute('INSERT OR REPLACE INTO steps VALUES(2,14,3,0,?,?,0)', (meta, pay))
            fx.db.commit()

        write_mid_user()
        fx.write_step(3, FIRST, 1, a3_text, created=SECONDS + 11, finished=SECONDS + 12, completed=SECONDS + 12,
                      transitions=((8, message((1, SECONDS + 11))), (3, message((1, SECONDS + 12)))))
        resolution = message((1, desktop_spec()), (3, b''))
        fx.db.execute('INSERT INTO executor_metadata VALUES(0,?)',
                      (message((1, 4), (2, 2), (3, 3), (9, FIRST), (16, resolution)),))
        fx.db.execute('INSERT INTO gen_metadata VALUES(0,?)', (fx.invocation(FIRST, 1, u0_wrap, 0),))
        fx.db.execute('INSERT INTO gen_metadata VALUES(1,?)', (fx.invocation(FIRST, 3, u2_wrap, 2),))
        fx.db.commit()

        obs = fx.result()
        self.assertEqual(obs.state, 'workspace_verified', obs)

        # Adversarial cases: missing started/completed, backdated before birth, commit before
        # prior step, swapped desktop spec, or dynamic workspace override MUST all fail closed!
        for label, kw in (
            ('missing_times', {'include_times': False}),
            ('before_birth', {'created': SECONDS - 1}),
            ('commit_before_prev_created', {'created': SECONDS + 2, 'started': SECONDS + 3, 'completed': SECONDS + 4}),
            ('commit_before_prev_commit', {'created': SECONDS + 3, 'started': SECONDS + 6, 'completed': SECONDS + 7}),
            ('swapped_spec', {'spec': desktop_spec(is_google=1)}),
            ('workspace_override', {'config': message((12, 'file:///other'))}),
        ):
            with self.subTest(case=label):
                write_mid_user(**kw)
                self.assertEqual(fx.result().state, 'unverified')


class LargeProjectTwoPhaseSearchAndConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.base = Path(self.tmp).resolve()
        os.chmod(self.base, 0o700)
        self.alpha = self.base / 'alpha-project'
        self.beta = self.base / 'beta-other'
        self.codex_home = self.base / 'codex-home'
        self.control = self.base / 'control'
        for directory in (self.alpha, self.beta, self.codex_home / 'sessions', self.control):
            directory.mkdir(parents=True, mode=0o700)

        self.target_title = '大项目标题检索合成样本三一五'
        self.target_id = 'ffffffff-0000-4000-8000-000000000315'
        self.newest_body_id = '00000000-0000-4000-8000-000000000005'
        self.newest_body_marker = 'SYNTHETIC_UNIQUE_BODY_NEEDLE_20261128'
        self.total_alpha = 320
        self.total_beta = 10

        now_sec = int(time.time())
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.codex_home / 'state_5.sqlite') as db:
            db.execute(
                'CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, '
                'title TEXT, updated_at INTEGER, archived INTEGER)'
            )
            for idx in range(self.total_alpha):
                if idx == 315:
                    tid = self.target_id
                    title = self.target_title
                    body_u = '合成客户端渲染帧率波动，请排查队列调度策略'
                    body_a = '已定位到合成渲染队列阻塞，建议调整预取窗口参数。'
                    updated = now_sec - 5000  # Deliberately older + last UUID!
                elif idx == 5:
                    tid = self.newest_body_id
                    title = f'Synthetic regular session #{idx:03d}'
                    body_u = f'Investigate {self.newest_body_marker} in newest rollout'
                    body_a = 'Confirmed synthetic body needle.'
                    updated = now_sec - 10  # Very recent
                else:
                    tid = f'{idx:08x}-0000-4000-8000-000000000000'
                    title = f'Synthetic regular session #{idx:03d}'
                    body_u = f'Routine engineering question #{idx:03d} ' + ('padding ' * 40)
                    body_a = f'Routine engineering answer #{idx:03d} ' + ('details ' * 40)
                    updated = now_sec - 100 - idx
                rp = self.codex_home / 'sessions' / f'rollout-{tid}.jsonl'
                rp.write_bytes(codex_encode([
                    {**row, 'timestamp': now_iso}
                    for row in (
                        codex_record('session_meta', {'id': tid, 'cwd': str(self.alpha), 'timestamp': now_iso}),
                        codex_record('event_msg', {'type': 'task_started', 'turn_id': f'turn-{idx}'}),
                        codex_message(body_u),
                        codex_message(body_a, 'assistant', 'final', native_id=f'ans-{idx}'),
                        codex_record('event_msg', {'type': 'task_complete', 'turn_id': f'turn-{idx}'}),
                    )
                ]))
                db.execute('INSERT INTO threads VALUES (?,?,?,?,?,0)', (tid, str(rp), str(self.alpha), title, updated))

            for bidx in range(self.total_beta):
                tid = f'bbbbbbbb-0000-4000-8000-{bidx:012d}'
                rp = self.codex_home / 'sessions' / f'rollout-{tid}.jsonl'
                rp.write_bytes(codex_encode([
                    {**row, 'timestamp': now_iso}
                    for row in (
                        codex_record('session_meta', {'id': tid, 'cwd': str(self.beta), 'timestamp': now_iso}),
                        codex_message(f'Foreign secret {self.target_title}'),
                        codex_message('Foreign reply', 'assistant', 'final', native_id=f'b-{bidx}'),
                    )
                ]))
                db.execute(
                    'INSERT INTO threads VALUES (?,?,?,?,?,0)',
                    (tid, str(rp), str(self.beta), self.target_title, now_sec - bidx),
                )
            db.commit()

    def _http_client(self, mode):
        settings = AccessSettings(
            'https://test-team.cloudflareaccess.com', 'a' * 64,
            'mcp.example.com', ('owner@example.com',),
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        token = jwt.encode(
            {'iss': settings.team_domain, 'aud': [settings.audience], 'iat': now - 1,
             'exp': now + 300, 'email': 'owner@example.com', 'sub': 'owner'},
            key, algorithm='RS256', headers={'kid': 'v057-test-key'},
        )
        actor = actor_digest(settings.team_domain, 'owner')
        if mode == 'v1':
            proj_cfg = self.base / 'projects-v1.json'
            proj_cfg.write_text(json.dumps({'projects': [
                {'id': 'alpha', 'name': 'Alpha', 'root': str(self.alpha)},
                {'id': 'beta', 'name': 'Beta', 'root': str(self.beta)},
            ]}))
            hist_cfg = self.base / 'history-v1.json'
            policy_cfg = self.base / 'agent-policy-v1.json'

            def write_v1(denied=()):
                hist_cfg.write_text(json.dumps({
                    'version': 2,
                    'codex_home': str(self.codex_home),
                    'state_db': 'state_5.sqlite',
                    'inherit_projects': True,
                    'denied_threads': list(denied),
                    'threads': [],
                }))
                policy_cfg.write_text(json.dumps({'version': 1, 'sources': {}}))

            write_v1()
            catalog = Catalog.from_config(proj_cfg)
            app = build_app(
                catalog, settings,
                history=HistoryAccess(hist_cfg, catalog=catalog),
                agent_policy=AgentPolicy(policy_cfg),
            )
            update_denied = write_v1
        else:
            control_dir = Path(tempfile.mkdtemp(dir=self.base, prefix='ctrl-v2-'))
            os.chmod(control_dir, 0o700)
            store = initialize_store(control_dir / 'generations')
            desc = control_dir / 'policy.json'

            def write_v2(denied=()):
                doc = {
                    'version': 2,
                    'projects': [
                        {'id': 'alpha', 'name': 'Alpha', 'root': str(self.alpha),
                         'directory_identity': persistent_identity(self.alpha)},
                        {'id': 'beta', 'name': 'Beta', 'root': str(self.beta),
                         'directory_identity': persistent_identity(self.beta)},
                    ],
                    'sources': {
                        'codex': {
                            'adapter': 'codex', 'root': str(self.codex_home), 'format': 'state_5',
                            'enabled': True, 'instance_id': 'codex-inst',
                            'root_identity': persistent_identity(self.codex_home),
                            'denied_threads': list(denied),
                        },
                    },
                    'legacy_history': {
                        'codex_home': str(self.codex_home), 'state_db': 'state_5.sqlite', 'tool_evidence': [],
                    },
                }
                pv, dg = preview_activation(doc, previous=store.snapshot() if desc.exists() else None)
                activate_preview(store, pv, dg, initial=not desc.exists())
                if not desc.exists():
                    write_descriptor(desc, store)

            write_v2()
            policy = AgentPolicy(desc, mode='v2')
            scratch = Path(tempfile.mkdtemp(dir=self.base, prefix='sc-v2-'))
            os.chmod(scratch, 0o700)
            policy.scratch = scratch
            app = build_app(Catalog.from_policy(policy), settings, agent_policy=policy)
            update_denied = write_v2

        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        return app, token, update_denied

    def _run_tool_ready(self, client, token, name, arguments):
        counter = [0]

        def call(args):
            counter[0] += 1
            resp = client.post(
                '/mcp',
                headers={
                    'Accept': 'application/json, text/event-stream',
                    'MCP-Protocol-Version': '2025-03-26',
                    'cf-access-jwt-assertion': token,
                },
                json={'jsonrpc': '2.0', 'id': counter[0], 'method': 'tools/call',
                      'params': {'name': name, 'arguments': args}},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            body = resp.json()
            self.assertNotIn('error', body)
            return body['result']

        cur_args = dict(arguments)
        for _ in range(40):
            res = call(cur_args)
            if res.get('isError'):
                return res
            page = json.loads(res['content'][0]['text'])
            if page.get('status') != 'processing':
                return page
            cur_args = {**arguments, 'cursor': page['next_cursor']}
            time.sleep(0.01)
        self.fail(f'{name} did not reach terminal status in bounded polls')

    def test_320_thread_codex_project_title_body_browse_and_revocation_in_v1_and_v2(self):
        for mode in ('v1', 'v2'):
            with self.subTest(mode=mode):
                app, token, update_denied = self._http_client(mode)
                with TestClient(app, base_url='https://mcp.example.com') as client:
                    # 1. Exact title search hits target at UUID index #315 (beyond MAX_SEARCH=256)
                    #    and NEVER leaks the identically-titled foreign beta threads.
                    found = self._run_tool_ready(client, token, 'find_agent_threads', {
                        'project_id': 'alpha', 'source_id': 'codex', 'query': self.target_title, 'limit': 10,
                    })
                    self.assertEqual(found['status'], 'ready', found)
                    self.assertEqual(len(found['threads']), 1, found)
                    hit = found['threads'][0]
                    self.assertEqual(hit['title'], self.target_title)
                    self.assertEqual(hit['project_id'], 'alpha')
                    self.assertEqual(hit['match'], {'in': 'title', 'mode': 'substring'})
                    # Honest coverage reporting: 319 non-title threads exceeded MAX_SEARCH=256 body cap.
                    self.assertFalse(found['coverage_complete'])
                    self.assertIn('resource_exhausted', found['coverage'][0]['warnings'])

                    # 2. Read target via latest_turn and paginated all-view.
                    latest = self._run_tool_ready(client, token, 'read_agent_thread', {
                        'thread_ref': hit['thread_ref'], 'view': 'latest_turn',
                    })
                    self.assertEqual(latest['status'], 'ready')
                    self.assertEqual([e['role'] for e in latest['entries']], ['user', 'assistant'])
                    self.assertIn('队列调度策略', latest['entries'][0]['text'])
                    self.assertIn('预取窗口参数', latest['entries'][1]['text'])

                    first_page = self._run_tool_ready(client, token, 'read_agent_thread', {
                        'thread_ref': hit['thread_ref'], 'limit': 1,
                    })
                    self.assertTrue(first_page['has_more'])

                    # 3. Body-only search scans newest non-title threads first and hits #5.
                    body_found = self._run_tool_ready(client, token, 'find_agent_threads', {
                        'project_id': 'alpha', 'source_id': 'codex', 'query': self.newest_body_marker, 'limit': 10,
                    })
                    self.assertEqual(body_found['status'], 'ready')
                    self.assertEqual(len(body_found['threads']), 1)
                    self.assertEqual(body_found['threads'][0]['match']['in'], 'visible_message')
                    self.assertFalse(body_found['coverage_complete'])
                    self.assertIn('resource_exhausted', body_found['coverage'][0]['warnings'])

                    # 4. Browse (query='') returns newest threads first without timing out.
                    browsed = self._run_tool_ready(client, token, 'find_agent_threads', {
                        'project_id': 'alpha', 'source_id': 'codex', 'query': '', 'limit': 5,
                    })
                    self.assertEqual(browsed['status'], 'ready')
                    self.assertEqual(len(browsed['threads']), 5)
                    self.assertEqual(browsed['threads'][0]['title'], 'Synthetic regular session #005')
                    self.assertFalse(browsed['coverage_complete'])

                    # 5. Mid-read revocation fails closed for BOTH find_agent_threads and continuation read.
                    update_denied(denied=(self.target_id,))
                    revoked_read = self._run_tool_ready(client, token, 'read_agent_thread', {
                        'thread_ref': hit['thread_ref'], 'limit': 1, 'cursor': first_page['next_cursor'],
                    })
                    self.assertNotIn('预取窗口参数', json.dumps(revoked_read, ensure_ascii=False))
                    if isinstance(revoked_read, dict) and not revoked_read.get('isError'):
                        self.assertIn(revoked_read.get('status'), ('unauthorized', 'restart_required'))
                    after_revoke = self._run_tool_ready(client, token, 'find_agent_threads', {
                        'project_id': 'alpha', 'source_id': 'codex', 'query': self.target_title, 'limit': 10,
                    })
                    self.assertEqual(after_revoke['status'], 'ready')
                    self.assertEqual(after_revoke['threads'], [])

    def test_non_codex_adapter_prioritizes_title_match_beyond_max_search(self):
        catalog = Catalog([Project('main', 'Main', self.alpha, True)])
        actor = 'a' * 64
        source = SimpleNamespace(
            adapter='codeg', format='0.45.0', enabled=True, inherit=True,
            instance_id='codeg', threads={}, exceptions={}, denied=frozenset(),
            links={}, link_instances={},
        )
        source.allows = lambda who, proj: who == actor
        policy = SimpleNamespace(
            mode='v2', version=2, config=lambda: ({'codeg': source}, 'gen-1'),
            allows_actor=lambda who: who == actor, excludes=lambda p: False,
            make_root=lambda name, src: None,
        )
        core = AgentHistoryCore(policy, catalog, SimpleNamespace(config_path=None), b'k' * 32)
        target = Thread(
            'thread-target-310', 'Exact Non-Codex Title Target',
            updated_at='2026-01-01T00:00:00+00:00',
            contexts=(str(self.alpha),), context_complete=True,
            agent='custom:test', surface='codeg_acp',
        )
        candidates = [
            Thread(
                f'other-{i:04d}', f'Unrelated title {i}',
                updated_at=f'2026-06-{(i % 28) + 1:02d}T00:00:00+00:00',
                contexts=(str(self.alpha),), context_complete=True,
                agent='custom:test', surface='codeg_acp',
            )
            for i in range(MAX_SEARCH + 50)
        ] + [target]
        adapter = SimpleNamespace(
            project_partition_complete=True, warnings=(),
            discover_project=lambda roots, **kw: iter(candidates),
            describe=lambda nid: target if nid == target.native_id else next(c for c in candidates if c.native_id == nid),
            snapshot=lambda t: Projection(
                (Message('user', f'Body for {t.native_id}', 'seq:1'),),
                f'rev-{t.native_id}', f'id-{t.native_id}',
                contexts=(str(self.alpha),), context_complete=True,
            ),
        )
        with patch('peters_mcp.agent_history._adapter', return_value=adapter):
            res = _finish(core._find('main', 'Exact Non-Codex Title Target', '', 'codeg', '', 10, actor, actor))
        self.assertEqual(res['status'], 'ready')
        self.assertEqual(len(res['threads']), 1)
        self.assertEqual(res['threads'][0]['title'], 'Exact Non-Codex Title Target')
        self.assertEqual(res['threads'][0]['match'], {'in': 'title', 'mode': 'substring'})
        self.assertFalse(res['coverage_complete'])
        self.assertIn('resource_exhausted', res['coverage'][0]['warnings'])

    def test_concurrent_same_source_requests_avoid_single_slot_busy_and_forget_cursor_is_scoped(self):
        # Build a small v1 AgentHistoryService and verify two concurrent requests on codex
        # both complete without false busy lockout, and _abandon forgets only the targeted cursor.
        proj_cfg = self.base / 'projects-conc.json'
        proj_cfg.write_text(json.dumps({'projects': [{'id': 'alpha', 'name': 'Alpha', 'root': str(self.alpha)}]}))
        hist_cfg = self.base / 'history-conc.json'
        hist_cfg.write_text(json.dumps({
            'version': 2, 'codex_home': str(self.codex_home), 'state_db': 'state_5.sqlite',
            'inherit_projects': True, 'denied_threads': [], 'threads': [],
        }))
        policy_cfg = self.base / 'agent-policy-conc.json'
        policy_cfg.write_text(json.dumps({'version': 1, 'sources': {}}))
        catalog = Catalog.from_config(proj_cfg)
        legacy = HistoryAccess(hist_cfg, catalog=catalog)
        service = AgentHistoryService(AgentPolicy(policy_cfg), legacy, local=True)
        self.addCleanup(service.close)

        results = {}
        errors = []

        def run_query(slot_name, q):
            try:
                cursor = ''
                for _ in range(40):
                    page = service.find_agent_threads('alpha', query=q, source_id='codex', cursor=cursor, limit=5)
                    if page['status'] != 'processing':
                        results[slot_name] = page
                        return
                    cursor = page['next_cursor']
                    time.sleep(0.01)
                results[slot_name] = {'status': 'timeout'}
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=run_query, args=('a', self.target_title))
        t2 = threading.Thread(target=run_query, args=('b', self.newest_body_marker))
        t1.start(); t2.start()
        t1.join(30); t2.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(results['a']['status'], 'ready', results['a'])
        self.assertEqual(results['b']['status'], 'ready', results['b'])
        self.assertEqual(results['a']['threads'][0]['title'], self.target_title)
        self.assertEqual(results['b']['threads'][0]['match']['in'], 'visible_message')

        # Verify forget_cursor cleanly drops an abandoned task without crashing the worker.
        slot = service._workers['codex']
        self.assertFalse(slot.worker.forget_cursor('not-a-valid-cursor'))
        service._abandon('codex', 'hp1.invalid.sig')
        after = service.find_agent_threads('alpha', query=self.target_title, source_id='codex', limit=5)
        while after['status'] == 'processing':
            after = service.find_agent_threads(
                'alpha', query=self.target_title, source_id='codex', cursor=after['next_cursor'], limit=5
            )
        self.assertEqual(after['status'], 'ready')
        self.assertEqual(after['threads'][0]['title'], self.target_title)

    def test_exact_title_ranks_first_despite_280_newer_similar_suffix_titles_across_v1_v2_and_aggregate(self):
        exact_title = '合成精确标题检索回归主任务'
        mild_title = 'Synthetic Exact Ranking Title'
        now_sec = int(time.time())
        with sqlite3.connect(self.codex_home / 'state_5.sqlite') as db:
            # 280 newer threads sharing the exact phrase plus distinct suffixes -> exceeds MAX_TITLE_SEARCH=256.
            for idx in range(280):
                tid = self.newest_body_id if idx == 5 else f'{idx:08x}-0000-4000-8000-000000000000'
                db.execute(
                    'UPDATE threads SET title=?, updated_at=? WHERE id=?',
                    (f'{exact_title} - 后缀变体 {idx:03d}', now_sec - idx, tid),
                )
            # 1 older unique exact-title target (#315) must never be starved or buried behind the 280 suffixes.
            db.execute(
                'UPDATE threads SET title=?, updated_at=? WHERE id=?',
                (exact_title, now_sec - 9000, self.target_id),
            )
            # Foreign beta threads with identical exact title must stay isolated.
            db.execute('UPDATE threads SET title=? WHERE cwd=?', (exact_title, str(self.beta)))
            # Mild similarity group (< MAX_TITLE_SEARCH) using 24 newer suffix titles + 1 older exact title.
            for offset in range(24):
                idx = 280 + offset
                tid = f'{idx:08x}-0000-4000-8000-000000000000'
                db.execute(
                    'UPDATE threads SET title=?, updated_at=? WHERE id=?',
                    (f'{mild_title} - suffix {offset:02d}', now_sec - 10 - offset, tid),
                )
            mild_exact_id = f'{310:08x}-0000-4000-8000-000000000000'
            db.execute(
                'UPDATE threads SET title=?, updated_at=? WHERE id=?',
                (mild_title, now_sec - 8000, mild_exact_id),
            )
            db.commit()

        for mode, source_id in (('v1', 'codex'), ('v2', 'codex'), ('v2', '')):
            with self.subTest(mode=mode, source_id=source_id or 'aggregate'):
                app, token, _ = self._http_client(mode)
                with TestClient(app, base_url='https://mcp.example.com') as client:
                    # 1. 280 newer suffix-collision stress case: exact match MUST be Page 1 index 0.
                    args = {'project_id': 'alpha', 'query': exact_title, 'limit': 10}
                    if source_id:
                        args['source_id'] = source_id
                    found = self._run_tool_ready(client, token, 'find_agent_threads', args)
                    self.assertEqual(found['status'], 'ready', found)
                    self.assertGreaterEqual(len(found['threads']), 1, found)
                    hit = found['threads'][0]
                    self.assertEqual(hit['title'], exact_title)
                    self.assertEqual(hit['project_id'], 'alpha')
                    self.assertEqual(hit['match'], {'in': 'title', 'mode': 'substring'})
                    # Coverage remains honest when >256 similar titles hit MAX_TITLE_SEARCH.
                    self.assertFalse(found['coverage_complete'])
                    codex_cov = [c for c in found['coverage'] if c['source_id'] == 'codex']
                    self.assertEqual(len(codex_cov), 1)
                    self.assertIn('resource_exhausted', codex_cov[0]['warnings'])
                    # Confirm no foreign beta thread leaked into page 1.
                    self.assertTrue(all(row['project_id'] == 'alpha' for row in found['threads']))
                    # Confirm the exact-title hit actually reads the expected #315 messages.
                    latest = self._run_tool_ready(client, token, 'read_agent_thread', {
                        'thread_ref': hit['thread_ref'], 'view': 'latest_turn',
                    })
                    self.assertEqual(latest['status'], 'ready')
                    self.assertIn('队列调度策略', latest['entries'][0]['text'])
                    self.assertIn('预取窗口参数', latest['entries'][1]['text'])

                    # 2. Leading/trailing spaces + case-insensitive mild similarity group: exact match still ranks #1.
                    mild_args = {'project_id': 'alpha', 'query': f'  {mild_title.lower()}  ', 'limit': 5}
                    if source_id:
                        mild_args['source_id'] = source_id
                    mild = self._run_tool_ready(client, token, 'find_agent_threads', mild_args)
                    self.assertEqual(mild['status'], 'ready', mild)
                    self.assertGreaterEqual(len(mild['threads']), 2, mild)
                    self.assertEqual(mild['threads'][0]['title'], mild_title)
                    self.assertEqual(mild['threads'][0]['match'], {'in': 'title', 'mode': 'substring'})


if __name__ == '__main__':
    unittest.main()
