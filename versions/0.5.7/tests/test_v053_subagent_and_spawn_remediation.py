"""v0.5.3 targeted L4 remediation regression tests.

Covers:
1. Native Codex subagent/thread_spawn rollouts with inline-copied parent headers/turns
   deliver ONLY the subagent's own public turns on both unified (read_agent_thread) and
   legacy (read_codex_thread) APIs across view='all' and view='latest_turn', both when
   delimited by thread_settings_applied and when delimited by own item_completed events.
2. Parent threads using spawn_agent / wait_agent exclude client-generated tool-provenance
   <subagent_notification> messages from public user turns and recognize CollabAgentToolCall
   events without spurious unknown_event_item_excluded warnings.
3. Bidirectional search attribution across default aggregate find_agent_threads,
   source-scoped find_agent_threads(source_id='codex'), and legacy find_codex_threads:
   parent-only text never hits child subagents, and child-only reply text never hits parents.
4. Fail-closed ancestor ACL enforcement on subagent threads (initial deny-list on both
   inline-copied and single-header subagents, cross-project parent rejection, and
   mid-pagination parent revocation) while preserving pre-fork prefixes on normal forks.
"""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import activate_preview, compile_generation, preview_activation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.history import HistoryAccess
from peters_mcp.workspaces import repository_probe


def _drain(gen):
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def _git(cwd, *args):
    subprocess.run(
        ["/usr/bin/git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
    )


def _jsonl(records):
    return b"".join(
        json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for r in records
    )


def _iso(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


class CodexSubagentAndSpawnNotificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o700)

        self.alpha = self.root / "alpha"
        self.beta = self.root / "beta"
        for repo in (self.alpha, self.beta):
            repo.mkdir()
            _git(repo, "init", "-q")
            (repo / "README.md").write_text(repo.name + "\n", encoding="utf-8")
            _git(repo, "add", "README.md")
            _git(repo, "commit", "-q", "-m", "init")

        self.codex_home = self.root / "codex-home"
        self.folder = self.codex_home / "sessions" / "2026" / "11" / "25"
        self.folder.mkdir(parents=True)
        self.state_db = self.codex_home / "state_5.sqlite"
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute(
                "CREATE TABLE threads ("
                "id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, cwd TEXT NOT NULL, "
                "title TEXT, updated_at INTEGER, archived INTEGER DEFAULT 0, created_at INTEGER, "
                "history_mode TEXT, attached_thread_parent_id TEXT, source TEXT)"
            )
            db.commit()

        self.state_dir = self.root / "generations-state"
        self.descriptor = self.root / "policy.json"
        self.actor = "a" * 64
        self.caller = {"actor": self.actor, "policy_actor": "local"}
        self.store = initialize_store(self.state_dir)
        self.document = compile_generation({
            "version": 2,
            "projects": [
                {"id": "alpha", "name": "Alpha", "root": str(self.alpha), "repository_id": repository_probe(self.alpha)["repository_id"]},
            ],
            "sources": {
                "codex": {
                    "adapter": "codex",
                    "root": str(self.codex_home),
                    "format": "local",
                    "enabled": True,
                    "instance_id": "codex",
                    "denied_threads": [],
                }
            },
            "legacy_history": {
                "codex_home": str(self.codex_home),
                "state_db": "state_5.sqlite",
                "tool_evidence": [],
            },
        })
        preview, digest = preview_activation(self.document)
        activate_preview(self.store, preview, digest, initial=True)
        write_descriptor(self.descriptor, self.store)
        time.sleep(0.05)
        self.now_ns = time.time_ns()

    def _make_service(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        scratch = self.root / f"scratch-{time.time_ns()}"
        scratch.mkdir(mode=0o700)
        policy.scratch = scratch
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        svc = AgentHistoryService(policy, legacy, local=True)
        self.addCleanup(svc.close)
        return legacy, svc

    def _make_core(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        scratch = self.root / f"scratch-{time.time_ns()}"
        scratch.mkdir(mode=0o700)
        policy.scratch = scratch
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        core = AgentHistoryCore(policy, catalog, legacy, b"k" * 32)
        return legacy, core

    def _build_spawn_pair(self, parent_id, child_id):
        t0 = _iso(self.now_ns - 6_000_000)
        t1 = _iso(self.now_ns - 5_000_000)
        t2 = _iso(self.now_ns - 4_000_000)
        t3 = _iso(self.now_ns - 3_000_000)

        subagent_src = {
            "subagent": {
                "thread_spawn": {
                    "parent_thread_id": parent_id,
                    "depth": 1,
                    "agent_path": None,
                    "agent_nickname": "Helper",
                    "agent_role": None,
                }
            }
        }

        parent_records = [
            {"timestamp": t0, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(self.alpha), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
            {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "p-t1"}},
            {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-t1"}},
            {"timestamp": t0, "type": "response_item", "payload": {
                "type": "message", "id": "m-p1-u", "role": "user",
                "content": [{"type": "input_text", "text": "Parent prompt marker ParentOnlyTokenAlpha"}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "p-t1", "content_item_kinds": ["user.text"],
                    "content_item_metadata": [{"provenance": {"type": "user"}}],
                },
            }},
            {"timestamp": t0, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t1",
                "item": {"type": "UserMessage", "id": "m-p1-u", "content": [{"type": "text", "text": "Parent prompt marker ParentOnlyTokenAlpha"}]},
            }},
            {"timestamp": t0, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t1",
                "item": {"type": "AgentMessage", "id": "m-p1-a", "phase": "final_answer", "content": [{"type": "Text", "text": "Parent body statement ParentBodyUnique901"}]},
            }},
            {"timestamp": t0, "type": "response_item", "payload": {
                "type": "message", "id": "m-p1-a", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Parent body statement ParentBodyUnique901"}],
            }},
            {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_complete", "turn_id": "p-t1"}},
            {"timestamp": t1, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "p-t2"}},
            {"timestamp": t1, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-t2"}},
            {"timestamp": t1, "type": "response_item", "payload": {
                "type": "message", "id": "m-p2-u", "role": "user",
                "content": [{"type": "input_text", "text": "Delegate the isolated helper task."}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "p-t2", "content_item_kinds": ["user.text"],
                    "content_item_metadata": [{"provenance": {"type": "user"}}],
                },
            }},
            {"timestamp": t1, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t2",
                "item": {"type": "UserMessage", "id": "m-p2-u", "content": [{"type": "text", "text": "Delegate the isolated helper task."}]},
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t2",
                "item": {"type": "CollabAgentToolCall", "id": "call-sp", "tool": "spawn_agent", "status": "completed"},
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t2",
                "item": {"type": "CollabAgentToolCall", "id": "call-wt", "tool": "wait", "status": "completed"},
            }},
            {"timestamp": t2, "type": "response_item", "payload": {
                "type": "message", "id": "m-notif", "role": "user",
                "content": [{"type": "input_text", "text": "<subagent_notification>\n{\"agent_path\":\"" + child_id + "\",\"status\":{\"completed\":\"Child body answer ChildBodyUnique902\"}}\n</subagent_notification>"}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "p-t2",
                    "content_item_kinds": ["multi_agent.subagent_notification"],
                    "content_item_metadata": [{"provenance": {"type": "tool", "namespace": "multi_agent_v1"}}],
                },
            }},
            {"timestamp": t3, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": parent_id, "turn_id": "p-t2",
                "item": {"type": "AgentMessage", "id": "m-p2-a", "phase": "final_answer", "content": [{"type": "Text", "text": "Parent finished delegation."}]},
            }},
            {"timestamp": t3, "type": "response_item", "payload": {
                "type": "message", "id": "m-p2-a", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Parent finished delegation."}],
            }},
            {"timestamp": t3, "type": "event_msg", "payload": {"type": "task_complete", "turn_id": "p-t2"}},
        ]

        child_records = [
            {"timestamp": t2, "type": "session_meta", "payload": {
                "id": child_id, "forked_from_id": parent_id, "parent_thread_id": parent_id,
                "cwd": str(self.alpha), "timestamp": t2, "cli_version": "0.171.0", "source": subagent_src,
            }},
            {"timestamp": t0, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(self.alpha), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
            {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "p-t1"}},
            {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-t1"}},
            {"timestamp": t0, "type": "response_item", "payload": {
                "type": "message", "id": "m-p1-u", "role": "user",
                "content": [{"type": "input_text", "text": "Parent prompt marker ParentOnlyTokenAlpha"}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "p-t1", "content_item_kinds": ["user.text"],
                    "content_item_metadata": [{"provenance": {"type": "user"}}],
                },
            }},
            {"timestamp": t0, "type": "response_item", "payload": {
                "type": "message", "id": "m-p1-a", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Parent body statement ParentBodyUnique901"}],
            }},
            {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_complete", "turn_id": "p-t1"}},
            {"timestamp": t1, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "p-t2"}},
            {"timestamp": t1, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-t2"}},
            {"timestamp": t1, "type": "response_item", "payload": {
                "type": "message", "id": "m-p2-u", "role": "user",
                "content": [{"type": "input_text", "text": "Delegate the isolated helper task."}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "p-t2", "content_item_kinds": ["user.text"],
                    "content_item_metadata": [{"provenance": {"type": "user"}}],
                },
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "thread_settings_applied", "thread_id": child_id, "thread_settings": {}}},
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "c-t1"}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "c-t1"}},
            {"timestamp": t2, "type": "response_item", "payload": {
                "type": "message", "id": "m-c1-u", "role": "user",
                "content": [{"type": "input_text", "text": "Return isolated child answer ChildPromptTokenBeta"}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "c-t1", "content_item_kinds": ["user.text"],
                    "content_item_metadata": [{"provenance": {"type": "user"}}],
                },
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": child_id, "turn_id": "c-t1",
                "item": {"type": "UserMessage", "id": "m-c1-u", "content": [{"type": "text", "text": "Return isolated child answer ChildPromptTokenBeta"}]},
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": child_id, "turn_id": "c-t1",
                "item": {"type": "AgentMessage", "id": "m-c1-a", "phase": "final_answer", "content": [{"type": "Text", "text": "Child body answer ChildBodyUnique902"}]},
            }},
            {"timestamp": t2, "type": "response_item", "payload": {
                "type": "message", "id": "m-c1-a", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Child body answer ChildBodyUnique902"}],
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "task_complete", "turn_id": "c-t1"}},
        ]
        return parent_records, child_records, subagent_src

    def test_bidirectional_public_views_and_search_across_all_entrances(self):
        parent_id = "11111111-1111-4111-8111-111111111111"
        child_id = "22222222-2222-4222-8222-222222222222"
        parent_records, child_records, subagent_src = self._build_spawn_pair(parent_id, child_id)

        p_file = self.folder / f"rollout-parent-{parent_id}.jsonl"
        c_file = self.folder / f"rollout-child-{child_id}.jsonl"
        p_file.write_bytes(_jsonl(parent_records))
        c_file.write_bytes(_jsonl(child_records))

        sec = int(self.now_ns // 1_000_000_000)
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute(
                "INSERT INTO threads VALUES (?, ?, ?, ?, ?, 0, ?, 'legacy', NULL, 'cli')",
                (parent_id, str(p_file), str(self.alpha), "Parent prompt marker ParentOnlyTokenAlpha", sec + 1, sec),
            )
            db.execute(
                "INSERT INTO threads VALUES (?, ?, ?, ?, ?, 0, ?, 'legacy', NULL, ?)",
                (child_id, str(c_file), str(self.alpha), "Return isolated child answer ChildPromptTokenBeta", sec + 2, sec, json.dumps(subagent_src)),
            )
            db.commit()

        legacy, svc = self._make_service()

        expected_parent_all = [
            ("user", "Parent prompt marker ParentOnlyTokenAlpha"),
            ("assistant", "Parent body statement ParentBodyUnique901"),
            ("user", "Delegate the isolated helper task."),
            ("assistant", "Parent finished delegation."),
        ]
        expected_parent_lt = [
            ("user", "Delegate the isolated helper task."),
            ("assistant", "Parent finished delegation."),
        ]
        expected_child_all = [
            ("user", "Return isolated child answer ChildPromptTokenBeta"),
            ("assistant", "Child body answer ChildBodyUnique902"),
        ]

        # Legacy reads: view='all' and view='latest_turn'
        p_leg_all = _drain(legacy._read_codex_thread_iter(parent_id, view="all", caller=self.caller))
        p_leg_lt = _drain(legacy._read_codex_thread_iter(parent_id, view="latest_turn", caller=self.caller))
        c_leg_all = _drain(legacy._read_codex_thread_iter(child_id, view="all", caller=self.caller))
        c_leg_lt = _drain(legacy._read_codex_thread_iter(child_id, view="latest_turn", caller=self.caller))

        self.assertEqual([(e["role"], e["text"]) for e in p_leg_all["entries"]], expected_parent_all)
        self.assertEqual([(e["role"], e["text"]) for e in p_leg_lt["entries"]], expected_parent_lt)
        self.assertEqual(p_leg_all["warnings"], {"unknown_event_item_excluded": 2})

        self.assertEqual([(e["role"], e["text"]) for e in c_leg_all["entries"]], expected_child_all)
        self.assertEqual([(e["role"], e["text"]) for e in c_leg_lt["entries"]], expected_child_all)
        self.assertTrue(c_leg_all["complete_public_projection"])
        self.assertTrue(c_leg_all["inherited_context"]["subagent_thread"])
        self.assertFalse(c_leg_all["inherited_context"]["parent_context_inlined"])
        self.assertEqual(c_leg_all["inherited_context"]["stored_ancestor_headers"], 1)

        # Unified reads: view='all' and view='latest_turn'
        found_all = svc.find_agent_threads(project_id="alpha", source_id="codex", query="", limit=10)["threads"]
        self.assertEqual(len(found_all), 2)
        p_summary = next(t for t in found_all if "ParentOnlyTokenAlpha" in t["title"])
        c_summary = next(t for t in found_all if "ChildPromptTokenBeta" in t["title"])
        self.assertEqual(p_summary["message_count"], 4)
        self.assertEqual(c_summary["message_count"], 2)

        p_uni_all = svc.read_agent_thread(p_summary["thread_ref"], view="all", limit=10)
        p_uni_lt = svc.read_agent_thread(p_summary["thread_ref"], view="latest_turn", limit=10)
        c_uni_all = svc.read_agent_thread(c_summary["thread_ref"], view="all", limit=10)
        c_uni_lt = svc.read_agent_thread(c_summary["thread_ref"], view="latest_turn", limit=10)

        self.assertEqual([(e["role"], e["text"]) for e in p_uni_all["entries"]], expected_parent_all)
        self.assertEqual([(e["role"], e["text"]) for e in p_uni_lt["entries"]], expected_parent_lt)
        self.assertEqual([(e["role"], e["text"]) for e in c_uni_all["entries"]], expected_child_all)
        self.assertEqual([(e["role"], e["text"]) for e in c_uni_lt["entries"]], expected_child_all)

        # Bidirectional search attribution across all 3 search entrances!
        # 1) Parent-body-only phrase (copied into child's raw file, absent from parent title & child own turns)
        for mode_kwargs in ({}, {"source_id": "codex"}):
            hits = svc.find_agent_threads(project_id="alpha", query="ParentBodyUnique901", limit=10, **mode_kwargs)["threads"]
            self.assertEqual([h["stable_thread_id"] for h in hits], [p_summary["stable_thread_id"]])
            self.assertEqual(hits[0]["match"]["in"], "visible_message")
        leg_p_hits = _drain(legacy._find_codex_threads_iter(project_id="alpha", query="ParentBodyUnique901", limit=10, caller=self.caller))["threads"]
        self.assertEqual([h["thread_id"] for h in leg_p_hits], [parent_id])
        self.assertEqual(leg_p_hits[0]["match"]["in"], "public_message")

        # 2) Child-body-only phrase (present in parent's <subagent_notification>, absent from child title & parent public turns)
        for mode_kwargs in ({}, {"source_id": "codex"}):
            hits = svc.find_agent_threads(project_id="alpha", query="ChildBodyUnique902", limit=10, **mode_kwargs)["threads"]
            self.assertEqual([h["stable_thread_id"] for h in hits], [c_summary["stable_thread_id"]])
            self.assertEqual(hits[0]["match"]["in"], "visible_message")
        leg_c_hits = _drain(legacy._find_codex_threads_iter(project_id="alpha", query="ChildBodyUnique902", limit=10, caller=self.caller))["threads"]
        self.assertEqual([h["thread_id"] for h in leg_c_hits], [child_id])
        self.assertEqual(leg_c_hits[0]["match"]["in"], "public_message")

    def test_subagent_without_thread_settings_applied_and_ancestor_acls_and_normal_forks(self):
        parent_id = "33333333-3333-4333-8333-333333333333"
        child_no_settings_id = "44444444-4444-4444-8444-444444444444"
        single_header_child_id = "55555555-5555-4555-8555-555555555555"
        cross_parent_id = "66666666-6666-4666-8666-666666666666"
        cross_child_id = "77777777-7777-4777-8777-777777777777"
        normal_fork_id = "88888888-8888-4888-8888-888888888888"

        parent_records, child_records, subagent_src = self._build_spawn_pair(parent_id, child_no_settings_id)
        # Strip thread_settings_applied from child_records to test item_completed fallback promotion!
        child_no_settings = [
            r for r in child_records
            if not (r.get("type") == "event_msg" and r.get("payload", {}).get("type") == "thread_settings_applied")
        ]

        t2 = _iso(self.now_ns - 2_000_000)
        single_header_records = [
            {"timestamp": t2, "type": "session_meta", "payload": {
                "id": single_header_child_id, "parent_thread_id": parent_id,
                "cwd": str(self.alpha), "timestamp": t2, "cli_version": "0.171.0", "source": subagent_src,
            }},
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "s-t1"}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "s-t1"}},
            {"timestamp": t2, "type": "event_msg", "payload": {
                "type": "item_completed", "thread_id": single_header_child_id, "turn_id": "s-t1",
                "item": {"type": "AgentMessage", "id": "s-a1", "phase": "final_answer", "content": [{"type": "Text", "text": "Standalone subagent reply"}]},
            }},
            {"timestamp": t2, "type": "response_item", "payload": {
                "type": "message", "id": "s-a1", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Standalone subagent reply"}],
            }},
        ]

        # Cross-project subagent copying a beta parent header
        cross_records = [
            {"timestamp": t2, "type": "session_meta", "payload": {
                "id": cross_child_id, "forked_from_id": cross_parent_id, "parent_thread_id": cross_parent_id,
                "cwd": str(self.alpha), "timestamp": t2, "cli_version": "0.171.0",
                "source": {"subagent": {"thread_spawn": {"parent_thread_id": cross_parent_id, "depth": 1}}},
            }},
            {"timestamp": t2, "type": "session_meta", "payload": {"id": cross_parent_id, "cwd": str(self.beta), "timestamp": t2, "cli_version": "0.171.0"}},
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "thread_settings_applied", "thread_id": cross_child_id, "thread_settings": {}}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "x-t1"}},
            {"timestamp": t2, "type": "response_item", "payload": {
                "type": "message", "role": "assistant", "phase": "final_answer",
                "content": [{"type": "output_text", "text": "Should be rejected"}],
            }},
        ]

        # Normal inline-copied fork (source != subagent) MUST still preserve pre-fork parent turns!
        normal_fork_records = [
            {"timestamp": t2, "type": "session_meta", "payload": {
                "id": normal_fork_id, "forked_from_id": parent_id,
                "cwd": str(self.alpha), "timestamp": t2, "cli_version": "0.171.0", "source": "cli",
            }},
            {"timestamp": t2, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(self.alpha), "timestamp": t2, "cli_version": "0.171.0", "source": "cli"}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "nf-p1"}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Copied fork parent Q"}]}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "nf-c1"}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Normal fork child A"}]}},
        ]

        files = [
            (parent_id, "p", parent_records, str(self.alpha), "Parent", "cli"),
            (child_no_settings_id, "cns", child_no_settings, str(self.alpha), "Child no settings", json.dumps(subagent_src)),
            (single_header_child_id, "sh", single_header_records, str(self.alpha), "Single header subagent", json.dumps(subagent_src)),
            (cross_child_id, "xc", cross_records, str(self.alpha), "Cross subagent", json.dumps({"subagent": {"thread_spawn": {"parent_thread_id": cross_parent_id}}})),
            (normal_fork_id, "nf", normal_fork_records, str(self.alpha), "Normal inline fork", "cli"),
        ]
        sec = int(self.now_ns // 1_000_000_000)
        with closing(sqlite3.connect(self.state_db)) as db:
            for idx, (tid, tag, recs, cwd, title, src) in enumerate(files, 1):
                fp = self.folder / f"rollout-{tag}-{tid}.jsonl"
                fp.write_bytes(_jsonl(recs))
                db.execute(
                    "INSERT INTO threads VALUES (?, ?, ?, ?, ?, 0, ?, 'legacy', NULL, ?)",
                    (tid, str(fp), cwd, title, sec + idx, sec, src),
                )
            db.commit()

        legacy, core = self._make_core()

        # 1. Subagent without thread_settings_applied still isolates own turn cleanly
        cns_page1 = _drain(legacy._read_codex_thread_iter(child_no_settings_id, limit=1, view="all", caller=self.caller))
        self.assertTrue(cns_page1["has_more"])
        self.assertEqual([(e["role"], e["text"]) for e in cns_page1["entries"]], [("user", "Return isolated child answer ChildPromptTokenBeta")])
        cns_page2 = _drain(legacy._read_codex_thread_iter(child_no_settings_id, cursor=cns_page1["next_cursor"], limit=1, view="all", caller=self.caller))
        self.assertEqual([(e["role"], e["text"]) for e in cns_page2["entries"]], [("assistant", "Child body answer ChildBodyUnique902")])

        # 2. Single-header fork_context=False subagent reads own turn
        sh_page = _drain(legacy._read_codex_thread_iter(single_header_child_id, view="all", caller=self.caller))
        self.assertEqual([(e["role"], e["text"]) for e in sh_page["entries"]], [("assistant", "Standalone subagent reply")])

        # 3. Cross-project parent header inside subagent is strictly denied
        with self.assertRaises(AccessError) as ctx_cross:
            _drain(legacy._read_codex_thread_iter(cross_child_id, view="all", caller=self.caller))
        self.assertIn(ctx_cross.exception.code, {"unverifiable_source", "unauthorized"})

        # 4. Normal inline-copied fork STILL preserves pre-fork parent message
        nf_page = _drain(legacy._read_codex_thread_iter(normal_fork_id, view="all", caller=self.caller))
        self.assertEqual(
            [(e["role"], e["text"]) for e in nf_page["entries"]],
            [("user", "Copied fork parent Q"), ("assistant", "Normal fork child A")],
        )

        # 5. Revoking parent_id mid-pagination invalidates child cursor AND blocks both inline-copied & single-header subagents!
        cur_snap = AgentPolicy(self.descriptor, mode="v2").snapshot()
        updated = deepcopy(cur_snap[0])
        updated["sources"]["codex"]["denied_threads"] = [parent_id]
        p2, d2 = preview_activation(updated, previous=cur_snap)
        activate_preview(self.store, p2, d2)

        with self.assertRaises(AccessError) as ctx_mid:
            _drain(legacy._read_codex_thread_iter(child_no_settings_id, cursor=cns_page1["next_cursor"], limit=1, view="all", caller=self.caller))
        self.assertIn(ctx_mid.exception.code, {"authorization_changed", "unauthorized", "unverifiable_source"})

        legacy_after, core_after = self._make_core()
        for blocked_id in (child_no_settings_id, single_header_child_id):
            with self.assertRaises(AccessError):
                _drain(legacy_after._read_codex_thread_iter(blocked_id, view="all", caller=self.caller))
        scope = core_after._configuration("alpha", self.actor, "local")
        rows, _ = _drain(core_after._search(scope, "", "", "codex"))
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
