"""WS3 + WS4 / D3 / S3 / S4 / S5 tests: four-source honesty, multi-tier UX, live append & pagination."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import (
    activate_preview, compile_generation, lint_policy, preview_activation,
    preview_coverage, write_descriptor,
)
from peters_mcp.agent_history_deepseek import _project_key
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.history import HistoryAccess
from tests import test_agent_history_codeg as codeg
from tests import test_agent_history_deepseek as deepseek


def _drain(gen):
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def _iso_from_ns(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


def _rollout_bytes(records):
    return b"".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n" for item in records)


class FourSourceUxAndPaginationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o700)

        self.project = self.root / "studio-project"
        self.empty_project = self.root / "empty-project"
        self.foreign = self.root / "foreign-project"
        for d in (self.project, self.empty_project, self.foreign):
            d.mkdir(mode=0o700)

        # 1. Codeg root
        self.codeg_root = self.root / "codeg-root"
        self.codeg_root.mkdir(mode=0o700)
        self.codeg_db = self.codeg_root / "codeg.db"
        with closing(sqlite3.connect(self.codeg_db)) as db:
            db.executescript(codeg._SCHEMA)
            db.execute("INSERT INTO folder VALUES (1, ?, 'regular', NULL, NULL)", (str(self.project),))
            db.execute("INSERT INTO folder VALUES (2, ?, 'regular', NULL, NULL)", (str(self.foreign),))
            db.commit()

        # 2. DeepSeek Harness root
        self.dsh_root = self.root / "dsh-root"
        self.dsh_root.mkdir(mode=0o700)

        # 3. Codex root
        self.codex_root = self.root / "codex-root"
        (self.codex_root / "sessions").mkdir(parents=True)
        self.codex_db = self.codex_root / "state_5.sqlite"
        with closing(sqlite3.connect(self.codex_db)) as db:
            db.execute(
                "CREATE TABLE threads ("
                "id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, cwd TEXT NOT NULL, "
                "title TEXT, updated_at INTEGER, archived INTEGER DEFAULT 0, created_at INTEGER)"
            )
            db.commit()

        self.state_dir = self.root / "generations-state"
        self.descriptor = self.root / "policy.json"
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.actor = "a" * 64
        self.store = initialize_store(self.state_dir)

        self.document = compile_generation({
            "version": 2,
            "projects": [
                {"id": "studio", "name": "Studio", "root": str(self.project)},
                {"id": "empty", "name": "Empty", "root": str(self.empty_project)},
            ],
            "sources": {
                "codeg": {
                    "adapter": "codeg", "root": str(self.codeg_root), "format": "0.45.0",
                    "enabled": True, "instance_id": "codeg",
                    "links": {"codex": "codex"},
                    "link_instances": {"codex": "codex"},
                },
                "codex": {
                    "adapter": "codex", "root": str(self.codex_root), "format": "local",
                    "enabled": True, "instance_id": "codex", "denied_threads": [],
                },
                "deepseek": {
                    "adapter": "deepseek_harness", "root": str(self.dsh_root), "format": "0.2.2-rc.3",
                    "enabled": True, "instance_id": "deepseek",
                },
            },
            "legacy_history": {
                "codex_home": str(self.codex_root),
                "state_db": "state_5.sqlite",
                "tool_evidence": [],
            },
        })
        p, d = preview_activation(self.document)
        self.epoch = activate_preview(self.store, p, d, initial=True)
        write_descriptor(self.descriptor, self.store)

    def _add_dsh_session(self, native_id, cwd, title, messages):
        now_ms = time.time_ns() // 1_000_000
        folder = self.dsh_root / _project_key(str(cwd)) / native_id
        folder.mkdir(parents=True, exist_ok=True)
        events = [{**deepseek.header(native_id, str(cwd)), "createdAt": now_ms}]
        seq = 0
        events.append({**deepseek.event(seq, "session/title", {"title": title}), "time": now_ms})
        seq += 1
        for turn_idx, (u_text, a_text) in enumerate(messages, start=1):
            events.append({**deepseek.event(seq, "turn/start", {"turn": turn_idx}), "time": now_ms})
            seq += 1
            events.append({**deepseek.user(seq, u_text), "time": now_ms})
            seq += 1
            a = deepseek.assistant(seq, a_text)
            a["data"]["turn"] = turn_idx
            a["time"] = now_ms
            events.append(a)
            seq += 1
            events.append({**deepseek.event(seq, "turn/end", {"turn": turn_idx, "reason": {"kind": "completed"}}),
                           "time": now_ms})
            seq += 1
        path = folder / "session.v4.jsonl"
        path.write_bytes(deepseek.records(*events))
        time.sleep(0.01)
        return path, now_ms, seq

    def _add_codex_session(self, thread_id, cwd, title, messages):
        ts_ns = time.time_ns()
        ts_iso = _iso_from_ns(ts_ns)
        created_s = int(ts_ns // 1_000_000_000)
        rows = [{"timestamp": ts_iso, "type": "session_meta",
                 "payload": {"id": thread_id, "cwd": str(cwd), "timestamp": ts_iso, "cli_version": "0.167.0"}}]
        for idx, (u_text, a_text) in enumerate(messages, start=1):
            t_iso = _iso_from_ns(ts_ns + idx * 1000)
            rows.append({"timestamp": t_iso, "type": "turn_context",
                         "payload": {"cwd": str(cwd), "turn_id": f"turn-{idx}"}})
            rows.append({"timestamp": t_iso, "type": "response_item",
                         "payload": {"type": "message", "role": "user",
                                     "content": [{"type": "input_text", "text": u_text}]}})
            rows.append({"timestamp": t_iso, "type": "response_item",
                         "payload": {"type": "message", "role": "assistant", "phase": "final_answer",
                                     "content": [{"type": "output_text", "text": a_text}]}})
        rollout = self.codex_root / "sessions" / f"rollout-test-{thread_id}.jsonl"
        rollout.write_bytes(_rollout_bytes(rows))
        with closing(sqlite3.connect(self.codex_db)) as db:
            db.execute(
                "INSERT OR REPLACE INTO threads (id, rollout_path, cwd, title, updated_at, archived, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (thread_id, str(rollout), str(cwd), title, created_s, created_s),
            )
            db.commit()
        time.sleep(0.01)
        return rollout, ts_ns

    def _core(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        policy.scratch = self.scratch
        policy.scratch_identity = SourceRoot(self.scratch).identity
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        self.addCleanup(legacy.close)
        self.addCleanup(policy.store.locations.close)
        return AgentHistoryCore(policy, catalog, legacy, b"v05-four-source-test-key-32bytes")

    def test_codeg_unsupported_types_unlinked_provider_lint_and_linked_dedup(self):
        time.sleep(0.05)
        self._add_dsh_session("dsh-1", self.project, "DeepSeek 选题", [("整理选题", "已整理完成")])
        # Add Codeg rows: 1 unsupported antigravity row, 1 deepseek link row, 1 foreign antigravity row
        with closing(sqlite3.connect(self.codeg_db)) as db:
            db.execute("INSERT INTO conversation VALUES (1, 'AG in Codeg Secret', '2026-11-24T00:00:00Z', 'antigravity', 'ag-acp-1', NULL, 1, 'regular', NULL, NULL)")
            db.execute("INSERT INTO conversation VALUES (2, 'Codeg DSH Link', '2026-11-24T00:00:00Z', 'deepseek', 'dsh-1', NULL, 1, 'regular', NULL, NULL)")
            db.execute("INSERT INTO conversation VALUES (3, 'Foreign AG', '2026-11-24T00:00:00Z', 'antigravity', 'ag-foreign', NULL, 2, 'regular', NULL, NULL)")
            db.commit()

        # 1. Policy lint MUST warn about unlinked deepseek_harness!
        findings = lint_policy(self.document)
        self.assertTrue(any(f["code"] == "unlinked_codeg_provider" and f["provider"] == "deepseek_harness" for f in findings))

        # 2. Before linking deepseek_harness, Codeg reports unsupported_agent_types=['antigravity'] AND unverified_project_candidates=1!
        cov = preview_coverage(self.descriptor)
        codeg_studio = cov["projects"]["studio"]["codeg"]
        self.assertFalse(codeg_studio["coverage_complete"])
        self.assertEqual(codeg_studio["unsupported_agent_types"], ["antigravity"])
        self.assertEqual(codeg_studio["unverified_project_candidates"], 1)
        self.assertNotIn("AG in Codeg Secret", json.dumps(cov))

        # Empty project is 100% complete across ALL sources (including DeepSeek small-store full partition!).
        for src_id in ("codeg", "codex", "deepseek"):
            self.assertTrue(cov["projects"]["empty"][src_id]["coverage_complete"])
            self.assertEqual(cov["projects"]["empty"][src_id]["thread_count"], 0)
        # Studio DeepSeek is ALSO 100% complete!
        self.assertTrue(cov["projects"]["studio"]["deepseek"]["coverage_complete"])
        self.assertEqual(cov["projects"]["studio"]["deepseek"]["thread_count"], 1)

        # 3. Link codeg -> deepseek_harness -> lint becomes clean and search deduplicates codeg+deepseek!
        linked_doc = deepcopy(self.document)
        linked_doc["sources"]["codeg"]["links"]["deepseek_harness"] = "deepseek"
        linked_doc["sources"]["codeg"]["link_instances"]["deepseek_harness"] = "deepseek"
        self.assertEqual(lint_policy(linked_doc), [])
        p, d = preview_activation(linked_doc, previous=AgentPolicy(self.descriptor, mode="v2").snapshot())
        self.epoch = activate_preview(self.store, p, d)

        core = self._core()
        found = _drain(core.operation_iter("find_agent_threads", {
            "project_id": "studio", "query": "", "agent": "", "source_id": "",
            "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": "local",
        }))
        self.assertEqual(len(found["threads"]), 1)
        self.assertEqual(found["threads"][0]["matched_sources"], ["codeg", "deepseek"])
        by_src = {c["source_id"]: c for c in found["coverage"]}
        self.assertEqual(by_src["codeg"]["unsupported_agent_types"], ["antigravity"])
        self.assertNotIn("unverified_project_candidates", by_src["codeg"])

    def test_deepseek_corrupt_header_degrades_coverage_honestly(self):
        time.sleep(0.05)
        self._add_dsh_session("dsh-clean", self.project, "Clean Thread", [("Hello", "World")])
        corrupt = self.dsh_root / "--foreign-corrupt--" / "bad-sess"
        corrupt.mkdir(parents=True)
        (corrupt / "session.v4.jsonl").write_bytes(b"NOT VALID JSON\n")
        core = self._core()
        found = _drain(core.operation_iter("find_agent_threads", {
            "project_id": "studio", "query": "", "agent": "", "source_id": "deepseek",
            "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": "local",
        }))
        self.assertEqual(len(found["threads"]), 1)
        self.assertFalse(found["coverage_complete"])
        self.assertEqual(found["coverage"][0]["state"], "association_unverified")

    def test_multi_tier_search_nfkc_ranking_and_zero_hit_browse_hint(self):
        time.sleep(0.05)
        tid_exact = "aaaaaaaa-1111-4111-8111-111111111111"
        tid_tokens = "bbbbbbbb-2222-4222-8222-222222222222"
        self._add_codex_session(tid_exact, self.project, "H3C 交付基线", [("请核对 H3C 交付文档", "已核对")])
        self._add_codex_session(tid_tokens, self.project, "3D 打印规划", [("第一轮讨论 H3C 主板", "收到"), ("第二轮安排交付计划", "收到")])
        # Foreign thread with matching text must NEVER be counted in total_project_threads!
        self._add_codex_session("cccccccc-3333-4333-8333-333333333333", self.foreign, "Foreign H3C 交付", [("secret", "secret")])

        core = self._core()
        # Full-width NFKC query "Ｈ３Ｃ 交付": exact substring ranks #1, token_all ranks #2!
        res = _drain(core.operation_iter("find_agent_threads", {
            "project_id": "studio", "query": "Ｈ３Ｃ 交付", "agent": "", "source_id": "codex",
            "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": "local",
        }))
        self.assertEqual([t["title"] for t in res["threads"]], ["H3C 交付基线", "3D 打印规划"])
        self.assertEqual(res["threads"][0]["match"]["mode"], "substring")
        self.assertEqual(res["threads"][1]["match"]["mode"], "token_all")
        self.assertEqual(res["threads"][0]["message_count"], 2)
        self.assertTrue(res["threads"][0]["supports_turns"])

        # Legacy find_codex_threads also supports multi-token matching!
        legacy_found = _drain(core.legacy._find_codex_threads_iter(
            query="Ｈ３Ｃ 交付", project_id="studio",
            caller={"actor": self.actor, "policy_actor": "local"},
        ))
        self.assertEqual([t["title"] for t in legacy_found["threads"]], ["H3C 交付基线", "3D 打印规划"])

        # 0-hit filtered search returns total_project_threads=2 (NOT 3!) + browse_hint!
        zero = _drain(core.operation_iter("find_agent_threads", {
            "project_id": "studio", "query": "nonexistent-needle-xyz", "agent": "", "source_id": "codex",
            "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": "local",
        }))
        self.assertEqual(zero["threads"], [])
        self.assertEqual(zero["total_project_threads"], 2)
        self.assertIn("query=''", zero["browse_hint"])

    def test_append_safe_initial_read_and_mid_pagination_consistency_and_tamper_rejection(self):
        time.sleep(0.05)
        tid = "dddddddd-4444-4444-8444-444444444444"
        rollout, base_ns = self._add_codex_session(
            tid, self.project, "Live Growing Codex",
            [("Turn 1 question", "Turn 1 answer"), ("Turn 2 question", "Turn 2 answer")],
        )
        core = self._core()
        found = _drain(core.operation_iter("find_agent_threads", {
            "project_id": "studio", "query": "", "agent": "", "source_id": "codex",
            "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": "local",
        }))
        tref = found["threads"][0]["thread_ref"]

        # 1. Append Turn 3 BETWEEN find_agent_threads and initial read_agent_thread(cursor="")!
        time.sleep(0.01)
        t3_iso = _iso_from_ns(time.time_ns())
        turn3 = [
            {"timestamp": t3_iso, "type": "turn_context", "payload": {"cwd": str(self.project), "turn_id": "turn-3"}},
            {"timestamp": t3_iso, "type": "response_item",
             "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Turn 3 question"}]}},
            {"timestamp": t3_iso, "type": "response_item",
             "payload": {"type": "message", "role": "assistant", "phase": "final_answer",
                         "content": [{"type": "output_text", "text": "Turn 3 answer"}]}},
        ]
        with rollout.open("ab") as fh:
            fh.write(_rollout_bytes(turn3))
        time.sleep(0.01)

        # Initial read succeeds smoothly and includes Turn 3 (6 messages total)!
        read_args = {
            "thread_ref": tref, "view": "all", "turn_id": "", "cursor": "",
            "limit": 2, "max_chars": 16000, "actor": self.actor, "policy_actor": "local",
        }
        p1 = _drain(core.operation_iter("read_agent_thread", read_args))
        p1 = _drain(core.revalidate_result_iter("read_agent_thread", read_args, p1))
        self.assertTrue(p1["has_more"])
        collected = list(p1["entries"])

        # 2. Append Turn 4 MID-PAGINATION!
        time.sleep(0.01)
        t4_iso = _iso_from_ns(time.time_ns())
        turn4 = [
            {"timestamp": t4_iso, "type": "turn_context", "payload": {"cwd": str(self.project), "turn_id": "turn-4"}},
            {"timestamp": t4_iso, "type": "response_item",
             "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Turn 4 question"}]}},
            {"timestamp": t4_iso, "type": "response_item",
             "payload": {"type": "message", "role": "assistant", "phase": "final_answer",
                         "content": [{"type": "output_text", "text": "Turn 4 answer"}]}},
        ]
        with rollout.open("ab") as fh:
            fh.write(_rollout_bytes(turn4))
        time.sleep(0.01)

        # Continue paging to end of frozen snapshot: ZERO duplicates, ZERO omissions, appended_since_snapshot=True!
        cursor = p1["next_cursor"]
        saw_appended_flag = False
        while cursor:
            step_args = {**read_args, "cursor": cursor}
            page = _drain(core.operation_iter("read_agent_thread", step_args))
            page = _drain(core.revalidate_result_iter("read_agent_thread", step_args, page))
            if page.get("appended_since_snapshot"):
                saw_appended_flag = True
            collected.extend(page["entries"])
            cursor = page["next_cursor"]

        self.assertTrue(saw_appended_flag)
        self.assertEqual([m["text"] for m in collected], [
            "Turn 1 question", "Turn 1 answer",
            "Turn 2 question", "Turn 2 answer",
            "Turn 3 question", "Turn 3 answer",
        ])
        self.assertEqual(len({m["message_id"] for m in collected}), 6)  # Zero duplicates!

        # Fresh read (view="latest_turn") immediately sees Turn 4!
        latest_args = {**read_args, "cursor": "", "view": "latest_turn", "limit": 10}
        latest = _drain(core.operation_iter("read_agent_thread", latest_args))
        latest = _drain(core.revalidate_result_iter("read_agent_thread", latest_args, latest))
        self.assertEqual([m["text"] for m in latest["entries"]], ["Turn 4 question", "Turn 4 answer"])

        # 3. NEGATIVE: tamper an earlier message mid-pagination -> MUST raise restart_required!
        p_tamper = _drain(core.operation_iter("read_agent_thread", read_args))
        p_tamper = _drain(core.revalidate_result_iter("read_agent_thread", read_args, p_tamper))
        raw_bytes = rollout.read_bytes().replace(b"Turn 1 question", b"TAMPERED 1 ques")
        rollout.write_bytes(raw_bytes)
        next_args = {**read_args, "cursor": p_tamper["next_cursor"]}
        next_page = _drain(core.operation_iter("read_agent_thread", next_args))
        with self.assertRaises(AccessError) as err:
            _drain(core.revalidate_result_iter("read_agent_thread", next_args, next_page))
        self.assertEqual(err.exception.code, "restart_required")

        # 4. NEGATIVE: revoke project mid-pagination -> MUST immediately deny!
        revoked = deepcopy(self.document)
        revoked["projects"] = [p for p in revoked["projects"] if p["id"] != "studio"]
        pr, dr = preview_activation(revoked, previous=AgentPolicy(self.descriptor, mode="v2").snapshot())
        self.epoch = activate_preview(self.store, pr, dr)
        with self.assertRaises(AccessError) as err:
            _drain(core.operation_iter("read_agent_thread", next_args))
        self.assertIn(err.exception.code, ("unauthorized", "restart_required"))

    def test_single_round_bounded_aggregate_service_four_sources(self):
        time.sleep(0.05)
        self._add_dsh_session("dsh-live", self.project, "DSH Live", [("DSH Q", "DSH A")])
        self._add_codex_session("eeeeeeee-5555-4555-8555-555555555555", self.project, "Codex Live", [("CDX Q", "CDX A")])
        pol = AgentPolicy(self.descriptor, mode="v2")
        pol.scratch = self.scratch
        cat = Catalog.from_policy(pol)
        cat.set_agent_history_policy(pol)
        leg = HistoryAccess(catalog=cat, unified_policy=pol)
        svc = AgentHistoryService(pol, leg, local=True)
        svc.start(monitor_locations=False)
        self.addCleanup(svc.close)
        self.addCleanup(leg.close)
        # Completes all 3 enabled sources in ONE single call (rounds=1)!
        res = svc.find_agent_threads("studio", limit=10)
        self.assertEqual(res["status"], "ready")
        self.assertEqual({t["title"] for t in res["threads"]}, {"DSH Live", "Codex Live"})


if __name__ == "__main__":
    unittest.main()
