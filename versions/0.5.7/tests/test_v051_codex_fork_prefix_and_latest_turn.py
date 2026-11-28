"""v0.5.1 WS-R1 tests: Codex sparse fork public prefix recovery, cutoff isolation, latest_turn parity, and .zst e2e."""

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

from backports import zstd

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import activate_preview, compile_generation, preview_activation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
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


def _iso(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


def _jsonl(records):
    return b"".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n" for r in records)


def _turn_records(cwd, ts_iso, turn_id, user_text, assistant_text):
    return [
        {"timestamp": ts_iso, "type": "turn_context", "payload": {"cwd": str(cwd), "turn_id": turn_id}},
        {
            "timestamp": ts_iso,
            "type": "response_item",
            "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": user_text}]},
        },
        {
            "timestamp": ts_iso,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": assistant_text}],
            },
        },
    ]


def _session_meta(thread_id, cwd, ts_iso, *, forked_from_id=None, history_base=None, cli_version="0.171.0-alpha.13"):
    payload = {
        "id": thread_id,
        "cwd": str(cwd),
        "timestamp": ts_iso,
        "cli_version": cli_version,
        "history_mode": "paginated",
    }
    if forked_from_id is not None:
        payload["forked_from_id"] = forked_from_id
    if history_base is not None:
        payload["history_base"] = history_base
        payload["forked_from_ordinal_exclusive"] = history_base["end_ordinal_exclusive"]
    return {"timestamp": ts_iso, "type": "session_meta", "payload": payload}


class CodexForkPrefixAndLatestTurnTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o700)

        self.alpha = self.root / "alpha"
        self.alpha.mkdir()
        _git(self.alpha, "init", "-q")
        (self.alpha / "README.md").write_text("alpha\n", encoding="utf-8")
        _git(self.alpha, "add", "README.md")
        _git(self.alpha, "commit", "-q", "-m", "init")

        self.beta = self.root / "beta"
        self.beta.mkdir()
        _git(self.beta, "init", "-q")
        (self.beta / "README.md").write_text("beta\n", encoding="utf-8")
        _git(self.beta, "add", "README.md")
        _git(self.beta, "commit", "-q", "-m", "init")

        self.codex_home = self.root / "codex-home"
        (self.codex_home / "sessions").mkdir(parents=True)
        self.state_db = self.codex_home / "state_5.sqlite"
        with closing(sqlite3.connect(self.state_db)) as db:
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
                {"id": "alpha", "name": "Alpha", "root": str(self.alpha), "repository_id": repository_probe(self.alpha)["repository_id"]},
                {"id": "beta", "name": "Beta", "root": str(self.beta), "repository_id": repository_probe(self.beta)["repository_id"]},
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
        self.epoch = activate_preview(self.store, preview, digest, initial=True)
        write_descriptor(self.descriptor, self.store)
        time.sleep(0.05)
        self.now_ns = time.time_ns()

    def _add_thread(self, tid, cwd, records, *, created_s, title="Thread", compress=False):
        ext = ".jsonl.zst" if compress else ".jsonl"
        folder = self.codex_home / "sessions" / "2026" / "11" / "24"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"rollout-2026-11-24T00-00-00-{tid}{ext}"
        raw = _jsonl(records)
        path.write_bytes(zstd.compress(raw) if compress else raw)
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute(
                "INSERT OR REPLACE INTO threads VALUES(?,?,?,?,?,0,?)",
                (tid, str(path), str(cwd), title, created_s, created_s),
            )
            db.commit()
        return path, len(raw), len(records)

    def _engine(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        core = AgentHistoryCore(policy, catalog, legacy, b"k" * 32)
        return policy, catalog, legacy, core

    def _read_all_agent(self, core, project_id, title_or_idx=0, *, limit=2):
        found = _drain(core._find(project_id, "", "", "codex", "", 20, self.actor, "local"))
        threads = found["threads"]
        if isinstance(title_or_idx, str):
            row = next(t for t in threads if t["title"] == title_or_idx)
        else:
            row = threads[title_or_idx]
        ref = row["thread_ref"]
        entries, cursor, warnings, complete = [], "", [], True
        while True:
            body = _drain(core._read(ref, "all", "", cursor, limit, 16000, self.actor, "local"))
            entries.extend(body["entries"])
            warnings = body["warnings"]
            complete = body["coverage_complete"]
            if not body["has_more"]:
                break
            cursor = body["next_cursor"]
        return row, entries, warnings, complete

    def _read_all_legacy(self, legacy, tid, *, limit=2):
        caller = {"actor": self.actor, "policy_actor": "local"}
        entries, cursor, last = [], "", None
        while True:
            page = _drain(legacy._read_codex_thread_iter(tid, cursor=cursor, limit=limit, caller=caller))
            entries.extend(page["entries"])
            last = page
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        return entries, last

    def test_one_hop_and_two_hop_sparse_forks_recover_exact_prefix_without_post_fork_bleed(self):
        t1 = self.now_ns
        t2 = t1 + 1_000_000
        t3 = t2 + 1_000_000
        t4 = t3 + 1_000_000
        t5 = t4 + 1_000_000

        tid_a = "11111111-1111-4111-8111-111111111111"
        tid_b = "22222222-2222-4222-8222-222222222222"
        tid_c = "33333333-3333-4333-8333-333333333333"

        # Parent A: 2 pre-fork turns
        a_pre = [
            _session_meta(tid_a, self.alpha, _iso(t1)),
            *_turn_records(self.alpha, _iso(t1), "turn-a1", "A prompt 1", "A answer 1"),
            *_turn_records(self.alpha, _iso(t2), "turn-a2", "A prompt 2", "A answer 2"),
        ]
        path_a, a_cutoff_bytes, a_cutoff_lines = self._add_thread(tid_a, self.alpha, a_pre, created_s=int(t1 // 1e9), title="Thread A")

        # Child B forks from A at (a_cutoff_lines, a_cutoff_bytes) and adds 1 turn
        b_pre = [
            _session_meta(
                tid_b, self.alpha, _iso(t3), forked_from_id=tid_a,
                history_base={"thread_id": tid_a, "end_ordinal_exclusive": a_cutoff_lines, "end_byte_offset": a_cutoff_bytes},
            ),
            *_turn_records(self.alpha, _iso(t3), "turn-b1", "B prompt 3", "B answer 3"),
        ]
        path_b, b_cutoff_bytes, b_local_lines = self._add_thread(tid_b, self.alpha, b_pre, created_s=int(t3 // 1e9), title="Thread B")

        # Post-fork turn appended to A AFTER B forked (must NEVER bleed into B or C!)
        a_post = _turn_records(self.alpha, _iso(t4), "turn-a-post", "A POST-FORK SECRET", "A POST-FORK ANSWER")
        with path_a.open("ab") as fh:
            fh.write(_jsonl(a_post))

        # Grandchild C forks from B using cumulative ordinal = a_cutoff_lines + b_local_lines (exact Codex CLI 0.171 behavior!)
        c_records = [
            _session_meta(
                tid_c, self.alpha, _iso(t4), forked_from_id=tid_b,
                history_base={"thread_id": tid_b, "end_ordinal_exclusive": a_cutoff_lines + b_local_lines, "end_byte_offset": b_cutoff_bytes},
            ),
            *_turn_records(self.alpha, _iso(t4), "turn-c1", "C prompt 4", "C answer 4"),
        ]
        self._add_thread(tid_c, self.alpha, c_records, created_s=int(t4 // 1e9), title="Thread C")

        # Post-fork turn appended to B AFTER C forked (must NEVER bleed into C!)
        b_post = _turn_records(self.alpha, _iso(t5), "turn-b-post", "B POST-FORK SECRET", "B POST-FORK ANSWER")
        with path_b.open("ab") as fh:
            fh.write(_jsonl(b_post))

        _, _, legacy, core = self._engine()

        # Verify 1-hop B (has A's 2 pre-fork turns + B's 2 own turns = 8 msgs; NO A post-fork!)
        expected_b = [
            ("user", "A prompt 1"), ("assistant", "A answer 1"),
            ("user", "A prompt 2"), ("assistant", "A answer 2"),
            ("user", "B prompt 3"), ("assistant", "B answer 3"),
            ("user", "B POST-FORK SECRET"), ("assistant", "B POST-FORK ANSWER"),
        ]
        _, agent_b, warn_b, comp_b = self._read_all_agent(core, "alpha", "Thread B", limit=2)
        self.assertEqual([(e["role"], e["text"]) for e in agent_b], expected_b)
        self.assertTrue(comp_b)
        self.assertEqual(warn_b, [])

        leg_b, last_b = self._read_all_legacy(legacy, tid_b, limit=2)
        self.assertEqual([(e["role"], e["text"]) for e in leg_b], expected_b)
        self.assertTrue(last_b["complete_public_projection"])
        self.assertTrue(last_b["inherited_context"]["followed_other_threads"])
        self.assertEqual(last_b["inherited_context"]["followed_ancestor_count"], 1)
        self.assertTrue(last_b["inherited_context"]["cutoff_verified"])

        # Verify 2-hop C (A pre-fork + B pre-fork + C own = 8 msgs; ZERO post-fork bleed from A or B!)
        expected_c = [
            ("user", "A prompt 1"), ("assistant", "A answer 1"),
            ("user", "A prompt 2"), ("assistant", "A answer 2"),
            ("user", "B prompt 3"), ("assistant", "B answer 3"),
            ("user", "C prompt 4"), ("assistant", "C answer 4"),
        ]
        _, agent_c, warn_c, comp_c = self._read_all_agent(core, "alpha", "Thread C", limit=2)
        self.assertEqual([(e["role"], e["text"]) for e in agent_c], expected_c)
        self.assertTrue(comp_c)
        self.assertEqual(warn_c, [])

        leg_c, last_c = self._read_all_legacy(legacy, tid_c, limit=2)
        self.assertEqual([(e["role"], e["text"]) for e in leg_c], expected_c)
        self.assertTrue(last_c["complete_public_projection"])
        self.assertEqual(last_c["inherited_context"]["followed_ancestor_count"], 2)
        self.assertTrue(last_c["inherited_context"]["cutoff_verified"])

    def test_missing_cutoff_and_misaligned_parent_report_incomplete_without_expanding(self):
        t1 = self.now_ns
        t2 = t1 + 1_000_000
        tid_p = "44444444-4444-4444-8444-444444444444"
        tid_nocut = "55555555-5555-4555-8555-555555555555"
        tid_badcut = "66666666-6666-4666-8666-666666666666"

        p_rec = [_session_meta(tid_p, self.alpha, _iso(t1)), *_turn_records(self.alpha, _iso(t1), "tp1", "Parent U", "Parent A")]
        self._add_thread(tid_p, self.alpha, p_rec, created_s=int(t1 // 1e9), title="Parent")

        # Fork WITHOUT history_base cutoff
        nocut_rec = [
            _session_meta(tid_nocut, self.alpha, _iso(t2), forked_from_id=tid_p, history_base=None),
            *_turn_records(self.alpha, _iso(t2), "tc1", "Child NoCut U", "Child NoCut A"),
        ]
        self._add_thread(tid_nocut, self.alpha, nocut_rec, created_s=int(t2 // 1e9), title="NoCut")

        # Fork WITH wrong end_byte_offset (simulates rewritten/misaligned parent)
        badcut_rec = [
            _session_meta(
                tid_badcut, self.alpha, _iso(t2), forked_from_id=tid_p,
                history_base={"thread_id": tid_p, "end_ordinal_exclusive": len(p_rec), "end_byte_offset": 999999},
            ),
            *_turn_records(self.alpha, _iso(t2), "tc2", "Child BadCut U", "Child BadCut A"),
        ]
        self._add_thread(tid_badcut, self.alpha, badcut_rec, created_s=int(t2 // 1e9), title="BadCut")

        _, _, legacy, core = self._engine()

        for title, tid, expected_u in [("NoCut", tid_nocut, "Child NoCut U"), ("BadCut", tid_badcut, "Child BadCut U")]:
            _, agent_entries, warn, comp = self._read_all_agent(core, "alpha", title, limit=10)
            self.assertEqual([e["text"] for e in agent_entries], [expected_u, expected_u.replace(" U", " A")])
            self.assertFalse(comp)
            self.assertIn("inherited_prefix_unverified", warn)

            leg_entries, last = self._read_all_legacy(legacy, tid, limit=10)
            self.assertEqual([e["text"] for e in leg_entries], [expected_u, expected_u.replace(" U", " A")])
            self.assertFalse(last["complete_public_projection"])
            self.assertIn("inherited_prefix_unverified", last["warnings"])
            self.assertFalse(last["inherited_context"]["followed_other_threads"])
            self.assertFalse(last["inherited_context"]["cutoff_verified"])

    def test_denied_or_cross_project_ancestor_fails_closed(self):
        t1 = self.now_ns
        t2 = t1 + 1_000_000
        tid_beta = "77777777-7777-4777-8777-777777777777"
        tid_cross_child = "88888888-8888-4888-8888-888888888888"

        beta_rec = [_session_meta(tid_beta, self.beta, _iso(t1)), *_turn_records(self.beta, _iso(t1), "tb1", "BETA SECRET", "BETA ANS")]
        _, b_bytes, b_lines = self._add_thread(tid_beta, self.beta, beta_rec, created_s=int(t1 // 1e9), title="Beta Parent")

        child_rec = [
            _session_meta(
                tid_cross_child, self.alpha, _iso(t2), forked_from_id=tid_beta,
                history_base={"thread_id": tid_beta, "end_ordinal_exclusive": b_lines, "end_byte_offset": b_bytes},
            ),
            *_turn_records(self.alpha, _iso(t2), "tc1", "Alpha Child U", "Alpha Child A"),
        ]
        self._add_thread(tid_cross_child, self.alpha, child_rec, created_s=int(t2 // 1e9), title="Cross Child")

        _, _, legacy, core = self._engine()
        found = _drain(core._find("alpha", "", "", "codex", "", 20, self.actor, "local"))
        self.assertEqual(found["threads"], [])
        with self.assertRaises(AccessError):
            _drain(legacy._read_codex_thread_iter(tid_cross_child, caller={"actor": self.actor, "policy_actor": "local"}))

        # Also deny a same-project parent via denied_threads and verify fail-closed on both APIs!
        tid_same_p = "77777777-7777-4777-8777-777777777778"
        tid_same_c = "88888888-8888-4888-8888-888888888889"
        p_rec = [_session_meta(tid_same_p, self.alpha, _iso(t1)), *_turn_records(self.alpha, _iso(t1), "ts1", "DENIED PARENT", "DENIED ANS")]
        _, p_bytes, p_lines = self._add_thread(tid_same_p, self.alpha, p_rec, created_s=int(t1 // 1e9), title="SameParent")
        c_rec = [
            _session_meta(
                tid_same_c, self.alpha, _iso(t2), forked_from_id=tid_same_p,
                history_base={"thread_id": tid_same_p, "end_ordinal_exclusive": p_lines, "end_byte_offset": p_bytes},
            ),
            *_turn_records(self.alpha, _iso(t2), "ts2", "ChildOfDenied U", "ChildOfDenied A"),
        ]
        self._add_thread(tid_same_c, self.alpha, c_rec, created_s=int(t2 // 1e9), title="ChildOfDenied")
        denied_doc = deepcopy(self.document)
        denied_doc["sources"]["codex"]["denied_threads"] = [tid_same_p]
        prev_raw = (self.state_dir / "active.json").read_bytes()
        import hashlib
        prev_digest = hashlib.sha256(prev_raw).hexdigest()
        self.store.activate(denied_doc, expected_digest=prev_digest)
        _, _, legacy2, core2 = self._engine()
        found2 = _drain(core2._find("alpha", "", "", "codex", "", 20, self.actor, "local"))
        self.assertEqual(found2["threads"], [])
        with self.assertRaises(AccessError):
            _drain(legacy2._read_codex_thread_iter(tid_same_c, caller={"actor": self.actor, "policy_actor": "local"}))

    def test_parent_rewrite_during_pagination_invalidates_child_cursor(self):
        t1 = self.now_ns
        t2 = t1 + 1_000_000
        tid_p = "99999999-9999-4999-8999-999999999999"
        tid_c = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

        p_rec = [
            _session_meta(tid_p, self.alpha, _iso(t1)),
            *_turn_records(self.alpha, _iso(t1), "tp1", "P1", "PA1"),
            *_turn_records(self.alpha, _iso(t1), "tp2", "P2", "PA2"),
        ]
        path_p, p_bytes, p_lines = self._add_thread(tid_p, self.alpha, p_rec, created_s=int(t1 // 1e9), title="P")
        c_rec = [
            _session_meta(
                tid_c, self.alpha, _iso(t2), forked_from_id=tid_p,
                history_base={"thread_id": tid_p, "end_ordinal_exclusive": p_lines, "end_byte_offset": p_bytes},
            ),
            *_turn_records(self.alpha, _iso(t2), "tc1", "C1", "CA1"),
        ]
        self._add_thread(tid_c, self.alpha, c_rec, created_s=int(t2 // 1e9), title="C")

        _, _, legacy, _ = self._engine()
        caller = {"actor": self.actor, "policy_actor": "local"}
        p1 = _drain(legacy._read_codex_thread_iter(tid_c, limit=2, caller=caller))
        self.assertTrue(p1["has_more"])
        # Appending post-fork turn to parent MUST allow page 2 cleanly!
        with path_p.open("ab") as fh:
            fh.write(_jsonl(_turn_records(self.alpha, _iso(t2 + 1_000_000), "tp3", "P3 POST", "PA3 POST")))
        p2 = _drain(legacy._read_codex_thread_iter(tid_c, cursor=p1["next_cursor"], limit=2, caller=caller))
        self.assertEqual([e["text"] for e in p2["entries"]], ["P2", "PA2"])
        # Rewriting parent pre-fork bytes MUST fail page 3 immediately!
        raw = path_p.read_bytes().replace(b"PA1", b"XX1")
        path_p.write_bytes(raw)
        with self.assertRaises(AccessError) as caught:
            _drain(legacy._read_codex_thread_iter(tid_c, cursor=p2["next_cursor"], limit=2, caller=caller))
        self.assertEqual(caught.exception.code, "source_changed")

    def test_latest_turn_parity_when_pre_turn_message_has_empty_turn_id(self):
        t1 = self.now_ns
        tid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        # Matches real 0.169 sparse fork shape: pre-turn user item before first task_started/turn_context.
        records = [
            _session_meta(tid, self.alpha, _iso(t1), cli_version="0.169.0-alpha.11.1"),
            {
                "timestamp": _iso(t1),
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Pre-turn bridge"}]},
            },
            *_turn_records(self.alpha, _iso(t1), "turn-real-latest", "Latest Q", "Latest A"),
        ]
        self._add_thread(tid, self.alpha, records, created_s=int(t1 // 1e9), title="PreTurnBridge")

        _, _, legacy, core = self._engine()
        caller = {"actor": self.actor, "policy_actor": "local"}
        leg_lt = _drain(legacy._read_codex_thread_iter(tid, view="latest_turn", caller=caller))
        self.assertEqual([(e["role"], e["text"]) for e in leg_lt["entries"]], [("user", "Latest Q"), ("assistant", "Latest A")])

        found = _drain(core._find("alpha", "", "", "codex", "", 20, self.actor, "local"))
        summary = found["threads"][0]
        self.assertTrue(summary["supports_turns"])
        agent_lt = _drain(core._read(summary["thread_ref"], "latest_turn", "", "", 20, 16000, self.actor, "local"))
        self.assertEqual([(e["role"], e["text"]) for e in agent_lt["entries"]], [("user", "Latest Q"), ("assistant", "Latest A")])

    def test_authorized_zstd_compressed_rollout_and_zstd_fork_parent_read_end_to_end(self):
        t1 = self.now_ns
        t2 = t1 + 1_000_000
        tid_p = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        tid_c = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

        p_rec = [
            _session_meta(tid_p, self.alpha, _iso(t1)),
            *_turn_records(self.alpha, _iso(t1), "tz1", "Compressed parent Q", "Compressed parent A"),
        ]
        _, p_decoded_bytes, p_lines = self._add_thread(tid_p, self.alpha, p_rec, created_s=int(t1 // 1e9), title="Zstd Parent", compress=True)
        c_rec = [
            _session_meta(
                tid_c, self.alpha, _iso(t2), forked_from_id=tid_p,
                history_base={"thread_id": tid_p, "end_ordinal_exclusive": p_lines, "end_byte_offset": p_decoded_bytes},
            ),
            *_turn_records(self.alpha, _iso(t2), "tz2", "Compressed child Q", "Compressed child A"),
        ]
        self._add_thread(tid_c, self.alpha, c_rec, created_s=int(t2 // 1e9), title="Zstd Child", compress=True)

        _, _, legacy, core = self._engine()
        _, entries, warn, comp = self._read_all_agent(core, "alpha", "Zstd Child", limit=2)
        self.assertEqual(
            [(e["role"], e["text"]) for e in entries],
            [("user", "Compressed parent Q"), ("assistant", "Compressed parent A"),
             ("user", "Compressed child Q"), ("assistant", "Compressed child A")],
        )
        self.assertTrue(comp)
        self.assertEqual(warn, [])
        leg_entries, last = self._read_all_legacy(legacy, tid_c, limit=2)
        self.assertEqual([(e["role"], e["text"]) for e in leg_entries], [(e["role"], e["text"]) for e in entries])
        self.assertEqual(last["snapshot"]["storage_encoding"], "zstd")


if __name__ == "__main__":
    unittest.main()
