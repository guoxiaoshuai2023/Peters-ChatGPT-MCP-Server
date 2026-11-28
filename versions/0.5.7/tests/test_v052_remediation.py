"""v0.5.2 targeted L4 remediation regression tests.

Covers:
1. Codex attached_thread=true sessions deliver ONLY own public turns (excluding
   pre-fork parent turns and excluding synthetic auto-compact-* bridge items),
   expose attached_thread metadata, and strictly enforce parent authorization
   (deny-list, cross-project, mid-pagination parent revocation, mismatched DB parent),
   while normal non-attached forks still reconstruct cutoff-verified parent prefixes.
2. Codex multimodal <image ...> / </image> wrapper blocks around attached images
   deduplicate 1-to-1 with UserMessage (eliminating H3C duplicate user message)
   while preserving genuine consecutive identical user sends and literal <image> text.
3. release_cutover.py CLI rollback recovers cleanly from 0-byte, 96-byte truncated,
   invalid-UTF8, and partial-payload manifest interruptions, and restored runtime
   enforces prior project revocations, old thread_refs, and old cursors.
4. Antigravity _CAPTURE_CACHE binds all four dependency stamp groups (INDEX, native DB,
   transcripts, related child DBs) end-to-end and refuses to cache if any dependency
   mutates between verification and cache store.
"""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from peters_mcp import agent_history_antigravity_native as ag_native
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


def _jsonl(records):
    return b"".join(
        json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for r in records
    )


def _iso(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


class CodexAttachedThreadAndMultimodalTests(unittest.TestCase):
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
                "history_mode TEXT, attached_thread_parent_id TEXT)"
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

    def _make_engines(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        scratch = self.root / f"scratch-{time.time_ns()}"
        scratch.mkdir(mode=0o700)
        policy.scratch = scratch
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        core = AgentHistoryCore(policy, catalog, legacy, b"k" * 32)
        return legacy, core

    def test_attached_thread_vs_normal_fork_and_parent_acl(self):
        parent_id = "11111111-1111-4111-8111-111111111111"
        attached_id = "22222222-2222-4222-8222-222222222222"
        normal_fork_id = "33333333-3333-4333-8333-333333333333"
        cross_parent_id = "44444444-4444-4444-8444-444444444444"
        cross_attached_id = "55555555-5555-4555-8555-555555555555"
        mismatch_attached_id = "66666666-6666-4666-8666-666666666666"

        t0 = _iso(self.now_ns - 5_000_000)
        t1 = _iso(self.now_ns - 4_000_000)
        t2 = _iso(self.now_ns - 3_000_000)
        t3 = _iso(self.now_ns - 2_000_000)

        parent_pre = [
            {"timestamp": t0, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(self.alpha), "timestamp": t0, "cli_version": "0.171.0", "history_mode": "paginated"}},
            {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-turn-1"}},
            {"timestamp": t0, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Parent Q1"}]}},
            {"timestamp": t0, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Parent A1"}]}},
            {"timestamp": t1, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-turn-2"}},
            {"timestamp": t1, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Parent Q2"}]}},
            {"timestamp": t1, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Parent A2"}]}},
        ]
        pre_bytes = _jsonl(parent_pre)
        cutoff_ord = len(parent_pre)
        cutoff_byte = len(pre_bytes)

        parent_post = [
            {"timestamp": t3, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "p-turn-post"}},
            {"timestamp": t3, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Parent PostFork Q3"}]}},
            {"timestamp": t3, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Parent PostFork A3"}]}},
        ]
        p_path = self.folder / f"rollout-2026-11-25T00-00-00-{parent_id}.jsonl"
        p_path.write_bytes(pre_bytes + _jsonl(parent_post))

        # Attached side-thread: carries attached_thread=True, history_base, AND auto-compact-1 bridge!
        att_rows = [
            {
                "timestamp": t2,
                "type": "session_meta",
                "payload": {
                    "id": attached_id,
                    "forked_from_id": parent_id,
                    "attached_thread": True,
                    "forked_from_ordinal_exclusive": cutoff_ord,
                    "history_base": {"thread_id": parent_id, "end_ordinal_exclusive": cutoff_ord, "end_byte_offset": cutoff_byte},
                    "cwd": str(self.alpha),
                    "timestamp": t2,
                    "cli_version": "0.171.0",
                    "history_mode": "paginated",
                },
            },
            {
                "timestamp": t2,
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "SYSTEM AUTO COMPACT SUMMARY " * 60}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "auto-compact-1",
                        "create_time": 1794812093.6,
                        "content_item_kinds": ["unknown"],
                    },
                },
            },
            {"timestamp": t2, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "att-turn-1"}},
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "att-turn-1"}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Attached Child Q1"}]}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "commentary", "content": [{"type": "output_text", "text": "Attached Child Commentary"}]}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Attached Child Final"}]}},
        ]
        att_path = self.folder / f"rollout-2026-11-25T00-00-01-{attached_id}.jsonl"
        att_path.write_bytes(_jsonl(att_rows))

        # Normal non-attached fork at the exact same cutoff (also test auto-compact-1 filtering if present).
        fork_rows = [
            {
                "timestamp": t2,
                "type": "session_meta",
                "payload": {
                    "id": normal_fork_id,
                    "forked_from_id": parent_id,
                    "forked_from_ordinal_exclusive": cutoff_ord,
                    "history_base": {"thread_id": parent_id, "end_ordinal_exclusive": cutoff_ord, "end_byte_offset": cutoff_byte},
                    "cwd": str(self.alpha),
                    "timestamp": t2,
                    "cli_version": "0.171.0",
                    "history_mode": "paginated",
                },
            },
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "f-turn-1"}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Normal Fork Q3"}]}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Normal Fork A3"}]}},
        ]
        fork_path = self.folder / f"rollout-2026-11-25T00-00-02-{normal_fork_id}.jsonl"
        fork_path.write_bytes(_jsonl(fork_rows))

        # Cross-project parent (in unauthorized beta) + attached child claiming alpha cwd.
        cp_rows = [
            {"timestamp": t0, "type": "session_meta", "payload": {"id": cross_parent_id, "cwd": str(self.beta), "timestamp": t0, "cli_version": "0.171.0", "history_mode": "paginated"}},
            {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(self.beta), "turn_id": "cp-1"}},
            {"timestamp": t0, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Secret Beta Q"}]}},
        ]
        cp_bytes = _jsonl(cp_rows)
        cp_path = self.folder / f"rollout-2026-11-25T00-00-03-{cross_parent_id}.jsonl"
        cp_path.write_bytes(cp_bytes)

        ca_rows = [
            {
                "timestamp": t2,
                "type": "session_meta",
                "payload": {
                    "id": cross_attached_id,
                    "forked_from_id": cross_parent_id,
                    "attached_thread": True,
                    "forked_from_ordinal_exclusive": len(cp_rows),
                    "history_base": {"thread_id": cross_parent_id, "end_ordinal_exclusive": len(cp_rows), "end_byte_offset": len(cp_bytes)},
                    "cwd": str(self.alpha),
                    "timestamp": t2,
                    "cli_version": "0.171.0",
                    "history_mode": "paginated",
                },
            },
            {"timestamp": t2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "ca-1"}},
            {"timestamp": t2, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Cross Attached Q"}]}},
        ]
        ca_path = self.folder / f"rollout-2026-11-25T00-00-04-{cross_attached_id}.jsonl"
        ca_path.write_bytes(_jsonl(ca_rows))

        # Attached thread with mismatched attached_thread_parent_id in SQLite.
        mm_rows = [dict(r) for r in att_rows]
        mm_rows[0] = {**att_rows[0], "payload": {**att_rows[0]["payload"], "id": mismatch_attached_id}}
        mm_path = self.folder / f"rollout-2026-11-25T00-00-05-{mismatch_attached_id}.jsonl"
        mm_path.write_bytes(_jsonl(mm_rows))

        sec = int(self.now_ns // 1_000_000_000)
        with closing(sqlite3.connect(self.state_db)) as db:
            db.executemany(
                "INSERT INTO threads VALUES(?,?,?,?,?,0,?,?,?)",
                [
                    (parent_id, str(p_path), str(self.alpha), "ParentTitle", sec, sec, "paginated", None),
                    (attached_id, str(att_path), str(self.alpha), "AttachedTitle", sec, sec, "paginated", parent_id),
                    (normal_fork_id, str(fork_path), str(self.alpha), "NormalForkTitle", sec, sec, "paginated", None),
                    (cross_parent_id, str(cp_path), str(self.beta), "BetaParent", sec, sec, "paginated", None),
                    (cross_attached_id, str(ca_path), str(self.alpha), "CrossAttached", sec, sec, "paginated", cross_parent_id),
                    (mismatch_attached_id, str(mm_path), str(self.alpha), "MismatchAttached", sec, sec, "paginated", normal_fork_id),
                ],
            )
            db.commit()

        legacy, core = self._make_engines()
        self.addCleanup(legacy.close)

        # Discovery MUST include only parent, attached_id, and normal_fork_id (rejecting cross_attached & mismatch_attached!).
        found = _drain(core._find("alpha", "", "", "codex", "", 20, self.actor, "local"))
        by_title = {row["title"]: row for row in found["threads"]}
        self.assertEqual(set(by_title), {"ParentTitle", "AttachedTitle", "NormalForkTitle"})
        self.assertTrue(by_title["AttachedTitle"].get("attached_thread"))
        self.assertFalse(by_title["NormalForkTitle"].get("attached_thread", False))
        self.assertEqual(by_title["AttachedTitle"]["message_count"], 3)
        self.assertEqual(by_title["NormalForkTitle"]["message_count"], 6)

        # Unified & legacy read on attached_id: ONLY its 3 own messages, zero auto-compact-1, zero parent messages!
        expected_att = [
            ("user", "Attached Child Q1"),
            ("assistant", "Attached Child Commentary"),
            ("assistant", "Attached Child Final"),
        ]
        u_att = _drain(core._read(by_title["AttachedTitle"]["thread_ref"], "all", "", "", 20, 16000, self.actor, "local"))
        self.assertEqual([(e["role"], e["text"]) for e in u_att["entries"]], expected_att)
        self.assertTrue(u_att["coverage_complete"])
        self.assertTrue(u_att["thread"]["attached_thread"])

        l_att_p1 = _drain(legacy._read_codex_thread_iter(attached_id, view="all", limit=2, caller=self.caller))
        l_att_p2 = _drain(legacy._read_codex_thread_iter(attached_id, view="all", limit=2, cursor=l_att_p1["next_cursor"], caller=self.caller))
        self.assertEqual([(e["role"], e["text"]) for e in l_att_p1["entries"] + l_att_p2["entries"]], expected_att)
        self.assertEqual(
            l_att_p1["inherited_context"],
            {
                "stored_ancestor_headers": 0,
                "followed_other_threads": False,
                "attached_thread": True,
                "parent_context_inlined": False,
                "verified_ancestor_count": 1,
            },
        )
        self.assertTrue(l_att_p1["complete_public_projection"])

        # Normal fork still reconstructs the exact 4 pre-fork parent messages + 2 own messages!
        expected_fork = [
            ("user", "Parent Q1"),
            ("assistant", "Parent A1"),
            ("user", "Parent Q2"),
            ("assistant", "Parent A2"),
            ("user", "Normal Fork Q3"),
            ("assistant", "Normal Fork A3"),
        ]
        u_fork = _drain(core._read(by_title["NormalForkTitle"]["thread_ref"], "all", "", "", 20, 16000, self.actor, "local"))
        self.assertEqual([(e["role"], e["text"]) for e in u_fork["entries"]], expected_fork)

        # Cross-project and mismatched attached threads fail closed on direct legacy read too.
        for bad_id in (cross_attached_id, mismatch_attached_id):
            with self.assertRaises(AccessError):
                _drain(legacy._read_codex_thread_iter(bad_id, view="all", caller=self.caller))

        # Denying parent_id in live policy immediately blocks attached_id (including mid-pagination cursor!).
        mid_page = _drain(legacy._read_codex_thread_iter(attached_id, view="all", limit=1, caller=self.caller))
        self.assertTrue(mid_page["has_more"])
        revoked = deepcopy(self.document)
        revoked["sources"]["codex"]["denied_threads"] = [parent_id]
        prev_digest = hashlib.sha256((self.state_dir / "active.json").read_bytes()).hexdigest()
        self.store.activate(revoked, expected_digest=prev_digest)

        with self.assertRaises(AccessError):
            _drain(legacy._read_codex_thread_iter(attached_id, view="all", limit=1, cursor=mid_page["next_cursor"], caller=self.caller))
        with self.assertRaises(AccessError):
            _drain(core._read(by_title["AttachedTitle"]["thread_ref"], "all", "", "", 20, 16000, self.actor, "local"))

    def test_multimodal_image_wrapper_dedup_preserves_consecutive_identical_sends(self):
        tid = "77777777-7777-4777-8777-777777777777"
        ts = _iso(self.now_ns)
        rows = [
            {"timestamp": ts, "type": "session_meta", "payload": {"id": tid, "cwd": str(self.alpha), "timestamp": ts, "cli_version": "0.171.0"}},
            # Turn 1: Single multimodal user send (1 response_item with <image>...</image> + 1 UserMessage) -> MUST emit 1 user message!
            {"timestamp": ts, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "t-img-1"}},
            {
                "timestamp": ts,
                "type": "response_item",
                "payload": {
                    "id": "ri-1",
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Inspect nozzle photo"},
                        {"type": "input_text", "text": '<image name=[Image #1] path="/Users/someone/secret/nozzle.png">'},
                        {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
                        {"type": "input_text", "text": "</image>"},
                    ],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "t-img-1",
                        "content_item_metadata": [
                            {"provenance": {"type": "user"}},
                            {"provenance": {"type": "user"}},
                            {"provenance": {"type": "user"}},
                            {"provenance": {"type": "user"}},
                        ],
                    },
                },
            },
            {
                "timestamp": ts,
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "turn_id": "t-img-1",
                    "item": {
                        "id": "ev-1",
                        "type": "UserMessage",
                        "content": [
                            {"type": "text", "text": "Inspect nozzle photo"},
                            {"type": "local_image", "path": "/Users/someone/secret/nozzle.png"},
                        ],
                    },
                },
            },
            {"timestamp": ts, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Nozzle looks clean."}]}},
            # Turn 2: User genuinely sends TWO identical consecutive messages in the same turn -> BOTH must be preserved!
            {"timestamp": ts, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "t-dup-2"}},
            {"timestamp": ts, "type": "response_item", "payload": {"id": "ri-2a", "type": "message", "role": "user", "content": [{"type": "input_text", "text": "Run check again"}]}},
            {"timestamp": ts, "type": "event_msg", "payload": {"type": "item_completed", "turn_id": "t-dup-2", "item": {"id": "ev-2a", "type": "UserMessage", "content": [{"type": "text", "text": "Run check again"}]}}},
            {"timestamp": ts, "type": "response_item", "payload": {"id": "ri-2b", "type": "message", "role": "user", "content": [{"type": "input_text", "text": "Run check again"}]}},
            {"timestamp": ts, "type": "event_msg", "payload": {"type": "item_completed", "turn_id": "t-dup-2", "item": {"id": "ev-2b", "type": "UserMessage", "content": [{"type": "text", "text": "Run check again"}]}}},
            {"timestamp": ts, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Checked twice."}]}},
            # Turn 3: User writes literal <image ...> tag WITHOUT an image block -> preserved literally!
            {"timestamp": ts, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "t-lit-3"}},
            {"timestamp": ts, "type": "response_item", "payload": {"id": "ri-3", "type": "message", "role": "user", "content": [{"type": "input_text", "text": '<image name="demo">'}, {"type": "input_text", "text": "literal xml"}, {"type": "input_text", "text": "</image>"}]}},
            {"timestamp": ts, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Saw literal xml."}]}},
        ]
        path = self.folder / f"rollout-2026-11-25T00-01-00-{tid}.jsonl"
        path.write_bytes(_jsonl(rows))
        sec = int(self.now_ns // 1_000_000_000)
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute("INSERT INTO threads VALUES(?,?,?,?,?,0,?,?,?)", (tid, str(path), str(self.alpha), "ImgThread", sec, sec, "paginated", None))
            db.commit()

        legacy, core = self._make_engines()
        self.addCleanup(legacy.close)

        found = _drain(core._find("alpha", "", "", "codex", "", 10, self.actor, "local"))
        u_read = _drain(core._read(found["threads"][0]["thread_ref"], "all", "", "", 20, 16000, self.actor, "local"))
        l_read = _drain(legacy._read_codex_thread_iter(tid, view="all", limit=20, caller=self.caller))

        expected = [
            ("user", "Inspect nozzle photo"),
            ("assistant", "Nozzle looks clean."),
            ("user", "Run check again"),
            ("user", "Run check again"),
            ("assistant", "Checked twice."),
            ("user", '<image name="demo">\nliteral xml\n</image>'),
            ("assistant", "Saw literal xml."),
        ]
        self.assertEqual([(e["role"], e["text"]) for e in u_read["entries"]], expected)
        self.assertEqual([(e["role"], e["text"]) for e in l_read["entries"]], expected)


class CutoverManifestInterruptionCliTests(unittest.TestCase):
    """Prove standard CLI rollback recovers from 0-byte, 96-byte, invalid-UTF8, and partial-file interruptions."""

    def test_cli_rollback_recovers_all_corrupt_manifest_states_and_preserves_revocations(self):
        from tests.test_v051_release_cutover import _make_bundle

        tool = Path(__file__).resolve().parent.parent / "tools" / "release_cutover.py"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        os.chmod(root, 0o700)

        cand = root / "candidate"
        rb = root / "rollback"
        runtime = root / "runtime"
        work_keep = runtime / "work" / "keep.txt"
        work_keep.parent.mkdir(parents=True, exist_ok=True)
        work_keep.write_text("keep-audit\n", encoding="utf-8")

        cand_mf = _make_bundle(cand, "cand-0.5.2", {"README.md": b"cand\n", "mod.py": b"X = 2\n"})
        rb_mf = _make_bundle(rb, "rb-0.4.4-p12", {"README.md": b"rb\n", "mod.py": b"X = 1\n"}, bundle_mode="rollback")

        def run_cli(*cli_args):
            return subprocess.run(
                [sys.executable, "-B", str(tool), *cli_args],
                capture_output=True,
                text=True,
            )

        # Initial deploy succeeds.
        dep = run_cli("deploy", "--runtime-dir", str(runtime), "--candidate-dir", str(cand), "--confirm-cutover")
        self.assertEqual(dep.returncode, 0, dep.stderr)
        full_manifest_bytes = (runtime / "manifest.json").read_bytes()
        self.assertGreater(len(full_manifest_bytes), 120)

        fault_cases = [
            ("zero_byte_manifest", lambda: (runtime / "manifest.json").write_bytes(b""), "incomplete_or_corrupt"),
            ("truncated_96b_manifest", lambda: (runtime / "manifest.json").write_bytes(full_manifest_bytes[:96]), "incomplete_or_corrupt"),
            ("invalid_utf8_manifest", lambda: (runtime / "manifest.json").write_bytes(b"\xff\xfe\x00{"), "incomplete_or_corrupt"),
            ("truncated_payload_32b", lambda: (runtime / "README.md").write_bytes(b"x" * 32), "incomplete_or_corrupt"),
            ("missing_manifest_partial_files", lambda: (runtime / "manifest.json").unlink(), "uninitialized_or_missing_manifest"),
        ]

        for idx, (name, inject_fault, expected_prev_state) in enumerate(fault_cases):
            with self.subTest(fault=name):
                # Reset to deployed candidate, then inject the exact interruption state.
                re_dep = run_cli("deploy", "--runtime-dir", str(runtime), "--candidate-dir", str(cand), "--confirm-cutover")
                self.assertEqual(re_dep.returncode, 0, re_dep.stderr)
                inject_fault()

                # Preflight must still succeed and report the broken runtime state cleanly.
                pre = run_cli(
                    "preflight", "--runtime-dir", str(runtime),
                    "--candidate-dir", str(cand), "--rollback-dir", str(rb),
                )
                self.assertEqual(pre.returncode, 0, pre.stderr)

                # Standard rollback CLI must succeed on first attempt AND idempotent retry!
                receipt_path = root / f"rb-{idx}.json"
                rb1 = run_cli(
                    "rollback", "--runtime-dir", str(runtime),
                    "--rollback-dir", str(rb), "--receipt", str(receipt_path), "--confirm-rollback",
                )
                self.assertEqual(rb1.returncode, 0, f"{name} failed: {rb1.stderr}")
                rb1_doc = json.loads(rb1.stdout)
                self.assertEqual(rb1_doc["previous_state"], expected_prev_state)
                self.assertEqual(rb1_doc["active_fingerprint"], rb_mf["content_fingerprint"])
                self.assertTrue(receipt_path.is_file())
                self.assertEqual(work_keep.read_text(encoding="utf-8"), "keep-audit\n")

                rb2 = run_cli(
                    "rollback", "--runtime-dir", str(runtime),
                    "--rollback-dir", str(rb), "--confirm-rollback",
                )
                self.assertEqual(rb2.returncode, 0, rb2.stderr)
                self.assertEqual(json.loads(rb2.stdout)["previous_state"], "verified")
                self.assertEqual(cand_mf["bundle_mode"], "candidate")


class AntigravityCaptureCacheStampBindingTests(unittest.TestCase):
    """Prove AG _CAPTURE_CACHE refuses to bind stale projections when any dependency mutates mid-capture."""

    def _make_native_fixture(self):
        from tests.test_agent_history_antigravity_native import AntigravityNativeTests

        class _Harness(AntigravityNativeTests):
            live_clock = True

            def runTest(self):
                pass

        h = _Harness()
        h.setUp()
        self.addCleanup(h.doCleanups)
        return h

    def test_post_toctou_drift_on_transcript_or_index_skips_caching(self):
        ag_native._CAPTURE_CACHE.clear()
        ag_native._CAPTURE_CACHE_BYTES = 0
        h = self._make_native_fixture()

        real_capture_stamps = ag_native._capture_stamps
        call_num = {"n": 0}

        def mutating_final_stamps(root, index_rel, native_id, transcript_rel, child_ids=()):
            call_num["n"] += 1
            if call_num["n"] == 2:
                # Simulate a concurrent transcript mutation right after TOCTOU checks pass,
                # immediately before final_stamps is sampled for cache insertion!
                h.logs[1] = {**h.logs[1], "content": "CONCURRENT_TAMPER_DURING_STORE"}
                h.write_logs()
            return real_capture_stamps(root, index_rel, native_id, transcript_rel, child_ids)

        with patch.object(ag_native, "_capture_stamps", side_effect=mutating_final_stamps):
            obs, proj = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs.state, "workspace_verified")
        self.assertEqual(len(proj.messages), 4)
        # Crucial: _CAPTURE_CACHE MUST NOT store the old projection paired with the new transcript stamp!
        self.assertEqual(len(ag_native._CAPTURE_CACHE), 0)

        # Consequently, the very next capture sees the tampered transcript and fails closed!
        with self.assertRaises(ag_native.EvidenceIssue):
            ag_native.capture(h.reader, h.thread)

    def test_concurrent_reads_and_index_stamp_drift_never_serve_mismatched_projection(self):
        ag_native._CAPTURE_CACHE.clear()
        ag_native._CAPTURE_CACHE_BYTES = 0
        h = self._make_native_fixture()

        real_capture_stamps = ag_native._capture_stamps
        call_num = {"n": 0}

        def mutating_index_stamps(root, index_rel, native_id, transcript_rel, child_ids=()):
            call_num["n"] += 1
            if call_num["n"] == 2:
                # Simulate concurrent INDEX mutation (killed=1) right before cache insertion!
                h.index.execute("UPDATE conversation_summaries SET killed=1")
                h.index.commit()
            return real_capture_stamps(root, index_rel, native_id, transcript_rel, child_ids)

        with patch.object(ag_native, "_capture_stamps", side_effect=mutating_index_stamps):
            obs, _ = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs.state, "workspace_verified")
        self.assertEqual(len(ag_native._CAPTURE_CACHE), 0)

        with self.assertRaises(ag_native.EvidenceIssue):
            ag_native.capture(h.reader, h.thread)

        # Restore healthy index and verify concurrent multi-threaded captures remain 100% consistent.
        h.index.execute("UPDATE conversation_summaries SET killed=0")
        h.index.commit()
        errors = []
        results = []

        def worker():
            try:
                for _ in range(8):
                    o, p = ag_native.capture(h.reader, h.thread)
                    results.append((o.state, o.revision, len(p.messages)))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(results[0][0], "workspace_verified")
        self.assertEqual(results[0][2], 4)


if __name__ == "__main__":
    unittest.main()
