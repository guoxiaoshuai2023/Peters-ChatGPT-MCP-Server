"""v0.5.1 WS-R4 tests: prove stamp-bound proof/projection caches never serve stale or revoked history."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
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
    return b"".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n" for r in records)


def _iso(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


class StampCacheSecurityTests(unittest.TestCase):
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

        self.codex_home = self.root / "codex-home"
        self.folder = self.codex_home / "sessions" / "2026" / "11" / "24"
        self.folder.mkdir(parents=True)
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
        self.actor = "a" * 64
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

    def test_warm_cache_reflects_appends_immediately_and_blocks_revocation_at_zero_staleness(self):
        tid = "11111111-2222-4333-8444-555555555555"
        ts = _iso(self.now_ns)
        path = self.folder / f"rollout-2026-11-24T00-00-00-{tid}.jsonl"
        rows = [
            {"timestamp": ts, "type": "session_meta", "payload": {"id": tid, "cwd": str(self.alpha), "timestamp": ts, "cli_version": "0.171.0"}},
            {"timestamp": ts, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "t1"}},
            {"timestamp": ts, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "First Q"}]}},
            {"timestamp": ts, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "First A"}]}},
        ]
        path.write_bytes(_jsonl(rows))
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute("INSERT INTO threads VALUES(?,?,?,?,?,0,?)", (tid, str(path), str(self.alpha), "T", int(self.now_ns // 1e9), int(self.now_ns // 1e9)))
            db.commit()

        policy = AgentPolicy(self.descriptor, mode="v2")
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        core = AgentHistoryCore(policy, catalog, legacy, b"k" * 32)

        # Warm scan populates both _proof_cache and _proj_cache
        f1 = _drain(core._find("alpha", "", "", "codex", "", 10, self.actor, "local"))
        self.assertEqual(len(f1["threads"]), 1)
        self.assertEqual(f1["threads"][0]["message_count"], 2)
        self.assertGreaterEqual(len(legacy._proof_cache), 1)
        self.assertGreaterEqual(len(legacy._proj_cache), 1)

        # Append a new turn -> fstat stamp changes -> cache misses -> new message count visible immediately!
        ts2 = _iso(self.now_ns + 1_000_000)
        more = [
            {"timestamp": ts2, "type": "turn_context", "payload": {"cwd": str(self.alpha), "turn_id": "t2"}},
            {"timestamp": ts2, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Second Q"}]}},
            {"timestamp": ts2, "type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "Second A"}]}},
        ]
        with path.open("ab") as fh:
            fh.write(_jsonl(more))
        f2 = _drain(core._find("alpha", "", "", "codex", "", 10, self.actor, "local"))
        self.assertEqual(f2["threads"][0]["message_count"], 4)

        # Now deny the thread in live generation store -> SAME warm engine MUST deny immediately!
        revoked = deepcopy(self.document)
        revoked["sources"]["codex"]["denied_threads"] = [tid]
        prev_digest = hashlib.sha256((self.state_dir / "active.json").read_bytes()).hexdigest()
        self.store.activate(revoked, expected_digest=prev_digest)
        f3 = _drain(core._find("alpha", "", "", "codex", "", 10, self.actor, "local"))
        self.assertEqual(f3["threads"], [])
        with self.assertRaises(AccessError):
            _drain(core._read(f2["threads"][0]["thread_ref"], "all", "", "", 10, 16000, self.actor, "local"))


class AntigravityCaptureCacheInvalidationTests(unittest.TestCase):
    """Prove AG _CAPTURE_CACHE is strictly stamp-bound and authorization-free."""

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

    def test_capture_cache_hit_and_immediate_invalidation_on_disk_mutations(self):
        from unittest.mock import patch
        from peters_mcp import agent_history_antigravity_native as ag_native

        ag_native._CAPTURE_CACHE.clear()
        ag_native._CAPTURE_CACHE_BYTES = 0
        h = self._make_native_fixture()

        # First capture populates _CAPTURE_CACHE.
        obs1, proj1 = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs1.state, "workspace_verified")
        self.assertEqual(len(proj1.messages), 4)
        self.assertEqual(len(ag_native._CAPTURE_CACHE), 1)

        # Second capture on identical files hits _CAPTURE_CACHE without re-parsing trajectory SQLite.
        with patch.object(ag_native, "_trajectory", side_effect=AssertionError("expected _CAPTURE_CACHE hit")):
            obs2, proj2 = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs1, obs2)
        self.assertEqual(proj1, proj2)

        # 1) Tampering transcript.jsonl changes fstat stamp -> immediate cache miss + fail-closed!
        orig_logs = list(h.logs)
        h.logs[1] = {**h.logs[1], "content": "TAMPERED ANSWER"}
        h.write_logs()
        with self.assertRaises(ag_native.EvidenceIssue):
            ag_native.capture(h.reader, h.thread)

        # Restore transcript and re-warm cache.
        h.logs = orig_logs
        h.write_logs()
        obs3, _ = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs3.state, "workspace_verified")

        # 2) Creating a mismatched transcript_full.jsonl changes optional companion stamp -> immediate miss + fail-closed!
        full_path = h.transcript.with_name("transcript_full.jsonl")
        bad_full = [dict(row) for row in h.logs]
        bad_full[1]["content"] = "COMPANION TAMPER"
        full_path.write_text("\n".join(json.dumps(r) for r in bad_full) + "\n", encoding="utf-8")
        with self.assertRaises((AccessError, ag_native.EvidenceIssue)):
            ag_native.capture(h.reader, h.thread)
        full_path.unlink()

        # Re-warm cache.
        obs4, _ = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs4.state, "workspace_verified")

        # 3) Mutating native trajectory DB changes DB stamp -> immediate miss + fail-closed!
        other_dir = h.project.parent / "other-project"
        other_dir.mkdir(mode=0o700)
        h.db.execute("UPDATE trajectory_metadata_blob SET data=? WHERE id='main'", (h.header(roots=[other_dir.as_uri()]),))
        h.db.commit()
        with self.assertRaises(ag_native.EvidenceIssue):
            ag_native.capture(h.reader, h.thread)

        # Restore native DB and re-warm cache.
        h.db.execute("UPDATE trajectory_metadata_blob SET data=? WHERE id='main'", (h.header(),))
        h.db.commit()
        obs5, _ = ag_native.capture(h.reader, h.thread)
        self.assertEqual(obs5.state, "workspace_verified")

        # 4) Mutating conversation_summaries.db (INDEX) sets killed=1 -> immediate miss + fail-closed!
        h.index.execute("UPDATE conversation_summaries SET killed=1")
        h.index.commit()
        with self.assertRaises(ag_native.EvidenceIssue):
            ag_native.capture(h.reader, h.thread)

    def test_capture_cache_enforces_live_policy_revocation_at_zero_staleness(self):
        from peters_mcp import agent_history_antigravity_native as ag_native
        from tests.test_agent_history_antigravity_native import SESSION

        ag_native._CAPTURE_CACHE.clear()
        ag_native._CAPTURE_CACHE_BYTES = 0
        h = self._make_native_fixture()

        state_dir = h.project.parent / "generations-state"
        descriptor = h.project.parent / "policy.json"
        actor = "b" * 64
        store = initialize_store(state_dir)
        doc = compile_generation({
            "version": 2,
            "projects": [
                {"id": "agproj", "name": "AGProj", "root": str(h.project)},
            ],
            "sources": {
                "antigravity": {
                    "adapter": "antigravity",
                    "root": str(h.db_path.parent.parent),
                    "format": "2.33.0",
                    "enabled": True,
                    "instance_id": "antigravity",
                    "denied_threads": [],
                }
            },
            "legacy_history": None,
        })
        preview, digest = preview_activation(doc)
        activate_preview(store, preview, digest, initial=True)
        write_descriptor(descriptor, store)

        policy = AgentPolicy(descriptor, mode="v2")
        scratch_dir = h.project.parent / "policy-scratch"
        scratch_dir.mkdir(mode=0o700)
        policy.scratch = scratch_dir
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        core = AgentHistoryCore(policy, catalog, legacy, b"k" * 32)

        # Warm find + read populates _CAPTURE_CACHE.
        found = _drain(core._find("agproj", "", "", "antigravity", "", 10, actor, "local"))
        self.assertEqual(len(found["threads"]), 1)
        self.assertGreaterEqual(len(ag_native._CAPTURE_CACHE), 1)
        tref = found["threads"][0]["thread_ref"]
        read_ok = _drain(core._read(tref, "all", "", "", 10, 16000, actor, "local"))
        self.assertEqual(len(read_ok["entries"]), 4)

        # Revoke thread in live policy while _CAPTURE_CACHE is warm -> MUST deny immediately!
        revoked = deepcopy(doc)
        revoked["sources"]["antigravity"]["denied_threads"] = [SESSION]
        prev_digest = hashlib.sha256((state_dir / "active.json").read_bytes()).hexdigest()
        store.activate(revoked, expected_digest=prev_digest)
        found_after = _drain(core._find("agproj", "", "", "antigravity", "", 10, actor, "local"))
        self.assertEqual(found_after["threads"], [])
        with self.assertRaises(AccessError):
            _drain(core._read(tref, "all", "", "", 10, 16000, actor, "local"))


if __name__ == "__main__":
    unittest.main()
