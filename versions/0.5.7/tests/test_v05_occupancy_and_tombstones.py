"""WS2 / D1 / S2 tests: physical occupancy, durable tombstones, rollback compat, and Codex fork chains."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import activate_preview, compile_generation, preview_activation, write_descriptor
from peters_mcp.agent_history_generation import GenerationStore, initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.fs_identity import persistent_identity
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


def _rollout_bytes(records):
    return b"".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n" for item in records)


def _iso_from_ns(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


def _codex_records(thread_id, cwd, ts_iso, user_text, assistant_text, *, forked_from_id=None, extra_cwds=()):
    meta = {"id": thread_id, "cwd": str(cwd), "timestamp": ts_iso, "cli_version": "0.167.0"}
    if forked_from_id is not None:
        meta["forked_from_id"] = forked_from_id
    rows = [
        {"timestamp": ts_iso, "type": "session_meta", "payload": meta},
        {"timestamp": ts_iso, "type": "turn_context", "payload": {"cwd": str(cwd), "turn_id": "turn-1"}},
        {
            "timestamp": ts_iso,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": user_text}],
            },
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
    for idx, extra in enumerate(extra_cwds, start=2):
        rows.append({"timestamp": ts_iso, "type": "turn_context", "payload": {"cwd": str(extra), "turn_id": f"turn-{idx}"}})
    return rows


class OccupancyTombstonesAndForkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o700)

        # Parent dir hosting projects (so sibling mutations exercise parent st_mtime_ns / st_ctime_ns).
        self.projects_parent = self.root / "workspace"
        self.projects_parent.mkdir(mode=0o700)
        self.repo_dir = self.projects_parent / "alpha-repo"
        self.repo_dir.mkdir()
        _git(self.repo_dir, "init", "-q")
        (self.repo_dir / "README.md").write_text("alpha\n", encoding="utf-8")
        _git(self.repo_dir, "add", "README.md")
        _git(self.repo_dir, "commit", "-q", "-m", "init")

        self.plain_dir = self.projects_parent / "beta-plain"
        self.plain_dir.mkdir()
        (self.plain_dir / "note.txt").write_text("beta\n", encoding="utf-8")

        self.foreign_dir = self.projects_parent / "foreign-unregistered"
        self.foreign_dir.mkdir()

        # Codex local store
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

        # Unified v2 generation store
        self.state_dir = self.root / "generations-state"
        self.descriptor = self.root / "policy.json"
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.actor = "a" * 64
        self.store = initialize_store(self.state_dir)
        self.document = compile_generation({
            "version": 2,
            "projects": [
                {
                    "id": "alpha",
                    "name": "Alpha Repo",
                    "root": str(self.repo_dir),
                    "repository_id": repository_probe(self.repo_dir)["repository_id"],
                },
                {
                    "id": "beta",
                    "name": "Beta Plain",
                    "root": str(self.plain_dir),
                },
            ],
            "sources": {
                "codex": {
                    "adapter": "codex",
                    "root": str(self.codex_home),
                    "format": "local",
                    "enabled": True,
                    "instance_id": "codex",
                    "denied_threads": [],
                },
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

    def _add_codex_thread(self, thread_id, cwd, *, ts_ns=None, title="Codex Thread",
                          user_text="Question", assistant_text="Answer",
                          forked_from_id=None, extra_cwds=()):
        if ts_ns is None:
            ts_ns = time.time_ns() + 10_000_000
        ts_iso = _iso_from_ns(ts_ns)
        created_s = int(ts_ns // 1_000_000_000)
        rollout = self.codex_home / "sessions" / f"rollout-test-{thread_id}.jsonl"
        records = _codex_records(
            thread_id, cwd, ts_iso, user_text, assistant_text,
            forked_from_id=forked_from_id, extra_cwds=extra_cwds,
        )
        rollout.write_bytes(_rollout_bytes(records))
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute(
                "INSERT OR REPLACE INTO threads (id, rollout_path, cwd, title, updated_at, archived, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (thread_id, str(rollout), str(cwd), title, created_s, created_s),
            )
            db.commit()
        return rollout

    def _core(self):
        policy = AgentPolicy(self.descriptor, mode="v2")
        policy.scratch = self.scratch
        policy.scratch_identity = SourceRoot(self.scratch).identity
        catalog = Catalog.from_policy(policy)
        catalog.set_agent_history_policy(policy)
        legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
        self.addCleanup(legacy.close)
        self.addCleanup(policy.store.locations.close)
        return AgentHistoryCore(policy, catalog, legacy, b"test-signing-key-32-bytes-long!!")

    def _find_codex(self, core, project_id, query=""):
        return _drain(core.operation_iter("find_agent_threads", {
            "project_id": project_id, "query": query, "agent": "", "source_id": "codex",
            "cursor": "", "limit": 20, "actor": self.actor, "policy_actor": "local",
        }))

    def test_sibling_and_project_file_activity_and_cold_restart_preserve_history(self):
        # Create a lawful historical thread after repo & plain dir creation.
        time.sleep(0.05)
        tid_repo = "11111111-1111-4111-8111-111111111111"
        tid_plain = "22222222-2222-4222-8222-222222222222"
        ts_ns = time.time_ns()
        self._add_codex_thread(tid_repo, self.repo_dir, ts_ns=ts_ns, title="Alpha History")
        self._add_codex_thread(tid_plain, self.plain_dir, ts_ns=ts_ns, title="Beta History")

        # Mutate parent directory (add/remove sibling) and project directories (add/delete files) AFTER thread creation!
        time.sleep(0.05)
        sibling = self.projects_parent / "unrelated-sibling"
        sibling.mkdir()
        (sibling / "x.txt").write_text("unrelated", encoding="utf-8")
        (self.repo_dir / "later.txt").write_text("new file", encoding="utf-8")
        (self.plain_dir / "later.txt").write_text("new file", encoding="utf-8")

        # Cold restart: brand-new AgentHistoryCore / GenerationStore / Catalog (no warm vnode cache!).
        core = self._core()
        alpha = self._find_codex(core, "alpha")
        beta = self._find_codex(core, "beta")
        self.assertEqual([t["title"] for t in alpha["threads"]], ["Alpha History"])
        self.assertEqual([t["title"] for t in beta["threads"]], ["Beta History"])

    def test_directory_replacement_with_equalized_ctime_blocked_by_durable_tombstone(self):
        time.sleep(0.05)
        tid = "33333333-3333-4333-8333-333333333333"
        ts_ns = time.time_ns()
        self._add_codex_thread(tid, self.plain_dir, ts_ns=ts_ns, title="Old Beta Secret")

        # Confirm readable before replacement.
        core1 = self._core()
        before = self._find_codex(core1, "beta")
        self.assertEqual(len(before["threads"]), 1)

        # Revoke beta -> records durable tombstone in .path-tombstones.json.
        revoked_doc = deepcopy(self.document)
        revoked_doc["projects"] = [p for p in revoked_doc["projects"] if p["id"] != "beta"]
        p1, d1 = preview_activation(revoked_doc, previous=AgentPolicy(self.descriptor, mode="v2").snapshot())
        self.epoch = activate_preview(self.store, p1, d1)

        # Verify .path-tombstones.json exists with 0600 and active.json remains strictly .12-compatible!
        tombstone_file = self.state_dir / ".path-tombstones.json"
        self.assertTrue(tombstone_file.is_file())
        self.assertEqual(os.stat(tombstone_file).st_mode & 0o777, 0o600)
        active_pointer = json.loads((self.state_dir / "active.json").read_text(encoding="utf-8"))
        self.assertEqual(
            set(active_pointer) - {"root_history"},
            {"version", "sha256", "activation_id", "project_tokens", "project_identities", "retained_sources"},
        )

        # Replace plain_dir at the exact same path and touch a file inside so st_ctime_ns == st_mtime_ns!
        time.sleep(0.05)
        moved_away = self.projects_parent / "beta-moved-away"
        self.plain_dir.rename(moved_away)
        self.plain_dir.mkdir()
        (self.plain_dir / "touch.txt").write_text("equalize ctime==mtime", encoding="utf-8")

        # Re-register the NEW physical directory at the same path.
        readded_doc = deepcopy(revoked_doc)
        readded_doc["projects"].append({
            "id": "beta-replacement",
            "name": "Beta Replacement",
            "root": str(self.plain_dir),
            "directory_identity": persistent_identity(self.plain_dir),
        })
        p2, d2 = preview_activation(readded_doc, previous=AgentPolicy(self.descriptor, mode="v2").snapshot())
        self.epoch = activate_preview(self.store, p2, d2)

        # Cold restart: new directory MUST NOT see Old Beta Secret (blocked by durable tombstone + birth!).
        core2 = self._core()
        after = self._find_codex(core2, "beta-replacement")
        self.assertEqual(after["threads"], [])
        self.assertEqual(after["coverage"][0]["state"], "association_unverified")
        self.assertEqual(after["coverage"][0].get("unverified_project_candidates"), 1)
        self.assertNotIn("Old Beta Secret", json.dumps(after))

        # A brand-new thread created AFTER replacement IS readable by beta-replacement!
        time.sleep(0.05)
        new_tid = "44444444-4444-4444-8444-444444444444"
        self._add_codex_thread(new_tid, self.plain_dir, ts_ns=time.time_ns(), title="Fresh Replacement Thread")
        after_new = self._find_codex(core2, "beta-replacement")
        self.assertEqual([t["title"] for t in after_new["threads"]], ["Fresh Replacement Thread"])

    def test_mid_session_nested_subdir_allowed_while_post_session_symlink_replacement_blocked(self):
        time.sleep(0.05)
        start_ns = time.time_ns()
        time.sleep(0.05)
        nested = self.repo_dir / "sub-created-mid-session"
        nested.mkdir()
        time.sleep(0.05)
        end_ns = time.time_ns()

        tid = "55555555-5555-4555-8555-555555555555"
        rollout = self.codex_home / "sessions" / f"rollout-test-{tid}.jsonl"
        rows = [
            {"timestamp": _iso_from_ns(start_ns), "type": "session_meta",
             "payload": {"id": tid, "cwd": str(self.repo_dir), "timestamp": _iso_from_ns(start_ns)}},
            {"timestamp": _iso_from_ns(start_ns), "type": "turn_context",
             "payload": {"cwd": str(self.repo_dir), "turn_id": "t1"}},
            {"timestamp": _iso_from_ns(start_ns), "type": "response_item",
             "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Create subdir"}]}},
            {"timestamp": _iso_from_ns(end_ns), "type": "turn_context",
             "payload": {"cwd": str(nested), "turn_id": "t2"}},
            {"timestamp": _iso_from_ns(end_ns), "type": "response_item",
             "payload": {"type": "message", "role": "assistant", "phase": "final_answer",
                         "content": [{"type": "output_text", "text": "Subdir created"}]}},
        ]
        rollout.write_bytes(_rollout_bytes(rows))
        with closing(sqlite3.connect(self.state_db)) as db:
            db.execute(
                "INSERT INTO threads (id, rollout_path, cwd, title, updated_at, archived, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (tid, str(rollout), str(self.repo_dir), "Mid-Session Subdir", int(end_ns // 1e9), int(start_ns // 1e9)),
            )
            db.commit()

        core = self._core()
        found = self._find_codex(core, "alpha")
        self.assertEqual([t["title"] for t in found["threads"]], ["Mid-Session Subdir"])

        # Now replace the nested dir AFTER session end with a brand-new directory -> MUST fail!
        time.sleep(0.05)
        nested.rename(self.projects_parent / "nested-old")
        nested.mkdir()
        core_after = self._core()
        blocked = self._find_codex(core_after, "alpha")
        self.assertEqual(blocked["threads"], [])
        self.assertEqual(blocked["coverage"][0]["state"], "association_unverified")

    def test_codex_fork_ancestor_chain_positive_and_negative_matrix(self):
        time.sleep(0.05)
        t0 = time.time_ns()

        # 1. Valid 3-deep fork chain within alpha
        ids = [f"66666666-6666-4666-8666-00000000000{i}" for i in range(1, 5)]
        self._add_codex_thread(ids[0], self.repo_dir, ts_ns=t0, title="Fork Root")
        self._add_codex_thread(ids[1], self.repo_dir, ts_ns=t0 + 1_000_000, title="Fork Depth 1", forked_from_id=ids[0])
        self._add_codex_thread(ids[2], self.repo_dir, ts_ns=t0 + 2_000_000, title="Fork Depth 2", forked_from_id=ids[1])
        self._add_codex_thread(ids[3], self.repo_dir, ts_ns=t0 + 3_000_000, title="Fork Depth 3", forked_from_id=ids[2])

        # 2. Cross-project fork (parent in beta, child in alpha) -> MUST BE REJECTED!
        beta_parent = "77777777-7777-4777-8777-000000000001"
        cross_child = "77777777-7777-4777-8777-000000000002"
        self._add_codex_thread(beta_parent, self.plain_dir, ts_ns=t0, title="Beta Parent")
        self._add_codex_thread(cross_child, self.repo_dir, ts_ns=t0 + 1_000_000, title="Cross-Project Child",
                               forked_from_id=beta_parent)

        # 3. Missing ancestor -> MUST BE REJECTED!
        missing_child = "77777777-7777-4777-8777-000000000003"
        self._add_codex_thread(missing_child, self.repo_dir, ts_ns=t0 + 1_000_000, title="Missing Parent Child",
                               forked_from_id="99999999-9999-4999-8999-999999999999")

        # 4. Cyclic fork (A -> B -> A) -> MUST BE REJECTED!
        cyc_a = "77777777-7777-4777-8777-000000000004"
        cyc_b = "77777777-7777-4777-8777-000000000005"
        self._add_codex_thread(cyc_a, self.repo_dir, ts_ns=t0 + 1_000_000, title="Cycle A", forked_from_id=cyc_b)
        self._add_codex_thread(cyc_b, self.repo_dir, ts_ns=t0 + 2_000_000, title="Cycle B", forked_from_id=cyc_a)

        # 5. Depth > 8 (depth 9) -> MUST BE REJECTED!
        deep_ids = [f"88888888-8888-4888-8888-0000000000{i:02d}" for i in range(11)]
        self._add_codex_thread(deep_ids[0], self.repo_dir, ts_ns=t0, title="Deep 0")
        for i in range(1, 11):
            self._add_codex_thread(deep_ids[i], self.repo_dir, ts_ns=t0 + i * 1_000_000,
                                   title=f"Deep {i}", forked_from_id=deep_ids[i - 1])

        # 6. Pre-git ancestor -> post-git child MUST BE REJECTED (D3-3)!
        pre_git_ns = int(os.stat(self.repo_dir / ".git").st_birthtime * 1_000_000_000) - 60_000_000_000
        pre_parent = "77777777-7777-4777-8777-000000000006"
        post_child = "77777777-7777-4777-8777-000000000007"
        self._add_codex_thread(pre_parent, self.repo_dir, ts_ns=pre_git_ns, title="Pre-Git Parent")
        self._add_codex_thread(post_child, self.repo_dir, ts_ns=t0 + 5_000_000, title="Fork From Pre-Git",
                               forked_from_id=pre_parent)

        # 7. Explicitly denied ancestor -> child MUST BE REJECTED!
        denied_parent = "77777777-7777-4777-8777-000000000008"
        denied_child = "77777777-7777-4777-8777-000000000009"
        self._add_codex_thread(denied_parent, self.repo_dir, ts_ns=t0, title="Denied Parent")
        self._add_codex_thread(denied_child, self.repo_dir, ts_ns=t0 + 1_000_000, title="Child Of Denied",
                               forked_from_id=denied_parent)
        updated = deepcopy(self.document)
        updated["sources"]["codex"]["denied_threads"] = [denied_parent]
        p, d = preview_activation(updated, previous=AgentPolicy(self.descriptor, mode="v2").snapshot())
        self.epoch = activate_preview(self.store, p, d)

        core = self._core()
        found = self._find_codex(core, "alpha")
        titles = {t["title"] for t in found["threads"]}

        # Positive assertions
        for expected in ("Fork Root", "Fork Depth 1", "Fork Depth 2", "Fork Depth 3", "Deep 0", "Deep 8"):
            self.assertIn(expected, titles)
        # Negative security assertions
        for forbidden in ("Cross-Project Child", "Missing Parent Child", "Cycle A", "Cycle B",
                          "Deep 9", "Deep 10", "Pre-Git Parent", "Fork From Pre-Git",
                          "Denied Parent", "Child Of Denied"):
            self.assertNotIn(forbidden, titles)


if __name__ == "__main__":
    unittest.main()
