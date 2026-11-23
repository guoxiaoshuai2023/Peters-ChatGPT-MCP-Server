"""Real v2 generations with Codeg's pinned native index and transcript format."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import activate_preview, compile_generation, preview_path_migration, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.history import HistoryAccess
from tests.test_workspaces import fixture_git, fixture_registered_worktree

import test_agent_history_codeg as codeg
import test_agent_history_deepseek as deepseek
import test_agent_history_antigravity as antigravity
import test_agent_history_antigravity_native as native
from peters_mcp.agent_history_deepseek import _project_key
from test_agent_history_v2_core import finish


class UnifiedNativeHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "codeg-profile"
        self.source.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.second = self.root / "second"
        self.second.mkdir()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.actor = "a" * 64
        self.document = compile_generation({
            "version": 2,
            "projects": [{"id": "main", "name": "Main", "root": str(self.project)}],
            "sources": {"codeg": {"adapter": "codeg", "root": str(self.source),
                                    "format": "0.45.0", "enabled": True, "instance_id": "codeg"}},
            "legacy_history": None,
        })
        self.store = initialize_store(self.private / "generations")
        self.epoch = self.store.activate(self.document, initial=True)
        self.descriptor = self.private / "agent-history.json"
        write_descriptor(self.descriptor, self.store)
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.policy.scratch.mkdir(mode=0o700)
        self.catalog = Catalog.from_policy(self.policy)
        self.catalog.set_agent_history_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"k" * 32)
        with closing(sqlite3.connect(self.source / "codeg.db")) as db:
            db.executescript(codeg._SCHEMA)
            for index, project in enumerate((self.project, self.second), 1):
                db.execute("INSERT INTO folder VALUES (?, ?, 'regular', NULL, NULL)", (index, str(project)))
                db.execute("INSERT INTO conversation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (index, "Visible session " + str(index), "2026-11-20T00:00:00+00:00",
                            "custom:goose", "session-" + str(index), None, index, "regular", None, None))
            db.commit()
        for index, project in enumerate((self.project, self.second), 1):
            path = self.source / "acp-transcripts" / "goose" / ("session-" + str(index) + ".jsonl")
            path.parent.mkdir(parents=True, exist_ok=True)
            header = {"v": 1, "kind": "header", "agent": "custom:goose",
                      "session_id": "session-" + str(index), "cwd": str(project),
                      "started_at_ms": time.time_ns() // 1_000_000}
            records = (header, codeg.prompt("Visible question " + str(index)),
                       codeg.update("agent_thought_chunk", codeg.text("SECRET_THOUGHT")),
                       codeg.answer("Visible reply " + str(index)), codeg.end())
            for record in records[1:]:
                record["t"] = header["started_at_ms"]
            path.write_text("".join(json.dumps(record) + "\n" for record in records))

    def operation(self, name, **arguments):
        arguments.update(actor=self.actor, policy_actor=self.actor)
        result = finish(self.core.operation_iter(name, arguments))
        return finish(self.core.revalidate_result_iter(name, arguments, result))

    def search(self, project="main", query=""):
        return self.operation("find_agent_threads", project_id=project, query=query,
                              agent="", source_id="codeg", cursor="", limit=10)

    def test_reauthorizing_same_directory_restores_history_but_reusing_path_does_not(self):
        # Both directories exist before the recorded session. Birth time alone
        # cannot distinguish the subsequent rename from a continuing project.
        old_ref, = self.search()["threads"]
        old_id = self.document["projects"][0]["directory_identity"]
        self.assertLess(self.second.stat().st_birthtime, time.time())
        withdrawn = {**self.document, "projects": []}
        revoked = self.store.activate(withdrawn, expected_digest=self.epoch)
        restored = self.store.activate(self.document, expected_digest=revoked)
        self.assertEqual(len(self.search()["threads"]), 1)
        with self.assertRaises(AccessError):
            self.operation("read_agent_thread", thread_ref=old_ref["thread_ref"], view="all", turn_id="",
                           cursor="", limit=20, max_chars=16000)
        revoked = self.store.activate(withdrawn, expected_digest=restored)
        self.project.rename(self.root / "previous-repository")
        self.second.rename(self.project)
        target = compile_generation({**self.document, "projects": [
            {"id": "replacement", "name": "Replacement", "root": str(self.project)}]})
        self.assertNotEqual(old_id, target["projects"][0]["directory_identity"])
        self.store.activate(target, expected_digest=revoked)
        page = self.search(project="replacement")
        self.assertEqual(page["threads"], [])
        self.assertEqual(page["coverage"][0]["state"], "association_unverified")
        self.assertNotIn("Visible session 1", str(page))

        # A new, independently identified session in the replacement is visible.
        with closing(sqlite3.connect(self.source / "codeg.db")) as db:
            db.execute("INSERT INTO conversation SELECT 3, 'Replacement session', updated_at, agent_type,"
                       "'session-3', origin_cwd, folder_id, kind, parent_id, deleted_at FROM conversation WHERE id=1")
            db.commit()
        path = self.source / "acp-transcripts/goose/session-3.jsonl"
        with path.open("w") as stream:
            header = {"v": 1, "kind": "header", "agent": "custom:goose", "session_id": "session-3",
                      "cwd": str(self.project), "started_at_ms": time.time_ns() // 1_000_000}
            for value in (header, codeg.prompt("Second project prompt"), codeg.answer("Second project reply"), codeg.end()):
                if value is not header:
                    value["t"] = header["started_at_ms"]
                stream.write(json.dumps(value) + "\n")
        fresh = self.search(project="replacement")
        self.assertEqual([item["title"] for item in fresh["threads"]], ["Replacement session"])
        read = self.operation("read_agent_thread", thread_ref=fresh["threads"][0]["thread_ref"], view="all", turn_id="",
                              cursor="", limit=20, max_chars=16000)
        self.assertEqual([item["text"] for item in read["entries"]], ["Second project prompt", "Second project reply"])

    def test_native_index_and_projection_follow_live_project_generation(self):
        first = self.search()
        self.assertEqual(len(first["threads"]), 1)
        self.assertTrue(first["coverage_complete"])
        ref = first["threads"][0]["thread_ref"]
        page = self.operation("read_agent_thread", thread_ref=ref, view="all", turn_id="",
                              cursor="", limit=20, max_chars=16000)
        self.assertEqual([message["text"] for message in page["entries"]],
                         ["Visible question 1", "Visible reply 1"])
        self.assertEqual(self.search(query="SECRET_THOUGHT")["threads"], [])
        previous_source = deepcopy(self.document["sources"])
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "second", "name": "Second", "root": str(self.second)})
        updated = compile_generation(updated)
        self.store.activate(updated, expected_digest=self.epoch)
        self.assertEqual(updated["sources"], previous_source)
        second = self.search(project="second")
        self.assertEqual(len(second["threads"]), 1)
        self.assertEqual(second["threads"][0]["title"], "Visible session 2")
        self.assertTrue(second["coverage_complete"])
        with self.assertRaises(AccessError):
            self.operation("read_agent_thread", thread_ref=ref, view="all", turn_id="",
                           cursor="", limit=20, max_chars=16000)

    def test_native_source_disable_and_project_revocation_block_prepared_pages(self):
        arguments = {"project_id": "main", "query": "", "agent": "", "source_id": "codeg",
                     "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": self.actor}
        prepared = finish(self.core.operation_iter("find_agent_threads", arguments))
        updated = deepcopy(self.document)
        updated["sources"]["codeg"]["enabled"] = False
        epoch = self.store.activate(updated, expected_digest=self.epoch)
        with self.assertRaises(AccessError):
            finish(self.core.revalidate_result_iter("find_agent_threads", arguments, prepared))
        updated["projects"] = []
        self.store.activate(updated, expected_digest=epoch)
        with self.assertRaises(AccessError) as denied:
            self.search()
        self.assertEqual(denied.exception.code, "unauthorized")

    def test_registered_worktree_move_rechecks_backlink_epoch(self):
        checkout, other = self.root / "checkout", self.root / "other-checkout"
        repository = self.root / "git-origin"
        git_project = fixture_registered_worktree(repository, checkout)
        fixture_git(repository, "worktree", "add", "--detach", str(other))
        document = compile_generation({**self.document, "projects": [git_project]})
        self.store.activate(document, expected_digest=self.epoch)
        with closing(sqlite3.connect(self.source / "codeg.db")) as db:
            db.execute("UPDATE folder SET path=? WHERE id=1", (str(checkout),))
            db.commit()
        path = self.source / "acp-transcripts/goose/session-1.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0].update(cwd=str(checkout), started_at_ms=time.time_ns() // 1_000_000)
        for event in rows[1:]:
            event["t"] = rows[0]["started_at_ms"]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        fixture_git(checkout, "commit", "--allow-empty", "-m", "normal project activity")
        self.assertEqual(len(self.search("git-origin")["threads"]), 1)
        fixture_git(repository, "worktree", "move", str(checkout), str(self.root / "old-checkout"))
        fixture_git(repository, "worktree", "move", str(other), str(checkout))
        unavailable = self.search("git-origin")
        self.assertEqual(unavailable["threads"], [])
        self.assertEqual(unavailable["coverage"][0]["state"], "association_unverified")

    def _check_nested_working_directory_history(self, checkout, project_id):
        stable = checkout / "stable" / "nested"
        stable.mkdir(parents=True)
        formerly_linked = checkout / "formerly-linked"
        elsewhere = self.root / "another-project"
        elsewhere.mkdir()
        formerly_linked.symlink_to(elsewhere, target_is_directory=True)
        replacement = self.root / "staging" / "older-physical-directory"
        replacement.mkdir(parents=True)
        self.assertEqual(formerly_linked.resolve(), elsewhere)
        time.sleep(0.003)  # The native Codeg clock has millisecond precision.
        for index, cwd in enumerate((stable, formerly_linked), 1):
            with closing(sqlite3.connect(self.source / "codeg.db")) as db:
                db.execute("UPDATE folder SET path=? WHERE id=?", (str(cwd), index))
                db.commit()
            transcript = self.source / "acp-transcripts/goose" / f"session-{index}.jsonl"
            rows = [json.loads(line) for line in transcript.read_text().splitlines()]
            stamp = time.time_ns() // 1_000_000
            rows[0].update(cwd=str(cwd), started_at_ms=stamp)
            for event in rows[1:]:
                event["t"] = stamp
            transcript.write_text("".join(json.dumps(row) + "\n" for row in rows))
        formerly_linked.unlink()
        replacement.rename(formerly_linked)
        result = self.search(project_id)
        self.assertEqual([r["title"] for r in result["threads"]], ["Visible session 1"])
        self.assertEqual(result["coverage"][0]["state"], "association_unverified")
        self.assertNotIn("Visible session 2", str(result))
        page = self.operation("read_agent_thread", thread_ref=result["threads"][0]["thread_ref"], view="all",
                              turn_id="", cursor="", limit=8, max_chars=16000)
        self.assertEqual([m["text"] for m in page["entries"]], ["Visible question 1", "Visible reply 1"])

    def test_deeper_cwd_needs_its_own_interval_in_an_ordinary_project(self):
        self._check_nested_working_directory_history(self.project, "main")

    def test_deeper_cwd_needs_its_own_interval_in_a_registered_external_checkout(self):
        git_root, side = self.root / "another-git", self.root / "external-checkout"
        row = fixture_registered_worktree(git_root, side)
        self.store.activate(compile_generation({**self.document, "projects": [row]}), expected_digest=self.epoch)
        self._check_nested_working_directory_history(side, row["id"])

    def test_verified_historical_interval_survives_cold_restart_and_unrelated_file_creations(self):
        result, = self.search()["threads"]
        self.assertEqual(result["title"], "Visible session 1")
        self.policy.store.locations.close()
        # Both ends of the leaf's named edge have a new ctime. The previously
        # committed location witness still proves this original session.
        (self.project / "changed-contents").touch()
        (self.root / "new-sibling").touch()
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, HistoryAccess(catalog=self.catalog,
                                     unified_policy=self.policy), b"k" * 32)
        self.assertEqual([item["title"] for item in self.search()["threads"]], ["Visible session 1"])

    def test_service_retains_an_unqueried_native_session_across_restart(self):
        service = AgentHistoryService(self.policy, self.legacy, local=True)
        self.addCleanup(service.close)
        service.start(monitor_locations=True)
        time.sleep(0.005)
        stamp = time.time_ns() // 1_000_000
        path = self.source / "acp-transcripts/goose/session-1.jsonl"
        with path.open("a") as stream:
            for event in (codeg.prompt("unqueried turn", at=stamp), codeg.answer("new reply", at=stamp),
                          codeg.end(at=stamp)):
                stream.write(json.dumps(event) + "\n")
        (self.project / "regular-created-file").touch()
        (self.root / "new-sibling").touch()
        service.close()
        self.policy.store.locations.close()
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, HistoryAccess(catalog=self.catalog,
                                     unified_policy=self.policy), b"k" * 32)
        self.assertEqual([item["title"] for item in self.search(query="new reply")["threads"]], ["Visible session 1"])

    def test_only_server_lifespan_checkpoints_roots_and_external_checkouts_before_any_history_query(self):
        from peters_mcp.fs_identity import persistent_identity
        from peters_mcp.history_location import owner_key

        repo, checkout = self.root / "qa-repo", self.root / "qa-checkout"
        row = fixture_registered_worktree(repo, checkout)
        document = compile_generation({**self.document, "projects": self.document["projects"] + [row]})
        self.store.activate(document, expected_digest=self.epoch)
        service = AgentHistoryService(self.policy, self.legacy, local=True)
        self.addCleanup(service.close)
        service.start()
        self.assertIsNone(service._checkpoint_process)
        with patch("peters_mcp.agent_history_service.CHECKPOINT_SECONDS", 0.025):
            service.start(monitor_locations=True)
        after_first_round = time.time_ns()
        pin = document["projects"][1]["repository_id"]
        locations = [(self.project, None), (repo, pin), (checkout, pin)]
        keys = [owner_key(root, persistent_identity(root), repository) for root, repository in locations]
        confirmed = set()
        limit = time.monotonic() + 4
        while len(confirmed) != len(keys) and time.monotonic() < limit:
            for key in keys:
                receipt = self.store.path / (".project-occupancy-" + key) / "observed.json"
                if receipt.exists():
                    record = json.loads(receipt.read_bytes())
                    if record["owner"] == key and any(lo <= after_first_round <= hi for lo, hi in record["windows"]):
                        confirmed.add(key)
            time.sleep(0.01)
        self.assertEqual(confirmed, set(keys))
        service.close()
        self.assertIsNone(service._checkpoint_process)

    def test_server_releases_location_observers_when_another_component_fails(self):
        import asyncio
        import multiprocessing
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from peters_mcp.server import create_server

        async def exercise(phase):
            exports = SimpleNamespace(start_lifespan=AsyncMock(), close_lifespan=AsyncMock(return_value={"state": "stopped"}))
            getattr(exports, phase + "_lifespan").side_effect = OSError(phase + " failed")
            catalog = Catalog.from_policy(self.policy)
            server = create_server(catalog, agent_policy=self.policy, exports=exports)
            self.assertTrue(self.policy.store.locations.nodes)
            with self.assertRaisesRegex(OSError, phase + " failed"):
                async with server._lowlevel_server.lifespan(server._lowlevel_server):
                    pass
            self.assertFalse(self.policy.store.locations.nodes)
            self.assertFalse(any(child.name == "project-history-locations" for child in multiprocessing.active_children()))

        for phase in ("start", "close"):
            with self.subTest(phase=phase):
                asyncio.run(exercise(phase))

    def test_append_during_temporary_path_reuse_remains_unverified_after_return_and_source_reenable(self):
        path = self.source / "acp-transcripts/goose/session-1.jsonl"
        def append(text):
            stamp = time.time_ns() // 1_000_000
            with path.open("a") as stream:
                for event in (codeg.prompt(text, at=stamp), codeg.answer(text, at=stamp), codeg.end(at=stamp)):
                    stream.write(json.dumps(event) + "\n")

        self.assertEqual(len(self.search()["threads"]), 1)
        append("new turn in the same project")
        self.assertEqual(len(self.search(query="new turn in the same project")["threads"]), 1)
        self.project.rename(self.root / "parked")
        self.second.rename(self.project)
        append("temporary other project")
        self.project.rename(self.second)
        (self.root / "parked").rename(self.project)
        disabled = deepcopy(self.document)
        disabled["sources"]["codeg"]["enabled"] = False
        stopped = self.store.activate(disabled, expected_digest=self.epoch)
        self.store.activate(self.document, expected_digest=stopped)
        denied = self.search()
        self.assertEqual(denied["threads"], [])
        self.assertEqual(denied["coverage"][0]["state"], "association_unverified")
        self.assertNotIn("temporary other project", str(denied))

    def test_first_grant_after_ancestor_exchange_cannot_claim_history_from_the_other_tree(self):
        first, second = self.root / "left", self.root / "right"
        for tree in (first, second):
            (tree / "checkout").mkdir(parents=True)
        target = first / "checkout"
        with closing(sqlite3.connect(self.source / "codeg.db")) as db:
            db.execute("UPDATE folder SET path=? WHERE id=1", (str(target),))
            db.commit()
        path = self.source / "acp-transcripts/goose/session-1.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        stamp = time.time_ns() // 1_000_000
        rows[0].update(cwd=str(target), started_at_ms=stamp)
        for event in rows[1:]:
            event["t"] = stamp
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        untouched_child = (second / "checkout").stat().st_ctime_ns
        first.rename(self.root / "temporary")
        second.rename(first)
        (self.root / "temporary").rename(second)
        self.assertEqual(target.stat().st_ctime_ns, untouched_child)
        doc = compile_generation({**self.document, "projects": [{"id": "first-grant", "name": "First", "root": str(target)}]})
        self.store.activate(doc, expected_digest=self.epoch)
        denied = self.search("first-grant")
        self.assertEqual(denied["threads"], [])
        self.assertEqual(denied["coverage"][0]["state"], "association_unverified")

    def test_local_facade_reconstructs_the_live_v2_catalog_in_supervised_worker(self):
        service = AgentHistoryService(self.policy, self.legacy, local=True)
        self.addCleanup(service.close)

        def ready(operation, **arguments):
            for _ in range(80):
                page = operation(**arguments)
                if page["status"] != "processing":
                    self.assertEqual(page["status"], "ready", page)
                    return page
                arguments["cursor"] = page["next_cursor"]
                time.sleep(0.01)
            self.fail("The v2 worker did not finish its bounded continuation.")

        found = ready(service.find_agent_threads, project_id="main", source_id="codeg")
        self.assertEqual(len(found["threads"]), 1)
        page = ready(service.read_agent_thread, thread_ref=found["threads"][0]["thread_ref"])
        self.assertEqual([message["text"] for message in page["entries"]],
                         ["Visible question 1", "Visible reply 1"])

    def _register_deepseek(self):
        root = self.root / "dsh-profile"
        root.mkdir()
        for native, changed in (("dsh-good", False), ("dsh-conflict", True)):
            folder = root / _project_key(str(self.project)) / native
            folder.mkdir(parents=True)
            items = [{**deepseek.header(native, str(self.project)), "createdAt": time.time_ns() // 1_000_000},
                     deepseek.user(0, "DeepSeek visible question")]
            if changed:
                items.append(deepseek.event(1, "working-directory/change", {"cwd": str(self.second)}))
            else:
                items.append(deepseek.assistant(1, "DeepSeek visible reply"))
            for item in items[1:]:
                item["time"] = items[0]["createdAt"]
            (folder / "session.v4.jsonl").write_bytes(deepseek.records(*items))
        document = deepcopy(self.document)
        document["sources"]["dsh"] = {"adapter": "deepseek_harness", "root": str(root),
                                      "format": "0.2.2-rc.3", "enabled": True, "instance_id": "dsh"}
        document["sources"]["codeg"]["links"] = {"deepseek_harness": "dsh"}
        document["sources"]["codeg"]["link_instances"] = {"deepseek_harness": "dsh"}
        document = compile_generation(document)
        self.epoch = self.store.activate(document, expected_digest=self.epoch)
        self.document = document
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.catalog.set_agent_history_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"k" * 32)
        with closing(sqlite3.connect(self.source / "codeg.db")) as db:
            db.execute("INSERT INTO conversation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (3, "DeepSeek native alias", "2026-11-20T00:00:00+00:00", "deepseek",
                        "dsh-good", None, 1, "regular", None, None))
            db.commit()

    def test_deepseek_native_proof_rejects_cross_project_context_and_links_deduplicate(self):
        self._register_deepseek()
        page = self.operation("find_agent_threads", project_id="main", query="DeepSeek visible",
                              agent="", source_id="", cursor="", limit=10)
        thread, = page["threads"]
        self.assertEqual(thread["source_id"], "dsh")
        self.assertEqual(thread["matched_sources"], ["codeg", "dsh"])
        self.assertFalse(page["coverage_complete"])
        self.assertEqual(page["coverage"][1]["state"], "association_unverified")
        read = self.operation("read_agent_thread", thread_ref=thread["thread_ref"], view="all", turn_id="",
                              cursor="", limit=20, max_chars=16000)
        self.assertEqual([message["text"] for message in read["entries"]],
                         ["DeepSeek visible question", "DeepSeek visible reply"])

    def test_native_link_cannot_bypass_disabled_underlying_profile(self):
        self._register_deepseek()
        updated = deepcopy(self.document)
        updated["sources"]["dsh"]["enabled"] = False
        self.store.activate(updated, expected_digest=self.epoch)
        page = self.search(query="DeepSeek visible")
        self.assertEqual(page["threads"], [])

    def moved_native_project(self):
        fixture = native.AntigravityNativeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old = fixture.project
        current = old.with_name('migrated-root')
        old.rename(current)
        document = {'version': 2, 'projects': [{'id': 'moved', 'root': str(current), 'name': 'Migrated'}],
                    'legacy_history': None, 'sources': {'antigravity': {'adapter': 'antigravity',
                        'root': str(fixture.reader.root.path), 'format': '2.33.0', 'enabled': True,
                        'instance_id': 'desktop', 'path_aliases': [{'source_instance': 'desktop',
                            'native_project_id': native.PROJECT, 'old_root': str(old),
                            'project_id': 'moved', 'target_root': str(current)}]}}}
        updated = datetime.fromtimestamp(native.SECONDS + 1, timezone.utc).isoformat()
        return fixture, old, document, updated

    def test_native_migration_preview_needs_a_pre_move_cut_and_one_native_project(self):
        _, old, document, updated = self.moved_native_project()
        previous = self.policy.snapshot()
        early = datetime.fromtimestamp(native.SECONDS - 1, timezone.utc).isoformat()
        early_preview, _ = preview_path_migration(document, 'antigravity', str(old), early, previous=previous)
        self.assertEqual(early_preview['path_migration']['proposed'], [])
        self.assertEqual(early_preview['path_migration']['pending'][0]['reason'], 'updated_after_migration_cutoff')
        multiple = deepcopy(document)
        aliases = multiple['sources']['antigravity']['path_aliases']
        aliases.append({**aliases[0], 'native_project_id': native.SECOND})
        with self.assertRaises(AccessError):
            preview_path_migration(multiple, 'antigravity', str(old), updated, previous=previous)
        selected, _ = preview_path_migration(multiple, 'antigravity', str(old), updated, previous=previous,
                                             native_project=native.PROJECT)
        self.assertEqual(selected['path_migration']['proposed'], [native.SESSION])

    def test_operator_can_preview_and_read_one_finite_native_migration(self):
        fixture, old, document, updated = self.moved_native_project()
        previous = self.policy.snapshot()
        preview, digest = preview_path_migration(document, 'antigravity', str(old), updated, previous=previous)
        report = preview['path_migration']
        self.assertEqual(report['proposed'], [native.SESSION])
        self.assertFalse(report['pending'])
        self.assertNotIn('Visible Gemini answer', str(preview))
        activate_preview(self.store, preview, digest)
        self.policy = AgentPolicy(self.descriptor, mode='v2')
        self.catalog = Catalog.from_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b'k' * 32)
        search = dict(project_id='moved', query='', agent='', source_id='antigravity', cursor='', limit=8)
        found = self.operation('find_agent_threads', **search)
        self.assertEqual(len(found['threads']), 1)
        args = dict(thread_ref=found['threads'][0]['thread_ref'], view='all', turn_id='', cursor='',
                    limit=8, max_chars=16000)
        page = self.operation('read_agent_thread', **args)
        self.assertEqual([row['text'] for row in page['entries']],
                         ['问题 0', 'Visible Gemini answer 0', '问题 1', 'Visible Gemini answer 1'])
        fixture.index.execute("UPDATE conversation_summaries SET title='Changed after snapshot review'")
        fixture.index.commit()
        with self.assertRaises(AccessError):
            self.operation('read_agent_thread', **args)
        self.assertEqual(self.operation('find_agent_threads', **search)['threads'], [])
        with self.assertRaises(AccessError):
            activate_preview(self.store, preview, digest)

    def test_stale_migration_template_uses_the_approved_generation_receipt(self):
        fixture, old, document, updated = self.moved_native_project()
        previous = self.policy.snapshot()
        preview, digest = preview_path_migration(document, 'antigravity', str(old), updated, previous=previous)
        activate_preview(self.store, preview, digest)
        self.policy = AgentPolicy(self.descriptor, mode='v2')
        active = self.policy.snapshot()

        def review(template):
            return preview_path_migration(template, 'antigravity', str(old), updated, previous=active)

        restored, _ = review(document)  # This original operator template omits the approved receipt.
        self.assertEqual(restored['path_migration']['existing'], [native.SESSION])
        self.assertEqual(restored['path_migration']['proposed'], [])
        self.assertEqual(restored['document']['sources']['antigravity']['exceptions'],
                         active[0]['sources']['antigravity']['exceptions'])

        def assert_previous_conflict(template):
            refused, refused_digest = review(template)
            self.assertEqual(refused['path_migration']['proposed'], [])
            self.assertEqual(refused['unresolved'],
                             [{'native_id': native.SESSION, 'reason': 'previous_approval_drifted'}])
            with self.assertRaises(AccessError) as conflict:
                activate_preview(self.store, refused, refused_digest)
            self.assertEqual(conflict.exception.code, 'generation_conflict')
            self.assertEqual(self.policy.snapshot(), active)

        swapped = deepcopy(active[0])
        swapped['sources']['antigravity']['exceptions'][native.SESSION]['source_revision'] = 'a' * 64
        assert_previous_conflict(swapped)
        other = deepcopy(document)
        other_source = other['sources']['antigravity']
        other_source['instance_id'] = other_source['path_aliases'][0]['source_instance'] = 'other-desktop'
        assert_previous_conflict(other)
        # A new physical project at a new target cannot inherit the approved snapshot.
        other = deepcopy(document)
        other_target = old.with_name('other-project')
        other_target.mkdir()
        other['projects'][0]['root'] = str(other_target)
        other['sources']['antigravity']['path_aliases'][0]['target_root'] = str(other_target)
        assert_previous_conflict(other)
        # Even when the native row no longer matches this alias's selection,
        # a successful empty scan cannot discard or replace the active receipt.
        fixture.index.execute("UPDATE conversation_summaries SET project_id = ?", (native.SECOND,))
        fixture.index.commit()
        assert_previous_conflict(document)
        fixture.index.execute("UPDATE conversation_summaries SET project_id = ?", (native.PROJECT,))
        fixture.index.commit()
        fixture.index.execute("UPDATE conversation_summaries SET title='Changed after snapshot review'")
        fixture.index.commit()
        assert_previous_conflict(document)

    def test_antigravity_exact_snapshot_alias_uses_native_project_and_current_target_pin(self):
        fixture = antigravity.AntigravityAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old = self.root / "missing-old-project"
        native_project = '99999999-9999-9999-9999-999999999999'
        fixture.add_thread(antigravity.FIRST, workspaces=[old.as_uri()])
        fixture.add_thread(antigravity.SECOND, workspaces=[self.project.as_uri()])
        fixture.db.execute('ALTER TABLE conversation_summaries ADD COLUMN project_id TEXT')
        fixture.db.execute('UPDATE conversation_summaries SET project_id = ?', (native_project,))
        fixture.db.commit()
        antigravity.write_steps(fixture.transcript(antigravity.FIRST), [
            antigravity.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Historical visible question'),
            antigravity.step(2, 'PLANNER_RESPONSE', 'MODEL', 'Historical visible reply'),
        ])
        antigravity.write_steps(fixture.transcript(antigravity.SECOND), [
            antigravity.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Other approved ordinary question'),
        ])
        project = self.catalog.repositories.discover_all()["main"]["fingerprint"]
        exceptions = {}
        for native_id in (antigravity.FIRST, antigravity.SECOND):
            original = fixture.reader.snapshot(fixture.reader.describe(native_id))
            exceptions[native_id] = {"project_id": "main", "source_identity": original.identity,
                                     "source_revision": original.revision, "project_fingerprint": project}
        document = deepcopy(self.document)
        document["sources"]["antigravity"] = {
            "adapter": "antigravity", "format": "2.33.0", "root": str(fixture.root),
            "enabled": True, "instance_id": "antigravity",
            "exceptions": exceptions,
            "path_aliases": [{"native_project_id": native_project, "source_instance": "antigravity",
                              "old_root": str(old), "project_id": "main", "target_root": str(self.project)}],
        }
        document = compile_generation(document)
        self.store.activate(document, expected_digest=self.epoch)
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"k" * 32)
        def search(query):
            return self.operation("find_agent_threads", project_id="main", query=query,
                                  agent="", source_id="antigravity", cursor="", limit=10)["threads"]

        thread, = search("Historical visible")
        self.assertEqual(thread["title"], "Historical visible question")
        self.assertEqual(thread["updated_at"], "2026-11-16T03:00:00.000000+00:00")
        args = dict(thread_ref=thread["thread_ref"], view="all", turn_id="", cursor="", limit=20, max_chars=16000)
        first = self.operation("read_agent_thread", **{**args, "limit": 1})
        fixture.db.execute('UPDATE conversation_summaries SET title=?, last_modified_time=? WHERE conversation_id=?',
                           ('Unreviewed migrated label', '2026-11-20T05:00:00Z', antigravity.FIRST))
        fixture.db.execute('UPDATE conversation_summaries SET title=?, last_modified_time=? WHERE conversation_id=?',
                           ('Ordinary indexed label', '2026-11-20T05:00:00Z', antigravity.SECOND))
        fixture.db.commit()
        self.assertEqual(search("Unreviewed migrated label"), [])
        after, = search("Historical visible")
        self.assertEqual((after["stable_thread_id"], after["title"], after["updated_at"]),
                         (thread["stable_thread_id"], thread["title"], thread["updated_at"]))
        ordinary, = search("Ordinary indexed label")
        self.assertEqual((ordinary["title"], ordinary["updated_at"]),
                         ("Ordinary indexed label", "2026-11-20T05:00:00.000000+00:00"))
        read = self.operation("read_agent_thread", **args)
        self.assertEqual([message["text"] for message in read["entries"]],
                         ['Historical visible question', 'Historical visible reply'])
        self.assertIn("missing_steps", read["warnings"])
        continuation = self.operation("read_agent_thread", **{**args, "limit": 1, "cursor": first["next_cursor"]})
        self.assertEqual(continuation["entries"][0]["text"], "Historical visible reply")
        self.assertEqual(continuation["thread"]["updated_at"], thread["updated_at"])
        old_template = deepcopy(document)
        del old_template["sources"]["antigravity"]["exceptions"][antigravity.FIRST]
        reviewed, _ = preview_path_migration(old_template, "antigravity", str(old),
                                              datetime.now(timezone.utc).isoformat(),
                                              previous=self.policy.snapshot())
        self.assertEqual(reviewed["path_migration"]["existing"], [antigravity.FIRST])
        self.assertEqual(reviewed["document"]["sources"]["antigravity"]["exceptions"],
                         document["sources"]["antigravity"]["exceptions"])
        old.mkdir()
        with self.assertRaises(AccessError):
            self.operation("read_agent_thread", thread_ref=thread["thread_ref"], view="all", turn_id="",
                           cursor="", limit=20, max_chars=16000)

    def test_antigravity_native_session_precedes_grant_but_not_a_replacement_at_the_same_path(self):
        fixture = native.AntigravityNativeTests()
        fixture.live_clock = True
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        project = {"id": "real-root", "name": "Real root", "root": str(fixture.project)}
        doc = compile_generation({**self.document, "projects": [project], "sources": {
            "desktop": {"enabled": True, "adapter": "antigravity", "format": "2.33.0",
                        "root": str(fixture.db_path.parent.parent), "instance_id": "qa-desktop"}}})
        active = self.store.activate(doc, expected_digest=self.epoch)
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"k" * 32)

        def search(project_id):
            return self.operation("find_agent_threads", project_id=project_id, query="", source_id="desktop",
                                  agent="", cursor="", limit=10)

        result, = search("real-root")["threads"]
        page = self.operation("read_agent_thread", thread_ref=result["thread_ref"], view="all", turn_id="",
                              cursor="", limit=20, max_chars=16000)
        self.assertEqual(page["entries"][-1]["text"], "Visible Gemini answer 1")
        removed = self.store.activate({**doc, "projects": []}, expected_digest=active)
        fixture.project.rename(fixture.project.with_name("former-root"))
        fixture.project.mkdir()
        target = compile_generation({**doc, "projects": [{**project, "id": "other-root"}]})
        self.store.activate(target, expected_digest=removed)
        unavailable = search("other-root")
        self.assertEqual(unavailable["threads"], [])
        self.assertEqual(unavailable["coverage"][0]["state"], "association_unverified")
        self.assertNotIn("Visible Gemini", str(unavailable))


if __name__ == "__main__":
    unittest.main()
