"""Real v2 generations with Codeg's pinned native index and transcript format."""

from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_admin import compile_generation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.history import HistoryAccess

import test_agent_history_codeg as codeg
import test_agent_history_deepseek as deepseek
import test_agent_history_antigravity as antigravity
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
            "version": 2, "principals": [self.actor],
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
                      "session_id": "session-" + str(index), "cwd": str(project), "started_at_ms": 1000}
            records = (header, codeg.prompt("Visible question " + str(index)),
                       codeg.update("agent_thought_chunk", codeg.text("SECRET_THOUGHT")),
                       codeg.answer("Visible reply " + str(index)), codeg.end())
            path.write_text("".join(json.dumps(record) + "\n" for record in records))

    def operation(self, name, **arguments):
        arguments.update(actor=self.actor, policy_actor=self.actor)
        result = finish(self.core.operation_iter(name, arguments))
        return finish(self.core.revalidate_result_iter(name, arguments, result))

    def search(self, project="main", query=""):
        return self.operation("find_agent_threads", project_id=project, query=query,
                              agent="", source_id="codeg", cursor="", limit=10)

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

    def test_native_source_disable_and_global_actor_revocation_block_prepared_pages(self):
        arguments = {"project_id": "main", "query": "", "agent": "", "source_id": "codeg",
                     "cursor": "", "limit": 10, "actor": self.actor, "policy_actor": self.actor}
        prepared = finish(self.core.operation_iter("find_agent_threads", arguments))
        updated = deepcopy(self.document)
        updated["sources"]["codeg"]["enabled"] = False
        epoch = self.store.activate(updated, expected_digest=self.epoch)
        with self.assertRaises(AccessError):
            finish(self.core.revalidate_result_iter("find_agent_threads", arguments, prepared))
        updated["principals"] = []
        self.store.activate(updated, expected_digest=epoch)
        with self.assertRaises(AccessError) as denied:
            self.search()
        self.assertEqual(denied.exception.code, "unauthorized")

    def test_local_facade_reconstructs_the_live_v2_catalog_in_supervised_worker(self):
        document = deepcopy(self.document)
        document["principals"] = ["local"]
        self.store.activate(document, expected_digest=self.epoch)
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
            items = [deepseek.header(native, str(self.project)), deepseek.user(0, "DeepSeek visible question")]
            if changed:
                items.append(deepseek.event(1, "working-directory/change", {"cwd": str(self.second)}))
            else:
                items.append(deepseek.assistant(1, "DeepSeek visible reply"))
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

    def test_antigravity_exact_snapshot_alias_uses_native_project_and_current_target_pin(self):
        fixture = antigravity.AntigravityAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old = self.root / "missing-old-project"
        native_project = '99999999-9999-9999-9999-999999999999'
        fixture.add_thread(antigravity.FIRST, workspaces=[old.as_uri()])
        fixture.db.execute('ALTER TABLE conversation_summaries ADD COLUMN project_id TEXT')
        fixture.db.execute('UPDATE conversation_summaries SET project_id = ?', (native_project,))
        fixture.db.commit()
        antigravity.write_steps(fixture.transcript(antigravity.FIRST), [
            antigravity.step(0, 'USER_INPUT', 'USER_EXPLICIT', 'Historical visible question'),
            antigravity.step(1, 'PLANNER_RESPONSE', 'MODEL', 'Historical visible reply'),
        ])
        original = fixture.reader.snapshot(fixture.reader.describe(antigravity.FIRST))
        project = self.catalog.repositories.discover_all()["main"]["fingerprint"]
        document = deepcopy(self.document)
        document["sources"]["antigravity"] = {
            "adapter": "antigravity", "format": "2.33.0", "root": str(fixture.root),
            "enabled": True, "instance_id": "antigravity",
            "exceptions": {antigravity.FIRST: {"project_id": "main", "source_identity": original.identity,
                          "source_revision": original.revision, "project_fingerprint": project}},
            "path_aliases": [{"native_project_id": native_project, "source_instance": "antigravity",
                              "old_root": str(old), "project_id": "main", "target_root": str(self.project)}],
        }
        document = compile_generation(document)
        self.store.activate(document, expected_digest=self.epoch)
        self.policy = AgentPolicy(self.descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.legacy = HistoryAccess(catalog=self.catalog, unified_policy=self.policy)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"k" * 32)
        page = self.operation("find_agent_threads", project_id="main", query="Historical visible",
                              agent="", source_id="antigravity", cursor="", limit=10)
        thread, = page["threads"]
        read = self.operation("read_agent_thread", thread_ref=thread["thread_ref"], view="all", turn_id="",
                              cursor="", limit=20, max_chars=16000)
        self.assertEqual([message["text"] for message in read["entries"]],
                         ['Historical visible question', 'Historical visible reply'])
        old.mkdir()
        with self.assertRaises(AccessError):
            self.operation("read_agent_thread", thread_ref=thread["thread_ref"], view="all", turn_id="",
                           cursor="", limit=20, max_chars=16000)


if __name__ == "__main__":
    unittest.main()
