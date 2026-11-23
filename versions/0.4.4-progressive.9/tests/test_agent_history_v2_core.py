"""Unified history gates, source identity and project-scoped scan budgets."""

from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.agent_history import AgentHistoryCore, MAX_SEARCH
from peters_mcp.agent_history_source import Message, Projection, Thread
from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.fs_identity import persistent_identity


def finish(iterator):
    while True:
        try:
            next(iterator)
        except StopIteration as result:
            return result.value


class UnifiedCoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / "project"
        self.foreign = self.root / "foreign"
        self.project.mkdir()
        self.foreign.mkdir()
        self.catalog = Catalog([Project("main", "Main", self.project, True),
                                Project("foreign", "Foreign", self.foreign, True)])
        self.actor = "a" * 64
        self.principals = {self.actor}
        self.source = SimpleNamespace(
            adapter="codeg", format="0.45.0", enabled=True, inherit=True,
            instance_id="codeg", threads={}, exceptions={}, denied=frozenset(),
            links={}, link_instances={},
        )
        self.source.allows = lambda actor, project: self.source.enabled and actor in self.principals
        self.sources = {"codeg": self.source}
        self.policy = SimpleNamespace(
            mode="v2", version=2, config=lambda: (self.sources, "synthetic-generation"),
            allows_actor=lambda actor: actor in self.principals, excludes=lambda path: False,
            make_root=lambda name, source: None,
        )
        self.legacy = SimpleNamespace(config_path=None)
        self.core = AgentHistoryCore(self.policy, self.catalog, self.legacy, b"x" * 32)
        self.thread = Thread("thread", "Visible title", contexts=(str(self.project),),
                             context_complete=True, agent="custom:test", surface="codeg_acp")
        self.projection = Projection((Message("user", "Visible question", "seq:1"),),
                                     "revision-1", "identity-1", contexts=(str(self.project),),
                                     context_complete=True)
        self.candidates = [self.thread]
        self.adapter = SimpleNamespace(
            project_partition_complete=True, warnings=(),
            discover_project=lambda roots, **options: iter(self.candidates),
            describe=lambda native: self.thread,
            snapshot=lambda thread: self.projection,
        )
        self.patched = patch("peters_mcp.agent_history._adapter", return_value=self.adapter)
        self.factory = self.patched.start()
        self.addCleanup(self.patched.stop)

    def scope(self):
        return self.core._configuration("main", self.actor, self.actor)

    def find(self, query=""):
        result = finish(self.core._find("main", query, "", "codeg", "", 10, self.actor, self.actor))
        return finish(self.core.revalidate_result_iter("find_agent_threads",
            {"actor": self.actor, "policy_actor": self.actor}, result))

    def test_unregistered_authenticated_principal_is_rejected_before_source_scan(self):
        with self.assertRaises(AccessError) as denied:
            self.core._configuration("main", "b" * 64, "b" * 64)
        self.assertEqual(denied.exception.code, "unauthorized")
        self.factory.assert_not_called()

    def test_foreign_candidates_do_not_charge_the_selected_project_budget(self):
        self.candidates = [Thread("foreign-" + str(index), "Visible title",
                                 contexts=(str(self.foreign),), context_complete=True)
                           for index in range(MAX_SEARCH + 5)] + [self.thread]
        page = self.find("Visible question")
        self.assertEqual(len(page["threads"]), 1)
        self.assertTrue(page["coverage_complete"])
        self.assertEqual(page["coverage"][0]["state"], "complete")
        self.assertEqual(page["threads"][0]["source_instance"], "codeg")

    def test_partial_project_index_reports_capability_without_unknown_record_counts(self):
        self.adapter.project_partition_complete = False
        before = self.find("missing")
        self.candidates.extend(Thread("unknown-" + str(index)) for index in range(MAX_SEARCH + 5))
        after = self.find("missing")
        self.assertEqual(before["coverage"], after["coverage"])
        self.assertEqual(after["coverage"][0]["state"], "association_unverified")
        self.assertFalse(after["coverage_complete"])
        self.assertEqual(after["threads"], [])

    def test_legacy_exception_is_bound_to_exact_source_cut_and_project_identity(self):
        self.source.threads["thread"] = "main"
        scope = self.scope()
        self.source.exceptions["thread"] = {
            "project_id": "main", "source_identity": "identity-1", "source_revision": "revision-1",
            "project_fingerprint": scope.worktrees["main"]["fingerprint"],
        }
        self.projection = replace(self.projection, context_complete=False)
        record = finish(self.core._load(scope, "codeg", "thread"))
        self.assertEqual(record.entries[0].text, "Visible question")
        for altered in (replace(self.projection, revision="appended"),
                        replace(self.projection, identity="replacement")):
            self.projection = altered
            with self.assertRaises(AccessError) as denied:
                finish(self.core._load(scope, "codeg", "thread"))
            self.assertEqual(denied.exception.code, "association_unverified")

    def test_source_instance_changes_stable_ids_and_message_namespace(self):
        first = finish(self.core._load(self.scope(), "codeg", "thread"))
        expected = hashlib.sha256(b'["codeg","thread"]').hexdigest()
        self.assertEqual(first.stable_id, expected)
        self.source.instance_id = "another-profile"
        second = finish(self.core._load(self.scope(), "codeg", "thread"))
        self.assertNotEqual(first.stable_id, second.stable_id)
        self.assertNotEqual(self.core._message_id(first, first.entries[0]),
                            self.core._message_id(second, second.entries[0]))

    def test_codex_is_gated_by_the_same_enabled_source_before_legacy_read(self):
        self.sources["codex"] = SimpleNamespace(enabled=False, allows=lambda actor, project: False)
        with self.assertRaises(AccessError) as denied:
            finish(self.core._load(self.scope(), "codex", "native-id"))
        self.assertEqual(denied.exception.code, "unauthorized")
        self.assertNotIn("codex", self.core._sources(self.scope(), ""))

    def test_prepared_page_cannot_be_delivered_after_global_actor_revocation(self):
        prepared = finish(self.core._find("main", "", "", "codeg", "", 10, self.actor, self.actor))
        self.principals.clear()
        with self.assertRaises(AccessError) as denied:
            finish(self.core.revalidate_result_iter("find_agent_threads",
                {"actor": self.actor, "policy_actor": self.actor}, prepared))
        self.assertEqual(denied.exception.code, "unauthorized")

    def test_denied_ancestors_do_not_consume_the_authorized_body_budget(self):
        self.source.denied = frozenset({"blocked-parent"})
        self.candidates = [replace(self.thread, native_id="blocked-" + str(index))
                           for index in range(MAX_SEARCH + 5)] + [self.thread]
        self.adapter.snapshot = lambda thread: self.projection if thread.native_id == "thread" else replace(
            self.projection, ancestors=("blocked-parent",))
        page = self.find()
        self.assertEqual(len(page["threads"]), 1)
        self.assertTrue(page["coverage_complete"])

    def alias(self):
        old = self.root / "old-project"
        self.source.path_aliases = [{
            "native_project_id": "native-project", "source_instance": self.source.instance_id,
            "old_root": str(old), "project_id": "main", "target_root": str(self.project),
            "target_identity": persistent_identity(self.project),
        }]
        self.thread = replace(self.thread, contexts=(str(old),), native_project_id="native-project")
        self.projection = replace(self.projection, contexts=(str(old),))
        return old

    def test_alias_maps_only_the_exact_missing_root_with_matching_native_project(self):
        old = self.alias()
        record = finish(self.core._load(self.scope(), "codeg", "thread"))
        self.assertEqual(record.entries[0].text, "Visible question")
        self.thread = replace(self.thread, contexts=(str(old / "subdirectory"),))
        self.projection = replace(self.projection, contexts=(str(old / "subdirectory"),))
        with self.assertRaises(AccessError):
            finish(self.core._load(self.scope(), "codeg", "thread"))

    def test_alias_requires_the_matching_source_instance_and_native_project(self):
        self.alias()
        for changed in (replace(self.thread, native_project_id="another-native-project"),
                        replace(self.thread, native_project_id="")):
            self.thread = changed
            with self.assertRaises(AccessError):
                finish(self.core._load(self.scope(), "codeg", "thread"))
        self.thread = replace(self.thread, native_project_id="native-project")
        self.source.instance_id = "another-profile"
        with self.assertRaises(AccessError):
            finish(self.core._load(self.scope(), "codeg", "thread"))

    def test_alias_rejects_reused_old_path_and_replaced_target_directory(self):
        old = self.alias()
        old.mkdir()
        with self.assertRaises(AccessError):
            finish(self.core._load(self.scope(), "codeg", "thread"))
        old.rmdir()
        self.project.rename(self.root / "previous-target")
        self.project.mkdir()
        with self.assertRaises(AccessError):
            finish(self.core._load(self.scope(), "codeg", "thread"))

    def test_alias_keeps_all_ancestor_project_and_workspace_checks(self):
        self.alias()
        self.thread = replace(self.thread, ancestors=("parent",),
                              ancestor_projects=(("parent", "native-project"),))
        self.projection = replace(self.projection, ancestors=("parent",))
        self.assertTrue(finish(self.core._load(self.scope(), "codeg", "thread")).entries)
        for projects in ((), (("parent", "another-project"),)):
            self.thread = replace(self.thread, ancestor_projects=projects)
            with self.assertRaises(AccessError):
                finish(self.core._load(self.scope(), "codeg", "thread"))
        self.thread = replace(self.thread, ancestor_projects=(("parent", "native-project"),))
        self.projection = replace(self.projection, contexts=(*self.projection.contexts, str(self.foreign)))
        with self.assertRaises(AccessError):
            finish(self.core._load(self.scope(), "codeg", "thread"))

    def test_alias_never_replaces_the_complete_context_or_exact_snapshot_requirement(self):
        self.alias()
        self.projection = replace(self.projection, context_complete=False)
        with self.assertRaises(AccessError) as denied:
            finish(self.core._load(self.scope(), "codeg", "thread"))
        self.assertEqual(denied.exception.code, "association_unverified")


if __name__ == "__main__":
    unittest.main()
