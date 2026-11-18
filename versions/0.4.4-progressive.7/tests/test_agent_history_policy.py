import json
from pathlib import Path
import tempfile
import unittest
import unicodedata

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_source import Projection, Thread
from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.history import HistoryAccess


class AgentHistoryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.project = self.base / "projects"
        self.project.mkdir()
        self.source = self.project / "caf\u00e9"
        self.source.mkdir()
        (self.source / "hidden.jsonl").write_text("synthetic raw history marker")
        self.other = self.base / "other"
        self.other.mkdir()
        self.policy_file = self.base / "agent-history-access.local.json"
        self.actor = "a" * 64

    def policy(self, *, threads=None, deny=()):
        self.policy_file.write_text(json.dumps({"version": 1, "sources": {"codeg": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": True, "actors": {self.actor: ["main"]},
            "threads": threads or {}, "denied_threads": list(deny),
        }}}))
        return AgentPolicy(self.policy_file)

    def catalog(self):
        return Catalog([Project("main", "Main", self.project, True),
                        Project("other", "Other", self.other, True)])

    def test_normalized_alias_cannot_access_registered_source_through_files(self):
        policy = self.policy()
        catalog = self.catalog()
        catalog.set_agent_history_policy(policy)
        alias = unicodedata.normalize("NFD", self.source.name)
        for value in (self.source.name, alias):
            with self.assertRaises(AccessError) as result:
                catalog.read_file("main", value + "/hidden.jsonl")
            self.assertEqual(result.exception.code, "private_path")
        listing = catalog.list_files("main")
        self.assertEqual(listing["entries"], [])

    def test_project_inheritance_requires_complete_verified_body_and_checks_ancestors(self):
        catalog = self.catalog()
        policy = self.policy(deny=("parent",))
        core = AgentHistoryCore(policy, catalog, HistoryAccess(catalog=catalog), b"k" * 32)
        scope = core._configuration("main", self.actor, self.actor)
        source = scope.sources["codeg"]
        metadata = Thread("test-id", contexts=(str(self.project),), context_complete=True)
        for projection in (
            Projection((), "", "", context_complete=False),
            Projection((), "", "", ancestors=("parent",), context_complete=True),
            Projection((), "", "", contexts=(str(self.other),), context_complete=True),
        ):
            with self.subTest(projection=projection), self.assertRaises(AccessError) as result:
                core._binding(scope, source, metadata, projection)
            self.assertEqual(result.exception.code, "unauthorized")
        self.assertTrue(core._binding(scope, source, metadata, Projection((), "", "", context_complete=True)))

    def test_changed_source_stays_protected_until_operator_restarts(self):
        policy = self.policy()
        old_store = self.project / "old-store"
        self.source.rename(old_store)
        self.source.mkdir()
        source = policy.config()[0]["codeg"]
        with self.assertRaises(AccessError) as result:
            policy.make_root("codeg", source)
        self.assertEqual(result.exception.code, "source_unavailable")
        self.assertTrue(policy.excludes(self.source / "hidden.jsonl"))
        self.assertTrue(policy.excludes(old_store / "hidden.jsonl"))
        catalog = self.catalog()
        catalog.set_agent_history_policy(policy)
        with self.assertRaises(AccessError) as blocked:
            catalog.read_file("main", "old-store/hidden.jsonl")
        self.assertEqual(blocked.exception.code, "private_path")
