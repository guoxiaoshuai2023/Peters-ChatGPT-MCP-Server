from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from peters_mcp.agent_history_admin import (activate_preview, compile_generation,
                                            approve_migration_scope, preview_activation,
                                            preview_migration, write_descriptor)
from peters_mcp.agent_history_generation import GenerationStore, canonical_bytes, initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import AccessError, Catalog


def _activate_child(path, document, token, ready, done):
    store = GenerationStore(path)
    ready.set()
    store.activate(document, expected_digest=token)
    done.set()


class UnifiedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "public.txt").write_text("visible text")
        self.source = self.base / "source"
        self.source.mkdir()
        self.actor = "a" * 64
        self.document = compile_generation({
            "version": 2, "projects": [{"id": "main", "name": "Main", "root": str(self.project)}],
            "principals": [self.actor], "sources": {"sample": {
                "adapter": "codeg", "root": str(self.source), "format": "0.45.0",
                "enabled": True, "instance_id": "sample-profile"}}, "legacy_history": None})
        self.store = initialize_store(self.private / "generations")
        self.token = self.store.activate(self.document, initial=True)
        self.descriptor = self.private / "agent-history.json"
        write_descriptor(self.descriptor, self.store)
        self.policy = AgentPolicy(self.descriptor, mode="v2")

    def test_global_actor_and_one_live_project_allowlist(self):
        catalog = Catalog.from_policy(self.policy)
        sources, token = self.policy.config()
        self.assertEqual(token, self.token)
        self.assertTrue(sources["sample"].allows(self.actor, "main"))
        self.assertFalse(sources["sample"].allows("b" * 64, "main"))
        self.policy.require_actor(self.actor)
        with self.assertRaises(AccessError):
            self.policy.require_actor("local")
        second = self.base / "second"
        second.mkdir()
        updated = deepcopy(self.document)
        updated["projects"].append({"id": "second", "name": "Second", "root": str(second)})
        updated = compile_generation(updated)
        self.store.activate(updated, expected_digest=self.token)
        catalog.refresh()
        self.assertEqual(set(catalog.projects), {"main", "second"})
        current, _ = self.policy.config()
        self.assertEqual(current["sample"].immutable(), sources["sample"].immutable())
        self.assertTrue(current["sample"].allows(self.actor, "second"))

    def test_activation_epoch_prevents_revoke_restore_aba(self):
        denied = deepcopy(self.document)
        denied["principals"] = []
        revoked = self.store.activate(denied, expected_digest=self.token)
        restored = self.store.activate(self.document, expected_digest=revoked)
        self.assertNotEqual(restored, self.token)
        self.assertEqual(self.policy.snapshot(), (self.document, restored))
        with self.assertRaises(AccessError) as rejected:
            with self.policy.commit_guard(self.token):
                self.fail("An old prepared response passed the restored policy.")
        self.assertEqual(rejected.exception.code, "restart_required")

    def test_shared_delivery_lock_serializes_cross_process_activation(self):
        context = multiprocessing.get_context("spawn")
        ready, done = context.Event(), context.Event()
        updated = deepcopy(self.document)
        updated["principals"] = []
        process = context.Process(target=_activate_child,
                                  args=(self.store.path, updated, self.token, ready, done))
        try:
            with self.policy.commit_guard(self.token) as snapshot:
                self.assertEqual(snapshot[1], self.token)
                process.start()
                self.assertTrue(ready.wait(5))
                self.assertFalse(done.wait(0.15))
            self.assertTrue(done.wait(5))
            process.join(5)
            self.assertEqual(process.exitcode, 0)
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)

    def test_loss_corruption_and_permissions_never_fall_back(self):
        pointer = self.store.path / "active.json"
        original = pointer.read_bytes()
        for value in (b"{", b'{"version":1}', b'{}'):
            with self.subTest(value=value):
                pointer.write_bytes(value)
                with self.assertRaises(AccessError):
                    self.policy.snapshot()
        pointer.write_bytes(original)
        pointer.unlink()
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        pointer.write_bytes(original)
        pointer.chmod(0o644)
        with self.assertRaises(AccessError):
            self.policy.snapshot()
        pointer.chmod(0o600)
        pointer_document = json.loads(original)
        generation = self.store.path / "generations" / (pointer_document["sha256"] + ".json")
        generation.write_text("{}")
        with self.assertRaises(AccessError):
            self.policy.snapshot()

    def test_v2_descriptor_requires_explicit_mode_and_private_file(self):
        with self.assertRaises(AccessError):
            AgentPolicy(self.descriptor)
        with self.assertRaises(AccessError):
            AgentPolicy(None, mode="v2")
        self.descriptor.chmod(0o644)
        with self.assertRaises(AccessError):
            AgentPolicy(self.descriptor, mode="v2")

    def test_root_replacement_rejected_across_new_runtime_and_catalog_reads(self):
        catalog = Catalog.from_policy(self.policy)
        self.project.rename(self.base / "old-project")
        self.project.mkdir()
        (self.project / "public.txt").write_text("replacement")
        restarted = Catalog.from_policy(AgentPolicy(self.descriptor, mode="v2"))
        for current in (catalog, restarted):
            entry = current.repositories.discover("main")["worktrees"][0]
            self.assertEqual(entry["state"], "identity_mismatch")
            with self.assertRaises(AccessError):
                current.read_file("main", "public.txt")
        self.source.rename(self.base / "old-source")
        self.source.mkdir()
        restarted_policy = AgentPolicy(self.descriptor, mode="v2")
        source = restarted_policy.config()[0]["sample"]
        with self.assertRaises(AccessError) as rejected:
            restarted_policy.make_root("sample", source)
        self.assertEqual(rejected.exception.code, "source_unavailable")
        self.assertTrue(restarted_policy.excludes(self.base / "old-source" / "raw.jsonl"))

    def test_empty_allowlist_is_a_valid_revocation(self):
        catalog = Catalog.from_policy(self.policy)
        updated = deepcopy(self.document)
        updated["projects"] = []
        self.store.activate(updated, expected_digest=self.token)
        catalog.refresh()
        self.assertEqual(catalog.list_projects()["projects"], [])
        with self.assertRaises(AccessError):
            catalog.read_file("main", "public.txt")

    def test_project_removal_needs_no_source_exception_edit(self):
        updated = deepcopy(self.document)
        updated["sources"]["sample"]["exceptions"] = {"old-thread": {
            "project_id": "main", "source_identity": "1:2:3", "source_revision": "a" * 64,
            "project_fingerprint": "b" * 64}}
        updated["projects"] = []
        prepared = compile_generation(updated)
        self.assertEqual(prepared["sources"]["sample"], updated["sources"]["sample"])
        self.store.activate(prepared, expected_digest=self.token)
        self.assertEqual(Catalog.from_policy(self.policy).list_projects()["projects"], [])

    def test_disabled_codex_keeps_storage_and_tool_evidence_independent(self):
        updated = deepcopy(self.document)
        updated["sources"] = {"codex": {
            "adapter": "codex", "root": str(self.source), "format": "local", "enabled": False,
            "instance_id": "native-codex", "denied_threads": ["c14584e8-ab98-4404-a949-a9fb275d7173"]}}
        updated["legacy_history"] = {"codex_home": str(self.source), "state_db": "state_5.sqlite",
                                     "tool_evidence": [{"id": "909e7151-a3ce-4c1b-ac17-17575c1d49bf", "allow_tool_results": True,
                                                        "mcp_tools": ["example/read"]}]}
        updated = compile_generation(updated)
        token = self.store.activate(updated, expected_digest=self.token)
        restarted = AgentPolicy(self.descriptor, mode="v2")
        snapshot = restarted.snapshot()
        self.assertEqual(snapshot[1], token)
        source = restarted.config(snapshot)[0]["codex"]
        self.assertFalse(source.allows(self.actor, ""))
        legacy = restarted.legacy_document(snapshot)
        self.assertEqual(legacy["codex_home"], str(self.source))
        self.assertEqual(legacy["denied_threads"], ["c14584e8-ab98-4404-a949-a9fb275d7173"])
        self.assertEqual(legacy["threads"][0]["mcp_tools"], ["example/read"])

    def test_native_links_bind_exact_registered_instance(self):
        updated = deepcopy(self.document)
        deepseek = self.base / "deepseek"
        deepseek.mkdir()
        updated["sources"]["native"] = {"adapter": "deepseek_harness", "root": str(deepseek),
                                           "format": "0.2.2-rc.3", "enabled": True,
                                           "instance_id": "dsh-profile"}
        updated["sources"]["sample"]["links"] = {"deepseek_harness": "native"}
        with self.assertRaises(AccessError):
            compile_generation(updated)
        updated["sources"]["sample"]["link_instances"] = {"deepseek_harness": "wrong-profile"}
        with self.assertRaises(AccessError):
            compile_generation(updated)
        updated["sources"]["sample"]["link_instances"] = {"deepseek_harness": "dsh-profile"}
        prepared = compile_generation(updated)
        self.assertEqual(prepared["sources"]["sample"]["links"], {"deepseek_harness": "native"})

    def test_preview_bound_to_inputs_generation_and_pins(self):
        draft = self.private / "draft.json"
        draft.write_text(json.dumps(self.document))
        preview, digest = preview_activation(self.document, inputs=[{
            "path": str(draft), "sha256": hashlib.sha256(draft.read_bytes()).hexdigest()}],
                                             previous=self.policy.snapshot())
        changed = deepcopy(preview)
        changed["document"]["principals"].append("b" * 64)
        with self.assertRaises(AccessError):
            activate_preview(self.store, changed, digest)
        draft.write_text("{}")
        with self.assertRaises(AccessError):
            activate_preview(self.store, preview, digest)
        self.project.rename(self.base / "old-project")
        self.project.mkdir()
        with self.assertRaises(AccessError):
            compile_generation(self.document)

    def test_source_registration_change_requires_restart_and_stays_protected(self):
        updated = deepcopy(self.document)
        updated["sources"]["sample"]["instance_id"] = "different-profile"
        self.store.activate(updated, expected_digest=self.token)
        with self.assertRaises(AccessError) as rejected:
            self.policy.config()
        self.assertEqual(rejected.exception.code, "restart_required")
        self.assertTrue(self.policy.excludes(self.source / "secret.jsonl"))
        self.assertTrue(self.policy.excludes(self.store.path / "active.json"))

    def test_migration_preview_preserves_denials_and_requires_verified_exceptions(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "v1.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {"old-thread": "main"},
            "denied_threads": ["denied-thread"]}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor])
        self.assertEqual(preview["document"]["sources"]["sample"]["denied_threads"], ["denied-thread"])
        self.assertEqual(preview["unresolved"][0]["reason"], "snapshot_binding_requires_verification")
        with self.assertRaises(AccessError):
            activate_preview(self.store, preview, digest)
        with self.assertRaises(AccessError):
            compile_generation({**self.document, "principals": ["not-a-verified-principal"]})

    def test_heterogeneous_migration_needs_exact_scope_approval_for_each_actor(self):
        second = self.base / "second"
        second.mkdir()
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [
            {"id": "main", "name": "Main", "root": str(self.project)},
            {"id": "second", "name": "Second", "root": str(second)}]}))
        other = "b" * 64
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": True, "actors": {self.actor: ["main"], other: ["second"]},
            "threads": {}, "denied_threads": []}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor, other])
        self.assertEqual(preview["unresolved"], [])
        self.assertEqual(len(preview["required_scope_approvals"]), 2)
        target_store = initialize_store(self.private / "migration-target")
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, preview, digest, initial=True)
        preview, digest = approve_migration_scope(preview, self.actor, "sample", digest)
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, preview, digest, initial=True)
        preview, digest = approve_migration_scope(preview, other, "sample", digest)
        corrupted = deepcopy(preview)
        corrupted["document"]["principals"].append("c" * 64)
        corrupted_digest = hashlib.sha256(canonical_bytes(corrupted)).hexdigest()
        with self.assertRaisesRegex(AccessError, "Confirm every"):
            activate_preview(target_store, corrupted, corrupted_digest, initial=True)
        active = activate_preview(target_store, preview, digest, initial=True)
        self.assertEqual(target_store.snapshot()[1], active)

    def test_migration_to_automatic_inheritance_needs_explicit_scope_decision(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "codeg", "root": str(self.source), "format": "0.45.0", "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {}, "denied_threads": []}}}))
        preview, digest = preview_migration(projects, old, None, [self.actor])
        self.assertEqual(preview["changes"][0]["added_projects"], [])
        self.assertFalse(preview["changes"][0]["old_inherit_projects"])
        self.assertEqual(len(preview["required_scope_approvals"]), 1)
        approved, approved_digest = approve_migration_scope(preview, self.actor, "sample", digest)
        old.write_text("{}")
        with self.assertRaisesRegex(AccessError, "input changed"):
            activate_preview(self.store, approved, approved_digest)

    def test_cli_migration_preserves_optional_antigravity_format_without_activation(self):
        projects = self.private / "projects.json"
        projects.write_text(json.dumps({"projects": [{"id": "main", "name": "Main", "root": str(self.project)}]}))
        old = self.private / "old.json"
        old.write_text(json.dumps({"version": 1, "sources": {"sample": {
            "adapter": "antigravity", "root": str(self.source), "enabled": True,
            "inherit_projects": False, "actors": {self.actor: ["main"]}, "threads": {}, "denied_threads": []}}}))
        result = subprocess.run([sys.executable, "-m", "peters_mcp.agent_history_admin", "preview-migration",
                                 "--projects", str(projects), "--agent-v1", str(old),
                                 "--principal", self.actor], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        preview = json.loads(result.stdout)
        self.assertIsNone(preview["preview"]["document"]["sources"]["sample"]["format"])
        self.assertEqual(preview["preview"]["scope_approvals"], [])
        self.assertEqual(self.store.snapshot()[1], self.token)
        wrong = deepcopy(preview["preview"]["document"])
        wrong["sources"]["sample"]["adapter"] = "codeg"
        with self.assertRaises(AccessError):
            compile_generation(wrong)


if __name__ == "__main__":
    unittest.main()
