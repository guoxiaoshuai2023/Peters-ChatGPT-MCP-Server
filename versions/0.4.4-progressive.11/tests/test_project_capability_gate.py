"""An actual ASGI response and confirmed candidate publication use the live project epoch."""

import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import anyio
from mcp.client import Client

from peters_mcp.agent_history_admin import compile_generation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.candidates import CandidateDelivery, publish_exclusive
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import verified_file_actor
from peters_mcp.file_targets import FileTargets
from peters_mcp.project_guard import ProjectResponseGate, _async_reservation, commit_project, local_tool_scope, project_token
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp import workspaces
from peters_mcp.server import create_server
from tests.test_workspaces import fixture_git, fixture_registered_worktree


async def post(app, body, headers=(), *, observe=None):
    events = []
    request_delivered = False

    async def receive():
        nonlocal request_delivered
        if request_delivered:
            await anyio.sleep_forever()
        request_delivered = True
        return {"type": "http.request", "body": json.dumps(body).encode()}

    async def send(event):
        events.append(event)
        if observe is not None:
            observe(event)

    await app({"type": "http", "method": "POST", "scheme": "https", "path": "/mcp",
               "root_path": "", "http_version": "1.1", "query_string": b"", "server": ("test.example", 443),
               "headers": [(b"host", b"test.example"), (b"content-type", b"application/json"),
                           (b"accept", b"application/json, text/event-stream"), *headers]}, receive, send)
    return events[0]["status"], b"".join(event["body"] for event in events[1:]).decode()


async def start(app, task_status=anyio.TASK_STATUS_IGNORED):
    stopping = anyio.Event()
    fresh = True

    async def receive():
        nonlocal fresh
        if fresh:
            fresh = False
            return {"type": "lifespan.startup"}
        await stopping.wait()
        return {"type": "lifespan.shutdown"}

    async def send(event):
        if event["type"] == "lifespan.startup.complete":
            task_status.started(stopping)
        elif event["type"].endswith("failed"):
            raise RuntimeError(event["message"])

    await app({"type": "lifespan", "state": {}}, receive, send)


class _ScopeFixture:
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        self.project = base / "project"
        self.project.mkdir()
        self.other = base / "other"
        self.other.mkdir()
        self.document = compile_generation({
            "version": 2, "projects": [{"id": "demo", "name": "Demo", "root": str(self.project)}],
            "sources": {}, "legacy_history": None,
        })
        private = base / "private"
        private.mkdir(mode=0o700)
        self.store = initialize_store(private / "generations")
        self.epoch = self.store.activate(self.document, initial=True)
        descriptor = private / "agent-history.json"
        write_descriptor(descriptor, self.store)
        self.policy = AgentPolicy(descriptor, mode="v2")
        self.catalog = Catalog.from_policy(self.policy)
        self.delivery = CandidateDelivery(self.catalog)

    def change(self, projects):
        document = deepcopy(self.document)
        document["projects"] = projects
        self.epoch = self.store.activate(compile_generation(document), expected_digest=self.epoch)

    def revoke(self):
        self.change([])


class UnifiedCandidateTests(_ScopeFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        actor = verified_file_actor.set("demo-actor")
        self.addCleanup(verified_file_actor.reset, actor)

    def preview(self):
        return self.delivery.prepare_candidate("demo", "plan.md", "# Confirmed content")["save_arguments"]

    def test_default_path_is_created_only_after_confirmation(self):
        args = self.preview()
        self.assertEqual(list(self.project.iterdir()), [])
        self.assertEqual(args["path"], "docs/candidates/chatgpt/plan.md")
        self.assertEqual(self.delivery.save_candidate(**args)["status"], "saved")
        self.assertEqual((self.project / args["path"]).read_bytes(), args["document"].encode())
        self.assertEqual(self.delivery.save_candidate(**args)["status"], "already_saved")

    def test_unknown_publish_outcome_allows_exact_verification_without_recreation(self):
        args = self.preview()

        def lost_result(*arguments):
            publish_exclusive(*arguments)
            raise OSError("publication reply lost")

        with patch("peters_mcp.candidates.publish_exclusive", side_effect=lost_result):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        self.assertEqual(self.delivery.save_candidate(**args)["status"], "already_saved")
        path = self.project / args["path"]
        path.unlink()
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertFalse(path.exists())

    def save_during_foreign_move(self, *, overlaps):
        side = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, side)])
        args = self.preview()
        real_fsync = os.fsync
        changed = False

        def move_after_staging(fd):
            nonlocal changed
            if not changed:
                destination = (self.project if overlaps else self.project.parent) / 'moved'
                fixture_git(self.other, 'worktree', 'move', str(side), str(destination))
                changed = True
            return real_fsync(fd)

        with patch('peters_mcp.candidates.os.fsync', move_after_staging):
            if overlaps:
                with self.assertRaises(AccessError):
                    self.delivery.save_candidate(**args)
            else:
                self.assertEqual(self.delivery.save_candidate(**args)['status'], 'saved')
        self.assertTrue(changed)
        return self.project / args['path']

    def test_direct_candidate_rejects_new_overlap_before_rename(self):
        self.assertFalse(self.save_during_foreign_move(overlaps=True).exists())
        self.assertFalse((self.project / 'docs').exists())

    def test_direct_candidate_can_finish_after_unrelated_worktree_move(self):
        self.assertTrue(self.save_during_foreign_move(overlaps=False).is_file())

    def test_incomplete_git_discovery_cannot_be_replaced_by_later_healthy_evidence(self):
        side = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, side)])
        self.catalog.refresh()
        (self.project / 'note.txt').write_text('verified file')
        @contextmanager
        def git_offline():
            # Simulate an interrupted config edit on the registered fixture.
            # Both the failure and recovery are observed by the actual Git binary.
            config = self.other / '.git' / 'config'
            healthy = config.read_bytes()
            try:
                config.write_bytes(b'[core\n')
                yield
            finally:
                config.write_bytes(healthy)

        token = project_token(self.catalog, 'demo')
        with git_offline():
            prior = self.catalog.repositories.discover_all(observe=False).topology
            self.assertFalse(prior.complete)
            with self.assertRaises(AccessError):
                self.catalog.read_file('demo', 'note.txt')
        with self.assertRaises(AccessError) as rejected:
            with commit_project(self.catalog, 'demo', token, topology=prior):
                self.fail('a later successful Git query cannot validate a prior incomplete selection')
        self.assertEqual(rejected.exception.code, 'restart_required')
        with self.assertRaises(AccessError) as rejected:
            with local_tool_scope(self.catalog):
                with git_offline(), self.assertRaises(AccessError):
                    self.catalog.read_file('demo', 'note.txt')
                with self.assertRaises(AccessError):
                    self.catalog.read_file('demo', 'note.txt')
        self.assertEqual(rejected.exception.code, 'restart_required')
        with local_tool_scope(self.catalog):
            self.assertIn('verified file', str(self.catalog.read_file('demo', 'note.txt')))

    def git_scope(self):
        side = self.project.parent / 'external'
        row = fixture_registered_worktree(self.other, side)
        self.change([*self.document['projects'], row])
        self.catalog.refresh()
        return side

    def test_git_control_change_after_successful_discovery_and_recovery(self):
        self.git_scope()
        before = self.catalog.repositories.discover('other').topology
        token = project_token(self.catalog, 'other')
        fixture_git(self.other, 'config', 'core.bare', 'true')
        self.assertFalse(self.catalog.repositories.discover_all(observe=False).topology.complete)
        with self.assertRaises(AccessError):
            with commit_project(self.catalog, 'other', token, topology=before):
                self.fail('a now-unavailable repository cannot commit')
        fixture_git(self.other, 'config', 'core.bare', 'false')
        self.assertTrue(self.catalog.repositories.discover('other').topology.complete)
        with commit_project(self.catalog, 'other', token, topology=before):
            pass

    def test_nested_conditional_missing_include_is_watched_on_first_discovery(self):
        self.git_scope()
        config = self.other / '.git' / 'local.inc'
        missing = config.with_name('optional.inc')
        fixture_git(self.other, 'config', 'includeIf.onbranch:main.path', config.name)
        fixture_git(self.other, 'config', '--file', str(config), 'include.path', missing.name)
        before = self.catalog.repositories.discover('other').topology
        self.assertIn(missing, dict(before.controls))
        fixture_git(self.other, 'config', '--file', str(missing), 'core.bare', 'true')
        with self.assertRaises(AccessError):
            with commit_project(self.catalog, 'other', project_token(self.catalog, 'other'), topology=before):
                self.fail('the newly present native include changes repository recognition')

    def test_reftable_branch_switch_invalidates_onbranch_in_default_and_linked_worktrees(self):
        try:
            fixture_git(self.other, "init", "--ref-format=reftable", "-b", "main")
        except subprocess.CalledProcessError as error:
            if "unknown option" in error.stderr:
                self.skipTest("Installed Git lacks the reftable backend.")
            raise
        fixture_git(self.other, "commit", "--allow-empty", "-m", "fixture")
        side = self.project.parent / "linked"
        fixture_git(self.other, "worktree", "add", "-b", "side", str(side))
        fragment = self.other / ".git" / "branch.inc"
        fixture_git(self.other, "config", "--file", str(fragment), "test.checked", "true")
        for branch in ("main", "side"):
            fixture_git(self.other, "config", f"includeIf.onbranch:{branch}.path", str(fragment))
        self.change([*self.document["projects"], {"id": "other", "name": "Other", "root": str(self.other),
                                                  "repository_id": workspaces.RepositoryRegistry.identity(self.other)}])
        self.catalog.refresh()
        for directory, branch in ((self.other, "main"), (side, "side")):
            with self.subTest(branch=branch):
                fixture_git(directory, "switch", "--detach")
                old = self.catalog.repositories.discover("other").topology
                self.assertTrue(old.complete)
                fixture_git(directory, "switch", branch)
                self.assertEqual(fixture_git(directory, "config", "--includes", "--get", "test.checked").strip(), "true")
                self.assertFalse(old.current(self.policy.snapshot(), time.monotonic() + 2))
                self.assertTrue(self.catalog.repositories.discover("other").topology.complete)

    def test_worktree_config_rechecks_only_affected_physical_membership(self):
        side = self.git_scope()
        fixture_git(self.other, 'config', 'extensions.worktreeConfig', 'true')
        before = self.catalog.repositories.discover('other').topology
        fixture_git(side, 'config', '--worktree', 'core.bare', 'true')
        fresh = self.catalog.repositories.discover_all()
        self.assertTrue(fresh.topology.complete)
        self.assertEqual(next(w for w in fresh['other']['worktrees'] if w['root'] == str(side))['state'], 'unavailable')
        with self.assertRaises(AccessError):
            with commit_project(self.catalog, 'other', project_token(self.catalog, 'other'), topology=before):
                self.fail('the previously verified linked worktree is unavailable')
        with commit_project(self.catalog, 'demo', project_token(self.catalog, 'demo'), topology=before):
            pass

    def test_include_symlink_tracks_the_actual_file_and_unknown_conditions_are_unverified(self):
        self.git_scope()
        settings = self.project.parent / 'external-settings'
        settings.mkdir()
        fragment = settings / 'settings.inc'
        fixture_git(self.other, 'config', '--file', str(fragment), 'core.bare', 'false')
        alias = self.other / '.git' / 'settings-link'
        alias.symlink_to(settings, target_is_directory=True)
        fixture_git(self.other, 'config', 'include.path', 'settings-link/settings.inc')
        before = self.catalog.repositories.discover('other').topology
        fixture_git(self.other, 'config', '--file', str(fragment), 'core.bare', 'true')
        self.assertFalse(before.current(self.policy.snapshot(), time.monotonic() + 2))
        fixture_git(self.other, 'config', '--file', str(fragment), 'core.bare', 'false')
        fixture_git(self.other, 'config', 'includeIf.future:policy.path', 'settings-link/settings.inc')
        self.assertFalse(self.catalog.repositories.discover_all(observe=False).topology.complete)

    def test_native_commit_and_detached_head_preserve_scope(self):
        side = self.git_scope()
        before = self.catalog.repositories.discover('other').topology
        fixture_git(side, 'checkout', '-q', '--detach')
        fixture_git(side, 'commit', '--allow-empty', '-m', 'normal detached commit')
        self.assertFalse(before.current(self.policy.snapshot(), time.monotonic() + 2))
        with commit_project(self.catalog, 'other', project_token(self.catalog, 'other'), topology=before):
            pass

    def test_unavailable_registered_overlap_cannot_prove_file_membership(self):
        side = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, side)])
        destination = self.project / 'side'
        fixture_git(self.other, 'worktree', 'move', str(side), str(destination))
        (self.project / 'visible.md').write_text('project text')
        probe = workspaces._probe

        def unavailable(path):
            if path == destination:
                raise AccessError('Synthetic Git metadata temporarily unavailable.')
            return probe(path)

        with patch.object(workspaces, '_probe', unavailable), self.assertRaises(AccessError):
            self.catalog.read_file('demo', 'visible.md')

    def test_background_rediscovery_runs_outside_private_and_policy_reservations(self):
        side = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, side)])
        self.catalog.refresh()
        proof = self.catalog.repositories.discover('demo').topology
        grant = project_token(self.catalog, 'demo')
        fixture_git(self.other, 'worktree', 'move', str(side), str(side.with_name('unrelated')))
        control = self.project.parent / 'protection'
        control.mkdir(mode=0o700)
        registry = PrivateRootRegistry(control, allowed_roots=())
        registry.initialize()
        held, calls = set(), []
        git = workspaces._git

        def observe_lock(name, guard):
            @contextmanager
            def examine(*args, **kwargs):
                with guard(*args, **kwargs) as value:
                    held.add(name)
                    try:
                        yield value
                    finally:
                        held.remove(name)
            return examine

        def observe_git(*args):
            calls.append(set(held))
            return git(*args)

        with patch.object(self.policy, 'commit_guard', observe_lock('policy', self.policy.commit_guard)), \
                patch.object(registry, 'read_guard', observe_lock('private', registry.read_guard)), \
                patch.object(workspaces, '_git', observe_git):
            with commit_project(self.catalog, 'demo', grant, topology=proof, private_registry=registry):
                self.assertEqual(held, {'private', 'policy'})
        self.assertTrue(calls)
        self.assertFalse(any(calls))

    def test_different_actor_new_generation_and_unexpected_parent_are_rejected(self):
        args = self.preview()
        actor = verified_file_actor.set("other-actor")
        try:
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        finally:
            verified_file_actor.reset(actor)
        self.revoke()
        self.change(self.document["projects"])
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertEqual(list(self.project.iterdir()), [])
        args = self.preview()
        docs = self.project / "docs"
        docs.mkdir()
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertEqual(list(docs.iterdir()), [])

    def test_revoke_after_staging_cleans_only_owned_empty_directories(self):
        args = self.preview()
        real_fsync = os.fsync
        invoked = False

        def revoke_while_staging(fd):
            nonlocal invoked
            if not invoked:
                invoked = True
                with patch("peters_mcp.candidates.os.fsync", real_fsync):
                    self.revoke()
            return real_fsync(fd)

        with patch("peters_mcp.candidates.os.fsync", side_effect=revoke_while_staging):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        self.assertEqual(list(self.project.iterdir()), [])


class ActualResponseGateTests(_ScopeFixture, unittest.IsolatedAsyncioTestCase):
    async def test_capability_list_fences_an_unavailable_project_revoked_after_preparation(self):
        healthy = self.document["projects"]
        self.change([*healthy, {"id": "retired", "name": "Retired scope marker", "root": str(self.other)}])
        self.other.rename(self.other.with_name("offline"))
        targets = FileTargets(self.catalog)

        async def prepare(scope, receive, send):
            await receive()
            result = targets.capabilities()
            by_id = {row["project_id"]: row for row in result["projects"]}
            self.assertEqual(by_id["retired"]["worktrees"], [])
            self.assertTrue(by_id["demo"]["worktrees"])
            self.change(healthy)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": json.dumps(result).encode()})

        _, body = await post(ProjectResponseGate(prepare, self.policy),
                             {"jsonrpc": "2.0", "id": 18, "method": "tools/call"})
        self.assertIn("restart_required", body)
        self.assertNotIn("Retired scope marker", body)

    async def test_local_sdk_fences_prepared_project_data_without_an_http_request(self):
        side = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, side)])
        (self.project / 'visible.md').write_text('LOCAL_PREPARED_CONTENT')
        server = create_server(self.catalog, agent_policy=self.policy, agent_local=True)
        read = self.catalog.read_file

        def move_after_read(*args, **kwargs):
            result = read(*args, **kwargs)
            fixture_git(self.other, 'worktree', 'move', str(side), str(self.project / 'side'))
            return result

        with patch.object(self.catalog, 'read_file', move_after_read):
            async with Client(server) as client:
                result = await client.call_tool('read_file', {'project_id': 'demo', 'path': 'visible.md'})
        self.assertTrue(result.is_error)
        self.assertNotIn('LOCAL_PREPARED_CONTENT', result.content[0].text)

    async def read_while_worktree_changes(self, *, overlaps, restore=False):
        registered = self.project.parent / "registered"
        destination = (self.project if overlaps else self.project.parent) / "moved"
        row = fixture_registered_worktree(self.other, registered)
        self.change([*self.document["projects"], row])
        (self.project / "visible.md").write_text("PREPARED_PROJECT_TEXT")
        if restore:
            fixture_git(self.other, "worktree", "move", str(registered), str(destination))
            destination.rename(registered)

        async def prepared_app(scope, receive, send):
            await receive()
            result = self.catalog.read_file("demo", "visible.md")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            if restore:
                registered.rename(destination)
            else:
                fixture_git(self.other, "worktree", "move", str(registered), str(destination))
            await send({"type": "http.response.body", "body": result["text"].encode()})

        status, body = await post(ProjectResponseGate(prepared_app, self.policy),
                                  {"jsonrpc": "2.0", "id": 51, "method": "tools/call"})
        self.assertEqual(status, 200)
        return body

    async def test_newly_overlapping_external_worktree_blocks_prepared_bytes(self):
        body = await self.read_while_worktree_changes(overlaps=True)
        self.assertIn("restart_required", body)
        self.assertNotIn("PREPARED_PROJECT_TEXT", body)

    async def test_restore_of_missing_registered_worktree_checks_physical_location(self):
        body = await self.read_while_worktree_changes(overlaps=True, restore=True)
        self.assertIn("restart_required", body)
        self.assertNotIn("PREPARED_PROJECT_TEXT", body)

    async def test_unrelated_worktree_move_preserves_prepared_bytes(self):
        self.assertEqual(await self.read_while_worktree_changes(overlaps=False), "PREPARED_PROJECT_TEXT")

    async def test_new_overlap_during_real_header_send_blocks_the_body(self):
        original = self.project.parent / 'side'
        self.change([*self.document['projects'], fixture_registered_worktree(self.other, original)])
        (self.project / 'result.md').write_text('VISIBLE')
        sent = []

        async def prepared_app(scope, receive, send):
            await receive()
            result = self.catalog.read_file('demo', 'result.md')
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': result['text'].encode()})

        def observe(event):
            sent.append(event['type'])
            if event['type'] == 'http.response.start':
                fixture_git(self.other, 'worktree', 'move', str(original), str(self.project / 'side'))

        with self.assertRaises(AccessError):
            await post(ProjectResponseGate(prepared_app, self.policy),
                       {'jsonrpc': '2.0', 'id': 52, 'method': 'tools/call'}, observe=observe)
        self.assertEqual(sent, ['http.response.start'])

    async def test_prepared_body_rejected_after_revoke_and_readd(self):
        async def prepared_app(scope, receive, send):
            await receive()
            project_token(self.catalog, "demo")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            self.revoke()
            self.change(self.document["projects"])
            await send({"type": "http.response.body", "body": b"VISIBLE_PROJECT_DATA"})

        status, body = await post(ProjectResponseGate(prepared_app, self.policy),
                                  {"jsonrpc": "2.0", "id": 51, "method": "tools/call"})
        self.assertEqual(status, 200)
        self.assertNotIn("VISIBLE_PROJECT_DATA", body)
        response = json.loads(body)
        self.assertEqual(response["id"], 51)
        self.assertIn("restart_required", response["error"]["message"])

    async def test_unrelated_project_generation_does_not_discard_single_project_response(self):
        async def prepared_app(scope, receive, send):
            await receive()
            project_token(self.catalog, "demo")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            self.change([*self.document["projects"], {"id": "other", "name": "Other", "root": str(self.other)}])
            self.catalog.refresh()
            self.assertEqual(list(self.catalog.projects), ["demo"])
            await send({"type": "http.response.body", "body": b"CURRENT_PROJECT_DATA"})

        status, body = await post(ProjectResponseGate(prepared_app, self.policy),
                                  {"jsonrpc": "2.0", "id": 51, "method": "tools/call"})
        self.assertEqual(status, 200)
        self.assertEqual(body, "CURRENT_PROJECT_DATA")

    async def test_delivery_rechecks_configured_directory_identity(self):
        async def prepared_app(scope, receive, send):
            await receive()
            project_token(self.catalog, "demo")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            self.project.rename(self.project.with_name("previous-project"))
            self.project.mkdir()
            await send({"type": "http.response.body", "body": b"DISCARDED_RESULT"})

        status, body = await post(ProjectResponseGate(prepared_app, self.policy),
                                  {"jsonrpc": "2.0", "id": 63, "method": "tools/call"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["id"], 63)
        self.assertIn("restart_required", body)
        self.assertNotIn("DISCARDED_RESULT", body)

    async def test_private_state_is_held_through_asgi_delivery(self):
        control = self.project.parent / "native-control"
        control.mkdir(mode=0o700)
        registry = PrivateRootRegistry(control, allowed_roots=())
        registry.initialize()

        async def prepared_app(scope, receive, send):
            await receive()
            project_token(self.catalog, "demo")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"CURRENT_PROJECT_DATA"})

        status, body = await post(ProjectResponseGate(prepared_app, self.policy, registry),
                                  {"jsonrpc": "2.0", "id": 55, "method": "tools/call"})
        self.assertEqual(status, 200)
        self.assertEqual(body, "CURRENT_PROJECT_DATA")

    async def test_raw_task_cancellation_releases_thread_owned_lease(self):
        for stage in ("enter", "exit"):
            with self.subTest(stage=stage):
                paused = threading.Event()
                resume = threading.Event()
                released = threading.Event()

                @contextmanager
                def coordinator(*arguments, **keywords):
                    try:
                        if stage == "enter":
                            paused.set()
                            self.assertTrue(resume.wait(2))
                        yield self.policy.snapshot()
                    finally:
                        if stage == "exit":
                            paused.set()
                            self.assertTrue(resume.wait(2))
                        released.set()

                entered = False

                async def use_lease():
                    nonlocal entered
                    async with _async_reservation(self.policy, None, ()):
                        entered = True

                with patch.object(self.policy, "commit_guard", coordinator):
                    task = asyncio.create_task(use_lease())
                    try:
                        self.assertTrue(await asyncio.to_thread(paused.wait, 2))
                        task.cancel()
                        await asyncio.sleep(0)
                        self.assertFalse(task.done())
                    finally:
                        resume.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertTrue(released.is_set())
                self.assertEqual(entered, stage == "exit")

    async def test_access_auth_and_real_stateless_mcp_sdk(self):
        settings = AccessSettings("https://test.cloudflareaccess.com", "a" * 64, "test.example", ("test@test.example",))
        claims = {"iss": settings.team_domain, "sub": "verified", "exp": time.time() + 600}
        app = build_app(self.catalog, settings, agent_policy=self.policy)
        async with anyio.create_task_group() as group:
            stopping = await group.start(start, app)
            body = {"jsonrpc": "2.0", "id": 42, "method": "tools/call",
                    "params": {"name": "list_projects", "arguments": {}}}
            status, _ = await post(app, body)
            self.assertEqual(status, 401)
            with patch("peters_mcp.cloudflare.AccessVerifier.verify", return_value=claims):
                status, content = await post(app, body, [(b"cf-access-jwt-assertion", b"synthetic-test")])
            self.assertEqual(status, 200, content)
            self.assertIn("Demo", json.dumps(json.loads(content)["result"]))
            stopping.set()
