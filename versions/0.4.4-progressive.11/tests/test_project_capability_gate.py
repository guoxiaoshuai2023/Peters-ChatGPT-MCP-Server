"""An actual ASGI response and confirmed candidate publication use the live project epoch."""

import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import anyio

from peters_mcp.agent_history_admin import compile_generation, write_descriptor
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.candidates import CandidateDelivery, publish_exclusive
from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.file_context import verified_file_actor
from peters_mcp.project_guard import ProjectResponseGate, _async_reservation, project_token
from peters_mcp.private_roots import PrivateRootRegistry


async def post(app, body, headers=()):
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
