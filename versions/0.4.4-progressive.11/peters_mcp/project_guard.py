"""Unified project capabilities pinned from tool preparation to actual delivery."""

import asyncio
from contextlib import asynccontextmanager, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import threading
import time

import anyio
from starlette.responses import JSONResponse

from .catalog import AccessError


_COMMIT_SECONDS = 4.0
_MAX_BODY = 262144
_slots = threading.BoundedSemaphore(16)
_enter_limit = anyio.CapacityLimiter(8)
_exit_limit = anyio.CapacityLimiter(8)
_request = ContextVar("peters_project_request", default=None)
_commit = ContextVar("peters_project_commit", default=None)
_resource_send = ContextVar("peters_project_resource_send", default=None)


@dataclass
class _Request:
    policy: object
    snapshot: tuple
    registry: object = None
    protection: bytes | None = None
    roots: dict = field(default_factory=dict)
    registrations: dict = field(default_factory=dict)
    absent_roots: set = field(default_factory=set)
    tokens: dict = field(default_factory=dict)
    catalogs: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.Lock)
    generation_wide: bool = False


def _policy(catalog):
    return getattr(catalog, "unified_policy", None)


def snapshot_for(policy):
    held = _commit.get()
    if held is not None and held[0] is policy:
        return held[1]
    request = _request.get()
    if request is not None and request.policy is policy:
        return request.snapshot
    return None


def has_operation_scope(policy):
    return snapshot_for(policy) is not None


def catalog_view(catalog, snapshot, factory):
    request = _request.get()
    if request is None or request.policy is not _policy(catalog):
        return factory() if has_operation_scope(_policy(catalog)) else None
    key = (catalog, snapshot[1])
    with request.lock:
        cached = request.catalogs.get(key)
    if cached is None:
        prepared = factory()
        with request.lock:
            cached = request.catalogs.setdefault(key, prepared)
    return cached


def _revoked():
    return AccessError("The project authorization changed. Start a new request.", code="scope_revoked")


def note_project(catalog, project_id, token):
    policy = _policy(catalog)
    if policy is None:
        return
    request = _request.get()
    if request is not None and request.policy is policy:
        if policy.project_token(project_id, request.snapshot) != token:
            raise _revoked()
        with request.lock:
            if request.tokens.setdefault(project_id, token) != token:
                raise _revoked()


def require_request_epoch(catalog):
    request = _request.get()
    if request is not None and request.policy is _policy(catalog):
        with request.lock:
            request.generation_wide = True


def project_token(catalog, project_id):
    policy = _policy(catalog)
    if policy is None:
        return None
    token = policy.project_token(project_id, snapshot_for(policy))
    note_project(catalog, project_id, token)
    return token


def note_worktree(catalog, project_id, member):
    """Record the exact root already selected by verified discovery."""
    request = _request.get()
    if request is None or request.policy is not _policy(catalog) or member["state"] != "valid":
        return
    project_token(catalog, project_id)
    root = Path(member["root"])
    identity = tuple(member["root_identity"])
    pin = member["repository_id"]
    proof = None
    if pin is not None:
        from .workspaces import repository_probe
        proof = repository_probe(root)
        if (proof["root"] != root or proof["repository_id"] != pin
                or tuple(proof["root_runtime_identity"]) != identity):
            raise _revoked()
    with request.lock:
        key = (project_id, root)
        facts = (identity, proof)
        if request.roots.setdefault(key, facts) != facts:
            raise _revoked()


def note_registration(policy, common, stamp):
    request = _request.get()
    if request is not None and request.policy is policy:
        with request.lock:
            if request.registrations.setdefault(common, stamp) != stamp:
                raise _revoked()


def note_missing_root(policy, root):
    request = _request.get()
    if request is not None and request.policy is policy:
        with request.lock:
            request.absent_roots.add(root)


def _verify_registration(registrations, absent_roots):
    from .workspaces import registration_stamp

    for common, stamp in registrations:
        if registration_stamp(common) != stamp:
            raise _revoked()
    for root in absent_roots:
        try:
            root.lstat()
        except FileNotFoundError:
            continue
        raise _revoked()


def _registration_receipt(request):
    if request is None:
        return (), ()
    with request.lock:
        return tuple(request.registrations.items()), tuple(request.absent_roots)


def _verify_roots(snapshot, projects, roots):
    from .fs_identity import persistent_identity
    from .workspaces import _open_path, revalidate_repository_probe

    if projects:
        definitions = {item["id"]: item["root"] for item in snapshot[0]["projects"]}
        for project_id, _ in projects:
            if persistent_identity(Path(definitions[project_id])) != snapshot.project_identities[project_id]:
                raise _revoked()
    for (_, root), (identity, proof) in roots:
        if proof is not None:
            revalidate_repository_probe(proof)
        else:
            fd, info = _open_path(root, directory=True)
            try:
                if (info.st_dev, info.st_ino) != identity:
                    raise _revoked()
            finally:
                os.close(fd)


@contextmanager
def _reservation(policy, digest, projects, deadline, *, request=None, roots=(), registration_receipt=None):
    registry = request.registry if request is not None else None
    protection = registry.delivery_guard(request.protection, deadline=deadline) if registry is not None else nullcontext()
    with protection, policy.commit_guard(digest, deadline=deadline) as snapshot:
        for project_id, token in projects:
            if not isinstance(token, str) or policy.project_token(project_id, snapshot) != token:
                raise _revoked()
        try:
            if registration_receipt is not None:
                _verify_registration(*registration_receipt)
            if request is not None:
                _verify_roots(snapshot, projects, roots)
        except OSError:
            raise _revoked() from None
        if time.monotonic() >= deadline:
            raise AccessError("Project authorization commit expired.", code="commit_busy")
        yield snapshot


@contextmanager
def commit_project(catalog, project_id, expected_token, *, deadline=None):
    policy = _policy(catalog)
    if policy is None:
        yield
        return
    note_project(catalog, project_id, expected_token)
    deadline = min(deadline, time.monotonic() + _COMMIT_SECONDS) if deadline is not None else (
        time.monotonic() + _COMMIT_SECONDS)
    request = _request.get()
    receipts = _registration_receipt(request) if request is not None and request.policy is policy else None
    with _reservation(policy, None, ((project_id, expected_token),), deadline,
                      registration_receipt=receipts) as snapshot:
        marker = _commit.set((policy, snapshot))
        try:
            yield
        finally:
            _commit.reset(marker)


async def _complete_thread_call(function, *arguments, limiter):
    """Pair each synchronous lease operation even if the ASGI task is cancelled."""
    cancellation = None
    with anyio.CancelScope(shield=True):
        operation = asyncio.create_task(anyio.to_thread.run_sync(function, *arguments, limiter=limiter))
        while True:
            try:
                return await asyncio.shield(operation), cancellation
            except asyncio.CancelledError as error:
                if operation.cancelled():
                    raise
                if cancellation is None:
                    cancellation = error


@asynccontextmanager
async def _async_reservation(policy, digest, projects, deadline=None, *, request=None, roots=(), registration_receipt=None):
    bound = time.monotonic() + _COMMIT_SECONDS
    deadline = min(bound, deadline) if deadline is not None else bound
    if not _slots.acquire(blocking=False):
        raise AccessError("Project authorization commit is busy.", code="commit_busy")
    manager = _reservation(policy, digest, projects, deadline, request=request, roots=roots,
                           registration_receipt=registration_receipt)
    try:
        snapshot, cancellation = await _complete_thread_call(manager.__enter__, limiter=_enter_limit)
        try:
            if cancellation is not None:
                raise cancellation
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            with anyio.fail_after(remaining):
                yield snapshot
        finally:
            _, cancellation = await _complete_thread_call(manager.__exit__, None, None, None, limiter=_exit_limit)
            if cancellation is not None:
                raise cancellation
    finally:
        _slots.release()


@asynccontextmanager
async def async_commit_project(catalog, project_id, expected_token, *, deadline=None):
    """Reserve one actual export send. Only this in-process scope bypasses JSON gating."""
    policy = _policy(catalog)
    if policy is None:
        yield
        return
    note_project(catalog, project_id, expected_token)
    request = _request.get()
    if request is not None and request.policy is not policy:
        request = None
    async with _async_reservation(policy, None, ((project_id, expected_token),), deadline,
                                  request=request, registration_receipt=_registration_receipt(request)) as snapshot:
        boundary = _commit.set((policy, snapshot))
        marker = _resource_send.set(policy)
        try:
            yield
        finally:
            _resource_send.reset(marker)
            _commit.reset(boundary)


class ProjectResponseGate:
    """Fence actual JSON response delivery, after authentication and SDK preparation."""

    def __init__(self, app, policy, registry=None):
        self.app = app
        self.policy = policy
        self.registry = registry

    def _request_context(self):
        snapshot = self.policy.snapshot()
        barrier = self.registry.delivery_guard() if self.registry is not None else nullcontext()
        with barrier as digest:
            return _Request(self.policy, snapshot, self.registry, digest)

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope["method"] != "POST" or
                scope["path"].rstrip("/") != "/mcp"):
            await self.app(scope, receive, send)
            return
        try:
            request = await anyio.to_thread.run_sync(self._request_context)
        except (AccessError, TimeoutError):
            await JSONResponse({"error": "Project policy unavailable."}, status_code=503,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
            return
        marker = _request.set(request)
        headers = None
        started = False
        request_bytes = bytearray()
        request_too_large = False

        async def observed_receive():
            nonlocal request_too_large
            event = await receive()
            if event["type"] == "http.request" and not request_too_large:
                body = event.get("body", b"")
                if len(request_bytes) + len(body) > _MAX_BODY:
                    request_too_large = True
                    request_bytes.clear()
                else:
                    request_bytes.extend(body)
            return event

        async def reject_delivery():
            nonlocal started
            try:
                value = json.loads(request_bytes) if not request_too_large else None
                identifier = value.get("id") if isinstance(value, dict) else None
            except (ValueError, RecursionError):
                identifier = None
            if type(identifier) in (int, str):
                result = {"jsonrpc": "2.0", "id": identifier, "error": {
                    "code": -32000, "message": "[restart_required] Project policy changed or delivery expired."}}
                status = 200
            else:
                result = {"error": "Project delivery unavailable."}
                status = 409
            started = True
            await JSONResponse(result, status_code=status, headers={"Cache-Control": "no-store"})(
                scope, receive, send)

        async def guarded_send(event):
            nonlocal headers, started
            if _resource_send.get() is self.policy:
                if event["type"] == "http.response.start":
                    started = True
                await send(event)
                return
            if event["type"] == "http.response.start":
                if started:
                    raise _revoked()
                headers = event
                return
            if event["type"] != "http.response.body" or headers is None or event.get("more_body") or started:
                raise _revoked()
            with request.lock:
                projects = tuple(request.tokens.items())
                digest = request.snapshot[1] if request.generation_wide or not projects else None
                roots = tuple(request.roots.items())
                registration_receipt = (tuple(request.registrations.items()), tuple(request.absent_roots))
            try:
                async with _async_reservation(self.policy, digest, projects, request=request, roots=roots,
                                              registration_receipt=registration_receipt):
                    started = True
                    await send(headers)
                    await send(event)
            except (AccessError, TimeoutError):
                if started:
                    raise
                await reject_delivery()

        try:
            await self.app(scope, observed_receive, guarded_send)
        except (AccessError, TimeoutError):
            if started:
                raise
            await reject_delivery()
        finally:
            _request.reset(marker)
