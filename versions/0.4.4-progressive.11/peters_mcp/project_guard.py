"""Unified project capabilities pinned from tool preparation to actual delivery."""

import asyncio
from contextlib import asynccontextmanager, contextmanager, ExitStack, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
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
_page_aliases = ContextVar("peters_history_page_aliases", default=None)


@dataclass
class _Request:
    policy: object
    snapshot: tuple
    registry: object = None
    protection: bytes | None = None
    roots: dict = field(default_factory=dict)
    topology: object = None
    first_fingerprints: dict = field(default_factory=dict)
    changed_projects: set = field(default_factory=set)
    tokens: dict = field(default_factory=dict)
    aliases: set = field(default_factory=set)
    catalogs: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.Lock)
    generation_wide: bool = False
    all_projects: bool = False


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


def require_request_epoch(catalog, *, all_projects=False):
    request = _request.get()
    if request is not None and request.policy is _policy(catalog):
        with request.lock:
            request.generation_wide = True
            request.all_projects |= all_projects


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


def note_discovery(policy, receipt):
    request = _request.get()
    if request is None or request.policy is not policy:
        return
    with request.lock:
        previous = request.topology
        if previous is not None:
            previous.require_complete()
        # Keep an incomplete observation even if the tool catches its error. A
        # later healthy discovery cannot establish what was known at selection.
        request.topology = receipt
        receipt.require_complete()
        fingerprints = dict(receipt.fingerprints)
        if previous is None:
            request.first_fingerprints = fingerprints
        else:
            request.changed_projects.update(pid for pid in request.first_fingerprints.keys() | fingerprints.keys()
                                            if fingerprints.get(pid) != request.first_fingerprints.get(pid))


def _request_topology(request, projects):
    if request is None:
        return None
    with request.lock:
        if request.topology is None:
            return None
        request.topology.require_complete()
        selected = {pid for pid, _ in projects}
        whole = request.all_projects or not selected
        if request.changed_projects and (whole or selected.intersection(request.changed_projects)):
            raise _revoked()
        return request.topology, None if whole else selected


def _same_selection(old, new, selected):
    if selected is None:
        return old.fingerprints == new.fingerprints
    before, after = dict(old.fingerprints), dict(new.fingerprints)
    return all(pid in before and before[pid] == after.get(pid) for pid in selected)


class WorkspaceChanged(AccessError):
    """Physical evidence changed inside a reservation; fresh discovery requires leaving it."""
    def __init__(self):
        super().__init__("Workspace membership changed. Repeat validation.", code="scope_changed")


def verify_committed_topology():
    held = _commit.get()
    if held is not None:
        _, snapshot, receipts, deadline = held
        if any(not receipt.current(snapshot, deadline) for receipt in receipts):
            raise WorkspaceChanged()


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


def _verify_history_aliases(snapshot, witnesses):
    """Resolve private worker fingerprints only against this origin's policy."""
    if not witnesses:
        return
    from .agent_history import _digest
    from .agent_history_policy import migration_location_current

    pending = set(witnesses)
    for source in snapshot[0]["sources"].values():
        if not source["enabled"]:
            continue
        for alias in source.get("path_aliases", ()):
            key = (alias["project_id"], _digest(alias))
            if key not in pending or alias["source_instance"] != source["instance_id"]:
                continue
            if not migration_location_current(alias):
                raise _revoked()
            pending.remove(key)
    if pending:
        raise _revoked()


def retain_history_aliases(policy, witnesses):
    if not witnesses:
        return
    collecting = _page_aliases.get()
    if collecting is not None and collecting[0] is policy:
        collecting[1].update(witnesses)
        return
    request = _request.get()
    if request is not None and request.policy is policy:
        with request.lock:
            request.aliases.update(witnesses)


@contextmanager
def collect_page_aliases(policy):
    witnesses = set()
    marker = _page_aliases.set((policy, witnesses))
    try:
        yield witnesses
    finally:
        _page_aliases.reset(marker)


def verify_worker_aliases(catalog, project_id, fingerprints):
    if (not isinstance(fingerprints, list) or len(fingerprints) > 1024 or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in fingerprints)):
        raise _revoked()
    if not fingerprints:
        return
    policy = _policy(catalog)
    witnesses = {(project_id, value) for value in fingerprints}
    _verify_history_aliases(policy.snapshot(), witnesses)
    retain_history_aliases(policy, witnesses)


@contextmanager
def _reservation(policy, digest, projects, deadline, *, request=None, roots=(), bindings=(), private_registry=None):
    from .catalog import Catalog
    from .workspaces import discovery_deadline

    registry = request.registry if request is not None else None
    receipts = tuple(receipt for receipt, _ in bindings)
    for receipt in receipts:
        receipt.require_complete()
    while True:
        with ExitStack() as stack:
            if private_registry is not None:
                stack.enter_context(private_registry.read_guard(deadline=deadline))
            elif registry is not None:
                stack.enter_context(registry.delivery_guard(request.protection, deadline=deadline))
            snapshot = stack.enter_context(policy.commit_guard(digest, deadline=deadline))
            for project_id, token in projects:
                if not isinstance(token, str) or policy.project_token(project_id, snapshot) != token:
                    raise _revoked()
            try:
                current = all(receipt.current(snapshot, deadline) for receipt in receipts)
                if current and request is not None:
                    _verify_roots(snapshot, projects, roots)
                    with request.lock:
                        aliases = tuple(request.aliases)
                    _verify_history_aliases(snapshot, aliases)
            except OSError:
                raise _revoked() from None
            if time.monotonic() >= deadline:
                raise AccessError("Project authorization commit expired.", code="commit_busy")
            if current:
                yield policy, snapshot, receipts, deadline
                return
        # Full Git discovery never occupies a policy or private transport reservation.
        # Use the live policy snapshot read under the preceding lock, not the request's pinned catalog.
        with discovery_deadline(deadline):
            registry_view = Catalog.from_policy(policy, snapshot=snapshot)._view.repositories
            refreshed = registry_view.discover_all(observe=False).topology
        if not refreshed.complete or not all(_same_selection(old, refreshed, ids) for old, ids in bindings):
            raise _revoked()
        receipts = (refreshed,)


@contextmanager
def commit_project(catalog, project_id, expected_token, *, deadline=None, topology=None, private_registry=None):
    policy = _policy(catalog)
    if policy is None:
        with private_registry.read_guard() if private_registry is not None else nullcontext():
            yield
        return
    note_project(catalog, project_id, expected_token)
    deadline = min(deadline, time.monotonic() + _COMMIT_SECONDS) if deadline is not None else (
        time.monotonic() + _COMMIT_SECONDS)
    request = _request.get()
    projects = ((project_id, expected_token),)
    local = _request_topology(request, projects) if request is not None and request.policy is policy else None
    supplied = (topology, {project_id}) if topology is not None else None
    with _reservation(policy, None, projects, deadline, bindings=tuple(b for b in (local, supplied) if b),
                      private_registry=private_registry) as held:
        marker = _commit.set(held)
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
async def _async_reservation(policy, digest, projects, deadline=None, *, request=None, roots=(), bindings=()):
    bound = time.monotonic() + _COMMIT_SECONDS
    deadline = min(bound, deadline) if deadline is not None else bound
    if not _slots.acquire(blocking=False):
        raise AccessError("Project authorization commit is busy.", code="commit_busy")
    manager = _reservation(policy, digest, projects, deadline, request=request, roots=roots, bindings=bindings)
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
async def async_commit_project(catalog, project_id, expected_token, *, deadline=None, topology=None):
    """Reserve one actual export send. Only this in-process scope bypasses JSON gating."""
    policy = _policy(catalog)
    if policy is None:
        yield
        return
    note_project(catalog, project_id, expected_token)
    request = _request.get()
    if request is not None and request.policy is not policy:
        request = None
    projects = ((project_id, expected_token),)
    local = _request_topology(request, projects)
    supplied = (topology, {project_id}) if topology is not None else None
    async with _async_reservation(policy, None, projects, deadline, request=request,
                                  bindings=tuple(b for b in (local, supplied) if b)) as held:
        boundary = _commit.set(held)
        marker = _resource_send.set(policy)
        try:
            yield
        finally:
            _resource_send.reset(marker)
            _commit.reset(boundary)


def _begin_request(policy, registry):
    snapshot = policy.snapshot()
    barrier = registry.delivery_guard() if registry is not None else nullcontext()
    with barrier as digest:
        return _Request(policy, snapshot, registry, digest)


def _delivery_scope(request):
    with request.lock:
        projects = tuple(request.tokens.items())
        digest = request.snapshot[1] if request.generation_wide or not projects else None
        roots = tuple(request.roots.items())
    binding = _request_topology(request, projects)
    return digest, projects, roots, (binding,) if binding else ()


@contextmanager
def bind_project_request(request):
    """The SDK captures this context when the transport submits the request."""
    marker = _request.set(request)
    try:
        yield
    finally:
        _request.reset(marker)


@asynccontextmanager
async def stdio_delivery(policy, deadline):
    request = _request.get()
    if request is None or request.policy is not policy:
        raise _revoked()
    digest, projects, roots, bindings = _delivery_scope(request)
    async with _async_reservation(policy, digest, projects, deadline, request=request, roots=roots, bindings=bindings):
        yield


@contextmanager
def local_tool_scope(catalog):
    """Fence a trusted local SDK call when no authenticated HTTP gate owns it."""
    policy = _policy(catalog)
    if policy is None or has_operation_scope(policy):
        yield
        return
    request = _begin_request(policy, catalog._private_registry)
    with bind_project_request(request):
        yield
        digest, projects, roots, bindings = _delivery_scope(request)
        with _reservation(policy, digest, projects, time.monotonic() + _COMMIT_SECONDS,
                          request=request, roots=roots, bindings=bindings):
            pass


class ProjectResponseGate:
    """Fence actual JSON response delivery, after authentication and SDK preparation."""

    def __init__(self, app, policy, registry=None):
        self.app = app
        self.policy = policy
        self.registry = registry

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope["method"] != "POST" or
                scope["path"].rstrip("/") != "/mcp"):
            await self.app(scope, receive, send)
            return
        try:
            request = await anyio.to_thread.run_sync(_begin_request, self.policy, self.registry)
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
            try:
                digest, projects, roots, bindings = _delivery_scope(request)
                deadline = time.monotonic() + _COMMIT_SECONDS
                # A suspended header send gives external filesystem changes time to occur.
                # Reserve/check the actual body separately, using the same total deadline.
                for frame in (headers, event):
                    async with _async_reservation(self.policy, digest, projects, deadline, request=request,
                                                  roots=roots, bindings=bindings):
                        started = True
                        await send(frame)
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
