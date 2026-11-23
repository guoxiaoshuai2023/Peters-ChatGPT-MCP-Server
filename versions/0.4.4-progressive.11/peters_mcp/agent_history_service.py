"""MCP facade for the additional supervised history readers."""

from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass
import fcntl
import multiprocessing
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
import threading
import time

from .agent_history import AgentHistoryCore, build_core, verify_token
from .agent_history_policy import SOURCE
from .agent_history_source import SourceRoot, clear_snapshot_copies
from .catalog import AccessError
from .file_context import current_file_actor
from .history_process import IsolatedHistory
from .history_location import CHECKPOINT_SECONDS

_MAX_WORKERS = 2
_CHECKPOINT_BUDGET = 3.0


def _monitor_locations(store, stop, ready, interval):
    """Own the vnode watches in a supervised process, independently of the source readers."""
    parent = multiprocessing.parent_process()
    next_project, checkout_indexes = 0, {}
    try:
        while parent.is_alive():
            closing = stop.is_set()
            try:
                next_project = store.checkpoint_locations(next_project, checkout_indexes,
                    deadline=time.monotonic() + _CHECKPOINT_BUDGET, stop=None if closing else stop)
            except (AccessError, OSError):
                pass
            ready.set()
            if closing:
                break
            stop.wait(interval)
    finally:
        store.locations.close()


def _private():
    return AccessError("Agent history workspace could not be safely initialized.", code="private_protection_unavailable")


def _prepare_workspace(path):
    path.mkdir(mode=0o700, exist_ok=True)
    root = SourceRoot(path)
    with root.directory() as directory:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _private()
        descriptor = os.open(".reader-lock", os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        try:
            file_info = os.fstat(descriptor)
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                    or file_info.st_uid != os.getuid() or stat.S_IMODE(file_info.st_mode) != 0o600):
                raise _private()
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            clear_snapshot_copies(path, root.identity, include_workers=True)
            return descriptor, root.identity
        except (OSError, AccessError):
            os.close(descriptor)
            raise _private() from None


@dataclass
class Slot:
    worker: IsolatedHistory
    scratch: Path
    scratch_identity: tuple
    users: int = 0
    pending_until: float = 0
    pending_cursor: str = ""
    last_use: float = 0


class AgentHistoryService:
    def __init__(self, policy, legacy, *, local=False, audit=None):
        self.policy, self.legacy, self.local, self.audit = policy, legacy, local, audit
        self.key = secrets.token_bytes(32)
        self.local_actor = secrets.token_hex(32)
        self._lock = threading.RLock()
        self._workers = {}
        self._workspace = None
        self._closed = False
        self._checkpoint_stop = None
        self._checkpoint_process = None
        from .agent_history_aggregate import AggregateFind
        self._aggregate = AggregateFind(AgentHistoryCore(policy, legacy.catalog, legacy, self.key),
                                        self._run, self._abandon)

    def start(self, *, monitor_locations=False):
        with self._lock:
            if self._closed:
                raise _private()
            if self._workspace is None and self.policy.path is not None:
                try:
                    self._workspace, self.policy.scratch_identity = _prepare_workspace(self.policy.scratch)
                except OSError:
                    raise _private() from None
            if monitor_locations and self.policy.mode == "v2" and self._checkpoint_process is None:
                context = multiprocessing.get_context("spawn")
                self._checkpoint_stop, ready = context.Event(), context.Event()
                process = context.Process(target=_monitor_locations, args=(self.policy.store,
                    self._checkpoint_stop, ready, CHECKPOINT_SECONDS), name="project-history-locations", daemon=True)
                process.start()
                self._checkpoint_process = process
                if not ready.wait(_CHECKPOINT_BUDGET + 3):
                    self._stop_monitor()
                    raise AccessError("The project location observer could not start.", code="history_observer_unavailable")

    def _stop_monitor(self):
        process = self._checkpoint_process
        if process is None:
            return
        self._checkpoint_stop.set()
        process.join(_CHECKPOINT_BUDGET * 2 + 1)
        forced = process.is_alive()
        if forced:
            process.terminate()
            process.join(0.5)
        if process.is_alive():
            process.kill()
            process.join(0.5)
        if process.is_alive():
            raise AccessError("Project location observer shutdown is pending.", code="history_observer_shutdown_pending")
        status = process.exitcode
        process.close()
        self._checkpoint_process = self._checkpoint_stop = None
        if forced or status != 0:
            raise AccessError("The last project location checkpoint did not finish.", code="history_checkpoint_incomplete")

    def caller(self):
        if self.local:
            return {"actor": self.local_actor, "policy_actor": "local"}
        actor = current_file_actor()
        return {"actor": actor, "policy_actor": actor}

    @contextmanager
    def worker(self, route, cursor):
        with self._lock:
            if self._closed:
                raise _private()
            slot = self._workers.get(route)
            if slot is None and not cursor:
                if len(self._workers) == _MAX_WORKERS:
                    now = time.monotonic()
                    idle = [(key, value) for key, value in self._workers.items()
                            if value.users == 0 and value.pending_until <= now]
                    if idle:
                        evicted, _ = min(idle, key=lambda item: item[1].last_use)
                        # Terminate the evicted child before admitting a new one.
                        self._close_slot(self._workers.pop(evicted))
                if len(self._workers) < _MAX_WORKERS:
                    self.start()
                    worker_policy = self._worker_policy()
                    reader = IsolatedHistory(self.legacy, _factory=build_core,
                        _spec_extra={"agent_policy": worker_policy, "agent_key": self.key}, _max_tasks=1)
                    if self.audit is not None:
                        reader.set_diagnostic_sink(self._diagnostic_sink(route))
                    slot = Slot(reader, worker_policy.scratch, worker_policy.scratch_identity)
                    self._workers[route] = slot
            if slot is not None:
                slot.users += 1
        try:
            yield slot
        finally:
            if slot is not None:
                with self._lock:
                    slot.users -= 1
                    slot.last_use = time.monotonic()

    def _worker_policy(self):
        SourceRoot(self.policy.scratch, expected_identity=self.policy.scratch_identity)
        try:
            scratch = Path(tempfile.mkdtemp(prefix="worker-", dir=self.policy.scratch))
        except OSError:
            raise _private() from None
        policy = copy(self.policy)
        policy.scratch = scratch
        policy.scratch_identity = SourceRoot(scratch).identity
        return policy

    def _close_slot(self, slot):
        slot.worker.close()
        try:
            SourceRoot(slot.scratch, expected_identity=slot.scratch_identity)
            shutil.rmtree(slot.scratch)
        except (OSError, AccessError):
            # Startup cleanup retries any abandoned service-owned copies.
            pass

    def _abandon(self, route, cursor):
        with self._lock:
            slot = self._workers.get(route)
            if slot is not None and slot.users == 0 and slot.pending_cursor == cursor:
                self._close_slot(self._workers.pop(route))

    def _diagnostic_sink(self, route):
        import json
        return lambda event: self.audit.info(json.dumps({"component": "agent_history_worker",
                                                          "source": route, **event}, ensure_ascii=True))

    def _run(self, route, operation, cursor, arguments):
        with self.worker(route, cursor) as slot:
            if slot is None:
                return {"status": "restart_required" if cursor else "busy", "coverage_complete": False}
            response = slot.worker._call(operation, {**arguments, "cursor": cursor})
            with self._lock:
                if response["status"] in {"processing", "waiting_source_stable"}:
                    slot.pending_until = time.monotonic() + 20
                    slot.pending_cursor = response.get("next_cursor") or ""
                elif response["status"] != "busy" and (not slot.pending_cursor or slot.pending_cursor == cursor):
                    slot.pending_until = 0
                    slot.pending_cursor = ""
            return response

    def find_agent_threads(self, project_id, query="", agent="", source_id="", cursor="", limit=10):
        if source_id and not SOURCE.fullmatch(source_id):
            raise AccessError("Invalid source filter.", code="invalid_arguments")
        caller = self.caller()
        if source_id and source_id != "codex" and source_id not in self.policy.fixed:
            raise AccessError("The requested history is not authorized.", code="unauthorized")
        if not source_id:
            return self._aggregate.find(project_id, query, agent, cursor, limit, caller)
        return self._run(source_id, "find_agent_threads", cursor,
                         {"project_id": project_id, "query": query, "agent": agent, "source_id": source_id,
                          "limit": limit, **caller})

    def read_agent_thread(self, thread_ref, cursor="", view="all", turn_id="", limit=20, max_chars=16000):
        caller = self.caller()
        reference = verify_token(self.key, thread_ref, "thread")
        if reference["actor"] != caller["actor"]:
            raise AccessError("The requested history is not authorized.", code="unauthorized")
        return self._run(reference["source"], "read_agent_thread", cursor,
                         {"thread_ref": thread_ref, "view": view, "turn_id": turn_id, "limit": limit,
                          "max_chars": max_chars, **caller})

    def close(self):
        with self._lock:
            if self._closed:
                self._stop_monitor()
                return
            self._closed = True
            if self._checkpoint_stop is not None:
                self._checkpoint_stop.set()
            for slot in self._workers.values():
                self._close_slot(slot)
            self._workers.clear()
            if self._workspace is not None:
                os.close(self._workspace)
                self._workspace = None
            self._stop_monitor()
