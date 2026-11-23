"""Merge authorized search summaries while keeping source scans independently supervised."""

from collections import deque
from dataclasses import dataclass, field
import json
import re
import secrets
import threading
import time

from .agent_history import ERROR_CODES, VERSION, _restart, coverage_status, unified
from .agent_history_policy import AGENT, IDENTIFIER
from .catalog import AccessError, integer
from .project_guard import collect_page_aliases, retain_history_aliases

_MAX_SEARCHES = 12
_MAX_AGE = 300
_MAX_ATTEMPTS = 6
_MAX_SOURCE_ROWS = 64
_CONTINUATION = frozenset({"processing", "busy", "waiting_source_stable"})
_RESTART = frozenset({"unauthorized", "agent_policy_invalid", "private_protection_unavailable"})
_FAILURES = ERROR_CODES | {"restart_required", "snapshot_expired", "busy", "source_changed"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SUMMARY_FIELDS = (
    "source_id", "agent", "surface", "stable_thread_id", "title", "updated_at",
    "project_id", "thread_ref", "source_adapter",
)


@dataclass
class _Task:
    source: str
    vouchers: str = ""
    cursor: str = ""
    attempts: int = 0
    validated: bool = False


@dataclass(frozen=True)
class _Hit:
    summary: dict
    canonical: str
    primary: bool
    vouchers: tuple


@dataclass
class _Search:
    key: str
    sources: tuple
    scans: deque
    started: float = field(default_factory=time.monotonic)
    lock: object = field(default_factory=threading.Lock, repr=False)
    sequence: int = 0
    hits: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    ordered: list | None = None
    offset: int = 0
    validation: tuple | None = None


def _malformed():
    return AccessError("The history worker returned an invalid summary.", code="history_processing_failed")


def _digest(value):
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _hit(value, source, project_id):
    if not isinstance(value, dict) or not _digest(value.get("canonical")) or type(value.get("primary")) is not bool:
        raise _malformed()
    summary = value.get("summary")
    if (not isinstance(summary, dict) or summary.get("source_id") != source
            or summary.get("project_id") != project_id
            or any(not isinstance(summary.get(key), str) for key in _SUMMARY_FIELDS)):
        raise _malformed()
    summary = {key: summary[key] for key in _SUMMARY_FIELDS} | {"match": _match(summary.get("match"))}
    if "source_instance" in value["summary"]:
        instance = value["summary"]["source_instance"]
        if not isinstance(instance, str) or not IDENTIFIER.fullmatch(instance):
            raise _malformed()
        summary["source_instance"] = instance
    vouchers = value.get("vouchers")
    if not isinstance(vouchers, list) or len(vouchers) != 1:
        raise _malformed()
    for voucher in vouchers:
        if (not isinstance(voucher, list) or len(voucher) != 3 or voucher[0] != source
                or not isinstance(voucher[1], str) or not IDENTIFIER.fullmatch(voucher[1])
                or not _digest(voucher[2])):
            raise _malformed()
    return _Hit(summary, value["canonical"], value["primary"], tuple(map(tuple, vouchers)))


def _match(value):
    kind = value.get("in") if isinstance(value, dict) else None
    if not isinstance(kind, str) or kind not in {"title", "project", "visible_message"}:
        raise _malformed()
    if kind != "visible_message":
        return {"in": kind}
    if (not isinstance(value.get("message_id"), str) or len(value["message_id"]) > 64
            or not _digest(value.get("snapshot_sha256"))):
        raise _malformed()
    return {key: value[key] for key in ("in", "message_id", "snapshot_sha256")}


def _failure(source, code):
    code = code if code in _FAILURES else "history_processing_failed"
    return {"source_id": source, "coverage_complete": False, "warnings": [code]}


def _coverage(value, source):
    if (not isinstance(value, dict) or value.get("source_id") != source or type(value.get("coverage_complete")) is not bool
            or not isinstance(value.get("warnings"), list) or len(value["warnings"]) > len(_FAILURES)
            or any(not isinstance(warning, str) or warning not in _FAILURES for warning in value["warnings"])):
        raise _malformed()
    result = {"source_id": source, "coverage_complete": value["coverage_complete"],
              "warnings": sorted(set(value["warnings"]))}
    if "state" in value:
        if value["state"] != coverage_status(result["warnings"]):
            raise _malformed()
        result["state"] = value["state"]
    return result


def _merge(groups):
    matches = {}
    for hits in groups.values():
        for hit in hits:
            matches.setdefault(hit.canonical, []).append(hit)
    rows = []
    for same in matches.values():
        best = min(same, key=lambda hit: (not hit.primary, hit.summary["source_id"], hit.summary["stable_thread_id"]))
        sources = sorted({hit.summary["source_id"] for hit in same})
        vouchers = tuple(sorted({voucher for hit in same for voucher in hit.vouchers}))
        rows.append(({**best.summary, "matched_sources": sources}, vouchers))
    rows.sort(key=lambda item: (item[0]["updated_at"], item[0]["stable_thread_id"]), reverse=True)
    return rows


def _validation_tasks(page):
    grouped = {}
    for _, vouchers in page:
        for source, native_id, proof in vouchers:
            grouped.setdefault(source, set()).add((source, native_id, proof))
    tasks = []
    for source, group in sorted(grouped.items()):
        payload = json.dumps(sorted(group), ensure_ascii=False, separators=(",", ":"))
        tasks.append(_Task(source, vouchers=payload))
    return tuple(tasks)


class AggregateFind:
    def __init__(self, core, run, abandon=None):
        self._core = core
        self._run = run
        self._abandon = abandon
        self._searches = {}
        self._lock = threading.Lock()
        self._scope_lock = threading.Lock()

    def _configuration(self, project_id, caller):
        with self._scope_lock:
            return self._core._configuration(project_id, **caller)

    def _claim(self, scope, params, cursor):
        token = self._core._resume(cursor, "aggregate", scope, params) if cursor else None
        with self._lock:
            now = time.monotonic()
            for key, state in tuple(self._searches.items()):
                if now - state.started > _MAX_AGE and not state.lock.locked():
                    del self._searches[key]
            if token is not None:
                state = self._searches.get(token["key"])
                if state is None or now - state.started > _MAX_AGE:
                    raise _restart()
                if not state.lock.acquire(blocking=False):
                    return None
                if token["sequence"] != state.sequence:
                    state.lock.release()
                    raise _restart()
                return state
            if len(self._searches) == _MAX_SEARCHES:
                evict = next((item for item in self._searches.values() if not item.lock.locked()), None)
                if evict is None:
                    return None
                del self._searches[evict.key]
            sources = tuple(self._core._sources(scope, "", params[2].casefold()))
            state = _Search(secrets.token_hex(16), sources, deque(_Task(source) for source in sources))
            state.lock.acquire()
            self._searches[state.key] = state
            return state

    def _discard(self, state):
        with self._lock:
            self._searches.pop(state.key, None)

    def _cursor(self, state, scope, params):
        state.sequence += 1
        return self._core._token(scope, "aggregate", key=state.key, sequence=state.sequence, parameters=params)

    def _continuation(self, state, scope, params):
        return {"status": "processing", "coverage_complete": False,
                "next_cursor": self._cursor(state, scope, params),
                "continue_with": "Keep the same search parameters and use next_cursor."}

    def _response(self, task, operation, arguments):
        try:
            value = self._run(task.source, operation, task.cursor, arguments)
        except AccessError as error:
            if error.code in _RESTART or (operation == "validate_agent_hits" and error.code == "restart_required"):
                raise _restart() from None
            return {"status": error.code}
        except TimeoutError:
            return {"status": "processing_timeout"}
        except OSError:
            return {"status": "source_unavailable"}
        if not isinstance(value, dict) or not isinstance(value.get("status"), str):
            return {"status": "history_processing_failed"}
        return value

    @staticmethod
    def _retry(task, response):
        if response["status"] not in _CONTINUATION or task.attempts >= _MAX_ATTEMPTS:
            return False
        cursor = response.get("next_cursor")
        if isinstance(cursor, str) and 0 < len(cursor) <= 4096:
            task.cursor = cursor
            return True
        return response["status"] == "busy"

    def _release(self, task, response):
        cursor = response.get("next_cursor") or task.cursor
        if self._abandon is not None and isinstance(cursor, str) and cursor:
            self._abandon(task.source, cursor)

    def _scan(self, state, project_id, query, agent, caller):
        task = state.scans.popleft()
        task.attempts += 1
        arguments = {"project_id": project_id, "query": query, "agent": agent,
                     "source_id": task.source, **caller}
        response = self._response(task, "scan_agent_source", arguments)
        status = response["status"]
        if status == "ready":
            try:
                rows = response.get("rows")
                if not isinstance(rows, list) or len(rows) > _MAX_SOURCE_ROWS:
                    raise _malformed()
                parsed = tuple(_hit(row, task.source, project_id) for row in rows)
                state.coverage[task.source] = _coverage(response.get("coverage"), task.source)
                state.hits[task.source] = parsed
            except AccessError as error:
                state.coverage[task.source] = _failure(task.source, error.code)
        elif self._retry(task, response):
            state.scans.append(task)
        else:
            self._release(task, response)
            code = "processing_timeout" if status == "processing" else status
            state.coverage[task.source] = _failure(task.source, code)

    def _validate(self, state, project_id, caller):
        # Every displayed source must attest within the call that returns the
        # page. A previous success may have gone stale while another source
        # was processing, so the task is retained and run again on each call.
        for task in state.validation:
            arguments = {"project_id": project_id, "source_id": task.source,
                         "vouchers": task.vouchers, **caller}
            response = self._response(task, "validate_agent_hits", arguments)
            if (task.validated and task.cursor
                    and response["status"] in {"restart_required", "snapshot_expired"}):
                # A completed worker may be evicted to make space for another
                # source. The same bound vouchers can be validated from scratch.
                task.cursor = ""
                response = self._response(task, "validate_agent_hits", arguments)
            status = response["status"]
            if status == "ready":
                task.validated = True
                continue
            task.attempts += 1
            if self._retry(task, response):
                return False
            self._release(task, response)
            if state.offset:
                raise _restart()
            code = "processing_timeout" if status == "processing" else status
            state.coverage[task.source] = _failure(task.source, code)
            state.hits.pop(task.source, None)
            state.ordered = None
            state.validation = None
            return False
        return True

    def find(self, project_id, query, agent, cursor, limit, caller):
        integer(limit, "limit", 1, 20)
        if (not isinstance(project_id, str) or not 0 < len(project_id) <= 200
                or not isinstance(query, str) or len(query) > 200 or not isinstance(agent, str)
                or (agent and not AGENT.fullmatch(agent))):
            raise AccessError("Invalid history search parameters.", code="invalid_arguments")
        scope = self._configuration(project_id, caller)
        params = [project_id, query, agent, limit]
        state = self._claim(scope, params, cursor)
        if state is None:
            return {"status": "busy", "coverage_complete": False, "next_cursor": cursor or None,
                    "continue_with": "Retry the same search shortly."}
        try:
            if state.scans:
                self._scan(state, project_id, query, agent, caller)
                if state.scans or any(state.hits.values()):
                    return self._continuation(state, scope, params)
            if state.ordered is None:
                state.ordered = _merge(state.hits)
            end = state.offset + limit
            page = state.ordered[state.offset:end]
            if state.validation is None:
                state.validation = _validation_tasks(page)
            with collect_page_aliases(self._core.policy) as aliases:
                if not self._validate(state, project_id, caller):
                    return self._continuation(state, scope, params)
            if self._configuration(project_id, caller).key != scope.key:
                raise _restart()
            coverage = [state.coverage[source] for source in state.sources]
            if unified(self._core.policy):
                coverage = [{**item, "state": coverage_status(item["warnings"])} for item in coverage]
            more = end < len(state.ordered)
            state.offset = end
            state.validation = None
            result = {"status": "ready" if coverage else "no_enabled_sources", "projection_version": VERSION,
                      "threads": [summary for summary, _ in page], "coverage": coverage,
                      "coverage_complete": bool(coverage) and all(item["coverage_complete"] for item in coverage),
                      "has_more": more, "next_cursor": self._cursor(state, scope, params) if more else None}
            if not more:
                self._discard(state)
            retain_history_aliases(self._core.policy, aliases)
            return result
        except Exception:
            self._discard(state)
            raise
        finally:
            state.lock.release()
