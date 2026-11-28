"""Merge authorized search summaries while keeping source scans independently supervised."""

from collections import deque
from dataclasses import dataclass, field
import json
import re
import secrets
import threading
import time

from .agent_history import (
    ERROR_CODES, VERSION, _normalize_query, _restart, _search_rank_key, coverage_status, unified,
)
from .agent_history_policy import AGENT, IDENTIFIER
from .catalog import AccessError, integer
from .history_process import bound_worker_replies
from .project_guard import collect_page_aliases, retain_history_aliases

_MAX_SEARCHES = 12
_MAX_AGE = 300
_MAX_ATTEMPTS = 6
_ADMISSION_SECONDS = 25
_SCAN_BUDGET_SECONDS = 8.0
_PAGE_SECONDS = 12
_MAX_SINGLE_ROW_SECONDS = 40
# A 40 s indivisible row can span ten ordinary 4 s worker demands.
_MAX_SINGLE_ROW_POLLS = 12
_MAX_SOURCE_ROWS = 64
_MAX_PROJECT_CANONICALS = 256
_CONTINUATION = frozenset({"processing", "busy", "waiting_source_stable"})
_RESTART = frozenset({"unauthorized", "agent_policy_invalid", "private_protection_unavailable"})
_FAILURES = ERROR_CODES | {"restart_required", "snapshot_expired", "busy", "source_changed"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SUMMARY_FIELDS = (
    "source_id", "agent", "surface", "stable_thread_id", "title", "updated_at",
    "project_id", "thread_ref", "source_adapter",
)
_OPTIONAL_INT_SUMMARY_FIELDS = (
    "message_count", "user_message_count", "assistant_message_count", "total_chars",
)
_OPTIONAL_BOOL_SUMMARY_FIELDS = ("supports_turns", "is_in_progress", "attached_thread")


@dataclass
class _Task:
    source: str
    vouchers: str = ""
    cursor: str = ""
    attempts: int = 0
    busy_since: float | None = None


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
    project_canonicals: dict = field(default_factory=dict)
    ordered: list | None = None
    offset: int = 0
    validation: tuple | None = None
    page_limit: int | None = None


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
    raw_summary = value["summary"]
    if "source_instance" in raw_summary:
        instance = raw_summary["source_instance"]
        if not isinstance(instance, str) or not IDENTIFIER.fullmatch(instance):
            raise _malformed()
        summary["source_instance"] = instance
    for key in _OPTIONAL_INT_SUMMARY_FIELDS:
        if key in raw_summary:
            item = raw_summary[key]
            if type(item) is not int or item < 0 or item > 100_000_000:
                raise _malformed()
            summary[key] = item
    for key in _OPTIONAL_BOOL_SUMMARY_FIELDS:
        if key in raw_summary:
            item = raw_summary[key]
            if type(item) is not bool:
                raise _malformed()
            summary[key] = item
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
    mode = value.get("mode")
    if mode is not None and (not isinstance(mode, str) or mode not in {"substring", "token_all"}):
        raise _malformed()
    extra = {"mode": mode} if mode is not None else {}
    if kind != "visible_message":
        return {"in": kind, **extra}
    if (not isinstance(value.get("message_id"), str) or len(value["message_id"]) > 64
            or not _digest(value.get("snapshot_sha256"))):
        raise _malformed()
    return {key: value[key] for key in ("in", "message_id", "snapshot_sha256")} | extra


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
    if "unverified_project_candidates" in value:
        count = value["unverified_project_candidates"]
        if type(count) is not int or count < 0 or count > 100_000:
            raise _malformed()
        if count:
            result["unverified_project_candidates"] = count
    if "unsupported_agent_types" in value:
        types = value["unsupported_agent_types"]
        if (not isinstance(types, list) or len(types) > 64
                or any(not isinstance(item, str) or not AGENT.fullmatch(item) for item in types)):
            raise _malformed()
        if types:
            result["unsupported_agent_types"] = sorted(set(types))
    return result


def _merge(groups, query=""):
    needle = _normalize_query(query.strip()) if query else ""
    matches = {}
    for hits in groups.values():
        for hit in hits:
            matches.setdefault(hit.canonical, []).append(hit)
    rows = []
    for same in matches.values():
        best = min(same, key=lambda hit: (
            not (bool(needle) and hit.summary["match"].get("in") == "title"
                 and _normalize_query((hit.summary.get("title") or "").strip()) == needle),
            not (bool(needle) and hit.summary["match"].get("in") == "title"
                 and hit.summary["match"].get("mode") != "token_all"),
            hit.summary["match"].get("mode") == "token_all",
            not hit.primary,
            hit.summary["source_id"],
            hit.summary["stable_thread_id"],
        ))
        sources = sorted({hit.summary["source_id"] for hit in same})
        vouchers = tuple(sorted({voucher for hit in same for voucher in hit.vouchers}))
        rows.append(({**best.summary, "matched_sources": sources}, vouchers))
    rows.sort(key=lambda item: _search_rank_key(item[0], needle), reverse=True)
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
            retired = [self._searches.pop(key) for key, state in tuple(self._searches.items())
                       if now - state.started > _MAX_AGE and not state.lock.locked()]
            if token is None and len(self._searches) == _MAX_SEARCHES:
                evict = next((item for item in self._searches.values() if not item.lock.locked()), None)
                if evict is not None:
                    retired.append(self._searches.pop(evict.key))
        # Only this search can own its keyed worker requests. Retire children
        # outside the broker lock so unrelated callers can continue.
        for state in retired:
            self._release_pending(state)
        with self._lock:
            if token is not None:
                state = self._searches.get(token["key"])
                if state is None or time.monotonic() - state.started > _MAX_AGE:
                    raise _restart()
                if not state.lock.acquire(blocking=False):
                    return None
                if token["sequence"] != state.sequence:
                    state.lock.release()
                    raise _restart()
                return state
            if len(self._searches) == _MAX_SEARCHES:
                return None
            sources = tuple(self._core._sources(scope, "", params[2].casefold()))
            state = _Search(secrets.token_hex(16), sources, deque(_Task(source) for source in sources))
            state.lock.acquire()
            self._searches[state.key] = state
            return state

    def _discard(self, state):
        with self._lock:
            self._searches.pop(state.key, None)
        self._release_pending(state)

    def _release_pending(self, state):
        for task in (*state.scans, *(state.validation or ())):
            if task.cursor:
                self._release(task, {})

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
    def _retry(task, response, *, max_processing_polls=_MAX_ATTEMPTS):
        status = response["status"]
        if status not in _CONTINUATION:
            return False
        cursor = response.get("next_cursor")
        has_cursor = isinstance(cursor, str) and 0 < len(cursor) <= 4096
        if has_cursor:
            task.cursor = cursor
        if status == "busy":
            # No source work was admitted. Fast polls must not eat the budget
            # of a healthy queued source while other routes own the workers.
            now = time.monotonic()
            if task.busy_since is None:
                task.busy_since = now
            if now - task.busy_since >= _ADMISSION_SECONDS:
                return False
        else:
            task.busy_since = None
            task.attempts += 1
            if task.attempts >= (max_processing_polls if status == "processing" else _MAX_ATTEMPTS):
                return False
        return has_cursor or status == "busy"

    def _release(self, task, response):
        cursor = response.get("next_cursor") or task.cursor
        task.cursor = ""
        if self._abandon is not None and isinstance(cursor, str) and cursor:
            self._abandon(task.source, cursor)

    def _scan(self, state, project_id, query, agent, caller):
        task = state.scans[0]
        # The opaque search key keeps worker de-duplication and cancellation
        # private to this search, even for two otherwise identical queries.
        arguments = {"project_id": project_id, "query": query, "agent": agent,
                     "source_id": task.source, "search_key": state.key, **caller}
        response = self._response(task, "scan_agent_source", arguments)
        state.scans.popleft()
        status = response["status"]
        admitted = next((other for other in state.scans if other.cursor), None)
        if status == "busy" and not task.cursor and admitted is not None:
            # The wait is caused by this very search. Drive its admitted work
            # before starting the clock for external service contention.
            task.busy_since = None
            state.scans.remove(admitted)
            state.scans.appendleft(admitted)
            state.scans.append(task)
            return status
        if status == "ready":
            try:
                rows = response.get("rows")
                if not isinstance(rows, list) or len(rows) > _MAX_SOURCE_ROWS:
                    raise _malformed()
                parsed = tuple(_hit(row, task.source, project_id) for row in rows)
                state.coverage[task.source] = _coverage(response.get("coverage"), task.source)
                state.hits[task.source] = parsed
                canonicals = response.get("project_canonicals")
                if canonicals is not None:
                    if (not isinstance(canonicals, list) or len(canonicals) > _MAX_PROJECT_CANONICALS
                            or any(not _digest(item) for item in canonicals)):
                        raise _malformed()
                    state.project_canonicals[task.source] = tuple(canonicals)
            except AccessError as error:
                state.coverage[task.source] = _failure(task.source, error.code)
        elif self._retry(task, response):
            state.scans.append(task)
        else:
            self._release(task, response)
            code = "processing_timeout" if status == "processing" else status
            state.coverage[task.source] = _failure(task.source, code)
        return status

    def _page_budget(self, state, page):
        self._release_pending(state)
        if len(page) == 1:
            # One deduplicated row is indivisible. If it cannot fit even its
            # larger bounded call, omit the whole row and report that limit.
            for task in state.validation:
                report = state.coverage[task.source]
                report["coverage_complete"] = False
                report["warnings"] = sorted(set(report["warnings"]) | {"resource_exhausted"})
            return None
        # Keep the full ordered set and its untouched offset. The next call
        # validates only this prefix, with a fresh collection of alias proofs.
        state.page_limit = (len(page) + 1) // 2
        state.validation = None
        return False

    def _validate(self, state, page, project_id, caller, deadline):
        # Service held demands first. A healthy worker may finish a validation
        # after its 4 s delivery window; leaving it idle while redoing earlier
        # sources forces that whole validation to start again on the next poll.
        tasks = sorted(state.validation, key=lambda task: not bool(task.cursor))
        drain = len(page) == 1 or any(task.cursor for task in tasks)
        polls = _MAX_SINGLE_ROW_POLLS if len(page) == 1 else _MAX_ATTEMPTS
        for task in tasks:
            if time.monotonic() >= deadline:
                return self._page_budget(state, page)
            arguments = {"project_id": project_id, "source_id": task.source,
                         "vouchers": task.vouchers, "search_key": state.key, **caller}
            response = self._response(task, "validate_agent_hits", arguments)
            if task.cursor and response["status"] in {"restart_required", "snapshot_expired"}:
                # A worker cursor expired. Its original immutable vouchers must
                # still pass a fresh load; ownership changes raise _restart().
                task.cursor = ""
                if time.monotonic() >= deadline:
                    return self._page_budget(state, page)
                response = self._response(task, "validate_agent_hits", arguments)
            pending = self._retry(task, response, max_processing_polls=polls)
            while drain and pending and response["status"] == "processing":
                if time.monotonic() >= deadline:
                    return self._page_budget(state, page)
                response = self._response(task, "validate_agent_hits", arguments)
                pending = self._retry(task, response, max_processing_polls=polls)
            status = response["status"]
            if time.monotonic() >= deadline or (len(page) == 1 and status == "processing" and not pending):
                return self._page_budget(state, page)
            if status == "ready":
                task.cursor, task.attempts, task.busy_since = "", 0, None
                continue
            if pending:
                return False
            self._release(task, response)
            if state.offset:
                raise _restart()
            code = "processing_timeout" if status == "processing" else status
            state.coverage[task.source] = _failure(task.source, code)
            state.hits.pop(task.source, None)
            state.ordered = None
            self._release_pending(state)
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
                scan_deadline = time.monotonic() + _SCAN_BUDGET_SECONDS
                while state.scans:
                    status = self._scan(state, project_id, query, agent, caller)
                    if status in _CONTINUATION or time.monotonic() >= scan_deadline:
                        break
                if state.scans:
                    return self._continuation(state, scope, params)
            if state.ordered is None:
                state.ordered = _merge(state.hits, query=query)
            end = min(len(state.ordered), state.offset + (state.page_limit or limit))
            page = state.ordered[state.offset:end]
            if state.validation is None:
                state.validation = _validation_tasks(page)
            seconds = _PAGE_SECONDS
            if len(page) == 1:
                seconds = min(_MAX_SINGLE_ROW_SECONDS, _PAGE_SECONDS * max(2, len(state.validation)))
            deadline = time.monotonic() + seconds
            with collect_page_aliases(self._core.policy) as aliases, bound_worker_replies(deadline):
                verified = self._validate(state, page, project_id, caller, deadline)
                if verified is not False and self._configuration(project_id, caller).key != scope.key:
                    raise _restart()
                if verified is True and page and time.monotonic() >= deadline:
                    verified = self._page_budget(state, page)
                if verified is False:
                    return self._continuation(state, scope, params)
                if verified is None:
                    page = ()
                    aliases.clear()
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
            if query and not state.ordered:
                total = len({item for group in state.project_canonicals.values() for item in group})
                if total:
                    result["total_project_threads"] = total
                    result["browse_hint"] = (
                        f"No thread matched query; retry with query='' to browse {total} "
                        "authorized thread(s) in this project."
                    )
            if not more:
                self._discard(state)
            retain_history_aliases(self._core.policy, aliases)
            return result
        except Exception:
            self._discard(state)
            raise
        finally:
            state.lock.release()
