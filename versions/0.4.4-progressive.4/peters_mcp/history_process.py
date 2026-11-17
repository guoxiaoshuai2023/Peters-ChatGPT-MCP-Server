"""Ephemeral, supervised history parsing; only bounded pages cross the process boundary.

The child owns every projection and generator. A completed page is revalidated
inside the child for each live delivery request, including delayed polling.
"""

import base64
from collections import deque
from dataclasses import asdict
import hashlib
import hmac
import json
import multiprocessing
import os
import resource
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time

from .catalog import AccessError

OPERATIONS = frozenset(("find_codex_threads", "read_codex_thread", "read_codex_thread_item"))
REQUEST_BYTES = 64 * 1024
RESPONSE_BYTES = 256 * 1024
STAGES = frozenset(("_configuration", "_metadata", "_derive", "_snapshot"))
PHASES = frozenset(("new", "operation", "validation", "scanning", "finalizing", "authorization_check", "candidate_scan", "delivery", "done", "unknown"))
CURSOR_TTL = 1800
PREFIX = "hp1."


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")


def _frame(value, maximum):
    data = _json(value)
    if len(data) > maximum:
        raise AccessError("History IPC payload exceeds its bounded transport limit.", code="resource_exhausted")
    return struct.pack("!I", len(data)) + data


def _messages(buffer, maximum):
    while len(buffer) >= 4:
        size = struct.unpack("!I", buffer[:4])[0]
        if size > maximum:
            raise ValueError("oversized frame")
        if len(buffer) < size + 4:
            return
        data = bytes(buffer[4:4 + size])
        del buffer[:4 + size]
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("invalid message")
        yield value


def _engine(spec):
    from .catalog import Catalog, Project
    from .history import HistoryAccess
    catalog = None
    if spec.get("catalog_path"):
        catalog = Catalog.from_config(spec["catalog_path"])
    elif spec.get("projects"):
        catalog = Catalog([Project(**{**p, "root": Path(p["root"])}) for p in spec["projects"]])
    return HistoryAccess(spec.get("config_path"), spec.get("project_ids", ()), catalog)


def _rss_bytes(pid):
    """Live RSS, including while the child is stuck inside an atomic operation."""
    try:
        with open(f"/proc/{pid}/statm", encoding="ascii") as stream:
            return int(stream.read(128).split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        try:
            value = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True,
                                   timeout=0.2, check=False).stdout.strip()
            return int(value) * 1024 if value else 0
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return 0


def _worker(connection, spec, factory, task_ttl):
    connection.setblocking(False)
    incoming = bytearray()
    tasks = {}
    order = deque()

    def send(value):
        # ru_maxrss captures short allocation peaks missed by live sampling.
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        value["peak_rss_bytes"] = int(peak if sys.platform == "darwin" else peak * 1024)
        packet = memoryview(_frame(value, RESPONSE_BYTES))
        if value["type"] == "delivery":
            send({"type": "delivery_begin", "bytes": len(packet)})
        deadline = time.monotonic() + 1
        while packet:
            if time.monotonic() > deadline:
                raise TimeoutError()
            if select.select([], [connection], [], 0.05)[1]:
                try:
                    packet = packet[connection.send(packet):]
                except BlockingIOError:
                    pass

    def error(exc):
        if isinstance(exc, AccessError):
            # AccessError is deliberately the application's safe disclosure type.
            message = str(exc)
            prefix = f"[{exc.code}] "
            if message.startswith(prefix):
                message = message[len(prefix):]
            return {"code": exc.code, "message": message[:2000]}
        return {"code": "history_processing_failed", "message": "History processing failed safely; start a fresh read."}

    try:
        core = (factory or _engine)(spec)
        def observe_stage(name, method):
            def observed(*args, **kwargs):
                started = time.monotonic()
                send({"type": "stage", "stage": name})
                try:
                    return method(*args, **kwargs)
                finally:
                    send({"type": "stage_done", "stage": name,
                          "elapsed_ms": int(1000 * (time.monotonic() - started))})
            return observed
        for name in STAGES:
            method = getattr(core, name, None)
            if method is not None:
                setattr(core, name, observe_stage(name, method))
        send({"type": "boot"})
        while True:
            runnable = any(t["iterator"] is not None or t["demands"] for t in tasks.values())
            if select.select([connection], [], [], 0 if runnable else 0.05)[0]:
                data = connection.recv(REQUEST_BYTES + 4)
                if not data:
                    return
                incoming.extend(data)
                for msg in _messages(incoming, REQUEST_BYTES):
                    if msg["type"] == "submit":
                        tid = msg["id"]
                        if tid not in tasks:
                            tasks[tid] = {"operation": msg["operation"], "arguments": msg["arguments"],
                                          "iterator": None, "phase": "new", "result": None,
                                          "error": None, "demands": {}, "revision": 0,
                                          "idle_notified": False, "touched": time.monotonic()}
                            order.append(tid)
                    elif msg["type"] == "demand":
                        if msg["id"] not in tasks:
                            send({"type": "delivery", "id": msg["id"], "nonce": msg["nonce"],
                                  "result": {"status": "snapshot_expired",
                                             "continue_with": "Start a fresh call without the previous cursor."}})
                        else:
                            task = tasks[msg["id"]]
                            task["revision"] = msg["revision"]
                            task["idle_notified"] = False
                            task["demands"][msg["nonce"]] = msg["until"]
                            task["touched"] = time.monotonic()
                    elif msg["type"] == "forget":
                        tasks.pop(msg["id"], None)
            now = time.monotonic()
            for tid, task in list(tasks.items()):
                task["demands"] = {key: expiry for key, expiry in task["demands"].items() if expiry > now}
                if now - task["touched"] > task_ttl:
                    send({"type": "complete", "id": tid, "revision": task["revision"]})
                    tasks.pop(tid, None)
            if not order:
                continue
            tid = order.popleft()
            if tid not in tasks:
                continue
            order.append(tid)
            task = tasks[tid]
            if task["phase"] == "done" and not task["demands"]:
                if not task["idle_notified"]:
                    send({"type": "complete", "id": tid, "revision": task["revision"]})
                    task["idle_notified"] = True
                continue
            if task["error"] is not None:
                for nonce in task["demands"]:
                    send({"type": "delivery", "id": tid, "nonce": nonce, "error": task["error"]})
                task["demands"].clear()
                continue
            if task["phase"] == "done" and not task["demands"]:
                continue
            send({"type": "step", "id": tid, "phase": task["phase"],
                  "checkpoint": task.get("checkpoint", "unknown")})
            try:
                if task["phase"] == "new":
                    task["iterator"] = iter(core.operation_iter(task["operation"], task["arguments"]))
                    task["phase"] = "operation"
                elif task["phase"] == "done":
                    task["iterator"] = iter(core.revalidate_result_iter(
                        task["operation"], task["arguments"], task["result"]))
                    task["phase"] = "validation"
                try:
                    checkpoint = next(task["iterator"])
                    phase = checkpoint.get("phase") if isinstance(checkpoint, dict) else None
                    task["checkpoint"] = phase if phase in PHASES else "unknown"
                except StopIteration as finished:
                    if not isinstance(finished.value, dict):
                        raise ValueError("invalid history result")
                    task["result"] = finished.value
                    validating = task["phase"] == "validation"
                    task["iterator"] = None
                    task["phase"] = "done"
                    if validating:
                        send({"type": "delivery_start"})
                        # A late result is retained only in the child. A later demand
                        # will run validation again rather than receiving this page.
                        for nonce, expiry in task["demands"].items():
                            if expiry > time.monotonic():
                                send({"type": "delivery", "id": tid, "nonce": nonce, "result": task["result"]})
                        task["demands"].clear()
                    if validating:
                        send({"type": "complete", "id": tid, "revision": task["revision"]})
                        task["idle_notified"] = True
            except Exception as exc:
                task["error"] = error(exc)
                task["result"] = None
                task["iterator"] = None
                task["phase"] = "done"
                send({"type": "complete", "id": tid, "revision": task["revision"]})
            finally:
                send({"type": "idle"})
    except Exception:
        # Fixed control label only: never serialize exception text or source data.
        try:
            send({"type": "fatal"})
        except Exception:
            pass
    finally:
        connection.close()


class IsolatedHistory:
    """Synchronous tool facade with one bounded, restartable parsing process."""

    def __init__(self, history, *, _factory=None, wait_seconds=4.0, step_seconds=3.0,
                 worker_rss=256 * 1024 * 1024, ttl=CURSOR_TTL):
        catalog = history.catalog
        self._spec = {"config_path": str(history.config_path) if history.config_path else None,
                      "project_ids": sorted(history.project_ids), "catalog_path": None, "projects": []}
        if catalog is not None:
            if catalog._config_path is not None:
                self._spec["catalog_path"] = str(catalog._config_path)
            else:
                self._spec["projects"] = [{**asdict(p), "root": str(p.root)} for p in catalog.projects.values()]
        self._factory = _factory
        self._wait_seconds = wait_seconds
        self._step_seconds = step_seconds
        self._worker_rss = worker_rss
        self._ttl = ttl
        self._key = secrets.token_bytes(32)
        self._generation = secrets.token_hex(8)
        self._lock = threading.RLock()
        self._process = None
        self._socket = None
        self._outgoing = bytearray()
        self._incoming = bytearray()
        self._tasks = {}
        self._keys = {}
        self._waiters = {}
        self._closed = False
        self._epoch = 0
        self._serial = 0
        self._diagnostics = deque(maxlen=256)
        self._diagnostic_sink = None
        self._stops = deque(maxlen=16)
        self._active = {}
        self._step_started = None
        self._rss = 0
        self._peak_rss = 0
        self._monitor = threading.Thread(target=self._supervise, name="history-supervisor", daemon=True)
        self._monitor.start()

    def set_diagnostic_sink(self, sink):
        """Operational events only; callers must not add request/source context."""
        with self._lock:
            self._diagnostic_sink = sink

    def diagnostic_events(self):
        with self._lock:
            return [dict(event) for event in self._diagnostics]

    def _diagnose(self, event, **metrics):
        # All values originate from fixed labels and counters below, never args.
        record = {"event": event, "epoch": self._epoch, **metrics}
        self._diagnostics.append(record)
        if self._diagnostic_sink is not None:
            try:
                self._diagnostic_sink(dict(record))
            except Exception:
                pass

    def _start(self):
        parent, child = socket.socketpair()
        process = multiprocessing.get_context("spawn").Process(
            target=_worker, args=(child, self._spec, self._factory, self._ttl), daemon=True,
            name="history-parser")
        try:
            process.start()
        except Exception:
            parent.close()
            child.close()
            raise
        child.close()
        parent.setblocking(False)
        self._process, self._socket = process, parent
        self._epoch += 1
        self._active = {}
        self._diagnose("worker_start")
        self._started = time.monotonic()
        self._booted = False
        self._step_started = None
        self._last_rss_check = 0

    def _queue(self, value):
        packet = _frame(value, REQUEST_BYTES)
        if len(self._outgoing) + len(packet) > 8 * REQUEST_BYTES:
            raise AccessError("History request queue is full; retry shortly.", code="busy")
        self._outgoing.extend(packet)

    def _stop(self, status, reason="explicit_close"):
        process = self._process
        if process is not None:
            self._stops.append((self._generation, reason))
            self._diagnose("worker_stop", reason=reason, status=status,
                           waiters=len(self._waiters), tasks=len(self._tasks),
                           rss_bytes=self._rss, peak_rss_bytes=self._peak_rss,
                           elapsed_ms=int(1000 * (time.monotonic() - self._step_started)) if self._step_started else 0,
                           exitcode=process.exitcode, incoming_bytes=len(self._incoming), outgoing_bytes=len(self._outgoing), **self._active)
        if process is not None:
            if process.is_alive():
                process.terminate()
                process.join(0.3)
            if process.is_alive():
                process.kill()
            process.join(1)
            if process.is_alive():
                # Do not start another worker if the previous process cannot be reaped.
                self._closed = True
            else:
                process.close()
        if self._socket is not None:
            self._socket.close()
        self._process = self._socket = None
        self._outgoing.clear()
        self._incoming.clear()
        self._generation = secrets.token_hex(8)
        self._tasks.clear()
        self._keys.clear()
        for waiter in self._waiters.values():
            waiter["reply"] = {"result": {"status": status, "continue_with": "Start a fresh call without the previous cursor."}}
            waiter["event"].set()
        self._step_started = None

    def _receive_messages(self):
        # Drain already available IPC before deciding a worker has stalled.
        # A frame can arrive in many short reads, with the worker's idle marker
        # queued behind it. Both storage and work per pass remain bounded.
        received = 0
        deadline = time.monotonic() + 0.05
        for _ in range(64):
            try:
                data = self._socket.recv(RESPONSE_BYTES + 4)
            except BlockingIOError:
                return
            if not data:
                self._stop("restart_required", "ipc_eof")
                return
            self._incoming.extend(data)
            received += len(data)
            yield from _messages(self._incoming, RESPONSE_BYTES)
            if self._socket is None:
                return
            # Positive byte movement during a bounded delivery is observable
            # progress, even before JSON framing is complete. No bytes, no reset.
            if self._step_started is not None and self._active.get("phase") == "delivery":
                self._step_started = time.monotonic()
            if received >= 2 * RESPONSE_BYTES or time.monotonic() >= deadline:
                return

    def _supervise(self):
        while True:
            time.sleep(0.01)
            with self._lock:
                if self._closed:
                    return
                if self._process is None:
                    continue
                now = time.monotonic()
                try:
                    if self._outgoing:
                        try:
                            sent = self._socket.send(self._outgoing)
                            del self._outgoing[:sent]
                        except BlockingIOError:
                            pass
                    for msg in self._receive_messages():
                        peak = msg.get("peak_rss_bytes", 0)
                        if type(peak) is not int or peak < 0:
                            raise ValueError("invalid peak memory measurement")
                        self._peak_rss = max(self._peak_rss, peak)
                        if peak > self._worker_rss:
                            self._stop("resource_exhausted", "peak_rss")
                            break
                        if msg["type"] == "boot":
                            self._booted = True
                        elif msg["type"] == "step":
                            self._step_started = now
                            task = self._tasks.get(msg["id"], {})
                            self._active = {"task": task.get("serial", 0),
                                            "operation": task.get("operation", "unknown"),
                                            "phase": msg.get("phase") if msg.get("phase") in PHASES else "unknown",
                                            "checkpoint": msg.get("checkpoint") if msg.get("checkpoint") in PHASES else "unknown"}
                        elif msg["type"] == "idle":
                            if self._step_started is not None:
                                elapsed = int(1000 * (time.monotonic() - self._step_started))
                                if elapsed >= 1000:
                                    self._diagnose("slow_step", elapsed_ms=elapsed, **self._active)
                            self._step_started = None
                        elif msg["type"] == "delivery_start":
                            self._active["phase"] = "delivery"
                        elif msg["type"] == "delivery_begin":
                            size = msg.get("bytes")
                            if type(size) is not int or not 4 <= size <= RESPONSE_BYTES + 4:
                                raise ValueError("invalid delivery size")
                            self._active["response_bytes"] = size
                        elif msg["type"] == "stage" and msg.get("stage") in STAGES:
                            self._active["stage"] = msg["stage"]
                            self._active["stage_state"] = "running"
                        elif msg["type"] == "stage_done" and msg.get("stage") in STAGES:
                            self._active["stage_state"] = "completed"
                            elapsed = msg.get("elapsed_ms")
                            if type(elapsed) is not int or elapsed < 0:
                                raise ValueError("invalid stage duration")
                            if elapsed >= 1000:
                                self._diagnose("slow_stage", elapsed_ms=elapsed, **self._active)
                            if elapsed > self._step_seconds * 1000:
                                self._stop("processing_timeout", "step_timeout")
                                break
                            # A completed bounded check is real progress. Keep the
                            # final authorization guard synchronous: no other task
                            # can run here and no timer heartbeat hides a stuck call.
                            if self._step_started is not None:
                                self._step_started = time.monotonic()
                        elif msg["type"] == "fatal":
                            self._stop("restart_required", "worker_fatal")
                            break
                        elif msg["type"] == "complete" and msg["id"] in self._tasks:
                            task = self._tasks[msg["id"]]
                            # A completion already on the socket cannot release a
                            # newly reserved validation demand for the same task.
                            if msg["revision"] == task["revision"]:
                                task["complete"] = True
                        elif msg["type"] == "delivery":
                            # One whole bounded response has crossed IPC. Several
                            # duplicate waiters must not look like a stalled parser
                            # merely because their successful sends accumulate.
                            if self._step_started is not None:
                                self._step_started = time.monotonic()
                            self._diagnose("delivery_complete", **self._active)
                            waiter = self._waiters.get(msg["nonce"])
                            if waiter is not None and waiter["id"] == msg["id"]:
                                waiter["reply"] = msg
                                waiter["event"].set()
                    if self._process is None:
                        continue
                    if not self._process.is_alive():
                        self._stop("restart_required", "worker_exit")
                    elif ((not self._booted and now - self._started > 5) or
                          (self._step_started is not None and now - self._step_started > self._step_seconds)):
                        self._stop("processing_timeout", "boot_timeout" if not self._booted else "step_timeout")
                    elif now - self._last_rss_check >= 0.2:
                        self._last_rss_check = now
                        self._rss = _rss_bytes(self._process.pid)
                        self._peak_rss = max(self._peak_rss, self._rss)
                        if self._rss > self._worker_rss:
                            self._stop("resource_exhausted", "live_rss")
                except Exception:
                    self._stop("restart_required", "supervisor_failure")

    def _token(self, task):
        value = {"id": task["id"], "op": task["operation"], "key": task["key"],
                 "generation": self._generation, "expires": time.time() + self._ttl}
        encoded = base64.urlsafe_b64encode(_json(value)).decode()
        return PREFIX + encoded + "." + hmac.new(self._key, encoded.encode(), hashlib.sha256).hexdigest()

    def _verify(self, token, operation):
        try:
            if len(token) > 2048:
                raise ValueError()
            encoded, signature = token[len(PREFIX):].split(".")
            if not hmac.compare_digest(signature, hmac.new(self._key, encoded.encode(), hashlib.sha256).hexdigest()):
                raise ValueError()
            value = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
            if value["op"] != operation or value["expires"] < time.time():
                raise ValueError()
            return value
        except (ValueError, KeyError, TypeError):
            raise AccessError("Invalid, expired or cross-operation processing cursor; start a fresh read.",
                              code="invalid_cursor") from None

    def _call(self, operation, arguments):
        # Validate serialization before enqueuing or launching a child.
        if any(not isinstance(value, (str, bool, int, type(None))) for value in arguments.values()):
            raise AccessError("History arguments must be scalar values.", code="invalid_arguments")
        if sum(len(value) for value in arguments.values() if isinstance(value, str)) > REQUEST_BYTES:
            raise AccessError("History arguments exceed the request limit.", code="resource_exhausted")
        try:
            encoded = _json(arguments)
        except (TypeError, ValueError):
            raise AccessError("History arguments must be bounded JSON values.", code="invalid_arguments") from None
        if len(encoded) > REQUEST_BYTES - 1024:
            raise AccessError("History arguments exceed the request limit.", code="resource_exhausted")
        started = time.monotonic()
        with self._lock:
            if self._closed:
                raise AccessError("History worker is closed.", code="restart_required")
            token = arguments.get("cursor", "")
            if isinstance(token, str) and token.startswith(PREFIX):
                value = self._verify(token, operation)
                if value["generation"] != self._generation:
                    reason = next((r for g, r in self._stops if g == value["generation"]), "expired_diagnostic")
                    self._diagnose("stale_continuation", reason=reason)
                    return {"status": "restart_required", "continue_with": "Start a fresh call without the previous cursor."}
                task = self._tasks.get(value["id"])
                if task is None or time.monotonic() - task["touched"] > self._ttl:
                    return {"status": "snapshot_expired", "continue_with": "Start a fresh call without the previous cursor."}
                supplied = {key: item for key, item in arguments.items() if key != "cursor"}
                original = {key: item for key, item in task["arguments"].items() if key != "cursor"}
                if value["key"] != task["key"] or _json(supplied) != _json(original):
                    raise AccessError("Processing cursor arguments cannot be changed.", code="invalid_cursor")
            else:
                key = hashlib.sha256(operation.encode() + b"\0" + encoded).hexdigest()
                task = self._tasks.get(self._keys.get(key))
                if task is not None and time.monotonic() - task["touched"] > self._ttl:
                    self._tasks.pop(task["id"], None)
                    self._keys.pop(key, None)
                    self._queue({"type": "forget", "id": task["id"]})
                    task = None
                if task is None:
                    if sum(not t["complete"] for t in self._tasks.values()) >= 5:
                        return {"status": "busy", "continue_with": "Retry the same request shortly."}
                    if self._process is None:
                        self._start()
                    # Parent task descriptions remain bounded even when a client
                    # abandons cursors. Removed entries expire explicitly.
                    for tid, old in list(self._tasks.items()):
                        if time.monotonic() - old["touched"] > self._ttl or (len(self._tasks) >= 64 and old["complete"]):
                            self._queue({"type": "forget", "id": tid})
                            self._tasks.pop(tid)
                            if self._keys.get(old["key"]) == tid:
                                self._keys.pop(old["key"], None)
                    tid = secrets.token_hex(16)
                    self._serial += 1
                    task = {"id": tid, "serial": self._serial, "key": key, "operation": operation, "arguments": arguments,
                            "complete": False, "revision": 0, "attempt": 0,
                            "retry": False, "touched": time.monotonic()}
                    self._queue({"type": "submit", "id": tid, "operation": operation, "arguments": arguments})
                    self._tasks[tid], self._keys[key] = task, tid
            if task["complete"] and sum(not t["complete"] for t in self._tasks.values()) >= 5:
                return {"status": "busy", "next_cursor": self._token(task),
                        "continue_with": "Retry the same request shortly."}
            task["touched"] = time.monotonic()
            if len(self._waiters) >= 16:
                return {"status": "busy", "continue_with": "Retry the same request shortly."}
            if task["retry"]:
                # Only an explicit subsequent call restarts a temporarily unstable
                # source. The original core cursor remains in these arguments.
                self._queue({"type": "submit", "id": task["id"],
                             "operation": task["operation"], "arguments": task["arguments"]})
                task["attempt"] += 1
                task["retry"] = False
            task["complete"] = False
            task["revision"] += 1
            nonce = secrets.token_hex(12)
            waiter = {"id": task["id"], "attempt": task["attempt"],
                      "event": threading.Event(), "reply": None}
            self._queue({"type": "demand", "id": task["id"], "nonce": nonce,
                         "revision": task["revision"], "until": started + self._wait_seconds})
            self._waiters[nonce] = waiter
        waiter["event"].wait(max(0, self._wait_seconds - (time.monotonic() - started)))
        with self._lock:
            self._waiters.pop(nonce, None)
            reply = waiter["reply"]
            if reply is not None:
                if "error" in reply:
                    err = reply["error"]
                    if err["code"] == "waiting_source_stable":
                        # Several callers may receive the same failed attempt. An
                        # older waiter must not forget an already restarted task.
                        if waiter["attempt"] == task["attempt"] and not task["retry"]:
                            self._queue({"type": "forget", "id": task["id"]})
                            task["retry"] = True
                            task["complete"] = True
                        return {"status": "waiting_source_stable", "next_cursor": self._token(task),
                                "continue_with": "Wait for the source to stabilize, then call the same tool "
                                                 "with the same arguments and next_cursor."}
                    self._tasks.pop(task["id"], None)
                    if self._keys.get(task["key"]) == task["id"]:
                        self._keys.pop(task["key"], None)
                    self._queue({"type": "forget", "id": task["id"]})
                    raise AccessError(err["message"], code=err["code"])
                # A new initial call after delivery must observe a new snapshot.
                # Existing processing tokens still retain their original task.
                if self._keys.get(task["key"]) == task["id"]:
                    self._keys.pop(task["key"], None)
                return reply["result"]
            return {"status": "processing", "next_cursor": self._token(task),
                    "continue_with": "Call the same tool with the same arguments, replacing cursor with next_cursor."}

    def find_codex_threads(self, query="", project_id="", cursor="", limit=10):
        return self._call("find_codex_threads", dict(query=query, project_id=project_id, cursor=cursor, limit=limit))

    def read_codex_thread(self, thread_id, cursor="", limit=20, max_chars=16000,
                          include_tool_refs=False, view="all", turn_id=""):
        return self._call("read_codex_thread", dict(thread_id=thread_id, cursor=cursor, limit=limit,
                         max_chars=max_chars, include_tool_refs=include_tool_refs, view=view, turn_id=turn_id))

    def read_codex_thread_item(self, thread_id, item_id, cursor="", max_chars=12000):
        return self._call("read_codex_thread_item", dict(thread_id=thread_id, item_id=item_id,
                                                       cursor=cursor, max_chars=max_chars))

    def close(self):
        with self._lock:
            self._closed = True
            self._stop("restart_required")
        if threading.current_thread() is not self._monitor:
            self._monitor.join(1)
