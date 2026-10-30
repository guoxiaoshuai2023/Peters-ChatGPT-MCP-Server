"""Bounded process-local original snapshots; no persistent export jobs or database."""
import asyncio
from collections import deque
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import threading
import time

from .catalog import AccessError
from .file_context import ExportActor
from .chunked_export_config import (ChunkedExportConfig, read_chunked_export_config,
    PROTOCOL_VERSION, PART_MAX_BYTES, MAX_CHUNKED_BYTES, PARENT_SECONDS, DELIVERY_SECONDS)
from .file_discovery import FileDiscovery, FileSources, SourceRef
from .private_roots import _directory, _close as _close_protection_fd


PROFILE_ID = 'chatgpt-web-gpt56sol-high-mcp-resource-20261003-v1'
PROFILE_SHA256 = '6b5798e7dfa689c1347bddd5ae957a8d8d3cd4c55f6ce3e90b85ea71969f1e90'
MAX_ORIGINAL_BYTES = 12_659_780
CHUNK = 64 * 1024
SERIALIZATION_BYTES = 128 * 1024 * 1024
TERMINAL = frozenset({'failed', 'expired', 'revoked', 'cancelled'})
PENDING_CLEANUP = frozenset({'source_cleanup_pending', 'protection_cleanup_pending',
                             'identity_cleanup_pending'})
SOURCE_DENIAL = frozenset({'access_denied', 'scope_changed', 'authentication_required',
    'private_protection_unavailable', 'export_disabled', 'export_config_invalid',
    'private_path', 'sensitive_source', 'nested_member_required', 'unsupported_source_type',
    'source_unavailable', 'private_protection_busy', 'file_config_invalid',
    'file_config_changed', 'chunked_export_config_invalid'}) | PENDING_CLEANUP


def _error(code, message='Original export could not complete.'):
    return AccessError(message, code=code)


def _safe_error(error):
    if isinstance(error, AccessError):
        code = error.code
        if isinstance(code, str) and re.fullmatch('[a-z_]{1,64}', code):
            return _error(code)
    if isinstance(error, OSError) and error.errno == errno.ENOSPC:
        return _error('insufficient_space')
    return _error('local_io_failed' if isinstance(error, OSError) else 'internal_error')


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


@dataclass(frozen=True)
class ExportConfig:
    enabled: bool
    spool_root: Path
    max_file_bytes: int = MAX_ORIGINAL_BYTES
    min_free_bytes: int = 1024 * 1024 * 1024
    profile_id: str = PROFILE_ID
    path: Path | None = None

    def validate(self):
        if (type(self.enabled) is not bool or self.profile_id != PROFILE_ID or
                type(self.max_file_bytes) is not int or not 1 <= self.max_file_bytes <= MAX_ORIGINAL_BYTES or
                type(self.min_free_bytes) is not int or self.min_free_bytes < 0):
            raise _error('export_config_invalid')
        path = Path(self.spool_root)
        if not path.is_absolute() or '..' in path.parts or path.resolve() != path or path in (Path('/'), Path.home()):
            raise _error('export_config_invalid')
        return self

    def current(self):
        current = read_export_config(self.path) if self.path is not None else self
        if not current.enabled:
            raise _error('export_disabled')
        if current != self:
            raise _error('scope_changed')
        return hashlib.sha256(_json([self.profile_id, str(self.spool_root),
            self.max_file_bytes, self.min_free_bytes])).hexdigest()


def read_export_config(path):
    """Explicit private configuration only; never creates protection or job state."""
    path = Path(path)
    fd = None
    try:
        path = Path(os.path.abspath(path))
        parent = _directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            _close_protection_fd(parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 65536):
            raise _error('export_config_invalid')
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(fd, min(8192, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if (len(raw) != before.st_size or _version(before) != _version(os.fstat(fd)) or
                _version(before) != _version(path.lstat())):
            raise _error('export_config_invalid')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise _error('export_config_invalid')
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) != {
                'version', 'enabled', 'spool_root', 'profile_id', 'max_file_bytes', 'min_free_bytes'}
                or type(data['version']) is not int or data['version'] != 1):
            raise _error('export_config_invalid')
        return ExportConfig(data['enabled'], Path(data['spool_root']),
            data['max_file_bytes'], data['min_free_bytes'], data['profile_id'], path.resolve()).validate()
    except AccessError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise _error('export_config_invalid') from None
    finally:
        if fd is not None:
            _close_protection_fd(fd)


@dataclass(frozen=True)
class ExportLimits:
    queued: int = 2
    snapshots: int = 8
    actor_snapshots: int = 4
    snapshot_bytes: int = 256 * 1024 * 1024
    actor_snapshot_bytes: int = 128 * 1024 * 1024
    keys: int = 256
    actor_keys: int = 128
    records: int = 256
    actor_records: int = 128
    metadata_bytes: int = 1024 * 1024
    window_seconds: float = 900
    ready_seconds: float = 600
    queue_seconds: float = 30
    preparation_seconds: float = 600
    idle_seconds: float = 30
    transfer_seconds: float = 600
    expiry_grace_seconds: float = 30
    health_seconds: float = 1
    close_seconds: float = 15
    reap_seconds: float = 5


@dataclass
class _Snapshot:
    fd: int
    size: int
    sha256: str
    pins: int = 0
    retired: bool = False
    close_started: bool = False
    close_uncertain: bool = False


@dataclass
class _Slot:
    kind: str
    index: int | None
    offset: int
    size: int
    sha256: str
    resource_name: str
    token: str | None = None
    expires: float = 0
    issued_tokens: int = 0
    actual_reads: int = 0
    active_lease_id: int | None = None
    stream_finished: bool = False


@dataclass
class _Record:
    export_id: str
    actor: ExportActor
    window: str
    intent: str
    source: SourceRef
    expected_sha256: str | None
    accepted: float
    metadata_cost: int
    state: str = 'queued'
    error_code: str | None = None
    prepared_bytes: int = 0
    started: float = 0
    progress_at: float = 0
    ready_at: float = 0
    expires: float = 0
    captured_at: float = 0
    last_used: float = 0
    owner: bool = False
    reserved: bool = True
    snapshot: _Snapshot | None = None
    candidate_fd: int | None = None
    server_stream_finished: bool = False
    delivery_mode: str = 'legacy'
    part_sha256: list = field(default_factory=list)
    plan: dict | None = None
    slots: dict = field(default_factory=dict)
    issued_tokens: int = 0
    issued_delivery_ids: set = field(default_factory=set)
    expires_at_unix: int = 0
    cleanup_error_code: str | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    changed: threading.Event = field(default_factory=threading.Event)


@dataclass
class _MetadataCall:
    actor: ExportActor
    function: object
    future: Future = field(default_factory=Future)
    cancelled: threading.Event = field(default_factory=threading.Event)


class ResourceLease:
    """One whole-resource response, from provisional pin to actual task exit."""
    def __init__(self, service, record, actor, loop, *, slot=None):
        self.service, self.record, self.actor, self.loop = service, record, actor, loop
        self.slot = slot
        self.resource_id = slot.token if slot is not None else record.export_id
        self.read_admitted = False
        self.ready = asyncio.Event()
        self.checked = asyncio.Event()
        self.construction_done = threading.Event()
        self.transport_done = threading.Event()
        self.stop = threading.Event()
        self.payload = None
        self.error_code = None
        self.owner_checked = False
        self.owner_complete = False
        self.asgi_done = False
        self.sdk_done = False
        self.final_body_forwarded = False
        self.safe_error_response = False
        self.released = False
        self.created = service.monotonic()
        self.deadline = min(self.created + service.limits.transfer_seconds,
            record.expires + service.limits.expiry_grace_seconds, actor.deadline)
        if slot is not None:
            self.deadline = min(self.created + service.limits.transfer_seconds,
                                record.expires, slot.expires, actor.deadline)
        self.valid_until = 0.0
        self.last_progress = self.created
        self.stop_at = None

    def notify(self, event):
        try:
            self.loop.call_soon_threadsafe(event.set)
        except RuntimeError:
            self.fail('transfer_interrupted')

    def fail(self, code='transfer_interrupted'):
        with self.service.lock:
            if self.error_code is None:
                self.error_code = code
            if self.stop_at is None:
                self.stop_at = self.service.monotonic()
            self.stop.set()
        self.notify_waiters()

    def notify_waiters(self):
        try:
            self.loop.call_soon_threadsafe(self.ready.set)
            self.loop.call_soon_threadsafe(self.checked.set)
        except RuntimeError:
            pass

    def finish_construction(self, *, failed=False):
        if failed:
            self.fail()
        self.construction_done.set()

    def mark_transport(self, *, asgi=False, sdk=False, final_body=False):
        with self.service.lock:
            self.asgi_done |= asgi
            self.sdk_done |= sdk
            self.final_body_forwarded |= final_body
            if self.asgi_done and self.sdk_done:
                self.transport_done.set()
            self.service._finish_lease_locked(self)

    async def bytes_ready(self):
        await self.ready.wait()
        if self.error_code or self.payload is None:
            raise _error(self.error_code or 'transfer_interrupted')
        return self.payload

    async def wait_checked(self):
        await self.checked.wait()
        if self.error_code or not self.owner_checked:
            raise _error(self.error_code or 'transfer_interrupted')

    async def before_send(self):
        while True:
            now = self.service.monotonic()
            with self.service.lock:
                if self.stop.is_set() or now >= self.deadline:
                    self.fail(self.error_code or 'transfer_interrupted')
                    raise _error(self.error_code)
                if now - self.last_progress > self.service.limits.idle_seconds:
                    self.fail('transfer_interrupted')
                    raise _error('transfer_interrupted')
                fresh = self.owner_checked and now < self.valid_until
            if fresh:
                self.actor.check(wall_clock=self.service.wall_clock, monotonic=self.service.monotonic)
                return
            await asyncio.sleep(.01)

    def sent(self):
        self.last_progress = self.service.monotonic()


class FileExportService:
    """One preparation lane, two metadata owners, one binary-response owner."""
    def __init__(self, catalog, config, *, protected_paths=(), external_reserved=None,
                 limits=None, monotonic=time.monotonic, wall_clock=time.time, fault_hook=None,
                 space_floor=0, infrastructure_config=None, chunked_config=None):
        self.catalog, self.config = catalog, config.validate()
        self.chunked_config = (chunked_config or ChunkedExportConfig()).validate()
        self.chunked_audit = None
        self.registry = catalog._private_registry
        if self.registry is None or not self.config.enabled:
            raise _error('private_protection_unavailable')
        self.monotonic, self.wall_clock = monotonic, wall_clock
        self.limits = limits or ExportLimits()
        self.fault_hook = fault_hook
        self.external_reserved = external_reserved or (lambda: 0)
        self.infrastructure_config = infrastructure_config
        if type(space_floor) is not int or space_floor < 0:
            raise _error('export_config_invalid')
        self.min_free_bytes = max(config.min_free_bytes, space_floor,
            infrastructure_config.min_free_bytes if infrastructure_config is not None else 0)
        self.chunked_min_free_bytes = max(self.min_free_bytes, self.chunked_config.min_free_bytes, 1024 * 1024 * 1024)
        self.lock = threading.RLock()
        self.instance_id = secrets.token_hex(16)
        self._window_generation = 0
        self._window = '0-' + secrets.token_hex(16)
        self._window_started = self.monotonic()
        self._records, self._keys = {}, {}
        self._chunked_keys, self._deliveries, self._issued_deliveries = {}, {}, {}
        self._metadata_actors = set()
        self._metadata_calls = {}
        self._metadata_queue = queue.Queue(maxsize=2)
        self._prepare_queue = deque()
        self._close_queue = deque()
        self._resource_queue = queue.Queue(maxsize=1)
        self._leases = {}
        self._threads = []
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._started = False
        self._closing = False
        self._uncertain_close = False
        self._pending_aux = set()
        self._close_active = None
        self._close_started_at = 0.0
        self._reaper = None
        self._spool_identity = None
        self._written_total = 0
        paths = tuple(protected_paths) + ((config.path,) if config.path is not None else ())
        if self.chunked_config.path is not None:
            paths += (self.chunked_config.path,)
        self.sources = FileSources(catalog, protected_paths=paths, policy_check=self._policy,
            wall_clock=wall_clock, monotonic=monotonic)
        self.discovery = FileDiscovery(self.sources, lock=self.lock, instance_id=self.instance_id,
            monotonic=self.monotonic, capabilities=self.file_capabilities)
        with self.registry.read_guard() as guard:
            guard.revalidate()
            with self._spool_fd(initial=True):
                pass

    def _policy(self):
        if self.infrastructure_config is not None:
            # Reuse the explicit infrastructure identity/limits check. Enabling
            # reads never enables writes, and disabling writes does not revoke reads.
            self.infrastructure_config.sources(require_enabled=False)
        legacy = self.config.current()
        if self.chunked_config.path is not None or self.chunked_config.enabled:
            return hashlib.sha256(_json([legacy, self.chunked_config.current(require_enabled=False)])).hexdigest()
        return legacy

    def _fault(self, stage, value=None):
        if self.fault_hook is not None:
            self.fault_hook(stage, value)

    @contextmanager
    def _spool_fd(self, initial=False):
        fd = _directory(self.config.spool_root)
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _error('private_protection_unavailable')
            if initial:
                registered = self.registry.spool_for(info.st_dev, roots=[self.config.spool_root])
                if registered is None or tuple(registered['identity']) != identity:
                    raise _error('private_protection_unavailable')
                self._spool_identity = identity
            elif identity != self._spool_identity:
                raise _error('private_protection_unavailable')
            yield fd
        finally:
            _close_protection_fd(fd)

    def start(self):
        with self.lock:
            if self._started:
                return
            if self._closing:
                raise _error('export_disabled')
            self._started = True
        functions = [self._prepare_loop, self._metadata_loop, self._metadata_loop, self._resource_loop]
        try:
            for index, function in enumerate(functions):
                thread = threading.Thread(target=function, name=f'original-export-{index}', daemon=True)
                self._threads.append(thread)
                thread.start()
        except BaseException:
            self._closing = True
            self._stop.set()
            self._wake.set()
            raise _error('private_protection_unavailable') from None

    async def start_lifespan(self):
        self.start()
        if self._reaper is None:
            async def reaper():
                while not self._closing:
                    await asyncio.sleep(self.limits.reap_seconds)
                    self.reap()
            self._reaper = asyncio.create_task(reaper())

    def _actor(self, actor):
        if not isinstance(actor, ExportActor):
            raise _error('authentication_required')
        actor.check(wall_clock=self.wall_clock, monotonic=self.monotonic)

    def _admission(self):
        if not self._started or self._closing:
            raise _error('export_disabled')
        now = self.monotonic()
        if (self._uncertain_close or self._pending_aux or
                self._close_active is not None and now - self._close_started_at >= self.limits.close_seconds):
            raise _error('resource_stop_pending')
        if any(lease.stop_at is not None and now - lease.stop_at >= self.limits.close_seconds
               and not lease.released for lease in self._leases.values()):
            raise _error('resource_stop_pending')
        if any(r.owner and r.stop.is_set() and now - r.progress_at >= self.limits.close_seconds
               for r in self._records.values()):
            raise _error('resource_stop_pending')

    async def metadata(self, actor, function):
        self._actor(actor)
        call = _MetadataCall(actor, function)
        with self.lock:
            self._admission()
            if len(self._metadata_calls) >= 2 or actor.key in self._metadata_actors:
                raise _error('busy')
            self._metadata_actors.add(actor.key)
            self._metadata_calls[id(call)] = call
            try:
                self._metadata_queue.put_nowait(call)
            except queue.Full:
                self._metadata_actors.remove(actor.key)
                del self._metadata_calls[id(call)]
                raise _error('busy') from None
        waiting = asyncio.wrap_future(call.future)
        # A cancelled waiter does not claim the actual worker or queued item ended.
        waiting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            return await asyncio.shield(waiting)
        except asyncio.CancelledError:
            call.cancelled.set()
            raise

    def _metadata_loop(self):
        while not self._stop.is_set() or not self._metadata_queue.empty():
            try:
                call = self._metadata_queue.get(timeout=.05)
            except queue.Empty:
                continue
            result = error = None
            try:
                if call.cancelled.is_set() or self._closing:
                    raise _error('export_disabled')
                self._actor(call.actor)
                result = call.function()
            except BaseException as observed:
                error = _safe_error(observed)
            finally:
                call.function = None
                with self.lock:
                    if error is not None and error.code in PENDING_CLEANUP:
                        self._pending_aux.add(('metadata', id(call)))
                    else:
                        self._metadata_calls.pop(id(call), None)
                        self._metadata_actors.discard(call.actor.key)
                if error is None:
                    call.future.set_result(result)
                else:
                    call.future.set_exception(error)
                self._metadata_queue.task_done()

    def _rotate_window_locked(self):
        if self.monotonic() - self._window_started >= self.limits.window_seconds:
            self._window_generation += 1
            self._window = format(self._window_generation, 'x') + '-' + secrets.token_hex(16)
            self._window_started = self.monotonic()
            self._keys.clear()
            self._chunked_keys.clear()
            self._prune_locked()

    def capabilities(self, actor):
        self._actor(actor)
        with self.registry.read_guard() as guard:
            guard.revalidate()
            self._policy()
        with self.lock:
            self._admission()
            self._rotate_window_locked()
            remaining = max(0.0, self.limits.window_seconds - (self.monotonic() - self._window_started))
            return {'service_instance_id': self.instance_id, 'request_window_id': self._window,
                'request_window_remaining_seconds': int(remaining),
                'request_window_expires_at': _iso(self.wall_clock() + remaining),
                'delivery_profile_id': PROFILE_ID, 'max_original_bytes': self.config.max_file_bytes,
                'snapshot_max_seconds': self.limits.ready_seconds,
                'client_ingestion': {'validation': 'verified_profile', 'model': 'GPT-5.6 Sol',
                    'mode': 'Chat', 'reasoning_effort': 'High', 'verified_mime_types': ['application/zip'],
                    'pro_compatibility': 'not_tested'}}

    def file_capabilities(self, source):
        supported = source.size <= self.config.max_file_bytes
        return {'original_export_supported': supported,
            'original_export_reason': None if supported else 'client_ingestion_unverified',
            'max_original_bytes': self.config.max_file_bytes,
            'client_ingestion': {'validation': 'verified_profile' if source.mime_type == 'application/zip'
                else 'format_not_tested', 'delivery_profile_id': PROFILE_ID}}

    async def find_files(self, actor, project_id, worktree_id, **query):
        return await self.metadata(actor, lambda: self.discovery.find(actor, project_id, worktree_id, **query))

    def _window_check_locked(self, instance, window):
        self._rotate_window_locked()
        if instance != self.instance_id:
            raise _error('instance_changed')
        if window != self._window:
            raise _error('request_window_expired')

    @staticmethod
    def _intent(project_id, worktree_id, path, request_key, expected_sha256):
        if (not isinstance(project_id, str) or not 1 <= len(project_id) <= 128 or
                not isinstance(worktree_id, str) or not 1 <= len(worktree_id) <= 128 or
                not isinstance(path, str) or not 1 <= len(path) <= 4096 or
                not isinstance(request_key, str) or not 1 <= len(request_key) <= 128 or
                any(ord(c) < 32 or ord(c) == 127 for c in request_key)):
            raise _error('invalid_argument')
        if expected_sha256 is not None and (not isinstance(expected_sha256, str) or
                re.fullmatch('[a-f0-9]{64}', expected_sha256) is None):
            raise _error('invalid_expected_hash')
        return hashlib.sha256(_json([PROFILE_ID, project_id, worktree_id, path, expected_sha256])).hexdigest()

    def _usage_locked(self, actor=None):
        rows = [r for r in self._records.values() if r.reserved and (actor is None or r.actor.key == actor)]
        return len(rows), sum(r.source.size for r in rows)

    def _unwritten_locked(self):
        return sum(max(0, r.source.size - r.prepared_bytes) for r in self._records.values() if r.reserved
                   and (r.state in {'queued', 'preparing'} or r.owner))

    def _space(self, additional=0, *, chunked=False):
        with self.lock:
            written_at_start = self._written_total
        with self._spool_fd() as fd:
            space = os.fstatvfs(fd)
            free = space.f_bavail * space.f_frsize
        try:
            outside = self.external_reserved()
        except Exception:
            raise _error('insufficient_space') from None
        if outside is None:
            raise _error('busy', 'Existing file work has an unknown space reservation.')
        if type(outside) is not int or outside < 0:
            raise _error('insufficient_space')
        with self.lock:
            unwritten = self._unwritten_locked()
            spent = self._written_total - written_at_start
        if free - spent - unwritten - additional - outside < (self.chunked_min_free_bytes if chunked else self.min_free_bytes):
            raise _error('insufficient_space')
        return free - outside, written_at_start

    def _retire_locked(self, record, state, code):
        if record.state not in TERMINAL or state == 'revoked':
            record.state, record.error_code = state, code
        record.stop.set()
        record.changed.set()
        if record.snapshot is not None:
            record.snapshot.retired = True
            self._queue_close_locked(record)
        elif not record.owner:
            record.reserved = False
        for lease in self._leases.values():
            if lease.record is record:
                lease.fail(code)
        self._wake.set()

    def _queue_close_locked(self, record):
        snapshot = record.snapshot
        if (snapshot is not None and snapshot.retired and not snapshot.pins and
                not snapshot.close_started and not snapshot.close_uncertain):
            snapshot.close_started = True
            self._close_queue.append(record)

    def _prune_locked(self):
        indexed = {entry[1] for entry in list(self._keys.values()) + list(self._chunked_keys.values())}
        for export_id, record in list(self._records.items()):
            # The 1h parent outlives its 900s request window. Retain bounded
            # terminal metadata for a fixed additional delivery interval so
            # cancel/status can report actual cleanup after key rotation.
            if record.delivery_mode == PROTOCOL_VERSION and self.monotonic() < record.expires + DELIVERY_SECONDS:
                continue
            if (export_id not in indexed and record.state in TERMINAL and not record.reserved
                    and not record.owner and not any(x.record is record for x in self._leases.values())):
                for token in record.issued_delivery_ids:
                    self._deliveries.pop(token, None)
                    self._issued_deliveries.pop(token, None)
                del self._records[export_id]

    def _reserve_locked(self, actor, source, metadata_cost):
        self._prune_locked()
        actor_rows = [r for r in self._records.values() if r.actor.key == actor.key]
        if (len(self._records) >= self.limits.records or len(actor_rows) >= self.limits.actor_records
                or sum(r.metadata_cost for r in self._records.values()) + metadata_cost > self.limits.metadata_bytes):
            raise _error('resource_budget_exhausted')
        keys = list(self._keys) + list(self._chunked_keys)
        if len(keys) >= self.limits.keys or sum(k[0] == actor.key for k in keys) >= self.limits.actor_keys:
            raise _error('resource_budget_exhausted')
        if any(r.actor.key == actor.key and (r.owner or r.state in {'queued', 'preparing'}) for r in self._records.values()):
            raise _error('busy')
        if sum(r.state == 'queued' for r in self._prepare_queue) >= self.limits.queued:
            raise _error('busy')
        def fits():
            count, size = self._usage_locked()
            actor_count, actor_size = self._usage_locked(actor.key)
            return (count < self.limits.snapshots and actor_count < self.limits.actor_snapshots and
                size + source.size <= self.limits.snapshot_bytes and
                actor_size + source.size <= self.limits.actor_snapshot_bytes)
        if not fits():
            # Retirement is asynchronous; the caller retries after actual FD close.
            actor_count, actor_size = self._usage_locked(actor.key)
            actor_full = (actor_count >= self.limits.actor_snapshots or
                          actor_size + source.size > self.limits.actor_snapshot_bytes)
            candidates = sorted((r for r in self._records.values() if r.state == 'ready' and
                r.snapshot is not None and not r.snapshot.pins and
                (not actor_full or r.actor.key == actor.key)), key=lambda r: r.last_used)
            if candidates:
                self._retire_locked(candidates[0], 'expired', 'resource_budget_exhausted')
            raise _error('busy' if candidates else 'resource_budget_exhausted')

    def _accept(self, actor, project_id, worktree_id, path, instance, window, key, expected, *, chunked=False):
        intent = self._intent(project_id, worktree_id, path, key, expected)
        keys = self._chunked_keys if chunked else self._keys
        if chunked:
            config_digest = self.chunked_config.current()
            intent = hashlib.sha256(_json([PROTOCOL_VERSION, project_id, worktree_id, path,
                                          expected, PART_MAX_BYTES, config_digest])).hexdigest()
        with self.lock:
            self._admission()
            self._window_check_locked(instance, window)
            previous = keys.get((actor.key, window, key))
            if previous is not None and previous[0] != intent:
                raise _error('idempotency_conflict')
        space = None
        try:
            with self.sources.scope(actor, project_id, worktree_id) as scope:
                source = scope.inspect(path)
                if previous is not None:
                    with self.lock:
                        self._admission()
                        self._window_check_locked(instance, window)
                        record = self._records.get(previous[1])
                        if record is None:
                            return {'export_id': previous[1], 'state': previous[2] or 'expired'}
                        if source.scope_key != record.source.scope_key:
                            self._retire_locked(record, 'revoked', 'scope_changed')
                        if record.state == 'ready' and self.monotonic() >= record.expires:
                            self._retire_locked(record, 'expired', 'export_expired')
                        # Context exit performs the final source/guard check
                        # after metadata construction, before this can return.
                        return self._status_locked(record)
                if previous is None and source.size > (self.chunked_config.max_file_bytes if chunked else self.config.max_file_bytes):
                    raise _error('client_ingestion_unverified')
                if previous is None:
                    space = self._space(source.size, chunked=chunked)
        except AccessError as error:
            if chunked and error.code == 'authentication_required':
                raise
            if previous is not None and error.code in SOURCE_DENIAL:
                with self.lock:
                    old = self._records.get(previous[1])
                    if old is not None:
                        self._retire_locked(old, 'revoked', 'scope_changed')
                        if error.code not in PENDING_CLEANUP:
                            return self._status_locked(old)
            raise
        cost = len(_json([source.public(), project_id, worktree_id, path, expected, actor.key, intent])) + 1536
        if chunked:
            cost += 4096 + 1024 * max(1, (source.size + PART_MAX_BYTES - 1) // PART_MAX_BYTES) + 48 * 1024
        with self.lock:
            self._admission()
            self._window_check_locked(instance, window)
            previous = keys.get((actor.key, window, key))
            if previous is not None:
                if previous[0] != intent:
                    raise _error('idempotency_conflict')
                # The normal per-actor metadata admission prevents this race.
                # A direct internal competitor must retry through a fresh guard.
                raise _error('busy')
            if (space is None or space[0] - (self._written_total - space[1])
                    - self._unwritten_locked() - source.size < (self.chunked_min_free_bytes if chunked else self.min_free_bytes)):
                raise _error('insufficient_space')
            if chunked and any(r.delivery_mode == PROTOCOL_VERSION and r.actor.key == actor.key
                               and r.reserved for r in self._records.values()):
                raise _error('busy')
            self._reserve_locked(actor, source, cost)
            now = self.monotonic()
            export_id = None
            for _ in range(8):
                proposed = secrets.token_hex(16)
                if proposed not in self._records and proposed not in self._issued_deliveries:
                    export_id = proposed
                    break
            if export_id is None:
                raise _error('busy')
            record = _Record(export_id, actor, window, intent, source, expected, now, cost,
                             progress_at=now, delivery_mode=PROTOCOL_VERSION if chunked else 'legacy')
            if chunked:
                record.expires = now + PARENT_SECONDS
                record.expires_at_unix = int(self.wall_clock() + PARENT_SECONDS)
            self._records[record.export_id] = record
            keys[(actor.key, window, key)] = (intent, record.export_id, None)
            self._prepare_queue.append(record)
            self._wake.set()
            return self._status_locked(record)

    async def export_file(self, actor, project_id, worktree_id, path, service_instance_id,
                          request_window_id, request_key, expected_sha256=None, *, wait_seconds=1.0):
        result = await self.metadata(actor, lambda: self._accept(actor, project_id, worktree_id, path,
            service_instance_id, request_window_id, request_key, expected_sha256))
        if result['state'] in {'queued', 'preparing'} and wait_seconds > 0:
            deadline = self.monotonic() + min(1.0, wait_seconds)
            while self.monotonic() < deadline:
                with self.lock:
                    record = self._records.get(result['export_id'])
                    complete = record is None or record.state not in {'queued', 'preparing'}
                if complete:
                    return await self.get_status(actor, result['export_id'])
                await asyncio.sleep(.01)
        return result

    def _owned_locked(self, actor, export_id, *, mode='legacy'):
        if not isinstance(export_id, str) or re.fullmatch('[a-f0-9]{32}', export_id) is None:
            raise _error('export_unavailable')
        record = self._records.get(export_id)
        if record is None or record.actor.key != actor.key or record.delivery_mode != mode:
            raise _error('export_unavailable')
        return record

    def _status_locked(self, record):
        if record.delivery_mode == PROTOCOL_VERSION:
            return self._chunked_status_locked(record)
        result = {'export_id': record.export_id, 'state': record.state, 'client_received': 'not_observed'}
        if record.state == 'preparing':
            result['prepared_bytes'] = record.prepared_bytes
        if record.error_code is not None:
            result['error_code'] = record.error_code
        if record.state == 'ready' and record.snapshot is not None and not record.snapshot.retired:
            result.update(source=record.source.public(), bytes=record.snapshot.size,
                sha256=record.snapshot.sha256, captured_at=_iso(record.captured_at),
                expires_in_seconds=max(0, int(record.expires - self.monotonic())),
                expires_at=_iso(self.wall_clock() + max(0, record.expires - self.monotonic())),
                may_expire_early=True, resource_uri='peters-export://' + record.export_id,
                delivery_profile_id=PROFILE_ID, server_stream_finished=record.server_stream_finished)
        return result

    def _current_source(self, scope, record, *, version=False):
        current = scope.inspect(record.source.path)
        if current.scope_key != record.source.scope_key:
            raise _error('scope_changed')
        if version and current.version != record.source.version:
            raise _error('source_changed')
        return current

    def _get_status(self, actor, export_id, *, mode='legacy'):
        with self.lock:
            record = self._owned_locked(actor, export_id, mode=mode)
        if mode == PROTOCOL_VERSION:
            self.chunked_config.current()
        try:
            with self.sources.scope(actor, record.source.project_id, record.source.worktree_id) as scope:
                self._current_source(scope, record)
                with self.lock:
                    if record.state == 'ready' and self.monotonic() >= record.expires:
                        self._retire_locked(record, 'expired', 'export_expired')
                    return self._status_locked(record)
        except AccessError as error:
            if mode == PROTOCOL_VERSION and error.code == 'authentication_required':
                raise
            with self.lock:
                self._retire_locked(record, 'revoked', 'scope_changed')
            if error.code in PENDING_CLEANUP:
                raise
            with self.lock:
                return self._status_locked(record)

    async def get_status(self, actor, export_id):
        self._actor(actor)
        with self.lock:
            if self._closing or self._uncertain_close or self._pending_aux:
                record = self._owned_locked(actor, export_id)
                return {'export_id': export_id, 'state': record.state,
                    'operation_state': 'shutdown_pending', 'error_code': 'resource_stop_pending',
                    'client_received': 'not_observed'}
        return await self.metadata(actor, lambda: self._get_status(actor, export_id))

    def chunked_capabilities(self, actor):
        self._actor(actor)
        with self.registry.read_guard() as guard:
            guard.revalidate()
            self._policy()
        with self.lock:
            self._admission()
        value = {'enabled': self.chunked_config.enabled, 'protocol_version': PROTOCOL_VERSION,
                 'configured_max_file_bytes': self.chunked_config.max_file_bytes,
                 'part_max_bytes': PART_MAX_BYTES,
                 'validation': 'requires_per_transfer_native_verification'}
        if self.chunked_config.enabled:
            from .transport_asset import receiver_metadata
            value['receiver_asset'] = receiver_metadata()
        return value

    def _part_hashes(self, record, fd, size, checkpoint, expected_sha256):
        hashes, whole = [], hashlib.sha256()
        for index in range(max(1, (size + PART_MAX_BYTES - 1) // PART_MAX_BYTES)):
            offset, remaining = index * PART_MAX_BYTES, min(PART_MAX_BYTES, max(0, size - index * PART_MAX_BYTES))
            digest = hashlib.sha256()
            while remaining:
                checkpoint()
                block = os.pread(fd, min(CHUNK, remaining), offset)
                if not block:
                    raise _error('snapshot_hash_mismatch')
                # Progress is the successful real read, not a plan/status poll.
                # A read returning after an expired idle/absolute deadline does
                # not retroactively renew that deadline.
                now = self.monotonic()
                with self.lock:
                    if (not record.owner or record.state != 'preparing' or record.stop.is_set()):
                        raise _error(record.error_code or 'preparation_interrupted')
                    if (now - record.started >= self.limits.preparation_seconds
                            or now - record.progress_at >= self.limits.idle_seconds):
                        raise _error('preparation_timeout')
                    record.progress_at = now
                digest.update(block)
                whole.update(block)
                offset += len(block)
                remaining -= len(block)
            hashes.append(digest.hexdigest())
        if whole.hexdigest() != expected_sha256:
            raise _error('snapshot_hash_mismatch')
        return hashes

    def _make_chunked_plan(self, record, snapshot):
        from .transport_asset import receiver_metadata
        asset = receiver_metadata()
        if (set(asset) != {'asset_id', 'name', 'bytes', 'sha256'}
                or type(asset['bytes']) is not int or not 0 < asset['bytes'] <= PART_MAX_BYTES):
            raise _error('receiver_asset_invalid')
        parts = []
        for index, digest in enumerate(record.part_sha256):
            offset = index * PART_MAX_BYTES
            parts.append({'index': index, 'offset': offset,
                          'bytes': min(PART_MAX_BYTES, max(0, record.source.size - offset)),
                          'sha256': digest,
                          'resource_name': 'original-' + record.export_id + '-part-' + str(index).zfill(4) + '.samplebin'})
        captured = {'protocol': PROTOCOL_VERSION, 'scope_key': record.source.scope_key,
                    'version': list(record.source.version), 'bytes': record.source.size,
                    'sha256': snapshot.sha256}
        plan = {'protocol_version': PROTOCOL_VERSION, 'service_instance_id': self.instance_id,
                'export_id': record.export_id,
                'source': {'project_id': record.source.project_id, 'worktree_id': record.source.worktree_id,
                           'path': record.source.path},
                'capture_version_sha256': hashlib.sha256(_json(captured)).hexdigest(),
                'total_bytes': record.source.size, 'total_sha256': snapshot.sha256,
                'part_max_bytes': PART_MAX_BYTES, 'part_count': len(parts), 'parts': parts,
                'receiver_asset': asset, 'expires_at_unix': record.expires_at_unix}
        plan['plan_sha256'] = hashlib.sha256(_json(plan)).hexdigest()
        if len(_json(plan)) > 65536 or len(parts) > 13:
            raise _error('resource_budget_exhausted')
        return plan

    def _chunked_status_locked(self, record, *, details=True):
        released = (not record.reserved and not record.owner and not self._pending_aux
                    and not any(lease.record is record for lease in self._leases.values())
                    and not any(kind == 'prepare' and value == record.export_id for kind, value in self._pending_aux))
        value = {'export_id': record.export_id, 'state': record.state,
                 'delivery_mode': PROTOCOL_VERSION, 'client_received': 'not_observed',
                 'resources_released': released,
                 'cleanup': {'snapshot_reserved': record.reserved, 'prepare_owner': record.owner,
                             'active_responses': sum(lease.record is record for lease in self._leases.values()),
                             'snapshot_fd_open': bool(record.snapshot is not None and record.snapshot.fd >= 0),
                             'snapshot_close_uncertain': bool(record.snapshot is not None and record.snapshot.close_uncertain)}}
        if record.error_code is not None:
            value['error_code'] = record.error_code
        if record.cleanup_error_code is not None:
            value['cleanup']['error_code'] = record.cleanup_error_code
        if record.state == 'preparing':
            value['prepared_bytes'] = record.prepared_bytes
        if details and record.state == 'ready' and record.snapshot is not None and not record.snapshot.retired:
            value.update(source=record.source.public(), bytes=record.snapshot.size,
                         sha256=record.snapshot.sha256, captured_at=_iso(record.captured_at),
                         expires_at_unix=record.expires_at_unix,
                         expires_in_seconds=max(0, int(record.expires - self.monotonic())),
                         plan_sha256=record.plan['plan_sha256'],
                         server_stream_finished=record.server_stream_finished,
                         slots=[{'kind': slot.kind, 'index': slot.index,
                                 'issued_tokens': slot.issued_tokens, 'actual_reads': slot.actual_reads,
                                 'reading_or_draining': slot.active_lease_id is not None,
                                 'server_stream_finished': slot.stream_finished}
                                for slot in record.slots.values()])
        return value

    async def prepare_chunked_export(self, actor, project_id, worktree_id, path, service_instance_id,
                                     request_window_id, request_key, expected_sha256=None, *, wait_seconds=1.0):
        result = await self.metadata(actor, lambda: self._accept(actor, project_id, worktree_id, path,
            service_instance_id, request_window_id, request_key, expected_sha256, chunked=True))
        if result['state'] in {'queued', 'preparing'} and wait_seconds > 0:
            deadline = self.monotonic() + min(1.0, wait_seconds)
            while self.monotonic() < deadline:
                with self.lock:
                    record = self._records.get(result['export_id'])
                    complete = record is None or record.state not in {'queued', 'preparing'}
                if complete:
                    return await self.get_chunked_export_status(actor, result['export_id'])
                await asyncio.sleep(.01)
        return result

    async def get_chunked_export_status(self, actor, export_id):
        self._actor(actor)
        with self.lock:
            record = self._owned_locked(actor, export_id, mode=PROTOCOL_VERSION)
            if self._closing or self._uncertain_close or self._pending_aux:
                value = self._chunked_status_locked(record, details=False)
                value.update(operation_state='shutdown_pending', operation_error_code='resource_stop_pending')
                value.setdefault('error_code', 'resource_stop_pending')
                return value
            if record.state == 'cancelled':
                return self._chunked_status_locked(record)
        return await self.metadata(actor, lambda: self._get_status(actor, export_id, mode=PROTOCOL_VERSION))

    def _chunked_plan(self, actor, export_id):
        result = self._get_status(actor, export_id, mode=PROTOCOL_VERSION)
        if result['state'] != 'ready':
            return result
        with self.lock:
            record = self._owned_locked(actor, export_id, mode=PROTOCOL_VERSION)
            if record.state != 'ready' or record.snapshot is None or record.snapshot.retired:
                raise _error('export_unavailable')
            return {'export_id': export_id, 'state': 'ready', 'client_received': 'not_observed',
                    'plan': json.loads(_json(record.plan))}

    async def get_chunked_export_plan(self, actor, export_id):
        return await self.metadata(actor, lambda: self._chunked_plan(actor, export_id))

    def _chunked_materialize(self, actor, export_id, part_index=None, *, receiver=False):
        self.chunked_config.current()
        with self.lock:
            record = self._owned_locked(actor, export_id, mode=PROTOCOL_VERSION)
        try:
            with self.sources.scope(actor, record.source.project_id, record.source.worktree_id) as scope:
                self._current_source(scope, record)
                with self.lock:
                    self._admission()
                    if record.state == 'ready' and self.monotonic() >= record.expires:
                        self._retire_locked(record, 'expired', 'export_expired')
                    if record.state != 'ready' or record.snapshot is None or record.snapshot.retired:
                        raise _error('export_unavailable')
                    if receiver:
                        item = record.plan['receiver_asset']
                        key, kind, index, offset = 'receiver', 'receiver', None, 0
                        size, digest, name = item['bytes'], item['sha256'], item['name']
                    else:
                        if type(part_index) is not int or not 0 <= part_index < record.plan['part_count']:
                            raise _error('invalid_part_index')
                        item = record.plan['parts'][part_index]
                        key, kind, index, offset = 'part-' + str(part_index), 'part', part_index, item['offset']
                        size, digest, name = item['bytes'], item['sha256'], item['resource_name']
                    slot = record.slots.get(key)
                    if slot is None:
                        if len(record.slots) >= record.plan['part_count'] + 1:
                            raise _error('resource_budget_exhausted')
                        slot = record.slots[key] = _Slot(kind, index, offset, size, digest, name)
                    if slot.active_lease_id is not None:
                        raise _error('busy')
                    if slot.actual_reads >= 3:
                        raise _error('retry_limit_exceeded')
                    if slot.token is None or self.monotonic() >= slot.expires:
                        if slot.issued_tokens >= 3:
                            raise _error('retry_limit_exceeded')
                        if record.issued_tokens >= 48:
                            raise _error('resource_budget_exhausted')
                        token = None
                        for _ in range(8):
                            proposed = secrets.token_hex(16)
                            if proposed not in self._records and proposed not in self._issued_deliveries:
                                token = proposed
                                break
                        if token is None:
                            raise _error('busy')
                        if slot.token is not None:
                            self._deliveries.pop(slot.token, None)
                        slot.token = token
                        slot.expires = min(self.monotonic() + DELIVERY_SECONDS, record.expires)
                        slot.issued_tokens += 1
                        record.issued_tokens += 1
                        self._deliveries[token] = (record.export_id, key)
                        self._issued_deliveries[token] = record.export_id
                        record.issued_delivery_ids.add(token)
                    return {'export_id': record.export_id, 'state': 'ready', 'delivery_mode': PROTOCOL_VERSION,
                            'kind': kind, 'part_index': index, 'offset': offset, 'bytes': size,
                            'sha256': digest, 'resource_uri': 'peters-chunk://' + slot.token,
                            'resource_name': name, 'resource_mime_type': 'application/octet-stream',
                            'client_received': 'not_observed',
                            'expires_in_seconds': max(0, int(slot.expires - self.monotonic()))}
        except AccessError as error:
            if error.code in SOURCE_DENIAL and error.code != 'authentication_required':
                with self.lock:
                    self._retire_locked(record, 'revoked', error.code)
            raise

    async def materialize_chunked_export_part(self, actor, export_id, part_index):
        return await self.metadata(actor, lambda: self._chunked_materialize(actor, export_id, part_index))

    async def materialize_chunked_export_receiver(self, actor, export_id):
        return await self.metadata(actor, lambda: self._chunked_materialize(actor, export_id, receiver=True))

    async def cancel_chunked_export(self, actor, export_id):
        # Cancellation can still stop this actor's own work when general admission
        # is closed. It does not open a source or grant access to old metadata.
        self._actor(actor)
        with self.lock:
            record = self._owned_locked(actor, export_id, mode=PROTOCOL_VERSION)
            if record.state not in TERMINAL:
                self._retire_locked(record, 'cancelled', 'cancelled')
            return self._chunked_status_locked(record)

    def open_chunked_resource(self, actor, delivery_id, loop):
        self._actor(actor)
        with self.lock:
            self._admission()
            if not isinstance(delivery_id, str) or re.fullmatch('[a-f0-9]{32}', delivery_id) is None:
                raise _error('export_unavailable')
            found = self._deliveries.get(delivery_id)
            if found is None:
                raise _error('export_unavailable')
            record = self._owned_locked(actor, found[0], mode=PROTOCOL_VERSION)
            slot = record.slots.get(found[1])
            if slot is None or slot.token != delivery_id:
                raise _error('export_unavailable')
            if record.state == 'ready' and self.monotonic() >= record.expires:
                self._retire_locked(record, 'expired', 'export_expired')
            if (record.state != 'ready' or record.snapshot is None or record.snapshot.retired
                    or self.monotonic() >= slot.expires):
                raise _error('export_unavailable')
            if self._leases or slot.active_lease_id is not None:
                raise _error('busy')
            if slot.actual_reads >= 3:
                raise _error('retry_limit_exceeded')
            lease = ResourceLease(self, record, actor, loop, slot=slot)
            self._leases[id(lease)] = lease
            slot.active_lease_id = id(lease)
            record.snapshot.pins += 1
            try:
                self._resource_queue.put_nowait(lease)
            except queue.Full:
                slot.active_lease_id = None
                record.snapshot.pins -= 1
                del self._leases[id(lease)]
                raise _error('busy') from None
            return lease


    def _checkpoint(self, record, scope, *, source_version=True, force=False):
        now = self.monotonic()
        if record.stop.is_set() or self._closing:
            raise _error(record.error_code or 'preparation_interrupted')
        if record.delivery_mode == PROTOCOL_VERSION and now >= record.expires:
            raise _error('export_expired')
        if now - record.started >= self.limits.preparation_seconds or now - record.progress_at >= self.limits.idle_seconds:
            raise _error('preparation_timeout')
        self._actor(record.actor)
        if force or now >= getattr(record, '_next_check', 0):
            scope.revalidate()
            self._current_source(scope, record, version=source_version)
            self._space(chunked=record.delivery_mode == PROTOCOL_VERSION)
            record._next_check = self.monotonic() + self.limits.health_seconds

    def _anonymous(self, record):
        with self._spool_fd() as parent:
            name = '.original-export-' + secrets.token_hex(16)
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            # Ownership is visible before leaving the parent-FD context: its
            # cleanup may fail after the return value has been evaluated.
            record.candidate_fd = fd
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                    raise _error('private_protection_unavailable')
                # No body is written while a name is visible.
                os.unlink(name, dir_fd=parent)
                if os.fstat(fd).st_nlink != 0:
                    raise _error('private_protection_unavailable')
                return fd
            except BaseException:
                try:
                    os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass
                raise

    def _prepare_loop(self):
        while True:
            record = close = None
            with self.lock:
                if self._close_queue:
                    close = self._close_queue.popleft()
                    self._close_active = close
                    self._close_started_at = self.monotonic()
                else:
                    while self._prepare_queue:
                        candidate = self._prepare_queue.popleft()
                        if candidate.state == 'queued' and not candidate.stop.is_set():
                            record = candidate
                            record.owner = True
                            record.state = 'preparing'
                            record.started = record.progress_at = self.monotonic()
                            break
                if (record is None and close is None and self._stop.is_set()
                        and not self._leases):
                    return
            if close is not None:
                self._close_snapshot(close)
            elif record is not None:
                self._prepare(record)
            else:
                self._wake.wait(.05)
                self._wake.clear()

    def _prepare(self, record):
        snapshot = None
        fd = None
        failure = None
        handed_off = False
        try:
            self._fault('before_prepare', record)
            with self.sources.scope(record.actor, record.source.project_id, record.source.worktree_id) as scope:
                self._checkpoint(record, scope, force=True)
                with scope.open_file(record.source.path) as source:
                    if _version(os.fstat(source)) != record.source.version:
                        raise _error('source_changed')
                    fd = self._anonymous(record)
                    self._fault('anonymous_unlinked', (record, fd))
                    digest, offset = hashlib.sha256(), 0
                    while offset < record.source.size:
                        self._checkpoint(record, scope)
                        data = os.pread(source, min(CHUNK, record.source.size - offset), offset)
                        if not data:
                            raise _error('source_changed')
                        if record.stop.is_set():
                            raise _error('preparation_interrupted')
                        self._fault('copy_chunk', record)
                        written = 0
                        while written < len(data):
                            count = os.write(fd, data[written:])
                            if count <= 0:
                                raise _error('local_io_failed')
                            written += count
                            with self.lock:
                                self._written_total += count
                        digest.update(data)
                        offset += len(data)
                        with self.lock:
                            record.prepared_bytes = offset
                            record.progress_at = self.monotonic()
                    data = None
                    self._checkpoint(record, scope, force=True)
                    if _version(os.fstat(source)) != record.source.version:
                        raise _error('source_changed')
                    actual = digest.hexdigest()
                    if record.expected_sha256 is not None and actual != record.expected_sha256:
                        raise _error('expected_hash_mismatch')
                    self._fault('before_snapshot_sync', record)
                    os.fsync(fd)
                    reread, offset = hashlib.sha256(), 0
                    while offset < record.source.size:
                        self._checkpoint(record, scope)
                        block = os.pread(fd, min(CHUNK, record.source.size - offset), offset)
                        if not block:
                            raise _error('local_io_failed')
                        reread.update(block)
                        offset += len(block)
                        record.progress_at = self.monotonic()
                    block = None
                    if reread.hexdigest() != actual or os.fstat(fd).st_size != record.source.size:
                        raise _error('snapshot_hash_mismatch')
                    self._checkpoint(record, scope, force=True)
                    if record.delivery_mode == PROTOCOL_VERSION:
                        record.part_sha256 = self._part_hashes(record, fd, record.source.size,
                            lambda: self._checkpoint(record, scope), actual)
                        self._checkpoint(record, scope, force=True)
                    snapshot = _Snapshot(fd, record.source.size, actual)
            # Construct immutable metadata before ownership handoff. A failed
            # helper/plan check must leave the preparation owner closing its FD.
            plan = self._make_chunked_plan(record, snapshot) if record.delivery_mode == PROTOCOL_VERSION else None
            # A successful guard exit is a prerequisite for publishing ready.
            self._fault('before_ready', record)
            with self.lock:
                if (self._closing or record.stop.is_set() or record.state != 'preparing'
                        or not record.owner):
                    raise _error('preparation_interrupted')
                now = self.monotonic()
                if record.delivery_mode == PROTOCOL_VERSION and now >= record.expires:
                    raise _error('export_expired')
                expires = now + self.limits.ready_seconds if record.delivery_mode == 'legacy' else record.expires
                captured_at = self.wall_clock()
                # All calls and rejection points precede ownership publication.
                # Waiters acquire this same lock before observing the ready row.
                record.changed.set()
                record.ready_at = record.last_used = now
                record.expires = expires
                record.captured_at = captured_at
                if record.delivery_mode == PROTOCOL_VERSION:
                    record.plan = plan
                record.snapshot = snapshot
                record.candidate_fd = None
                fd = None
                handed_off = True
                record.state = 'ready'
        except BaseException as observed:
            failure = _safe_error(observed)
        finally:
            if not handed_off and fd is None:
                fd = record.candidate_fd
            if not handed_off and fd is not None:
                # The preparation worker is the unique owner until handoff.
                try:
                    self._fault('before_snapshot_close', fd)
                    os.close(fd)
                    if snapshot is not None:
                        snapshot.fd = -1
                except BaseException:
                    with self.lock:
                        record.snapshot = snapshot or _Snapshot(fd, record.source.size, '')
                        record.snapshot.retired = True
                        record.snapshot.close_uncertain = True
                        self._uncertain_close = True
                    failure = _error('snapshot_close_pending')
                finally:
                    record.candidate_fd = None
            with self.lock:
                record.owner = False
                if failure is not None:
                    if failure.code in PENDING_CLEANUP:
                        self._pending_aux.add(('prepare', record.export_id))
                    if record.state != 'cancelled':
                        record.state = 'revoked' if failure.code in SOURCE_DENIAL else 'failed'
                        record.error_code = failure.code
                    if failure.code in PENDING_CLEANUP or failure.code == 'snapshot_close_pending':
                        record.cleanup_error_code = failure.code
                    record.stop.set()
                    if handed_off and record.snapshot is not None:
                        record.snapshot.retired = True
                        self._queue_close_locked(record)
                    if record.snapshot is None and failure.code not in PENDING_CLEANUP:
                        record.reserved = False
                record.changed.set()
                self._wake.set()

    def _close_snapshot(self, record):
        snapshot = record.snapshot
        try:
            if snapshot is None or snapshot.pins:
                raise _error('snapshot_close_pending')
            self._fault('before_snapshot_close', snapshot.fd)
            os.close(snapshot.fd)
        except BaseException:
            with self.lock:
                if snapshot is not None:
                    snapshot.close_uncertain = True
                self._uncertain_close = True
        else:
            with self.lock:
                snapshot.fd = -1
                record.reserved = False
                if record.delivery_mode == PROTOCOL_VERSION and self.chunked_audit is not None:
                    self.chunked_audit('chunked_snapshot_closed', True,
                        value={'export_id': record.export_id, 'plan_sha256': (record.plan or {}).get('plan_sha256'),
                               'resources_released': self._chunked_status_locked(record)['resources_released']})
                self._prune_locked()
        finally:
            with self.lock:
                self._close_active = None
                self._wake.set()

    def open_resource(self, actor, export_id, loop):
        self._actor(actor)
        with self.lock:
            self._admission()
            record = self._owned_locked(actor, export_id)
            if record.state == 'ready' and self.monotonic() >= record.expires:
                self._retire_locked(record, 'expired', 'export_expired')
            if record.state != 'ready' or record.snapshot is None or record.snapshot.retired:
                raise _error('export_unavailable')
            if self._leases:
                raise _error('busy')
            lease = ResourceLease(self, record, actor, loop)
            self._leases[id(lease)] = lease
            record.snapshot.pins += 1
            try:
                self._resource_queue.put_nowait(lease)
            except queue.Full:
                record.snapshot.pins -= 1
                del self._leases[id(lease)]
                raise _error('busy') from None
            return lease

    def _lease_check(self, lease, scope, *, force=False):
        now = self.monotonic()
        if lease.stop.is_set() or self._closing or now >= lease.deadline:
            raise _error(lease.error_code or 'transfer_interrupted')
        self._actor(lease.actor)
        if force or now >= lease.valid_until:
            scope.revalidate()
            self._current_source(scope, lease.record)
            with self.lock:
                if lease.record.state != 'ready' or lease.record.snapshot.retired:
                    raise _error('export_unavailable')
                lease.valid_until = min(self.monotonic() + self.limits.health_seconds, lease.deadline)

    def _resource_loop(self):
        while not self._stop.is_set() or not self._resource_queue.empty():
            try:
                lease = self._resource_queue.get(timeout=.05)
            except queue.Empty:
                continue
            self._resource_owner(lease)
            self._resource_queue.task_done()

    def _resource_owner(self, lease):
        chunks = []
        payload = None
        record = lease.record
        try:
            with self.sources.scope(lease.actor, record.source.project_id, record.source.worktree_id) as scope:
                self._lease_check(lease, scope, force=True)
                snapshot = record.snapshot
                info = os.fstat(snapshot.fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or
                        info.st_size != snapshot.size or snapshot.size > (
                            self.chunked_config.max_file_bytes if lease.slot is not None else self.config.max_file_bytes)):
                    raise _error('export_unavailable')
                if lease.slot is not None:
                    self.chunked_config.current()
                    with self.lock:
                        if lease.slot.active_lease_id != id(lease) or lease.slot.actual_reads >= 3:
                            raise _error('retry_limit_exceeded')
                        lease.slot.actual_reads += 1
                        lease.read_admitted = True
                    if lease.slot.kind == 'receiver':
                        from .transport_asset import load_receiver_asset
                        asset = load_receiver_asset()
                        if len(asset) != lease.slot.size or len(asset) > PART_MAX_BYTES:
                            raise _error('receiver_asset_invalid')
                        chunks.append(asset)
                        digest, offset, end = hashlib.sha256(asset), len(asset), len(asset)
                    else:
                        digest, offset = hashlib.sha256(), lease.slot.offset
                        end = offset + lease.slot.size
                else:
                    digest, offset, end = hashlib.sha256(), 0, snapshot.size
                while offset < end:
                    self._lease_check(lease, scope)
                    chunk = os.pread(snapshot.fd, min(CHUNK, end - offset), offset)
                    if not chunk:
                        raise _error('snapshot_hash_mismatch')
                    digest.update(chunk)
                    chunks.append(chunk)
                    offset += len(chunk)
                chunk = None
                if digest.hexdigest() != (lease.slot.sha256 if lease.slot is not None else snapshot.sha256):
                    raise _error('snapshot_hash_mismatch')
                self._lease_check(lease, scope, force=True)
                payload = b''.join(chunks)
                chunks.clear()
                lease.payload = payload
                lease.notify(lease.ready)
                while not lease.construction_done.wait(.025):
                    self._lease_check(lease, scope)
                if lease.error_code:
                    raise _error(lease.error_code)
                self._lease_check(lease, scope, force=True)
                self._fault('construction_finished', lease)
            # The original owner performs the final guard check, then reports it.
            lease.owner_checked = True
            lease.payload = payload = None
            lease.notify(lease.checked)
            while not lease.transport_done.wait(.025):
                if lease.stop.is_set():
                    continue
                if self.monotonic() >= lease.valid_until:
                    with self.sources.scope(lease.actor, record.source.project_id, record.source.worktree_id) as scope:
                        self._lease_check(lease, scope, force=True)
        except BaseException as observed:
            failure = _safe_error(observed)
            lease.fail(failure.code)
            with self.lock:
                if failure.code in PENDING_CLEANUP:
                    self._pending_aux.add(('resource', id(lease)))
                if lease.slot is not None and failure.code in {'snapshot_hash_mismatch', 'receiver_asset_invalid'}:
                    self._retire_locked(record, 'failed', failure.code)
                elif failure.code in SOURCE_DENIAL and not (lease.slot is not None and failure.code == 'authentication_required'):
                    self._retire_locked(record, 'revoked', failure.code)
        finally:
            chunks.clear()
            lease.payload = payload = None
            lease.notify_waiters()
            # No further IO or guard use occurs after this point. Unconfirmed
            # transport/task termination still retains the response and pin.
            with self.lock:
                lease.owner_complete = True
                self._finish_lease_locked(lease)

    def _finish_lease_locked(self, lease):
        if lease.released or not (lease.asgi_done and lease.sdk_done and lease.owner_complete):
            return
        lease.released = True
        self._leases.pop(id(lease), None)
        record = lease.record
        if lease.slot is not None:
            if lease.slot.active_lease_id != id(lease):
                self._uncertain_close = True
                raise RuntimeError('Resource slot ownership was violated.')
            lease.slot.active_lease_id = None
            if lease.error_code is None and lease.final_body_forwarded:
                lease.slot.stream_finished = True
        if record.snapshot is not None:
            record.snapshot.pins -= 1
            if record.snapshot.pins < 0:
                self._uncertain_close = True
                raise RuntimeError('Snapshot pin ownership was violated.')
            if lease.error_code is None and lease.final_body_forwarded:
                if lease.slot is None:
                    record.server_stream_finished = True
                else:
                    record.server_stream_finished = all(
                        record.slots.get('part-' + str(index)) is not None
                        and record.slots['part-' + str(index)].stream_finished
                        for index in range(record.plan['part_count']))
                record.last_used = self.monotonic()
            self._queue_close_locked(record)
        if lease.slot is not None and self.chunked_audit is not None:
            self.chunked_audit('chunked_resource_finished', lease.error_code is None,
                value={'export_id': record.export_id, 'plan_sha256': (record.plan or {}).get('plan_sha256'),
                       'part_index': lease.slot.index, 'bytes': lease.slot.size,
                       'server_stream_finished': lease.error_code is None and lease.final_body_forwarded,
                       'actual_reads': lease.slot.actual_reads, 'resources_released': False},
                error_code=lease.error_code)
        self._wake.set()

    def reap(self):
        now = self.monotonic()
        with self.lock:
            self._rotate_window_locked()
            for record in list(self._records.values()):
                if record.state == 'ready' and now >= record.expires:
                    self._retire_locked(record, 'expired', 'export_expired')
                elif record.state == 'queued' and now - record.accepted >= self.limits.queue_seconds:
                    self._retire_locked(record, 'failed', 'preparation_timeout')
                elif record.state == 'preparing' and (now - record.started >= self.limits.preparation_seconds
                        or now - record.progress_at >= self.limits.idle_seconds):
                    self._retire_locked(record, 'failed', 'preparation_timeout')
            for lease in self._leases.values():
                if now >= lease.deadline or now - lease.last_progress >= self.limits.idle_seconds:
                    lease.fail('transfer_interrupted')
            self._prune_locked()
        self.discovery.reap()

    def diagnostics(self):
        with self.lock:
            reserved, size = self._usage_locked()
            prepare = sum(r.owner for r in self._records.values())
            auxiliary = 10 * (len(self._metadata_calls) + prepare + len(self._leases)
                + sum(kind != 'metadata' for kind, _ in self._pending_aux))
            return {'records': len(self._records), 'keys': len(self._keys) + len(self._chunked_keys),
                'metadata_bytes': sum(r.metadata_cost for r in self._records.values()),
                'metadata_owners': len(self._metadata_calls), 'prepare_owners': prepare,
                'queued': sum(r.state == 'queued' for r in self._prepare_queue),
                'snapshot_reservations': reserved, 'snapshot_bytes_reserved': size,
                'snapshot_fds': sum(r.snapshot is not None and r.snapshot.fd >= 0 for r in self._records.values()),
                'active_responses': len(self._leases),
                'encoding_bytes_reserved': SERIALIZATION_BYTES * len(self._leases),
                'auxiliary_fd_reservations': auxiliary,
                'total_fd_reservations': auxiliary + reserved,
                'close_active': int(self._close_active is not None),
                'pending_auxiliary_owners': len(self._pending_aux),
                'uncertain_snapshot_close': self._uncertain_close,
                'closing': self._closing, 'discovery': self.discovery.diagnostics()}

    def close(self, timeout=None):
        timeout = self.limits.close_seconds if timeout is None else max(0, timeout)
        deadline = time.monotonic() + timeout
        with self.lock:
            self._closing = True
            self._stop.set()
            for call in self._metadata_calls.values():
                call.cancelled.set()
            for record in self._records.values():
                self._retire_locked(record, 'expired', 'export_disabled')
            for lease in self._leases.values():
                lease.fail('transfer_interrupted')
                lease.construction_done.set()
            self._wake.set()
        self.discovery.close()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(max(0, deadline - time.monotonic()))
        with self.lock:
            remaining = self.diagnostics()
            pending = (any(t.is_alive() for t in self._threads) or self._metadata_calls or self._leases
                or any(r.reserved for r in self._records.values()) or self._pending_aux or self._uncertain_close)
            return {'state': 'shutdown_pending' if pending else 'stopped', **remaining}

    async def close_lifespan(self):
        if self._reaper is not None:
            self._reaper.cancel()
            try:
                await self._reaper
            except asyncio.CancelledError:
                pass
            self._reaper = None
        return await asyncio.to_thread(self.close)


def load_export_service(path, catalog, history=None, *, files=None, protected_paths=(), inspection_only=False, chunked_config_path=None):
    """Use existing initialized private infrastructure; never enables file writes."""
    chunked = read_chunked_export_config(chunked_config_path)
    if path is None:
        if chunked.enabled and not inspection_only:
            try:
                from ._file_release_mode import INSPECTION_ONLY
            except ImportError:
                raise _error('private_protection_unavailable') from None
            if not INSPECTION_ONLY:
                raise _error('private_protection_unavailable')
        return None
    config = read_export_config(path)
    try:
        from ._file_release_mode import INSPECTION_ONLY
    except ImportError:
        raise _error('private_protection_unavailable') from None
    if inspection_only or INSPECTION_ONLY:
        return None
    if not config.enabled:
        if chunked.enabled:
            raise _error('private_protection_unavailable')
        return None
    if catalog._private_registry is None:
        raise _error('private_protection_unavailable', 'Explicit initialized private infrastructure is required.')
    protected = list(protected_paths) + [config.path]
    if catalog._config_path is not None:
        protected.append(catalog._config_path)
    if history is not None:
        if history.config_path is not None:
            protected.append(Path(history.config_path))
        home = history._configuration().get('home')
        if home is not None:
            protected.append(Path(home))
    reservation = None
    floor = 0
    infrastructure = None
    infrastructure_path = getattr(catalog._private_registry, 'config_path', None)
    if infrastructure_path is not None:
        from .file_config import read_file_config
        infrastructure = read_file_config(infrastructure_path)
        if (infrastructure.control_directory != catalog._private_registry.control_dir or
                frozenset(infrastructure.spool_roots) != catalog._private_registry.allowed_roots or
                config.spool_root not in infrastructure.spool_roots):
            raise _error('private_protection_unavailable')
    if files is not None:
        reservation = files.pending_space_reservation
        floor = getattr(files, 'min_free_bytes', 0)
    elif (catalog._private_registry.control_dir / 'file-jobs.sqlite3').exists():
        raise _error('private_protection_unavailable', 'Existing file reservations require their read-only owner.')
    return FileExportService(catalog, config, protected_paths=protected, external_reserved=reservation,
                             space_floor=floor, infrastructure_config=infrastructure, chunked_config=chunked)
