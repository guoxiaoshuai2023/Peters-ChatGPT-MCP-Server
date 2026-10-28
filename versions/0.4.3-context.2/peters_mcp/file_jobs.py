"""Durable create-only original-file jobs with isolated receivers and private spools.

No file body or signed source URL is stored in SQLite. Only authenticated service
callers may invoke this layer. Fault hooks/receiver injection are constructor-only
test seams and must never be exposed through configuration or MCP tools.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
import unicodedata

from .catalog import AccessError
from .file_receiver import ReceiverHandle, Isolated, process_identity
from .fs_identity import persistent_identity_fd, boot_session_id
from .file_source import NativeFile, SourceError, receive_file, source_identity
from .file_targets import FileTargets, FrozenTarget, TargetError, CreatedDirectory
from .private_roots import _directory
from .workspaces import _probe

TERMINAL = frozenset({'completed', 'cancelled', 'failed', 'conflict', 'authorization_blocked',
                      'publication_unverified', 'needs_new_content_request'})
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _error(code, text):
    return AccessError(text, code=code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _identity(info):
    return [info.st_dev, info.st_ino]


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _target(row):
    values = dict(row['target'])
    values['root_identity'] = tuple(values['root_identity'])
    return FrozenTarget(**values)


def _actor(actor):
    if not isinstance(actor, str) or not re.fullmatch('[0-9a-f]{64}', actor):
        raise _error('unauthorized', 'A verified server-side actor is required.')


def _hash_fd(fd):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise _error('file_identity_changed', 'Only an unlinked ordinary owned file can be verified.')
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while chunk := os.read(fd, 65536):
        count += len(chunk)
        if count > before.st_size:
            raise _error('file_changed', 'File changed during verification.')
        digest.update(chunk)
    if _version(before) != _version(os.fstat(fd)) or count != before.st_size:
        raise _error('file_changed', 'File changed during verification.')
    return {'bytes': count, 'sha256': digest.hexdigest(), 'identity': _identity(before)}


def _readonly_database_preflight(database, fd):
    """Reject journal processing before SQLite can create any sidecar.

    SQLite's mode=ro still creates shared memory for some WAL snapshots. Do
    not use immutable to hide a real journal: only a clean DELETE-mode store
    is eligible for this no-side-effect inspector.
    """
    before = os.fstat(fd)
    header = os.pread(fd, 100, 0)
    if (len(header) != 100 or header[:16] != b'SQLite format 3\0'
            or header[18:20] != b'\x01\x01'):
        raise _error('metadata_unavailable', 'Readonly job inspection requires a clean DELETE-mode database.')
    parent = _directory(database.parent)
    try:
        for suffix in ('-wal', '-shm', '-journal'):
            try:
                os.stat(database.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise _error('metadata_unavailable', 'Job database sidecars require an explicit recovery check.')
        current = os.stat(database.name, dir_fd=parent, follow_symlinks=False)
        if _version(before) != _version(os.fstat(fd)) or _version(before) != _version(current):
            raise _error('metadata_unavailable', 'Job database changed during readonly inspection preflight.')
    finally:
        os.close(parent)


def publish_exclusive(source_fd, source_name, target_fd, target_name):
    """Same-volume atomic create, never a check-then-replace or copy fallback."""
    name, flag = ('renameatx_np', 4) if sys.platform == 'darwin' else ('renameat2', 1)
    try:
        function = getattr(ctypes.CDLL(None, use_errno=True), name)
    except AttributeError:
        raise _error('unsupported_filesystem', 'No supported atomic create-only primitive.') from None
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), flag):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


class FileSaveService:
    inspection_only = False
    def __init__(self, catalog, registry, control_dir, sources, *, autostart=True,
                 fault_hook=None, min_free_bytes=64 * 1024 * 1024, max_workers=2,
                 special_exceptions=(), protected_paths=(), _receiver=receive_file):
        self.catalog, self.registry = catalog, registry
        self.control_dir = Path(control_dir)
        if self.control_dir != registry.control_dir:
            raise _error('private_protection_unavailable', 'Jobs must use the protected control anchor.')
        if type(max_workers) is not int or not 1 <= max_workers <= 4:
            raise ValueError('max_workers must be 1..4')
        if type(min_free_bytes) is not int or min_free_bytes < 0:
            raise ValueError('min_free_bytes must be nonnegative')
        self.sources, self.fault_hook, self._receiver = sources, fault_hook, _receiver
        self.min_free_bytes, self.max_workers = min_free_bytes, max_workers
        self._db_lock, self._publish_lock = threading.RLock(), threading.RLock()
        self._stop = threading.Event()
        self._storage_failed = threading.Event()
        self._sources = {}
        self._handles = {}
        self._active = {}
        self._claims = {}  # Running attempts, coordinated with source refresh.
        self._closed = False
        self._last_close_result = None
        self._lease = None
        self._thread = None
        self.targets = FileTargets(catalog, special_exceptions=special_exceptions,
                                   protected_paths=protected_paths, private_guard=registry.check_path,
                                   readiness=self._readiness)
        with registry.read_guard():
            fd = _directory(self.control_dir)
            try:
                self._lease = os.open('file-jobs.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                info = os.fstat(self._lease)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise _error('metadata_unavailable', 'Coordinator anchor is unsafe.')
                try:
                    fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise _error('coordinator_busy', 'Another file coordinator already owns this store.') from None
                database = self.control_dir / 'file-jobs.sqlite3'
                init = os.open(database, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    info = os.fstat(init)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                        raise _error('metadata_unavailable', 'Job database is unsafe.')
                finally:
                    os.close(init)
                self.db = sqlite3.connect(database, check_same_thread=False, timeout=1)
                self.db.execute('PRAGMA journal_mode=DELETE')
                self.db.execute('PRAGMA synchronous=FULL')
                version = self.db.execute('PRAGMA user_version').fetchone()[0]
                if version not in (0, 1):
                    raise _error('metadata_unavailable', 'Unsupported job schema version.')
                self.db.executescript('''CREATE TABLE IF NOT EXISTS jobs
                    (id TEXT PRIMARY KEY, actor TEXT NOT NULL, request_key TEXT NOT NULL,
                     intent TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(actor,request_key));
                    CREATE TABLE IF NOT EXISTS ledger
                    (key TEXT PRIMARY KEY, generation INTEGER NOT NULL, valid INTEGER NOT NULL);
                    CREATE TABLE IF NOT EXISTS requests
                    (job TEXT PRIMARY KEY, cancel_requested INTEGER NOT NULL);
                    PRAGMA user_version=1;''')
                self.db.commit()
                os.fsync(fd)
            except BaseException:
                if self._lease is not None:
                    os.close(self._lease)
                    self._lease = None
                raise
            finally:
                os.close(fd)
        try:
            self._reserve()
        except BaseException:
            self.db.close()
            os.close(self._lease)
            self._lease = None
            raise
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='file-coordinator')
        if autostart:
            self.start()

    def _fault(self, phase, row=None):
        if self.fault_hook is not None:
            self.fault_hook(phase, None if row is None else row['job_id'])

    def _reserve(self):
        self._reserve_path = self.control_dir / 'file-control.reserve'
        try:
            fd = os.open(self._reserve_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            info = os.lstat(self._reserve_path)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or info.st_size != 1024 * 1024 or info.st_blocks * 512 < 1024 * 1024):
                raise _error('metadata_unavailable', 'Control reserve is unsafe.')
            self._reserve_identity = _identity(info)
            return
        owned = _identity(os.fstat(fd))
        try:
            for _ in range(16):
                block = os.urandom(65536)  # Incompressible allocated reserve, not a sparse zero promise.
                view = memoryview(block)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError(errno.ENOSPC, 'control reserve unavailable')
                    view = view[count:]
            os.fsync(fd)
            info = os.fstat(fd)
            if info.st_size != 1024 * 1024 or info.st_blocks * 512 < 1024 * 1024:
                raise _error('metadata_unavailable', 'Control reserve has insufficient physical allocation.')
            self._reserve_identity = _identity(info)
            parent = _directory(self.control_dir)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except BaseException:
            try:
                if _identity(os.lstat(self._reserve_path)) == owned:
                    self._reserve_path.unlink()
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(fd)

    def _control_failure(self):
        self._storage_failed.set()
        try:
            if _identity(os.lstat(self._reserve_path)) == self._reserve_identity:
                self._reserve_path.unlink()
                fd = _directory(self.control_dir)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except (OSError, AttributeError):
            pass

    def _put(self, row, *, advance_source_from=None):
        row['updated_at'] = time.time()
        try:
            self._fault('before_job_commit', row)
            with self._db_lock, self.db:
                existing = self.db.execute('SELECT body FROM jobs WHERE id=?', (row['job_id'],)).fetchone()
                if existing:
                    current = json.loads(existing[0])
                    if current.get('runtime_epoch') != row.get('runtime_epoch'):
                        raise _error('stale_file_snapshot', 'A job runtime epoch is immutable.')
                    current_revision = current['source_revision']
                    if advance_source_from is None:
                        source_matches = row['source_revision'] == current_revision
                    else:
                        source_matches = (current_revision == advance_source_from
                                          and row['source_revision'] == advance_source_from + 1)
                    if (not source_matches or row['attempt_number'] < current['attempt_number']
                            or row['attempt_number'] > current['attempt_number'] + 1):
                        raise _error('stale_file_snapshot', 'A newer source or receiver attempt owns this task.')
                    if (advance_source_from is None and row['attempt_number'] == current['attempt_number']
                            and row.get('receiver') and current.get('receiver')
                            and row['receiver']['attempt'] != current['receiver']['attempt']):
                        raise _error('stale_file_snapshot', 'A different receiver attempt owns this task.')
                    # Irreversible control facts survive older worker snapshots.
                    # Cancellation is a durable request, independent of publication's lock.
                    row['cancel_requested'] = bool(row.get('cancel_requested') or current.get('cancel_requested'))
                    if current['published'] is True:
                        row['published'] = True
                        for key in ('publish_intent', 'complete', 'receipt_candidate', 'spool_identity',
                                    'attempt_directory', 'attempt_directory_identity', 'receiver', 'writer_exited'):
                            if key in current:
                                row[key] = current[key]
                        if row['state'] not in {'publishing', 'verifying_destination', 'completed', 'publication_unverified'}:
                            row['state'] = current['state']
                        if current['durability'] == 'confirmed':
                            row['durability'] = 'confirmed'
                        if current['verification'] == 'matched':
                            row['verification'] = 'matched'
                    elif current['published'] == 'unknown' and row['published'] is False:
                        row['published'] = 'unknown'
                    if row['published'] is True and row['cancel_requested']:
                        row['cancel_effect'] = 'too_late'
                    elif current.get('cancel_effect') == 'prevented_publish':
                        row['cancel_effect'] = 'prevented_publish'
                    elif row['cancel_requested'] and not row.get('cancel_effect'):
                        row['cancel_effect'] = current.get('cancel_effect') or 'pending'
                    if current['state'] == 'completed':
                        for key in ('state', 'durability', 'verification', 'destination_sha256',
                                    'verified_at', 'completed_at'):
                            row[key] = current[key]
                    elif current['state'] == 'cancelled' and row['state'] not in {'cancelled', 'completed'}:
                        row['state'] = 'cancelled'
                self.db.execute('INSERT INTO jobs VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body',
                                (row['job_id'], row['actor'], row['key'], row['intent'], _json(row)))
        except (sqlite3.Error, OSError):
            self._control_failure()
            raise _error('metadata_unavailable', 'Durable job state is unconfirmed; new publication is blocked.') from None

    def _get(self, job_id):
        with self._db_lock:
            found = self.db.execute('SELECT body FROM jobs WHERE id=?', (job_id,)).fetchone()
        if not found:
            raise _error('not_found', 'File job is unavailable for this actor.')
        return self._signals(json.loads(found[0]))

    def _signals(self, row):
        with self._db_lock:
            signal = self.db.execute('SELECT cancel_requested FROM requests WHERE job=?', (row['job_id'],)).fetchone()
        if signal and signal[0]:
            row['cancel_requested'] = True
            row['cancel_effect'] = ('too_late' if row['published'] is True else
                                    'unresolved' if row['published'] == 'unknown' else
                                    row.get('cancel_effect') or 'pending')
        return row

    def _owned(self, actor, job_id=None, request_key=None):
        _actor(actor)
        if (job_id is None) == (request_key is None):
            raise _error('invalid_request', 'Use job_id or request_key, exclusively.')
        if request_key is not None:
            key = self._key(request_key)
            with self._db_lock:
                found = self.db.execute('SELECT body FROM jobs WHERE actor=? AND request_key=?', (actor, key)).fetchone()
            if not found:
                raise _error('not_found', 'File job is unavailable for this actor.')
            row = json.loads(found[0])
        else:
            row = self._get(job_id)
        if row['actor'] != actor:
            raise _error('not_found', 'File job is unavailable for this actor.')
        return self._signals(row)

    @staticmethod
    def _key(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
            raise _error('invalid_request_key', 'Provide a bounded stable request key.')
        return _digest(value)

    def _policy(self):
        result = self.sources() if callable(self.sources) else self.sources
        if not isinstance(result, dict):
            raise _error('source_policy_unavailable', 'File-source policy is unavailable.')
        return result

    def _readiness(self, path, identity):
        if sys.platform != 'darwin':
            return {'execution_ready': False, 'readiness_reason': 'unsupported_receiver_platform'}
        blocked = self._admission_block()
        if blocked:
            return {'execution_ready': False, 'readiness_reason': blocked}
        try:
            boot_session_id()
        except (AccessError, OSError, ValueError):
            return {'execution_ready': False, 'readiness_reason': 'runtime_epoch_unavailable'}
        spool = self.registry.spool_for(identity[0])
        return {'execution_ready': spool is not None, 'readiness_reason': None if spool else 'spool_not_ready'}

    def _runtime_epoch(self, row):
        """Only this job's volumes enter the epoch; no authorization is observed.

        Paths are opened through the no-follow directory walker. Persistent
        identity and the current device number come from that same held FD.
        A repeated volume UUID with inconsistent device mappings is unknown.
        """
        target = row['target']
        paths = [self.control_dir, row['spool_root']['path'], target['root']]
        if target.get('repository_id') is not None:
            paths.append(_probe(Path(target['root']))['common'])
        volumes = {}
        for path in paths:
            fd = _directory(path)
            try:
                before = os.fstat(fd)
                stable = persistent_identity_fd(fd)
                after = os.fstat(fd)
                if _identity(before) != _identity(after):
                    raise _error('runtime_epoch_unavailable', 'Runtime volume mapping changed.')
                volume = stable['volume_uuid']
                if volume in volumes and volumes[volume] != before.st_dev:
                    raise _error('runtime_epoch_unavailable', 'Runtime volume mapping is ambiguous.')
                volumes[volume] = before.st_dev
            finally:
                os.close(fd)
        return {'format': 1, 'boot_session': boot_session_id(),
                'volumes': [[volume, volumes[volume]] for volume in sorted(volumes)]}

    def _epoch_matches(self, row):
        if not isinstance(row.get('runtime_epoch'), dict):
            return False
        try:
            return row['runtime_epoch'] == self._runtime_epoch(row)
        except (AccessError, OSError, ValueError, KeyError, RuntimeError):
            return False

    def _current_claim(self, row):
        """Claims are installed/advanced/removed under the publication lock.

        A status/cancel read must not wait for rename or directory fsync. If
        another publisher owns that lock, it also prevents a claim handoff;
        the immutable claim snapshot can be compared without taking ownership.
        """
        acquired = self._publish_lock.acquire(blocking=False)
        try:
            claim = self._claims.get(row['job_id'])
            if (not claim or claim['revision'] != row['source_revision']
                    or claim['attempt'] != row['attempt_number']
                    or not claim['thread'].is_alive()):
                return None
            ticket = row.get('receiver')
            if ticket and (ticket.get('generation') != row['attempt_number']
                           or ticket.get('revision') != row['source_revision']
                           or claim.get('receiver_attempt') != ticket.get('attempt')):
                return None
            return claim
        finally:
            if acquired:
                self._publish_lock.release()

    @staticmethod
    def _pending_publication(row):
        return bool(row.get('publish_intent') and not row.get('publish_aborted')
                    and row['published'] is not True)

    def _quarantined(self, row):
        # Old terminal facts remain readable and are never rewritten. An
        # unresolved publication is not a completed historical fact.
        pending = (row['state'] not in TERMINAL or row['state'] == 'publication_unverified'
                   or row['published'] == 'unknown' or self._pending_publication(row))
        return pending and not self._epoch_matches(row)

    def _receiver_unknown(self, row):
        if not row.get('receiver') or row.get('writer_exited') or self._current_claim(row):
            return False
        try:
            return process_identity(row['receiver']['identity']['pid']) != row['receiver']['identity']
        except (AccessError, OSError, ValueError, KeyError):
            return True

    def _recovery_required(self, row):
        return bool(self._quarantined(row) or row['state'] == 'publication_unverified'
                    or row['published'] == 'unknown'
                    or self._pending_publication(row) and not self._current_claim(row)
                    or self._receiver_unknown(row))

    def _admission_block(self):
        """Only creation of a new job consults this aggregate gate."""
        if self.db is None:
            return None
        with self._db_lock:
            rows = [json.loads(item[0]) for item in self.db.execute('SELECT body FROM jobs')]
        for row in rows:
            if self._quarantined(row):
                return 'identity_epoch_changed'
            if (row['state'] == 'publication_unverified' or row['published'] == 'unknown'
                    or self._pending_publication(row) and not self._current_claim(row)):
                return 'publication_unverified'
            if self._receiver_unknown(row):
                return 'receiver_identity_unverified'
        return None

    def _continuation_guard(self, row, *, authorize=True, worker=False):
        """Per-job continuation; deliberately never reads admission_block.

        A current worker owns the exact source/attempt. A stopped same-epoch
        job may enter the existing recovery state machine under a new claim.
        Cross-epoch/legacy jobs fail before authorization can change a ledger.
        """
        if not self._epoch_matches(row):
            raise _error('identity_epoch_changed', 'This job requires explicit identity recovery.')
        with self._publish_lock:
            current = self._get(row['job_id'])
            if (current['source_revision'] != row['source_revision']
                    or current['attempt_number'] != row['attempt_number']):
                raise _error('stale_file_snapshot', 'A different source or attempt owns this job.')
            claim = self._claims.get(row['job_id'])
            if claim and self._current_claim(current) is None:
                raise _error('stale_file_snapshot', 'The current worker claim no longer matches this job.')
            if worker and (not claim or claim['thread'] is not threading.current_thread()):
                raise _error('stale_file_snapshot', 'This operation does not own the current worker claim.')
        return self._authorize(current) if authorize else _target(current)

    def capabilities(self, actor):
        _actor(actor)
        with self.registry.read_guard():
            result = self.targets.capabilities()
        result['write_enabled'] = not self._closed and not self._storage_failed.is_set() and sys.platform == 'darwin'
        blocked = self._admission_block()
        if blocked:
            result.update(execution_ready=False, readiness_reason=blocked)
        return result

    def inspect(self, actor, project_id, worktree_id, path):
        _actor(actor)
        with self.registry.read_guard():
            return self.targets.inspect(project_id, worktree_id, path)

    def _ledger(self, target):
        return [target.project_id + ':repo', target.project_id + ':member:' + target.worktree_id,
                target.project_id + ':path:' + _digest([target.worktree_id, target.path]), ':file-service']

    def _grant_versions(self, target):
        result = {}
        try:
            with self._db_lock, self.db:
                for key in self._ledger(target):
                    row = self.db.execute('SELECT generation,valid FROM ledger WHERE key=?', (key,)).fetchone()
                    generation = 1 if row is None else row[0] + int(not row[1])
                    self.db.execute('INSERT OR REPLACE INTO ledger VALUES (?,?,1)', (key, generation))
                    result[key] = generation
        except sqlite3.Error:
            self._control_failure()
            raise _error('metadata_unavailable', 'Authorization ledger cannot be committed.') from None
        return result

    def _authorize(self, row):
        # A revocation is effective only after this coordinator admits it. Do
        # not commit invalid generations concurrently with a publisher that has
        # already won the same arbitration lock. Reads/cancel requests do not use it.
        if not self._epoch_matches(row):
            raise _error('identity_epoch_changed', 'This job requires explicit identity recovery.')
        with self._publish_lock:
            return self._authorize_locked(row)

    def _authorize_locked(self, row):
        try:
            self._policy()  # Reload enabled/special/path policy before every side-effect phase.
        except AccessError as exc:
            if exc.code in {'write_not_enabled', 'file_config_changed'}:
                try:
                    with self._db_lock, self.db:
                        self.db.execute("UPDATE ledger SET generation=generation+1,valid=0 WHERE key=':file-service' AND valid=1")
                except sqlite3.Error:
                    self._control_failure()
                    raise _error('metadata_unavailable', 'Service revocation cannot be committed.') from None
                raise _error('authorization_blocked', 'An observed file-write configuration change blocks this job.') from None
            raise
        target = _target(row)
        with self.registry.read_guard():
            try:
                self.targets.revalidate(target)
            except TargetError as exc:
                if exc.permanent:
                    keys = self._ledger(target)
                    if (target.project_id not in self.catalog.projects or
                            self.catalog.projects[target.project_id].repository_id != target.repository_id):
                        revoked = keys[:1]
                    elif exc.code in {'protected_path', 'path_excluded', 'special_path_requires_exception',
                                      'repository_boundary'}:
                        revoked = keys[2:3]
                    else:
                        revoked = keys[1:2]
                    try:
                        with self._db_lock, self.db:
                            for key in revoked:
                                self.db.execute('UPDATE ledger SET generation=generation+1,valid=0 WHERE key=? AND valid=1', (key,))
                    except sqlite3.Error:
                        self._control_failure()
                        raise _error('metadata_unavailable', 'Authorization observation cannot be committed.') from None
                    raise _error('authorization_blocked', 'Previously observed permission or target was revoked.') from None
                raise
        with self._db_lock:
            for key, version in row['authorization'].items():
                current = self.db.execute('SELECT generation,valid FROM ledger WHERE key=?', (key,)).fetchone()
                if not current or current != (version, 1):
                    raise _error('authorization_blocked', 'Frozen authorization generation is no longer active.')
        return target

    def submit(self, actor, file, project_id, worktree_id, path, target_version,
               destination_display, request_key, expected_sha256=None, expected_size_bytes=None):
        _actor(actor)
        try:
            file = NativeFile.model_validate(file).model_dump()
            selection = source_identity(file)
        except (ValueError, TypeError):
            raise _error('invalid_file_reference', 'A valid native file reference is required.') from None
        key = self._key(request_key)
        if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256)):
            raise _error('invalid_expected_hash', 'Expected hash must be lowercase SHA256.')
        if expected_size_bytes is not None and (type(expected_size_bytes) is not int or expected_size_bytes < 0):
            raise _error('invalid_expected_length', 'Expected length must be nonnegative.')
        intent = _digest([1, project_id, worktree_id, path, target_version, selection,
                          expected_sha256, expected_size_bytes])
        with self._publish_lock:
            with self._db_lock:
                found = self.db.execute('SELECT body FROM jobs WHERE actor=? AND request_key=?', (actor, key)).fetchone()
            if found:
                row = json.loads(found[0])
                if row['intent'] != intent:
                    raise _error('idempotency_conflict', 'Request key is already bound to a different file or target.')
                return self._status(row)
            if self._closed or self._storage_failed.is_set():
                raise _error('metadata_unavailable', 'File coordinator is not accepting new work.')
            if sys.platform != 'darwin':
                raise _error('unsupported_receiver_platform', 'Receiver lifecycle is not supported on this platform.')
            blocked = self._admission_block()
            if blocked:
                raise _error(blocked, 'Existing unresolved jobs block acceptance of a new file job.')
            self._policy()
            with self.registry.read_guard():
                target = self.targets.resolve(project_id, worktree_id, path, target_version)
                if destination_display != target.destination_display:
                    raise _error('destination_mismatch', 'Displayed target differs from the resolved destination.')
                with self.targets.open_parent(target) as parent:
                    spool = self.registry.spool_for(os.fstat(parent.fd).st_dev)
                if spool is None:
                    raise _error('spool_not_ready', 'No protected same-filesystem private root is ready.')
            claim = _digest([target.root_identity,
                             unicodedata.normalize('NFC', target.path.casefold())])
            rows = self._rows()
            if len([r for r in rows if r['state'] not in TERMINAL]) >= 64:
                raise _error('busy', 'File job queue is full; retry after existing jobs finish.')
            if any(r['claim'] == claim and r['state'] not in TERMINAL - {'publication_unverified'} for r in rows):
                raise _error('target_busy', 'An existing job owns this target or has an unresolved publication.')
            runtime_epoch = self._runtime_epoch({'target': asdict(target), 'spool_root': spool})
            row = {'job_id': secrets.token_hex(16), 'actor': actor, 'key': key, 'intent': intent,
                   'normalization_version': 1, 'target': asdict(target), 'claim': claim,
                   'authorization': self._grant_versions(target), 'spool_root': spool,
                   'expected_sha256': expected_sha256, 'expected_size_bytes': expected_size_bytes,
                   'source_selection': selection, 'source_revision': 1, 'attempt_number': 0,
                   'state': 'queued', 'published': False, 'durability': 'pending',
                   'verification': 'not_started', 'cancel_requested': False, 'cancel_effect': None,
                   'created_at': time.time(), 'created_directories': [], 'error_code': None,
                   'trace_id': secrets.token_hex(12)}
            row['runtime_epoch'] = runtime_epoch
            # Recheck at the durable insertion boundary. Other workers may
            # have committed a failed/unverified outcome during resolution.
            # Holding the DB lock keeps that observation and new-row insertion
            # indivisible with respect to their state commits.
            with self._db_lock:
                blocked = self._admission_block()
                if blocked:
                    raise _error(blocked, 'Existing unresolved jobs block acceptance of a new file job.')
                self._put(row)
            self._sources[row['job_id']] = file
            self._fault('accepted', row)
            return self._status(row)

    def _status(self, row):
        result = {key: row.get(key) for key in ('job_id', 'state', 'published', 'durability', 'verification',
                  'cancel_requested', 'cancel_effect', 'error_code', 'source_revision', 'created_at', 'updated_at', 'trace_id')}
        result.update(accepted=True, saved=row['state'] == 'completed', current_target_observation='not_checked')
        if self._pending_publication(row):
            result['published'] = 'unknown'
        quarantined = self._quarantined(row)
        result['recovery_required'] = self._recovery_required(row)
        if quarantined:
            result.update(state='recovery_required', error_code='identity_epoch_changed', saved=False)
        if result['published'] == 'unknown' and result['recovery_required'] and row.get('cancel_requested'):
            result['cancel_effect'] = 'unresolved'
        if quarantined:
            return result
        if row.get('cleanup'):
            result['cleanup'] = row['cleanup']  # Fixed categories/counts, never private paths.
        try:
            with self.registry.read_guard():
                self.targets.revalidate(_target(row))
        except (AccessError, OSError):
            return result
        result.update(project_id=row['target']['project_id'], worktree_id=row['target']['worktree_id'],
                      path=row['target']['path'], destination_display=row['target']['destination_display'])
        if row.get('checkpoint'):
            result['durable_offset'] = row['checkpoint']['durable_offset']
        if row.get('complete'):
            result.update(bytes=row['complete']['bytes'], download_sha256=row['complete']['download_sha256'],
                          expected_hash_matched=row['complete'].get('expected_hash_matched'),
                          expected_hash_provenance=row['complete'].get('expected_hash_provenance'),
                          source_evidence_kind=row['complete'].get('source_evidence_kind'))
        for key in ('destination_sha256', 'verified_at', 'completed_at'):
            if key in row:
                result[key] = row[key]
        return result

    def status(self, actor, job_id=None, request_key=None):
        return self._status(self._owned(actor, job_id, request_key))

    def refresh_source(self, actor, job_id, expected_source_revision, file):
        try:
            file = NativeFile.model_validate(file).model_dump()
            source_identity(file)
        except (ValueError, TypeError):
            raise _error('invalid_file_reference', 'A valid native file reference is required.') from None
        with self._publish_lock:
            row = self._owned(actor, job_id)
            self._continuation_guard(row)
            if job_id in self._claims:
                raise _error('refresh_not_ready', 'A coordinator attempt still owns this task; wait for it to stop.')
            if row['state'] not in {'needs_file_reference', 'paused_network', 'paused_space',
                                    'paused_io', 'paused_scope_unverifiable'} or row['published'] is not False:
                raise _error('refresh_not_ready', 'This job cannot accept a new source.')
            if row.get('receiver') and not row.get('writer_exited'):
                raise _error('refresh_not_ready', 'Previous writer has not been proven stopped.')
            if row['source_revision'] != expected_source_revision:
                raise _error('source_revision_changed', 'Source revision changed; inspect the current job.')
            if row['expected_sha256'] is None:
                raise _error('needs_new_content_request', 'Refreshing requires the original bound content hash.')
            if row.get('attempt_directory') and not self._cleanup_private(row):
                raise _error('private_cleanup_unverified', 'Stopped attempt cannot be safely replaced.')
            row.update(source_revision=row['source_revision'] + 1, state='queued', error_code=None)
            for key in ('receiver', 'receipt_candidate', 'complete', 'checkpoint', 'writer_exited',
                        'attempt_directory', 'attempt_directory_identity', 'spool_identity', 'cleanup'):
                row.pop(key, None)
            self._put(row, advance_source_from=expected_source_revision)
            self._sources[job_id] = file
            return self._status(row)

    def cancel(self, actor, job_id):
        # Persist without waiting for a filesystem syscall/directory fsync held
        # by the publisher. A pending request does not claim rename was prevented.
        try:
            with self._db_lock, self.db:
                row = self._owned(actor, job_id)
                self.db.execute('INSERT OR REPLACE INTO requests VALUES (?,1)', (job_id,))
        except sqlite3.Error:
            self._control_failure()
            raise _error('metadata_unavailable', 'Cancellation persistence is unconfirmed.') from None
        if self._publish_lock.acquire(blocking=False):
            try:
                row = self._get(job_id)
                if not self._epoch_matches(row):
                    return self._status(row)
                self._continuation_guard(row, authorize=False)
                if (row['published'] is False and (not row.get('publish_intent') or row.get('publish_aborted'))
                        and (not row.get('receiver') or row.get('writer_exited'))):
                    row.update(state='cancelled', cancel_effect='prevented_publish')
                    self._put(row)
                    if row.get('attempt_directory'):
                        self._pool.submit(self._cleanup_private, dict(row))
                elif row['published'] is False and row['state'] in TERMINAL and (not row.get('publish_intent') or row.get('publish_aborted')):
                    row['state'] = 'writer_stop_pending'
                    self._put(row)
            finally:
                self._publish_lock.release()
        return self._status(self._get(job_id))

    def _rows(self):
        skipped = sorted(TERMINAL - {'publication_unverified'})
        with self._db_lock:
            return [self._signals(json.loads(r[0])) for r in self.db.execute(
                'SELECT body FROM jobs LEFT JOIN requests ON requests.job=jobs.id '
                'WHERE json_extract(body,\'$.state\') NOT IN ('
                + ','.join('?' for _ in skipped) + ') OR (requests.cancel_requested=1 '
                'AND json_extract(body,\'$.published\')=0 AND json_extract(body,\'$.state\') '
                "NOT IN ('cancelled','completed','publication_unverified')) LIMIT 65", skipped)]

    def pending_space_reservation(self):
        """Read scalar outstanding space only; no source references leave the store.

        An unknown-length resumable writer prevents new export preparation until
        its reservation can be accounted for. Completed payload space is already
        reflected by statvfs. No job/state mutation or scheduling is performed.
        """
        if self.db is None:
            return 0
        with self._db_lock:
            try:
                rows = [json.loads(item[0]) for item in self.db.execute('SELECT body FROM jobs')]
            except sqlite3.Error:
                return None
        reservations = []
        for row in rows:
            # Completed/stopped terminal payloads are already reflected by
            # statvfs. Unknown execution cannot be treated as a stopped writer.
            if row['published'] is True or row.get('complete'):
                continue
            # This scalar inspection deliberately needs only the read-only DB
            # contract. A frozen maximum length remains a conservative bound
            # across epochs, without observing a PID or authorizing a target.
            uncertain = bool(row.get('receiver') and not row.get('writer_exited')
                             or row['published'] == 'unknown'
                             or FileSaveService._pending_publication(row))
            if (not uncertain and row['state'] in TERMINAL | {'needs_file_reference'}):
                continue
            amount = row.get('expected_size_bytes')
            if type(amount) is not int or amount < 0:
                return None
            reservations.append(amount)
            if len(reservations) > 64:
                return None
        return sum(reservations)

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._schedule, name='file-job-scheduler', daemon=True)
            self._thread.start()

    def _schedule(self):
        while not self._stop.wait(.05):
            if self._storage_failed.is_set():
                continue
            try:
                for job_id, future in list(self._active.items()):
                    if future.done():
                        future.result()
                        del self._active[job_id]
                rows = self._rows()
                for row in rows:
                    if self._quarantined(row):
                        continue
                    if row['state'] in {'needs_file_reference', 'paused_network', 'paused_space', 'paused_io', 'paused_scope_unverifiable'}:
                        try:
                            self._continuation_guard(row)
                        except AccessError as exc:
                            if exc.code == 'authorization_blocked':
                                current = self._get(row['job_id'])
                                current.update(state='authorization_blocked', error_code=exc.code)
                                self._put(current)
                                row['state'] = 'authorization_blocked'
                for row in rows:
                    if len(self._active) >= self.max_workers:
                        break
                    if self._quarantined(row):
                        continue
                    cancellable = row['cancel_requested'] and row['state'] not in {'cancelled', 'completed', 'publication_unverified'}
                    if (row['state'] in TERMINAL and not cancellable or row['state'] == 'needs_file_reference' and not cancellable
                            or row['job_id'] in self._active or row.get('retry_after', 0) > time.time()):
                        continue
                    self._active[row['job_id']] = self._pool.submit(self._run, row['job_id'])
            except AccessError as exc:
                if exc.code != 'stale_file_snapshot':
                    self._control_failure()
            except Exception:
                self._control_failure()

    def _open_attempt(self, row):
        root = row['spool_root']
        selected = self.registry.spool_for(root['identity'][0], roots=[root['path']])
        if selected is None or selected['identity'] != root['identity']:
            raise _error('spool_not_ready', 'Private spool identity is unavailable.')
        fd = _directory(root['path'])
        try:
            if _identity(os.fstat(fd)) != root['identity']:
                raise _error('spool_not_ready', 'Private spool identity changed.')
            name = row['job_id'] + '-' + str(row['attempt_number'])
            os.mkdir(name, 0o700, dir_fd=fd)
            os.fsync(fd)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                output = os.open('payload', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
                try:
                    identity = _identity(os.fstat(output))
                    os.fsync(output)
                finally:
                    os.close(output)
                os.fsync(child)
                return str(Path(root['path']) / name), _identity(os.fstat(child)), identity
            finally:
                os.close(child)
        finally:
            os.close(fd)

    def _verify_spool(self, row):
        fd = _directory(row['attempt_directory'])
        try:
            if _identity(os.fstat(fd)) != row['attempt_directory_identity']:
                raise _error('file_identity_changed', 'Attempt directory changed.')
            source = os.open('payload', _READ, dir_fd=fd)
            try:
                result = _hash_fd(source)
            finally:
                os.close(source)
            if result['identity'] != row['spool_identity']:
                raise _error('file_identity_changed', 'Received file identity changed.')
            return result
        finally:
            os.close(fd)

    def _receive(self, row):
        job_id = row['job_id']
        self._continuation_guard(row, worker=True)
        if row.get('writer_exited') and row.get('receipt_candidate'):
            self._seal(row)
            return True
        if row.get('writer_exited'):
            if row['expected_sha256'] is None:
                row.update(state='needs_new_content_request', error_code='needs_new_content_request')
                self._put(row)
                return False
            if job_id not in self._sources:
                row.update(state='needs_file_reference', error_code='file_reference_unavailable')
                self._put(row)
                return False
            if row.get('attempt_directory') and not self._cleanup_private(row):
                raise _error('private_cleanup_unverified', 'Stopped partial attempt requires private cleanup review.')
            row.pop('receiver', None)
        if not row.get('receiver'):
            file = self._sources.get(job_id)
            if file is None:
                row.update(state='needs_file_reference', error_code='file_reference_unavailable')
                self._put(row)
                return False
            with self._publish_lock:
                self._continuation_guard(row, worker=True)
                row = self._get(job_id)
                if row['cancel_requested']:
                    row.update(state='cancelled', cancel_effect='prevented_publish')
                    self._put(row)
                    return False
                row['attempt_number'] += 1
                directory, directory_identity, spool_identity = self._open_attempt(row)
                row.update(attempt_directory=directory, attempt_directory_identity=directory_identity,
                           spool_identity=spool_identity, state='receiving', writer_exited=False,
                           cleanup={'state': 'not_started'})
                handle = ReceiverHandle.spawn(directory, secrets.token_hex(16), row['attempt_number'],
                                              row['source_revision'], spool_identity,
                                              receiver=self._receiver, min_free_bytes=self.min_free_bytes)
                self._handles[job_id] = handle
                row['receiver'] = handle.ticket
                self._put(row)  # Durable identity before permission, never persist file.
                # The worker was claimed before attempt_number advanced. Move
                # the same ownership token only after its receiver is durable.
                claim = self._claims[job_id]
                self._claims[job_id] = {**claim, 'attempt': row['attempt_number'],
                                        'receiver_attempt': handle.ticket['attempt']}
                self._continuation_guard(row, worker=True)
            handle.permit(file, self._policy(), row['expected_sha256'], row['expected_size_bytes'])
        else:
            handle = self._handles.setdefault(job_id, ReceiverHandle(row['receiver']))
            if handle.exited():
                row['writer_exited'] = True
                self._put(row)
                handle.dispose()
                if row.get('cancel_requested'):
                    row.update(state='cancelled', cancel_effect='prevented_publish')
                    self._put(row)
                    return False
                if row.get('receipt_candidate'):
                    self._seal(row)
                    return True
                row.update(state='needs_file_reference' if row['expected_sha256'] else 'needs_new_content_request')
                self._put(row)
                return False
        last_checkpoint = row.get('checkpoint')
        while not self._stop.is_set():
            current = self._get(job_id)
            self._continuation_guard(current, worker=True)
            if current['cancel_requested']:
                if not handle.stop(timeout=2):
                    current.update(state='writer_stop_pending')
                    self._put(current)
                    return False
                current.update(writer_exited=True, state='cancelled', cancel_effect='prevented_publish', published=False)
                self._put(current)
                handle.dispose()
                return False
            reply = handle.command('status')
            if reply['state'] == 'awaiting_permission':
                if not handle.stop(3):
                    raise Isolated('writer_exit_unknown')
                current.update(writer_exited=True,
                               state='needs_file_reference' if current['expected_sha256'] else 'needs_new_content_request',
                               error_code='start_permission_not_delivered')
                self._put(current)
                handle.dispose()
                return False
            if reply.get('checkpoint') != last_checkpoint:
                last_checkpoint = reply.get('checkpoint')
                current['checkpoint'] = last_checkpoint
                self._put(current)
            if reply['state'] in ('received', 'failed'):
                if reply['state'] == 'received':
                    current['receipt_candidate'] = reply['receipt']
                    self._put(current)
                if not handle.release(3):
                    raise Isolated('writer_exit_unknown')
                current['writer_exited'] = True
                self._put(current)
                handle.dispose()
                if reply['state'] == 'failed':
                    raise _error(reply['error_code'], 'Receiver stopped without a complete original file.')
                self._seal(current)
                return True
            time.sleep(.1)
        # close() owns bounded stop/reap after scheduler has stopped dispatching.
        return False

    def _seal(self, current):
        self._continuation_guard(current, worker=True)
        receipt = current['receipt_candidate']
        if (not current.get('writer_exited') or not receipt.get('protocol_complete')
                or not receipt.get('file_fsynced')):
            raise _error('completion_unverifiable', 'No valid complete-message and exit receipt exists.')
        actual = self._verify_spool(current)
        if ((actual['bytes'], actual['sha256']) != (receipt['bytes'], receipt['download_sha256'])
                or current['expected_sha256'] is not None and actual['sha256'] != current['expected_sha256']
                or current['expected_size_bytes'] is not None and actual['bytes'] != current['expected_size_bytes']):
            raise _error('hash_mismatch', 'Received bytes changed after the writer exited.')
        current.update(complete={**receipt, 'writer_exit_verified': True,
                                 'receive_complete_persisted': True,
                                 'attempt': current['receiver']['attempt'], 'source_revision': current['source_revision']},
                       state='ready_to_publish')
        self._put(current)
        self._fault('receive_complete', current)

    def _run(self, job_id):
        # Claim/refresh ordering spans the entire worker lifetime, including the
        # period before a receiver exists and after it exits. Only this tiny
        # acquisition/release uses the coordinator lock; network/hash stay outside.
        with self._publish_lock:
            if job_id in self._claims:
                return
            row = self._get(job_id)
            if not self._epoch_matches(row):
                return
            claim = {'revision': row['source_revision'], 'attempt': row['attempt_number'],
                     'token': secrets.token_hex(8), 'thread': threading.current_thread(),
                     'receiver_attempt': row.get('receiver', {}).get('attempt')}
            self._claims[job_id] = claim
        try:
            self._run_claimed(job_id)
        finally:
            with self._publish_lock:
                if self._claims.get(job_id, {}).get('token') == claim['token']:
                    self._claims.pop(job_id)

    def _run_claimed(self, job_id):
        try:
            row = self._get(job_id)
            self._continuation_guard(row, authorize=False, worker=True)
            if row['cancel_requested'] and (not row.get('publish_intent') or row.get('publish_aborted')):
                if row.get('receiver') and not row.get('writer_exited'):
                    handle = self._handles.setdefault(job_id, ReceiverHandle(row['receiver']))
                    if not handle.stop(2):
                        row.update(state='writer_stop_pending', retry_after=time.time() + 2)
                        self._put(row)
                        return
                    row['writer_exited'] = True
                    handle.dispose()
                row.update(state='cancelled', cancel_effect='prevented_publish')
                self._put(row)
                return
            self._continuation_guard(row, worker=True)
            if row.get('publish_intent'):
                self._recover_publication(row)
                return
            if not row.get('complete') and not self._receive(row):
                return
            if not self._stop.is_set():
                self._publish(self._get(job_id))
        except BaseException as exc:
            if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                return  # Test-only simulated crash: persisted state is left intact.
            if self._storage_failed.is_set():
                return
            if isinstance(exc, AccessError) and exc.code in {'stale_file_snapshot', 'identity_epoch_changed'}:
                return  # Never rewrite the newer attempt as a failure of this one.
            try:
                row = self._get(job_id)
                if row.get('publish_intent'):
                    row.update(state='publication_unverified', error_code='publication_unverified',
                               published=row['published'] if row['published'] is True else 'unknown')
                else:
                    code = exc.code if isinstance(exc, (AccessError, SourceError)) else 'file_processing_failed'
                    states = {'authorization_blocked': 'authorization_blocked', 'target_exists': 'conflict',
                              'insufficient_space': 'paused_space', 'paused_scope_unverifiable': 'paused_scope_unverifiable',
                              'file_config_invalid': 'paused_scope_unverifiable',
                              'source_policy_unavailable': 'paused_scope_unverifiable',
                              'private_protection_unavailable': 'paused_scope_unverifiable',
                              'file_reference_unavailable': 'needs_file_reference', 'source_timeout': 'paused_network',
                              'source_dns_timeout': 'paused_network', 'transfer_incomplete': 'paused_network',
                              'transfer_idle_timeout': 'paused_network', 'source_temporarily_unavailable': 'paused_network',
                              'source_or_output_io_failed': 'paused_io',
                              'source_unavailable': 'paused_network', 'writer_stop_pending': 'writer_stop_pending'}
                    row.update(state=states.get(code, 'failed'), error_code=code, retry_after=time.time() + 2)
                    handle = self._handles.get(job_id)
                    if handle and not row.get('writer_exited'):
                        try:
                            row['writer_exited'] = handle.stop(1)
                            if row['writer_exited']:
                                handle.dispose()
                        except Exception:
                            row['writer_exited'] = False
                    if row['state'] in ('paused_network', 'paused_space', 'paused_io') and row.get('writer_exited'):
                        if not row['expected_sha256']:
                            row['state'] = 'needs_new_content_request'
                        elif job_id not in self._sources:
                            row['state'] = 'needs_file_reference'
                self._put(row)
            except Exception:
                self._control_failure()
        finally:
            try:
                final = self._get(job_id)
                if final['state'] in TERMINAL:
                    self._sources.pop(job_id, None)
                    if final.get('writer_exited'):
                        self._handles.pop(job_id, None)
                        if final['state'] in ('cancelled', 'completed'):
                            self._cleanup_private(final)
            except Exception:
                pass

    def _cleanup_private(self, row):
        """Only our stopped attempt, and never an unresolved publication scene."""
        try:
            self._continuation_guard(row, authorize=False)
        except AccessError:
            return
        row = self._get(row['job_id'])
        if (not row.get('writer_exited') or not row.get('attempt_directory')
                or row.get('publish_intent') and row['state'] != 'completed' and not row.get('publish_aborted')):
            return
        root = self.registry.spool_for(row['spool_root']['identity'][0], roots=[row['spool_root']['path']])
        if root is None or root['identity'] != row['spool_root']['identity']:
            return
        parent = _directory(root['path'])
        attempt = None
        try:
            name = Path(row['attempt_directory']).name
            if Path(root['path']) / name != Path(row['attempt_directory']):
                return
            try:
                attempt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if self._get(row['job_id']).get('cleanup', {}).get('private_state') == 'completed':
                    self._finish_cleanup(row['job_id'])
                    return True
                return
            if _identity(os.fstat(attempt)) != row['attempt_directory_identity']:
                return
            entries = os.listdir(attempt)
            if set(entries) - {'payload', 'permit.json'}:
                return
            for entry in entries:
                info = os.stat(entry, dir_fd=attempt, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    return
                if entry == 'payload' and _identity(info) != row['spool_identity']:
                    return
                if entry == 'permit.json':
                    fd = os.open(entry, _READ, dir_fd=attempt)
                    try:
                        if info.st_size > 65536:
                            return
                        value = json.loads(os.read(fd, 65536))
                    finally:
                        os.close(fd)
                    ticket = row['receiver']
                    if value != {k: ticket[k] for k in ('identity', 'attempt', 'generation', 'revision', 'nonce', 'spool_identity')}:
                        return
            for entry in entries:
                os.unlink(entry, dir_fd=attempt)
            os.fsync(attempt)
            if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['attempt_directory_identity']:
                return
            os.rmdir(name, dir_fd=parent)
            os.fsync(parent)
            current = self._get(row['job_id'])
            current['cleanup'] = {'state': 'pending', 'private_state': 'completed'}
            self._put(current)
            self._finish_cleanup(row['job_id'])
            return True
        except (OSError, ValueError):
            return  # Unknown cleanup state is retained; no broad recursive deletion.
        finally:
            if attempt is not None:
                os.close(attempt)
            os.close(parent)

    def _finish_cleanup(self, job_id):
        """Project cleanup is separate from private-spool deletion and is scoped.

        Delete only recorded, still-empty directories after a proven unpublished
        cancellation. Revoked/changed scopes retain them with path-free counts.
        A completed publication intentionally retains its project directories.
        """
        with self._publish_lock:
            current = self._get(job_id)
            self._continuation_guard(current, authorize=False)
            records = current.get('created_directories', [])
            removed = set(current.get('removed_created_directories', []))
            directory_state = 'preserved'
            if (current['state'] == 'cancelled' and current['published'] is False
                    and current.get('writer_exited') and
                    (not current.get('publish_intent') or current.get('publish_aborted'))):
                try:
                    target = self._authorize(current)
                    pending = [CreatedDirectory(item['path'], tuple(item['identity'])) for item in records
                               if item['path'] not in removed]
                    with self.registry.read_guard():
                        removed.update(self.targets.cleanup_created(target, pending))
                    directory_state = 'completed' if len(removed) == len(records) else 'retained_or_unverified'
                except (AccessError, OSError):
                    directory_state = 'retained_scope_unavailable'
            current['removed_created_directories'] = sorted(removed)
            current['cleanup'] = {'state': 'completed' if directory_state in {'completed', 'preserved'} else 'retained',
                                  'private_state': 'completed',
                                  'project_directories': {'state': directory_state,
                                      'recorded_count': len(records), 'removed_count': len(removed),
                                      'retained_or_unverified_count': len(records) - len(removed)}}
            self._put(current)

    def _publish(self, row):
        self._continuation_guard(row, worker=True)
        if not row.get('writer_exited') or not row.get('complete'):
            raise _error('completion_unverifiable', 'Writer exit and complete reception are required.')
        actual = self._verify_spool(row)
        complete = row['complete']
        if (any(complete.get(field) is not True for field in ('protocol_complete', 'file_fsynced',
                                                            'writer_exit_verified', 'receive_complete_persisted'))
                or actual['bytes'] != complete['bytes'] or actual['sha256'] != complete['download_sha256']
                or complete['source_revision'] != row['source_revision']
                or complete['attempt'] != row['receiver']['attempt']
                or row['expected_sha256'] is not None and actual['sha256'] != row['expected_sha256']
                or row['expected_size_bytes'] is not None and actual['bytes'] != row['expected_size_bytes']):
            raise _error('hash_mismatch', 'Durable complete reception no longer matches its spool.')
        with self._publish_lock, self.registry.read_guard():
            row = self._get(row['job_id'])
            target = self._continuation_guard(row, worker=True)
            if self._stop.is_set() or self._storage_failed.is_set():
                return
            if row['cancel_requested']:
                row.update(state='cancelled', cancel_effect='prevented_publish')
                self._put(row)
                return
            def created(item):
                row['created_directories'].append(asdict(item))
                self._put(row)
            with self.targets.open_parent(target, create=True, on_created=created) as parent:
                source = _directory(row['attempt_directory'])
                try:
                    if (_identity(os.fstat(source)) != row['attempt_directory_identity']
                            or os.fstat(source).st_dev != os.fstat(parent.fd).st_dev):
                        raise _error('unsupported_filesystem', 'Publication needs the same verified filesystem.')
                    staged = os.stat('payload', dir_fd=source, follow_symlinks=False)
                    if _identity(staged) != row['spool_identity'] or staged.st_nlink != 1:
                        raise _error('file_identity_changed', 'Spool changed before publication.')
                    self._continuation_guard(row, worker=True)
                    row.update(state='publishing', publish_intent={'spool_identity': row['spool_identity'],
                               'parent_identity': _identity(os.fstat(parent.fd)), 'receive_complete': _digest(complete)})
                    self._put(row)
                    self._fault('publish_intent', row)
                    row = self._get(row['job_id'])
                    if row['cancel_requested']:
                        row.update(state='cancelled', cancel_effect='prevented_publish', publish_aborted=True)
                        self._put(row)
                        return
                    if self._storage_failed.is_set():
                        raise _error('metadata_unavailable', 'Control storage failed before publication.')
                    self._continuation_guard(row, authorize=False, worker=True)
                    try:
                        publish_exclusive(source, 'payload', parent.fd, parent.name)
                    except FileExistsError:
                        row.update(state='conflict', error_code='target_exists', published=False, publish_aborted=True)
                        self._put(row)
                        return
                    row['published'] = True
                    self._fault('renamed', row)
                    self._put(row)
                    os.fsync(source)
                    os.fsync(parent.fd)
                    row.update(durability='confirmed', state='verifying_destination', verification='pending')
                    self._put(row)
                    self._fault('published_durable', row)
                finally:
                    os.close(source)
        self._verify_destination(row)

    def _verify_destination(self, row):
        self._continuation_guard(row, authorize=False, worker=True)
        target = _target(row)
        with self.registry.read_guard():
            self.targets.revalidate(target)
            parts = target.path.split('/')
            parent = _directory(Path(target.root).joinpath(*parts[:-1]))
            try:
                if _identity(os.fstat(parent)) != row['publish_intent']['parent_identity']:
                    raise _error('target_changed', 'Published parent identity changed.')
                fd = os.open(parts[-1], _READ, dir_fd=parent)
                try:
                    result = _hash_fd(fd)
                    if _identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != result['identity']:
                        raise _error('target_changed', 'Published target changed during verification.')
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
            self.targets.revalidate(target)
        if (result['identity'] != row['spool_identity'] or result['bytes'] != row['complete']['bytes']
                or result['sha256'] != row['complete']['download_sha256']):
            raise _error('target_changed', 'Published file differs from this job; no repair attempted.')
        with self._publish_lock:
            current = self._get(row['job_id'])
            self._continuation_guard(current, authorize=False, worker=True)
            current.update(state='completed', verification='matched', published=True,
                           destination_sha256=result['sha256'], verified_at=time.time(), completed_at=time.time())
            self._put(current)
            self._fault('completed', current)

    def _recover_publication(self, row):
        self._continuation_guard(row, worker=True)
        if row['published'] is not True:
            row.update(state='publication_unverified', published='unknown', error_code='publication_unverified')
            self._put(row)
            return
        if row['durability'] != 'confirmed':
            target = self._continuation_guard(row)
            with self.registry.read_guard():
                source = _directory(row['attempt_directory'])
                parent = _directory(Path(target.destination_display).parent)
                try:
                    os.fsync(source)
                    os.fsync(parent)
                finally:
                    os.close(source)
                    os.close(parent)
            row['durability'] = 'confirmed'
            self._put(row)
        self._verify_destination(row)

    def close(self, timeout=15):
        if self._lease is None:
            # Releasing coordinator ownership does not prove isolated writers
            # exited. Lifespan and CLI cleanup may both call close normally.
            return dict(self._last_close_result or {
                'state': 'stopped', 'isolated_receivers': 0, 'coordinator_released': True})
        deadline = time.monotonic() + timeout
        self._closed = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(max(0, deadline - time.monotonic()))
        pending = []
        for job_id, handle in list(self._handles.items()):
            try:
                row = self._get(job_id)
                if not self._epoch_matches(row):
                    if not row.get('writer_exited'):
                        pending.append(job_id)
                    continue
                self._continuation_guard(row, authorize=False)
                if handle.process is None and row.get('writer_exited'):
                    continue
                stopped = handle.stop(max(0, min(2, deadline - time.monotonic())), force_owned=True)
                if stopped:
                    handle.dispose()
                    row = self._get(job_id)
                    row['writer_exited'] = True
                    self._put(row)
                else:
                    pending.append(job_id)
            except Exception:
                try:
                    known_exit = self._get(job_id).get('writer_exited')
                except Exception:
                    known_exit = False
                if not known_exit:
                    pending.append(job_id)
        while any(not f.done() for f in self._active.values()) and time.monotonic() < deadline:
            time.sleep(.02)
        active = any(not f.done() for f in self._active.values())
        self._pool.shutdown(wait=False, cancel_futures=True)
        if not active:
            with self._db_lock:
                self.db.close()
            if self._lease is not None:
                os.close(self._lease)
                self._lease = None
        self._last_close_result = {'state': 'shutdown_pending' if active or pending else 'stopped',
                                   'isolated_receivers': len(pending), 'coordinator_released': not active}
        return dict(self._last_close_result)


class FileSaveInspector:
    """Rollback/status reader: no schema writes, reserves, worker, lease or recovery."""
    inspection_only = True
    _get = FileSaveService._get
    _signals = FileSaveService._signals
    _key = staticmethod(FileSaveService._key)
    _status = FileSaveService._status
    _runtime_epoch = FileSaveService._runtime_epoch
    _epoch_matches = FileSaveService._epoch_matches
    _current_claim = FileSaveService._current_claim
    _pending_publication = staticmethod(FileSaveService._pending_publication)
    _quarantined = FileSaveService._quarantined
    _receiver_unknown = FileSaveService._receiver_unknown
    _recovery_required = FileSaveService._recovery_required
    status = FileSaveService.status
    pending_space_reservation = FileSaveService.pending_space_reservation

    def __init__(self, catalog, registry, control_dir, sources=None, *,
                 special_exceptions=(), protected_paths=()):
        self.catalog, self.registry = catalog, registry
        self.control_dir = Path(control_dir)
        if self.control_dir != registry.control_dir:
            raise _error('private_protection_unavailable', 'Inspector requires the protected control anchor.')
        self._db_lock, self._publish_lock = threading.RLock(), threading.RLock()
        self._claims = {}
        self.targets = FileTargets(catalog, special_exceptions=special_exceptions,
                                   protected_paths=protected_paths, private_guard=registry.check_path)
        self.db = None
        with registry.read_guard():
            database = self.control_dir / 'file-jobs.sqlite3'
            try:
                try:
                    fd = os.open(database, _READ)
                except FileNotFoundError:
                    self._closed = False
                    return
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                        raise _error('metadata_unavailable', 'Job database is unsafe.')
                    _readonly_database_preflight(database, fd)
                finally:
                    os.close(fd)
                self.db = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True,
                                           check_same_thread=False, timeout=1)
                self.db.execute('PRAGMA query_only=ON')
                if self.db.execute('PRAGMA user_version').fetchone()[0] != 1:
                    self.db.close()
                    raise _error('metadata_unavailable', 'Unsupported readonly job schema.')
            except (OSError, sqlite3.Error):
                if self.db is not None:
                    self.db.close()
                    self.db = None
                raise _error('metadata_unavailable', 'Existing job state cannot be inspected.') from None
        self._closed = False

    def _owned(self, actor, job_id=None, request_key=None):
        if self.db is None:
            _actor(actor)
            raise _error('job_not_found', 'No existing job state is available.')
        return FileSaveService._owned(self, actor, job_id, request_key)

    def capabilities(self, actor):
        _actor(actor)
        with self.registry.read_guard():
            result = self.targets.capabilities()
        result.update(inspection_only=True, execution_ready=False,
                      write_enabled=False, readiness_reason='file_writes_disabled', mode='inspection-only')
        return result

    def close(self, timeout=15):
        with self._db_lock:
            if not self._closed:
                if self.db is not None:
                    self.db.close()
                self._closed = True
        return {'state': 'stopped', 'inspection_only': True}
