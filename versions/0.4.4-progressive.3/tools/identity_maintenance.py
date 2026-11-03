"""Offline identity migration and origin-only switching; never an MCP tool.

All plans bind exact input bytes and both approved startup definitions. The
operator verifies this maintenance bundle independently before invoking it.
"""
import argparse
import base64
from contextlib import contextmanager
import copy
import ctypes
from datetime import datetime, timezone
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent / 'candidate' if (HERE.parent / 'candidate/peters_mcp').is_dir() else HERE.parent
sys.path.insert(0, str(RUNTIME))
from peters_mcp.fs_identity import persistent_identity, persistent_identity_fd, boot_session_id
from peters_mcp.private_roots import validate_manifest_v2
from peters_mcp.workspaces import repository_probe, repository_pin_v1

LABEL = 'com.peters.chatgpt-mcp.origin'
TUNNEL = 'com.peters.chatgpt-mcp.tunnel'
PENDING = 'identity-migration.pending.json'
TERMINAL = {'completed', 'failed', 'cancelled', 'rejected', 'authorization_blocked'}
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
FAULT = None  # Synthetic fault-injection hook; no CLI bypass or fault flag.
_OPERATOR = threading.local()


class MaintenanceError(ValueError):
    def __init__(self, code, exit_code=2):
        self.code, self.exit_code = code, exit_code
        super().__init__(code)


def fail(code, exit_code=2):
    raise MaintenanceError(code, exit_code)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def point(name):
    if FAULT is not None:
        FAULT(name)


def close(fd):
    try:
        os.close(fd)
    except OSError:
        fail('descriptor_cleanup_unconfirmed', 3)


def directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        fail('noncanonical_path')
    fd = os.open('/', _DIR)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIR, dir_fd=fd)
            previous, fd = fd, child
            close(previous)
        return fd
    except BaseException:
        close(fd)
        raise


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink]


def read(path, limit=512 * 1024 * 1024):
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, _READ, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid() or before.st_mode & 0o022
                    or before.st_size > limit):
                fail('unsafe_input_file')
            chunks = []
            count = 0
            while True:
                block = os.read(fd, min(65536, limit + 1 - count))
                if not block:
                    break
                chunks.append(block)
                count += len(block)
                if count > limit:
                    fail('input_budget_exceeded')
            after = os.fstat(fd)
            if stamp(before) != stamp(after) or stamp(after) != stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
                fail('input_changed_during_read')
            raw = b''.join(chunks)
            return raw, {'path': str(path), 'sha256': sha(raw), 'bytes': len(raw),
                         'mode': stat.S_IMODE(after.st_mode), 'uid': after.st_uid,
                         'gid': after.st_gid, 'runtime': [after.st_dev, after.st_ino]}
        finally:
            close(fd)
    finally:
        close(parent)


def sync(fd, name):
    point('before_sync:' + name)
    os.fsync(fd)
    point('after_sync:' + name)


def write_new(path, raw, mode=0o600):
    path = Path(path)
    parent = directory(path.parent)
    fd = None
    try:
        point('before_create:' + path.name)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                fail('short_write', 3)
            view = view[count:]
        sync(fd, path.name)
        close(fd)
        fd = None
        sync(parent, 'directory:' + path.parent.name)
        point('after_create:' + path.name)
    finally:
        if fd is not None:
            close(fd)
        close(parent)


def private_directory(path):
    path = Path(path)
    parent = directory(path.parent)
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            sync(parent, 'mkdir:' + path.name)
        except FileExistsError:
            pass
        fd = os.open(path.name, _DIR, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                fail('unsafe_operation_directory')
            sync(fd, 'directory:' + path.name)
            # A prior mkdir may have been visible when its parent sync failed.
            # Reusing the directory must confirm that directory entry as well.
            sync(parent, 'mkdir:' + path.name)
        finally:
            close(fd)
    finally:
        close(parent)


def confirm_durable_file(path, expected):
    """Confirm known visible bytes and their directory entry before reuse."""
    path = Path(path)
    raw, info = read(path)
    if raw != expected:
        fail('durable_file_content_conflict', 3)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, _READ, dir_fd=parent)
        before = os.fstat(fd)
        if [before.st_dev, before.st_ino] != info['runtime']:
            fail('durable_file_identity_changed', 3)
        sync(fd, 'confirm:' + path.name)
        sync(parent, 'confirm_parent:' + path.parent.name)
        checked, metadata = read(path)
        if checked != expected or metadata['runtime'] != info['runtime']:
            fail('durable_file_readback_changed', 3)
    finally:
        if fd is not None:
            close(fd)
        close(parent)


def confirm_durable_journal(path, plan_sha):
    path = Path(path)
    records = journal_read(path)[0]
    if not records or any(record.get('plan_sha256') != plan_sha for record in records):
        fail('journal_plan_mismatch', 3)
    raw, metadata = read(path, 4 * 1024 * 1024)
    if metadata['mode'] != 0o600:
        fail('unsafe_journal', 3)
    confirm_durable_file(path, raw)
    if journal_read(path)[0] != records:
        fail('journal_changed_during_confirmation', 3)
    return records


@contextmanager
def operator_lock(plan, plan_sha):
    """Serialize the entire administrative operation, including launchctl/logs.

    This is a distinct administrator mutex under the protected control tree;
    neither of the two existing service locks is created or replaced.
    """
    control = Path(plan['control_directory'])
    held = getattr(_OPERATOR, 'held', None)
    if held is not None:
        if held[:2] != (str(control), plan_sha):
            fail('another_operation_owns_this_thread', 3)
        yield
        return
    if persistent_identity(control) != plan['anchors'][0]['identity']:
        fail('control_anchor_changed', 3)
    private_directory(control / 'identity-repair')
    parent = directory(control / 'identity-repair')
    fd = None
    try:
        try:
            fd = os.open('maintenance.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            sync(fd, 'operator_mutex')
            sync(parent, 'operator_mutex_parent')
        except FileExistsError:
            fd = os.open('maintenance.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            fail('unsafe_operator_mutex', 3)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    fail('another_maintenance_operator_active', 3)
                time.sleep(.01)
        current = os.stat('maintenance.lock', dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            fail('operator_mutex_replaced', 3)
        _OPERATOR.held = (str(control), plan_sha, fd)
        yield
    finally:
        _OPERATOR.held = None
        if fd is not None:
            close(fd)
        close(parent)


def serialized(function):
    @functools.wraps(function)
    def run(plan, plan_sha, *args, **kwargs):
        reject_aborted(plan, plan_sha)
        with operator_lock(plan, plan_sha):
            # A queued caller may have passed the early check before another
            # operator aborted this plan and restored the previous service.
            reject_aborted(plan, plan_sha)
            return function(plan, plan_sha, *args, **kwargs)
    return run


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def decoded(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        fail('invalid_encoded_plan')


def file_target(path, after):
    raw, metadata = read(path)
    metadata.update(before=encoded(raw), after=encoded(after), after_sha256=sha(after),
                    parent_identity=persistent_identity(Path(path).parent))
    return metadata


def atomic_target(target, allowed, desired):
    path = Path(target['path'])
    raw, info = read(path)
    if (sha(raw) not in allowed or persistent_identity(path.parent) != target['parent_identity']
            or any(info[key] != target[key] for key in ('mode', 'uid', 'gid'))):
        fail('target_not_in_approved_state', 3)
    if sha(raw) == sha(desired):
        # Recovery may observe a completed rename whose parent fsync never
        # returned. Visibility is not a durability receipt: establish both
        # file and containing-directory barriers before recording AFTER/READY.
        parent = directory(path.parent)
        fd = None
        try:
            if persistent_identity_fd(parent) != target['parent_identity']:
                fail('target_parent_changed', 3)
            fd = os.open(path.name, _READ, dir_fd=parent)
            current = os.fstat(fd)
            if [current.st_dev, current.st_ino] != info['runtime']:
                fail('target_changed_before_durable_confirmation', 3)
            sync(fd, 'existing_target:' + path.name)
            sync(parent, 'target_parent:' + path.name)
            checked, checked_info = read(path)
            if checked != desired or checked_info['runtime'] != info['runtime']:
                fail('target_changed_during_durable_confirmation', 3)
        finally:
            if fd is not None:
                close(fd)
            close(parent)
        return
    parent = directory(path.parent)
    temporary = '.identity-' + uuid.uuid4().hex
    fd = None
    replaced = False
    try:
        if persistent_identity_fd(parent) != target['parent_identity']:
            fail('target_parent_changed', 3)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, target['mode'], dir_fd=parent)
        os.fchmod(fd, target['mode'])
        os.fchown(fd, -1, target['gid'])
        view = memoryview(desired)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                fail('short_write', 3)
            view = view[count:]
        sync(fd, 'target:' + path.name)
        close(fd)
        fd = None
        current, current_info = read(path)
        if sha(current) != sha(raw) or current_info['runtime'] != info['runtime']:
            fail('target_changed_before_replace', 3)
        if persistent_identity_fd(parent) != target['parent_identity']:
            fail('target_parent_changed', 3)
        point('before_replace:' + path.name)
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        replaced = True
        sync(parent, 'target_parent:' + path.name)
        point('after_replace:' + path.name)
        if read(path)[0] != desired:
            fail('target_readback_mismatch', 3)
    finally:
        if fd is not None:
            close(fd)
        # The sole temporary file belongs to this invocation. Keep it after an
        # unconfirmed replacement/sync so recovery can inspect the scene.
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=parent)
                sync(parent, 'temporary_cleanup')
            except FileNotFoundError:
                pass
        close(parent)


def journal_read(path):
    path = Path(path)
    if not path.exists():
        return [], 0
    raw, _ = read(path, 4 * 1024 * 1024)
    result, position, previous = [], 0, None
    for index, line in enumerate(raw.splitlines(keepends=True)):
        if not line.endswith(b'\n'):
            break  # Only an incomplete final record may be discarded.
        try:
            record = json.loads(line)
            digest = record.pop('sha256')
            if record['sequence'] != len(result) + 1 or record['previous'] != previous or sha(canonical(record)) != digest:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            fail('journal_corrupt', 3)
        record['sha256'] = digest
        result.append(record)
        previous = digest
        position += len(line)
    return result, position


def journal_append(path, event, plan_sha, **fields):
    path = Path(path)
    records, valid_end = journal_read(path)
    if any(r['plan_sha256'] != plan_sha for r in records):
        fail('journal_plan_mismatch', 3)
    record = {'sequence': len(records) + 1, 'previous': records[-1]['sha256'] if records else None,
              'event': event, 'plan_sha256': plan_sha, 'time': now(), **fields}
    record['sha256'] = sha(canonical(record))
    parent = directory(path.parent)
    fd = None
    try:
        try:
            fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        except FileExistsError:
            fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            fail('unsafe_journal', 3)
        if info.st_size != valid_end:
            os.ftruncate(fd, valid_end)
            sync(fd, 'journal_tail_repair')
        os.lseek(fd, 0, os.SEEK_END)
        raw = canonical(record)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                fail('short_journal_write', 3)
            offset += count
        sync(fd, 'journal:' + event)
        sync(parent, 'journal_parent')
    finally:
        if fd is not None:
            close(fd)
        close(parent)
    return record


def events(path):
    return [r['event'] for r in journal_read(path)[0]]


def _validated_ledger_entries(rows):
    if not isinstance(rows, list) or len(rows) > 10000:
        fail('authorization_ledger_not_verified', 3)
    result = []
    for row in rows:
        if (not isinstance(row, (list, tuple)) or len(row) != 3
                or not isinstance(row[0], str) or not row[0]
                or type(row[1]) is not int or row[1] < 1
                or type(row[2]) is not int or row[2] not in (0, 1)):
            fail('authorization_ledger_not_verified', 3)
        result.append(list(row))
    if result != sorted(result, key=lambda row: row[0]) or len({row[0] for row in result}) != len(result):
        fail('authorization_ledger_not_verified', 3)
    return result


def _ledger_continuity(before, current):
    before = _validated_ledger_entries(before)
    current = {row[0]: row for row in _validated_ledger_entries(current)}
    for key, generation, valid in before:
        row = current.get(key)
        if (row is None or row[1] < generation
                or row[1] == generation and valid == 0 and row[2] == 1):
            fail('historical_ledger_regressed', 3)


def database_snapshot(path):
    path = Path(path)
    sidecars = []
    for suffix in ('-journal', '-wal', '-shm'):
        p = Path(str(path) + suffix)
        if p.exists() or p.is_symlink():
            raw, meta = read(p)
            if raw:
                fail('sqlite_sidecar_requires_offline_review')
            sidecars.append(meta)
    raw, metadata = read(path)
    if len(raw) < 100 or raw[:16] != b'SQLite format 3\x00' or raw[18:20] != b'\x01\x01':
        fail('sqlite_read_requires_delete_snapshot')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        if version != 1 or connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            fail('job_database_not_verified')
        schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        expected_columns = {'jobs': [('id', 'TEXT'), ('actor', 'TEXT'), ('request_key', 'TEXT'), ('intent', 'TEXT'), ('body', 'TEXT')],
                            'ledger': [('key', 'TEXT'), ('generation', 'INTEGER'), ('valid', 'INTEGER')],
                            'requests': [('job', 'TEXT'), ('cancel_requested', 'INTEGER')]}
        allowed_names = set(expected_columns) | {'sqlite_autoindex_jobs_1', 'sqlite_autoindex_jobs_2',
                                                  'sqlite_autoindex_ledger_1', 'sqlite_autoindex_requests_1'}
        if {row[1] for row in schema} != allowed_names:
            fail('job_database_schema_changed')
        for table, expected in expected_columns.items():
            columns = connection.execute('PRAGMA table_info(' + table + ')').fetchall()
            if [(row[1], row[2]) for row in columns] != expected:
                fail('job_database_schema_changed')
        rows = connection.execute('SELECT id,actor,request_key,intent,body FROM jobs ORDER BY id LIMIT 10001').fetchall()
        if len(rows) > 10000:
            fail('job_metadata_budget_exceeded')
        states, receivers, row_sums, facts = {}, [], {}, {}
        unsafe = []
        for row in rows:
            data = json.loads(row[4])
            state = data.get('state')
            states[state] = states.get(state, 0) + 1
            row_sums[row[0]] = sha(canonical(list(row)))
            facts[row[0]] = {key: data.get(key) for key in ('state', 'published', 'durability', 'verification', 'writer_exited')}
            if (state not in TERMINAL or data.get('published') == 'unknown'
                    or not data.get('writer_exited')
                    or data.get('publish_intent') and not data.get('publish_aborted') and data.get('published') is not True):
                unsafe.append(row[0])
            identity = (data.get('receiver') or {}).get('identity')
            if identity:
                receivers.append(identity)
        requests = connection.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
        ledger = _validated_ledger_entries(connection.execute(
            'SELECT key,generation,valid FROM ledger ORDER BY key LIMIT 10001').fetchall())
    finally:
        connection.close()
    if read(path)[0] != raw:
        fail('job_database_changed_during_inspection')
    return {**metadata, 'user_version': version, 'rows': row_sums, 'facts': facts, 'count': len(rows),
            'states': states, 'requests': requests, 'ledger_sha256': sha(canonical(ledger)), 'ledger_entries': ledger,
            'schema_sha256': sha(canonical(schema)),
            'unsafe_jobs': unsafe, 'receiver_identities': receivers, 'sidecars': sidecars}


def object_info(path):
    path = Path(path)
    parent = directory(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            fail('unsafe_anchor_type')
        return {'path': str(path), 'runtime': [info.st_dev, info.st_ino],
                'identity': persistent_identity(path), 'uid': info.st_uid,
                'mode': stat.S_IMODE(info.st_mode), 'nlink': info.st_nlink,
                'directory': stat.S_ISDIR(info.st_mode)}
    finally:
        close(parent)


def spool_inventory(root):
    root = Path(root)
    result = []
    count = 0
    for parent, names, files, parent_fd in os.fwalk(root, follow_symlinks=False):
        for name in sorted(names + files):
            count += 1
            if count > 10000:
                fail('spool_inventory_budget_exceeded')
            path = Path(parent) / name
            item = object_info(path)
            if not item['directory']:
                raw, meta = read(path)
                item.update(bytes=len(raw), sha256=meta['sha256'])
            result.append(item)
    return result


class LaunchCtl:
    def __init__(self):
        self.domain = 'gui/' + str(os.getuid())
        self.target = self.domain + '/' + LABEL

    def command(self, *args, check=True):
        result = subprocess.run(['launchctl', *args], capture_output=True, text=True, timeout=10)
        if check and result.returncode:
            fail('launchctl_operation_failed', 4)
        return result

    def disabled(self):
        raw = self.command('print-disabled', self.domain).stdout
        selected = [line.strip() for line in raw.splitlines() if re.match(r'"' + re.escape(LABEL) + r'"\s*=>', line.strip())]
        if not selected:
            return False  # No override means the ordinary enabled state.
        if len(selected) != 1:
            fail('origin_disabled_state_unverifiable', 4)
        match = re.fullmatch(r'"' + re.escape(LABEL) + r'"\s*=>\s*(true|false|enabled|disabled)', selected[0])
        if match is None:
            fail('origin_disabled_state_unverifiable', 4)
        return match.group(1) in ('true', 'disabled')

    def loaded(self):
        return self.command('print', self.target, check=False).returncode == 0

    def disable(self):
        self.command('disable', self.target)
        if not self.disabled():
            fail('origin_disable_not_confirmed', 4)

    def enable(self):
        self.command('enable', self.target)
        if self.disabled():
            fail('origin_enable_not_confirmed', 4)

    def stop(self, plan):
        self.disable()
        self.command('bootout', self.target, check=False)
        deadline = time.monotonic() + 30
        while self.loaded():
            if time.monotonic() >= deadline:
                fail('origin_exit_unconfirmed', 4)
            time.sleep(.1)
        self.quiescent(plan)

    def quiescent(self, plan):
        if not self.disabled() or self.loaded():
            fail('origin_not_persistently_quiescent', 3)
        with socket.socket() as connection:
            connection.settimeout(1)
            if connection.connect_ex(('127.0.0.1', plan['port'])) == 0:
                fail('origin_port_still_active', 3)
        paths = [plan['database']['path'], str(Path(plan['control_directory']) / 'file-jobs.lock'),
                 str(Path(plan['control_directory']) / 'private-roots.lock')]
        for root in plan['spool_roots']:
            result = subprocess.run(['/usr/sbin/lsof', '-nP', '-t', '+D', root], capture_output=True, text=True, timeout=10)
            if (result.returncode not in (0, 1) or result.stderr.strip()
                    or any(int(v) != os.getpid() for v in result.stdout.split())):
                fail('spool_handles_unconfirmed', 3)
        result = subprocess.run(['/usr/sbin/lsof', '-nP', '-t', *paths], capture_output=True, text=True, timeout=10)
        if (result.returncode not in (0, 1) or result.stderr.strip()
                or any(int(v) != os.getpid() for v in result.stdout.split())):
            fail('job_handles_unconfirmed', 3)
        from peters_mcp.file_receiver import process_identity, Isolated
        boot = boot_session_id().casefold()
        current_database = database_snapshot(Path(plan['database']['path']))
        for expected in current_database['receiver_identities']:
            if str(expected.get('boot', '')).casefold() != boot:
                continue
            try:
                actual = process_identity(expected['pid'])
            except Isolated:
                live = subprocess.run(['/bin/ps', '-p', str(expected['pid']), '-o', 'pid='], capture_output=True, text=True)
                if live.stdout.strip():
                    fail('receiver_exit_unverifiable', 3)
            else:
                if actual == expected:
                    fail('receiver_still_alive', 3)

    def start(self, plan):
        current = read(Path(plan['targets']['origin']['path']))[1]['sha256']
        choices = [name for name, definition in plan['definitions'].items() if definition['sha256'] == current]
        if len(choices) != 1:
            fail('origin_start_definition_not_approved', 4)
        bundle = choices[0]
        self.enable()
        result = self.command('bootstrap', self.domain, plan['targets']['origin']['path'], check=False)
        if result.returncode and not self.loaded():
            self.disable()
            fail('origin_bootstrap_failed', 4)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.loaded():
                try:
                    self.identity(plan, bundle)
                    with socket.socket() as connection:
                        connection.settimeout(.2)
                        if connection.connect_ex(('127.0.0.1', plan['port'])) == 0:
                            return
                except (MaintenanceError, ValueError, OSError):
                    pass  # launchctl may be loaded before exec/PID/TCP readiness.
            time.sleep(.1)
        self.disable()
        fail('origin_load_unconfirmed', 4)

    @staticmethod
    def definition(raw):
        lines = raw.splitlines()
        starts = [i for i, line in enumerate(lines) if line.strip() == 'arguments = {']
        if len(starts) != 1:
            fail('loaded_origin_arguments_unverifiable', 4)
        start = starts[0]
        indent = lines[start][:len(lines[start]) - len(lines[start].lstrip())]
        arguments = []
        for line in lines[start + 1:]:
            if line == indent + '}':
                break
            value = line.strip()
            if not value or value in ('{', '}'):
                fail('loaded_origin_arguments_unverifiable', 4)
            arguments.append(value)
        else:
            fail('loaded_origin_arguments_unverifiable', 4)
        def field(name):
            prefix = indent + name + ' = '
            values = [line[len(prefix):] for line in lines if line.startswith(prefix)]
            if len(values) != 1:
                fail('loaded_origin_definition_unverifiable', 4)
            return values[0]
        pid = field('pid')
        if not re.fullmatch(r'[1-9][0-9]*', pid):
            fail('origin_running_pid_unconfirmed', 4)
        return {'arguments': arguments, 'program': field('program'),
                'working_directory': field('working directory'), 'pid': int(pid)}

    @staticmethod
    def process_arguments(pid):
        # Darwin KERN_PROCARGS2 supplies the real NUL-delimited argv, avoiding
        # ambiguous shell/ps text and prefix/substring matching.
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        function = library.sysctl
        function.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_int
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t()
        if function(mib, 3, None, ctypes.byref(size), None, 0) or not 4 < size.value <= 1024 * 1024:
            fail('origin_process_arguments_unverifiable', 4)
        output = ctypes.create_string_buffer(size.value)
        if function(mib, 3, output, ctypes.byref(size), None, 0):
            fail('origin_process_arguments_unverifiable', 4)
        raw = output.raw[:size.value]
        count = struct.unpack_from('=i', raw)[0]
        if not 1 <= count <= 512:
            fail('origin_process_arguments_unverifiable', 4)
        end = raw.find(b'\0', 4)
        if end < 0:
            fail('origin_process_arguments_unverifiable', 4)
        executable = os.fsdecode(raw[4:end])
        cursor = end
        while cursor < len(raw) and raw[cursor] == 0:
            cursor += 1
        arguments = []
        for _ in range(count):
            end = raw.find(b'\0', cursor)
            if end < 0:
                fail('origin_process_arguments_unverifiable', 4)
            arguments.append(os.fsdecode(raw[cursor:end]))
            cursor = end + 1
        return executable, arguments

    def matches(self, plan, bundle):
        result = self.command('print', self.target, check=False)
        if result.returncode:
            return False
        try:
            actual = self.definition(result.stdout)
        except MaintenanceError:
            return False
        expected = plistlib.loads(decoded(plan['definitions'][bundle]['raw']))
        return (actual['arguments'] == expected['ProgramArguments']
                and actual['program'] == expected['ProgramArguments'][0]
                and actual['working_directory'] == expected['WorkingDirectory'])

    def identity(self, plan, bundle):
        actual = self.definition(self.command('print', self.target).stdout)
        settings = plistlib.loads(decoded(plan['definitions'][bundle]['raw']))
        if (actual['arguments'] != settings['ProgramArguments']
                or actual['program'] != settings['ProgramArguments'][0]
                or actual['working_directory'] != settings['WorkingDirectory']):
            fail('origin_process_not_selected_bundle', 4)
        from peters_mcp.file_receiver import process_identity
        identity = process_identity(actual['pid'])
        executable, arguments = self.process_arguments(actual['pid'])
        expected = settings['ProgramArguments']
        if (arguments != expected or Path(executable).resolve() != Path(expected[0]).resolve()
                or process_identity(actual['pid']) != identity
                or self.definition(self.command('print', self.target).stdout) != actual):
            fail('origin_process_command_mismatch', 4)
        return identity


def startup_definition(path):
    raw, meta = read(path, 65536)
    settings = plistlib.loads(raw)
    args = settings.get('ProgramArguments', [])
    if (settings.get('Label') != LABEL or len(args) < 3 or args[1] != '-B'
            or Path(args[2]).name != 'run_release.py'
            or set(settings.get('EnvironmentVariables', {})) - {'PYTHONDONTWRITEBYTECODE'}):
        fail('unsupported_origin_definition')
    flags = {}
    index = 3
    allowed = {'--access-config', '--config', '--history-config', '--file-config', '--file-export-config',
               '--chunked-export-config', '--port'}
    while index < len(args):
        flag = args[index]
        if flag not in allowed or flag in flags or index + 1 >= len(args):
            fail('unsupported_origin_arguments')
        flags[flag] = args[index + 1]
        index += 2
    if not {'--access-config', '--config', '--file-config', '--port'} <= flags.keys():
        fail('missing_origin_configuration')
    if Path(settings['WorkingDirectory']) != Path(args[2]).parent:
        fail('origin_working_directory_mismatch')
    return raw, meta, settings, flags


def inspect_origin(path, host=None, resume_plan=None, resume_sha=None):
    host = host or LaunchCtl()
    resumed = None
    raw, meta, settings, flags = startup_definition(path)
    if host.disabled():
        if resume_plan is None or resume_sha is None:
            fail('origin_originally_disabled')
        resumed = owned_pre_target_stop(resume_plan, resume_sha, path, host)
    elif resume_plan is not None or resume_sha is not None:
        fail('owned_stop_is_no_longer_disabled')
    projects_raw, projects_meta = read(Path(flags['--config']), 65536)
    projects = json.loads(projects_raw)
    policy_raw, policy_meta = read(Path(flags['--file-config']), 65536)
    policy = json.loads(policy_raw)
    control = Path(policy['control_directory'])
    manifest_raw, manifest_meta = read(control / 'private-roots.json', 262144)
    manifest = json.loads(manifest_raw)
    if (set(manifest) != {'version', 'generation', 'control_identity', 'lock_identity', 'roots'}
            or manifest['version'] != 1 or type(manifest['generation']) is not int
            or manifest['generation'] < 1 or not isinstance(manifest['roots'], list)):
        fail('legacy_manifest_not_supported')
    anchors = []
    old_devices = {}
    def anchor(path, old, private=False):
        if type(old) is not list or len(old) != 2 or any(type(v) is not int for v in old):
            fail('invalid_legacy_identity')
        current = object_info(path)
        if current['runtime'][1] != old[1] or current['uid'] != os.getuid():
            fail('legacy_anchor_not_equivalent')
        if private and current['mode'] != (0o700 if current['directory'] else 0o600):
            fail('legacy_anchor_permissions_changed')
        if not current['directory'] and current['nlink'] != 1:
            fail('legacy_anchor_linked')
        mapped = old_devices.setdefault(str(old[0]), current['identity']['volume_uuid'])
        if mapped != current['identity']['volume_uuid']:
            fail('legacy_device_mapping_ambiguous')
        current['legacy'] = old
        anchors.append(current)
        return current['identity']
    after_manifest = copy.deepcopy(manifest)
    after_manifest.update(version=2, generation=manifest['generation'] + 1,
                          control_identity=anchor(control, manifest['control_identity'], True),
                          lock_identity=anchor(control / 'private-roots.lock', manifest['lock_identity'], True))
    jobs_lock = object_info(control / 'file-jobs.lock')
    if (jobs_lock['directory'] or jobs_lock['mode'] != 0o600 or jobs_lock['uid'] != os.getuid()
            or jobs_lock['nlink'] != 1):
        fail('unsafe_job_lock')
    anchors.append(jobs_lock)
    for before, after in zip(manifest['roots'], after_manifest['roots']):
        if set(before) != {'path', 'status', 'parent_identity', 'identity'} or before['status'] not in {'pending', 'active'}:
            fail('invalid_legacy_root')
        root = Path(before['path'])
        after['parent_identity'] = anchor(root.parent, before['parent_identity'])
        if before['identity'] is not None:
            after['identity'] = anchor(root, before['identity'], True)
        elif before['status'] != 'pending':
            fail('active_legacy_root_without_identity')
    after_projects = copy.deepcopy(projects)
    pins = []
    for before, after in zip(projects['projects'], after_projects['projects']):
        if before.get('repository_id') is None:
            continue
        probe = repository_probe(Path(before['root']))
        current = probe['common_runtime_identity']
        matches = [int(old) for old in old_devices if repository_pin_v1(probe['common'], int(old), current[1]) == before['repository_id']]
        if len(matches) != 1 or old_devices[str(matches[0])] != probe['common_identity']['volume_uuid']:
            fail('repository_pin_not_equivalent')
        after['repository_id'] = probe['repository_id']
        pins.append({'project_id': before['id'], 'before': before['repository_id'], 'after': after['repository_id'],
                     'common': str(probe['common']), 'identity': probe['common_identity'], 'runtime': current})
    db = database_snapshot(control / 'file-jobs.sqlite3')
    if db['unsafe_jobs'] or db['requests']:
        fail('jobs_not_quiescent_for_migration')
    unchanged = []
    for flag in ('--access-config', '--history-config', '--file-config', '--file-export-config',
                 '--chunked-export-config'):
        if flag in flags:
            _, info = read(Path(flags[flag]), 65536)
            unchanged.append(info)
    tunnel = Path(path).parent / (TUNNEL + '.plist')
    if tunnel.exists():
        unchanged.append(read(tunnel, 65536)[1])
    spool = []
    for row in manifest['roots']:
        if row['identity'] is not None:
            spool.extend(spool_inventory(Path(row['path'])))
    return {'format_version': 1, 'created_at': now(), 'origin_enabled': True,
            'origin': {**meta, 'raw': encoded(raw)}, 'origin_settings': settings,
            'flags': flags, 'control_directory': str(control), 'spool_roots': policy['spool_roots'],
            'port': int(flags['--port']), 'projects': {**projects_meta, 'after': encoded(json.dumps(after_projects, ensure_ascii=False, indent=2).encode() + b'\n')},
            'manifest': {**manifest_meta, 'after': encoded(canonical(after_manifest))},
            'anchors': anchors, 'pins': pins, 'database': db, 'unchanged': unchanged,
            'spool_inventory': spool, 'resumed_from': resumed}


def package_info(root):
    root = Path(root).absolute()
    directory_fd = directory(root)
    close(directory_fd)
    raw, _ = read(root / 'manifest.json', 1024 * 1024)
    manifest = json.loads(raw)
    rows = manifest['files']
    if (manifest['bundle_mode'] not in ('candidate', 'rollback')
            or manifest['content_fingerprint'] != sha(canonical(rows))
            or rows != sorted(rows, key=lambda r: r['path'])):
        fail('release_manifest_invalid')
    names = set()
    for row in rows:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or row['path'] in names:
            fail('release_path_invalid')
        names.add(row['path'])
        payload, _ = read(root / relative, 16 * 1024 * 1024)
        if len(payload) != row['bytes'] or sha(payload) != row['sha256']:
            fail('release_payload_changed')
    required = {'run_release.py', 'peters_mcp/_file_release_mode.py', 'peters_mcp/cloudflare.py',
                'peters_mcp/private_roots.py', 'peters_mcp/fs_identity.py',
                'peters_mcp/workspaces.py', 'peters_mcp/file_jobs.py', 'peters_mcp/file_config.py'}
    if not required <= names:
        fail('release_closure_incomplete')
    expected_files = names | {'manifest.json'}
    expected_directories = {str(parent) for name in names for parent in Path(name).parents if str(parent) != '.'}
    for item in root.rglob('*'):
        relative = str(item.relative_to(root))
        if item.is_symlink():
            fail('linked_release_entry')
        if relative == 'work':
            if not item.is_dir():
                fail('unsafe_runtime_work')
            continue
        if relative.startswith('work/'):
            if not re.fullmatch(r'work/remote-audit\.jsonl(?:\.[1-3])?', relative) or not item.is_file():
                fail('unapproved_runtime_entry')
            continue
        if item.is_dir():
            if relative not in expected_directories:
                fail('unapproved_release_directory')
        elif relative not in expected_files:
            fail('unapproved_release_file')
    marker = read(root / 'peters_mcp/_file_release_mode.py')[0]
    expected = ('# Generated immutable release mode.\nINSPECTION_ONLY = ' +
                ('True' if manifest['bundle_mode'] == 'rollback' else 'False') + '\nREQUIRE_PRIVATE_CONFIG = True\n').encode()
    if marker != expected or manifest.get('require_private_config') is not True:
        fail('release_mode_changed')
    return {'root': str(root), 'manifest_sha256': sha(raw),
            'fingerprint': manifest['content_fingerprint'], 'mode': manifest['bundle_mode']}


def verify_maintenance(path):
    path = Path(path)
    raw, _ = read(path, 1024 * 1024)
    manifest = json.loads(raw)
    if (manifest.get('format_version') != 1 or manifest.get('python') != list(sys.version_info[:2])
            or set(manifest.get('dependencies', {})) != {'candidate', 'rollback'}):
        fail('maintenance_manifest_invalid')
    names = set()
    for row in manifest['files']:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or row['path'] in names:
            fail('maintenance_path_invalid')
        content, _ = read(path.parent / relative, 16 * 1024 * 1024)
        if sha(content) != row['sha256'] or len(content) != row['bytes']:
            fail('maintenance_payload_changed')
        names.add(row['path'])
    if not {'identity_maintenance.py', 'migrate_persistent_identity.py', 'switch_identity_release.py'} <= names:
        fail('maintenance_closure_incomplete')
    actual = set()
    for item in path.parent.rglob('*'):
        if item.is_symlink() or item.is_dir():
            fail('unapproved_maintenance_entry')
        actual.add(str(item.relative_to(path.parent)))
    if actual != names | {path.name}:
        fail('unapproved_maintenance_file')
    return {'path': str(path), 'sha256': sha(raw), 'dependencies': manifest['dependencies'],
            'python': manifest['python']}


def make_plan(snapshot, candidate, rollback, maintenance, operation_id):
    if not _ID.fullmatch(operation_id):
        fail('invalid_operation_id')
    packages = {name: package_info(root) for name, root in [('candidate', candidate), ('rollback', rollback)]}
    if any(value['mode'] != key for key, value in packages.items()):
        fail('release_mode_mismatch')
    tool = verify_maintenance(maintenance)
    if tool['dependencies'] != {name: package['fingerprint'] for name, package in packages.items()}:
        fail('maintenance_dependency_mismatch')
    original_raw, original_meta = read(Path(snapshot['origin']['path']), 65536)
    if sha(original_raw) != snapshot['origin']['sha256']:
        fail('origin_changed_after_snapshot')
    definitions = {}
    for name, package in packages.items():
        settings = copy.deepcopy(snapshot['origin_settings'])
        settings['WorkingDirectory'] = package['root']
        settings['ProgramArguments'][2] = str(Path(package['root']) / 'run_release.py')
        raw = plistlib.dumps(settings)
        definitions[name] = {'raw': encoded(raw), 'sha256': sha(raw)}
    targets = {'origin': file_target(Path(snapshot['origin']['path']), decoded(definitions['candidate']['raw'])),
               'manifest': file_target(Path(snapshot['manifest']['path']), decoded(snapshot['manifest']['after'])),
               'projects': file_target(Path(snapshot['projects']['path']), decoded(snapshot['projects']['after']))}
    for name in ('manifest', 'projects'):
        if targets[name]['sha256'] != snapshot[name]['sha256']:
            fail('configuration_changed_after_snapshot')
    control = Path(snapshot['control_directory'])
    result = {'format_version': 1, 'operation_id': operation_id, 'created_at': now(),
            'operation_directory': str(control / 'identity-repair' / operation_id),
            'control_directory': str(control), 'spool_roots': snapshot['spool_roots'], 'port': snapshot['port'],
            'origin_enabled': snapshot['origin_enabled'], 'targets': targets, 'definitions': definitions,
            'packages': packages, 'maintenance': tool, 'anchors': snapshot['anchors'], 'pins': snapshot['pins'],
            'database': snapshot['database'], 'unchanged': snapshot['unchanged'],
            'spool_inventory': snapshot['spool_inventory'], 'resumed_from': snapshot.get('resumed_from')}
    if result.get('resumed_from') is not None:
        proof = result['resumed_from']
        previous, _ = load_plan(proof['plan_path'], proof['plan_sha256'])
        resume_compatible(result, previous)
    return result


def load_plan(path, expected):
    raw, _ = read(Path(path), 4 * 1024 * 1024)
    if sha(raw) != expected:
        fail('plan_sha256_mismatch')
    plan = json.loads(raw)
    if plan.get('format_version') != 1 or not _ID.fullmatch(plan['operation_id']):
        fail('invalid_plan')
    control = Path(plan['control_directory'])
    if Path(plan['operation_directory']) != control / 'identity-repair' / plan['operation_id']:
        fail('operation_directory_not_protected')
    for name, package in plan['packages'].items():
        if package_info(package['root']) != package or package['mode'] != name:
            fail('release_not_approved')
    if verify_maintenance(plan['maintenance']['path']) != plan['maintenance']:
        fail('maintenance_not_approved')
    return plan, expected


def owned_pre_target_stop(path, digest, origin_path, host):
    """Read-only continuity proof for this operator's interrupted stop phase.

    This cannot adopt an externally disabled service, a partial migration or an
    activated operation. It permits a corrected, independently frozen tool to
    create a new exact plan while retaining the already owned disabled state.
    """
    previous, checked = load_plan(Path(path), digest)
    if Path(previous['targets']['origin']['path']) != Path(origin_path):
        fail('owned_stop_origin_mismatch')
    operation = Path(previous['operation_directory'])
    if read(operation / 'plan.json', 4 * 1024 * 1024)[0] != canonical(previous):
        fail('owned_stop_plan_not_frozen')
    records = journal_read(operation / 'journal.jsonl')[0]
    if (not records or any(record.get('plan_sha256') != digest for record in records)
            or not any(record['event'] == 'MAINTENANCE_INTENT'
                       and record.get('original_effective_enabled') is True for record in records)
            or any(record['event'].startswith('AFTER_') or record['event'] in
                   {'PREPARED', 'COMMITTED', 'SUPERSEDED_BEFORE_TARGETS'} for record in records)
            or (operation / 'activation.json').exists() or check_pending(previous, digest)):
        fail('owned_pre_target_stop_required')
    host.quiescent(previous)
    check_anchors(previous)
    verify_spool_inventory(previous, pre_activation=True)
    verify_database(previous, pre_activation=True)
    for target in previous['targets'].values():
        if read(Path(target['path']))[1]['sha256'] != target['sha256']:
            fail('owned_stop_targets_not_before')
    intent = [record for record in records if record['event'] == 'MAINTENANCE_INTENT'][0]
    return {'plan_path': str(operation / 'plan.json'), 'plan_sha256': digest,
            'operation_id': previous['operation_id'], 'intent_sha256': intent['sha256']}


def resume_compatible(current, previous):
    """Only operation bookkeeping and the corrected tool may change on resume.

    Runtime device numbers and directory link counts are observations, not
    cross-boot identity. Every target byte, permission, definition, package
    location, stable anchor, database fact and authorization input stays bound.
    """
    allowed = {'operation_id', 'operation_directory', 'created_at', 'maintenance', 'resumed_from'}
    def normalized(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == 'nlink' and value.get('directory') is True:
                    continue
                if key == 'runtime' and isinstance(item, list) and len(item) == 2:
                    result[key] = ['runtime-device', item[1]]
                else:
                    result[key] = normalized(item)
            return result
        if isinstance(value, list):
            return [normalized(item) for item in value]
        return value
    old = normalized({key: value for key, value in previous.items() if key not in allowed})
    new = normalized({key: value for key, value in current.items() if key not in allowed})
    if old != new:
        fail('owned_stop_resume_scope_changed')


def ensure_operation(plan, plan_sha):
    control = Path(plan['control_directory'])
    if persistent_identity(control) != plan['anchors'][0]['identity']:
        fail('control_anchor_changed')
    private_directory(control / 'identity-repair')
    operation = Path(plan['operation_directory'])
    private_directory(operation)
    frozen = operation / 'plan.json'
    raw = canonical(plan)
    if sha(raw) != plan_sha:
        fail('noncanonical_plan_encoding')
    if frozen.exists():
        if read(frozen)[0] != raw:
            fail('operation_plan_conflict')
        confirm_durable_file(frozen, raw)
    else:
        write_new(frozen, raw)
    return operation


def check_anchors(plan):
    for expected in plan['anchors']:
        current = object_info(Path(expected['path']))
        if (current['identity'] != expected['identity']
                or current['mode'] != expected['mode'] or current['uid'] != expected['uid']
                or not current['directory'] and current['nlink'] != expected['nlink']):
            fail('approved_anchor_changed', 3)
    for pin in plan['pins']:
        probe = repository_probe(Path(next(p['root'] for p in json.loads(decoded(plan['targets']['projects']['after']))['projects']
                                          if p['id'] == pin['project_id'])))
        if (probe['common_identity'] != pin['identity'] or probe['repository_id'] != pin['after']
                or str(probe['common']) != pin['common']):
            fail('approved_repository_changed', 3)
    for metadata in plan['unchanged']:
        current = read(Path(metadata['path']))[1]
        if current['sha256'] != metadata['sha256']:
            fail('nonmigration_configuration_changed', 3)
        if metadata.get('parent_identity') is not None and (
                persistent_identity(Path(metadata['path']).parent) != metadata['parent_identity']
                or any(current[key] != metadata[key] for key in ('mode', 'uid', 'gid'))):
            fail('bound_configuration_identity_changed', 3)


def reject_aborted(plan, plan_sha):
    records = journal_read(Path(plan['operation_directory']) / 'journal.jsonl')[0]
    if any(record.get('plan_sha256') != plan_sha for record in records):
        fail('maintenance_journal_plan_mismatch', 3)
    if any(record['event'] == 'ABORTED_BEFORE_TARGETS' for record in records):
        fail('maintenance_operation_aborted', 3)


def _code_switch_previous(plan):
    previous, digest = load_plan(plan['previous_plan_path'], plan['previous_plan_sha256'])
    active = plan['previous_active_bundle']
    if (active not in ('candidate', 'rollback')
            or previous['operation_id'] != plan['previous_operation_id']
            or previous['maintenance'] != plan['previous_maintenance']
            or previous['control_directory'] != plan['control_directory']
            or previous['spool_roots'] != plan['spool_roots'] or previous['port'] != plan['port']
            or previous['targets']['origin']['path'] != plan['targets']['origin']['path']
            or previous['definitions'][active]['sha256'] != plan['targets']['origin']['sha256']
            or any(previous['targets'][name]['path'] != plan['targets'][name]['path']
                   or previous['targets'][name]['after_sha256'] != plan['targets'][name]['sha256']
                   for name in ('manifest', 'projects'))):
        fail('previous_code_switch_binding_changed', 3)
    operation = require_owned_maintenance(previous, digest)
    records = journal_read(operation / 'journal.jsonl')[0]
    if 'COMMITTED' not in [row['event'] for row in records]:
        fail('previous_operation_not_committed', 3)
    activation_data = json.loads(read(operation / 'activation.json', 16384)[0])
    if activation_data.get('state') != 'ACTIVATING' or activation_data.get('plan_sha256') != digest:
        fail('previous_activation_not_bound', 3)
    verify_runtime_inputs(previous, digest, active)
    # Historical R7 verifies these retained payloads when restoring. A fresh
    # current inventory must never silently adopt their deletion/replacement.
    verify_spool_inventory(previous, pre_activation=False)
    return previous, digest, active


def _no_other_maintenance(plan):
    root = Path(plan['control_directory']) / 'identity-repair'
    if not root.exists():
        return
    entries = list(root.iterdir())
    if len(entries) > 1000:
        fail('maintenance_inventory_budget_exceeded', 3)
    for entry in entries:
        if entry.is_symlink():
            fail('unsafe_maintenance_entry', 3)
        if not entry.is_dir() or entry == Path(plan['operation_directory']):
            continue
        records = journal_read(entry / 'journal.jsonl')[0]
        names = {row['event'] for row in records}
        if ('MAINTENANCE_INTENT' in names and not names.intersection(
                {'COMMITTED', 'ABORTED_BEFORE_TARGETS', 'SUPERSEDED_BEFORE_TARGETS'})):
            fail('another_unfinished_maintenance_operation', 3)


def _before_code_switch_targets(plan):
    if (plan.get('operation_kind') != 'runtime_code_update_no_identity_changes'
            or set(plan['targets']) != {'origin', 'manifest', 'projects'}
            or any(plan['targets'][name]['sha256'] != plan['targets'][name]['after_sha256']
                   for name in ('manifest', 'projects'))
            or any(pin['before'] != pin['after'] for pin in plan['pins'])):
        fail('before_only_requires_code_switch', 3)
    result = {}
    for name, target in plan['targets'].items():
        raw, current = read(Path(target['path']))
        if (sha(decoded(target['before'])) != target['sha256'] or current['sha256'] != target['sha256']
                or persistent_identity(Path(target['path']).parent) != target['parent_identity']
                or any(current[key] != target[key] for key in ('mode', 'uid', 'gid'))):
            fail('code_switch_target_not_before', 3)
        result[name] = current['sha256']
    return result


def _no_code_switch_progress(plan, records):
    operation = Path(plan['operation_directory'])
    if (any(row['event'] in ('PREPARED', 'COMMITTED') or row['event'].startswith('AFTER_') for row in records)
            or (operation / 'activation.json').exists()
            or (operation / 'activation.json').is_symlink()
            or (Path(plan['control_directory']) / PENDING).exists()
            or (Path(plan['control_directory']) / PENDING).is_symlink()):
        fail('code_switch_transaction_already_progressed', 3)


def _historical_ledger_entries(plan):
    bound = plan['database']
    if 'ledger_entries' in bound:
        entries = _validated_ledger_entries(bound['ledger_entries'])
        if sha(canonical(entries)) != bound['ledger_sha256']:
            fail('bound_ledger_digest_invalid', 3)
        return entries
    # R7 plans have a ledger hash but not its rows. Recover the facts only from
    # their already-bound immutable DB backup, never from the current database.
    operation = Path(plan['operation_directory'])
    digest = sha(canonical(plan))
    if (operation != Path(plan['control_directory']) / 'identity-repair' / plan['operation_id']
            or read(operation / 'plan.json', 4 * 1024 * 1024)[0] != canonical(plan)):
        fail('historical_ledger_plan_not_bound', 3)
    manifest = json.loads(read(operation / 'backup-manifest.json', 4 * 1024 * 1024)[0])
    entries = [row for row in manifest['files'] if row.get('role') == 'database']
    backup_path = operation / 'backups/database.before'
    if (manifest.get('plan_sha256') != digest or len(entries) != 1
            or entries[0].get('backup') != str(backup_path)
            or entries[0].get('sha256') != bound['sha256']
            or entries[0].get('source', {}).get('path') != bound['path']
            or entries[0].get('source', {}).get('sha256') != bound['sha256']):
        fail('historical_ledger_backup_not_bound', 3)
    raw, metadata = read(backup_path)
    if metadata['mode'] != 0o600 or sha(raw) != bound['sha256']:
        fail('historical_ledger_backup_not_bound', 3)
    for suffix in ('-journal', '-wal', '-shm'):
        if Path(str(backup_path) + suffix).exists() or Path(str(backup_path) + suffix).is_symlink():
            fail('historical_ledger_backup_sidecar', 3)
    snapshot = database_snapshot(backup_path)
    if (snapshot['sha256'] != bound['sha256'] or snapshot['schema_sha256'] != bound['schema_sha256']
            or snapshot['ledger_sha256'] != bound['ledger_sha256'] or snapshot['sidecars']):
        fail('historical_ledger_backup_not_bound', 3)
    for suffix in ('-journal', '-wal', '-shm'):
        if Path(str(backup_path) + suffix).exists() or Path(str(backup_path) + suffix).is_symlink():
            fail('historical_ledger_backup_sidecar', 3)
    return snapshot['ledger_entries']


def _code_switch_database(plan):
    current = database_snapshot(Path(plan['database']['path']))
    if (current['unsafe_jobs'] or current['requests']
            or current['schema_sha256'] != plan['database']['schema_sha256']
            or any(current['rows'].get(key) != value for key, value in plan['database']['rows'].items())):
        fail('code_switch_database_not_safe', 3)
    _ledger_continuity(_historical_ledger_entries(plan), current['ledger_entries'])
    return current


def _code_switch_output(path, plan):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        fail('code_switch_output_not_canonical', 3)
    forbidden = [Path(plan['control_directory']), *map(Path, plan['spool_roots']),
                 Path(plan['maintenance']['path']).parent]
    forbidden += [Path(package['root']) for package in plan['packages'].values()]
    if plan.get('previous_maintenance'):
        forbidden.append(Path(plan['previous_maintenance']['path']).parent)
    old_settings = plistlib.loads(decoded(plan['targets']['origin']['before']))
    forbidden.append(Path(old_settings['WorkingDirectory']))
    if any(path == root or path.is_relative_to(root) for root in forbidden):
        fail('code_switch_output_is_runtime_state', 3)
    return path


def _copy_restoration_output(path, raw, plan):
    path = _code_switch_output(path, plan)
    if path.exists() or path.is_symlink():
        if read(path, 4 * 1024 * 1024)[0] != raw:
            fail('restoration_output_conflict', 3)
        confirm_durable_file(path, raw)
    else:
        write_new(path, raw)
    return str(path)


def _restoration_file(plan, plan_sha, records):
    operation = Path(plan['operation_directory'])
    path = operation / 'abort-restoration.json'
    raw, metadata = read(path, 4 * 1024 * 1024)
    data = json.loads(raw)
    if (raw != canonical(data) or metadata['mode'] != 0o600
            or data.get('new_plan_sha256') != plan_sha
            or data.get('new_operation_id') != plan['operation_id']
            or data.get('previous_plan_path') != plan['previous_plan_path']
            or data.get('previous_plan_sha256') != plan['previous_plan_sha256']
            or data.get('previous_active_bundle') != plan['previous_active_bundle']
            or data.get('previous_maintenance') != plan['previous_maintenance']
            or data.get('before_targets') != {name: target['sha256'] for name, target in plan['targets'].items()}
            or not isinstance(data.get('restore_switch_id'), str)
            or not re.fullmatch(r'restore-[0-9a-f]{32}', data['restore_switch_id'])):
        fail('restoration_proof_invalid', 3)
    for row in records:
        if row['event'] in ('ABORT_INTENT', 'ABORTED_BEFORE_TARGETS') and (
                row.get('restoration_path') != str(path) or row.get('restoration_sha256') != sha(raw)):
            fail('restoration_journal_binding_changed', 3)
    aborted = [row for row in records if row['event'] == 'ABORTED_BEFORE_TARGETS']
    intents = [row for row in records if row['event'] == 'ABORT_INTENT']
    if aborted and (len(aborted) != 1 or len(intents) != 1 or intents[0]['sequence'] >= aborted[0]['sequence']):
        fail('restoration_abort_order_invalid', 3)
    return raw, data


def abort_before_targets(plan, plan_sha, restoration_output, host=None):
    """End only an owned, still-BEFORE code switch. Never restores databases."""
    host = host or LaunchCtl()
    operation = Path(plan['operation_directory'])
    if (operation != Path(plan['control_directory']) / 'identity-repair' / plan['operation_id']
            or read(operation / 'plan.json', 4 * 1024 * 1024)[0] != canonical(plan)
            or sha(canonical(plan)) != plan_sha):
        fail('owned_maintenance_plan_changed', 3)
    records = journal_read(operation / 'journal.jsonl')[0]
    if any(row.get('plan_sha256') != plan_sha for row in records):
        fail('maintenance_journal_plan_mismatch', 3)
    if any(row['event'] == 'ABORTED_BEFORE_TARGETS' for row in records):
        records = confirm_durable_journal(operation / 'journal.jsonl', plan_sha)
        raw, _ = _restoration_file(plan, plan_sha, records)
        confirm_durable_file(operation / 'abort-restoration.json', raw)
        # Historical proof retrieval must not stop a service already restored.
        output = _copy_restoration_output(restoration_output, raw, plan)
        return {'state': 'aborted_before_targets', 'idempotent': True,
                'restoration_bindings': output, 'restoration_sha256': sha(raw)}
    with operator_lock(plan, plan_sha):
        require_owned_maintenance(plan, plan_sha)
        host.quiescent(plan)
        with Lease(plan, plan_sha, host):
            records = confirm_durable_journal(operation / 'journal.jsonl', plan_sha)
            _no_code_switch_progress(plan, records)
            _no_other_maintenance(plan)
            before = _before_code_switch_targets(plan)
            check_anchors(plan)
            _code_switch_previous(plan)
            database = _code_switch_database(plan)
            proof = operation / 'abort-restoration.json'
            if proof.exists() or proof.is_symlink():
                raw, data = _restoration_file(plan, plan_sha, records)
                if data.get('database') != database:
                    fail('abort_proof_state_changed', 3)
                confirm_durable_file(proof, raw)
            else:
                data = {'format_version': 1, 'new_operation_id': plan['operation_id'],
                        'new_plan_sha256': plan_sha, 'previous_plan_path': plan['previous_plan_path'],
                        'previous_plan_sha256': plan['previous_plan_sha256'],
                        'previous_active_bundle': plan['previous_active_bundle'],
                        'previous_maintenance': plan['previous_maintenance'], 'before_targets': before,
                        'database': database, 'restore_switch_id': 'restore-' + uuid.uuid4().hex}
                raw = canonical(data)
                write_new(proof, raw)
            point('abort_restoration_durable')
            fields = {'restoration_path': str(proof), 'restoration_sha256': sha(raw)}
            if not any(row['event'] == 'ABORT_INTENT' for row in records):
                journal_append(operation / 'journal.jsonl', 'ABORT_INTENT', plan_sha, **fields)
            point('abort_intent_durable')
            journal_append(operation / 'journal.jsonl', 'ABORTED_BEFORE_TARGETS', plan_sha, **fields)
            point('abort_terminal_durable')
        output = _copy_restoration_output(restoration_output, raw, plan)
        return {'state': 'aborted_before_targets', 'idempotent': False,
                'restoration_bindings': output, 'restoration_sha256': sha(raw)}


def prepare_code_switch(previous_path, previous_sha, active_bundle, candidate, rollback,
                        maintenance_manifest, chunked_config, contract_sha, operation_id,
                        output, bindings_output, host=None):
    """Read current activated v2 state and create only two external plan files."""
    if not _ID.fullmatch(operation_id) or not re.fullmatch(r'[0-9a-f]{64}', contract_sha):
        fail('invalid_code_switch_identity')
    previous_path = Path(previous_path)
    previous, checked = load_plan(previous_path, previous_sha)
    host = host or LaunchCtl()
    if active_bundle not in ('candidate', 'rollback'):
        fail('invalid_active_bundle')
    old_operation = require_owned_maintenance(previous, checked)
    if 'COMMITTED' not in events(old_operation / 'journal.jsonl'):
        fail('previous_operation_not_committed', 3)
    previous_activation = json.loads(read(old_operation / 'activation.json', 16384)[0])
    if (previous_activation.get('state') != 'ACTIVATING'
            or previous_activation.get('plan_sha256') != checked
            or check_pending(previous, checked)):
        fail('previous_operation_not_active', 3)
    if host.disabled() or not host.loaded() or not host.matches(previous, active_bundle):
        fail('previous_origin_not_running', 3)
    identity = host.identity(previous, active_bundle)
    verify_runtime_inputs(previous, checked, active_bundle)
    verify_spool_inventory(previous, pre_activation=False)
    current_origin, origin_meta, settings, flags = startup_definition(Path(previous['targets']['origin']['path']))
    if sha(current_origin) != previous['definitions'][active_bundle]['sha256']:
        fail('previous_origin_definition_changed', 3)
    control = Path(previous['control_directory'])
    manifest_raw, _ = read(Path(previous['targets']['manifest']['path']))
    manifest = json.loads(manifest_raw)
    if manifest.get('version') != 2:
        fail('code_switch_requires_manifest_v2', 3)
    control_fd = directory(control)
    lock_fd = None
    try:
        lock_fd = os.open('private-roots.lock', _READ, dir_fd=control_fd)
        validate_manifest_v2(manifest, control_fd, lock_fd, control_dir=control)
    finally:
        if lock_fd is not None:
            close(lock_fd)
        close(control_fd)
    projects_raw, _ = read(Path(previous['targets']['projects']['path']))
    projects = json.loads(projects_raw)
    database = _code_switch_database(previous)
    packages = {name: package_info(root) for name, root in [('candidate', candidate), ('rollback', rollback)]}
    if any(package['mode'] != name for name, package in packages.items()):
        fail('release_mode_mismatch')
    tool = verify_maintenance(maintenance_manifest)
    if tool['dependencies'] != {name: package['fingerprint'] for name, package in packages.items()}:
        fail('maintenance_dependency_mismatch')
    tool_rows = json.loads(read(Path(maintenance_manifest), 1024 * 1024)[0])['files']
    for name in ('identity_maintenance.py', 'prepare_code_switch.py'):
        selected = [row for row in tool_rows if row['path'] == name]
        if len(selected) != 1 or read(HERE / name, 16 * 1024 * 1024)[1]['sha256'] != selected[0]['sha256']:
            fail('code_switch_preparer_not_frozen', 3)
    chunked_config = Path(chunked_config)
    config_raw, config_meta = read(chunked_config, 65536)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('chunked_configuration_invalid', 3)
            result[key] = value
        return result
    config = json.loads(config_raw, object_pairs_hook=unique)
    if (set(config) != {'version', 'enabled', 'max_file_bytes', 'min_free_bytes', 'protocol_version'}
            or type(config['version']) is not int or config['version'] != 1
            or type(config['enabled']) is not bool
            or type(config['max_file_bytes']) is not int or not 1 <= config['max_file_bytes'] <= 100_000_000
            or type(config['min_free_bytes']) is not int or config['min_free_bytes'] < 1024 * 1024 * 1024
            or config['protocol_version'] != 'raw-parts-v1' or config_meta['mode'] != 0o600):
        fail('chunked_configuration_invalid', 3)
    parent = object_info(chunked_config.parent)
    if not parent['directory'] or parent['mode'] != 0o700 or parent['uid'] != os.getuid():
        fail('chunked_configuration_parent_not_private', 3)
    definitions = {}
    for name, package in packages.items():
        updated = copy.deepcopy(settings)
        updated['WorkingDirectory'] = package['root']
        updated['ProgramArguments'][2] = str(Path(package['root']) / 'run_release.py')
        if '--chunked-export-config' in flags:
            index = updated['ProgramArguments'].index('--chunked-export-config')
            updated['ProgramArguments'][index + 1] = str(chunked_config)
        else:
            updated['ProgramArguments'].extend(['--chunked-export-config', str(chunked_config)])
        raw = plistlib.dumps(updated)
        definitions[name] = {'raw': encoded(raw), 'sha256': sha(raw)}
    anchors = [object_info(Path(row['path'])) for row in previous['anchors']]
    pins = []
    for project in projects['projects']:
        if project.get('repository_id') is None:
            continue
        probe = repository_probe(Path(project['root']))
        if probe['repository_id'] != project['repository_id']:
            fail('approved_repository_changed', 3)
        pins.append({'project_id': project['id'], 'before': probe['repository_id'], 'after': probe['repository_id'],
                     'common': str(probe['common']), 'identity': probe['common_identity'],
                     'runtime': probe['common_runtime_identity']})
    unchanged = []
    for path in dict.fromkeys([row['path'] for row in previous['unchanged']] + [str(chunked_config)]):
        info = read(Path(path), 65536)[1]
        info['parent_identity'] = persistent_identity(Path(path).parent)
        unchanged.append(info)
    spool = []
    for row in manifest['roots']:
        if row['identity'] is not None:
            spool.extend(spool_inventory(Path(row['path'])))
    plan = {'format_version': 1, 'operation_id': operation_id,
            'operation_directory': str(control / 'identity-repair' / operation_id),
            'created_at': now(), 'control_directory': str(control), 'spool_roots': previous['spool_roots'],
            'port': previous['port'], 'origin_enabled': True,
            'targets': {'origin': file_target(Path(origin_meta['path']), decoded(definitions['candidate']['raw'])),
                        'manifest': file_target(Path(previous['targets']['manifest']['path']), manifest_raw),
                        'projects': file_target(Path(previous['targets']['projects']['path']), projects_raw)},
            'definitions': definitions, 'packages': packages, 'maintenance': tool, 'anchors': anchors,
            'pins': pins, 'database': database, 'unchanged': unchanged, 'spool_inventory': spool,
            'resumed_from': None, 'operation_kind': 'runtime_code_update_no_identity_changes',
            'previous_operation_id': previous['operation_id'], 'previous_plan_path': str(previous_path),
            'previous_plan_sha256': checked, 'previous_process_identity': identity,
            'previous_active_bundle': active_bundle, 'previous_maintenance': previous['maintenance'],
            'approved_contract_plan_sha256': contract_sha}
    if (Path(plan['operation_directory']).exists()
            or host.identity(previous, active_bundle) != identity
            or database_snapshot(Path(previous['database']['path'])) != database):
        fail('code_switch_inputs_changed_or_operation_exists', 3)
    verify_runtime_inputs(previous, checked, active_bundle)
    verify_spool_inventory(previous, pre_activation=False)
    check_anchors(plan)
    raw = canonical(plan)
    if len(raw) > 4 * 1024 * 1024:
        fail('code_switch_plan_budget_exceeded', 3)
    _no_other_maintenance(plan)
    plan_sha = sha(raw)
    output = _code_switch_output(output, plan)
    bindings_output = _code_switch_output(bindings_output, plan)
    if output == bindings_output:
        fail('code_switch_outputs_overlap', 3)
    bindings = {'plan': str(output), 'plan_sha256': plan_sha, 'operation_id': operation_id,
                'candidate_root': packages['candidate']['root'], 'rollback_root': packages['rollback']['root'],
                'maintenance_manifest': tool['path'], 'maintenance_sha256': tool['sha256'],
                'packages': {name: package['fingerprint'] for name, package in packages.items()},
                'chunked_config': str(chunked_config), 'chunked_config_sha256': config_meta['sha256'],
                'database_count': database['count'], 'previous_process_identity': identity,
                'previous_plan': str(previous_path), 'previous_plan_sha256': checked,
                'previous_active_bundle': active_bundle, 'previous_maintenance': previous['maintenance']}
    write_new(output, raw)
    write_new(bindings_output, canonical(bindings))
    return {'state': 'prepared_not_deployed', **bindings, 'bindings': str(bindings_output)}


def verify_spool_inventory(plan, pre_activation):
    current = {}
    for root in {str(Path(item['path'])) for item in plan['anchors']
                 if item.get('directory') and any(item['path'] == r for r in plan['spool_roots'])}:
        current.update({item['path']: item for item in spool_inventory(Path(root))})
    # Include retained roots absent from the current selectable root list.
    manifest = json.loads(decoded(plan['targets']['manifest']['after']))
    for row in manifest['roots']:
        if row['identity'] is not None and row['path'] not in plan['spool_roots']:
            current.update({item['path']: item for item in spool_inventory(Path(row['path']))})
    expected = {item['path']: item for item in plan['spool_inventory']}
    def stable(item):
        return {key: value for key, value in item.items() if key != 'runtime'}
    if (pre_activation and set(current) != set(expected)
            or any(path not in current or stable(current[path]) != stable(item) for path, item in expected.items())):
        fail('legacy_spool_scene_changed', 3)


class Lease:
    def __init__(self, plan, plan_sha, host):
        self.plan, self.plan_sha, self.host = plan, plan_sha, host
        self.control_fd = None
        self.lock_fds = []
        self.lock_stamps = []

    def __enter__(self):
        self.host.quiescent(self.plan)
        self.control_fd = directory(Path(self.plan['control_directory']))
        try:
            for name in ('private-roots.lock', 'file-jobs.lock'):
                fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.control_fd)
                self.lock_fds.append(fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    fail('unsafe_maintenance_lock', 3)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            fail('maintenance_lock_busy', 3)
                        time.sleep(.01)
                self.lock_stamps.append([info.st_dev, info.st_ino])
                approved = next((a for a in self.plan['anchors'] if Path(a['path']) == Path(self.plan['control_directory']) / name), None)
                if approved is None or persistent_identity_fd(fd) != approved['identity']:
                    fail('approved_maintenance_lock_changed', 3)
            self.validate()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def validate(self):
        if self.control_fd is None or len(self.lock_fds) != 2:
            fail('maintenance_lease_required', 3)
        if persistent_identity_fd(self.control_fd) != self.plan['anchors'][0]['identity']:
            fail('maintenance_control_changed', 3)
        for index, name in enumerate(('private-roots.lock', 'file-jobs.lock')):
            descriptor = os.fstat(self.lock_fds[index])
            path = os.stat(name, dir_fd=self.control_fd, follow_symlinks=False)
            if [descriptor.st_dev, descriptor.st_ino] != self.lock_stamps[index] or [path.st_dev, path.st_ino] != self.lock_stamps[index]:
                fail('maintenance_lock_replaced', 3)

    def __exit__(self, *args):
        descriptors, self.lock_fds = self.lock_fds, []
        if self.control_fd is not None:
            descriptors.append(self.control_fd)
            self.control_fd = None
        failure = None
        for fd in reversed(descriptors):
            try:
                close(fd)
            except MaintenanceError as error:
                failure = error
        if failure:
            raise failure


def pending_value(plan, plan_sha):
    return {'version': 1, 'operation_id': plan['operation_id'], 'plan_sha256': plan_sha,
            'operation_directory': plan['operation_directory']}


def check_pending(plan, plan_sha, required=False):
    path = Path(plan['control_directory']) / PENDING
    if not path.exists() and not path.is_symlink():
        if required:
            fail('migration_pending_missing', 3)
        return False
    raw, metadata = read(path, 16384)
    data = json.loads(raw)
    if (metadata['mode'] != 0o600 or not isinstance(data, dict)
            or type(data.get('version')) is not int or data != pending_value(plan, plan_sha)):
        fail('migration_pending_conflict', 3)
    return True


def verify_database(plan, pre_activation):
    current = database_snapshot(Path(plan['database']['path']))
    before = plan['database']
    if current['schema_sha256'] != before['schema_sha256']:
        fail('job_database_schema_changed', 3)
    if pre_activation and (current['sha256'] != before['sha256'] or current['requests'] != before['requests']):
        fail('pre_activation_database_changed', 3)
    if any(current['rows'].get(key) != value for key, value in before['rows'].items()):
        fail('historical_job_facts_changed', 3)
    _ledger_continuity(_historical_ledger_entries(plan), current['ledger_entries'])
    return {'count': current['count'], 'states': current['states'], 'sha256': current['sha256']}


def verify_transaction(lease, bundle='candidate', pre_activation=True, pending=False):
    lease.validate()
    plan, plan_sha = lease.plan, lease.plan_sha
    check_pending(plan, plan_sha, required=pending)
    if not pending and check_pending(plan, plan_sha):
        fail('migration_pending', 3)
    check_anchors(plan)
    verify_spool_inventory(plan, pre_activation)
    for name, target in plan['targets'].items():
        expected = plan['definitions'][bundle]['sha256'] if name == 'origin' else target['after_sha256']
        if read(Path(target['path']))[1]['sha256'] != expected:
            fail('migration_target_mismatch:' + name, 3)
    data = json.loads(read(Path(plan['targets']['manifest']['path']))[0])
    validate_manifest_v2(data, lease.control_fd, lease.lock_fds[0], control_dir=Path(plan['control_directory']))
    database = verify_database(plan, pre_activation)
    return {'verified': True, 'phase': 'pre-activation' if pre_activation else 'runtime',
            'bundle': bundle, 'database': database}


def verify_runtime_inputs(plan, plan_sha, bundle):
    """Pure live checks shared by every READY/HEALTHY/attestation shortcut.

    Database verification is deliberately performed under the offline Lease;
    live checks bind immutable inputs without opening an active SQLite store.
    """
    if check_pending(plan, plan_sha):
        fail('migration_pending', 4)
    check_anchors(plan)
    for name, target in plan['targets'].items():
        expected = plan['definitions'][bundle]['sha256'] if name == 'origin' else target['after_sha256']
        if read(Path(target['path']))[1]['sha256'] != expected:
            fail('runtime_input_not_approved:' + name, 4)
    package = plan['packages'][bundle]
    if package_info(package['root']) != package:
        fail('runtime_package_not_approved', 4)


def backup(plan, plan_sha, operation):
    backup_dir = operation / 'backups'
    private_directory(backup_dir)
    inventory = []
    originals = [(name, target['path'], target['sha256']) for name, target in plan['targets'].items()]
    originals += [('database', plan['database']['path'], plan['database']['sha256'])]
    originals += [('database-sidecar-' + str(i), item['path'], item['sha256']) for i, item in enumerate(plan['database']['sidecars'])]
    for role, path, expected in originals:
        raw, info = read(Path(path))
        if sha(raw) != expected:
            fail('backup_source_changed', 3)
        dest = backup_dir / (role + '.before')
        if dest.exists():
            if read(dest)[0] != raw:
                fail('backup_conflict', 3)
            confirm_durable_file(dest, raw)
        else:
            write_new(dest, raw)
        if read(Path(path))[0] != raw or read(dest)[0] != raw:
            fail('backup_verification_failed', 3)
        inventory.append({'role': role, 'source': info, 'backup': str(dest), 'sha256': expected})
    for name, value in [('baseline.json', {'anchors': plan['anchors'], 'database': plan['database'], 'spool_inventory': plan['spool_inventory']}),
                        ('backup-manifest.json', {'plan_sha256': plan_sha, 'files': inventory, 'payloads_copied': False})]:
        raw = canonical(value)
        if (operation / name).exists():
            if read(operation / name)[0] != raw:
                fail('backup_manifest_conflict', 3)
            confirm_durable_file(operation / name, raw)
        else:
            write_new(operation / name, raw)


def check_backups(plan, plan_sha, operation):
    raw, _ = read(operation / 'backup-manifest.json', 4 * 1024 * 1024)
    data = json.loads(raw)
    if data['plan_sha256'] != plan_sha:
        fail('backup_plan_mismatch', 3)
    expected_roles = set(plan['targets']) | {'database'} | {'database-sidecar-' + str(i) for i, _ in enumerate(plan['database']['sidecars'])}
    if len(data['files']) != len(expected_roles) or {item['role'] for item in data['files']} != expected_roles:
        fail('backup_inventory_incomplete', 3)
    baseline = {'anchors': plan['anchors'], 'database': plan['database'], 'spool_inventory': plan['spool_inventory']}
    if read(operation / 'baseline.json')[0] != canonical(baseline):
        fail('baseline_not_verified', 3)
    sources = {name: (t['path'], t['sha256']) for name, t in plan['targets'].items()}
    sources['database'] = (plan['database']['path'], plan['database']['sha256'])
    sources.update({'database-sidecar-' + str(i): (item['path'], item['sha256'])
                    for i, item in enumerate(plan['database']['sidecars'])})
    for item in data['files']:
        path = Path(item['backup'])
        expected_path, expected_sha = sources[item['role']]
        if (path != operation / 'backups' / (item['role'] + '.before')
                or item['source']['path'] != expected_path or item['sha256'] != expected_sha
                or read(path)[1]['sha256'] != expected_sha):
            fail('backup_not_verified', 3)
        confirm_durable_file(path, read(path)[0])
    confirm_durable_file(operation / 'baseline.json', canonical(baseline))
    confirm_durable_file(operation / 'backup-manifest.json', raw)


def require_owned_maintenance(plan, plan_sha):
    """An externally disabled service is not proof of this plan's stop phase."""
    operation = Path(plan['operation_directory'])
    reject_aborted(plan, plan_sha)
    records = journal_read(operation / 'journal.jsonl')[0]
    if any(record.get('plan_sha256') != plan_sha for record in records):
        fail('maintenance_journal_plan_mismatch', 3)
    if any(record['event'] == 'SUPERSEDED_BEFORE_TARGETS' for record in records):
        fail('maintenance_operation_superseded', 3)
    intents = [record for record in records if record['event'] == 'MAINTENANCE_INTENT'
               and record.get('original_effective_enabled') is True]
    if not intents or plan.get('origin_enabled') is not True:
        fail('owned_maintenance_intent_required', 3)
    if not any(record['event'] == 'DISABLED' and record['sequence'] > intents[0]['sequence']
               for record in records):
        fail('owned_disable_phase_required', 3)
    frozen = operation / 'plan.json'
    if read(frozen, 4 * 1024 * 1024)[0] != canonical(plan):
        fail('owned_maintenance_plan_changed', 3)
    proof = plan.get('resumed_from')
    if proof is not None:
        previous = json.loads(read(Path(proof['plan_path']), 4 * 1024 * 1024)[0])
        if sha(canonical(previous)) != proof['plan_sha256']:
            fail('owned_stop_plan_not_frozen', 3)
        resume_compatible(plan, previous)
        old_records = journal_read(Path(previous['operation_directory']) / 'journal.jsonl')[0]
        if (any(record.get('plan_sha256') != proof['plan_sha256'] for record in old_records)
                or not any(record['event'] == 'SUPERSEDED_BEFORE_TARGETS'
                           and record.get('successor_operation') == plan['operation_id']
                           and record.get('successor_plan_sha256') == plan_sha for record in old_records)):
            fail('owned_stop_successor_not_committed', 3)
    return operation


@serialized
def migration_apply(plan, plan_sha, host=None, recover=False):
    host = host or LaunchCtl()
    operation = require_owned_maintenance(plan, plan_sha)
    if (operation / 'activation.json').exists():
        if recover and 'COMMITTED' in events(operation / 'journal.jsonl'):
            return {'state': 'committed_runtime_active', 'no_changes': True}
        fail('already_activated_use_runtime_tools', 3)
    host.quiescent(plan)
    ensure_operation(plan, plan_sha)
    confirm_durable_journal(operation / 'journal.jsonl', plan_sha)
    if plan.get('resumed_from') is not None:
        proof = plan['resumed_from']
        confirm_durable_file(Path(proof['plan_path']), read(Path(proof['plan_path']))[0])
        confirm_durable_journal(Path(proof['plan_path']).parent / 'journal.jsonl', proof['plan_sha256'])
    with Lease(plan, plan_sha, host) as lease:
        check_anchors(plan)
        verify_spool_inventory(plan, pre_activation=True)
        states = {}
        for name, target in plan['targets'].items():
            current = read(Path(target['path']))[1]['sha256']
            if current not in {target['sha256'], target['after_sha256']}:
                fail('unknown_migration_target_state', 3)
            states[name] = current
        log = operation / 'journal.jsonl'
        if 'COMMITTED' in events(log):
            result = verify_transaction(lease, pending=check_pending(plan, plan_sha))
            confirm_durable_journal(log, plan_sha)
            if check_pending(plan, plan_sha):
                os.unlink(PENDING, dir_fd=lease.control_fd)
                sync(lease.control_fd, 'pending_removed')
            return {**result, 'state': 'committed', 'idempotent': True}
        all_before = all(states[name] == target['sha256'] for name, target in plan['targets'].items())
        if not recover:
            if not all_before:
                fail('partial_migration_use_recover', 3)
            current_db = database_snapshot(Path(plan['database']['path']))
            if current_db['unsafe_jobs'] or current_db['requests'] or current_db['sha256'] != plan['database']['sha256']:
                fail('migration_database_precondition_failed', 3)
            backup(plan, plan_sha, operation)
        else:
            check_backups(plan, plan_sha, operation)
            if 'PREPARED' not in events(log):
                if not all_before:
                    fail('recovery_preparation_not_durable', 3)
                # A loss before the marker/parent/PREPARED barrier is safe to
                # resume only while every target is BEFORE and all independently
                # bound backup/baseline material is intact. Rebuild the marker
                # barrier below before recording PREPARED or replacing anything.
                check_pending(plan, plan_sha)
        marker = Path(plan['control_directory']) / PENDING
        if not check_pending(plan, plan_sha):
            write_new(marker, canonical(pending_value(plan, plan_sha)))
        confirm_durable_file(marker, canonical(pending_value(plan, plan_sha)))
        if 'PREPARED' not in events(log):
            journal_append(log, 'PREPARED', plan_sha)
        for name in ('origin', 'manifest', 'projects'):
            target = plan['targets'][name]
            atomic_target(target, {target['sha256'], target['after_sha256']}, decoded(target['after']))
            journal_append(log, 'AFTER_' + name.upper(), plan_sha)
        result = verify_transaction(lease, pending=True)
        journal_append(log, 'COMMITTED', plan_sha)
        os.unlink(PENDING, dir_fd=lease.control_fd)
        sync(lease.control_fd, 'pending_removed')
        return {**result, 'state': 'committed'}


def migration_verify(plan, plan_sha, host=None):
    operation = require_owned_maintenance(plan, plan_sha)
    if (operation / 'activation.json').exists():
        fail('runtime_verification_required')
    if 'COMMITTED' not in events(operation / 'journal.jsonl'):
        fail('migration_not_committed', 3)
    with Lease(plan, plan_sha, host or LaunchCtl()) as lease:
        return verify_transaction(lease)


@serialized
def switch_stop(plan, plan_sha, host=None):
    host = host or LaunchCtl()
    operation = ensure_operation(plan, plan_sha)
    log = operation / 'journal.jsonl'
    if 'MAINTENANCE_INTENT' not in events(log):
        if host.disabled():
            proof = plan.get('resumed_from')
            if not isinstance(proof, dict) or owned_pre_target_stop(proof['plan_path'], proof['plan_sha256'],
                                                                  plan['targets']['origin']['path'], host) != proof:
                fail('origin_was_disabled_outside_operation')
            previous, _ = load_plan(proof['plan_path'], proof['plan_sha256'])
            resume_compatible(plan, previous)
        elif plan.get('resumed_from') is not None:
            fail('owned_stop_is_no_longer_disabled')
        check_anchors(plan)
        for target in plan['targets'].values():
            if read(Path(target['path']))[1]['sha256'] != target['sha256']:
                fail('before_state_changed')
        journal_append(log, 'MAINTENANCE_INTENT', plan_sha, original_effective_enabled=plan['origin_enabled'],
                       resumed_from=plan.get('resumed_from'))
    if plan.get('resumed_from') is not None:
        proof = plan['resumed_from']
        previous, _ = load_plan(proof['plan_path'], proof['plan_sha256'])
        resume_compatible(plan, previous)
        old_log = Path(previous['operation_directory']) / 'journal.jsonl'
        old_records = journal_read(old_log)[0]
        superseded = [record for record in old_records if record['event'] == 'SUPERSEDED_BEFORE_TARGETS']
        if superseded:
            if any(record.get('successor_operation') != plan['operation_id']
                   or record.get('successor_plan_sha256') != plan_sha for record in superseded):
                fail('owned_stop_has_another_successor', 3)
        else:
            if owned_pre_target_stop(proof['plan_path'], proof['plan_sha256'],
                                     plan['targets']['origin']['path'], host) != proof:
                fail('owned_stop_continuity_changed', 3)
            journal_append(Path(previous['operation_directory']) / 'journal.jsonl', 'SUPERSEDED_BEFORE_TARGETS',
                           proof['plan_sha256'], successor_operation=plan['operation_id'], successor_plan_sha256=plan_sha)
        confirm_durable_file(Path(proof['plan_path']), canonical(previous))
        confirm_durable_journal(old_log, proof['plan_sha256'])
    records = journal_read(log)[0]
    if (plan.get('operation_kind') == 'runtime_code_update_no_identity_changes'
            and not any(row['event'] == 'DISABLED' for row in records)):
        _no_other_maintenance(plan)
        _no_code_switch_progress(plan, records)
        _before_code_switch_targets(plan)
        check_anchors(plan)
        previous, _, active = _code_switch_previous(plan)
        if host.loaded():
            if (not host.matches(previous, active)
                    or host.identity(previous, active) != plan['previous_process_identity']):
                fail('owned_stop_previous_process_changed', 3)
        else:
            host.quiescent(plan)
        point('owned_code_stop_checked')
    confirm_durable_journal(log, plan_sha)
    host.stop(plan)
    journal_append(log, 'DISABLED', plan_sha)
    return {'state': 'disabled_quiescent', 'origin_disabled': True}


def activation(plan, plan_sha, operation, bundle):
    path = operation / 'activation.json'
    if path.exists():
        data = json.loads(read(path, 16384)[0])
        if data.get('state') != 'ACTIVATING' or data.get('plan_sha256') != plan_sha:
            fail('activation_conflict', 3)
        confirm_durable_file(path, canonical(data))
    else:
        write_new(path, canonical({'state': 'ACTIVATING', 'plan_sha256': plan_sha,
                                   'initial_bundle': bundle, 'time': now()}))


def health_challenge(plan, plan_sha, log, switch_id, bundle, host):
    verify_runtime_inputs(plan, plan_sha, bundle)
    identity = host.identity(plan, bundle)
    existing = [r for r in journal_read(log)[0] if r['event'] == 'BOOTSTRAPPED']
    if existing and existing[-1].get('process_identity') == identity:
        confirm_durable_journal(log, plan_sha)
        record = existing[-1]
    else:
        record = journal_append(log, 'BOOTSTRAPPED', plan_sha, process_identity=identity,
                                health_nonce=uuid.uuid4().hex, not_before_unix=time.time())
    return {'state': 'awaiting_authenticated_health', 'bundle': bundle, 'switch_id': switch_id,
            'process_identity': identity, 'health_nonce': record['health_nonce'],
            'not_before_unix': record['not_before_unix'], 'plan_sha256': plan_sha,
            'operation_id': plan['operation_id'], 'bundle_fingerprint': plan['packages'][bundle]['fingerprint']}


def confirmed_challenge(plan, plan_sha, log, switch_id, bundle, host):
    try:
        return health_challenge(plan, plan_sha, log, switch_id, bundle, host)
    except BaseException:
        host.stop(plan)
        raise


@serialized
def runtime_switch(plan, plan_sha, bundle, switch_id, host=None, recover=False):
    host = host or LaunchCtl()
    if bundle not in ('candidate', 'rollback') or not _ID.fullmatch(switch_id):
        fail('invalid_runtime_switch')
    # Ownership/lock entry failures do not confer authority to stop a different
    # operation. Once proved, every subsequent validation/sync/start failure
    # shares the same fail-stop boundary, including fast recovery paths.
    require_owned_maintenance(plan, plan_sha)
    try:
        return _runtime_switch_owned(plan, plan_sha, bundle, switch_id, host, recover)
    except BaseException:
        host.stop(plan)
        raise


def _runtime_switch_owned(plan, plan_sha, bundle, switch_id, host, recover):
    host = host or LaunchCtl()
    if bundle not in ('candidate', 'rollback') or not _ID.fullmatch(switch_id):
        fail('invalid_runtime_switch')
    operation = require_owned_maintenance(plan, plan_sha)
    if 'COMMITTED' not in events(operation / 'journal.jsonl') or check_pending(plan, plan_sha):
        fail('migration_not_ready_for_activation', 3)
    confirm_durable_journal(operation / 'journal.jsonl', plan_sha)
    first = not (operation / 'activation.json').exists()
    if first:
        migration_verify(plan, plan_sha, host)
    switches = operation / 'runtime-switches'
    private_directory(switches)
    log = switches / (switch_id + '.jsonl')
    records = journal_read(log)[0]
    if records and (records[0].get('to_bundle') != bundle or records[0]['plan_sha256'] != plan_sha):
        fail('runtime_switch_plan_conflict', 3)
    if 'HEALTHY' in [r['event'] for r in records]:
        confirm_durable_journal(log, plan_sha)
        try:
            verify_runtime_inputs(plan, plan_sha, bundle)
        except BaseException:
            host.stop(plan)
            raise
        if host.matches(plan, bundle):
            healthy = [r for r in records if r['event'] == 'HEALTHY'][-1]
            try:
                current_identity = host.identity(plan, bundle)
            except BaseException:
                host.stop(plan)
                raise
            if healthy.get('process_identity') == current_identity:
                return {'state': 'healthy_recorded', 'bundle': bundle, 'idempotent': True}
            return confirmed_challenge(plan, plan_sha, log, switch_id, bundle, host)
        host.stop(plan)
        fail('recorded_healthy_state_changed', 4)
    if not records:
        current = read(Path(plan['targets']['origin']['path']))[1]['sha256']
        matches = [name for name, definition in plan['definitions'].items() if current == definition['sha256']]
        if len(matches) != 1:
            fail('runtime_origin_not_approved', 3)
        journal_append(log, 'SWITCH_PREPARED', plan_sha, from_bundle=matches[0], to_bundle=bundle)
    elif not recover:
        fail('runtime_switch_incomplete_use_recover', 3)
    confirm_durable_journal(log, plan_sha)
    activation(plan, plan_sha, operation, bundle)
    recorded = events(log)
    if 'READY_TO_ENABLE' in recorded and host.loaded():
        if not host.matches(plan, bundle):
            host.stop(plan)
            fail('loaded_origin_not_selected_bundle', 4)
        return confirmed_challenge(plan, plan_sha, log, switch_id, bundle, host)
    host.stop(plan)
    journal_append(log, 'QUIESCENT', plan_sha)
    with Lease(plan, plan_sha, host) as lease:
        target = plan['targets']['origin']
        allowed = {definition['sha256'] for definition in plan['definitions'].values()}
        atomic_target(target, allowed, decoded(plan['definitions'][bundle]['raw']))
        journal_append(log, 'PLIST_COMMITTED', plan_sha)
        verify_transaction(lease, bundle=bundle, pre_activation=False)
        journal_append(log, 'READY_TO_ENABLE', plan_sha)
    verify_runtime_inputs(plan, plan_sha, bundle)
    if not host.disabled() or read(Path(target['path']))[1]['sha256'] != plan['definitions'][bundle]['sha256']:
        fail('runtime_enable_precondition_changed', 4)
    try:
        host.start(plan)
    except BaseException:
        host.stop(plan)
        raise
    return confirmed_challenge(plan, plan_sha, log, switch_id, bundle, host)


@serialized
def attest_health(plan, plan_sha, switch_id, receipt_path, host=None):
    host = host or LaunchCtl()
    if not _ID.fullmatch(switch_id):
        fail('invalid_runtime_switch')
    require_owned_maintenance(plan, plan_sha)
    try:
        return _attest_health_owned(plan, plan_sha, switch_id, receipt_path, host)
    except BaseException:
        host.stop(plan)
        raise


def _attest_health_owned(plan, plan_sha, switch_id, receipt_path, host):
    host = host or LaunchCtl()
    if not _ID.fullmatch(switch_id):
        fail('invalid_runtime_switch')
    operation = Path(plan['operation_directory'])
    log = operation / 'runtime-switches' / (switch_id + '.jsonl')
    records = journal_read(log)[0]
    if not records or 'READY_TO_ENABLE' not in [r['event'] for r in records]:
        fail('runtime_switch_not_ready')
    bundle = records[0]['to_bundle']
    try:
        verify_runtime_inputs(plan, plan_sha, bundle)
        raw, _ = read(Path(receipt_path), 1024 * 1024)
        receipt = json.loads(raw)
        starts = [r for r in records if r['event'] == 'BOOTSTRAPPED']
        if not starts:
            fail('origin_bootstrap_receipt_missing', 4)
        challenge = starts[-1]
        received = receipt.get('received_at_unix')
        result = receipt.get('result')
        expected_projects = {p['id'] for p in json.loads(decoded(plan['targets']['projects']['after']))['projects']}
        if (receipt.get('authenticated') is not True or receipt.get('tool') != 'list_projects'
                or receipt.get('ok') is not True or receipt.get('bundle_fingerprint') != plan['packages'][bundle]['fingerprint']
                or receipt.get('operation_id') != plan['operation_id'] or receipt.get('plan_sha256') != plan_sha
                or receipt.get('switch_id') != switch_id or receipt.get('health_nonce') != challenge['health_nonce']
                or receipt.get('process_identity') != challenge['process_identity']
                or host.identity(plan, bundle) != challenge['process_identity']
                or type(received) not in (int, float) or not challenge['not_before_unix'] <= received <= time.time() + 5
                or time.time() - received > 300 or not isinstance(result, dict)
                or not isinstance(result.get('projects'), list)
                or {p.get('id') for p in result['projects']} != expected_projects):
            fail('authenticated_health_not_proven', 4)
        audit_path = Path(plan['packages'][bundle]['root']) / 'work/remote-audit.jsonl'
        audit_raw, _ = read(audit_path, 2 * 1024 * 1024)
        matching = []
        for line in audit_raw.splitlines():
            item = json.loads(line)
            if item.get('tool') == 'list_projects' and item.get('ok') is True and isinstance(item.get('time'), str):
                observed = datetime.fromisoformat(item['time']).timestamp()
                if challenge['not_before_unix'] <= observed <= received + 5:
                    matching.append(sha(line))
        if receipt.get('audit_record_sha256') not in matching:
            fail('authenticated_origin_audit_not_proven', 4)
    except BaseException:
        # Failed or malformed evidence is never a reason to leave an unaccepted
        # origin enabled. stop() also confirms receivers/handles have exited.
        host.stop(plan)
        raise
    journal_append(log, 'HEALTHY', plan_sha, receipt_sha256=sha(raw),
                   process_identity=challenge['process_identity'])
    return {'state': 'healthy', 'bundle': bundle, 'receipt_sha256': sha(raw)}


def emit(value):
    print(json.dumps(value, ensure_ascii=True, sort_keys=True))


def migrate_main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    inspect = subs.add_parser('inspect')
    inspect.add_argument('--origin-plist', required=True, type=Path)
    inspect.add_argument('--output', required=True, type=Path)
    inspect.add_argument('--resume-plan', type=Path)
    inspect.add_argument('--resume-plan-sha256')
    plan_parser = subs.add_parser('plan')
    for option in ('snapshot', 'candidate-root', 'rollback-root', 'maintenance-manifest', 'output'):
        plan_parser.add_argument('--' + option, required=True, type=Path)
    plan_parser.add_argument('--operation-id', required=True)
    for name in ('apply', 'verify', 'recover'):
        sub = subs.add_parser(name)
        sub.add_argument('--plan', required=True, type=Path)
        sub.add_argument('--expected-plan-sha256', required=True)
        if name == 'apply':
            sub.add_argument('--adopt-current-anchors', action='store_true', required=True)
        elif name == 'verify':
            sub.add_argument('--phase', choices=['pre-activation'], required=True)
        else:
            sub.add_argument('--mode', choices=['inspect', 'complete'], required=True)
            sub.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'inspect':
            if (args.resume_plan is None) != (args.resume_plan_sha256 is None):
                fail('both_resume_plan_and_sha256_required')
            data = inspect_origin(args.origin_plist, resume_plan=args.resume_plan, resume_sha=args.resume_plan_sha256)
            write_new(args.output, canonical(data))
            emit({'ok': True, 'output': str(args.output), 'sha256': sha(canonical(data)),
                  'project_pins': len(data['pins']), 'jobs': data['database']['count']})
            return
        if args.action == 'plan':
            snapshot = json.loads(read(args.snapshot, 4 * 1024 * 1024)[0])
            data = make_plan(snapshot, args.candidate_root, args.rollback_root, args.maintenance_manifest, args.operation_id)
            write_new(args.output, canonical(data))
            emit({'ok': True, 'output': str(args.output), 'plan_sha256': sha(canonical(data)),
                  'pins': data['pins'], 'operation_directory': data['operation_directory']})
            return
        plan, digest = load_plan(args.plan, args.expected_plan_sha256)
        if args.action == 'apply':
            emit(migration_apply(plan, digest))
        elif args.action == 'verify':
            emit(migration_verify(plan, digest))
        elif args.mode == 'inspect':
            emit({'state': 'inspection_only', 'events': events(Path(plan['operation_directory']) / 'journal.jsonl'),
                  'pending': check_pending(plan, digest)})
        elif args.apply:
            emit(migration_apply(plan, digest, recover=True))
        else:
            fail('explicit_apply_required')
    except MaintenanceError as error:
        emit({'ok': False, 'error_code': error.code})
        raise SystemExit(error.exit_code)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        emit({'ok': False, 'error_code': 'maintenance_input_or_io_failure'})
        raise SystemExit(3)


def switch_main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'stop', 'start', 'fallback', 'runtime-verify', 'recover', 'attest-health',
                                         'abort-before-targets'])
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--bundle', choices=['candidate', 'rollback'])
    parser.add_argument('--switch-id', default='initial-candidate')
    parser.add_argument('--mode', choices=['inspect', 'complete'], default='inspect')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--restoration-bindings-output', type=Path)
    args = parser.parse_args(argv)
    try:
        if not _ID.fullmatch(args.switch_id):
            fail('invalid_runtime_switch')
        plan, digest = load_plan(args.plan, args.expected_plan_sha256)
        if args.action == 'check':
            check_anchors(plan)
            host = LaunchCtl()
            if host.disabled():
                proof = plan.get('resumed_from')
                if not isinstance(proof, dict) or owned_pre_target_stop(proof['plan_path'], proof['plan_sha256'],
                                                                      plan['targets']['origin']['path'], host) != proof:
                    fail('origin_was_disabled_outside_operation')
            elif plan.get('resumed_from') is not None:
                fail('owned_stop_is_no_longer_disabled')
            if any(read(Path(t['path']))[1]['sha256'] != t['sha256'] for t in plan['targets'].values()):
                fail('initial_state_not_approved')
            emit({'ok': True, 'state': 'prepared_not_deployed'})
        elif args.action == 'runtime-verify':
            if args.bundle is None:
                fail('explicit_bundle_required')
            with Lease(plan, digest, LaunchCtl()) as lease:
                emit(verify_transaction(lease, bundle=args.bundle, pre_activation=False))
        elif args.action == 'recover' and args.mode == 'inspect':
            emit({'state': 'inspection_only', 'events': events(Path(plan['operation_directory']) / 'runtime-switches' / (args.switch_id + '.jsonl'))})
        elif not args.apply:
            fail('explicit_apply_required')
        elif args.action == 'abort-before-targets':
            if args.restoration_bindings_output is None:
                fail('restoration_bindings_output_required')
            emit(abort_before_targets(plan, digest, args.restoration_bindings_output))
        elif args.action == 'stop':
            emit(switch_stop(plan, digest))
        elif args.action == 'attest-health':
            if args.receipt is None:
                fail('health_receipt_required')
            emit(attest_health(plan, digest, args.switch_id, args.receipt))
        else:
            if args.action == 'recover':
                records = journal_read(Path(plan['operation_directory']) / 'runtime-switches' / (args.switch_id + '.jsonl'))[0]
                if (not records or any(record['plan_sha256'] != digest for record in records)
                        or records[0].get('to_bundle') not in ('candidate', 'rollback')):
                    fail('runtime_switch_not_found_or_invalid', 3)
                bundle = records[0]['to_bundle']
                if args.bundle is not None and args.bundle != bundle:
                    fail('runtime_switch_plan_conflict', 3)
            else:
                bundle = 'rollback' if args.action == 'fallback' else args.bundle or 'candidate'
            emit(runtime_switch(plan, digest, bundle, args.switch_id, recover=args.action == 'recover'))
    except MaintenanceError as error:
        emit({'ok': False, 'error_code': error.code})
        raise SystemExit(error.exit_code)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        emit({'ok': False, 'error_code': 'maintenance_input_or_io_failure'})
        raise SystemExit(3)


def prepare_code_switch_main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only v2 code switch plan preparation.')
    for name in ('previous-plan', 'candidate-root', 'rollback-root', 'maintenance-manifest',
                 'chunked-config', 'output', 'bindings-output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-previous-plan-sha256', 'approved-contract-sha256', 'operation-id'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--active-bundle', choices=['candidate', 'rollback'], required=True)
    args = parser.parse_args(argv)
    try:
        emit(prepare_code_switch(args.previous_plan, args.expected_previous_plan_sha256,
             args.active_bundle, args.candidate_root, args.rollback_root, args.maintenance_manifest,
             args.chunked_config, args.approved_contract_sha256, args.operation_id,
             args.output, args.bindings_output))
    except MaintenanceError as error:
        emit({'ok': False, 'error_code': error.code})
        raise SystemExit(error.exit_code)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        emit({'ok': False, 'error_code': 'maintenance_input_or_io_failure'})
        raise SystemExit(3)
