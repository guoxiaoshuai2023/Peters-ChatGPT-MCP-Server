"""Persistent private-path protection independent of file-save feature switches.

Every generic filesystem operation must hold read_guard through result building.
Each entry/target must also pass guard.check_path. All participating processes
must use the SAME preconfigured control directory. The exclusive activation lock
drains old operations; new instances reload the current manifest under that lock.
This is cooperating-process protection, not an OS sandbox against the same uid.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
import unicodedata

from .catalog import AccessError
from .fs_identity import persistent_identity_fd, validate_identity

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_LOCK = 'private-roots.lock'
_MANIFEST = 'private-roots.json'
_PENDING = 'identity-migration.pending.json'
_MAX_BYTES = 256 * 1024
_MAX_ROOTS = 512


def _error(message='Private protection is unavailable; generic filesystem access is closed.',
           code='private_protection_unavailable'):
    return AccessError(message, code=code)


def _key(path):
    return tuple(unicodedata.normalize('NFC', part.casefold()) for part in Path(path).parts)


def _overlap(first, second):
    return first[:len(second)] == second or second[:len(first)] == first


def _identity(info):
    return [info.st_dev, info.st_ino]


def _stable_identity(fd):
    """Keep uncertain native-helper closes in the protection owner's budget."""
    try:
        return persistent_identity_fd(fd)
    except AccessError as error:
        if error.code == 'identity_cleanup_pending':
            raise _error('A private protection descriptor close was not confirmed.',
                         'protection_cleanup_pending') from None
        raise


def _close(fd):
    """Never retry an integer FD whose close outcome is uncertain."""
    try:
        os.close(fd)
    except OSError:
        raise _error('A private protection descriptor close was not confirmed.',
                     'protection_cleanup_pending') from None


def _canonical(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise _error('Private infrastructure paths must be absolute and canonical.')
    if path in (Path('/'), Path.home().resolve()):
        raise _error('A filesystem root or home directory cannot be private infrastructure.')
    return path


def _directory(path):
    """Open every absolute component without following links."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise _error()
    fd = os.open('/', _DIR)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIR, dir_fd=fd)
            previous, fd = fd, child
            _close(previous)
        return fd
    except BaseException:
        _close(fd)
        raise


def _private(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    return (kind(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (directory or info.st_nlink == 1))


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate protection field')
        value[key] = item
    return value


def validate_manifest_v2(data, control_fd, lock_fd, *, control_dir=None):
    """Pure schema/anchor validation using caller-held control and lock FDs.

    This function never creates, opens for locking, acquires or releases a lock,
    reads a pending marker, or changes a generation. Maintenance must validate its
    own operation-bound pending marker while retaining its exclusive lock Lease.
    Ordinary service loading always checks the pending marker before calling here.
    """
    try:
        if type(data) is dict and type(data.get('version')) is int and data['version'] == 1:
            raise _error('Private identity requires an explicit operator migration.',
                         'private_identity_migration_required')
        if (type(data) is not dict
                or set(data) != {'version', 'generation', 'control_identity', 'lock_identity', 'roots'}
                or type(data['version']) is not int or data['version'] != 2
                or type(data['generation']) is not int or data['generation'] < 1
                or type(data['roots']) is not list or len(data['roots']) > _MAX_ROOTS):
            raise _error()
        if control_dir is None:
            from .fs_identity import _fd_path
            control_dir = _fd_path(control_fd)
        control_dir = _canonical(control_dir)
        control_info, lock_info = os.fstat(control_fd), os.fstat(lock_fd)
        if not _private(control_info, True) or not _private(lock_info):
            raise _error()
        current = _directory(control_dir)
        try:
            if _identity(os.fstat(current)) != _identity(control_info):
                raise _error('Private control identity changed.', 'private_identity_mismatch')
        finally:
            _close(current)
        if (_identity(os.stat(_LOCK, dir_fd=control_fd, follow_symlinks=False)) != _identity(lock_info)
                or validate_identity(data['control_identity']) != _stable_identity(control_fd)
                or validate_identity(data['lock_identity']) != _stable_identity(lock_fd)):
            raise _error('Private anchor identity changed.', 'private_identity_mismatch')
        seen = []
        for row in data['roots']:
            if (type(row) is not dict or set(row) != {'path', 'status', 'parent_identity', 'identity'}
                    or type(row['path']) is not str or row['status'] not in {'pending', 'active'}):
                raise _error()
            path = _canonical(row['path'])
            key = _key(path)
            if _overlap(key, _key(control_dir)) or any(_overlap(key, old) for old in seen):
                raise _error()
            seen.append(key)
            validate_identity(row['parent_identity'])
            if row['identity'] is None:
                if row['status'] != 'pending':
                    raise _error()
            else:
                validate_identity(row['identity'])
            parent = _directory(path.parent)
            try:
                if _stable_identity(parent) != row['parent_identity']:
                    raise _error('Private parent identity changed.', 'private_identity_mismatch')
            finally:
                _close(parent)
            if row['identity'] is not None:
                root = _directory(path)
                try:
                    if not _private(os.fstat(root), True) or _stable_identity(root) != row['identity']:
                        raise _error('Private root identity changed.', 'private_identity_mismatch')
                finally:
                    _close(root)
        return data
    except AccessError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise _error() from None


class ProtectionGuard:
    def __init__(self, registry, manifest, health_check=None):
        self._registry = registry
        self.generation = manifest['generation']
        self._paths = (registry.control_dir, *(Path(r['path']) for r in manifest['roots']))
        self._manifest = manifest
        self._health_check = health_check

    def revalidate(self):
        """Re-read anchors/manifest while the same thread still owns this guard."""
        self._registry._require_guard(self)
        if self._health_check is None:
            raise _error('A live protection health check is required.')
        try:
            return self._health_check()
        except AccessError:
            raise
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            raise _error() from None

    def check_path(self, path):
        self._registry._require_guard(self)
        try:
            path = Path(path)
            if not path.is_absolute():
                raise _error('Filesystem protection requires an absolute target.')
            keys = (_key(Path(os.path.abspath(path))), _key(path.resolve()))
            for root in self._paths:
                protected = _key(root)
                if any(key[:len(protected)] == protected for key in keys):
                    raise _error('Service-owned private state is not a generic file target.', 'private_path')
        except AccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise _error() from None

    def assert_isolated_tree(self, path):
        """Allow a separate reader only when its entire source tree is disjoint."""
        self._registry._require_guard(self)
        try:
            path = Path(path)
            if not path.is_absolute():
                raise _error()
            keys = (_key(Path(os.path.abspath(path))), _key(path.resolve()))
            if any(_overlap(key, _key(root)) for key in keys for root in self._paths):
                raise _error('The separate reader overlaps protected service state.', 'private_path')
        except AccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise _error() from None


class PrivateRootRegistry:
    """Explicitly initialized control anchor plus append-only protected-root set.

Construction never creates files/directories. initialize is an operator-only
bootstrap for an existing empty 0700 control directory; never expose it as an MCP
tool. read_roots arguments must contain ALL current authorized project/worktree
roots, supplied by the service, never by the model. Removed allowed_roots remain
protected in the manifest; no remove/unprotect API is provided.
"""
    def __init__(self, control_dir, *, allowed_roots, lock_timeout=5.0):
        try:
            self.control_dir = _canonical(control_dir)
            self.allowed_roots = frozenset(_canonical(p) for p in allowed_roots)
            if len(self.allowed_roots) > _MAX_ROOTS or any(
                    _overlap(_key(p), _key(self.control_dir)) for p in self.allowed_roots):
                raise _error('Private roots must be separate from the control directory.')
            keys = [_key(p) for p in self.allowed_roots]
            if any(_overlap(a, b) for i, a in enumerate(keys) for b in keys[i + 1:]):
                raise _error('Configured private roots overlap or alias each other.')
            fd = _directory(self.control_dir)
            try:
                info = os.fstat(fd)
                if not _private(info, True):
                    raise _error('Control directory must already exist with owner-only permissions.')
                self._control_identity = _identity(info)
            finally:
                _close(fd)
        except (OSError, RuntimeError, ValueError) as exc:
            if isinstance(exc, AccessError):
                raise
            raise _error() from None
        if not isinstance(lock_timeout, (int, float)) or not 0 < lock_timeout <= 60:
            raise ValueError('lock_timeout must be within (0, 60] seconds')
        self.lock_timeout = lock_timeout
        self._local = threading.local()
        self._epoch_lock = threading.Lock()
        self._highest_generation = 0

    def _control(self):
        fd = _directory(self.control_dir)
        try:
            if (_identity(os.fstat(fd)) != self._control_identity
                    or not _private(os.fstat(fd), True)):
                raise _error()
            return fd
        except BaseException:
            _close(fd)
            raise

    @contextmanager
    def _locked(self, *, exclusive=False, initialize=False):
        if getattr(self._local, 'guard', None) is not None:
            raise _error('Infrastructure updates cannot run inside a generic operation.', 'private_protection_busy')
        control = anchor = None
        entered_body = False
        try:
            control = self._control()
            created = False
            if initialize:
                try:
                    os.stat(_LOCK, dir_fd=control, follow_symlinks=False)
                except FileNotFoundError:
                    if os.listdir(control):
                        raise _error('Existing control state cannot have its lock recreated.')
                    try:
                        anchor = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=control)
                        created = True
                    except FileExistsError:
                        pass
            if anchor is None:
                anchor = os.open(_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=control)
            info = os.fstat(anchor)
            if not _private(info):
                raise _error()
            deadline = time.monotonic() + self.lock_timeout
            while True:
                try:
                    fcntl.flock(anchor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise _error('Private protection barrier is busy; retry later.', 'private_protection_busy')
                    time.sleep(.01)
            if _identity(os.stat(_LOCK, dir_fd=control, follow_symlinks=False)) != _identity(info):
                raise _error()
            with_fd = self._control()
            _close(with_fd)
            self._local.lock_fd = anchor
            entered_body = True
            yield control, info, created
        except OSError:
            if entered_body and not exclusive:
                raise
            raise _error() from None
        finally:
            self._local.lock_fd = None
            failure = None
            for held in (anchor, control):
                if held is not None:
                    try:
                        _close(held)
                    except AccessError as error:
                        failure = error
            if failure is not None:
                raise failure

    def _load(self, fd, lock_info):
        try:
            return self._load_raw(fd, lock_info)
        except AccessError:
            raise
        except OSError:
            raise _error() from None

    def _load_raw(self, fd, lock_info):
        current = self._control()
        _close(current)
        anchor = os.stat(_LOCK, dir_fd=fd, follow_symlinks=False)
        if _identity(anchor) != _identity(lock_info) or not _private(anchor):
            raise _error()
        try:
            os.stat(_PENDING, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _error('Private identity migration is pending.', 'private_identity_migration_pending')
        reader = os.open(_MANIFEST, _READ, dir_fd=fd)
        try:
            before = os.fstat(reader)
            if not _private(before) or before.st_size > _MAX_BYTES:
                raise _error()
            raw = bytearray()
            while len(raw) <= _MAX_BYTES:
                chunk = os.read(reader, min(65536, _MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(reader)
            current_manifest = os.stat(_MANIFEST, dir_fd=fd, follow_symlinks=False)
            def version(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                        info.st_nlink, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
            if (len(raw) > _MAX_BYTES or len(raw) != before.st_size
                    or version(before) != version(after) or version(after) != version(current_manifest)):
                raise _error()
        finally:
            _close(reader)
        try:
            data = json.loads(raw, object_pairs_hook=_unique_object)
            validate_manifest_v2(data, fd, self._local.lock_fd, control_dir=self.control_dir)
        except AccessError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            raise _error() from None
        with self._epoch_lock:
            if data['generation'] < self._highest_generation:
                raise _error('Protection generation moved backwards; access is closed.')
            self._highest_generation = data['generation']
        return data, hashlib.sha256(raw).digest()

    def _store(self, fd, data):
        raw = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > _MAX_BYTES:
            raise _error('Private root registry capacity exceeded.', 'private_registry_capacity')
        name = '.private-roots-' + secrets.token_hex(16)
        writer = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(writer, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, _MANIFEST, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            with self._epoch_lock:
                self._highest_generation = max(self._highest_generation, data['generation'])
        finally:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass

    def initialize(self):
        """Explicit bootstrap; missing/corrupt existing registries are never reset."""
        with self._locked(exclusive=True, initialize=True) as (fd, info, created):
            if not created:
                return self._load(fd, info)[0]['generation']
            if os.listdir(fd) != [_LOCK]:
                raise _error('New control directory is not empty; initialization refused.')
            os.fsync(fd)
            data = {'version': 2, 'generation': 1, 'control_identity': _stable_identity(fd),
                    'lock_identity': _stable_identity(self._local.lock_fd), 'roots': []}
            self._store(fd, data)
            return 1

    def _require_guard(self, guard):
        if getattr(self._local, 'guard', None) is not guard:
            raise _error('A protection guard must remain held for the complete operation.')

    @contextmanager
    def read_guard(self):
        current = getattr(self._local, 'guard', None)
        if current is not None:
            yield current
            return
        with self._locked() as (fd, info, _):
            data, digest = self._load(fd, info)
            def health_check():
                current, checked = self._load(fd, info)
                if checked != digest:
                    raise _error('Protection changed outside its coordinator; access is closed.')
                return {'generation': current['generation'], 'digest': checked.hex()}

            guard = ProtectionGuard(self, data, health_check)
            self._local.guard = guard
            try:
                yield guard
                if self._load(fd, info)[1] != digest:
                    raise _error('Protection changed outside its coordinator; response refused.')
            finally:
                self._local.guard = None

    def check_path(self, path):
        """Convenience for nested Catalog checks; outer operation guard is required."""
        guard = getattr(self._local, 'guard', None)
        if guard is None:
            raise _error('Generic filesystem operations require a protection guard.')
        guard.check_path(path)

    def _target(self, path, read_roots):
        path = _canonical(path)
        if path not in self.allowed_roots:
            raise _error('Private root is not an operator-configured infrastructure target.', 'private_root_not_allowed')
        for root in read_roots:
            root = Path(root)
            if not root.is_absolute():
                raise _error('Authorized read roots must be absolute.')
            if any(_overlap(_key(path), _key(alias)) for alias in (root, root.resolve())):
                raise _error('Private root overlaps an authorized read root.', 'private_root_overlap')
        return path

    def register_pending(self, path, *, read_roots):
        with self._locked(exclusive=True) as (fd, info, _):
            data, _ = self._load(fd, info)
            path = self._target(path, read_roots)
            existing = next((r for r in data['roots'] if r['path'] == str(path)), None)
            if existing:
                return dict(existing, generation=data['generation'])
            if len(data['roots']) >= _MAX_ROOTS or any(_overlap(_key(path), _key(r['path'])) for r in data['roots']):
                raise _error('Private root overlaps an existing reservation or capacity is exhausted.')
            parent = _directory(path.parent)
            try:
                row = {'path': str(path), 'status': 'pending', 'identity': None,
                       'parent_identity': _stable_identity(parent)}
            finally:
                _close(parent)
            data['roots'].append(row)
            data['generation'] += 1
            self._store(fd, data)
            return dict(row, generation=data['generation'])

    def activate(self, path, *, read_roots):
        """Drain old operations, bind an empty private root, then mark it active."""
        with self._locked(exclusive=True) as (fd, info, _):
            data, _ = self._load(fd, info)
            path = self._target(path, read_roots)
            row = next((r for r in data['roots'] if r['path'] == str(path)), None)
            if row is None:
                raise _error('Pending protection must be registered before activation.')
            if row['status'] == 'active':
                return dict(row, generation=data['generation'])
            parent = _directory(path.parent)
            try:
                if _stable_identity(parent) != row['parent_identity']:
                    raise _error()
                try:
                    os.mkdir(path.name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
                root = os.open(path.name, _DIR, dir_fd=parent)
                try:
                    root_info = os.fstat(root)
                    if not _private(root_info, True) or os.listdir(root):
                        raise _error('Private root must be an empty owner-only directory before activation.')
                    if row['identity'] is not None and _stable_identity(root) != row['identity']:
                        raise _error()
                    row['identity'] = _stable_identity(root)
                    data['generation'] += 1
                    self._store(fd, data)  # Pending identity persists before active.
                    os.fsync(root)
                    current = _directory(path)
                    try:
                        if (_identity(os.fstat(current)) != _identity(root_info)
                                or _stable_identity(current) != row['identity']):
                            raise _error()
                    finally:
                        _close(current)
                    row['status'] = 'active'
                    data['generation'] += 1
                    self._store(fd, data)
                finally:
                    _close(root)
            finally:
                _close(parent)
            return dict(row, generation=data['generation'])

    def spool_for(self, device, roots=None):
        """Pure lookup of a validated active same-device root; never mkdir/register.

        roots optionally restricts the infrastructure selection further. The caller
        must still verify actual volume/no-replace support and final target identity.
        """
        if type(device) is not int or device < 0:
            raise ValueError('device must be an st_dev integer')
        selected = None if roots is None else frozenset(Path(p) for p in roots)
        with self.read_guard() as guard:
            for row in guard._manifest['roots']:
                path = Path(row['path'])
                if (row['status'] != 'active' or path not in self.allowed_roots
                        or selected is not None and path not in selected):
                    continue
                parent = _directory(path.parent)
                try:
                    root = os.open(path.name, _DIR, dir_fd=parent)
                    try:
                        info, parent_info = os.fstat(root), os.fstat(parent)
                        if (not _private(info, True) or _stable_identity(root) != row['identity']
                                or _stable_identity(parent) != row['parent_identity']):
                            raise _error('Private root identity changed.', 'private_identity_mismatch')
                        if info.st_dev == device:
                            return dict(row, identity=_identity(info), parent_identity=_identity(parent_info),
                                        generation=guard.generation)
                    finally:
                        _close(root)
                finally:
                    _close(parent)
        return None
