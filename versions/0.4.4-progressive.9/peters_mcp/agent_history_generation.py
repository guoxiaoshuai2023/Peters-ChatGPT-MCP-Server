"""Private immutable policy generations and the shared delivery/activation lock."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .catalog import AccessError

MAX_GENERATION_BYTES = 512 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW


def _invalid():
    return AccessError("The active unified history generation is unavailable or invalid.",
                       code="agent_policy_invalid")


def _unique(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("Duplicate configuration field.")
        value[key] = item
    return value


def canonical_bytes(document):
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path == Path("/"):
        raise _invalid()
    descriptor = os.open("/", _DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _invalid()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_at(directory, name, maximum):
    descriptor = os.open(name, _READ, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > maximum):
            raise _invalid()
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if len(raw) != before.st_size or _stamp(before) != _stamp(after) or _stamp(after) != _stamp(named):
            raise _invalid()
        return raw
    finally:
        os.close(descriptor)


def _write_new(directory, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=directory)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


class GenerationStore:
    """Opening a store never creates or repairs operator-owned state."""

    def __init__(self, path):
        self.path = Path(path)
        try:
            descriptor = _directory(self.path)
            try:
                info = os.fstat(descriptor)
                self.identity = (info.st_dev, info.st_ino)
            finally:
                os.close(descriptor)
        except (OSError, ValueError):
            raise _invalid() from None

    def _load(self, directory):
        pointer = json.loads(_read_at(directory, "active.json", 1024), object_pairs_hook=_unique)
        if (not isinstance(pointer, dict) or set(pointer) != {"version", "sha256", "activation_id"}
                or type(pointer["version"]) is not int or pointer["version"] != 2
                or not isinstance(pointer["sha256"], str) or not _DIGEST.fullmatch(pointer["sha256"])
                or not isinstance(pointer["activation_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", pointer["activation_id"])):
            raise _invalid()
        digest = pointer["sha256"]
        generations = os.open("generations", _DIRECTORY, dir_fd=directory)
        try:
            info = os.fstat(generations)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _invalid()
            raw = _read_at(generations, digest + ".json", MAX_GENERATION_BYTES)
        finally:
            os.close(generations)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise _invalid()
        document = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(document, dict) or document.get("version") != 2 or type(document["version"]) is not int:
            raise _invalid()
        return document, hashlib.sha256(canonical_bytes(pointer)).hexdigest()

    @contextmanager
    def locked(self, *, exclusive=False):
        directory = lock = None
        try:
            directory = _directory(self.path)
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self.identity:
                raise _invalid()
            lock = os.open("activation.lock", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
            before = os.fstat(lock)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600):
                raise _invalid()
            fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            named = os.stat("activation.lock", dir_fd=directory, follow_symlinks=False)
            if _stamp(before) != _stamp(named):
                raise _invalid()
            yield directory
            current = _directory(self.path)
            try:
                after = os.fstat(current)
                named = os.stat("activation.lock", dir_fd=directory, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != self.identity or _stamp(before) != _stamp(named):
                    raise _invalid()
            finally:
                os.close(current)
        except AccessError:
            raise
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            raise _invalid() from None
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)

    def snapshot(self):
        with self.locked() as directory:
            return self._load(directory)

    @contextmanager
    def commit_guard(self, expected_digest=None):
        with self.locked() as directory:
            snapshot = self._load(directory)
            if expected_digest is not None and snapshot[1] != expected_digest:
                raise AccessError("Unified history authorization changed before delivery.", code="restart_required")
            yield snapshot

    def activate(self, document, *, expected_digest=None, initial=False):
        raw = canonical_bytes(document)
        if len(raw) > MAX_GENERATION_BYTES:
            raise _invalid()
        digest = hashlib.sha256(raw).hexdigest()
        with self.locked(exclusive=True) as directory:
            if initial:
                try:
                    os.stat("active.json", dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise AccessError("The unified history store is already active.", code="generation_conflict")
            else:
                current = self._load(directory)
                if expected_digest is None or current[1] != expected_digest:
                    raise AccessError("The previewed unified policy is no longer active.", code="generation_conflict")
            generations = os.open("generations", _DIRECTORY, dir_fd=directory)
            temporary = ".active-" + secrets.token_hex(12)
            try:
                try:
                    _write_new(generations, digest + ".json", raw)
                except FileExistsError:
                    if _read_at(generations, digest + ".json", MAX_GENERATION_BYTES) != raw:
                        raise _invalid()
                os.fsync(generations)
                pointer = {"version": 2, "sha256": digest, "activation_id": secrets.token_hex(16)}
                _write_new(directory, temporary, canonical_bytes(pointer))
                os.rename(temporary, "active.json", src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(generations)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        return hashlib.sha256(canonical_bytes(pointer)).hexdigest()


def initialize_store(path):
    """Operator-only initialization, before a descriptor can be used by a server."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise _invalid()
    path.mkdir(mode=0o700)
    directory = _directory(path)
    try:
        os.mkdir("generations", 0o700, dir_fd=directory)
        _write_new(directory, "activation.lock", b"")
        os.fsync(directory)
    finally:
        os.close(directory)
    return GenerationStore(path)
