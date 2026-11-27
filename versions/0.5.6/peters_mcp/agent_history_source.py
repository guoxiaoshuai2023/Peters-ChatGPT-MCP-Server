"""Read-only sources and normalized records for agent history adapters."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import sqlite3
import shutil
import stat
import tempfile

from .catalog import AccessError

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
_MAX_DIRECTORY = 10_000
_MAX_SQLITE = 96 * 1024 * 1024
_BLOCK = 256 * 1024


@dataclass(frozen=True)
class Thread:
    native_id: str
    title: str = ""
    updated_at: str = ""
    contexts: tuple[str, ...] = ()
    ancestors: tuple[str, ...] = ()
    context_complete: bool = False
    agent: str = ""
    surface: str = ""
    native_link: tuple[str, str] | None = None
    location: str = ""
    native_project_id: str = ""
    ancestor_projects: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Message:
    role: str
    text: str
    position: str
    timestamp: str = ""
    turn_id: str = ""


@dataclass(frozen=True)
class Projection:
    messages: tuple[Message, ...]
    revision: str
    identity: str
    contexts: tuple[str, ...] = ()
    ancestors: tuple[str, ...] = ()
    context_complete: bool = False
    warnings: tuple[str, ...] = ()
    title: str = ""
    prefix: tuple[str, int, str] | None = None
    # Earliest native creation time in the verified lineage, never a file mtime.
    origin_ns: int | None = None
    last_ns: int | None = None
    # Native senders whose verified receipts contributed to this projection.
    related_threads: tuple[str, ...] = ()
    # Optional declared turn summary for sources with explicit turn boundaries.
    latest_turn_id: str = ""
    ambiguous_turn_ids: tuple[str, ...] = ()
    attached_thread: bool = False


def _unavailable():
    return AccessError("The registered history source is unavailable.", code="source_unavailable")


def _unstable():
    return AccessError("The registered history source is changing.", code="waiting_source_stable")


def _identity(info):
    return (info.st_dev, info.st_ino, getattr(info, "st_birthtime", None))


def _stamp(info):
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parts(relative, *, directory=False):
    value = os.fspath(relative)
    if directory and value in ("", "."):
        return ()
    if (not isinstance(value, str) or value.startswith("/") or "\\" in value or "\0" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise _unavailable()
    return PurePosixPath(value).parts


@contextmanager
def _directory(parts, *, initial=None):
    fd = os.open("/", _DIRECTORY) if initial is None else os.dup(initial)
    try:
        for part in parts:
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


class SourceRoot:
    def __init__(self, path, *, expected_identity=None, scratch=None, scratch_identity=None):
        self.path = Path(path)
        if not self.path.is_absolute() or ".." in self.path.parts:
            raise _unavailable()
        self.scratch = Path(scratch) if scratch is not None else None
        self._scratch_identity = scratch_identity
        self._root_identity = expected_identity
        with self.directory() as fd:
            self._root_identity = _identity(os.fstat(fd))

    @property
    def identity(self):
        return self._root_identity

    @contextmanager
    def directory(self, relative=""):
        try:
            with _directory(self.path.parts[1:]) as root:
                if self._root_identity is not None and _identity(os.fstat(root)) != self._root_identity:
                    raise _unavailable()
                if relative:
                    with _directory(_parts(relative, directory=True), initial=root) as fd:
                        yield fd
                else:
                    yield root
        except OSError:
            raise _unavailable() from None

    @contextmanager
    def open(self, relative):
        parts = _parts(relative)
        directory = "/".join(parts[:-1])
        with self.directory(directory) as parent:
            fd = os.open(parts[-1], _FILE, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise _unavailable()
                with os.fdopen(os.dup(fd), "rb") as stream:
                    yield stream
                with self.directory(directory) as current:
                    after = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
                    if _identity(after) != _identity(info) or after.st_nlink != 1:
                        raise _unstable()
            finally:
                os.close(fd)

    def identity_for(self, relative):
        with self.open(relative) as stream:
            info = os.fstat(stream.fileno())
            return ":".join(str(part) for part in _identity(info))

    def entries(self, relative="", *, select=None):
        result = []
        count = 0
        with self.directory(relative) as fd, os.scandir(fd) as entries:
            for entry in entries:
                if select is not None and not select(entry.name):
                    continue
                if count == _MAX_DIRECTORY:
                    raise AccessError("The source directory is too large.", code="resource_exhausted")
                count += 1
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    result.append((entry.name, "dir"))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    result.append((entry.name, "file"))
        return tuple(sorted(result))

    def iter_entries(self, relative="", *, select=None):
        """Stream metadata for scoped readers; the supervised worker bounds work."""
        with self.directory(relative) as fd, os.scandir(fd) as entries:
            for entry in entries:
                if select is not None and not select(entry.name):
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    yield entry.name, "dir"
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    yield entry.name, "file"

    def _sqlite_files(self, relative):
        parts = _parts(relative)
        directory, basename = "/".join(parts[:-1]), parts[-1]
        files = []
        with self.directory(directory) as fd:
            for name in (basename, basename + "-wal", basename + "-journal"):
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    if name == basename:
                        raise _unavailable() from None
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise _unavailable()
                if name.endswith("-journal"):
                    raise _unstable()
                files.append("/".join((*parts[:-1], name)))
        return tuple(files)

    def _digest(self, relative, budget, target=None):
        digest = hashlib.sha256()
        total = 0
        with self.open(relative) as stream:
            before = _stamp(os.fstat(stream.fileno()))
            if before[3] > budget:
                raise AccessError("The SQLite snapshot exceeds its byte budget.", code="resource_exhausted")
            while chunk := stream.read(_BLOCK):
                total += len(chunk)
                if total > budget:
                    raise AccessError("The SQLite snapshot exceeds its byte budget.", code="resource_exhausted")
                digest.update(chunk)
                if target is not None:
                    target.write(chunk)
            if _stamp(os.fstat(stream.fileno())) != before or total != before[3]:
                raise _unstable()
        return before, digest.hexdigest()

    @contextmanager
    def sqlite(self, relative):
        """Query a private DB/WAL copy. SQLite never opens the vendor's files."""
        files = self._sqlite_files(relative)
        if self.scratch is not None:
            with SourceRoot(self.scratch, expected_identity=self._scratch_identity).directory() as directory:
                metadata = os.fstat(directory)
                if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise _unavailable()
        with tempfile.TemporaryDirectory(prefix="sqlite-", dir=self.scratch) as temporary:
            copied = {}
            remaining = _MAX_SQLITE
            for name in files:
                destination = Path(temporary) / Path(name).name
                with destination.open("xb") as target:
                    copied[name] = self._digest(name, remaining, target)
                remaining -= copied[name][0][3]
            if self._sqlite_files(relative) != files:
                raise _unstable()
            for name, expected in copied.items():
                if self._digest(name, expected[0][3]) != expected:
                    raise _unstable()
            if self._sqlite_files(relative) != files:
                raise _unstable()
            database = Path(temporary) / Path(relative).name
            try:
                con = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
                try:
                    con.execute("PRAGMA query_only=ON")
                    con.execute("PRAGMA trusted_schema=OFF")
                    con.execute("BEGIN")
                    yield con
                finally:
                    con.close()
            except sqlite3.Error:
                raise AccessError("The source database format could not be read.", code="unsupported_format") from None


def clear_snapshot_copies(path, identity, *, include_workers=False):
    """Remove abandoned copies only from a pinned service-owned directory."""
    root = SourceRoot(path, expected_identity=identity)
    with root.directory() as directory:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise _unavailable()
        with os.scandir(directory) as scan:
            for item in scan:
                if item.name.startswith("sqlite-") or (include_workers and item.name.startswith("worker-")):
                    if item.is_dir(follow_symlinks=False):
                        shutil.rmtree(item.name, dir_fd=directory)
