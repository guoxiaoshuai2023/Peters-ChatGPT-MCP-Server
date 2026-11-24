"""Physical path lifetimes used only for unified session attribution."""

from collections import OrderedDict
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import stat
import threading
import time

from .catalog import AccessError
from .fs_identity import persistent_identity, persistent_identity_fd


CHECKPOINT_SECONDS = 30


def owner_key(root, identity, repository_id):
    data = json.dumps([str(root), identity, repository_id], ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()
    return sha256(data).hexdigest()


def git_metadata_locations(probe, pin):
    """Named directories that tie this checkout to the same Git repository over time."""
    common, gitdir = probe["common"], probe["gitdir"]
    if common.parent != probe["root"]:
        yield common.parent, persistent_identity(common.parent), pin, None
    yield common, probe["common_identity"], ["git-common", pin], common.parent
    if gitdir != common:
        yield gitdir, persistent_identity(gitdir), ["git-worktree", pin], common


def merge_windows(windows):
    merged = []
    for start, end in sorted(tuple(window) for window in windows):
        if start > end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def check_origins(origin_ns, last_ns, witnesses):
    if not witnesses:
        return True
    return (type(origin_ns) is int and type(last_ns) is int and 0 < origin_ns <= last_ns <= time.time_ns()
            and all(record.covers(origin_ns, last_ns) for record in witnesses))


@dataclass(frozen=True)
class LocationEvidence:
    key: str
    floor: int
    windows: tuple
    store: object

    def covers(self, start, end):
        covered = self.store.verified_location_span(self.key, self.windows, start, end)
        return start >= self.floor and covered


def _intersect(left, right):
    result = []
    for start, end in left:
        for low, high in right:
            if max(low, start) <= min(high, end):
                result.append((max(low, start), min(high, end)))
    return merge_windows(result)


def _changed():
    return AccessError("The physical workspace location could not be verified.", code="association_unverified")


def _edge_since(child, parent, observed_ns):
    if child.st_dev != parent.st_dev:
        # Attaching a filesystem can replace this edge without renaming either
        # inode. Start with the observed mount; older evidence stays separate.
        return observed_ns
    # Renaming an ordinary directory changes it and its parent's entry table.
    return min(child.st_ctime_ns, parent.st_ctime_ns)


class _DirectoryWatch:
    """A vnode rename, deletion or revoke ends this path component's continuity."""

    def __init__(self, fd, parent):
        self.files = ExitStack()
        self.queue = None
        try:
            identity = persistent_identity_fd(fd)
            self.physical = (identity["volume_uuid"], identity["file_id"], identity["birthtime_ns"])
            if hasattr(select, "kqueue"):
                held = os.dup(fd)
                self.files.callback(os.close, held)
                self.queue = select.kqueue()
                self.files.callback(self.queue.close)
                event = select.kevent(held, filter=select.KQ_FILTER_VNODE, flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                      fflags=select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME | select.KQ_NOTE_REVOKE)
                self.queue.control([event], 0, 0)
            self.since = _edge_since(os.fstat(fd), os.fstat(parent), time.time_ns())
        except BaseException:
            self.files.close()
            raise

    def continuous(self):
        return self.queue is not None and not self.queue.control(None, 1, 0)


class LocationWitnesses:
    """Hold bounded component watches and hand only closed intervals to a spawned worker."""

    def __init__(self, closed=()):
        self.nodes = OrderedDict()
        self.closed = OrderedDict(closed)
        self.roots = OrderedDict()
        self.lock = threading.RLock()

    def __reduce__(self):
        with self.lock:
            for path, (floor, identity, within) in tuple(self.roots.items()):
                try:
                    self.observe(path, floor, identity, within=within)
                except AccessError:
                    pass
            return type(self), (tuple(self.closed.items()),)

    def _node(self, key, fd, parent):
        previous = self.nodes.pop(key, None)
        if previous is not None:
            if previous.continuous():
                self.nodes[key] = previous
                return previous
            previous.files.close()
        while len(self.nodes) >= 96:
            _, old = self.nodes.popitem(last=False)
            old.files.close()
        current = _DirectoryWatch(fd, parent)
        self.nodes[key] = current
        return current

    def observe(self, root, floor, identity, *, within=None):
        path = Path(root)
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise _changed()
        base = Path(within) if within is not None else Path("/")
        if base == path or not path.is_relative_to(base):
            raise _changed()
        try:
            with self.lock, ExitStack() as stack:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                parent = os.open("/", flags)
                stack.callback(os.close, parent)
                address = Path("/")
                nodes = []
                for part in path.parts[1:]:
                    address = address / part
                    child = os.open(part, flags, dir_fd=parent)
                    stack.callback(os.close, child)
                    info = os.fstat(child)
                    key = (str(address), info.st_dev, info.st_ino)
                    nodes.append((key, self._node(key, child, parent), parent, part, child))
                    parent = child
                if persistent_identity_fd(parent) != identity:
                    raise _changed()
                end = time.time_ns()
                windows = ((floor, end),)
                for key, watch, parent, part, child in nodes:
                    named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                    if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != key[1:3]:
                        raise _changed()
                    if watch.queue is None:
                        start = _edge_since(named, os.fstat(parent), end)
                    elif watch.continuous():
                        start = watch.since
                    else:
                        self.nodes.pop(key).files.close()
                        raise _changed()
                    stable_key = (key[0], *watch.physical)
                    prior = self.closed.pop(stable_key, ())
                    evidence = merge_windows((*prior, (start, end)))[-64:]
                    self.closed[stable_key] = evidence
                    # The registered root's own receipt independently proves
                    # the prefix, including any retained pre-restart interval.
                    if Path(key[0]) != base and Path(key[0]).is_relative_to(base):
                        windows = _intersect(windows, evidence)
                while len(self.closed) > 256:
                    self.closed.popitem(last=False)
                self.roots[path] = (floor, identity, within)
                self.roots.move_to_end(path)
                if len(self.roots) > 32:
                    self.roots.popitem(last=False)
                return windows
        except OSError:
            raise _changed() from None

    def close(self):
        with self.lock:
            while self.nodes:
                _, item = self.nodes.popitem()
                item.files.close()

    def __del__(self):
        self.close()
