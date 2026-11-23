"""Read-only Git identity and registered working-directory discovery.

Repository authorization is pinned to the common Git directory's canonical path
and persistent filesystem identity. Legacy pins remain exact current-device pins.
Only this module's fixed discovery commands are allowed; no repository scripts,
index refresh, checkout, worktree repair, or arbitrary Git methods are exposed.
"""

from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from .catalog import AccessError, DIRECTORY_FLAGS, _close_source_fd
from .fs_identity import persistent_identity, persistent_identity_fd, validate_identity
from .history_location import LocationEvidence, merge_windows, owner_key


GIT = "/usr/bin/git"
MAX_GIT_OUTPUT = 2 * 1024 * 1024
MAX_WORKTREE_REGISTRATIONS = 4096
_discovery_deadline = ContextVar("peters_discovery_deadline", default=None)
_validation_observer = ContextVar("peters_history_topology", default=None)


def _time_left(maximum):
    deadline = _discovery_deadline.get()
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AccessError("The physical scope deadline expired.", code="restart_required")
    return min(maximum, remaining)


@contextmanager
def discovery_deadline(deadline):
    token = _discovery_deadline.set(deadline)
    try:
        yield
    finally:
        _discovery_deadline.reset(token)


@contextmanager
def observe_validation_topology(observer):
    """Each worker task observes only discoveries made by its own validation generator."""
    token = _validation_observer.set(observer)
    try:
        yield
    finally:
        _validation_observer.reset(token)

def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":")).encode()).hexdigest()


def _git(root, operation):
    commands = {
        "probe": ["rev-parse", "--path-format=absolute", "--git-common-dir",
                  "--show-toplevel", "--absolute-git-dir"],
        "worktrees": ["worktree", "list", "--porcelain", "-z"],
        # Ask Git for configuration dependencies only. Configuration values for
        # credentials, remotes and other unrelated settings never enter Python.
        "includes": ["config", "--includes", "--show-origin", "--null", "--type=path",
                     "--get-regexp", r"^include(if\..*)?\.path$"],
        "head-ref": ["symbolic-ref", "--quiet", "--no-recurse", "HEAD"],
        "resolved-head-ref": ["symbolic-ref", "--quiet", "HEAD"],
    }
    if operation not in commands:
        raise AccessError("Unsupported repository discovery operation.")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_ATTR_NOSYSTEM="1",
               LC_ALL="C")
    try:
        result = subprocess.run(
            [GIT, "--no-pager", "-c", "core.fsmonitor=false", "-c",
             f"core.hooksPath={os.devnull}", "-c", "maintenance.auto=false", "-c",
             "gc.auto=0", "-C", str(root), *commands[operation]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, timeout=_time_left(5), check=False,
        )
    except OSError:
        # Popen may fail while closing its temporary descriptors. Its public
        # exception cannot distinguish that from setup failure; do not refund
        # the export owner's auxiliary reservation on an unconfirmed outcome.
        raise AccessError('Repository process descriptor cleanup is unconfirmed.',
                          code='source_cleanup_pending') from None
    except subprocess.TimeoutExpired as exc:
        raise AccessError("Repository discovery unavailable or timed out.") from exc
    if operation in {"includes", "head-ref", "resolved-head-ref"} and result.returncode == 1 and not result.stdout:
        return ""  # No include declarations, or HEAD is detached.
    if result.returncode or len(result.stdout) > MAX_GIT_OUTPUT:
        raise AccessError("Repository discovery failed or exceeded its output limit.")
    return os.fsdecode(result.stdout)


def _clean_path(value):
    path = Path(value)
    if not path.is_absolute() or any(ord(char) < 32 for char in str(path)):
        raise AccessError("Repository path is not a supported absolute path.")
    return Path(os.path.normpath(path))


def _directory(path):
    """Reject aliases and replaced symbolic-link ancestors, including root itself."""
    path = _clean_path(path)
    try:
        canonical = path.resolve(strict=True)
    except RuntimeError as exc:
        raise AccessError("Repository path contains a symbolic-link cycle.") from exc
    if canonical != path or not path.is_dir():
        raise AccessError("Repository path unavailable or a symbolic link.")
    return path


def _runtime_identity(info):
    # Permissions and ownership must not change while metadata is being read.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _metadata_identity(info):
    return (*_runtime_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_path(path, *, directory):
    """Walk from / using directory FDs; never follow a symlink component."""
    path = _clean_path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    current = os.open("/", flags | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            is_directory = directory or index < len(path.parts) - 2
            following = os.open(component, flags | (os.O_DIRECTORY if is_directory else 0),
                                dir_fd=current)
            previous, current = current, following
            _close_source_fd(previous)
        info = os.fstat(current)
        if (directory and not stat.S_ISDIR(info.st_mode)) or (
                not directory and (not stat.S_ISREG(info.st_mode) or info.st_size > 4096)):
            raise AccessError("Invalid repository metadata object.")
        result, current = current, None
        return result, info
    finally:
        if current is not None:
            _close_source_fd(current)


class _ProbeHandles:
    """Hold directory anchors and preserve checked pointer-file proofs."""

    def __init__(self, stack):
        self.stack = stack
        self.proofs = {}

    def open(self, path, *, directory=True):
        path = _clean_path(path)
        if path in self.proofs:
            fd, before, was_directory, content = self.proofs[path]
            if was_directory != directory:
                raise AccessError("Repository metadata type changed.")
            return fd, before
        fd, info = _open_path(path, directory=directory)
        self.stack.callback(_close_source_fd, fd)
        self.proofs[path] = [fd, info, directory, None]
        return fd, info

    def read(self, path):
        path = _clean_path(path)
        fd, info = _open_path(path, directory=False)
        try:
            content = os.read(fd, 4097)
            if len(content) > 4096 or b"\0" in content:
                raise AccessError("Invalid repository metadata contents.")
            if _metadata_identity(os.fstat(fd)) != _metadata_identity(info):
                raise AccessError("Repository metadata changed while reading.", code="identity_mismatch")
        finally:
            _close_source_fd(fd)
        # Hold directory anchors throughout the probe. Small pointer files are
        # closed after reading, then reopened and checked by full stat metadata
        # and exact bytes. Keeping all of them open exceeds the export FD ticket.
        self.proofs[path] = [None, info, False, content]
        return os.fsdecode(content).rstrip("\n")

    def verify(self):
        for path, (fd, before, directory, content) in self.proofs.items():
            current = os.fstat(fd) if fd is not None else before
            if _runtime_identity(current) != _runtime_identity(before):
                raise AccessError("Repository metadata identity changed.", code="identity_mismatch")
            reopened, observed = _open_path(path, directory=directory)
            try:
                if _runtime_identity(observed) != _runtime_identity(before):
                    raise AccessError("Repository metadata path was replaced.", code="identity_mismatch")
                if content is not None:
                    if (_metadata_identity(observed) != _metadata_identity(before)
                            or os.read(reopened, 4097) != content
                            or _metadata_identity(os.fstat(reopened)) != _metadata_identity(before)):
                        raise AccessError("Repository metadata contents changed.", code="identity_mismatch")
            finally:
                _close_source_fd(reopened)


def repository_pin_v1(common, device, inode):
    """Recompute the original pin; this never validates or authorizes a path."""
    common = _clean_path(common)
    if type(device) is not int or type(inode) is not int or device < 0 or inode <= 0:
        raise AccessError("Invalid legacy repository identity.")
    return "git-" + _digest([str(common), device, inode])


def _pin_v2(common, identity):
    validate_identity(identity)
    return "git-v2-" + _digest(["peters-mcp-repository-pin-v2", str(common), identity])


def _pin_matches(pin, probe):
    if not isinstance(pin, str):
        return False
    if pin.startswith("git-v2-"):
        return pin == probe["repository_id"]
    return pin == probe["legacy_repository_id"]


def _probe(root):
    """Read verified metadata only. The caller still has to check authorization."""
    root = _directory(root)
    with ExitStack() as stack:
        handles = _ProbeHandles(stack)
        handles.open(root)
        fields = _git(root, "probe").rstrip("\n").split("\n")
        if len(fields) != 3:
            raise AccessError("Unsupported repository metadata format.")
        common, top, gitdir = (_directory(value) for value in fields)
        return _metadata_probe(top, gitdir, common, handles)


def _metadata_probe(top, gitdir, common, handles):
    for path in (common, top, gitdir):
        handles.open(path)
    common_fd, info = handles.open(common)
    dotgit = top / ".git"
    if gitdir != common:
        if gitdir.parent != common / "worktrees":
            raise AccessError("Worktree administration directory is not registered.")
        pointer = handles.read(dotgit)
        if not pointer.startswith("gitdir: ") or "\n" in pointer:
            raise AccessError("Invalid worktree Git pointer.")
        target = Path(pointer[len("gitdir: "):])
        target = _clean_path(target if target.is_absolute() else top / target)
        if target != gitdir:
            raise AccessError("Worktree Git pointer does not match.")
        backlink = handles.read(gitdir / "gitdir")
        if _clean_path(backlink) != dotgit:
            raise AccessError("Worktree registration backlink does not match.")
        commondir = Path(handles.read(gitdir / "commondir"))
        commondir = _clean_path(commondir if commondir.is_absolute() else gitdir / commondir)
        if commondir != common:
            raise AccessError("Worktree common directory does not match.")
    elif dotgit != common:
        raise AccessError("Working directory does not match its Git metadata.")
    else:
        handles.open(dotgit)
    try:
        identity = persistent_identity_fd(common_fd)
    except AccessError as error:
        if error.code == "identity_cleanup_pending":
            raise AccessError("Repository identity descriptor cleanup is unconfirmed.",
                              code="source_cleanup_pending") from None
        raise
    validate_identity(identity)
    if identity["file_id"] != info.st_ino:
        raise AccessError("Repository common identity changed.", code="identity_mismatch")
    # The checked pointer, backlink and commondir prove the fixed Git
    # result. Re-running a process while all anchors are open would exceed
    # the exporter ticket, and would not strengthen those FD proofs.
    handles.verify()
    root_fd, root_info = handles.open(top)
    # Birth of the physical checkout and common repository bounds their history.
    # Git rewrites the backlink when a linked checkout is moved to a new path.
    physical = persistent_identity_fd(root_fd)
    history_birth = max(identity["birthtime_ns"], physical["birthtime_ns"])
    if gitdir != common:
        _, backlink_info = handles.open(gitdir / "gitdir", directory=False)
        history_birth = max(history_birth, backlink_info.st_ctime_ns)
    return {"root": top, "common": common, "gitdir": gitdir, "common_identity": identity,
            "history_birth_ns": history_birth,
            "history_root_identity": physical,
            "root_runtime_identity": [root_info.st_dev, root_info.st_ino],
            "common_runtime_identity": [info.st_dev, info.st_ino],
            "repository_id": _pin_v2(common, identity),
            "legacy_repository_id": repository_pin_v1(common, info.st_dev, info.st_ino)}


def revalidate_repository_probe(probe):
    """Recheck a previously discovered root using small, no-follow metadata only."""
    with ExitStack() as stack:
        current = _metadata_probe(probe["root"], probe["gitdir"], probe["common"], _ProbeHandles(stack))
    if current != probe:
        raise AccessError("Verified repository identity changed.", code="scope_changed")


def registration_stamp(common):
    """Capture Git registration membership and the small administrative witnesses."""
    path = common / "worktrees"
    try:
        fd, info = _open_path(path, directory=True)
    except FileNotFoundError:
        return None
    try:
        names = sorted(os.listdir(fd))
        if len(names) > MAX_WORKTREE_REGISTRATIONS:
            raise AccessError("Git worktree registration exceeds the bounded proof size.", code="scope_changed")
        markers = []
        for name in names:
            _time_left(5)
            details = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode):
                raise AccessError("Git worktree registration entry is not a directory.", code="scope_changed")
            member = os.open(name, DIRECTORY_FLAGS, dir_fd=fd)
            try:
                if _runtime_identity(os.fstat(member)) != _runtime_identity(details):
                    raise AccessError("Git worktree registration changed.", code="scope_changed")
                pointers = []
                for pointer in ("gitdir", "commondir"):
                    try:
                        metadata = os.stat(pointer, dir_fd=member, follow_symlinks=False)
                    except FileNotFoundError:
                        pointers.append(None)
                    else:
                        pointers.append(_metadata_identity(metadata))
                markers.append((name, _runtime_identity(details), tuple(pointers)))
            finally:
                _close_source_fd(member)
        if _metadata_identity(os.fstat(fd)) != _metadata_identity(info):
            raise AccessError("Git worktree registration changed.", code="scope_changed")
        return _metadata_identity(info), tuple(markers)
    finally:
        _close_source_fd(fd)


def repository_probe(root):
    """Read-only checked anchors for the local maintenance tools; no repinning."""
    return _probe(root)


def repository_pin_v2(root):
    """Return a stable pin for a checked real worktree, without granting access."""
    return _probe(root)["repository_id"]


def _records(raw):
    records = []
    for block in raw.split("\0\0"):
        if not block:
            continue
        record = {}
        for field in block.split("\0"):
            if not field:
                continue
            key, separator, value = field.partition(" ")
            if key in {"worktree", "HEAD", "branch", "bare", "prunable"}:
                record[key] = value if separator else True
        if "worktree" not in record:
            raise AccessError("Unsupported worktree discovery record.")
        records.append(record)
    return records


def _path_stamp(path):
    """Metadata only. A directory's ordinary child writes do not change its scope."""
    try:
        info = path.lstat()
        try:
            canonical = path.resolve() == path
        except RuntimeError:
            # A symbolic-link cycle is not a canonical visible worktree.
            canonical = False
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
            return ("absent",)
        raise AccessError("Cannot verify a workspace path.", code="scope_changed") from None
    stamp = _runtime_identity(info) if stat.S_ISDIR(info.st_mode) else _metadata_identity(info)
    return (canonical, *stamp)


def _control_stamp(path):
    """Check the file Git would actually open, including a symlink's target."""
    try:
        info = path.stat()
        resolved = str(path.resolve(strict=True))
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR}:
            return ("absent",)
        raise AccessError("Cannot verify repository control metadata.", code="scope_changed") from None
    except RuntimeError:
        raise AccessError("Cannot resolve repository control metadata.", code="scope_changed") from None
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or resolved == os.devnull):
        raise AccessError("Unsupported repository control file type.", code="scope_changed")
    if stat.S_ISDIR(info.st_mode):
        return (resolved, *_runtime_identity(info), os.access(path, os.X_OK))
    return (resolved, *_metadata_identity(info), os.access(path, os.R_OK))


def _configuration_inputs(root):
    raw = _git(root, "includes")
    if not raw:
        return set(), False
    fields = raw.split("\0")
    if fields.pop() or len(fields) % 2 or len(fields) > 2 * MAX_WORKTREE_REGISTRATIONS:
        raise AccessError("Unsupported Git configuration dependency list.", code="scope_changed")
    paths, on_branch = set(), False
    for origin, setting in zip(fields[::2], fields[1::2]):
        key, separator, value = setting.partition("\n")
        name = origin.removeprefix("file:")
        if (not name or name == origin or not separator or not value or value.startswith(("~", "%("))
                or any(ord(ch) < 32 for ch in name + value)):
            raise AccessError("Cannot determine a Git configuration dependency.", code="scope_changed")
        source = root / name
        if key.startswith("includeif."):
            condition = key[len("includeif."):-len(".path")].lower()
            if condition.startswith("onbranch:"):
                on_branch = True
            elif not condition.startswith(("gitdir:", "gitdir/i:", "hasconfig:remote.*.url:")):
                raise AccessError("Cannot bound this Git include condition.", code="scope_changed")
        # Retain '..' components: a preceding symlink can change their POSIX meaning.
        paths.update((source, source.parent / value))
    return paths, on_branch


@dataclass(frozen=True)
class TopologyReceipt:
    """Local evidence from the discovery that actually produced a group of fingerprints."""
    generation: str
    fingerprints: tuple
    locations: tuple
    controls: tuple
    registrations: tuple
    complete: bool

    def require_complete(self):
        if not self.complete:
            raise AccessError("Physical project scope is unverifiable. Start a fresh request.", code="restart_required")

    def digest_for(self, project_id):
        self.require_complete()
        if project_id is None:
            return _digest(("all", self.fingerprints))
        fingerprints = dict(self.fingerprints)
        if project_id not in fingerprints:
            raise AccessError("Validated project is unavailable.", code="restart_required")
        return _digest(("project", project_id, fingerprints[project_id]))

    def current(self, snapshot, deadline):
        if self.generation != snapshot[1] or not self.complete:
            return False
        with discovery_deadline(deadline):
            for path, before in self.locations:
                _time_left(5)
                if _path_stamp(path) != before:
                    return False
            for path, before in self.controls:
                _time_left(5)
                if _control_stamp(path) != before:
                    return False
            for common, before in self.registrations:
                _time_left(5)
                if registration_stamp(common) != before:
                    return False
        return True


class _TopologyFacts:
    def __init__(self):
        self.locations = {}
        self.controls = {}
        self.git_contexts = set()
        self.registrations = {}
        self.complete = True

    def location(self, path):
        stamp = _path_stamp(path)
        if self.locations.setdefault(path, stamp) != stamp:
            raise AccessError("Workspace changed during discovery.", code="scope_changed")
        return stamp

    def watch_root(self, root, *, git):
        self.location(root)
        if git:
            self.location(root / ".git")

    def probe(self, probe):
        for key in ("root", "gitdir", "common"):
            self.location(probe[key])
        if probe["gitdir"] != probe["common"]:
            self.location(probe["gitdir"] / "gitdir")
        root, common, gitdir = probe["root"], probe["common"], probe["gitdir"]
        if root in self.git_contexts:
            return
        # These affect repository and worktree recognition. Ordinary objects,
        # refs and worktree file writes do not change their directory identity.
        for path in (common / "config", common / "config.worktree", gitdir / "config.worktree",
                     gitdir / "commondir", gitdir / "HEAD", common / "HEAD",
                     common / "objects", common / "refs", common / "reftable"):
            self.control(path)
        dependencies, on_branch = _configuration_inputs(root)
        if on_branch:
            # Ref storage may change the effective branch with an unchanged HEAD.
            # Do not grant from an indirect ref chain whose dependencies are unknown.
            for refdir in {common, gitdir}:
                self.control(refdir / "reftable" / "tables.list")
            direct = _git(root, "head-ref").rstrip("\n")
            ultimate = _git(root, "resolved-head-ref").rstrip("\n")
            if direct != ultimate or (direct and (not direct.startswith("refs/heads/")
                    or ".." in Path(direct).parts or any(ord(c) < 32 for c in direct))):
                raise AccessError("Cannot bound the current branch's Git references.", code="scope_changed")
            if direct:
                self.control(common / direct)
                self.control(common / "packed-refs")
        for path in dependencies:
            self.control(path)
        # An included file could have changed before it first became known.
        # Confirm the dependency closure and Git's actual decision with its
        # inputs now observed. The final metadata check also catches changes
        # while Git or another worktree in this same discovery is being read.
        if dependencies and _configuration_inputs(root) != (dependencies, on_branch):
            raise AccessError("Git configuration changed during discovery.", code="restart_required")
        if on_branch and (_git(root, "head-ref").rstrip("\n") != direct
                          or _git(root, "resolved-head-ref").rstrip("\n") != direct):
            raise AccessError("Git branch changed during discovery.", code="restart_required")
        decision = _git(root, "probe").rstrip("\n").split("\n")
        if decision != list(map(str, (common, root, gitdir))):
            raise AccessError("Git repository changed during discovery.", code="restart_required")
        self.git_contexts.add(root)

    def control(self, path):
        value = _control_stamp(path)
        if self.controls.setdefault(path, value) != value:
            raise AccessError("Git control metadata changed during discovery.", code="restart_required")

    def observe_registration(self, common):
        stamp = registration_stamp(common)
        if self.registrations.setdefault(common, stamp) != stamp:
            raise AccessError("Git registration changed during discovery.", code="scope_changed")

    def finish(self, snapshots, generation):
        for path in self.controls:
            _time_left(5)
            self.control(path)
        fingerprints = tuple(sorted((pid, info["fingerprint"]) for pid, info in snapshots.items()))
        return TopologyReceipt(generation, fingerprints, tuple(self.locations.items()),
                               tuple(self.controls.items()), tuple(self.registrations.items()), self.complete)


class DiscoveredWorkspaces(dict):
    """Regular public mapping. Private evidence is excluded from JSON serialization."""
    def __init__(self, values, topology):
        super().__init__(values)
        self.topology = topology


class RepositoryRegistry:
    def __init__(self, projects, *, scope_policy=None):
        self.projects = projects
        self.scope_policy = scope_policy
        self.generation = None
        self.history_windows = None
        self.history_store = None

    @staticmethod
    def identity(root):
        """Return a pin for a real worktree; never authorizes that pin implicitly."""
        try:
            return _probe(Path(root))["repository_id"]
        except OSError as exc:
            raise AccessError("Repository identity is unavailable.") from exc

    def _project(self, project_id):
        if not isinstance(project_id, str) or project_id not in self.projects:
            raise AccessError("Unknown project. Call list_projects first.")
        return self.projects[project_id]

    @staticmethod
    def _entry(root, default, pin, record=None, forced_state=None, reason=None, *, facts=None):
        record = record or {}
        root = _clean_path(root)
        branch = record.get("branch")
        entry = {"id": "main" if default else "wt-" + sha256(os.fsencode(root)).hexdigest()[:20],
                 "root": str(root), "branch": branch.removeprefix("refs/heads/") if branch else None,
                 "head": record.get("HEAD"), "state": "valid", "reason": "registered_worktree",
                 "is_default": default, "repository_id": pin}
        if forced_state:
            entry.update(state=forced_state, reason=reason)
            return entry
        try:
            if not root.exists():
                entry.update(state="missing", reason="working_directory_missing")
            elif root.is_symlink() or root.resolve(strict=True) != root:
                entry.update(state="identity_mismatch", reason="symbolic_link_directory")
            else:
                probe = _probe(root)
                if not _pin_matches(pin, probe) or probe["root"] != root or record.get("bare"):
                    entry.update(state="identity_mismatch", reason="repository_or_registration_changed")
                else:
                    if facts is not None:
                        try:
                            facts.probe(probe)
                        except (OSError, AccessError):
                            facts.complete = False
                            raise
                    entry["root_identity"] = probe["root_runtime_identity"]
        except (OSError, RuntimeError, AccessError) as error:
            if isinstance(error, AccessError) and error.code in {'source_cleanup_pending', 'restart_required'}:
                raise
            entry.update(state="unavailable", reason="working_directory_or_git_metadata_unavailable")
        return entry

    @staticmethod
    def _snapshot(project, pin, mode, entries):
        scope = []
        for entry in entries:
            inode = None
            if entry["state"] == "valid":
                try:
                    fd, info = _open_path(entry["root"], directory=True)
                    try:
                        inode = [info.st_dev, info.st_ino]
                        if entry.get("root_identity", inode) != inode:
                            raise AccessError("Working directory changed after repository verification.")
                        entry["root_identity"] = inode
                    finally:
                        _close_source_fd(fd)
                except (OSError, AccessError) as error:
                    if isinstance(error, AccessError) and error.code == "source_cleanup_pending":
                        raise
                    inode = None
                    entry.pop("root_identity", None)
                    entry.update(state="unavailable", reason="working_directory_changed")
            scope.append([entry["id"], entry["root"], entry["state"],
                          entry["repository_id"], inode])
        return {"project_id": project.id, "repository_id": pin, "mode": mode,
                "fingerprint": _digest([project.id, pin, mode, sorted(scope)]), "worktrees": entries}

    def _discover(self, project_id, facts=None):
        project = self._project(project_id)
        root = _clean_path(project.root)
        pin = getattr(project, "repository_id", None)
        if facts is not None:
            facts.watch_root(root, git=pin is not None)
        if pin is None:
            entry = self._entry(root, True, None, forced_state="valid", reason="configured_directory")
            try:
                _directory(root)
                expected = getattr(project, "directory_identity", None)
                if expected is not None:
                    descriptor, _ = _open_path(root, directory=True)
                    try:
                        if persistent_identity_fd(descriptor) != expected:
                            entry.update(state="identity_mismatch", reason="configured_directory_pin_changed")
                    finally:
                        _close_source_fd(descriptor)
            except FileNotFoundError:
                entry.update(state="missing", reason="working_directory_missing")
            except (OSError, AccessError):
                entry.update(state="unavailable", reason="working_directory_unavailable")
            return self._snapshot(project, None, "directory", [entry])
        try:
            origin = _probe(root)
            if facts is not None:
                facts.probe(origin)
            initial_identity = getattr(project, "registration_identity", None)
            matches_identity = True
            if initial_identity is not None:
                fd, _ = _open_path(root, directory=True)
                try:
                    matches_identity = persistent_identity_fd(fd) == initial_identity
                finally:
                    _close_source_fd(fd)
            if not _pin_matches(pin, origin) or origin["root"] != root or not matches_identity:
                entry = self._entry(root, True, pin, forced_state="identity_mismatch",
                                    reason="configured_repository_pin_changed")
                return self._snapshot(project, pin, "repository", [entry])
            common = origin["common"]
            if facts is not None:
                facts.observe_registration(common)
            records = _records(_git(root, "worktrees"))
        except FileNotFoundError:
            if facts is not None and facts.locations[root] != ("absent",) and facts.locations[root / ".git"] != ("absent",):
                facts.complete = False
            entry = self._entry(root, True, pin, forced_state="missing", reason="configured_directory_missing")
            return self._snapshot(project, pin, "repository", [entry])
        except (OSError, AccessError) as error:
            if isinstance(error, AccessError) and error.code in {"source_cleanup_pending", "restart_required"}:
                raise
            if facts is not None and facts.locations[root] != ("absent",) and facts.locations[root / ".git"] != ("absent",):
                # An ambiguous failure cannot prove the absence of external Git registrations.
                facts.complete = False
            entry = self._entry(root, True, pin, forced_state="unavailable", reason="repository_discovery_unavailable")
            return self._snapshot(project, pin, "repository", [entry])
        entries, roots = [], set()
        for record in records:
            try:
                path = _clean_path(record["worktree"])
            except (AccessError, TypeError):
                continue
            if path in roots:
                continue
            roots.add(path)
            if facts is not None:
                facts.watch_root(path, git=True)
            entries.append(self._entry(path, path == root, pin, record, facts=facts))
        if root not in roots:
            entries.append(self._entry(root, True, pin, forced_state="identity_mismatch",
                                       reason="configured_directory_not_registered"))
            # A forged/default pointer cannot be used as a gateway to other roots.
            entries = [entry for entry in entries if entry["is_default"]]
        entries.sort(key=lambda entry: (not entry["is_default"], entry["root"]))
        if facts is not None:
            facts.observe_registration(common)
        return self._snapshot(project, pin, "repository", entries)

    def discover(self, project_id):
        self._project(project_id)
        if self.scope_policy is None:
            return self._discover(project_id)
        snapshots = self.discover_all()
        snapshots.topology.require_complete()
        return snapshots[project_id]

    def discover_all(self, *, observe=True):
        if self.scope_policy is None:
            return {project_id: self._discover(project_id) for project_id in self.projects}
        from .agent_history_policy import _overlap
        facts = _TopologyFacts()
        snapshots = {project_id: self._discover(project_id, facts) for project_id in self.projects}
        # An existing registered path whose Git probe failed is still a
        # possible overlap. A transient subprocess failure has no filesystem
        # marker that could safely witness its continued unavailability.
        extents = {
            project_id: {str(self.projects[project_id].root), *(row["root"] for row in discovery["worktrees"]
                                                               if row["state"] in {"valid", "unavailable"})}
            for project_id, discovery in snapshots.items()
        }
        for project_id, discovery in snapshots.items():
            entries = []
            for row in discovery["worktrees"]:
                if row["state"] == "valid" and any(
                        _overlap(row["root"], path)
                        for other, paths in extents.items() if other != project_id for path in paths):
                    row = {**row, "state": "conflict", "reason": "overlapping_project_scope"}
                    row.pop("root_identity", None)
                entries.append(row)
            project = self.projects[project_id]
            snapshots[project_id] = self._snapshot(project, project.repository_id, discovery["mode"], entries)
        receipt = facts.finish(snapshots, self.generation)
        if observe:
            from .project_guard import note_discovery
            note_discovery(self.scope_policy, receipt)
            observer = _validation_observer.get()
            if observer is not None:
                receipt.require_complete()
                observer(receipt)
        return DiscoveredWorkspaces(
            {pid: DiscoveredWorkspaces(info, receipt) for pid, info in snapshots.items()}, receipt)

    def resolve(self, project_id, worktree_id=""):
        if not isinstance(worktree_id, str):
            raise AccessError("Invalid worktree identifier.")
        worktree_id = worktree_id or "main"
        snapshot = self.discover(project_id)
        entry = next((entry for entry in snapshot["worktrees"] if entry["id"] == worktree_id), None)
        if entry is None:
            raise AccessError("Worktree not discovered in the authorized repository.")
        if entry["state"] != "valid":
            raise AccessError(f"Worktree {entry['state']}: {entry['reason']}.")
        return entry

    def associate(self, cwd, snapshots=None):
        def result(state, reason, project_id=None, entry=None, history_birth=None, identity=None):
            value = {"state": state, "project_id": project_id,
                    "worktree_id": entry["id"] if entry else None,
                    "root": entry["root"] if entry else None,
                    "repository_id": entry["repository_id"] if entry else None, "reason": reason}
            if state == "matched" and self.history_store is not None:
                key = owner_key(entry["root"], identity, entry["repository_id"])
                current = self.history_store.locations.observe(entry["root"], history_birth, identity)
                windows = merge_windows((*self.history_windows.get(key, ()), *current))
                evidence = [LocationEvidence(key, history_birth, windows, self.history_store)]
                if path != Path(entry["root"]):
                    # A historical cwd beneath a continuing project may itself
                    # have been a link to a different project at that time.
                    child = persistent_identity(path)
                    birth = child["birthtime_ns"]
                    span = self.history_store.locations.observe(path, birth, child, within=entry["root"])
                    child_key = owner_key(path, child, ["cwd", key])
                    evidence.append(LocationEvidence(child_key, birth, span, self.history_store))
                value["history_windows"] = tuple(evidence)
            return value

        if not isinstance(cwd, (str, Path)) or not str(cwd):
            return result("pending", "working_directory_missing_from_metadata")
        snapshots = self.discover_all() if snapshots is None else snapshots
        if isinstance(snapshots, DiscoveredWorkspaces):
            snapshots.topology.require_complete()
        try:
            path = _directory(cwd)
        except (OSError, AccessError):
            return result("pending", "working_directory_missing_or_unverifiable")
        # Directory projects authorize their physical subtree, without requiring
        # Git or following linked worktrees outside it. The most specific project
        # owns a nested path; an unavailable child grant cannot fall back to its
        # parent. Equal roots remain ambiguous, including mixed scope modes.
        claims = [(project_id, snapshot, entry)
                  for project_id, snapshot in snapshots.items()
                  for entry in snapshot["worktrees"]
                  if path.is_relative_to(entry["root"])]
        if claims:
            depth = max(len(Path(entry["root"]).parts) for _, _, entry in claims)
            nearest = [(pid, snap, entry) for pid, snap, entry in claims
                       if len(Path(entry["root"]).parts) == depth]
            if any(snap["mode"] == "directory" for _, snap, _ in nearest):
                if len(nearest) != 1:
                    return result("ambiguous", "directory_is_configured_as_multiple_projects")
                project_id, _, entry = nearest[0]
                if entry["state"] != "valid":
                    return result("pending", "configured_directory_unavailable")
                try:
                    with ExitStack() as stack:
                        handles = _ProbeHandles(stack)
                        _, anchor = handles.open(entry["root"])
                        if [anchor.st_dev, anchor.st_ino] != entry.get("root_identity"):
                            return result("pending", "configured_directory_identity_changed")
                        handles.open(path)
                        handles.verify()
                except (OSError, AccessError) as error:
                    if isinstance(error, AccessError) and error.code == "source_cleanup_pending":
                        raise
                    return result("pending", "working_directory_unavailable_or_changed")
                registration = getattr(self._project(project_id), "registration_identity", None)
                return result("matched", "verified_configured_directory_subtree", project_id, entry,
                              registration["birthtime_ns"] if registration else None, registration)
        try:
            probe = _probe(path)
        except (OSError, AccessError) as error:
            if isinstance(error, AccessError) and error.code == "source_cleanup_pending":
                raise
            return result("pending", "working_directory_missing_or_repository_unverifiable")
        matches = []
        authorized_repository = False
        for project_id, snapshot in snapshots.items():
            if snapshot["mode"] != "repository" or not _pin_matches(snapshot["repository_id"], probe):
                continue
            # Pins of different versions can authorize the same common object.
            # Recheck the configured anchor, rather than grouping pin strings or
            # trusting a cached snapshot after its configured root was replaced.
            try:
                configured = _probe(self._project(project_id).root)
            except (OSError, AccessError) as error:
                if isinstance(error, AccessError) and error.code == "source_cleanup_pending":
                    raise
                continue
            if (not _pin_matches(snapshot["repository_id"], configured)
                    or configured["common"] != probe["common"]
                    or configured["common_identity"] != probe["common_identity"]):
                continue
            authorized_repository = True
            for entry in snapshot["worktrees"]:
                if entry["state"] == "valid" and str(probe["root"]) == entry["root"]:
                    try:
                        path.relative_to(entry["root"])
                    except ValueError:
                        continue
                    matches.append((project_id, entry))
        if len(matches) > 1:
            return result("ambiguous", "repository_is_configured_as_multiple_projects")
        if matches:
            project_id, entry = matches[0]
            return result("matched", "git_identity_and_registered_worktree", project_id, entry,
                          probe.get("history_birth_ns"), probe.get("history_root_identity"))
        if authorized_repository:
            return result("pending", "working_directory_not_in_valid_authorized_registration")
        return result("outside", "repository_is_not_authorized")
