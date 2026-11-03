"""Read-only Git identity and registered working-directory discovery.

Repository authorization is pinned to the common Git directory's canonical path
and persistent filesystem identity. Legacy pins remain exact current-device pins.
Only this module's fixed discovery commands are allowed; no repository scripts,
index refresh, checkout, worktree repair, or arbitrary Git methods are exposed.
"""

from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess

from .catalog import AccessError, _close_source_fd
from .fs_identity import persistent_identity_fd, validate_identity


GIT = "/usr/bin/git"
MAX_GIT_OUTPUT = 2 * 1024 * 1024


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":")).encode()).hexdigest()


def _git(root, operation):
    commands = {
        "probe": ["rev-parse", "--path-format=absolute", "--git-common-dir",
                  "--show-toplevel", "--absolute-git-dir"],
        "worktrees": ["worktree", "list", "--porcelain", "-z"],
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
            env=env, timeout=5, check=False,
        )
    except OSError:
        # Popen may fail while closing its temporary descriptors. Its public
        # exception cannot distinguish that from setup failure; do not refund
        # the export owner's auxiliary reservation on an unconfirmed outcome.
        raise AccessError('Repository process descriptor cleanup is unconfirmed.',
                          code='source_cleanup_pending') from None
    except subprocess.TimeoutExpired as exc:
        raise AccessError("Repository discovery unavailable or timed out.") from exc
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
        _, root_info = handles.open(top)
        return {"root": top, "common": common, "common_identity": identity,
                "root_runtime_identity": [root_info.st_dev, root_info.st_ino],
                "common_runtime_identity": [info.st_dev, info.st_ino],
                "repository_id": _pin_v2(common, identity),
                "legacy_repository_id": repository_pin_v1(common, info.st_dev, info.st_ino)}


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


class RepositoryRegistry:
    def __init__(self, projects):
        self.projects = projects

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
    def _entry(root, default, pin, record=None, forced_state=None, reason=None):
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
                    entry["root_identity"] = probe["root_runtime_identity"]
        except (OSError, RuntimeError, AccessError) as error:
            if isinstance(error, AccessError) and error.code == 'source_cleanup_pending':
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

    def discover(self, project_id):
        project = self._project(project_id)
        root = _clean_path(project.root)
        pin = getattr(project, "repository_id", None)
        if pin is None:
            entry = self._entry(root, True, None, forced_state="valid", reason="configured_directory")
            try:
                _directory(root)
            except FileNotFoundError:
                entry.update(state="missing", reason="working_directory_missing")
            except (OSError, AccessError):
                entry.update(state="unavailable", reason="working_directory_unavailable")
            return self._snapshot(project, None, "directory", [entry])
        try:
            origin = _probe(root)
            if not _pin_matches(pin, origin) or origin["root"] != root:
                entry = self._entry(root, True, pin, forced_state="identity_mismatch",
                                    reason="configured_repository_pin_changed")
                return self._snapshot(project, pin, "repository", [entry])
            records = _records(_git(root, "worktrees"))
        except FileNotFoundError:
            entry = self._entry(root, True, pin, forced_state="missing", reason="configured_directory_missing")
            return self._snapshot(project, pin, "repository", [entry])
        except (OSError, AccessError) as error:
            if isinstance(error, AccessError) and error.code == 'source_cleanup_pending':
                raise
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
            entries.append(self._entry(path, path == root, pin, record))
        if root not in roots:
            entries.append(self._entry(root, True, pin, forced_state="identity_mismatch",
                                       reason="configured_directory_not_registered"))
            # A forged/default pointer cannot be used as a gateway to other roots.
            entries = [entry for entry in entries if entry["is_default"]]
        entries.sort(key=lambda entry: (not entry["is_default"], entry["root"]))
        return self._snapshot(project, pin, "repository", entries)

    def discover_all(self):
        return {project_id: self.discover(project_id) for project_id in self.projects}

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
        def result(state, reason, project_id=None, entry=None):
            return {"state": state, "project_id": project_id,
                    "worktree_id": entry["id"] if entry else None,
                    "root": entry["root"] if entry else None,
                    "repository_id": entry["repository_id"] if entry else None, "reason": reason}

        if not isinstance(cwd, (str, Path)) or not str(cwd):
            return result("pending", "working_directory_missing_from_metadata")
        try:
            path = _directory(cwd)
            probe = _probe(path)
        except (OSError, AccessError) as error:
            if isinstance(error, AccessError) and error.code == "source_cleanup_pending":
                raise
            return result("pending", "working_directory_missing_or_repository_unverifiable")
        snapshots = self.discover_all() if snapshots is None else snapshots
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
            return result("matched", "git_identity_and_registered_worktree", project_id, entry)
        if authorized_repository:
            return result("pending", "working_directory_not_in_valid_authorized_registration")
        return result("outside", "repository_is_not_authorized")
