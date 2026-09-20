"""Read-only Git identity and registered working-directory discovery.

Repository authorization is pinned to the common Git directory's path and inode.
Only this module's fixed discovery commands are allowed; no repository scripts,
index refresh, checkout, worktree repair, or arbitrary Git methods are exposed.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess

from .catalog import AccessError


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
    except (OSError, subprocess.TimeoutExpired) as exc:
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


def _probe(root):
    root = _directory(root)
    fields = _git(root, "probe").rstrip("\n").split("\n")
    if len(fields) != 3:
        raise AccessError("Unsupported repository metadata format.")
    common, top, gitdir = (_directory(value) for value in fields)
    dotgit = top / ".git"
    if dotgit.is_symlink():
        raise AccessError("Symbolic-link Git metadata is not accepted.")
    if gitdir != common:
        # A copied/forged .git pointer is not a registration. Validate the admin
        # directory's backlink without exposing any raw metadata to callers.
        try:
            fd = os.open(gitdir / "gitdir", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                    raise AccessError("Invalid worktree registration backlink.")
                backlink = os.fsdecode(os.read(fd, 4097)).rstrip("\n")
            finally:
                os.close(fd)
            if _clean_path(backlink) != dotgit:
                raise AccessError("Worktree registration backlink does not match.")
        except OSError as exc:
            raise AccessError("Worktree registration backlink is unavailable.") from exc
    elif dotgit != common or not dotgit.is_dir():
        raise AccessError("Working directory does not match its Git metadata.")
    info = common.stat()
    return {"root": top, "repository_id": "git-" + _digest(
        [str(common), info.st_dev, info.st_ino]), "common": common}


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
                if probe["repository_id"] != pin or probe["root"] != root or record.get("bare"):
                    entry.update(state="identity_mismatch", reason="repository_or_registration_changed")
        except (OSError, RuntimeError, AccessError):
            entry.update(state="unavailable", reason="working_directory_or_git_metadata_unavailable")
        return entry

    @staticmethod
    def _snapshot(project, pin, mode, entries):
        scope = []
        for entry in entries:
            inode = None
            if entry["state"] == "valid":
                try:
                    info = Path(entry["root"]).stat()
                    inode = [info.st_dev, info.st_ino]
                    entry["root_identity"] = inode
                except OSError:
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
            if origin["repository_id"] != pin or origin["root"] != root:
                entry = self._entry(root, True, pin, forced_state="identity_mismatch",
                                    reason="configured_repository_pin_changed")
                return self._snapshot(project, pin, "repository", [entry])
            records = _records(_git(root, "worktrees"))
        except FileNotFoundError:
            entry = self._entry(root, True, pin, forced_state="missing", reason="configured_directory_missing")
            return self._snapshot(project, pin, "repository", [entry])
        except (OSError, AccessError):
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
        except (OSError, AccessError):
            return result("pending", "working_directory_missing_or_repository_unverifiable")
        snapshots = self.discover_all() if snapshots is None else snapshots
        matches = []
        for project_id, snapshot in snapshots.items():
            if snapshot["mode"] != "repository" or snapshot["repository_id"] != probe["repository_id"]:
                continue
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
        if any(snapshot["repository_id"] == probe["repository_id"] for snapshot in snapshots.values()):
            return result("pending", "working_directory_not_in_valid_authorized_registration")
        return result("outside", "repository_is_not_authorized")
