"""Published scopes for the independent Agent file reader.

The legacy project file is the only authority for project membership. The Agent
record binds its exact bytes and proves which effective roots were reviewed.
The protected sibling watermark guards state-directory backup replays. Restoring
the entire trusted control root, including its watermark, is an operator action
that requires keeping the listener down and explicitly checking revocations.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from types import MappingProxyType
import unicodedata

from .agent_history_generation import _directory, _read_at, _stamp, _unique, _write_new, canonical_bytes
from .catalog import AccessError, Catalog, Project
from .fs_identity import persistent_identity_fd, validate_identity
from .workspaces import (RepositoryRegistry, _ProbeHandles, _clean_path, _open_path,
                         _pin_v2, repository_pin_v1)

MAX_DOCUMENT_BYTES = 512 * 1024
MAX_TRANSACTION_BYTES = 4 * MAX_DOCUMENT_BYTES
MAX_PROJECTS = 128
MAX_ROOTS = 512
MAX_AGENTS = 128
MAX_RETIRED = 4096
LOCK_NAME = "agent-access.lock"
ACTIVE_NAME = "active.json"
WATERMARK_NAME = "watermark.json"
PENDING_NAME = "pending.json"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACTIVATION = re.compile(r"[0-9a-f]{32}\Z")
_ISSUER = re.compile(r"https://[a-z0-9-]+\.cloudflareaccess\.com\Z")
_INSTANCE = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
_WORKTREE_ID = re.compile(r"(?:main|wt-[0-9a-f]{20})\Z")
_REPOSITORY_ID = re.compile(r"git-(?:v2-)?[0-9a-f]{64}\Z")


def denied(code="agent_file_policy_invalid"):
    return AccessError("Agent file access policy is unavailable, changed, or invalid.", code=code)


def digest(raw):
    return sha256(raw).hexdigest()


def decode(raw):
    return json.loads(raw, object_pairs_hook=_unique)


def _match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value)


def _path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise denied()
    return path


def legacy_catalog(document):
    """Validate the existing v1 project schema, including an explicit empty set."""
    rows = _project_rows(document)
    if not rows:
        return Catalog([], _allow_empty=True)
    for row in rows:
        root = _path(Path(row["root"]).expanduser())
        if root != root.resolve(strict=True) or not root.is_dir():
            raise denied("agent_file_root_changed")
    return Catalog._from_document(document)


def _project_rows(document):
    if not isinstance(document, dict) or set(document) != {"projects"}:
        raise denied()
    rows = document["projects"]
    if not isinstance(rows, list) or len(rows) > MAX_PROJECTS:
        raise denied()
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not _match(_INSTANCE, row.get("id"))
                or row["id"] in seen or not isinstance(row.get("root"), str)):
            raise denied()
        seen.add(row["id"])
    return rows


def validate_agents(agents):
    if not isinstance(agents, list) or len(agents) > MAX_AGENTS:
        raise denied()
    ids, bindings = set(), set()
    for agent in agents:
        if (not isinstance(agent, dict)
                or set(agent) != {"id", "enabled", "issuer", "audience", "client_id"}
                or type(agent["enabled"]) is not bool or not _match(_INSTANCE, agent["id"])
                or not _match(_ISSUER, agent["issuer"]) or not _match(_HEX, agent["audience"])
                or not _match(_CLIENT_ID, agent["client_id"])):
            raise denied()
        key = credential_binding(agent)
        if agent["id"] in ids or key in bindings:
            raise denied()
        ids.add(agent["id"])
        bindings.add(key)
    return [dict(agent) for agent in sorted(agents, key=lambda item: item["id"])]


def credential_binding(agent):
    return agent["issuer"], agent["audience"], agent["client_id"]


def credential_digest(agent):
    return digest(canonical_bytes(credential_binding(agent)))


@dataclass(frozen=True)
class PublishedRoot:
    path: Path
    repository_id: str | None
    identity: MappingProxyType


def _path_key(path):
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _physical(identity):
    return identity["volume_uuid"], identity["file_id"], identity["birthtime_ns"]


def _validate_root_records(records, projects=None):
    if not isinstance(records, list) or len(records) > MAX_ROOTS:
        raise denied()
    roots = {}
    for row in records:
        if (not isinstance(row, dict) or set(row) != {"project", "worktree", "path", "repository_id", "identity"}
                or not _match(_INSTANCE, row["project"]) or not isinstance(row["path"], str)
                or not _match(_WORKTREE_ID, row["worktree"])
                or (row["repository_id"] is not None
                    and not _match(_REPOSITORY_ID, row["repository_id"]))):
            raise denied()
        key = row["project"], row["worktree"]
        if key in roots:
            raise denied()
        roots[key] = PublishedRoot(_path(row["path"]), row["repository_id"],
                                   MappingProxyType(validate_identity(row["identity"])))
    if projects is not None:
        configured = {row["id"]: row for row in _project_rows(projects)}
        if set(configured) != {key[0] for key in roots}:
            raise denied()
        for project_id, project in configured.items():
            default = roots.get((project_id, "main"))
            if default is None or default.path != _path(Path(project["root"]).expanduser()):
                raise denied()
        for (project_id, worktree_id), root in roots.items():
            pin = configured[project_id].get("repository_id")
            if root.repository_id != pin or (pin is None and worktree_id != "main"):
                raise denied()
    paths, identities, repositories = {}, {}, {}
    ordered = sorted((_path_key(root.path), key, root) for key, root in roots.items())
    for path, (project_id, _), root in ordered:
        identity = _physical(root.identity)
        if (any(paths.get(path[:index], project_id) != project_id for index in range(1, len(path) + 1))
                or identities.get(identity, project_id) != project_id
                or (root.repository_id is not None and repositories.get(root.repository_id, project_id) != project_id)):
            raise denied("agent_file_root_conflict")
        paths[path] = project_id
        identities[identity] = project_id
        if root.repository_id is not None:
            repositories[root.repository_id] = project_id
    return roots


def collect_root_records(document, *, check_path=None):
    """Operator-side discovery. Only verified current roots can be published."""
    catalog = legacy_catalog(document)
    snapshots = catalog.repositories.discover_all()
    records = []
    for project_id, scope in snapshots.items():
        if not any(row["is_default"] and row["state"] == "valid" for row in scope["worktrees"]):
            raise denied("agent_file_root_changed")
        for row in scope["worktrees"]:
            if row["state"] != "valid":
                continue
            path = Path(row["root"])
            if check_path is not None:
                check_path(path)
            identity = _observed_identity(path, row["root_identity"])
            if identity is None:
                raise denied("agent_file_root_changed")
            records.append({"project": project_id, "worktree": row["id"], "path": str(path),
                            "repository_id": row["repository_id"], "identity": identity})
            if len(records) > MAX_ROOTS:
                raise denied()
    records.sort(key=lambda row: (row["project"], row["worktree"]))
    _validate_root_records(records, document)
    return records


def _observed_identity(path, runtime_identity):
    try:
        fd, info = _open_path(path, directory=True)
        try:
            if [info.st_dev, info.st_ino] != list(runtime_identity):
                return None
            return persistent_identity_fd(fd)
        finally:
            os.close(fd)
    except (OSError, AccessError):
        return None


@dataclass(frozen=True)
class AgentFileSnapshot:
    revision: str
    _projects: dict = field(repr=False)
    principals: MappingProxyType = field(repr=False)
    roots: MappingProxyType = field(repr=False)

    @property
    def projects(self):
        return deepcopy(self._projects)


def _project_map(snapshot):
    for row in snapshot._projects["projects"]:
        proof = snapshot.roots[(row["id"], "main")]
        yield Project(row["id"], row["name"], proof.path, tuple(row.get("allow_hidden", [])),
                      tuple(row.get("exclude", [])), repository_id=proof.repository_id,
                      directory_identity=(dict(proof.identity) if proof.repository_id is None else None))


class _PublishedRepositoryRegistry(RepositoryRegistry):
    def __init__(self, projects, approved, check_path=None):
        super().__init__(projects)
        self._approved = approved
        self._check_path = check_path

    def discover(self, project_id):
        result = super().discover(project_id)
        included = []
        for row in result["worktrees"]:
            proof = self._approved.get((project_id, row["id"]))
            if (proof is None or row["state"] != "valid" or row["root"] != str(proof.path)
                    or row["repository_id"] != proof.repository_id
                    or _observed_identity(proof.path, row["root_identity"]) != proof.identity):
                continue
            if self._check_path is not None and not self._check_path(proof.path):
                continue
            included.append(row)
        if not any(row["is_default"] for row in included):
            included = []
        scope = [[row["id"], row["root"], row["repository_id"], row["root_identity"]] for row in included]
        return {**result, "worktrees": included, "fingerprint": digest(canonical_bytes(
            [project_id, result["repository_id"], scope]))}


class _AgentFileCatalog(Catalog):
    def list_projects(self):
        with self._private_read_guard():
            result = super().list_projects()
            result["projects"] = [entry for entry in result["projects"]
                                  if self.repositories.discover(entry["id"])["worktrees"]]
            return result


def catalog_for(snapshot, *, private_registry=None, agent_history_policy=None):
    """Create a request-local Catalog with no policy auto-refresh or write policy."""
    catalog = _AgentFileCatalog([], private_registry=private_registry, _allow_empty=True)
    if agent_history_policy is not None:
        catalog.set_agent_history_policy(agent_history_policy)
    catalog.projects = {project.id: project for project in _project_map(snapshot)}
    catalog.repositories = _PublishedRepositoryRegistry(catalog.projects, snapshot.roots,
                                                        catalog._visible_private_path)
    return catalog


def verify_root_scope(snapshot, project_id=None, worktree_id=None, *,
                      private_registry=None, agent_history_policy=None):
    """Return a stable scope digest to compare at preparation and at commit."""
    catalog = catalog_for(snapshot, private_registry=private_registry, agent_history_policy=agent_history_policy)
    with catalog._private_read_guard():
        if project_id is None:
            return digest(canonical_bytes(catalog.list_projects()["projects"]))
        if project_id not in catalog.projects:
            raise denied("unknown_project")
        scope = catalog.repositories.discover(project_id)
        available = scope["worktrees"]
        if not available or (worktree_id is not None
                             and not any(row["id"] == (worktree_id or "main") for row in available)):
            raise denied("agent_file_root_changed")
        return scope["fingerprint"]


def _deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise denied("agent_file_policy_busy")


def _registration_stamp(common, deadline):
    """Observe the namespace that Git uses to discover external worktrees."""
    registry = common / "worktrees"
    try:
        fd, info = _open_path(registry, directory=True)
    except FileNotFoundError:
        return None
    try:
        entries = []
        with os.scandir(fd) as cursor:
            for entry in cursor:
                _deadline(deadline)
                if len(entries) >= MAX_ROOTS:
                    raise denied("agent_file_root_changed")
                status = entry.stat(follow_symlinks=False)
                stamps = [entry.name, _stamp(status)]
                if stat.S_ISDIR(status.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if _stamp(os.fstat(child)) != _stamp(status):
                            raise denied("agent_file_root_changed")
                        for marker in ("gitdir", "commondir", "HEAD"):
                            try:
                                entry_stat = os.stat(marker, dir_fd=child, follow_symlinks=False)
                            except FileNotFoundError:
                                stamps.append(None)
                            else:
                                stamps.append(_stamp(entry_stat))
                    finally:
                        os.close(child)
                entries.append(stamps)
        if (_stamp(os.fstat(fd)) != _stamp(info)
                or _stamp(registry.stat(follow_symlinks=False)) != _stamp(info)):
            raise denied("agent_file_root_changed")
        return _stamp(info), sorted(entries)
    finally:
        os.close(fd)


def _delivery_root_stamp(proof, *, include_registrations=False, deadline=None):
    """Verify one authorized root and its linked-worktree anchors without Git."""
    try:
        with ExitStack() as stack:
            handles = _ProbeHandles(stack)
            root_fd, _ = handles.open(proof.path)
            root_identity = persistent_identity_fd(root_fd)
            if root_identity != proof.identity:
                raise denied("agent_file_root_changed")
            identity_stamp = [root_identity]
            if proof.repository_id is not None:
                dotgit = proof.path / ".git"
                if stat.S_ISDIR(dotgit.lstat().st_mode):
                    gitdir = common = dotgit
                else:
                    git_pointer = handles.read(dotgit)
                    if not git_pointer.startswith("gitdir: ") or "\n" in git_pointer:
                        raise denied("agent_file_root_changed")
                    location = Path(git_pointer[len("gitdir: "):])
                    gitdir = _clean_path(location if location.is_absolute() else proof.path / location)
                    handles.open(gitdir)
                    if _clean_path(handles.read(gitdir / "gitdir")) != dotgit:
                        raise denied("agent_file_root_changed")
                    location = Path(handles.read(gitdir / "commondir"))
                    common = _clean_path(location if location.is_absolute() else gitdir / location)
                    if gitdir.parent != common / "worktrees":
                        raise denied("agent_file_root_changed")
                common_fd, common_stat = handles.open(common)
                common_identity = persistent_identity_fd(common_fd)
                if proof.repository_id.startswith("git-v2-"):
                    pin = _pin_v2(common, common_identity)
                else:
                    pin = repository_pin_v1(common, common_stat.st_dev, common_stat.st_ino)
                if pin != proof.repository_id:
                    raise denied("agent_file_root_changed")
                identity_stamp.extend([str(gitdir), str(common), common_identity, pin])
                if include_registrations:
                    identity_stamp.append(_registration_stamp(common, deadline))
            handles.verify()
            _deadline(deadline)
            return digest(canonical_bytes(identity_stamp))
    except AccessError as error:
        if error.code == "agent_file_policy_busy":
            raise
        raise denied("agent_file_root_changed") from None
    except (OSError, RuntimeError, ValueError, TypeError):
        raise denied("agent_file_root_changed") from None


def capture_roots(snapshot, operation, project_id, result):
    """Bind a successful tool result to the roots it actually exposed."""
    if operation == "list_projects":
        keys = {(row["id"], "main") for row in result["projects"]}
    else:
        keys = {(project_id, "main")}
        if operation == "list_worktrees":
            keys.update((project_id, row["id"]) for row in result["worktrees"])
        else:
            keys.add((project_id, result["working_directory"]["id"]))
    return tuple((key, _delivery_root_stamp(snapshot.roots[key])) for key in sorted(keys))


def verify_delivery_roots(snapshot, receipt, *, deadline=None):
    for key, previous in receipt:
        _deadline(deadline)
        proof = snapshot.roots.get(key)
        if proof is None or _delivery_root_stamp(proof, deadline=deadline) != previous:
            raise denied("agent_file_root_changed")


def capture_publication_roots(records, projects):
    """Capture physical anchors before doing repository-wide Git discovery."""
    roots = _validate_root_records(records, projects)
    return tuple((proof, key[1] == "main", _delivery_root_stamp(proof, include_registrations=key[1] == "main"))
                 for key, proof in sorted(roots.items()))


def verify_publication_roots(receipt, *, deadline=None):
    """Check the same registered namespace and root identities without running Git."""
    for proof, include_registrations, previous in receipt:
        _deadline(deadline)
        if _delivery_root_stamp(proof, include_registrations=include_registrations, deadline=deadline) != previous:
            raise denied("agent_file_root_changed")


def validate_record(record, projects_path, projects=None):
    if (not isinstance(record, dict) or set(record) != {"version", "sequence", "activation_id",
                                                        "projects", "agents", "roots", "roots_sha256",
                                                        "retired_credentials", "approval_sha256"}
            or type(record["version"]) is not int or record["version"] != 1
            or type(record["sequence"]) is not int or not 1 <= record["sequence"] < 2**63
            or not _match(_ACTIVATION, record["activation_id"])
            or (record["approval_sha256"] is not None and not _match(_HEX, record["approval_sha256"]))):
        raise denied()
    reference = record["projects"]
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or reference["path"] != str(projects_path) or not _match(_HEX, reference["sha256"])
            or record["roots_sha256"] != digest(canonical_bytes(record["roots"]))):
        raise denied()
    agents = validate_agents(record["agents"])
    retired = record["retired_credentials"]
    if (not isinstance(retired, list) or len(retired) > MAX_RETIRED or any(not _match(_HEX, v) for v in retired)
            or sorted(set(retired)) != retired
            or any(agent["enabled"] and credential_digest(agent) in retired for agent in agents)):
        raise denied("agent_file_credential_retired")
    roots = _validate_root_records(record["roots"], projects)
    return MappingProxyType({credential_binding(agent): agent["id"] for agent in agents if agent["enabled"]}), roots


def make_record(projects_path, project_digest, records, agents, sequence, *, retired=(), approval=None):
    return {"version": 1, "sequence": sequence, "activation_id": secrets.token_hex(16),
            "projects": {"path": str(projects_path), "sha256": project_digest},
            "agents": validate_agents(agents), "roots": records,
            "roots_sha256": digest(canonical_bytes(records)), "retired_credentials": list(retired),
            "approval_sha256": approval}


def watermark(record, raw, project_stamp):
    return {"sequence": record["sequence"], "activation_id": record["activation_id"],
            "record_sha256": digest(raw), "project_stamp": project_stamp}


def watermark_anchor_name(state_directory):
    return "." + Path(state_directory).name + ".agent-file-watermark.json"


def read_projects(directory, name):
    before = _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))
    raw = _read_at(directory, name, MAX_DOCUMENT_BYTES)
    after = _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))
    if before != after:
        raise denied("agent_file_policy_mismatch")
    return raw, list(after)


def optional_read(directory, name, limit=MAX_DOCUMENT_BYTES):
    try:
        return _read_at(directory, name, limit)
    except FileNotFoundError:
        return None


def atomic_write(directory, name, raw, maximum=MAX_DOCUMENT_BYTES, *, before_replace=None):
    if len(raw) > maximum:
        raise denied()
    temporary = ".agent-file-" + secrets.token_hex(12)
    try:
        _write_new(directory, temporary, raw)
        if before_replace is not None:
            before_replace()
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


class AgentFilePolicy:
    """Shared lock for read admission and response commit. Startup repairs nothing."""

    def __init__(self, projects_path, state_directory, *, lock_timeout=0.5):
        try:
            self.projects_path = _path(projects_path)
            self.state_directory = _path(state_directory)
            if (self.projects_path.is_relative_to(self.state_directory)
                    or self.projects_path.resolve() != self.projects_path
                    or not 0 < lock_timeout <= 30):
                raise denied()
            self.lock_timeout = lock_timeout
            self._state_identity = self._identity(self.state_directory)
            self._anchor_parent_identity = self._identity(self.state_directory.parent)
            self.anchor_name = watermark_anchor_name(self.state_directory)
            self._projects_parent_identity = self._identity(self.projects_path.parent)
            state_fd = _directory(self.state_directory)
            try:
                info = os.stat(LOCK_NAME, dir_fd=state_fd, follow_symlinks=False)
                self._lock_identity = (info.st_dev, info.st_ino)
            finally:
                os.close(state_fd)
        except (OSError, RuntimeError, TypeError, ValueError):
            raise denied() from None

    @staticmethod
    def _identity(path):
        descriptor = _directory(path)
        try:
            info = os.fstat(descriptor)
            return info.st_dev, info.st_ino
        finally:
            os.close(descriptor)

    def _verify_open(self, descriptor, identity):
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != identity:
            raise denied()

    @contextmanager
    def locked(self, *, exclusive=False, timeout=None):
        """Yield pinned state and project parent descriptors under a bounded lock."""
        try:
            with ExitStack() as stack:
                state_fd = _directory(self.state_directory)
                stack.callback(os.close, state_fd)
                project_fd = _directory(self.projects_path.parent)
                stack.callback(os.close, project_fd)
                self._verify_open(state_fd, self._state_identity)
                self._verify_open(project_fd, self._projects_parent_identity)
                lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=state_fd)
                stack.callback(os.close, lock_fd)
                self._verify_open(lock_fd, self._lock_identity)
                info = os.fstat(lock_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise denied()
                deadline = time.monotonic() + min(self.lock_timeout, timeout if timeout is not None else self.lock_timeout)
                mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                while True:
                    try:
                        fcntl.flock(lock_fd, mode | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise denied("agent_file_policy_busy") from None
                        time.sleep(min(0.01, remaining))
                self._verify_lock(state_fd, info)
                yield state_fd, project_fd
                self._verify_lock(state_fd, info)
        except AccessError as error:
            if error.code == "agent_policy_invalid":
                raise denied() from None
            raise
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise denied() from None

    def _verify_lock(self, state_fd, info):
        if (_stamp(os.stat(LOCK_NAME, dir_fd=state_fd, follow_symlinks=False)) != _stamp(info)
                or self._identity(self.state_directory) != self._state_identity
                or self._identity(self.state_directory.parent) != self._anchor_parent_identity
                or self._identity(self.projects_path.parent) != self._projects_parent_identity):
            raise denied()

    @contextmanager
    def anchor_directory(self):
        descriptor = _directory(self.state_directory.parent)
        try:
            self._verify_open(descriptor, self._anchor_parent_identity)
            yield descriptor
            if self._identity(self.state_directory.parent) != self._anchor_parent_identity:
                raise denied()
        finally:
            os.close(descriptor)

    def current_record(self, state_fd, project_fd):
        if optional_read(state_fd, PENDING_NAME, MAX_TRANSACTION_BYTES) is not None:
            raise denied("agent_file_policy_pending")
        record, raw, mark = self.read_committed(state_fd)
        project_raw, stamp = read_projects(project_fd, self.projects_path.name)
        projects = decode(project_raw)
        validate_record(record, self.projects_path, projects)
        if record["projects"]["sha256"] != digest(project_raw) or mark["project_stamp"] != stamp:
            raise denied("agent_file_policy_mismatch")
        return record, raw, projects, project_raw

    def read_committed(self, state_fd):
        raw = _read_at(state_fd, ACTIVE_NAME, MAX_DOCUMENT_BYTES)
        record = decode(raw)
        validate_record(record, self.projects_path)
        mark = decode(_read_at(state_fd, WATERMARK_NAME, 2048))
        project_stamp = mark.get("project_stamp") if isinstance(mark, dict) else None
        if (not isinstance(project_stamp, list) or len(project_stamp) != 5
                or any(type(value) is not int for value in project_stamp)
                or mark != watermark(record, raw, project_stamp)):
            raise denied("agent_file_policy_mismatch")
        with self.anchor_directory() as anchor_fd:
            anchor = decode(_read_at(anchor_fd, self.anchor_name, 2048))
        if mark != anchor:
            raise denied("agent_file_policy_mismatch")
        return record, raw, mark

    catalog_for = staticmethod(catalog_for)
    verify_root_scope = staticmethod(verify_root_scope)
    capture_roots = staticmethod(capture_roots)
    verify_delivery_roots = staticmethod(verify_delivery_roots)

    def _snapshot(self, state_fd, project_fd):
        record, _, projects, _ = self.current_record(state_fd, project_fd)
        principals, roots = validate_record(record, self.projects_path, projects)
        return AgentFileSnapshot(record["activation_id"], projects, principals, MappingProxyType(roots))

    def snapshot(self):
        with self.locked() as (state_fd, project_fd):
            return self._snapshot(state_fd, project_fd)

    @contextmanager
    def commit_guard(self, revision, *, timeout=None):
        with self.locked(timeout=timeout) as (state_fd, project_fd):
            snapshot = self._snapshot(state_fd, project_fd)
            if snapshot.revision != revision:
                raise denied("agent_file_policy_changed")
            yield snapshot


def initialize_agent_file_policy(projects_path, state_directory, *, check_path=None):
    """Explicit bootstrap with no enabled Agent, preserving the project file."""
    path = _path(projects_path)
    target = _path(state_directory)
    if path.is_relative_to(target) or path.resolve() != path:
        raise denied()
    with ExitStack() as stack:
        parent = _directory(path.parent)
        stack.callback(os.close, parent)
        anchor_fd = _directory(target.parent)
        stack.callback(os.close, anchor_fd)
        anchor_name = watermark_anchor_name(target)
        try:
            os.stat(anchor_name, dir_fd=anchor_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise denied("agent_file_policy_mismatch")
        raw, stamp = read_projects(parent, path.name)
        records = collect_root_records(decode(raw), check_path=check_path)
        os.mkdir(target.name, 0o700, dir_fd=anchor_fd)
        state_fd = _directory(target)
        stack.callback(os.close, state_fd)
        record = make_record(path, digest(raw), records, [], 1)
        encoded = canonical_bytes(record)
        _write_new(state_fd, LOCK_NAME, b"")
        atomic_write(state_fd, ACTIVE_NAME, encoded)
        mark = canonical_bytes(watermark(record, encoded, stamp))
        atomic_write(state_fd, WATERMARK_NAME, mark, 2048)
        _write_new(anchor_fd, anchor_name, mark)
        os.fsync(anchor_fd)
    return AgentFilePolicy(path, target)
