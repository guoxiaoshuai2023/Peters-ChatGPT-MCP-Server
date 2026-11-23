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
import time
from types import MappingProxyType

from .catalog import AccessError
from .fs_identity import persistent_identity, validate_identity
from .history_location import CHECKPOINT_SECONDS, LocationWitnesses, git_metadata_locations, merge_windows, owner_key

MAX_GENERATION_BYTES = 512 * 1024
MAX_POINTER_BYTES = 64 * 1024
_READ_LOCK_SECONDS = 4.0
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ACTIVATION = re.compile(r"[0-9a-f]{32}")
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


def _replace(directory, name, raw):
    temporary = ".publish-" + secrets.token_hex(12)
    try:
        _write_new(directory, temporary, raw)
        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _open_lock(directory, name):
    fd = os.open(name, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise _invalid()
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _acquire(fd, action, deadline):
    if deadline is None:
        fcntl.flock(fd, action)
        return
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AccessError("The policy commit deadline expired.", code="restart_required")
        try:
            fcntl.flock(fd, action | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(min(0.005, remaining))


class GenerationSnapshot(tuple):
    """Preserve the document/digest interface while carrying persisted project grants."""

    def __new__(cls, document, digest, project_tokens, project_identities, retained_sources, root_history):
        snapshot = super().__new__(cls, (document, digest))
        snapshot.project_tokens = MappingProxyType(project_tokens)
        snapshot.project_identities = MappingProxyType(project_identities)
        snapshot.retained_sources = tuple(retained_sources)
        snapshot.root_history = MappingProxyType({key: tuple(tuple(window) for window in value)
                                                  for key, value in root_history.items()})
        return snapshot

    def __reduce__(self):
        return type(self), (self[0], self[1], dict(self.project_tokens), dict(self.project_identities),
                            self.retained_sources, dict(self.root_history))


def _root_history(previous, projects, identities, witnesses, worktrees):
    # Keep closed occupation intervals for each physical project even when
    # its name is subsequently granted to a different directory or project ID.
    history = dict(previous)
    locations = [(row["root"], row.get("repository_id"), identities[row["id"]]) for row in projects]
    for root, repository, identity in (*locations, *worktrees):
        key = owner_key(root, identity, repository)
        try:
            windows = witnesses.observe(root, identity["birthtime_ns"], identity)
        except AccessError:
            continue
        combined = merge_windows((*history.get(key, ()), *windows))
        if combined:
            history[key] = combined
    return history


def _registered_git_probes(project):
    from .catalog import Catalog
    from .workspaces import repository_probe

    if project.get("repository_id"):
        registry = Catalog._from_document({"projects": [project]}, unified=True).repositories
        for entry in registry.discover(project["id"])["worktrees"]:
            if entry["state"] == "valid":
                try:
                    proof = repository_probe(entry["root"])
                except (AccessError, OSError) as error:
                    if getattr(error, "code", None) == "source_cleanup_pending":
                        raise
                    continue
                if project["repository_id"] in (proof["repository_id"], proof["legacy_repository_id"]):
                    yield proof, entry["is_default"]


def _valid_windows(windows):
    return (isinstance(windows, list) and bool(windows)
            and all(isinstance(w, list) and len(w) == 2 and all(type(v) is int for v in w)
                    and 0 < w[0] <= w[1] < 2 ** 63 for w in windows)
            and tuple(map(tuple, windows)) == merge_windows(windows))


def _covers(windows, span):
    start, end = span
    return any(lo <= start <= end <= hi for lo, hi in windows)


def _recent_extension(saved, retained):
    return (len(saved) == len(retained) and bool(saved) and saved[:-1] == retained[:-1]
            and saved[-1][0] == retained[-1][0]
            and 0 <= retained[-1][1] - saved[-1][1] < CHECKPOINT_SECONDS * 1_000_000_000)


def _project_key(project):
    from .candidates import DEFAULT_DIRECTORY

    return (
        project["root"], project.get("repository_id"), project.get("directory_identity"),
        tuple(sorted(set(project.get("exclude", ())))),
        tuple(sorted(set(project.get("allow_hidden", ())))),
        project.get("candidate_directory") or DEFAULT_DIRECTORY,
    )



def _retired_sources(current, document):
    if current is None:
        return []
    live = {canonical_bytes([row["root"], row["root_identity"]]) for row in document["sources"].values()}
    retired = {canonical_bytes(row) for row in current.retained_sources}
    retired.update(canonical_bytes([row["root"], row["root_identity"]]) for row in current[0]["sources"].values())
    return [json.loads(row) for row in sorted(retired - live)]


class GenerationStore:
    """Opening a store never creates or repairs operator-owned state."""

    def __init__(self, path):
        self.path = Path(path)
        self.locations = LocationWitnesses()
        self.anchor_path = self.path.with_name("." + self.path.name + ".authorization-anchor.json")
        try:
            parent = _directory(self.path.parent)
            try:
                info = os.fstat(parent)
                self.parent_identity = (info.st_dev, info.st_ino)
            finally:
                os.close(parent)
            descriptor = _directory(self.path)
            try:
                info = os.fstat(descriptor)
                self.identity = (info.st_dev, info.st_ino)
            finally:
                os.close(descriptor)
        except (OSError, ValueError):
            raise _invalid() from None

    @contextmanager
    def _parent(self):
        parent = _directory(self.path.parent)
        try:
            info = os.fstat(parent)
            if (info.st_dev, info.st_ino) != self.parent_identity:
                raise _invalid()
            yield parent
        finally:
            os.close(parent)

    def _decode(self, directory, pointer_raw):
        pointer = json.loads(pointer_raw, object_pairs_hook=_unique)
        if (not isinstance(pointer, dict)
                or set(pointer) - {"root_history"} != {"version", "sha256", "activation_id", "project_tokens",
                                                       "project_identities", "retained_sources"}
                or type(pointer["version"]) is not int or pointer["version"] != 2
                or not isinstance(pointer["sha256"], str) or not _DIGEST.fullmatch(pointer["sha256"])
                or not isinstance(pointer["activation_id"], str)
                or not _ACTIVATION.fullmatch(pointer["activation_id"])
                or not isinstance(pointer["project_tokens"], dict)
                or not isinstance(pointer["project_identities"], dict)
                or pointer["project_tokens"].keys() != pointer["project_identities"].keys()
                or any(not isinstance(token, str) or not _ACTIVATION.fullmatch(token)
                       for token in pointer["project_tokens"].values())
                or canonical_bytes(pointer) != pointer_raw):
            raise _invalid()
        for identity in pointer["project_identities"].values():
            validate_identity(identity)
        retained = pointer["retained_sources"]
        if not isinstance(retained, list) or len(retained) > 256:
            raise _invalid()
        for entry in retained:
            if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str):
                raise _invalid()
            root = Path(entry[0])
            if not root.is_absolute() or root == Path("/") or ".." in root.parts:
                raise _invalid()
            validate_identity(entry[1])
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
        projects = document.get("projects")
        if (not isinstance(projects, list) or any(not isinstance(row, dict)
                or not isinstance(row.get("id"), str) for row in projects)
                or set(pointer["project_tokens"]) != {row["id"] for row in projects}
                or len(projects) != len(pointer["project_tokens"])):
            raise _invalid()
        if any(row.get("directory_identity") is not None
               and row["directory_identity"] != pointer["project_identities"][row["id"]] for row in projects):
            raise _invalid()
        identities = pointer["project_identities"]
        # Earlier v2 pointers stored no attested historical intervals.
        roots = pointer.get("root_history", {})
        if not isinstance(roots, dict):
            raise _invalid()
        for key, windows in roots.items():
            if not _DIGEST.fullmatch(key) or not _valid_windows(windows):
                raise _invalid()
        return GenerationSnapshot(document, hashlib.sha256(pointer_raw).hexdigest(),
                                  pointer["project_tokens"], identities, retained, roots)

    def retained_location_windows(self, key, windows, *, span=None, deadline=None):
        """Keep confirmed occupancy independently of the current source query.

        An interval records a physical location fact. It cannot grant a project,
        source or thread. Different locations have independent locks and budgets.
        """
        if not _DIGEST.fullmatch(key):
            raise _invalid()
        directory = _directory(self.path)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self.identity:
                raise _invalid()
            claim = ".project-occupancy-" + key
            try:
                os.mkdir(claim, 0o700, dir_fd=directory)
            except FileExistsError:
                pass
            slot = os.open(claim, _DIRECTORY, dir_fd=directory)
            try:
                info = os.fstat(slot)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _invalid()
                limit = time.monotonic() + 0.5
                _acquire(slot, fcntl.LOCK_EX, min(deadline, limit) if deadline is not None else limit)
                try:
                    record = json.loads(_read_at(slot, "observed.json", 16384), object_pairs_hook=_unique)
                    if isinstance(record, list):
                        # Earlier development caches lacked their own physical
                        # owner key. Re-establish intervals from current facts.
                        saved = []
                    elif (not isinstance(record, dict) or set(record) != {"version", "owner", "windows"}
                            or type(record["version"]) is not int or record["version"] != 1
                            or record["owner"] != key or not _valid_windows(record["windows"])):
                        raise _invalid()
                    else:
                        saved = record["windows"]
                except FileNotFoundError:
                    saved = []
                except ValueError:
                    raise _invalid() from None
                saved = tuple(tuple(window) for window in saved)
                retained = merge_windows((*saved, *windows))[-256:]
                if retained and retained != saved:
                    # Preserve newly admitted native times and disjoint observations
                    # immediately. Coalesce opportunistic tail growth during a scan.
                    if (span is None or not _recent_extension(saved, retained)
                            or (_covers(retained, span) and not _covers(saved, span))):
                        _replace(slot, "observed.json", canonical_bytes(
                            {"version": 1, "owner": key, "windows": retained}))
                return retained
            finally:
                os.close(slot)
        finally:
            os.close(directory)

    def verified_location_span(self, key, windows, start, end):
        span = (start, end)
        return _covers(self.retained_location_windows(key, windows, span=span), span)

    def checkpoint_locations(self, next_project, checkout_indexes, *, deadline, stop=None):
        """Close a bounded round of project observations without opening an agent source."""
        from .history_location import git_metadata_locations
        from .workspaces import checkpoint_worktree_probe, checkpoint_worktree_records, discovery_deadline

        def expired():
            return time.monotonic() >= deadline or (stop is not None and stop.is_set())

        observed = set()

        def checkpoint(root, identity, binding, within=None):
            key = owner_key(root, identity, binding)
            if key not in observed and not expired():
                windows = self.locations.observe(root, identity["birthtime_ns"], identity, within=within)
                if not expired():
                    self.retained_location_windows(key, windows, deadline=deadline)
                    observed.add(key)

        snapshot = self.snapshot(deadline=deadline)
        projects = snapshot[0]["projects"]
        if not projects:
            checkout_indexes.clear()
            return 0
        current_ids = {project["id"] for project in projects}
        for old in checkout_indexes.keys() - current_ids:
            del checkout_indexes[old]
        next_project %= len(projects)
        for _ in range(min(len(projects), 16)):
            if expired():
                break
            project = projects[next_project]
            next_project = (next_project + 1) % len(projects)
            pin = project.get("repository_id")
            root = project["root"]
            identity = snapshot.project_identities[project["id"]]
            try:
                checkpoint(root, identity, pin)
                if not pin:
                    continue
                with discovery_deadline(min(deadline, time.monotonic() + 1.0)):
                    anchor, checkouts = checkpoint_worktree_records(root, pin, identity)
                for location in git_metadata_locations(anchor, pin):
                    checkpoint(*location)
            except (AccessError, OSError):
                continue
            if checkouts:
                index = checkout_indexes.get(project["id"], 0) % len(checkouts)
                for _ in range(min(len(checkouts), 8)):
                    if expired():
                        break
                    record = checkouts[index]
                    index = (index + 1) % len(checkouts)
                    checkout_indexes[project["id"]] = index
                    try:
                        with discovery_deadline(min(deadline, time.monotonic() + 1.0)):
                            probe = checkpoint_worktree_probe(anchor, pin, record)
                        checkpoint(probe["root"], probe["history_root_identity"], pin)
                        for location in git_metadata_locations(probe, pin):
                            checkpoint(*location)
                    except (AccessError, OSError):
                        continue
        return next_project

    def _load(self, directory):
        with self._parent() as parent:
            authority = _read_at(parent, self.anchor_path.name, MAX_POINTER_BYTES)
        active = _read_at(directory, "active.json", MAX_POINTER_BYTES)
        if active != authority:
            raise _invalid()
        return self._decode(directory, active)

    @contextmanager
    def locked(self, *, exclusive=False, deadline=None):
        directory = lock = admission = None
        try:
            directory = _directory(self.path)
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self.identity:
                raise _invalid()
            admission, admission_before = _open_lock(directory, "admission.lock")
            action = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            _acquire(admission, action, deadline)
            lock, before = _open_lock(directory, "activation.lock")
            _acquire(lock, action, deadline)
            for name, original in (("activation.lock", before), ("admission.lock", admission_before)):
                if _stamp(original) != _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)):
                    raise _invalid()
            if not exclusive:
                os.close(admission)
                admission = None
            yield directory
            current = _directory(self.path)
            try:
                after = os.fstat(current)
                named = os.stat("activation.lock", dir_fd=directory, follow_symlinks=False)
                gate = os.stat("admission.lock", dir_fd=directory, follow_symlinks=False)
                if ((after.st_dev, after.st_ino) != self.identity or _stamp(before) != _stamp(named)
                        or _stamp(admission_before) != _stamp(gate)):
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
            if admission is not None:
                os.close(admission)
            if directory is not None:
                os.close(directory)

    def snapshot(self, *, deadline=None):
        deadline = time.monotonic() + _READ_LOCK_SECONDS if deadline is None else deadline
        with self.locked(deadline=deadline) as directory:
            return self._load(directory)

    @contextmanager
    def commit_guard(self, expected_digest=None, *, deadline=None):
        deadline = time.monotonic() + _READ_LOCK_SECONDS if deadline is None else deadline
        with self.locked(deadline=deadline) as directory:
            snapshot = self._load(directory)
            if expected_digest is not None and snapshot[1] != expected_digest:
                raise AccessError("Unified history authorization changed before delivery.", code="restart_required")
            if time.monotonic() >= deadline:
                raise AccessError("The policy commit deadline expired.", code="restart_required")
            yield snapshot

    def activate(self, document, *, expected_digest=None, initial=False, validate=None):
        raw = canonical_bytes(document)
        if len(raw) > MAX_GENERATION_BYTES:
            raise _invalid()
        digest = hashlib.sha256(raw).hexdigest()
        # Discover external Git checkouts outside the activation lock. A
        # saved interval is usable only for this physical checkout, pin and
        # current native registration, which are rechecked on each read.
        worktrees, observed = [], set()
        for row in document["projects"]:
            for probe, default in _registered_git_probes(row):
                pin = row["repository_id"]
                if not default:
                    worktrees.append((str(probe["root"]), pin, probe["history_root_identity"]))
                for path, identity, owner, within in git_metadata_locations(probe, pin):
                    key = owner_key(path, identity, owner)
                    if key in observed:
                        continue
                    try:
                        windows = self.locations.observe(path, identity["birthtime_ns"], identity, within=within)
                        self.retained_location_windows(key, windows)
                    except (AccessError, OSError):
                        # An optional history observation cannot block revoking
                        # another project. Actual admission still verifies each fact.
                        continue
                    observed.add(key)
        with self.locked(exclusive=True) as directory, self._parent() as parent:
            current = None
            if initial:
                for fd, filename in ((directory, "active.json"), (parent, self.anchor_path.name)):
                    try:
                        os.stat(filename, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise AccessError("The unified history store is already active.", code="generation_conflict")
            else:
                current = self._load(directory)
                if expected_digest is None or current[1] != expected_digest:
                    raise AccessError("The previewed unified policy is no longer active.", code="generation_conflict")
            generations = os.open("generations", _DIRECTORY, dir_fd=directory)
            try:
                try:
                    _write_new(generations, digest + ".json", raw)
                except FileExistsError:
                    if _read_at(generations, digest + ".json", MAX_GENERATION_BYTES) != raw:
                        raise _invalid()
                os.fsync(generations)
            finally:
                os.close(generations)
            project_identities = {row["id"]: persistent_identity(Path(row["root"])) for row in document["projects"]}
            if any(row.get("directory_identity") is not None and row["directory_identity"] != project_identities[row["id"]]
                   for row in document["projects"]):
                raise AccessError("Approved project, worktree or source evidence changed.", code="identity_mismatch")
            previous = {row["id"]: row for row in current[0]["projects"]} if current is not None else {}
            tokens = {}
            for row in document["projects"]:
                project = row["id"]
                old = previous.get(project)
                tokens[project] = (current.project_tokens[project]
                                   if old is not None and _project_key(old) == _project_key(row)
                                   and current.project_identities[project] == project_identities[project]
                                   else secrets.token_hex(16))
            pointer = canonical_bytes({"version": 2, "sha256": digest, "activation_id": secrets.token_hex(16),
                                       "project_tokens": tokens, "project_identities": project_identities,
                                       "retained_sources": _retired_sources(current, document),
                                       "root_history": _root_history(current.root_history if current else {},
                                                                     document["projects"], project_identities,
                                                                     self.locations, worktrees)})
            if len(pointer) > MAX_POINTER_BYTES:
                raise _invalid()
            snapshot = self._decode(directory, pointer)
            if validate is not None:
                validate(snapshot)
            # The independently retained authority advances first. A process
            # interrupted before updating active.json leaves runtime closed.
            _replace(parent, self.anchor_path.name, pointer)
            _replace(directory, "active.json", pointer)
        return hashlib.sha256(pointer).hexdigest()

    def recover(self, approved_document, *, validate=None):
        """Finish the exact generation already durably authorized by the anchor."""
        with self.locked(exclusive=True) as directory, self._parent() as parent:
            pointer = _read_at(parent, self.anchor_path.name, MAX_POINTER_BYTES)
            snapshot = self._decode(directory, pointer)
            if canonical_bytes(snapshot[0]) != canonical_bytes(approved_document):
                raise AccessError("Recovery does not match the last authorized generation.", code="generation_conflict")
            if validate is not None:
                validate(snapshot)
            os.fsync(parent)
            _replace(directory, "active.json", pointer)
            return snapshot[1]


def initialize_store(path):
    """Operator-only initialization, before a descriptor can be used by a server."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise _invalid()
    parent = _directory(path.parent)
    try:
        try:
            os.stat("." + path.name + ".authorization-anchor.json", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        else:
            raise _invalid()
    finally:
        os.close(parent)
    directory = _directory(path)
    try:
        os.mkdir("generations", 0o700, dir_fd=directory)
        _write_new(directory, "activation.lock", b"")
        _write_new(directory, "admission.lock", b"")
        os.fsync(directory)
    finally:
        os.close(directory)
    return GenerationStore(path)
