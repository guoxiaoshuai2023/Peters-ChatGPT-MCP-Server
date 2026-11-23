"""Operator-owned opt-in policy for additional history sources."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata

from .agent_history_source import SourceRoot, _identity
from .catalog import AccessError

ADAPTERS = frozenset({"codeg", "deepseek_harness", "antigravity"})
SOURCE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
IDENTIFIER = re.compile(r"[^\x00-\x1f\x7f-\x9f]{1,200}")
_PRINCIPAL = re.compile(r"[0-9a-f]{64}")
_MAX_POLICY = 65_536


def _bad():
    return AccessError("Agent history policy is invalid or unavailable.", code="agent_policy_invalid")


def _unique(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise ValueError()
        obj[key] = value
    return obj


def _read(path):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_POLICY:
            raise _bad()
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(_MAX_POLICY + 1)
        after = os.fstat(fd)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) != before.st_size or stamp(before) != stamp(after) or stamp(after) != stamp(path.lstat()):
            raise _bad()
        document = json.loads(raw, object_pairs_hook=_unique)
        if (not isinstance(document, dict) or document.keys() != {"version", "sources"}
                or type(document["version"]) is not int or document["version"] != 1
                or not isinstance(document["sources"], dict) or len(document["sources"]) > 8):
            raise _bad()
        return document["sources"], hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, TypeError):
        raise _bad() from None
    finally:
        if fd is not None:
            os.close(fd)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _path(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise _bad()
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or path.resolve() != path:
        raise _bad()
    return path


def migration_location_current(alias):
    """The exact old directory is still absent and its registered target still matches."""
    from .fs_identity import persistent_identity
    old = Path(alias["old_root"])
    try:
        if old.resolve() != old:
            return False
        try:
            old.lstat()
        except FileNotFoundError:
            return persistent_identity(Path(alias["target_root"])) == alias["target_identity"]
        return False
    except (AccessError, OSError, RuntimeError):
        return False


def _values(values, *, pattern=None, limit=128):
    if (not isinstance(values, list) or len(values) > limit
            or any(not isinstance(value, str) or not value or len(value) > 200
                   or (pattern is not None and not _matches(pattern, value)) for value in values)
            or len(values) != len(set(values))):
        raise _bad()
    return frozenset(values)


@dataclass(frozen=True)
class SourcePolicy:
    adapter: str
    root: Path
    format: str | None
    links: dict[str, str]
    enabled: bool
    inherit: bool
    actors: dict[str, frozenset[str]]
    threads: dict[str, str]
    denied: frozenset[str]
    instance_id: str = ""
    exceptions: dict = field(default_factory=dict)
    root_identity: dict | None = None
    link_instances: dict = field(default_factory=dict)
    path_aliases: tuple = ()

    def immutable(self):
        value = (self.adapter, str(self.root), self.format, tuple(sorted(self.links.items())))
        if self.instance_id:
            value += (self.instance_id, json.dumps(self.root_identity, sort_keys=True),
                      tuple(sorted(self.link_instances.items())))
        return value

    def allows(self, actor, project):
        if self.instance_id:
            return self.enabled and _verified_actor(actor)
        return self.enabled and project in self.actors.get(actor, ())


def _verified_actor(actor):
    # HTTP callers reach this point only through the authenticated origin's
    # identity context. "local" is supplied solely by the explicit stdio path.
    return actor == "local" or _matches(_PRINCIPAL, actor)


def _v2_source(source_id, value):
    from .fs_identity import validate_identity
    required = {"adapter", "root", "format", "enabled", "instance_id", "root_identity"}
    optional = {"links", "link_instances", "denied_threads", "exceptions", "path_aliases"}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise _bad()
    adapter = value["adapter"]
    if (not isinstance(adapter, str) or adapter not in ADAPTERS | {"codex"}
            or (source_id == "codex") != (adapter == "codex")
            or not (adapter == "antigravity" and value["format"] is None or _matches(AGENT, value["format"]))
            or type(value["enabled"]) is not bool
            or not _matches(IDENTIFIER, value["instance_id"])):
        raise _bad()
    identity = validate_identity(value["root_identity"])
    links = value.get("links", {})
    if not isinstance(links, dict) or (links and adapter != "codeg"):
        raise _bad()
    if any(provider not in {"codex", "deepseek_harness", "antigravity"}
           or not _matches(SOURCE, target) for provider, target in links.items()):
        raise _bad()
    link_instances = value.get("link_instances", {})
    if (not isinstance(link_instances, dict) or set(link_instances) != set(links)
            or any(not _matches(IDENTIFIER, instance) for instance in link_instances.values())):
        raise _bad()
    exceptions = value.get("exceptions", {})
    if not isinstance(exceptions, dict) or len(exceptions) > 128:
        raise _bad()
    for native_id, evidence in exceptions.items():
        if (not _matches(IDENTIFIER, native_id) or not isinstance(evidence, dict)
                or set(evidence) - {"migration_metadata_sha256"} != {"project_id", "source_identity", "source_revision", "project_fingerprint"}
                or "migration_metadata_sha256" in evidence and (
                    adapter != "antigravity" or not _matches(_PRINCIPAL, evidence["migration_metadata_sha256"]))
                or not _matches(IDENTIFIER, evidence["project_id"])
                or not _matches(IDENTIFIER, evidence["source_identity"])
                or any(not _matches(_PRINCIPAL, evidence[key]) for key in
                       ("source_revision", "project_fingerprint"))):
            raise _bad()
    denied = _values(value.get("denied_threads", []), pattern=IDENTIFIER,
                     limit=10000 if adapter == "codex" else 128)
    aliases = value.get("path_aliases", [])
    if adapter == "codex":
        from .history import ID_PATTERN
        if exceptions or aliases or any(not ID_PATTERN.fullmatch(native) for native in denied):
            raise _bad()
    if not isinstance(aliases, list) or len(aliases) > 128:
        raise _bad()
    seen = set()
    for alias in aliases:
        if (not isinstance(alias, dict) or set(alias) != {
                "native_project_id", "source_instance", "old_root", "project_id", "target_root", "target_identity"}
                or not _matches(IDENTIFIER, alias["native_project_id"])
                or alias["source_instance"] != value["instance_id"]
                or not _matches(IDENTIFIER, alias["project_id"])):
            raise _bad()
        old, target = _path(alias["old_root"]), _path(alias["target_root"])
        if old == target or (alias["native_project_id"], str(old)) in seen:
            raise _bad()
        validate_identity(alias["target_identity"])
        seen.add((alias["native_project_id"], str(old)))
    return SourcePolicy(adapter, _path(value["root"]), value["format"], links, value["enabled"], True,
                        {}, {native: item["project_id"] for native, item in exceptions.items()},
                        denied,
                        value["instance_id"], exceptions, identity, link_instances, tuple(aliases))


def validate_generation(document):
    """Validate an already pinned generation without touching vendor history."""
    if (not isinstance(document, dict)
            or set(document) != {"version", "projects", "sources", "legacy_history"}
            or type(document["version"]) is not int or document["version"] != 2
            or not isinstance(document["projects"], list) or len(document["projects"]) > 128
            or not isinstance(document["sources"], dict) or len(document["sources"]) > 8):
        raise _bad()
    sources = {}
    for source_id, value in document["sources"].items():
        if not _matches(SOURCE, source_id):
            raise _bad()
        sources[source_id] = _v2_source(source_id, value)
    if len({source.instance_id for source in sources.values()}) != len(sources):
        raise _bad()
    if any(not isinstance(project, dict) or not isinstance(project.get("id"), str)
           for project in document["projects"]):
        raise _bad()
    projects = {project["id"]: project for project in document["projects"]}
    if len(projects) != len(document["projects"]):
        raise _bad()
    for source_id, source in sources.items():
        for provider, target in source.links.items():
            if (target not in sources or target == source_id or sources[target].adapter != provider
                    or source.link_instances[provider] != sources[target].instance_id):
                raise _bad()
        for alias in source.path_aliases:
            project = projects.get(alias["project_id"])
            if project is not None and (project.get("root") != alias["target_root"]
                    or project.get("directory_identity") != alias["target_identity"]
                    or project.get("repository_id") is not None):
                raise _bad()
    legacy = document["legacy_history"]
    if legacy is not None:
        if (not isinstance(legacy, dict) or set(legacy) != {"codex_home", "state_db", "tool_evidence"}
                or legacy["state_db"] != "state_5.sqlite" or "codex" not in sources
                or _path(legacy["codex_home"]) != sources["codex"].root
                or not isinstance(legacy["tool_evidence"], list) or len(legacy["tool_evidence"]) > 64):
            raise _bad()
        seen = set()
        from .history import ID_PATTERN
        for evidence in legacy["tool_evidence"]:
            if (not isinstance(evidence, dict) or evidence.keys() - {"id", "label", "allow_tool_results", "mcp_tools"}
                    or not _matches(ID_PATTERN, evidence.get("id")) or evidence["id"] in seen
                    or type(evidence.get("allow_tool_results", False)) is not bool
                    or not isinstance(evidence.get("label", ""), str) or len(evidence.get("label", "")) > 120):
                raise _bad()
            tools = evidence.get("mcp_tools", [])
            if (not isinstance(tools, list) or len(tools) > 20
                    or any(not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+/[A-Za-z0-9_.:-]+", tool)
                           for tool in tools)):
                raise _bad()
            seen.add(evidence["id"])
        synthesized = {"version": 2, "codex_home": legacy["codex_home"], "state_db": legacy["state_db"],
                       "inherit_projects": True, "threads": legacy["tool_evidence"],
                       "denied_threads": sorted(sources["codex"].denied)}
        if len(json.dumps(synthesized, sort_keys=True, separators=(",", ":")).encode()) > _MAX_POLICY:
            raise _bad()
    elif "codex" in sources:
        raise _bad()
    return sources


def _source(value):
    keys = {"adapter", "root", "enabled", "inherit_projects", "actors", "threads", "denied_threads"}
    if not isinstance(value, dict) or not keys <= value.keys() or value.keys() - keys - {"format", "links"}:
        raise _bad()
    adapter = value["adapter"]
    if not isinstance(adapter, str) or adapter not in ADAPTERS:
        raise _bad()
    source_format = value.get("format")
    if (adapter != "antigravity" or "format" in value) and not _matches(AGENT, source_format):
        raise _bad()
    if type(value["enabled"]) is not bool or type(value["inherit_projects"]) is not bool:
        raise _bad()
    actors, threads, links = value["actors"], value["threads"], value.get("links", {})
    if not isinstance(actors, dict) or len(actors) > 32 or not isinstance(threads, dict) or len(threads) > 128:
        raise _bad()
    if not isinstance(links, dict) or (links and adapter != "codeg"):
        raise _bad()
    for provider, source_id in links.items():
        if provider not in {"codex", "deepseek_harness", "antigravity"} or not _matches(SOURCE, source_id):
            raise _bad()
    if any(not _matches(IDENTIFIER, ident) or not isinstance(pid, str) or not 0 < len(pid) <= 200
           for ident, pid in threads.items()):
        raise _bad()
    assignments = {}
    for actor, projects in actors.items():
        if actor != "local" and not _matches(_PRINCIPAL, actor):
            raise _bad()
        assignments[actor] = _values(projects)
    return SourcePolicy(adapter, _path(value["root"]), source_format, links, value["enabled"],
                        value["inherit_projects"], assignments, threads,
                        _values(value["denied_threads"], pattern=IDENTIFIER))


def _entries(path):
    data, digest = _read(path)
    entries = {}
    for key, value in data.items():
        if key == "codex" or not _matches(SOURCE, key):
            raise _bad()
        entries[key] = _source(value)
    for source_id, source in entries.items():
        for provider, target in source.links.items():
            valid_target = target == "codex" if provider == "codex" else (
                target in entries and target != source_id and entries[target].adapter == provider)
            if not valid_target:
                raise _bad()
    return entries, digest


def _key(path):
    return tuple(unicodedata.normalize("NFC", part.casefold()) for part in Path(path).parts)


def _overlap(left, right):
    a, b = _key(left), _key(right)
    return a[:len(b)] == b or b[:len(a)] == a



def reject_project_overlap(extents):
    """Reject equal or nested physical roots belonging to different projects."""
    by_path = [(project, _key(path)) for project, path in extents]
    for index, (project, path) in enumerate(by_path):
        for other, alternative in by_path[index + 1:]:
            if project != other and (path[:len(alternative)] == alternative
                                     or alternative[:len(path)] == path):
                raise AccessError("Verified project and worktree scopes overlap.", code="project_scope_overlap")


class AgentPolicy:
    def __init__(self, path=None, *, mode="v1"):
        if mode not in {"v1", "v2"}:
            raise _bad()
        self.mode = mode
        self.version = 2 if mode == "v2" else 1
        self.path = Path(path).absolute() if path else None
        self.scratch = self.path.parent / "agent-history-work" if self.path else None
        self.scratch_identity = None
        self.fixed = {}
        self.identities = {}
        self.source_roots = ()
        self.protected_paths = ()
        self.persistent_roots = ()
        self.store = None
        retired_roots = ()
        if self.path is None:
            if mode == "v2":
                raise _bad()
            return
        if self.path.resolve() != self.path or self.scratch.resolve() != self.scratch:
            raise _bad()
        if self.mode == "v2":
            from .agent_history_generation import GenerationStore, _read_at
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                raw = _read_at(directory, self.path.name, _MAX_POLICY)
            finally:
                os.close(directory)
            descriptor = json.loads(raw, object_pairs_hook=_unique)
            if (not isinstance(descriptor, dict) or set(descriptor) != {"version", "generation_directory"}
                    or type(descriptor["version"]) is not int or descriptor["version"] != 2):
                raise _bad()
            self.store = GenerationStore(_path(descriptor["generation_directory"]))
            snapshot = self.store.snapshot()
            entries = validate_generation(snapshot[0])
            retired_roots = snapshot.retained_sources
        else:
            entries, _ = _entries(self.path)
        self.fixed = {name: source.immutable() for name, source in entries.items()}
        roots = sorted({source.root for source in entries.values()} | {Path(path) for path, _ in retired_roots})
        retained_state = (self.store.path, self.store.anchor_path) if self.store is not None else ()
        control_paths = (self.path, self.scratch, *retained_state)
        if any(_overlap(root, path) for root in roots for path in control_paths):
            raise _bad()
        self.source_roots = tuple(roots)
        self.persistent_roots = tuple(source.root_identity for source in entries.values()
                                      if source.root_identity is not None) + tuple(identity for _, identity in retired_roots)
        self.protected_paths = (*self.source_roots, *control_paths)
        for name, source in entries.items():
            try:
                if source.root_identity is not None:
                    from .fs_identity import persistent_identity
                    if persistent_identity(source.root) != source.root_identity:
                        raise _bad()
                self.identities[name] = SourceRoot(source.root).identity
            except AccessError:
                self.identities[name] = None

    def snapshot(self):
        if self.mode != "v2":
            raise _bad()
        from .project_guard import snapshot_for
        bound = snapshot_for(self)
        if bound is not None:
            return bound
        snapshot = self.store.snapshot()
        self._v2_entries(snapshot)
        return snapshot

    def _v2_entries(self, snapshot):
        entries = validate_generation(snapshot[0])
        if {name: source.immutable() for name, source in entries.items()} != self.fixed:
            raise AccessError("Restart to change registered history sources.", code="restart_required")
        return entries

    def config(self, snapshot=None):
        if self.mode == "v2":
            snapshot = snapshot if snapshot is not None else self.snapshot()
            return self._v2_entries(snapshot), snapshot[1]
        if self.path is None:
            return {}, "disabled"
        if self.path.resolve() != self.path:
            raise _bad()
        entries, digest = _entries(self.path)
        if {name: source.immutable() for name, source in entries.items()} != self.fixed:
            raise AccessError("Restart to change registered history sources.", code="restart_required")
        return entries, digest

    def projects_document(self, snapshot=None):
        snapshot = snapshot if snapshot is not None else self.snapshot()
        self._v2_entries(snapshot)
        return {"projects": snapshot[0]["projects"]}

    def legacy_document(self, snapshot=None):
        snapshot = snapshot if snapshot is not None else self.snapshot()
        sources = self._v2_entries(snapshot)
        legacy = snapshot[0]["legacy_history"]
        if legacy is None:
            return None
        return {"version": 2, "codex_home": legacy["codex_home"], "state_db": legacy["state_db"],
                "inherit_projects": True, "threads": legacy["tool_evidence"],
                "denied_threads": sorted(sources["codex"].denied)}

    def allows_actor(self, actor, snapshot=None):
        if self.mode != "v2":
            return True
        if snapshot is not None:
            self._v2_entries(snapshot)
        return _verified_actor(actor)

    def require_actor(self, actor, snapshot=None):
        if not self.allows_actor(actor, snapshot):
            raise AccessError("The requested history is not authorized.", code="unauthorized")

    def project_token(self, project_id, snapshot=None):
        snapshot = snapshot if snapshot is not None else self.snapshot()
        if not isinstance(project_id, str) or project_id not in snapshot.project_tokens:
            raise AccessError("The requested project is no longer authorized.", code="scope_revoked")
        return snapshot.project_tokens[project_id]

    @contextmanager
    def commit_guard(self, expected_digest=None, *, project_id=None, expected_project_token=None, deadline=None):
        if self.mode != "v2":
            yield None
            return
        if expected_project_token is not None and project_id is None:
            raise ValueError("A project token requires a project ID.")
        with self.store.commit_guard(expected_digest, deadline=deadline) as snapshot:
            self._v2_entries(snapshot)
            if project_id is not None:
                token = self.project_token(project_id, snapshot)
                if expected_project_token is not None and token != expected_project_token:
                    raise AccessError("The requested project authorization changed.", code="scope_revoked")
            yield snapshot

    def excludes(self, path):
        if not self.protected_paths:
            return False
        try:
            absolute = Path(path).absolute()
            resolved = absolute.resolve()
            aliases = (_key(absolute), _key(resolved))
            if any(alias[:len(protected)] == protected for alias in aliases
                   for protected in map(_key, self.protected_paths)):
                return True
            pinned = {identity for identity in self.identities.values() if identity is not None}
            if self.scratch_identity is not None:
                pinned.add(self.scratch_identity)
            if not pinned and not self.persistent_roots:
                return False
            for node in (resolved, *resolved.parents):
                try:
                    info = node.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode) and _identity(info) in pinned:
                    return True
                if stat.S_ISDIR(info.st_mode):
                    candidates = [identity for identity in self.persistent_roots if identity["file_id"] == info.st_ino]
                    if candidates:
                        from .fs_identity import persistent_identity
                        if persistent_identity(node) in candidates:
                            return True
            return False
        except (OSError, RuntimeError, ValueError):
            raise AccessError("Local source isolation could not be verified.", code="private_protection_unavailable") from None

    def make_root(self, name, source):
        if source.root_identity is not None:
            from .fs_identity import persistent_identity
            try:
                if persistent_identity(source.root) != source.root_identity:
                    raise _bad()
            except AccessError:
                raise AccessError("The history source identity changed or is unavailable.", code="source_unavailable") from None
        identity = self.identities[name]
        if identity is None:
            raise AccessError("The history source is unavailable; restart after reconnecting it.", code="source_unavailable")
        return SourceRoot(source.root, expected_identity=identity, scratch=self.scratch,
                          scratch_identity=self.scratch_identity)
