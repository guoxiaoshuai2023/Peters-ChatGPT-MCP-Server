"""Operator-owned opt-in policy for additional history sources."""

from dataclasses import dataclass
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
    format: str
    links: dict[str, str]
    enabled: bool
    inherit: bool
    actors: dict[str, frozenset[str]]
    threads: dict[str, str]
    denied: frozenset[str]

    def immutable(self):
        return (self.adapter, str(self.root), self.format, tuple(sorted(self.links.items())))

    def allows(self, actor, project):
        return self.enabled and project in self.actors.get(actor, ())


def _source(value):
    keys = {"adapter", "root", "format", "enabled", "inherit_projects", "actors", "threads", "denied_threads"}
    if not isinstance(value, dict) or not keys <= value.keys() or value.keys() - keys - {"links"}:
        raise _bad()
    adapter = value["adapter"]
    if not isinstance(adapter, str) or adapter not in ADAPTERS or not _matches(AGENT, value["format"]):
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
    return SourcePolicy(adapter, _path(value["root"]), value["format"], links, value["enabled"],
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


class AgentPolicy:
    def __init__(self, path=None):
        self.path = Path(path).absolute() if path else None
        self.scratch = self.path.parent / "agent-history-work" if self.path else None
        self.scratch_identity = None
        self.fixed = {}
        self.identities = {}
        self.source_roots = ()
        self.protected_paths = ()
        if self.path is None:
            return
        if self.path.resolve() != self.path or self.scratch.resolve() != self.scratch:
            raise _bad()
        entries, _ = _entries(self.path)
        self.fixed = {name: source.immutable() for name, source in entries.items()}
        roots = sorted({source.root for source in entries.values()})
        if any(_overlap(root, path) for root in roots for path in (self.path, self.scratch)):
            raise _bad()
        self.source_roots = tuple(roots)
        self.protected_paths = (*self.source_roots, self.path, self.scratch)
        for name, source in entries.items():
            try:
                self.identities[name] = SourceRoot(source.root).identity
            except AccessError:
                self.identities[name] = None

    def config(self):
        if self.path is None:
            return {}, "disabled"
        if self.path.resolve() != self.path:
            raise _bad()
        entries, digest = _entries(self.path)
        if {name: source.immutable() for name, source in entries.items()} != self.fixed:
            raise AccessError("Restart to change registered history sources.", code="restart_required")
        return entries, digest

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
            if not pinned:
                return False
            for node in (resolved, *resolved.parents):
                try:
                    info = node.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode) and _identity(info) in pinned:
                    return True
            return False
        except (OSError, RuntimeError, ValueError):
            raise AccessError("Local source isolation could not be verified.", code="private_protection_unavailable") from None

    def make_root(self, name, source):
        identity = self.identities[name]
        if identity is None:
            raise AccessError("The history source is unavailable; restart after reconnecting it.", code="source_unavailable")
        return SourceRoot(source.root, expected_identity=identity, scratch=self.scratch,
                          scratch_identity=self.scratch_identity)
