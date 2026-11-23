"""Authorization and bounded search/read for agent history adapters."""

import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time

from .agent_history_policy import AGENT, IDENTIFIER, SOURCE, AgentPolicy, migration_location_current
from .agent_history_source import Message, Projection, Thread, clear_snapshot_copies
from .catalog import AccessError, Catalog, Project, integer
from .history import HistoryAccess, utc
from .history_projection import sanitize
from .history_location import check_origins

VERSION = "agent-visible-v1"
TTL = 1800
MAX_SEARCH = 256
MAX_FIND_CACHE = 12
MAX_READ_CACHE = 8
MAX_READ_BYTES = 24 * 1024 * 1024
MAX_THREAD_BYTES = 8 * 1024 * 1024
MAX_MESSAGES = 24_000
MAX_PAGE_BYTES = 160 * 1024
HEX = re.compile(r"[a-f0-9]{64}")
WARNING = re.compile(r"[a-z][a-z0-9_]{0,79}")
LOCATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+#-]{0,159}")
_LOCAL_PREFIXES = ("/Users", "/home", "/private/var", "/Volumes")
ABS_PATH = re.compile(r"(?<![\w./])(?:"
                      + "|".join(re.escape(root + "/") for root in _LOCAL_PREFIXES)
                      + r")[^\s`\x22'<>\])}]+")
ERROR_CODES = frozenset({"source_unavailable", "waiting_source_stable", "unsupported_format",
                         "resource_exhausted", "processing_timeout", "metadata_unavailable",
                         "history_processing_failed", "narrow_query_required", "coverage_unverified",
                         "association_unverified"})
DENIED = frozenset({"unauthorized", "unverifiable_source"})


def _error(message, code):
    return AccessError(message, code=code)


def _deny():
    return _error("The requested history is not authorized.", "unauthorized")


def _restart():
    return _error("The authorized history changed; start a fresh search or read.", "restart_required")


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def unified(policy):
    return getattr(policy, "mode", None) == "v2" or getattr(policy, "version", 1) == 2


def canonical_identity(source_id, instance, native_id):
    return (source_id, instance, native_id) if instance and instance != source_id else (source_id, native_id)


def coverage_status(warnings):
    for status in ("source_unavailable", "metadata_unavailable", "unsupported_format",
                   "resource_exhausted", "processing_timeout", "waiting_source_stable",
                   "history_processing_failed", "association_unverified", "coverage_unverified"):
        if status in warnings:
            return status
    return "complete" if not warnings else "coverage_unverified"


def _time(value):
    if not isinstance(value, str) or len(value) > 48:
        return ""
    try:
        value = datetime.fromisoformat(value)
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        pass
    return ""


def _safe_text(value):
    value, _ = sanitize(value)
    value = ABS_PATH.sub("[REDACTED LOCAL PATH]", value)
    return value.encode("utf-8", errors="replace").decode("utf-8")


def _adapter(provider, root, version):
    if provider == "codeg":
        from .agent_history_codeg import Adapter
    elif provider == "deepseek_harness":
        from .agent_history_deepseek import Adapter
    elif provider == "antigravity":
        from .agent_history_antigravity import Adapter
    else:
        raise _error("Unsupported history source.", "unsupported_format")
    return Adapter(root, version)


def verify_token(key, token, kind):
    try:
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError()
        prefix, encoded, signature = token.split(".")
        expected = hmac.new(key, encoded.encode(), hashlib.sha256).hexdigest()
        if prefix != "ah1" or not hmac.compare_digest(expected, signature):
            raise ValueError()
        value = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
        if value["type"] != kind or value["expires"] < time.time():
            raise ValueError()
        return value
    except (TypeError, ValueError, KeyError, UnicodeError):
        raise _error("The history reference or cursor is invalid or expired.", "invalid_cursor") from None



@dataclass(frozen=True)
class Record:
    source_id: str
    thread: Thread
    projection: Projection
    contexts: str
    canonical: tuple[str, str]
    backend: str
    title: str
    entries: tuple[Message, ...]
    fingerprint: str
    size: int
    source_instance: str = ""

    @property
    def stable_id(self):
        return _digest((self.source_instance or self.source_id, self.thread.native_id))

    @property
    def display_metadata(self):
        return self.title, self.thread.agent, self.thread.surface, self.backend, self.projection.warnings

    @property
    def proof(self):
        return _digest((self.canonical, self.contexts, self.projection.identity, self.projection.revision,
                        self.fingerprint, self.thread.updated_at, self.display_metadata))


@dataclass
class RequestScope:
    sources: dict
    project: str
    actor: str
    policy_actor: str
    key: str
    associations: dict
    worktrees: dict
    delivery_aliases: set = field(default_factory=set)


@dataclass(frozen=True)
class SnapshotProof:
    source_id: str
    native_id: str
    canonical: tuple[str, str]
    contexts: str
    identity: str
    revision: str
    prefix: tuple[str, int, str] | None
    fingerprint: str
    count: int
    display_metadata: tuple
    updated_at: str

    @classmethod
    def from_record(cls, record):
        return cls(record.source_id, record.thread.native_id, record.canonical, record.contexts,
                   record.projection.identity, record.projection.revision, record.projection.prefix,
                   record.fingerprint, len(record.entries), record.display_metadata, record.thread.updated_at)


class Prepared(dict):
    def __init__(self, result, scope, vouchers):
        super().__init__(result)
        self.scope = scope
        self.vouchers = vouchers


class AgentHistoryCore:
    """Runs inside the supervised worker. Raw messages remain in this process."""

    def __init__(self, policy, catalog, legacy, key):
        self.policy = policy
        self.catalog = catalog
        self.legacy = legacy
        self.key = key
        self.find_cache = {}
        self.read_cache = {}

    def _configuration(self, project, actor, policy_actor):
        if not isinstance(actor, str) or not HEX.fullmatch(actor):
            raise _deny()
        if policy_actor != "local" and policy_actor != actor:
            raise _deny()
        self.catalog.refresh()
        if project not in self.catalog.projects:
            raise _deny()
        sources, version = self.policy.config()
        if unified(self.policy) and not self.policy.allows_actor(policy_actor):
            raise _deny()
        worktrees = self.catalog.repositories.discover_all()
        if not any(entry["state"] == "valid" for entry in worktrees[project]["worktrees"] if entry["is_default"]):
            raise _deny()
        if unified(self.policy):
            topology = getattr(worktrees, "topology", None)
            if topology is not None and not topology.complete:
                raise _error("Project workspace membership could not be verified.", "restart_required")
            # Discovery already resolved overlaps against every registered project.
            membership = worktrees[project]["fingerprint"]
        else:
            membership = {item: data["fingerprint"] for item, data in worktrees.items()}
        token_scope = _digest((version, self.catalog._config_digest, membership, project, actor, policy_actor))
        return RequestScope(sources, project, actor, policy_actor, token_scope, {}, worktrees)

    def _token(self, scope, kind, **data):
        value = {"type": kind, "scope": scope.key, "expires": int(time.time()) + TTL, **data}
        encoded = base64.urlsafe_b64encode(_json(value)).decode()
        signature = hmac.new(self.key, encoded.encode(), hashlib.sha256).hexdigest()
        return "ah1." + encoded + "." + signature

    def _verify(self, token, kind):
        return verify_token(self.key, token, kind)

    def _resume(self, token, kind, scope, params):
        values = self._verify(token, kind)
        if values["scope"] != scope.key:
            raise _restart()
        if values.get("parameters") != params:
            raise _error("Keep the same parameters when using a history cursor.", "invalid_cursor")
        return values

    def _source(self, scope, source_id):
        source = scope.sources.get(source_id)
        if source is None or not source.allows(scope.policy_actor, scope.project):
            raise _deny()
        return source

    def _mapped_context(self, scope, source, thread, context, ancestors):
        if not unified(self.policy):
            return context, None
        aliases = [alias for alias in getattr(source, "path_aliases", ()) if alias["project_id"] == scope.project]
        if isinstance(context, str) and any(Path(alias["old_root"]) in Path(context).parents for alias in aliases):
            # An explicitly pinned transcript cannot turn a migration mapping
            # into a wildcard for other folders under the former pathname.
            raise _deny()
        candidates = [alias for alias in aliases if alias["old_root"] == context]
        if not candidates:
            return context, None
        matching = [alias for alias in candidates if alias["native_project_id"] == thread.native_project_id]
        if len(matching) != 1:
            raise _deny()
        alias = matching[0]
        lineage = dict(thread.ancestor_projects)
        if (alias["source_instance"] != source.instance_id
                or len(lineage) != len(thread.ancestor_projects)
                or any(lineage.get(native) != thread.native_project_id for native in ancestors)):
            raise _deny()
        # A path can be temporarily reused by another project and disappear
        # again. Only an explicitly reviewed native ID and cut may use this map.
        evidence = source.exceptions.get(thread.native_id)
        if (evidence is None or source.threads.get(thread.native_id) != scope.project
                or evidence.get("project_id") != scope.project):
            raise _error("The historical migration snapshot has not been reviewed.", "association_unverified")
        target = Path(alias["target_root"])
        if target != self.catalog.projects[scope.project].root or not migration_location_current(alias):
            raise _deny()
        fingerprint = _digest(alias)
        scope.delivery_aliases.add(fingerprint)
        return str(target), fingerprint

    def _binding(self, scope, source, thread, projection=None, *, used_mappings=None):
        ancestors = set(thread.ancestors)
        contexts = set(thread.contexts)
        complete = thread.context_complete
        if projection is not None:
            ancestors.update(projection.ancestors)
            contexts.update(projection.contexts)
            complete = projection.context_complete
        if thread.native_id in source.denied or ancestors & source.denied:
            raise _deny()
        assigned = source.threads.get(thread.native_id)
        if assigned is not None and assigned != scope.project:
            raise _deny()
        if len(contexts) > 128 or len(ancestors) > 128:
            raise _deny()
        membership, mappings, witnesses = [], [], []
        for context in sorted(contexts):
            context, mapping = self._mapped_context(scope, source, thread, context, ancestors)
            if mapping is not None:
                mappings.append(mapping)
            if not isinstance(context, str) or not Path(context).is_absolute() or self.policy.excludes(context):
                raise _deny()
            if context not in scope.associations:
                scope.associations[context] = self.catalog.repositories.associate(context, scope.worktrees)
            result = scope.associations[context]
            if result["state"] in {"outside", "ambiguous"} or (result["state"] == "matched"
                                                               and result["project_id"] != scope.project):
                raise _deny()
            if mapping is None and "history_windows" in result:
                witnesses.extend(result["history_windows"])
            membership.append((context, result["state"], result["worktree_id"], result["repository_id"]))
        if projection is not None and assigned is None:
            if not source.inherit or not complete or not membership or any(item[1] != "matched" for item in membership):
                if unified(self.policy) and any(item[1] == "matched" for item in membership):
                    raise _error("The session's complete project association is unverified.", "association_unverified")
                raise _deny()
            if not check_origins(projection.origin_ns, projection.last_ns, witnesses):
                raise _error("The session's physical project at creation is unverified.", "association_unverified")
        if projection is None and assigned is None and not source.inherit:
            raise _deny()
        if projection is not None and assigned is not None and unified(self.policy):
            exception = source.exceptions.get(thread.native_id)
            expected = {"project_id": scope.project,
                        "source_identity": projection.identity,
                        "source_revision": projection.revision,
                        "project_fingerprint": scope.worktrees[scope.project]["fingerprint"]}
            if exception is not None and "migration_metadata_sha256" in exception:
                from .agent_history_path_migration import metadata_digest
                aliases = [alias for alias in source.path_aliases if _digest(alias) in mappings]
                if len(aliases) != 1:
                    raise _error("The reviewed directory migration is unavailable.", "association_unverified")
                expected["migration_metadata_sha256"] = metadata_digest(thread, aliases[0])
            if exception != expected:
                raise _error("The verified historical association no longer matches its source.",
                             "association_unverified")
        proof = (assigned, complete, membership, sorted(ancestors))
        if unified(self.policy):
            proof += (thread.native_project_id, thread.ancestor_projects, sorted(mappings))
        if used_mappings is not None:
            used_mappings.update(mappings)
        return _digest(proof)

    def _codex_config(self, scope=None):
        if unified(self.policy):
            if scope is None:
                raise _deny()
            self._source(scope, "codex")
            return self.legacy._configuration(caller={"actor": scope.actor, "policy_actor": scope.policy_actor},
                                              project_id=scope.project)
        if self.legacy.config_path is None:
            raise _deny()
        return self.legacy._configuration()

    def _legacy_record(self, scope, native_id):
        config = self._codex_config(scope)
        row = self.legacy._metadata(config, thread_id=native_id).get(native_id)
        if not row or not self.legacy._eligible(config, row):
            raise _deny()
        yield from self.legacy._ensure_iter(config, row)
        grant, _ = self.legacy._derive(config, row)
        if not grant or grant.get("project_id") != scope.project:
            raise _deny()
        config["threads"][native_id] = grant
        yield from self.legacy._ensure_iter(config, row, projection=True)
        projection, snapshot, _ = self.legacy._snapshot(config, row)
        yield from self.legacy._revalidate_iter(config, {native_id: row}, {native_id: snapshot})
        summary = self.legacy._summary(config, row)
        thread = Thread(native_id, summary["title"], summary["updated_at"] or "", agent="codex", surface="local")
        visible = tuple(Message(item["role"], item["text"], "record:" + str(item["source_line"]),
                                item.get("timestamp") or "", item.get("turn_id") or "")
                        for item in projection["messages"])
        # The Codex history engine already canonicalizes and verifies the raw input.
        original = Projection(visible, snapshot["sha256"], _digest((config["scope"], row["rollout_path"])),
                              warnings=("coverage_unverified",) if not projection["complete_public_projection"] else (),
                              origin_ns=grant.get("_proof_context", {}).get("origin_ns"),
                              last_ns=grant.get("_proof_context", {}).get("last_ns"))
        binding = _digest((config["scope"], grant.get("_proof"), scope.project))
        instance = scope.sources["codex"].instance_id if unified(self.policy) else ""
        canonical = canonical_identity("codex", instance, native_id)
        return self._record("codex", thread, original, binding, canonical, "codex", instance)

    def _record(self, source_id, thread, projection, context, canonical, backend, instance=""):
        if not isinstance(projection, Projection) or len(projection.messages) > MAX_MESSAGES:
            raise _error("Thread projection exceeds the read budget.", "resource_exhausted")
        entries, size, positions = [], 0, set()
        for item in projection.messages:
            if not isinstance(item, Message) or item.role not in {"user", "assistant"} or not isinstance(item.text, str):
                raise _error("The source has an unsupported message.", "unsupported_format")
            if not isinstance(item.position, str) or not LOCATOR.fullmatch(item.position) or item.position in positions:
                raise _error("Message positions could not be verified.", "unsupported_format")
            positions.add(item.position)
            text = _safe_text(item.text)
            size += len(text.encode("utf-8")) + 240
            if size > MAX_THREAD_BYTES:
                raise _error("Thread projection exceeds the read budget.", "resource_exhausted")
            if text:
                turn = item.turn_id if isinstance(item.turn_id, str) and LOCATOR.fullmatch(item.turn_id) else ""
                entries.append(Message(item.role, text, item.position, _time(item.timestamp), turn))
        warnings = tuple(sorted({w for w in projection.warnings if isinstance(w, str) and WARNING.fullmatch(w)}))
        compact = replace(projection, messages=(), contexts=(), ancestors=(), warnings=warnings, title="")
        entries = tuple(entries)
        fingerprint = self._message_fingerprint(entries)
        title = _safe_text(projection.title or thread.title)[:500]
        agent = thread.agent if isinstance(thread.agent, str) and AGENT.fullmatch(thread.agent) else backend
        surface = thread.surface if isinstance(thread.surface, str) and AGENT.fullmatch(thread.surface) else "local"
        thread = replace(thread, agent=agent, surface=surface, updated_at=_time(thread.updated_at), title="")
        return Record(source_id, thread, compact, context, canonical, backend, title, entries, fingerprint, size, instance)

    def _load(self, scope, source_id, native_id, *, adapter=None, thread=None, allow_link=True):
        if source_id == "codex":
            return (yield from self._legacy_record(scope, native_id))
        source = self._source(scope, source_id)
        if adapter is None:
            adapter = _adapter(source.adapter, self.policy.make_root(source_id, source), source.format)
        if thread is None:
            describe = getattr(adapter, "describe_project", None) if unified(self.policy) else None
            thread = describe(native_id) if describe is not None else adapter.describe(native_id)
        if not isinstance(thread, Thread) or thread.native_id != native_id or not IDENTIFIER.fullmatch(native_id):
            raise _deny()
        self._binding(scope, source, thread)
        inheritance_snapshot = None
        if (unified(self.policy) and "migration_metadata_sha256" in source.exceptions.get(native_id, {})):
            inheritance_snapshot = getattr(adapter, "snapshot_for_inheritance", None)
            if inheritance_snapshot is None:
                raise _error("The approved migration format is unavailable.", "association_unverified")
        if (not getattr(adapter, "supports_inheritance", True)
                and thread.native_id not in source.threads):
            if not unified(self.policy):
                raise _deny()
            # Some native formats need a stronger snapshot for automatic
            # association than the one pinned by a historical exception.
            inheritance_snapshot = getattr(adapter, "snapshot_for_inheritance", None)
            if inheritance_snapshot is None:
                raise _error("This reader cannot verify complete workspace history.", "association_unverified")
        if thread.native_link is not None:
            if not allow_link:
                raise _deny()
            provider, target_id = thread.native_link
            target = source.links.get(provider)
            if target is None or not isinstance(target_id, str) or not IDENTIFIER.fullmatch(target_id):
                raise _deny()
            if unified(self.policy):
                target_source = self._source(scope, target)
                if source.link_instances.get(provider) != target_source.instance_id:
                    raise _deny()
            link_ownership = self._binding(scope, source, thread) if unified(self.policy) else self._binding(
                scope, source, thread, Projection((), "", "", context_complete=thread.context_complete))
            child = yield from self._load(scope, target, target_id, allow_link=False)
            if child.backend != provider:
                raise _deny()
            if unified(self.policy):
                link_ownership = self._binding(scope, source, thread,
                    replace(child.projection, context_complete=thread.context_complete))
            return replace(child, source_id=source_id,
                           thread=replace(thread, agent=child.thread.agent, title="", updated_at=_time(thread.updated_at)),
                           title=_safe_text(thread.title)[:500] or child.title,
                           contexts=_digest((target, link_ownership, child.contexts)),
                           source_instance=source.instance_id if unified(self.policy) else "")
        yield {"phase": "scanning"}
        snapshot = inheritance_snapshot or adapter.snapshot
        projection = snapshot(thread)
        used_mappings = set()
        binding = self._binding(scope, source, thread, projection, used_mappings=used_mappings)
        instance = source.instance_id if unified(self.policy) else ""
        canonical = canonical_identity(source_id, instance, native_id)
        record = self._record(source_id, thread, projection, binding, canonical, source.adapter, instance)
        if used_mappings and "migration_metadata_sha256" not in source.exceptions[native_id]:
            # This historical exception signed only the visible original. Search,
            # subsequent reads and delivery must not use the mutable index label.
            title = next((entry.text.lstrip().partition("\n")[0][:500] for entry in record.entries
                          if entry.role == "user" and entry.text.strip()), "")
            last_visible = max((entry.timestamp for entry in record.entries), default="")
            record = replace(record, title=title, thread=replace(record.thread, updated_at=last_visible))
        return record

    def _summary(self, scope, record):
        pinned = {"snapshot": record.proof} if unified(self.policy) else {}
        result = {"source_id": record.source_id, "agent": record.thread.agent, "surface": record.thread.surface,
                "stable_thread_id": record.stable_id, "title": record.title, "updated_at": record.thread.updated_at,
                "project_id": scope.project, "thread_ref": self._token(scope, "thread", actor=scope.actor,
                         project=scope.project, source=record.source_id, native=record.thread.native_id, **pinned),
                "source_adapter": scope.sources[record.source_id].adapter if record.source_id in scope.sources else "codex"}
        if unified(self.policy):
            result["source_instance"] = record.source_instance
        return result

    def _sources(self, scope, source_id, agent=""):
        sources = [name for name, source in sorted(scope.sources.items())
                   if source.allows(scope.policy_actor, scope.project)]
        if not unified(self.policy) and self.legacy.config_path is not None:
            sources.append("codex")
        if source_id:
            if source_id not in sources:
                raise _deny()
            return [source_id]
        if agent and agent != "codex":
            sources = [name for name in sources if name != "codex"
                       and scope.sources[name].adapter in ("codeg", agent)]
        return sources

    def _matching(self, summary, record, needle):
        if not needle or needle in record.title.casefold():
            return {**summary, "match": {"in": "title" if needle else "project"}}
        for message in record.entries:
            if needle in message.text.casefold():
                return {**summary, "match": {"in": "visible_message", "message_id": self._message_id(record, message),
                                             "snapshot_sha256": record.fingerprint}}
        return None

    def _discover(self, scope, source_id):
        if source_id == "codex":
            config = self._codex_config(scope)
            return None, (Thread(value["id"]) for value in self.legacy._metadata(config, project_id=scope.project).values())
        source = self._source(scope, source_id)
        adapter = _adapter(source.adapter, self.policy.make_root(source_id, source), source.format)
        if unified(self.policy):
            roots = tuple(entry["root"] for entry in scope.worktrees[scope.project]["worktrees"]
                          if entry["state"] == "valid")
            excluded = tuple(entry["root"] for project, snapshot in scope.worktrees.items()
                             if project != scope.project for entry in snapshot["worktrees"]
                             if any(Path(entry["root"]).is_relative_to(Path(root)) for root in roots))
            if hasattr(adapter, "discover_project"):
                aliases = tuple(alias["old_root"] for alias in getattr(source, "path_aliases", ())
                                if alias["project_id"] == scope.project)
                explicit = tuple(native for native, project in source.threads.items() if project == scope.project)
                return adapter, adapter.discover_project((*roots, *aliases), explicit_ids=explicit, excluded_roots=excluded,
                                                        denied_ids=source.denied)
            adapter.project_partition_complete = False
            return adapter, ()
        return adapter, adapter.discover()

    def _project_candidate(self, scope, source, thread):
        if thread.native_id in source.denied or set(thread.ancestors) & source.denied:
            return False
        assigned = source.threads.get(thread.native_id)
        if assigned is not None:
            return assigned == scope.project
        matched = False
        for context in thread.contexts:
            context, _ = self._mapped_context(scope, source, thread, context, set(thread.ancestors))
            if context not in scope.associations:
                scope.associations[context] = self.catalog.repositories.associate(context, scope.worktrees)
            result = scope.associations[context]
            if result["state"] in {"outside", "ambiguous"}:
                return False
            if result["state"] == "matched":
                if result["project_id"] != scope.project:
                    return False
                matched = True
        return matched

    def _search(self, scope, query, agent, source_id):
        needle = query.casefold()
        grouped, reports = {}, []
        for name in self._sources(scope, source_id, agent):
            warnings = set()
            started = time.monotonic()
            try:
                adapter, candidates = self._discover(scope, name)
                count = 0
                for index, thread in enumerate(candidates):
                    try:
                        if not isinstance(thread, Thread) or not isinstance(thread.native_id, str) or not IDENTIFIER.fullmatch(thread.native_id):
                            continue
                        if unified(self.policy) and name != "codex":
                            if not self._project_candidate(scope, self._source(scope, name), thread):
                                continue
                        if not unified(self.policy) and (index >= MAX_SEARCH or time.monotonic() - started > 25):
                            warnings.add("resource_exhausted")
                            break
                        record = yield from self._load(scope, name, thread.native_id, adapter=adapter, thread=thread)
                        if agent and record.thread.agent.casefold() != agent:
                            continue
                        if unified(self.policy) and count >= MAX_SEARCH:
                            warnings.add("resource_exhausted")
                            break
                        count += 1
                        if record.projection.warnings:
                            warnings.add("coverage_unverified")
                        found = self._matching(self._summary(scope, record), record, needle)
                        if found is not None:
                            voucher = (name, thread.native_id, record.proof)
                            grouped.setdefault(record.canonical, []).append((found, voucher))
                    except AccessError as error:
                        if error.code not in DENIED:
                            warnings.add(error.code if error.code in ERROR_CODES else "coverage_unverified")
                    yield {"phase": "candidate_scan"}
                if adapter is not None:
                    warnings.update(code for code in getattr(adapter, "warnings", ()) if code in ERROR_CODES)
                    if unified(self.policy) and not getattr(adapter, "project_partition_complete", False):
                        warnings.add("association_unverified")
            except AccessError as error:
                warnings.add(error.code if error.code in ERROR_CODES else "coverage_unverified")
            report = {"source_id": name, "coverage_complete": not warnings, "warnings": sorted(warnings)}
            if unified(self.policy):
                report["state"] = coverage_status(warnings)
            reports.append(report)
        rows = []
        for canonical, found in grouped.items():
            found.sort(key=lambda item: (item[0]["source_id"] != canonical[0], item[0]["source_id"],
                                         item[0]["stable_thread_id"]))
            summary, _ = found[0]
            unique = {}
            for row, voucher in found:
                unique.setdefault(row["source_id"], voucher)
            summary["matched_sources"] = sorted(unique)
            rows.append((summary, tuple(unique.values()), _digest(canonical),
                         summary["source_id"] == canonical[0]))
        rows.sort(key=lambda item: (item[0]["updated_at"], item[0]["stable_thread_id"]), reverse=True)
        return rows, reports

    def _find(self, project_id, query, agent, source_id, cursor, limit, actor, policy_actor):
        integer(limit, "limit", 1, 20)
        if not isinstance(query, str) or len(query) > 200 or (agent and not AGENT.fullmatch(agent)) or (source_id and not SOURCE.fullmatch(source_id)):
            raise _error("Invalid history search parameters.", "invalid_arguments")
        scope = self._configuration(project_id, actor, policy_actor)
        params = [query, agent, source_id, limit]
        self._expire(self.find_cache)
        if cursor:
            token = self._resume(cursor, "find", scope, params)
            cache_id, start = token["key"], token["offset"]
            cached = self.find_cache.get(cache_id)
            if cached is None:
                raise _restart()
            _, rows, reports = cached
        else:
            rows, reports = yield from self._search(scope, query, agent.casefold(), source_id)
            cache_id, start = secrets.token_hex(16), 0
        end = min(start + limit, len(rows))
        more = end < len(rows)
        if more:
            self._store(self.find_cache, MAX_FIND_CACHE, cache_id, (time.monotonic(), rows, reports))
        page = rows[start:end]
        complete = all(report["coverage_complete"] for report in reports)
        return Prepared({"status": "ready" if reports else "no_enabled_sources", "projection_version": VERSION,
                         "threads": [summary for summary, _, _, _ in page], "coverage": reports,
                         "coverage_complete": complete and bool(reports), "has_more": more,
                         "next_cursor": self._token(scope, "find", key=cache_id, offset=end, parameters=params) if more else None},
                        scope.key, ("find", project_id, tuple(voucher for _, vouchers, _, _ in page for voucher in vouchers)))

    def _scan_agent_source(self, project_id, query, agent, source_id, cursor, actor, policy_actor, search_key=""):
        if (cursor or not isinstance(query, str) or len(query) > 200
                or (agent and not AGENT.fullmatch(agent)) or not SOURCE.fullmatch(source_id)):
            raise _error("Invalid source search parameters.", "invalid_arguments")
        scope = self._configuration(project_id, actor, policy_actor)
        rows, reports = yield from self._search(scope, query, agent.casefold(), source_id)
        results = []
        payload_bytes = 0
        report = reports[0]
        for summary, vouchers, canonical, primary in rows:
            entry = {"summary": summary, "canonical": canonical, "primary": primary, "vouchers": vouchers}
            payload_bytes += len(_json(entry))
            if len(results) >= 64 or payload_bytes > 152 * 1024:
                report = {**report, "coverage_complete": False,
                          "warnings": sorted(set(report["warnings"]) | {"resource_exhausted"})}
                if unified(self.policy):
                    report["state"] = coverage_status(report["warnings"])
                break
            results.append(entry)
        return Prepared({"status": "ready", "rows": results, "coverage": report}, scope.key,
                        ("find", project_id, ()))

    def _validate_agent_hits(self, project_id, source_id, vouchers, cursor, actor, policy_actor, search_key=""):
        if cursor or not SOURCE.fullmatch(source_id) or not isinstance(vouchers, str) or len(vouchers) > 48 * 1024:
            raise _error("Invalid source validation parameters.", "invalid_arguments")
        try:
            evidence = json.loads(vouchers)
            if (not isinstance(evidence, list) or len(evidence) > 20 or any(
                    not isinstance(v, list) or len(v) != 3 or v[0] != source_id
                    or not isinstance(v[1], str) or not IDENTIFIER.fullmatch(v[1])
                    or not isinstance(v[2], str) or not HEX.fullmatch(v[2]) for v in evidence)):
                raise ValueError()
        except (ValueError, TypeError):
            raise _error("Invalid source validation parameters.", "invalid_arguments") from None
        scope = self._configuration(project_id, actor, policy_actor)
        yield {"phase": "authorization_check"}
        return Prepared({"status": "ready"}, scope.key, ("find", project_id, tuple(evidence)))

    @staticmethod
    def _expire(cache):
        for key, record in tuple(cache.items()):
            if time.monotonic() - record[0] > TTL:
                cache.pop(key)

    @staticmethod
    def _store(cache, capacity, cache_id, value):
        cache.pop(cache_id, None)
        while len(cache) >= capacity:
            cache.pop(next(iter(cache)))
        cache[cache_id] = value

    @staticmethod
    def _message_id(record, message):
        canonical = record.canonical[-2:]
        return "m-" + _digest((canonical, message.position))[:32]

    def _selected(self, record, view, turn_id):
        if view == "all":
            return record.entries
        known = [message.turn_id for message in record.entries]
        if not known or any(not value for value in known):
            raise _error("The source has no reliable turn boundaries; use view=all.", "turn_unavailable")
        chosen = turn_id if view == "turn" else known[-1]
        if chosen not in known:
            raise _error("The selected thread has no matching turn.", "turn_unavailable")
        return tuple(message for message in record.entries if message.turn_id == chosen)

    @staticmethod
    def _message_fingerprint(entries):
        return _digest([(m.position, m.role, m.text, m.timestamp, m.turn_id) for m in entries])

    def _same_snapshot(self, scope, frozen, current):
        if (frozen.canonical != current.canonical or frozen.contexts != current.contexts
                or frozen.identity != current.projection.identity):
            raise _restart()
        if unified(self.policy) and frozen.display_metadata != current.display_metadata:
            raise _restart()
        if frozen.revision == current.projection.revision and frozen.fingerprint == current.fingerprint:
            if unified(self.policy) and frozen.updated_at != current.thread.updated_at:
                raise _restart()
            return
        prefix = frozen.prefix
        if (prefix is None or len(current.entries) < frozen.count
                or self._message_fingerprint(current.entries[:frozen.count]) != frozen.fingerprint):
            raise _restart()
        if unified(self.policy):
            appended = current.projection.prefix
            if appended is None or appended[0] != prefix[0] or appended[1] <= prefix[1]:
                raise _restart()
        source_id = frozen.canonical[0]
        if source_id == "codex":
            raise _restart()
        source = self._source(scope, source_id)
        root = self.policy.make_root(source_id, source)
        name, remaining, previous = prefix
        state = hashlib.sha256()
        with root.open(name) as stream:
            while remaining:
                chunk = stream.read(min(remaining, 256 * 1024))
                if not chunk:
                    raise _restart()
                state.update(chunk)
                remaining -= len(chunk)
        if not hmac.compare_digest(state.hexdigest(), previous):
            raise _restart()

    def _page(self, record, chosen, position, offset, limit, max_chars):
        page, used = [], 0
        remaining = max_chars
        while position < len(chosen) and len(page) < limit and remaining > 0:
            message = chosen[position]
            count = min(remaining, len(message.text) - offset)
            result = {"message_id": self._message_id(record, message), "role": message.role,
                      "timestamp": message.timestamp or None, "turn_id": message.turn_id or None,
                      "source_position": message.position, "part_offset": offset,
                      "total_characters": len(message.text)}
            while count:
                end = offset + count
                item = {**result, "text": message.text[offset:end], "has_more_text": end < len(message.text)}
                encoded = len(_json(item))
                if used + encoded <= MAX_PAGE_BYTES:
                    break
                count //= 2
            if not count:
                break
            page.append(item)
            used += encoded
            remaining -= count
            if end < len(message.text):
                offset = end
                break
            position, offset = position + 1, 0
        return page, position, offset

    def _read(self, thread_ref, view, turn_id, cursor, limit, max_chars, actor, policy_actor):
        integer(limit, "limit", 1, 50)
        integer(max_chars, "max_chars", 100, 40_000)
        if view not in {"all", "latest_turn", "turn"} or bool(turn_id) != (view == "turn") or (turn_id and not LOCATOR.fullmatch(turn_id)):
            raise _error("Invalid history turn selection.", "invalid_arguments")
        ref = self._verify(thread_ref, "thread")
        if ref["actor"] != actor:
            raise _deny()
        project_id = ref["project"]
        scope = self._configuration(project_id, actor, policy_actor)
        if ref["scope"] != scope.key:
            raise _restart()
        source_id, native_id = ref["source"], ref["native"]
        params = [_digest(thread_ref), view, turn_id, limit, max_chars]
        self._expire(self.read_cache)
        if cursor:
            token = self._resume(cursor, "read", scope, params)
            cache_id, position, offset = token["key"], token["position"], token["offset"]
            cached = self.read_cache.get(cache_id)
            if cached is None:
                raise _restart()
            _, frozen = cached
        else:
            frozen = yield from self._load(scope, source_id, native_id)
            cache_id, position, offset = secrets.token_hex(16), 0, 0
        if unified(self.policy) and ref.get("snapshot") != frozen.proof:
            raise _restart()
        chosen = self._selected(frozen, view, turn_id)
        page, position, offset = self._page(frozen, chosen, position, offset, limit, max_chars)
        more = position < len(chosen)
        if more:
            self.read_cache.pop(cache_id, None)
            while self.read_cache and sum(item.size for _, item in self.read_cache.values()) + frozen.size > MAX_READ_BYTES:
                self.read_cache.pop(next(iter(self.read_cache)))
            self._store(self.read_cache, MAX_READ_CACHE, cache_id, (time.monotonic(), frozen))
        return Prepared({"status": "ready", "projection_version": VERSION, "thread": self._summary(scope, frozen),
                         "entries": page, "coverage_complete": not frozen.projection.warnings,
                         "warnings": list(frozen.projection.warnings), "snapshot_sha256": frozen.fingerprint,
                         "source_revision": _digest((frozen.canonical, frozen.projection.revision)),
                         "has_more": more, "next_cursor": self._token(scope, "read", key=cache_id, position=position,
                                                                   offset=offset, parameters=params) if more else None},
                        scope.key, ("read", project_id, SnapshotProof.from_record(frozen)))

    def operation_iter(self, operation, arguments):
        if operation == "find_agent_threads":
            return (yield from self._find(**arguments))
        if operation == "read_agent_thread":
            return (yield from self._read(**arguments))
        if operation == "scan_agent_source":
            return (yield from self._scan_agent_source(**arguments))
        if operation == "validate_agent_hits":
            return (yield from self._validate_agent_hits(**arguments))
        raise _error("Unknown history operation.", "invalid_arguments")

    def revalidate_result_iter(self, operation, arguments, result):
        if not isinstance(result, Prepared):
            raise _restart()
        kind, project_id, evidence = result.vouchers
        scope = self._configuration(project_id, arguments["actor"], arguments["policy_actor"])
        if scope.key != result.scope:
            raise _restart()
        if kind == "find":
            for source, thread, proof in evidence:
                current = yield from self._load(scope, source, thread)
                if current.proof != proof:
                    raise _restart()
                yield {"phase": "authorization_check"}
        else:
            current = yield from self._load(scope, evidence.source_id, evidence.native_id)
            self._same_snapshot(scope, evidence, current)
        if self._configuration(project_id, arguments["actor"], arguments["policy_actor"]).key != scope.key:
            raise _restart()
        # Only vouchers in this page were reloaded in this fresh scope. Internal
        # scans, dropped matches and other pages contribute no delivery conditions.
        result.delivery_aliases = sorted(scope.delivery_aliases)
        return result


def build_core(spec):
    if unified(spec["agent_policy"]):
        catalog = Catalog.from_policy(spec["agent_policy"])
    elif spec["catalog_path"]:
        catalog = Catalog.from_config(spec["catalog_path"])
    else:
        catalog = Catalog([Project(**{**data, "root": Path(data["root"])}) for data in spec["projects"]])
    policy = spec["agent_policy"]
    # A supervised restart may follow a kill during an incomplete SQLite copy.
    clear_snapshot_copies(policy.scratch, policy.scratch_identity)
    legacy = HistoryAccess(spec["config_path"], catalog=catalog, unified_policy=policy) if unified(policy) else HistoryAccess(spec["config_path"], catalog=catalog)
    return AgentHistoryCore(policy, catalog, legacy, spec["agent_key"])
