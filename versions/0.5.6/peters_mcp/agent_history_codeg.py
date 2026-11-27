"""Codeg 0.45.0 SQLite index and Codeg-owned ACP v1 transcript reader."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePath
import re

from .agent_history_source import Message, Projection, SourceRoot, Thread
from .catalog import AccessError

_DATABASE = "codeg.db"
_COMPONENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}\Z")
_INDEX_ID = re.compile(r"[1-9][0-9]{0,9}\Z")
_ALIASES = {"codex": "codex", "deepseek": "deepseek_harness"}
_ACP_DIRECTORIES = {
    "zcode": "codeg-zcode-acp",
    "trae": "codeg-trae-cli",
    "command_code": "codeg-command-code",
    "minimax_code": "codeg-minimax-code",
}
_RESERVED = set(_ACP_DIRECTORIES.values()) | {
    "claude_code", "codex", "open_code", "gemini", "open_claw", "cline",
    "hermes", "code_buddy", "kimi_code", "pi", "grok", "cursor", "deepseek",
    "qoder", "antigravity", "kiro",
}
_VISIBLE_INDEX = """
    SELECT c.id, c.title, c.updated_at, c.agent_type, c.external_id, c.origin_cwd,
           f.path, f.parent_id, p.path
    FROM conversation AS c
    JOIN folder AS f ON f.id = c.folder_id
    LEFT JOIN folder AS p ON p.id = f.parent_id AND p.deleted_at IS NULL
        AND p.kind = 'regular' AND p.parent_id IS NULL
    WHERE c.kind = 'regular' AND c.deleted_at IS NULL AND c.parent_id IS NULL
        AND f.kind = 'regular' AND f.deleted_at IS NULL AND c.external_id IS NOT NULL
        AND (c.agent_type IN ('codex', 'deepseek', 'zcode', 'trae', 'command_code', 'minimax_code')
             OR c.agent_type GLOB 'custom:*')
"""
_UNSUPPORTED_TYPES_QUERY = """
    SELECT DISTINCT c.agent_type
    FROM conversation AS c
    JOIN folder AS f ON f.id = c.folder_id
    WHERE c.kind = 'regular' AND c.deleted_at IS NULL AND c.parent_id IS NULL
        AND f.kind = 'regular' AND f.deleted_at IS NULL AND c.external_id IS NOT NULL
        AND NOT (c.agent_type IN ('codex', 'deepseek', 'zcode', 'trae', 'command_code', 'minimax_code')
                 OR c.agent_type GLOB 'custom:*')
"""
_SAFE_AGENT_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_ROUTE_PREFIX = '{"kind":"codeg_internal_'
_ROUTE_SEPARATOR = "\x1e"
_MAX_THREADS = 2_048
_MAX_CHAIN = 16
_MAX_LINE = 8 * 1024 * 1024
_MAX_TRANSCRIPT = 64 * 1024 * 1024
_MAX_TEXT = 8 * 1024 * 1024
_MAX_RECORDS = 50_000


def _unsupported():
    return AccessError("The Codeg history format is unsupported.", code="unsupported_format")


def _unavailable():
    return AccessError("The Codeg conversation source is unavailable.", code="source_unavailable")


def _unstable():
    return AccessError("The Codeg conversation changed during the read.", code="waiting_source_stable")


def _budget():
    return AccessError("The Codeg source exceeds its read budget.", code="resource_exhausted")


def _component(value):
    return isinstance(value, str) and _COMPONENT.fullmatch(value) is not None


def _index_id(value):
    if isinstance(value, str) and _INDEX_ID.fullmatch(value) and int(value) <= 2**31 - 1:
        return int(value)
    return None


def _registry_directory(agent):
    if agent in _ACP_DIRECTORIES:
        return _ACP_DIRECTORIES[agent]
    if agent.startswith("custom:"):
        registry_id = agent.removeprefix("custom:")
        if _component(registry_id) and len(registry_id) <= 64 and registry_id not in _RESERVED:
            return registry_id
    return None


def _cwd(value):
    return (
        isinstance(value, str) and len(value) <= 4096 and value.startswith("/")
        and "\x00" not in value and ".." not in PurePath(value).parts
    )


def _timestamp(value):
    try:
        if type(value) is int and value >= 0:
            return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
        if isinstance(value, str) and len(value) <= 64:
            parsed = datetime.fromisoformat(value)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        pass
    return ""


def _route_safe_text(text):
    """Discard transport-only suffixes, including a truncated frame in a title."""
    start = text.find(_ROUTE_SEPARATOR)
    marker = text.find(_ROUTE_PREFIX)
    candidates = [offset for offset in (start, marker) if offset >= 0]
    if candidates:
        return text[:min(candidates)].rstrip()
    return text


def _title(value):
    if not isinstance(value, str):
        return ""
    text = _route_safe_text(value[:512])
    # Codeg may have stored a sidebar title truncated partway through a marker.
    truncated = text.rstrip(".")
    for length in range(len(_ROUTE_PREFIX) - 1, len('{"kind":"c') - 1, -1):
        if truncated.endswith(_ROUTE_PREFIX[:length]):
            return truncated[:-length].rstrip()
    return text


def _thread(row):
    if row is None:
        return None
    row_id, title, updated_at, agent, external_id, origin, folder, parent_id, parent = row
    if type(row_id) is not int or _index_id(str(row_id)) is None or not isinstance(agent, str):
        return None
    provider = _ALIASES.get(agent)
    if not _component(external_id):
        if provider != "deepseek_harness" or not isinstance(external_id, str) or len(external_id) > 800:
            return None
        # Codeg indexes DeepSeek by the directory basename. The Harness
        # adapter's authenticated identity comes from the session header.
        from .agent_history_deepseek import decode_directory_id
        external_id = decode_directory_id(external_id)
        if external_id is None:
            return None
    if provider is None and _registry_directory(agent) is None:
        return None
    candidates = (folder, origin, parent)
    contexts = tuple(dict.fromkeys(cwd for cwd in candidates if _cwd(cwd)))
    contexts_complete = _cwd(folder) and (origin is None or _cwd(origin)) and (
        parent_id is None or _cwd(parent)
    )
    return Thread(
        str(row_id), _title(title), _timestamp(updated_at), contexts=contexts,
        context_complete=contexts_complete, agent=provider or agent,
        surface="codeg_native_link" if provider else "codeg_acp",
        native_link=(provider, external_id) if provider else None,
    )


def _json_line(line):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    try:
        value = json.loads(line.decode("utf-8"), object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise _unsupported() from None


def _text_block(block):
    if not isinstance(block, dict) or block.get("type") != "text":
        return ""
    annotations = block.get("annotations")
    if annotations is not None:
        if not isinstance(annotations, dict):
            return ""
        audience = annotations.get("audience")
        if audience is not None and (not isinstance(audience, list) or "user" not in audience):
            return ""
    text = block.get("text")
    if not isinstance(text, str) or not text:
        return ""
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeError:
        raise _unsupported() from None
    return text


def _stamp(stream):
    info = os.fstat(stream.fileno())
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _transcript_path(directory, native):
    if not _component(directory) or not _component(native):
        raise _unsupported()
    return f"acp-transcripts/{directory}/{native}.jsonl"


class _TranscriptBudget:
    def __init__(self):
        self.remaining_bytes = _MAX_TRANSCRIPT
        self.remaining_records = _MAX_RECORDS
        self.remaining_text = _MAX_TEXT

    def add_record(self):
        self.remaining_records -= 1
        if self.remaining_records < 0:
            raise _budget()

    def add_text(self, text):
        self.remaining_text -= len(text)
        if self.remaining_text < 0:
            raise _budget()


class _TranscriptProjection:
    """Only locally sent prompt records prove provenance for ACP dialogue."""

    def __init__(self, native, budget):
        self.session_key = hashlib.sha256(native.encode("ascii")).hexdigest()[:32]
        self.budget = budget
        self.messages = []
        self.warnings = set()
        self.turn_id = ""
        self.pending_position = ""
        self.pending_timestamp = ""
        self.pending_chunks = []
        self.prompt_just_recorded = False
        self.unverified_replay = False
        self.last_ms = 0
        self.ordered = True

    def _flush(self):
        if self.pending_chunks:
            text = _route_safe_text("".join(self.pending_chunks))
            if text:
                self.messages.append(Message(
                    "assistant", text, self.pending_position, self.pending_timestamp, self.turn_id,
                ))
        self.pending_chunks.clear()

    def record(self, record, line_no):
        kind, raw_time, payload = record.get("k"), record.get("t"), record.get("p")
        if type(raw_time) is not int or raw_time < 0:
            raise _unsupported()
        self.ordered = self.ordered and raw_time >= self.last_ms
        self.last_ms = max(self.last_ms, raw_time)
        position = f"acp:{self.session_key}:{line_no}"
        timestamp = _timestamp(raw_time)
        if kind == "prompt":
            if not isinstance(payload, list):
                raise _unsupported()
            self._flush()
            self.turn_id = position
            self.prompt_just_recorded = True
            text = _route_safe_text("".join(_text_block(block) for block in payload))
            if text:
                self.budget.add_text(text)
                self.messages.append(Message("user", text, position, timestamp, self.turn_id))
            return
        if kind == "turn_end":
            if not isinstance(payload, dict) or not isinstance(payload.get("stopReason"), str):
                raise _unsupported()
            self._flush()
            self.turn_id = ""
            self.prompt_just_recorded = False
            return
        if kind != "update" or not isinstance(payload, dict):
            raise _unsupported()
        update = payload.get("sessionUpdate")
        if update == "user_message_chunk":
            # A replay can include fork history and agent-authored user-shaped
            # chunks. These are indistinguishable from user messages on disk.
            if not self.prompt_just_recorded:
                self._flush()
                self.turn_id = ""
                self.unverified_replay = True
            return
        if update == "agent_message_chunk":
            self.prompt_just_recorded = False
            text = _text_block(payload.get("content"))
            if not text:
                return
            if not self.turn_id:
                self.unverified_replay = True
                return
            self.budget.add_text(text)
            if not self.pending_chunks:
                self.pending_position, self.pending_timestamp = position, timestamp
            self.pending_chunks.append(text)
            return
        if update in {"agent_thought_chunk", "tool_call", "tool_call_update", "plan"}:
            self._flush()
            return
        if not isinstance(update, str):
            raise _unsupported()
        if update not in {
            "current_mode_update", "config_option_update", "available_commands_update",
            "session_info_update", "usage_update",
        }:
            self.warnings.add("unknown_acp_update_omitted")

    def finish(self):
        if self.pending_chunks:
            self.warnings.add("unclosed_acp_output_omitted")
        if self.unverified_replay:
            self.warnings.add("unverified_acp_history_omitted")


def _read_transcript(root, agent, directory, native, budget):
    relative = _transcript_path(directory, native)
    identity = root.identity_for(relative)
    digest = hashlib.sha256()
    projection = _TranscriptProjection(native, budget)
    with root.open(relative) as stream:
        stamp = _stamp(stream)
        remaining = stamp[0]
        if remaining > budget.remaining_bytes:
            raise _budget()
        budget.remaining_bytes -= remaining
        header = None
        line_no = 0
        committed_bytes = 0
        while remaining:
            line = stream.readline(min(remaining, _MAX_LINE + 1))
            remaining -= len(line)
            line_no += 1
            budget.add_record()
            if len(line) > _MAX_LINE:
                raise _budget()
            if not line:
                raise _unstable()
            if not line.endswith(b"\n"):
                projection.warnings.add("incomplete_acp_tail")
                break
            value = _json_line(line)
            digest.update(line)
            committed_bytes += len(line)
            if header is None:
                header = value
                if (header.get("kind") != "header" or type(header.get("v")) is not int
                        or header["v"] != 1 or header.get("agent") != agent
                        or header.get("session_id") != native or not _cwd(header.get("cwd"))
                        or type(header.get("started_at_ms")) is not int or header["started_at_ms"] < 0
                        or (header.get("continues_from") is not None
                            and not _component(header["continues_from"]))):
                    raise _unsupported()
                projection.last_ms = header["started_at_ms"]
            else:
                projection.record(value, line_no)
        if _stamp(stream) != stamp:
            raise _unstable()
    if root.identity_for(relative) != identity:
        raise _unstable()
    if header is None:
        raise _unavailable()
    projection.finish()
    return header, projection, identity, (relative, committed_bytes, digest.hexdigest())


class Adapter:
    project_partition_complete = True

    def __init__(self, root: SourceRoot, version: str):
        if version != "0.45.0":
            raise _unsupported()
        self.root = root
        self.warnings = ()
        self.unsupported_agent_types = ()

    def discover(self):
        with self.root.sqlite(_DATABASE) as db:
            rows = db.execute(_VISIBLE_INDEX + " ORDER BY c.updated_at DESC, c.id ASC LIMIT ?", (_MAX_THREADS + 1,))
            for index, row in enumerate(rows):
                if index == _MAX_THREADS:
                    raise _budget()
                thread = _thread(row)
                if thread is not None:
                    yield thread

    def discover_project(self, project_roots, *, explicit_ids=(), excluded_roots=(), denied_ids=()):
        """Select project-indexed candidates before charging the body-read budget."""
        self.warnings = ()
        self.unsupported_agent_types = ()
        terms, values = [], []
        for root in project_roots:
            root = str(root).rstrip("/")
            prefix = root + "/"
            terms.append("(f.path = ? OR substr(f.path, 1, ?) = ?)")
            values.extend((root, len(prefix), prefix))
        predicate = "(" + " OR ".join(terms) + ")" if terms else "0"
        for root in excluded_roots:
            root = str(root).rstrip("/")
            prefix = root + "/"
            predicate += " AND NOT (f.path = ? OR substr(f.path, 1, ?) = ?)"
            values.extend((root, len(prefix), prefix))
        ids = tuple(value for native in explicit_ids if (value := _index_id(native)) is not None)
        if ids:
            predicate = "(" + predicate + ") OR c.id IN (" + ",".join("?" for _ in ids) + ")"
            values.extend(ids)
        if not terms and not ids:
            return
        denied = tuple(value for native in denied_ids if (value := _index_id(native)) is not None)
        if denied:
            predicate = "(" + predicate + ") AND c.id NOT IN (" + ",".join("?" for _ in denied) + ")"
            values.extend(denied)
        warnings = set()
        unsupported = set()
        with self.root.sqlite(_DATABASE) as db:
            for (agent_type,) in db.execute(_UNSUPPORTED_TYPES_QUERY + " AND (" + predicate + ")", values):
                if isinstance(agent_type, str) and _SAFE_AGENT_TYPE.fullmatch(agent_type):
                    unsupported.add(agent_type)
                else:
                    unsupported.add("unsupported")
            rows = db.execute(_VISIBLE_INDEX + " AND (" + predicate
                              + ") ORDER BY c.updated_at DESC, c.id ASC", values)
            for row in rows:
                thread = _thread(row)
                if thread is not None:
                    yield thread
                else:
                    warnings.add("association_unverified")
        if unsupported:
            warnings.add("coverage_unverified")
        self.unsupported_agent_types = tuple(sorted(unsupported))
        self.warnings = tuple(sorted(warnings))

    def describe(self, native_id: str):
        row_id = _index_id(native_id)
        if row_id is None:
            return None
        with self.root.sqlite(_DATABASE) as db:
            row = db.execute(_VISIBLE_INDEX + " AND c.id = ?", (row_id,)).fetchone()
        return _thread(row)

    def snapshot(self, thread: Thread) -> Projection:
        row_id = _index_id(thread.native_id)
        if row_id is None or thread.native_link is not None:
            raise _unavailable()
        database_identity = self.root.identity_for(_DATABASE)
        with self.root.sqlite(_DATABASE) as db:
            row = db.execute(_VISIBLE_INDEX + " AND c.id = ?", (row_id,)).fetchone()
            if row is None:
                raise _unavailable()
            if _thread(row) != thread:
                raise _unstable()
            agent, native = row[3], row[4]
            chain, contexts, ancestors = self._chain(db, row_id, agent, native)
        if self.root.identity_for(_DATABASE) != database_identity:
            raise _unstable()
        messages, warnings, identities, hashes = [], set(), [database_identity], []
        complete = thread.context_complete
        for _, part, identity, prefix in reversed(chain):
            messages.extend(part.messages)
            warnings.update(part.warnings)
            identities.append(identity)
            hashes.append(prefix[2])
            complete = complete and not part.unverified_replay
        prefix = chain[0][3] if len(chain) == 1 else None
        revision = prefix[2] if prefix is not None else self._digest(hashes)
        return Projection(
            tuple(messages), revision, self._digest(identities),
            contexts=tuple(dict.fromkeys(contexts)), ancestors=tuple(dict.fromkeys(ancestors)),
            context_complete=complete, warnings=tuple(sorted(warnings)), prefix=prefix,
            origin_ns=min(part[0]["started_at_ms"] for part in chain) * 1_000_000,
            last_ns=(max(part[1].last_ms for part in chain) + 1) * 1_000_000 - 1
                    if all(part[1].ordered for part in chain) else None,
        )

    @staticmethod
    def _digest(values):
        return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()

    def _chain(self, db, row_id, agent, native):
        directory = _registry_directory(agent)
        budget = _TranscriptBudget()
        chain, contexts, ancestors, seen = [], [], [], set()
        while native is not None:
            if native in seen or len(chain) == _MAX_CHAIN:
                raise _unsupported()
            if chain:
                self._check_ancestor_index(db, row_id, agent, native, contexts, ancestors)
            seen.add(native)
            part = _read_transcript(self.root, agent, directory, native, budget)
            chain.append(part)
            contexts.append(part[0]["cwd"])
            native = part[0].get("continues_from")
        return chain, contexts, ancestors

    @staticmethod
    def _check_ancestor_index(db, row_id, agent, native, contexts, ancestors):
        ancestors.append(native)
        rows = db.execute(
            "SELECT id FROM conversation WHERE agent_type = ? AND external_id = ? AND id <> ? LIMIT 2",
            (agent, native, row_id),
        ).fetchall()
        if not rows:
            return
        if len(rows) != 1:
            raise _unavailable()
        ancestor = _thread(db.execute(_VISIBLE_INDEX + " AND c.id = ?", rows[0]).fetchone())
        if ancestor is None or not ancestor.context_complete:
            raise _unavailable()
        contexts.extend(ancestor.contexts)
        ancestors.append(ancestor.native_id)
