"""Conservative public projection of locally persisted Codex rollout records.

This module never returns raw records, instructions, reasoning, tool arguments,
runtime context, or attachments. Known public text is retained, not summarized.
"""

from collections import Counter, defaultdict, deque
import hashlib
import io
import json
import re

from .catalog import AccessError

PUBLIC_PHASES = {"commentary", "final", "final_answer"}
TEXT_BLOCKS = {"text", "Text", "input_text", "output_text"}
ATTACHMENT_BLOCKS = {"image", "input_image", "output_image", "audio", "input_audio", "output_audio", "file", "input_file"}
TOOL_TYPES = {"CommandExecution", "McpToolCall", "FileChange", "FunctionCallOutput"}
IGNORED_RECORDS = {
    "world_state", "turn_context", "token_usage_record", "inter_agent_communication_metadata",
}
IGNORED_EVENTS = {"token_count", "thread_settings_applied", "agent_reasoning", "agent_message", "user_message"}
IGNORED_ITEMS = {"Reasoning", "SubAgentActivity", "Extension"}
INTERNAL_TAGS = (
    "environment_context", "user_instructions", "INSTRUCTIONS", "recommended_plugins",
    "skills_instructions", "permissions_instructions", "app-context", "system", "developer",
    "system-reminder", "developer_instructions",
)
MAX_PUBLIC_CHARS = 16 * 1024 * 1024
SENSITIVE_SOURCE = re.compile(
    r"(?i)(?:AGENTS\.md|CLAUDE\.md|SKILL\.md|\.codex(?:[/\\]|\b)|CODEX_HOME|state_\d+\.sqlite|history\.jsonl|"
    r"(?:^|[/\\\s])\.env(?:\b|\.)|credentials|secrets|cookies|\.pem\b|private[_-]?key)"
)
PRIVATE_DUMP = re.compile(r'(?i)["\'](?:base_instructions|developer_instructions|system_prompt|'
                          r'encrypted_content|raw_content|summary_text)["\']\s*:|'
                          r'["\']role["\']\s*:\s*["\'](?:system|developer)["\']')
HISTORY_TOOL = re.compile(r"(?i)(?:thread|conversation|session|history|reasoning|instructions|config|credential|cookie|secret)")
CREDENTIAL_ENUMERATION = re.compile(r"(?i)(?:\bprintenv\b|(?:^|[;&|])\s*env(?:\s|$)|os\.environ|process\.env|security\s+find-|\bcodex\b)")


def sanitize(text, *, tool=False):
    """Best-effort known-secret removal; this is explicitly NOT universal DLP."""
    if not isinstance(text, str):
        return "", 0
    redactions = 0
    if tool and PRIVATE_DUMP.search(text):
        return "[OMITTED: output contains internal instruction/reasoning fields]", 1
    for tag in INTERNAL_TAGS:
        # Find an opener once, then its first closer. Unlike a .*? expression,
        # repeated unmatched openers never rescan the remaining suffix.
        opener = re.compile(r"<" + re.escape(tag) + r"(?=\s|>)", re.I)
        closer = re.compile(r"</" + re.escape(tag) + r">", re.I)
        parts, position = [], 0
        while True:
            opening = opener.search(text, position)
            if opening is None:
                break
            end = text.find(">", opening.end())
            if end < 0:
                break  # An incomplete opening token was never a valid wrapper.
            closing = closer.search(text, end + 1)
            parts.extend((text[position:opening.start()], "[OMITTED: internal context]"))
            redactions += 1
            position = closing.end() if closing is not None else len(text)
            if closing is None:
                break
        if parts:
            parts.append(text[position:])
            text = "".join(parts)
    patterns = (
        (r"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END (?:[A-Z ]*PRIVATE KEY)-----", "[REDACTED PRIVATE KEY]"),
        (r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{15,}|AKIA[A-Z0-9]{16})\b", "[REDACTED CREDENTIAL]"),
        (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]"),
        (r"(?im)(\b(?:proxy-authorization|authorization|cookie|set-cookie)\s*:\s*)([^\r\n]+)", r"\1[REDACTED HEADER]"),
        (r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED AUTHORIZATION]"),
        (r'''(?im)(["']?\b(?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|SECRET_ACCESS_KEY|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|PASSWORD|PASSPHRASE|AUTH_TOKEN|TOKEN|SECRET)["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;}]+)''', r"\1[REDACTED]"),
        (r'''(?im)(["']?\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|authorization|cookie|token|secret)["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;}]+)''', r"\1[REDACTED]"),
        (r"(?i)(--(?:api-key|token|password|secret|cookie|authorization)\s+)(\S+)", r"\1[REDACTED]"),
        (r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@"),
    )
    for pattern, replacement in patterns:
        text, count = re.subn(pattern, replacement, text)
        redactions += count
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text, redactions


def content_text(content):
    if isinstance(content, str):
        return content, 0
    if not isinstance(content, list):
        return "", 1
    blocks, omitted = [], 0
    for block in content:
        if isinstance(block, dict) and block.get("type") in tuple(TEXT_BLOCKS) and isinstance(block.get("text"), str):
            blocks.append(block["text"])
        else:
            omitted += 1
    return "\n".join(blocks), omitted


def public_message(item, line, turn_id, timestamp, source):
    role = item.get("role") if source == "response_item" else (
        "user" if item.get("type") == "UserMessage" else "assistant"
    )
    if not isinstance(role, str) or role not in {"user", "assistant"}:
        return None
    phase = item.get("phase")
    if role == "assistant" and (not isinstance(phase, str) or phase not in PUBLIC_PHASES or
            (item.get("channel") is not None and item.get("channel") not in tuple(PUBLIC_PHASES))):
        return None
    content = item.get("content")
    text, attachments = content_text(content)
    unknown_blocks = 0
    if isinstance(content, list):
        unknown_blocks = sum(not isinstance(b, dict) or b.get("type") not in tuple(TEXT_BLOCKS | ATTACHMENT_BLOCKS)
                             or (b.get("type") in tuple(TEXT_BLOCKS) and not isinstance(b.get("text"), str)) for b in content)
    elif not isinstance(content, str):
        unknown_blocks = 1
    text, redactions = sanitize(text)
    # Generated context-only user envelopes are not public user requests.
    remainder = re.sub(r"\[OMITTED: internal context\]|# AGENTS\.md instructions", "", text).strip()
    if not remainder and not attachments:
        return None
    return {"kind": "message", "message_id": "m-" + str(line), "turn_id": turn_id,
            "role": role, "phase": phase if role == "assistant" else "user",
            "timestamp": timestamp, "text": text, "redactions": redactions,
            "omitted_attachments": attachments, "source_line": line, "record_source": source,
            "unknown_content_blocks": unknown_blocks,
            "_native_id": item.get("id") if isinstance(item.get("id"), str) else None, "_source": source}


class ProjectionBuilder:
    """Incremental projection; callers bound raw records and authenticate sources.

    No unfiltered tool payload is retained by default. The item bound includes
    both mirrors before deduplication, tool references and unique turn IDs,
    not only final output.
    """

    def __init__(self, expected_id, retain_tool_payloads=False, max_items=50000, include_tool_refs=True):
        if type(max_items) is not int or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        self.expected_id = expected_id
        self.retain_tool_payloads = retain_tool_payloads
        self.include_tool_refs = include_tool_refs
        self.max_items = max_items
        self.warnings = Counter()
        self.messages, self.events, self.tools = [], [], {}
        self.turn_id, self.meta = None, None
        self._turns, self._ambiguous_turns = {}, set()
        self.latest_turn_id = self._active_turn = None
        self._turn_segment = 0
        self._has_turn_boundary = False
        self.last_state = "unknown"
        self.total_chars = self.source_lines = 0
        self.seen_meta, self.permitted_meta = set(), set()
        self._finished = False
        self._failure = None

    def warn(self, reason, count=1):
        self.warnings[reason] += count

    def _check_items(self):
        if len(self.messages) + len(self.events) + len(self.tools) + len(self._turns) > self.max_items:
            self._failure = AccessError("History projection item budget exceeded; no partial history returned.",
                                        code="resource_exhausted")
            raise self._failure

    def _record_turn(self, turn_id, *, boundary=False):
        """Track declared boundaries without letting late mirrors rewind them.

        Item references supply a fallback only until this metadata segment has
        a declared turn_context/task_started boundary. Reused IDs are never
        merged across metadata identities or distinct declared turns.
        """
        if not isinstance(turn_id, str) or not turn_id:
            return
        info = self._turns.get(turn_id)
        if info is None:
            info = [self._turn_segment, False]
            self._turns[turn_id] = info
            self._check_items()
        elif info[0] != self._turn_segment:
            self._ambiguous_turns.add(turn_id)
        if boundary or not self._has_turn_boundary:
            if info[1] and self._active_turn != turn_id:
                self._ambiguous_turns.add(turn_id)
            info[1] = True
            self.latest_turn_id = self._active_turn = turn_id
        if boundary:
            self._has_turn_boundary = True

    def add_record(self, record, number, offset=0, length=0):
        if self._failure is not None:
            raise self._failure
        if self._finished:
            raise ValueError("Projection is already finished")
        self.source_lines = max(self.source_lines, number)
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            self.warnings["unknown_record_shape"] += 1
            return
        kind, payload, timestamp = record.get("type"), record["payload"], record.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            timestamp = None
            self.warnings["invalid_timestamp_excluded"] += 1
        if not isinstance(kind, str) or ("type" in payload and not isinstance(payload["type"], str)):
            self.warnings["unknown_type_shape_excluded"] += 1
            return
        message = None
        if kind == "session_meta":
            own = accept_session_metadata(payload, self.expected_id, self.seen_meta, self.permitted_meta)
            self._turn_segment += 1
            self._active_turn = None
            self._has_turn_boundary = False
            if own:
                self.meta = {k: payload.get(k) for k in ("id", "cwd", "timestamp", "cli_version", "history_mode")}
        elif kind == "turn_context":
            if isinstance(payload.get("turn_id"), str):
                self.turn_id = payload["turn_id"]
                self._record_turn(self.turn_id, boundary=True)
        elif kind == "response_item":
            item_type = payload.get("type")
            if item_type == "message":
                if payload.get("role") == "assistant" and (payload.get("phase") not in tuple(PUBLIC_PHASES) or
                        payload.get("channel") not in (*PUBLIC_PHASES, None)):
                    self.warnings["unsupported_assistant_phase_excluded"] += 1
                if payload.get("role") not in ("user", "assistant", "system", "developer"):
                    self.warnings["unknown_message_role_excluded"] += 1
                message = public_message(payload, number, self.turn_id, timestamp, "response_item")
            elif item_type not in {"reasoning", "function_call", "function_call_output", "custom_tool_call",
                                   "custom_tool_call_output", "agent_message", "web_search_call"}:
                self.warnings["unknown_response_item_excluded"] += 1
        elif kind == "event_msg":
            event_type = payload.get("type")
            if payload.get("thread_id") is not None and payload["thread_id"] != self.expected_id:
                self.warnings["other_thread_event_excluded"] += 1
                return
            if event_type == "task_started":
                if isinstance(payload.get("turn_id"), str):
                    self.turn_id = payload["turn_id"]
                    self._record_turn(self.turn_id, boundary=True)
                self.last_state = "recorded_in_progress"
            elif event_type in {"task_complete", "turn_aborted"}:
                self.last_state = "recorded_complete" if event_type == "task_complete" else "recorded_aborted"
            elif event_type == "item_completed":
                item = payload.get("item")
                if not isinstance(item, dict):
                    self.warnings["unknown_event_item_shape"] += 1
                    return
                item_type = item.get("type")
                if not isinstance(item_type, str):
                    self.warnings["unknown_event_item_shape"] += 1
                    return
                item_turn = payload.get("turn_id") if isinstance(payload.get("turn_id"), str) else self.turn_id
                if item_type in {"UserMessage", "AgentMessage"}:
                    if item_type == "AgentMessage" and item.get("delivery") is not None:
                        self.warnings["asynchronous_visibility_unverified_record_excluded"] += 1
                        return
                    if item_type == "AgentMessage" and (item.get("phase") not in tuple(PUBLIC_PHASES) or
                            (item.get("channel") is not None and item.get("channel") not in tuple(PUBLIC_PHASES))):
                        self.warnings["unsupported_assistant_phase_excluded"] += 1
                    message = public_message(item, number, item_turn, timestamp, "event_item")
                elif item_type in TOOL_TYPES:
                    self._record_turn(item_turn)
                    if not self.include_tool_refs:
                        return
                    # Production builders retain only the bounded source reference.
                    # Legacy callers may explicitly retain payloads for project_tool.
                    self.tools[number] = {"kind": "tool_reference", "type": item_type, "turn_id": item_turn,
                                     "timestamp": timestamp, "source_line": number, "_offset": offset, "_length": length}
                    if self.retain_tool_payloads:
                        self.tools[number]["_item"] = item
                    self._check_items()
                elif item_type not in IGNORED_ITEMS:
                    self.warnings["unknown_event_item_excluded"] += 1
            elif event_type not in IGNORED_EVENTS:
                self.warnings["unknown_event_excluded"] += 1
        elif kind == "compacted":
            self.warnings["compaction_record_excluded_history_may_be_partial"] += 1
        elif kind not in IGNORED_RECORDS:
            self.warnings["unknown_record_type_excluded"] += 1
        if message is not None:
            self._record_turn(message["turn_id"])
            if message["unknown_content_blocks"]:
                self.warnings["unknown_message_content_excluded"] += message["unknown_content_blocks"]
            self.total_chars += len(message["text"])
            if self.total_chars > MAX_PUBLIC_CHARS:
                self._failure = AccessError(
                    "Public history exceeds the supported projection size; no partial history returned.",
                    code="projection_limit_exceeded")
                raise self._failure
            (self.messages if message["_source"] == "response_item" else self.events).append(message)
            self._check_items()

    def finish(self):
        if self._failure is not None:
            raise self._failure
        if self._finished:
            raise ValueError("Projection is already finished")
        self._finished = True
        if self.meta is None:
            raise AccessError("History has no recognized session metadata; cannot establish its identity.")
        messages, events, warnings = self.messages, self.events, self.warnings
        used, removed = set(), 0
        by_id_text, by_text = defaultdict(deque), defaultdict(deque)
        id_counts, turn_counts = Counter(), Counter()
        all_turns = object()

        def digest(message):
            text = message["text"]
            return (len(text), hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).digest())

        for index, message in enumerate(messages):
            text_key = digest(message)
            base = (message["role"], message["phase"])
            turn = message["turn_id"]
            native = message["_native_id"]
            if native:
                identity = (*base, native)
                id_counts[identity] += 1
                turn_counts[(identity, turn or None)] += 1
                by_id_text[(identity, text_key, all_turns)].append(index)
                by_id_text[(identity, text_key, turn or None)].append(index)
            by_text[(*base, turn, text_key)].append(index)

        def peek_equal(queue, text):
            while queue and queue[0] in used:
                queue.popleft()
            # Digest is a selector, not proof of equality. In the extraordinary
            # collision case verify bounded source strings without losing others.
            return next((i for i in queue if i not in used and messages[i]["text"] == text), None)

        for event in events:
            base = (event["role"], event["phase"])
            turn, native = event["turn_id"], event["_native_id"]
            text_key, match = digest(event), None
            if native:
                identity = (*base, native)
                turns = (turn, None) if turn else (all_turns,)
                candidates = [peek_equal(by_id_text.get((identity, text_key, t), ()), event["text"]) for t in turns]
                match = min((i for i in candidates if i is not None), default=None)
                count = (turn_counts[(identity, turn)] + turn_counts[(identity, None)]
                         if turn else id_counts[identity])
                if count and match is None:
                    warnings["mirrored_message_text_disagrees"] += 1
            if match is None:
                match = peek_equal(by_text.get((*base, turn, text_key), ()), event["text"])
            if match is not None:
                used.add(match)
                original = messages[match]
                if original["_native_id"]:
                    identity = (original["role"], original["phase"], original["_native_id"])
                    id_counts[identity] -= 1
                    turn_counts[(identity, original["turn_id"] or None)] -= 1
                if not original["turn_id"]:
                    original["turn_id"] = turn
                removed += 1
            else:
                messages.append(event)
        messages.sort(key=lambda m: m["source_line"])
        for message in messages:
            message.pop("_source")
            message.pop("_native_id")
        self.events = []
        if not messages:
            warnings["no_public_messages_in_source_not_proven_empty"] += 1
        return {"meta": self.meta, "messages": messages, "tools": self.tools, "warnings": dict(warnings),
                "inherited_metadata_records": max(0, len(self.seen_meta) - 1),
                "stored_session_ids": sorted(self.seen_meta),
                "turn_ids": list(self._turns), "latest_turn_id": self.latest_turn_id,
                "ambiguous_turn_ids": [turn for turn in self._turns if turn in self._ambiguous_turns],
                "mirrored_messages_deduplicated": removed, "last_recorded_status": self.last_state,
                "complete_public_projection": not warnings, "source_lines": self.source_lines}


def project_rollout(raw, expected_id):
    """Legacy byte-prefix adapter. New callers feed bounded parsed records."""
    builder = ProjectionBuilder(expected_id, retain_tool_payloads=True)
    stream = io.BytesIO(raw)
    number = offset = 0
    while True:
        line = stream.readline(8 * 1024 * 1024 + 1)
        if not line:
            break
        number += 1
        length = len(line)
        oversized = length > 8 * 1024 * 1024
        while not line.endswith(b"\n") and len(line) == 8 * 1024 * 1024 + 1:
            line = stream.readline(8 * 1024 * 1024 + 1)
            length += len(line)
        if not line.endswith(b"\n"):
            builder.warn("incomplete_tail_excluded")
            break
        builder.source_lines = number
        if oversized:
            builder.warn("oversized_record_excluded")
        else:
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError, RecursionError):
                builder.warn("malformed_record_excluded")
            else:
                builder.add_record(record, number, offset, length)
        offset += length
    result = builder.finish()
    # Keep legacy tool-reference shape for existing direct callers.
    for tool in result["tools"].values():
        tool.pop("_offset", None)
        tool.pop("_length", None)
    return result


def accept_session_metadata(payload, expected_id, seen, permitted):
    """Accept only this session and copied headers on its declared fork lineage.

    No parent files or tasks are followed. Repository inheritance separately
    proves every stored cwd, including these copied headers, belongs to one repo.
    """
    identity = payload.get("id")
    if (not isinstance(identity, str) or identity in seen or len(seen) >= 32 or
            (not seen and identity != expected_id) or (seen and identity not in permitted)):
        raise AccessError("History identity mismatch or undeclared/repeated session metadata.")
    seen.add(identity)
    parent = payload.get("forked_from_id")
    if isinstance(parent, str) and parent and parent != identity:
        permitted.add(parent)
    return identity == expected_id


def project_tool(record, mcp_allowlist=()):
    """An explicit field whitelist, not arbitrary serialization of a tool record."""
    item, kind = record["_item"], record["type"]
    result, omissions, redactions = {"type": kind}, [], 0

    def text_field(name, value):
        nonlocal redactions
        if isinstance(value, str):
            value, count = sanitize(value, tool=True)
            result[name] = value
            redactions += count

    def scalar(name):
        value = item.get(name)
        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str):
                text_field(name, value)
            else:
                result[name] = value

    if kind == "CommandExecution":
        if SENSITIVE_SOURCE.search(str(item.get("command", "")) + " " + str(item.get("cwd", ""))) or CREDENTIAL_ENUMERATION.search(str(item.get("command", ""))):
            return {"type": kind, "omitted": "Command references sensitive/internal sources."}, 0
        for name in ("command", "status", "exit_code"):
            scalar(name)
        for name in ("stdout", "stderr", "aggregated_output"):
            text_field(name, item.get(name))
    elif kind == "McpToolCall":
        pair = str(item.get("server", "")) + "/" + str(item.get("tool", ""))
        if HISTORY_TOOL.search(pair) or pair not in mcp_allowlist:
            return {"type": kind, "omitted": "MCP source is not explicitly allowlisted or could expose other conversations/internal data."}, 0
        arguments = item.get("arguments")
        if SENSITIVE_SOURCE.search(json.dumps(arguments, ensure_ascii=False)):
            return {"type": kind, "omitted": "Tool references sensitive/internal sources."}, 0
        for name in ("server", "tool", "status"):
            scalar(name)
        value = item.get("result")
        if isinstance(value, dict) and isinstance(value.get("content"), list):
            value_text, omitted = content_text(value["content"])
            text_field("text_result", value_text)
            result["is_error"] = value.get("isError") if type(value.get("isError")) is bool else None
            result["omitted_nontext_blocks"] = omitted
            omissions.append("arguments, metadata, nontext and structured result fields")
        else:
            omissions.append("unrecognized MCP result shape")
    elif kind == "FileChange":
        scalar("status")
        changes = item.get("changes")
        safe_changes = []
        if isinstance(changes, dict):
            for path, change in list(changes.items())[:100]:
                if not isinstance(path, str) or SENSITIVE_SOURCE.search(path):
                    omissions.append("sensitive file change")
                    continue
                path, count = sanitize(path)
                redactions += count
                entry = {"path": path}
                if isinstance(change, dict):
                    if SENSITIVE_SOURCE.search(str(change.get("move_path", ""))):
                        omissions.append("sensitive moved file change")
                        continue
                    for key in ("type", "kind", "content", "diff", "unified_diff", "move_path"):
                        if isinstance(change.get(key), str):
                            entry[key], count = sanitize(change[key], tool=True)
                            redactions += count
                safe_changes.append(entry)
            if len(changes) > 100:
                omissions.append("file changes beyond first 100")
        else:
            omissions.append("unrecognized file-change shape")
        result["changes"] = safe_changes
        text_field("stderr", item.get("stderr"))
    else:
        omissions.append("generic function output has no supported field whitelist")
    result["omitted_fields"] = omissions
    return result, redactions
