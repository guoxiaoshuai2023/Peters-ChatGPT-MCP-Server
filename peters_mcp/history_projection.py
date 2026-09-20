"""Conservative public projection of locally persisted Codex rollout records.

This module never returns raw records, instructions, reasoning, tool arguments,
runtime context, or attachments. Known public text is retained, not summarized.
"""

from collections import Counter, defaultdict, deque
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
        text, count = re.subn(r"<" + re.escape(tag) + r"(?:\s[^>]*)?>[\s\S]*?</" + re.escape(tag) + r">",
                             "[OMITTED: internal context]", text, flags=re.I)
        redactions += count
        # Fail closed for an unfinished context wrapper.
        text, count = re.subn(r"<" + re.escape(tag) + r"(?:\s[^>]*)?>[\s\S]*$",
                             "[OMITTED: internal context]", text, flags=re.I)
        redactions += count
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


def project_rollout(raw, expected_id):
    """Parse a fixed byte prefix. The caller authenticates source and cursors."""
    warnings = Counter()
    messages, events, tools = [], [], {}
    turn_id = None
    last_state, meta, total_chars = "unknown", None, 0
    seen_meta, permitted_meta = set(), set()
    lines = raw.splitlines(keepends=True)
    if lines and not lines[-1].endswith(b"\n"):
        lines.pop()
        warnings["incomplete_tail_excluded"] += 1
    for number, line in enumerate(lines, 1):
        if len(line) > 8 * 1024 * 1024:
            warnings["oversized_record_excluded"] += 1
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError):
            warnings["malformed_record_excluded"] += 1
            continue
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            warnings["unknown_record_shape"] += 1
            continue
        kind, payload, timestamp = record.get("type"), record["payload"], record.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            timestamp = None
            warnings["invalid_timestamp_excluded"] += 1
        if not isinstance(kind, str) or ("type" in payload and not isinstance(payload["type"], str)):
            warnings["unknown_type_shape_excluded"] += 1
            continue
        message = None
        if kind == "session_meta":
            own = accept_session_metadata(payload, expected_id, seen_meta, permitted_meta)
            if own:
                meta = {k: payload.get(k) for k in ("id", "cwd", "timestamp", "cli_version", "history_mode")}
        elif kind == "turn_context":
            if isinstance(payload.get("turn_id"), str):
                turn_id = payload["turn_id"]
        elif kind == "response_item":
            item_type = payload.get("type")
            if item_type == "message":
                if payload.get("role") == "assistant" and (payload.get("phase") not in tuple(PUBLIC_PHASES) or
                        payload.get("channel") not in (*PUBLIC_PHASES, None)):
                    warnings["unsupported_assistant_phase_excluded"] += 1
                if payload.get("role") not in ("user", "assistant", "system", "developer"):
                    warnings["unknown_message_role_excluded"] += 1
                message = public_message(payload, number, turn_id, timestamp, "response_item")
            elif item_type not in {"reasoning", "function_call", "function_call_output", "custom_tool_call",
                                   "custom_tool_call_output", "agent_message", "web_search_call"}:
                warnings["unknown_response_item_excluded"] += 1
        elif kind == "event_msg":
            event_type = payload.get("type")
            if payload.get("thread_id") is not None and payload["thread_id"] != expected_id:
                warnings["other_thread_event_excluded"] += 1
                continue
            if event_type == "task_started":
                if isinstance(payload.get("turn_id"), str):
                    turn_id = payload["turn_id"]
                last_state = "recorded_in_progress"
            elif event_type in {"task_complete", "turn_aborted"}:
                last_state = "recorded_complete" if event_type == "task_complete" else "recorded_aborted"
            elif event_type == "item_completed":
                item = payload.get("item")
                if not isinstance(item, dict):
                    warnings["unknown_event_item_shape"] += 1
                    continue
                item_type = item.get("type")
                if not isinstance(item_type, str):
                    warnings["unknown_event_item_shape"] += 1
                    continue
                item_turn = payload.get("turn_id") if isinstance(payload.get("turn_id"), str) else turn_id
                if item_type in {"UserMessage", "AgentMessage"}:
                    if item_type == "AgentMessage" and item.get("delivery") is not None:
                        warnings["asynchronous_visibility_unverified_record_excluded"] += 1
                        continue
                    if item_type == "AgentMessage" and (item.get("phase") not in tuple(PUBLIC_PHASES) or
                            (item.get("channel") is not None and item.get("channel") not in tuple(PUBLIC_PHASES))):
                        warnings["unsupported_assistant_phase_excluded"] += 1
                    message = public_message(item, number, item_turn, timestamp, "event_item")
                elif item_type in TOOL_TYPES:
                    # Raw item stays inside the parser; only project_tool may expose it.
                    tools[number] = {"kind": "tool_reference", "type": item_type, "turn_id": item_turn,
                                     "timestamp": timestamp, "source_line": number, "_item": item}
                elif item_type not in IGNORED_ITEMS:
                    warnings["unknown_event_item_excluded"] += 1
            elif event_type not in IGNORED_EVENTS:
                warnings["unknown_event_excluded"] += 1
        elif kind == "compacted":
            warnings["compaction_record_excluded_history_may_be_partial"] += 1
        elif kind not in IGNORED_RECORDS:
            warnings["unknown_record_type_excluded"] += 1
        if message is not None:
            if message["unknown_content_blocks"]:
                warnings["unknown_message_content_excluded"] += message["unknown_content_blocks"]
            total_chars += len(message["text"])
            if total_chars > MAX_PUBLIC_CHARS:
                raise AccessError("Public history exceeds the supported projection size; no partial history returned.")
            (messages if message["_source"] == "response_item" else events).append(message)
    if meta is None:
        raise AccessError("History has no recognized session metadata; cannot establish its identity.")
    # Merge the two persisted mirrors. Match IDs first, then one-to-one matching
    # text within a turn. Repeated equal messages within one stream are retained.
    used, removed = set(), 0
    by_id, by_text = defaultdict(deque), defaultdict(deque)
    for index, message in enumerate(messages):
        if message["_native_id"]:
            by_id[(message["role"], message["phase"], message["_native_id"])].append(index)
        by_text[(message["role"], message["phase"], message["turn_id"], message["text"])].append(index)

    def take(queue):
        while queue and queue[0] in used:
            queue.popleft()
        return queue.popleft() if queue else None

    for event in events:
        candidates = [i for i in by_id[(event["role"], event["phase"], event["_native_id"])]] if event["_native_id"] else []
        candidates = [i for i in candidates if i not in used and (not event["turn_id"] or
                       not messages[i]["turn_id"] or messages[i]["turn_id"] == event["turn_id"])]
        match = next((i for i in candidates if messages[i]["text"] == event["text"]), None)
        if candidates and match is None:
            warnings["mirrored_message_text_disagrees"] += 1
        if match is None:
            match = take(by_text[(event["role"], event["phase"], event["turn_id"], event["text"])])
        if match is not None:
            used.add(match)
            if messages[match]["text"] != event["text"]:
                warnings["mirrored_message_text_disagrees"] += 1
            if not messages[match]["turn_id"]:
                messages[match]["turn_id"] = event["turn_id"]
            removed += 1
        else:
            messages.append(event)
            used.add(len(messages) - 1)
    messages.sort(key=lambda m: m["source_line"])
    for message in messages:
        message.pop("_source")
        message.pop("_native_id")
    if not messages:
        warnings["no_public_messages_in_source_not_proven_empty"] += 1
    return {"meta": meta, "messages": messages, "tools": tools, "warnings": dict(warnings),
            "inherited_metadata_records": max(0, len(seen_meta) - 1),
            "stored_session_ids": sorted(seen_meta),
            "mirrored_messages_deduplicated": removed, "last_recorded_status": last_state,
            "complete_public_projection": not warnings, "source_lines": len(lines)}


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
