"""Bounded JSONL scanning. No source bytes or tool payloads survive a scan."""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import time

from pydantic_core import SchemaValidator, core_schema

from .catalog import AccessError
from .history_projection import ProjectionBuilder, accept_session_metadata, is_subagent_source, subagent_parent_id
from .history_source import chunks

BLOCK_BYTES = 256 * 1024
RECORD_BYTES = 12 * 1024 * 1024
# Larger attachment/tool records need their envelope verified for inheritance,
# even when their content is outside the public projection budget.
PROOF_RECORD_BYTES = 64 * 1024 * 1024
SLICE_BYTES = 16 * 1024 * 1024
SLICE_SECONDS = 1.5
PROJECTION_VERSION = 'public-jsonl-stream-v4'

# Compaction contents are excluded by ProjectionBuilder. Drop those large
# replacement snapshots during decoding while still validating the whole JSON.
# Preserve the envelope fields used by its record-shape and timestamp checks.
_COMPACTION_SCHEMA = core_schema.typed_dict_schema({
    "type": core_schema.typed_dict_field(core_schema.literal_schema(["compacted"])),
    "timestamp": core_schema.typed_dict_field(core_schema.any_schema(), required=False),
    "payload": core_schema.typed_dict_field(core_schema.typed_dict_schema({
        "type": core_schema.typed_dict_field(core_schema.any_schema(), required=False),
    }, extra_behavior="ignore")),
}, extra_behavior="ignore")
_RECORD_DECODER = SchemaValidator(core_schema.union_schema(
    [_COMPACTION_SCHEMA, core_schema.any_schema()], mode="left_to_right",
), config={"cache_strings": False})


def _envelope_string(limit):
    return core_schema.typed_dict_field(core_schema.nullable_schema(
        core_schema.str_schema(strict=True, max_length=limit)), required=False)


# Validate the entire JSON, including ignored values, without constructing
# attachment strings, reasoning, tools or replacement histories in Python.
# No stdlib fallback here: failed large envelopes must never bypass proof.
_INT_FIELD = core_schema.typed_dict_field(core_schema.nullable_schema(
    core_schema.int_schema(strict=True)), required=False)
_HISTORY_BASE_SCHEMA = core_schema.typed_dict_field(core_schema.nullable_schema(
    core_schema.typed_dict_schema({
        "thread_id": _envelope_string(256),
        "end_ordinal_exclusive": _INT_FIELD,
        "end_byte_offset": _INT_FIELD,
    }, extra_behavior="ignore")), required=False)
_PROOF_DECODER = SchemaValidator(core_schema.typed_dict_schema({
    "type": _envelope_string(128),
    "timestamp": _envelope_string(512),
    "payload": core_schema.typed_dict_field(core_schema.typed_dict_schema({
        **{
            key: _envelope_string(limit) for key, limit in {
                "type": 128, "id": 256, "cwd": 4096, "forked_from_id": 256, "parent_thread_id": 256,
                "turn_id": 200, "cli_version": 100, "history_mode": 32, "timestamp": 64,
            }.items()
        },
        "forked_from_ordinal_exclusive": _INT_FIELD,
        "attached_thread": core_schema.typed_dict_field(
            core_schema.nullable_schema(core_schema.bool_schema()), required=False
        ),
        "source": core_schema.typed_dict_field(core_schema.any_schema(), required=False),
        "history_base": _HISTORY_BASE_SCHEMA,
    }, extra_behavior="ignore")),
}, extra_behavior="ignore"), config={"cache_strings": False})


def decode_record(raw):
    # Decode UTF-8 bytes directly, avoiding a full Unicode copy of large records.
    try:
        return _RECORD_DECODER.validate_json(raw)
    except ValueError:
        # Preserve stdlib support for legacy encodings, escapes and nesting.
        return json.loads(raw)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


_NATIVE_TIME = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.(\d{1,9}))?(?:Z|[+-]\d\d:\d\d)")


def _time_bounds(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        match = _NATIVE_TIME.fullmatch(value)
        if match is None:
            return None
        parsed = datetime.fromisoformat(value).replace(microsecond=0)
        delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
        digits = match[1] or ''
        start = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(digits.ljust(9, '0'))
        return start, start + 10 ** (9 - len(digits)) - 1
    except (ValueError, OverflowError):
        return None


def _parse_history_base(payload):
    """Extract and validate native paginated fork cutoff metadata from own session_meta.

    Returns (history_base_dict_or_None, is_invalid_bool).
    """
    raw_base = payload.get('history_base')
    raw_ord = payload.get('forked_from_ordinal_exclusive')
    parent = payload.get('forked_from_id')
    if raw_base is None:
        if raw_ord is not None and (type(raw_ord) is not int or raw_ord < 1 or not isinstance(parent, str) or not parent):
            return None, True
        return None, False
    if not isinstance(raw_base, dict):
        return None, True
    tid = raw_base.get('thread_id')
    end_ord = raw_base.get('end_ordinal_exclusive')
    end_byte = raw_base.get('end_byte_offset')
    if (not isinstance(tid, str) or not tid
            or not isinstance(parent, str) or tid != parent
            or type(end_ord) is not int or end_ord < 1
            or type(end_byte) is not int or end_byte < 1):
        return None, True
    if raw_ord is not None and (type(raw_ord) is not int or raw_ord != end_ord):
        return None, True
    return {'thread_id': tid, 'end_ordinal_exclusive': end_ord, 'end_byte_offset': end_byte}, False


def scan(fd, thread_id, *, projection=True, expected=None, tool_refs=False, temporal=False, cutoff=None):
    """Yield at bounded IO checkpoints; return proof and an optional projection.

    Complete-prefix hashing is distinct from the observed file size: incomplete
    trailing records are not part of a content snapshot. Mutation during a scan
    discards the attempt instead of joining observations from different versions.
    When cutoff is given ({'end_ordinal_exclusive', 'end_byte_offset'}), stops
    at the exact pre-fork boundary without reading post-fork records.
    """
    before = os.fstat(fd)
    initial = stamp(before)
    encoding = 'zstd' if getattr(fd, 'compressed', False) else 'jsonl'
    if expected and (before.st_dev != expected['device'] or before.st_ino != expected['inode']
                     or expected.get('storage_encoding', 'jsonl') != encoding
                     or encoding == 'jsonl' and before.st_size < expected['bytes']):
        raise AccessError('History identity changed or source was truncated; restart the read.', code='source_changed')
    target_bytes = None
    target_lines = None
    if cutoff is not None:
        if (not isinstance(cutoff, dict)
                or type(cutoff.get('end_ordinal_exclusive')) is not int or cutoff['end_ordinal_exclusive'] < 1
                or type(cutoff.get('end_byte_offset')) is not int or cutoff['end_byte_offset'] < 1):
            raise AccessError('Invalid fork cutoff metadata.', code='unverifiable_source')
        target_bytes = cutoff['end_byte_offset']
    builder = ProjectionBuilder(thread_id, include_tool_refs=tool_refs) if projection else None
    digest, prefix = hashlib.sha256(), hashlib.sha256()
    complete_digest = digest.copy()
    complete_bytes = offset = line_start = number = consumed = 0
    buffer = []
    record_bytes = 0
    oversized = False
    contexts, seen, permitted = set(), set(), set()
    origins = {}
    context_spans = {}
    active_cwd = None
    first_event = last_event = preceding = None
    clocks_valid = True
    own_seen, reason = False, None
    own_history_base = None
    history_base_invalid = False
    own_attached_thread = False
    own_subagent = False
    own_subagent_parent_id = None
    cutoff_stop = False
    started = time.monotonic()

    def context(record):
        nonlocal own_seen, reason, first_event, last_event, preceding, clocks_valid, active_cwd
        nonlocal own_history_base, history_base_invalid, own_attached_thread, own_subagent, own_subagent_parent_id, target_lines
        if not isinstance(record, dict):
            reason = reason or 'unknown_record_shape_cannot_prove_association'
            return
        kind = record.get('type')
        rec_bounds = None
        if temporal:
            bounds = _time_bounds(record.get('timestamp'))
            rec_bounds = bounds
            if bounds is None:
                clocks_valid = False
            else:
                start, end = bounds
                if kind != 'session_meta' and preceding is not None and end < preceding:
                    clocks_valid = False
                preceding = start
                first_event = start if first_event is None else min(start, first_event)
                last_event = end if last_event is None else max(end, last_event)
                if active_cwd is not None and active_cwd in context_spans:
                    context_spans[active_cwd][1] = max(context_spans[active_cwd][1], end)
        if not isinstance(kind, str) or kind not in {
            'session_meta', 'turn_context', 'response_item', 'event_msg', 'world_state',
            'token_usage_record', 'inter_agent_communication_metadata', 'compacted'
        }:
            reason = reason or 'unknown_record_type_cannot_prove_association'
            return
        if kind not in {'session_meta', 'turn_context'}:
            return
        payload = record.get('payload')
        if not isinstance(payload, dict):
            reason = reason or 'missing_context_metadata'
            return
        if kind == 'session_meta':
            # Identity failures also apply to explicit grants.
            is_own = accept_session_metadata(payload, thread_id, seen, permitted)
            own_seen = is_own or own_seen
            if is_own:
                raw_attached = payload.get('attached_thread')
                if raw_attached is not None and type(raw_attached) is not bool:
                    reason = reason or 'invalid_attached_thread_metadata'
                else:
                    own_attached_thread = bool(raw_attached)
                own_subagent = is_subagent_source(payload.get('source'))
                own_subagent_parent_id = subagent_parent_id(payload)
                parsed_base, invalid_base = _parse_history_base(payload)
                own_history_base = parsed_base
                history_base_invalid = invalid_base
                if cutoff is not None:
                    base_ord = parsed_base['end_ordinal_exclusive'] if parsed_base is not None else 0
                    target_lines = cutoff['end_ordinal_exclusive'] - base_ord
            # A copied parent's envelope can be generated by the child. Only
            # the parent's own native header can date that portion of a fork.
            if temporal:
                value = payload.get('timestamp')
                if value is None and payload['id'] == thread_id:
                    value = record.get('timestamp')
                bounds = _time_bounds(value)
                origins[payload['id']] = bounds[0] if bounds else None
                if bounds is not None and rec_bounds is None:
                    rec_bounds = bounds
        cwd = payload.get('cwd')
        if not isinstance(cwd, str) or not cwd or not Path(cwd).is_absolute():
            reason = reason or 'missing_recorded_working_directory'
        elif len(cwd) > 4096 or len(contexts) >= 256 and cwd not in contexts:
            raise AccessError('Recorded context budget exceeded.', code='resource_exhausted')
        else:
            contexts.add(cwd)
            if temporal and rec_bounds is not None:
                c_start, c_end = rec_bounds
                if cwd not in context_spans:
                    context_spans[cwd] = [c_start, c_end]
                else:
                    context_spans[cwd][0] = min(context_spans[cwd][0], c_start)
                    context_spans[cwd][1] = max(context_spans[cwd][1], c_end)
                active_cwd = cwd

    for chunk in chunks(fd, before.st_size):
        if expected and offset < expected['bytes']:
            prefix.update(chunk[:expected['bytes'] - offset])
        position = 0
        while position < len(chunk):
            end = chunk.find(b'\n', position)
            complete = end >= 0
            stop = end + 1 if complete else len(chunk)
            piece = chunk[position:stop]
            digest.update(piece)
            if not oversized:
                record_bytes += len(piece)
                if record_bytes > PROOF_RECORD_BYTES:
                    oversized = True
                    buffer.clear()
                else:
                    buffer.append(piece)
            if complete:
                number += 1
                absolute_end = offset + stop
                if oversized:
                    reason = reason or 'oversized_record_cannot_prove_association'
                    if builder:
                        builder.warn('oversized_record_excluded')
                else:
                    envelope_only = record_bytes > RECORD_BYTES
                    try:
                        raw = b"".join(buffer)
                        record = (_PROOF_DECODER.validate_json(raw) if envelope_only
                                  else decode_record(raw))
                    except (ValueError, UnicodeError):
                        reason = reason or 'malformed_record_cannot_prove_association'
                        if builder:
                            builder.warn('malformed_record_excluded')
                    except RecursionError:
                        raise AccessError('JSON nesting exceeds supported complexity.', code='resource_exhausted') from None
                    else:
                        context(record)
                        if builder:
                            if envelope_only:
                                builder.warn('oversized_record_excluded')
                            if not envelope_only or record.get('type') in {'session_meta', 'turn_context'}:
                                builder.add_record(record, number, line_start, absolute_end - line_start)
                        del record
                    finally:
                        del raw
                complete_bytes = absolute_end
                complete_digest = digest.copy()
                line_start = absolute_end
                buffer.clear()
                record_bytes = 0
                oversized = False
                if cutoff is not None:
                    if (target_lines is not None and (target_lines < 1 or number >= target_lines)) or complete_bytes >= target_bytes:
                        cutoff_stop = True
                        break
            position = stop
        if cutoff_stop:
            offset = complete_bytes
            break
        offset += len(chunk)
        consumed += len(chunk)
        if consumed >= SLICE_BYTES or time.monotonic() - started >= SLICE_SECONDS:
            if stamp(os.fstat(fd)) != initial:
                raise AccessError('Source changed during verification; wait for a stable source.', code='waiting_source_stable')
            yield {'phase': 'scanning'}
            consumed, started = 0, time.monotonic()
    if stamp(os.fstat(fd)) != initial:
        raise AccessError('Source changed during verification; wait for a stable source.', code='waiting_source_stable')
    if expected and (offset < expected['bytes'] or prefix.hexdigest() != expected['sha256']):
        raise AccessError('Earlier history changed between pages; restart the read.', code='source_changed')
    if not own_seen:
        raise AccessError('History has no recognized session metadata.', code='unverifiable_source')
    cutoff_verified = None
    if cutoff is not None:
        cutoff_verified = bool(
            target_lines is not None and target_lines >= 1
            and target_bytes >= 1 and number == target_lines and complete_bytes == target_bytes
        )
        if not cutoff_verified:
            reason = reason or 'fork_cutoff_mismatch'
    if builder and not cutoff_stop and (buffer or oversized):
        builder.warn('incomplete_tail_excluded')
    yield {'phase': 'finalizing'}
    projected = builder.finish() if builder else None
    if projected is not None:
        projected['source_lines'] = number
    return {'stamp': initial, 'bytes': complete_bytes, 'sha256': complete_digest.hexdigest(),
            'decoded_bytes': offset, 'storage_encoding': encoding,
            'device': before.st_dev, 'inode': before.st_ino, 'projection': projected,
            'cutoff_verified': cutoff_verified,
            'proof': {'contexts': sorted(contexts), 'reason': reason, 'session_ids': sorted(seen),
                      'origins': origins, 'missing_ancestor': bool(permitted - seen),
                      'missing_ancestors': sorted(permitted - seen),
                      'attached_thread': own_attached_thread,
                      'subagent': own_subagent,
                      'subagent_parent_id': own_subagent_parent_id,
                      'history_base': own_history_base,
                      'history_base_invalid': history_base_invalid,
                      'context_spans': {k: tuple(v) for k, v in context_spans.items()},
                      'first_event_ns': first_event, 'last_event_ns': last_event if clocks_valid else None}}
