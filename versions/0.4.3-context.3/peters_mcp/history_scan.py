"""Bounded JSONL scanning. No source bytes or tool payloads survive a scan."""

import hashlib
import json
import os
from pathlib import Path
import time

from .catalog import AccessError
from .history_projection import ProjectionBuilder, accept_session_metadata

BLOCK_BYTES = 256 * 1024
RECORD_BYTES = 12 * 1024 * 1024
SLICE_BYTES = 16 * 1024 * 1024
SLICE_SECONDS = 1.5
PROJECTION_VERSION = 'public-jsonl-stream-v1'


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def scan(fd, thread_id, *, projection=True, expected=None, tool_refs=False):
    """Yield at bounded IO checkpoints; return proof and an optional projection.

    Complete-prefix hashing is distinct from the observed file size: incomplete
    trailing records are not part of a content snapshot. Mutation during a scan
    discards the attempt instead of joining observations from different versions.
    """
    before = os.fstat(fd)
    initial = stamp(before)
    if expected and (before.st_dev != expected['device'] or before.st_ino != expected['inode']
                     or before.st_size < expected['bytes']):
        raise AccessError('History identity changed or source was truncated; restart the read.', code='source_changed')
    builder = ProjectionBuilder(thread_id, include_tool_refs=tool_refs) if projection else None
    digest, prefix = hashlib.sha256(), hashlib.sha256()
    complete_digest = digest.copy()
    complete_bytes = offset = line_start = number = consumed = 0
    buffer = bytearray()
    oversized = False
    contexts, seen, permitted = set(), set(), set()
    own_seen, reason = False, None
    started = time.monotonic()

    def context(record):
        nonlocal own_seen, reason
        if not isinstance(record, dict):
            reason = reason or 'unknown_record_shape_cannot_prove_association'
            return
        kind = record.get('type')
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
            own_seen = accept_session_metadata(payload, thread_id, seen, permitted) or own_seen
        cwd = payload.get('cwd')
        if not isinstance(cwd, str) or not cwd or not Path(cwd).is_absolute():
            reason = reason or 'missing_recorded_working_directory'
        elif len(cwd) > 4096 or len(contexts) >= 256 and cwd not in contexts:
            raise AccessError('Recorded context budget exceeded.', code='resource_exhausted')
        else:
            contexts.add(cwd)

    while offset < before.st_size:
        chunk = os.pread(fd, min(BLOCK_BYTES, before.st_size - offset), offset)
        if not chunk:
            raise AccessError('History was truncated during reading.', code='source_changed')
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
                if len(buffer) + len(piece) > RECORD_BYTES:
                    oversized = True
                    buffer.clear()
                else:
                    buffer.extend(piece)
            if complete:
                number += 1
                absolute_end = offset + stop
                if oversized:
                    reason = reason or 'oversized_record_cannot_prove_association'
                    if builder:
                        builder.warn('oversized_record_excluded')
                else:
                    try:
                        record = json.loads(buffer)
                    except (ValueError, UnicodeError):
                        reason = reason or 'malformed_record_cannot_prove_association'
                        if builder:
                            builder.warn('malformed_record_excluded')
                    except RecursionError:
                        raise AccessError('JSON nesting exceeds supported complexity.', code='resource_exhausted') from None
                    else:
                        context(record)
                        if builder:
                            builder.add_record(record, number, line_start, absolute_end - line_start)
                        del record
                complete_bytes = absolute_end
                complete_digest = digest.copy()
                line_start = absolute_end
                buffer.clear()
                oversized = False
            position = stop
        offset += len(chunk)
        consumed += len(chunk)
        if consumed >= SLICE_BYTES or time.monotonic() - started >= SLICE_SECONDS:
            if stamp(os.fstat(fd)) != initial:
                raise AccessError('Source changed during verification; wait for a stable source.', code='waiting_source_stable')
            yield {'phase': 'scanning'}
            consumed, started = 0, time.monotonic()
    if stamp(os.fstat(fd)) != initial:
        raise AccessError('Source changed during verification; wait for a stable source.', code='waiting_source_stable')
    if expected and prefix.hexdigest() != expected['sha256']:
        raise AccessError('Earlier history changed between pages; restart the read.', code='source_changed')
    if not own_seen:
        raise AccessError('History has no recognized session metadata.', code='unverifiable_source')
    if builder and (buffer or oversized):
        builder.warn('incomplete_tail_excluded')
    yield {'phase': 'finalizing'}
    projected = builder.finish() if builder else None
    if projected is not None:
        projected['source_lines'] = number
    return {'stamp': initial, 'bytes': complete_bytes, 'sha256': complete_digest.hexdigest(),
            'device': before.st_dev, 'inode': before.st_ino, 'projection': projected,
            'proof': {'contexts': sorted(contexts), 'reason': reason, 'session_ids': sorted(seen)}}
