"""Read Antigravity App's local conversation summaries and compact transcripts."""

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.parse import unquote_to_bytes, urlsplit

from .agent_history_source import Message, Projection, SourceRoot, Thread
from .catalog import AccessError


# https://antigravity.google/docs/hooks#common-input-fields describes the path.
# The v2.32.1 App's language_server embeds the compact transcript record layout
# in its conversation_transcript system prompt. This is distinct from ACP SQLite.
# The same bundled implementation classifies hook user messages as SYSTEM_SDK.
VERSIONS = frozenset({'2.32.1'})
INDEX = 'conversation_summaries.db'
INDEX_VERSION = 3
ID_PATTERN = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', re.ASCII)
MAX_THREADS = 2048
MAX_ANCESTORS = 32
MAX_CONTEXTS = 128
MAX_INDEX_FIELD_CHARS = 16384
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 50000
MAX_VISIBLE_CHARS = 16 * 1024 * 1024
VISIBLE_ROLES = {('USER_INPUT', 'USER_EXPLICIT'): 'user', ('PLANNER_RESPONSE', 'MODEL'): 'assistant'}
INDEX_ROWS = '''SELECT s.conversation_id, substr(s.title, 1, 501),
                       substr(s.last_modified_time, 1, 65),
                       substr(s.workspace_uris, 1, ?),
                       substr(s.parent_conversation_id, 1, 37),
                       substr(p.parent_id, 1, 37), s.nesting_depth
                FROM conversation_summaries s LEFT JOIN conversation_parents p
                  ON p.conversation_id = s.conversation_id'''


def _unsupported(message):
    return AccessError(message, code='unsupported_format')


def _budget(message):
    return AccessError(message, code='resource_exhausted')


def _native_id(value):
    return isinstance(value, str) and ID_PATTERN.fullmatch(value) is not None


def _timestamp(value):
    if not isinstance(value, str) or not 11 <= len(value) <= 64:
        return ''
    try:
        time = datetime.fromisoformat(value)
        if time.tzinfo is None:
            return ''
        return time.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return ''


def _local_workspace(uri):
    if not isinstance(uri, str) or len(uri) > 4096 or not uri.startswith('file:///'):
        return None
    if any(ord(char) <= 0x20 or ord(char) == 0x7f for char in uri):
        return None
    try:
        parts = urlsplit(uri)
        if parts.netloc or parts.query or parts.fragment or re.search(r'%(?![0-9a-fA-F]{2})', parts.path):
            return None
        path = unquote_to_bytes(parts.path).decode('utf-8')
        if not path.startswith('/') or path.startswith('//') or '\\' in path:
            return None
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in path):
            return None
        canonical = PurePosixPath(path)
        if len(canonical.parts) < 2 or '..' in canonical.parts:
            return None
        return str(canonical)
    except (ValueError, UnicodeError):
        return None


def _workspace_paths(raw):
    if not isinstance(raw, str) or len(raw) > MAX_INDEX_FIELD_CHARS:
        return ()
    try:
        uris = json.loads(raw)
    except (ValueError, RecursionError):
        return ()
    if not isinstance(uris, list) or len(uris) > 64:
        return ()
    # Even incomplete lists carry negative evidence against a cross-project grant.
    paths = (_local_workspace(uri) for uri in uris)
    return tuple(dict.fromkeys(path for path in paths if path is not None))


def _parents(*values):
    known = {value for value in values if value is not None and value != ''}
    if any(not _native_id(value) for value in known) or len(known) > 1:
        raise _unsupported('Antigravity index contains conflicting conversation ancestry.')
    return next(iter(known), '')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _profile_record(raw):
    try:
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        raise _unsupported('Antigravity transcript has a malformed complete record.') from None
    if not isinstance(record, dict):
        raise _unsupported('Antigravity transcript record is not an object.')
    index = record.get('step_index')
    kind = record.get('type')
    source = record.get('source')
    status = record.get('status')
    if (type(index) is not int or not 0 <= index < 2**53
            or any(not isinstance(field, str) or not 1 <= len(field) <= 80
                   for field in (kind, source, status))):
        raise _unsupported('Antigravity transcript record schema is not supported.')
    return index, kind, source, status, record


def _content_is_truncated(record):
    fields = record.get('truncated_fields', [])
    if fields is None:
        return False
    if not isinstance(fields, list) or any(not isinstance(field, str) for field in fields):
        raise _unsupported('Antigravity transcript has invalid truncation metadata.')
    return 'content' in fields


class Adapter:
    supports_inheritance = False

    def __init__(self, root: SourceRoot, version: str):
        if version not in VERSIONS:
            raise _unsupported('Antigravity App version is not supported.')
        self.root = root

    def _index(self, connection):
        if connection.execute('PRAGMA user_version').fetchone() != (INDEX_VERSION,):
            raise _unsupported('Antigravity conversation index version is not supported.')

    @staticmethod
    def _row(connection, native_id):
        return connection.execute(
            INDEX_ROWS + ' WHERE s.conversation_id = ?',
            (MAX_INDEX_FIELD_CHARS + 1, native_id),
        ).fetchone()

    def _materialize(self, connection, row):
        native_id, title, updated, workspaces, primary_parent, indexed_parent, depth = row
        if not _native_id(native_id) or type(depth) is not int or depth != 0:
            return None
        contexts = dict.fromkeys(_workspace_paths(workspaces))
        parent = _parents(primary_parent, indexed_parent)
        seen = {native_id}
        ancestors = []
        while parent:
            if parent in seen:
                raise _unsupported('Antigravity conversation ancestry contains a cycle.')
            if len(ancestors) >= MAX_ANCESTORS:
                raise _budget('Antigravity conversation ancestry exceeds the reader limit.')
            ancestors.append(parent)
            seen.add(parent)
            ancestor = self._row(connection, parent)
            if ancestor is None:
                break
            contexts.update(dict.fromkeys(_workspace_paths(ancestor[3])))
            if len(contexts) > MAX_CONTEXTS:
                raise _budget('Antigravity conversation workspace history exceeds the reader limit.')
            parent = _parents(ancestor[4], ancestor[5])
        # This index records workspace membership but no verified historical
        # workspace ledger. Keep explicit thread authorization mandatory.
        return Thread(native_id=native_id, title=title[:500] if isinstance(title, str) else '',
                      updated_at=_timestamp(updated), contexts=tuple(contexts),
                      ancestors=tuple(ancestors), context_complete=False,
                      agent='antigravity', surface='desktop')

    def discover(self):
        try:
            with self.root.sqlite(INDEX) as connection:
                self._index(connection)
                rows = connection.execute(
                    INDEX_ROWS + ''' WHERE s.nesting_depth = 0 AND length(s.conversation_id) = 36
                                      ORDER BY s.last_modified_time DESC, s.conversation_id ASC LIMIT ?''',
                    (MAX_INDEX_FIELD_CHARS + 1, MAX_THREADS + 1),
                ).fetchall()
                if len(rows) > MAX_THREADS:
                    raise _budget('Antigravity conversation index exceeds the reader limit.')
                return tuple(thread for row in rows
                             if (thread := self._materialize(connection, row)) is not None)
        except sqlite3.Error:
            raise _unsupported('Antigravity conversation index schema is not supported.') from None

    def describe(self, native_id):
        if not _native_id(native_id):
            return None
        try:
            with self.root.sqlite(INDEX) as connection:
                self._index(connection)
                row = self._row(connection, native_id)
                return self._materialize(connection, row) if row is not None else None
        except sqlite3.Error:
            raise _unsupported('Antigravity conversation index schema is not supported.') from None

    def snapshot(self, thread):
        if not _native_id(thread.native_id):
            raise AccessError('Antigravity conversation is unavailable.', code='source_unavailable')
        relative = f'brain/{thread.native_id}/.system_generated/logs/transcript.jsonl'
        source_identity = self.root.identity_for(relative)
        digest = hashlib.sha256()
        messages = []
        warnings = set()
        prior_index = -1
        saw_expected_message = False
        visible_chars = 0
        with self.root.open(relative) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_TRANSCRIPT_BYTES:
                raise _budget('Antigravity transcript exceeds the reader byte limit.')
            consumed = 0
            committed = 0
            for line_index in range(MAX_RECORDS + 1):
                raw = stream.readline(min(MAX_RECORD_BYTES + 1, before.st_size - consumed))
                consumed += len(raw)
                if not raw:
                    break
                if line_index == MAX_RECORDS or len(raw) > MAX_RECORD_BYTES:
                    raise _budget('Antigravity transcript exceeds the reader record limit.')
                if not raw.endswith(b'\n'):
                    warnings.add('incomplete_tail_omitted')
                    break
                digest.update(raw)
                committed = consumed
                index, kind, source, status, record = _profile_record(raw)
                if index <= prior_index:
                    raise _unsupported('Antigravity transcript steps are not strictly ordered.')
                if index != prior_index + 1:
                    warnings.add('missing_steps')
                prior_index = index
                role = VISIBLE_ROLES.get((kind, source))
                if role is None:
                    if source == 'USER_EXPLICIT' or (kind in ('USER_INPUT', 'PLANNER_RESPONSE')
                                                     and source not in ('SYSTEM', 'SYSTEM_SDK', 'USER_IMPLICIT')):
                        warnings.add('unrecognized_message_provenance_omitted')
                    continue
                saw_expected_message = True
                if status != 'DONE':
                    warnings.add('unfinished_messages_omitted')
                    continue
                if _content_is_truncated(record):
                    warnings.add('truncated_content_omitted')
                    continue
                content = record.get('content')
                if content is None or content == '':
                    continue
                if not isinstance(content, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in content):
                    raise _unsupported('Antigravity transcript text has an unsupported encoding or shape.')
                visible_chars += len(content)
                if visible_chars > MAX_VISIBLE_CHARS:
                    raise _budget('Antigravity transcript exceeds the visible text limit.')
                messages.append(Message(role, content, f'step:{index}', _timestamp(record.get('created_at'))))
            after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or consumed != before.st_size or self.root.identity_for(relative) != source_identity):
            raise AccessError('Antigravity transcript changed during capture.', code='waiting_source_stable')
        if prior_index < 0:
            raise AccessError('Antigravity transcript has no committed records yet.', code='waiting_source_stable')
        if not saw_expected_message:
            warnings.add('no_verified_public_step')
        revision = digest.hexdigest()
        return Projection(messages=tuple(messages), revision=revision, identity=str(source_identity),
                          contexts=thread.contexts, ancestors=thread.ancestors, context_complete=False,
                          warnings=tuple(sorted(warnings)), prefix=(relative, committed, revision))
