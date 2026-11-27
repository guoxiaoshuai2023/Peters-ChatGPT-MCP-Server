"""Read Antigravity App's local conversation summaries and visible transcript text."""

from contextlib import contextmanager
import hashlib
from itertools import zip_longest
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.parse import unquote_to_bytes, urlsplit

from .agent_history_source import Message, Projection, SourceRoot, Thread, _identity, _stamp
from .catalog import AccessError


# https://antigravity.google/docs/hooks#common-input-fields describes the path.
# The v2.32.1 App's language_server embeds the compact transcript record layout
# in its conversation_transcript system prompt. This is distinct from ACP SQLite.
# The same bundled implementation classifies hook user messages as SYSTEM_SDK.
VERSIONS = frozenset({'2.32.1', '2.33.0'})
VERSION_PATTERN = re.compile(r'2\.(3[2-9]|[4-9][0-9])\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z', re.ASCII)
INDEX = 'conversation_summaries.db'


def _supported_version(version):
    if version is None:
        return True
    return isinstance(version, str) and (version in VERSIONS or VERSION_PATTERN.fullmatch(version) is not None)


def _supports_native_sqlite(version):
    if not isinstance(version, str):
        return False
    match = VERSION_PATTERN.fullmatch(version)
    return match is not None and int(match[1]) >= 33
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
TRUNCATION_MARKER = re.compile(r'\n<truncated ([1-9][0-9]{0,8}) bytes>\n')
PAIRABLE_CAPTURE_WARNINGS = frozenset({'missing_steps'})
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


def _text(record):
    content = record.get('content')
    if content is None:
        return ''
    if not isinstance(content, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in content):
        raise _unsupported('Antigravity transcript text has an unsupported encoding or shape.')
    return content


def _is_replayable_non_public_step(kind, source):
    """Only non-public internal/status records may be deduplicated on exact replay."""
    if (kind, source) in VISIBLE_ROLES:
        return False
    if source == 'USER_EXPLICIT' or (
        kind in ('USER_INPUT', 'PLANNER_RESPONSE')
        and source not in ('SYSTEM', 'SYSTEM_SDK', 'USER_IMPLICIT')
    ):
        return False
    return True


class _Transcript:
    def __init__(self, stream):
        self.stream = stream
        self.before = os.fstat(stream.fileno())
        if self.before.st_size > MAX_TRANSCRIPT_BYTES:
            raise _budget('Antigravity transcript exceeds the reader byte limit.')
        self.identity = ':'.join(str(part) for part in _identity(self.before))
        self.digest = hashlib.sha256()
        self.consumed = self.committed = 0
        self.warnings = set()
        self.replayed_count = 0
        self.replayed_digest = hashlib.sha256()

    @property
    def revision(self):
        return self.digest.hexdigest()

    def __iter__(self):
        prior_index = -1
        seen_non_public_digests = {}
        for line_index in range(MAX_RECORDS + 1):
            raw = self.stream.readline(min(MAX_RECORD_BYTES + 1, self.before.st_size - self.consumed))
            self.consumed += len(raw)
            if not raw:
                break
            if line_index == MAX_RECORDS or len(raw) > MAX_RECORD_BYTES:
                raise _budget('Antigravity transcript exceeds the reader record limit.')
            if not raw.endswith(b'\n'):
                self.warnings.add('incomplete_tail_omitted')
                break
            self.digest.update(raw)
            self.committed = self.consumed
            step = _profile_record(raw)
            index, kind, source, status, record = step
            if index <= prior_index:
                if _is_replayable_non_public_step(kind, source):
                    raw_digest = hashlib.sha256(raw).digest()
                    if seen_non_public_digests.get(index) == raw_digest:
                        marker = json.dumps(
                            [line_index, index, kind, source, status, record.get('created_at')],
                            ensure_ascii=True, separators=(',', ':'),
                        ).encode('utf-8') + b'\n'
                        self.replayed_digest.update(marker)
                        self.replayed_count += 1
                        continue
                raise _unsupported('Antigravity transcript steps are not strictly ordered.')
            if index != prior_index + 1:
                self.warnings.add('missing_steps')
            prior_index = index
            if _is_replayable_non_public_step(kind, source):
                seen_non_public_digests[index] = hashlib.sha256(raw).digest()
            yield step
        if prior_index < 0:
            raise AccessError('Antigravity transcript has no committed records yet.', code='waiting_source_stable')


@contextmanager
def _transcript(root, relative):
    with root.open(relative) as stream:
        capture = _Transcript(stream)
        yield capture
        if (_stamp(capture.before) != _stamp(os.fstat(stream.fileno()))
                or capture.consumed != capture.before.st_size):
            raise AccessError('Antigravity transcript changed during capture.', code='waiting_source_stable')


def _matches_truncation(compact, full):
    # The native compactor writes the exact count of omitted UTF-8 bytes.
    marker = TRUNCATION_MARKER.search(compact)
    if marker is None or TRUNCATION_MARKER.search(compact, marker.end()) is not None:
        return False
    head, tail = compact[:marker.start()], compact[marker.end():]
    if not head or not tail or not full.startswith(head) or not full.endswith(tail):
        return False
    omitted = full[len(head):len(full) - len(tail)]
    return len(omitted.encode('utf-8')) == int(marker[1])


def _paired_steps(compact, full):
    for left, right in zip_longest(compact, full):
        if left is None or right is None or left[:4] != right[:4]:
            raise _unsupported('Antigravity companion steps do not match the compact transcript.')
        index, kind, source, status, record = left
        counterpart = right[4]
        if record.get('created_at') != counterpart.get('created_at'):
            raise _unsupported('Antigravity companion timestamps do not match the compact transcript.')
        if (kind, source) in VISIBLE_ROLES and status == 'DONE':
            compact_text, full_text = _text(record), _text(counterpart)
            if _content_is_truncated(counterpart):
                raise _unsupported('Antigravity companion still contains truncated visible text.')
            if _content_is_truncated(record):
                if not _timestamp(record.get('created_at')) or not _matches_truncation(compact_text, full_text):
                    raise _unsupported('Antigravity companion text does not match the compact transcript.')
                record = {**record, 'content': full_text, 'truncated_fields': []}
            elif compact_text != full_text:
                raise _unsupported('Antigravity companion changes an intact visible message.')
        yield index, kind, source, status, record


def _drain(gen):
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def _project_iter(steps, manifest=None):
    messages = []
    warnings = set()
    saw_expected_message = False
    visible_chars = 0
    current_turn = ''
    for step_no, (index, kind, source, status, record) in enumerate(steps):
        if step_no and step_no % 256 == 0:
            yield {'phase': 'scanning'}
        if manifest is not None:
            manifest.append((index, kind, source, status, _timestamp(record.get('created_at'))))
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
        content = _text(record)
        if not content:
            continue
        visible_chars += len(content)
        if visible_chars > MAX_VISIBLE_CHARS:
            raise _budget('Antigravity transcript exceeds the visible text limit.')
        if role == 'user':
            current_turn = f'turn:{index}'
        turn_id = current_turn or f'turn:{index}'
        messages.append(Message(role, content, f'step:{index}', _timestamp(record.get('created_at')), turn_id))
    if not saw_expected_message:
        warnings.add('no_verified_public_step')
    return tuple(messages), warnings


def _project(steps, manifest=None):
    return _drain(_project_iter(steps, manifest))


class Adapter:
    supports_inheritance = False
    project_partition_complete = False

    def __init__(self, root: SourceRoot, version: str):
        if not _supported_version(version):
            raise _unsupported('Antigravity App version is not supported.')
        self.root = root
        self.version = version
        self.warnings = ()
        self.project_partition_complete = False

    def _index(self, connection):
        if connection.execute('PRAGMA user_version').fetchone() != (INDEX_VERSION,):
            raise _unsupported('Antigravity conversation index version is not supported.')
        self._has_project_identity = 'project_id' in {
            row[1] for row in connection.execute('PRAGMA table_info(conversation_summaries)')}

    def _native_project(self, connection, native_id):
        if not self._has_project_identity:
            return ''
        row = connection.execute('SELECT substr(project_id, 1, 37) FROM conversation_summaries '
                                 'WHERE conversation_id = ?', (native_id,)).fetchone()
        return row[0] if row is not None and _native_id(row[0]) else ''

    @staticmethod
    def _row(connection, native_id):
        return connection.execute(
            INDEX_ROWS + ' WHERE s.conversation_id = ?',
            (MAX_INDEX_FIELD_CHARS + 1, native_id),
        ).fetchone()

    def _materialize(self, connection, row, *, denied_ids=()):
        native_id, title, updated, workspaces, primary_parent, indexed_parent, depth = row
        if not _native_id(native_id) or type(depth) is not int or depth != 0:
            return None
        contexts = dict.fromkeys(_workspace_paths(workspaces))
        parent = _parents(primary_parent, indexed_parent)
        seen = {native_id}
        ancestors = []
        ancestor_projects = []
        while parent:
            if parent in denied_ids:
                return None
            if parent in seen:
                raise _unsupported('Antigravity conversation ancestry contains a cycle.')
            if len(ancestors) >= MAX_ANCESTORS:
                raise _budget('Antigravity conversation ancestry exceeds the reader limit.')
            ancestors.append(parent)
            seen.add(parent)
            ancestor = self._row(connection, parent)
            if ancestor is None:
                break
            ancestor_projects.append((parent, self._native_project(connection, parent)))
            contexts.update(dict.fromkeys(_workspace_paths(ancestor[3])))
            if len(contexts) > MAX_CONTEXTS:
                raise _budget('Antigravity conversation workspace history exceeds the reader limit.')
            parent = _parents(ancestor[4], ancestor[5])
        # This index records workspace membership but no verified historical
        # workspace ledger. Keep explicit thread authorization mandatory.
        return Thread(native_id=native_id, title=title[:500] if isinstance(title, str) else '',
                      updated_at=_timestamp(updated), contexts=tuple(contexts),
                      ancestors=tuple(ancestors), context_complete=False,
                      agent='antigravity', surface='desktop',
                      native_project_id=self._native_project(connection, native_id),
                      ancestor_projects=tuple(ancestor_projects))

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

    def discover_project(self, project_roots, *, explicit_ids=(), excluded_roots=(), denied_ids=()):
        """Select metadata candidates without claiming historical attribution.

        Current index workspace membership can narrow the search. It cannot
        prove the workspaces attached during an entire previous conversation.
        Explicit snapshot exceptions are verified independently by the core.
        """
        roots = tuple(PurePosixPath(path) for path in project_roots
                      if isinstance(path, str) and path.startswith('/') and '..' not in PurePosixPath(path).parts)
        excluded = tuple(PurePosixPath(path) for path in excluded_roots
                         if isinstance(path, str) and path.startswith('/') and '..' not in PurePosixPath(path).parts)
        explicit = tuple(dict.fromkeys(native for native in explicit_ids if _native_id(native)))
        denied = frozenset(native for native in denied_ids if _native_id(native))
        if len(explicit) > 128:
            raise _budget('Antigravity explicit candidate set exceeds the reader limit.')

        def candidate(raw):
            try:
                paths = tuple(PurePosixPath(path) for path in _workspace_paths(raw))
            except AccessError:
                # An unreadable workspace field cannot identify this project.
                return 0
            return int(any(path.is_relative_to(root) for path in paths for root in roots)
                       and not any(path.is_relative_to(root) for path in paths for root in excluded))

        def _valid_workspace_list(raw):
            if not isinstance(raw, str) or len(raw) > MAX_INDEX_FIELD_CHARS:
                return False
            try:
                uris = json.loads(raw)
            except (ValueError, RecursionError):
                return False
            if not isinstance(uris, list) or len(uris) > 64:
                return False
            return all(_local_workspace(uri) is not None for uri in uris)

        native_capable = _supports_native_sqlite(self.version)
        self.project_partition_complete = False
        self.warnings = ('association_unverified',)
        try:
            with self.root.sqlite(INDEX) as connection:
                self._index(connection)
                if native_capable:
                    # Only mark partition complete when every non-denied top-level row
                    # has parseable local workspace_uris so no candidate could be hidden.
                    unparseable = False
                    for cid, raw_ws in connection.execute(
                        'SELECT conversation_id, substr(workspace_uris, 1, ?) '
                        'FROM conversation_summaries WHERE nesting_depth = 0 AND length(conversation_id) = 36',
                        (MAX_INDEX_FIELD_CHARS + 1,),
                    ):
                        if cid not in denied and not _valid_workspace_list(raw_ws):
                            unparseable = True
                            break
                    if not unparseable:
                        self.project_partition_complete = True
                        self.warnings = ()
                connection.create_function('mcp_workspace_candidate', 1, candidate, deterministic=True)
                selected = 'mcp_workspace_candidate(substr(s.workspace_uris, 1, ?))'
                arguments = [MAX_INDEX_FIELD_CHARS + 1, MAX_INDEX_FIELD_CHARS + 1]
                if explicit:
                    selected += ' OR s.conversation_id IN (' + ','.join('?' for _ in explicit) + ')'
                    arguments.extend(explicit)
                if denied:
                    connection.create_function('mcp_thread_denied', 1, lambda native: int(native in denied), deterministic=True)
                    selected = '(' + selected + ') AND NOT mcp_thread_denied(s.conversation_id)'
                query = INDEX_ROWS + ''' WHERE s.nesting_depth = 0 AND length(s.conversation_id) = 36
                                          AND (''' + selected + ''')
                                          ORDER BY s.last_modified_time DESC, s.conversation_id ASC'''
                for row in connection.execute(query, arguments):
                    thread = self._materialize(connection, row, denied_ids=denied)
                    if thread is not None and not denied.intersection(thread.ancestors):
                        yield thread
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
        return self._snapshot(thread)

    def snapshot_iter(self, thread):
        if 'snapshot' in self.__dict__ or '_snapshot' in self.__dict__:
            return self.snapshot(thread)
        return (yield from self._snapshot_iter(thread))

    def _snapshot(self, thread, manifest=None):
        return _drain(self._snapshot_iter(thread, manifest))

    def _snapshot_iter(self, thread, manifest=None):
        if not _native_id(thread.native_id):
            raise AccessError('Antigravity conversation is unavailable.', code='source_unavailable')
        relative = f'brain/{thread.native_id}/.system_generated/logs/transcript.jsonl'
        with _transcript(self.root, relative) as compact:
            messages, warnings = yield from _project_iter(compact, manifest)
        warnings.update(compact.warnings)
        revision = compact.revision
        identity = compact.identity
        prefix = (relative, compact.committed, revision)
        # Automatic attribution needs both logs for an omitted or still-open
        # tool row, or whenever transcript_full.jsonl exists alongside transcript.jsonl.
        # When a verbatim non-public step replay was skipped and a companion log exists,
        # corroborate both logs so conflicting two-log replay evidence fails closed.
        companion = relative.removesuffix('transcript.jsonl') + 'transcript_full.jsonl'
        has_companion = False
        if manifest is not None or compact.replayed_count > 0:
            try:
                with self.root.open(companion):
                    has_companion = True
            except AccessError:
                has_companion = False
        require_pair = (
            manifest is not None and (
                has_companion or 'missing_steps' in warnings or any(row[3] == 'RUNNING' for row in manifest)
            )
        ) or (compact.replayed_count > 0 and has_companion)
        if ('truncated_content_omitted' in warnings or require_pair) and compact.warnings <= PAIRABLE_CAPTURE_WARNINGS:
            yield {'phase': 'scanning'}
            try:
                recovered = yield from self._recover_iter(relative, compact)
            except AccessError as error:
                if has_companion and (manifest is not None or compact.replayed_count > 0) and error.code == 'unsupported_format':
                    raise
                if error.code not in {'source_unavailable', 'unsupported_format', 'resource_exhausted'}:
                    raise
            else:
                messages, warnings, full = recovered
                identity = f'paired:{compact.identity}:{full.identity}'
                revision = hashlib.sha256(f'{compact.revision}:{full.revision}'.encode('ascii')).hexdigest()
                # Append-only proof for one file cannot vouch for a paired projection.
                prefix = None
        return Projection(messages=messages, revision=revision, identity=identity,
                          contexts=thread.contexts, ancestors=thread.ancestors, context_complete=False,
                          warnings=tuple(sorted(warnings)), prefix=prefix)

    def inspect_native(self, thread):
        """Local operator diagnostic. Only the result class, counts and digest are returned."""
        from .agent_history_antigravity_native import Assessment, EvidenceIssue, capture
        try:
            observation, _ = capture(self, thread)
            return observation
        except EvidenceIssue as issue:
            return Assessment('unverified', str(issue))
        except AccessError as error:
            return Assessment('unverified', error.code)

    def snapshot_for_inheritance_iter(self, thread, *, excluded_related=()):
        """Cooperative generator variant of snapshot_for_inheritance for supervised workers."""
        if 'snapshot_for_inheritance' in self.__dict__:
            return self.snapshot_for_inheritance(thread, excluded_related=excluded_related)
        from .agent_history_antigravity_native import EvidenceIssue, capture_iter
        try:
            _, projection = yield from capture_iter(self, thread, excluded_related=excluded_related)
            return projection
        except EvidenceIssue as issue:
            if str(issue) == 'native_capture_changed':
                raise AccessError('The native history snapshot changed during capture.', code='waiting_source_stable') from None
        except AccessError as error:
            if error.code in {'waiting_source_stable', 'resource_exhausted'}:
                raise
        raise AccessError('The session\'s complete project association is unverified.', code='association_unverified')

    def snapshot_for_inheritance(self, thread, *, excluded_related=()):
        """Only a supported native desktop trajectory can supply complete project evidence."""
        from .agent_history_antigravity_native import EvidenceIssue, capture
        try:
            _, projection = capture(self, thread, excluded_related=excluded_related)
            return projection
        except EvidenceIssue as issue:
            if str(issue) == 'native_capture_changed':
                raise AccessError('The native history snapshot changed during capture.', code='waiting_source_stable') from None
        except AccessError as error:
            if error.code in {'waiting_source_stable', 'resource_exhausted'}:
                raise
        raise AccessError('The session\'s complete project association is unverified.', code='association_unverified')

    def _recover(self, relative, original):
        return _drain(self._recover_iter(relative, original))

    def _recover_iter(self, relative, original):
        companion = relative.removesuffix('transcript.jsonl') + 'transcript_full.jsonl'
        with _transcript(self.root, relative) as compact, _transcript(self.root, companion) as full:
            if _stamp(compact.before) != _stamp(original.before):
                raise AccessError('Antigravity transcript changed during capture.', code='waiting_source_stable')
            if full.before.st_size == 0:
                raise _unsupported('Antigravity companion contains incomplete steps.')
            messages, warnings = yield from _project_iter(_paired_steps(compact, full))
            # Exact step-by-step pairing proves any numbering gaps and replayed
            # non-public records are shared at identical positions across both logs.
            # A partial record or any other capture issue still disqualifies recovery.
            if (compact.replayed_count != full.replayed_count
                    or compact.replayed_digest.digest() != full.replayed_digest.digest()):
                raise _unsupported('Antigravity companion steps do not match the compact transcript.')
            if compact.warnings != full.warnings or not compact.warnings <= PAIRABLE_CAPTURE_WARNINGS:
                raise _unsupported('Antigravity companion contains incomplete steps.')
            if compact.revision != original.revision:
                raise AccessError('Antigravity transcript changed during capture.', code='waiting_source_stable')
        return messages, warnings | compact.warnings, full
