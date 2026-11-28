"""Read DeepSeek Harness v4 session files without opening the Harness runtime."""

from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from .agent_history_source import Message, Projection, SourceRoot, Thread
from .catalog import AccessError


_VERSION = '0.2.2-rc.3'
_GENERATION = re.compile(r'session(?:\.v([1-9][0-9]{0,15}))?\.jsonl(\.zstd)?\Z')
_ENCODED_ID = re.compile(r'(?:[A-Za-z0-9._-]|~[0-9A-F]{4})+\Z')
_SAFE_UNITS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
_HEADER_FIELDS = frozenset(('type', 'version', 'id', 'cwd', 'createdAt', 'parentSession',
                            'isSeeded', 'origin', 'delegationDepth', 'agentPreset'))
_ROW_FIELDS = frozenset(('type', 'seq', 'time', 'data', 'ignorable', 'surfaceOp', 'sourceEventSeqs'))
# The released registry determines which log-only events may be skipped without losing context.
_EVENTS = frozenset('''agent-preset/selected agent/inbox/spliced approval/asked approval/decided
approval/policy assistant/attempt assistant/message command/done command/run compaction/end
compaction/prune compaction/start compaction/summary deliverables/presented developer/message
feedback/message-delete feedback/message-put feedback/record goal/change hook/invoked hook/result
image/offload job/registered job/settled llm/retry llm/retry-started model/selection permission/preset
plan/mode request/context request/header sandbox/mode schedule/change session-log-deepseek/delivery-accepted
session/end-seed session/title session/title-llm-request step/end step/start subagent/catalog
subagent/descriptor subagent/model-selection-policy system/message team/member team/message/delivered
team/message/queued team/mode team/task todo/write tool-workflow/agent-end tool-workflow/agent-start
tool-workflow/run-end tool-workflow/run-start tool/call tool/ptc-dispatch tool/ptc-dispatch-start
tool/result turn/end turn/start user/message web/deepseek-search-llm-request working-directory/change
workspace/changes'''.split())
_BLOCK = 256 * 1024
_MAX_HEADER = 64 * 1024
_MAX_RECORD = 8 * 1024 * 1024
_MAX_FRAME = 16 * 1024 * 1024
_MAX_FILE = 128 * 1024 * 1024
_MAX_DECODED = 256 * 1024 * 1024
_MAX_CHARACTERS = 4 * 1024 * 1024
_MAX_EVENTS = 250_000
_MAX_MESSAGES = 20_000
_MAX_ENTRIES = 12_000
_MAX_FULL_PARTITION_ENTRIES = 256
_MAX_ANCESTORS = 8
_MAX_CONTEXTS = 64
_MAX_INTEGER = (1 << 53) - 1
_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
_SESSION_SENDERS = frozenset(('agent-message', 'subagent-report', 'subagent-settled'))


def _unsupported():
    return AccessError('DeepSeek Harness history has an unsupported or invalid format.',
                       code='unsupported_format')


def _unstable():
    return AccessError('DeepSeek Harness history changed during reading.', code='waiting_source_stable')


def _budget():
    return AccessError('DeepSeek Harness history exceeds its read limits.', code='resource_exhausted')


def _version_number(value):
    return type(value) is int and 0 <= value <= _MAX_INTEGER


def _text(value, maximum):
    return (isinstance(value, str) and 0 < len(value) <= maximum and '\x00' not in value
            and not any(0xd800 <= ord(char) <= 0xdfff for char in value))


def _cwd(value):
    return _text(value, 4096) and value.startswith('/')


def _iso(milliseconds):
    try:
        return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat(timespec='milliseconds')
    except (ValueError, OverflowError, OSError):
        return ''


def _units(text):
    encoded = text.encode('utf-16-le')
    for index in range(0, len(encoded), 2):
        yield chr(encoded[index] | (encoded[index + 1] << 8))


def _escaped(unit):
    return unit if unit in _SAFE_UNITS else f'~{ord(unit):04X}'


def _encode_id(value):
    if not _text(value, 255):
        raise _unsupported()
    return '~002E' * len(value) if value in ('.', '..') else ''.join(map(_escaped, _units(value)))


def decode_directory_id(value):
    """Translate a Codeg external ID from the canonical Harness directory spelling."""
    if not isinstance(value, str) or len(value) > 255 or not _ENCODED_ID.fullmatch(value):
        return None
    units = bytearray()
    for part in re.findall(r'~[0-9A-F]{4}|[A-Za-z0-9._-]', value):
        unit = int(part[1:], 16) if part.startswith('~') else ord(part)
        units.extend(unit.to_bytes(2, 'little'))
    try:
        decoded = units.decode('utf-16-le')
        if _encode_id(decoded) == value:
            return decoded
    except (UnicodeDecodeError, AccessError):
        pass
    return None


def _project_key(cwd):
    if cwd is None:
        return '_no-cwd'
    result = []
    separator = False
    for unit in _units(cwd):
        if unit not in '/\\:':
            result.append(_escaped(unit))
            separator = False
        elif not separator:
            result.append('-')
            separator = True
    slug = ''.join(result).lstrip('-') or 'root'
    return '--' + slug[:251] + '--'


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result


def _reject_constants(_):
    raise ValueError('non-finite JSON value')


def _record(raw, limit):
    if len(raw) > limit:
        raise _budget()
    try:
        item = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_reject_constants)
    except (ValueError, RecursionError):
        raise _unsupported() from None
    if not isinstance(item, dict):
        raise _unsupported()
    return item


def _file_identity(info):
    return f'{info.st_dev}:{info.st_ino}:{getattr(info, "st_birthtime", None)}'


def _stamp(info):
    return (_file_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _FileCut:
    def __init__(self, stream):
        self.stream = stream
        self.stamp = _stamp(os.fstat(stream.fileno()))
        self.remaining = self.stamp[1]
        self.committed = 0

    def read(self, count=_BLOCK):
        count = min(count, self.remaining)
        data = self.stream.read(count)
        if len(data) != count:
            raise _unstable()
        self.remaining -= count
        return data

    def verify(self):
        if _stamp(os.fstat(self.stream.fileno())) != self.stamp:
            raise _unstable()

    def physical_digest(self):
        self.verify()
        self.stream.seek(0)
        digest = hashlib.sha256()
        remaining = self.committed
        while remaining:
            block = self.stream.read(min(remaining, _BLOCK))
            if not block:
                raise _unstable()
            digest.update(block)
            remaining -= len(block)
        self.verify()
        return digest.hexdigest()


def _frames(source, cap):
    """Yield complete frames and a None marker for a torn final frame."""
    pending = b''
    while pending or source.remaining:
        if len(pending) < len(_ZSTD_MAGIC):
            pending += source.read()
        if len(pending) < len(_ZSTD_MAGIC):
            if not _ZSTD_MAGIC.startswith(pending):
                raise _unsupported()
            yield None
            return
        if not pending.startswith(_ZSTD_MAGIC):
            raise _unsupported()
        decoder = zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: 25})
        frame = bytearray()
        while not decoder.eof:
            if decoder.needs_input:
                if not pending:
                    pending = source.read()
                if not pending:
                    yield None
                    return
            try:
                block = decoder.decompress(pending, min(_BLOCK, cap - len(frame) + 1))
            except zstd.ZstdError:
                raise _unsupported() from None
            pending = b''
            frame.extend(block)
            if len(frame) > cap:
                raise _budget()
        pending = decoder.unused_data
        source.committed = source.stamp[1] - source.remaining - len(pending)
        yield frame


def _lines(source, compressed):
    if compressed:
        for index, frame in enumerate(_frames(source, _MAX_FRAME)):
            if frame is None:
                yield None
                return
            if not frame.endswith(b'\n') or (index == 0 and frame.count(b'\n') != 1):
                raise _unsupported()
            start = 0
            while start < len(frame):
                end = frame.index(b'\n', start) + 1
                yield frame[start:end]
                start = end
        return

    line = bytearray()
    while block := source.read():
        start = 0
        while start < len(block):
            end = block.find(b'\n', start) + 1
            if not end:
                line.extend(block[start:])
                if len(line) > _MAX_RECORD:
                    raise _budget()
                break
            line.extend(block[start:end])
            source.committed += len(line)
            yield line
            line = bytearray()
            start = end
    if line:
        yield None


@dataclass(frozen=True)
class _Header:
    native_id: str
    cwd: str | None
    created_at: int
    modified_at: str
    parent: str | None
    seeded: bool
    subagent: bool


def _header(line, location, modified):
    if line is None:
        raise _unstable()
    record = _record(line, _MAX_HEADER)
    native_id = record.get('id')
    cwd = record.get('cwd')
    parent = record.get('parentSession')
    if (record.keys() - _HEADER_FIELDS or record.get('type') != 'session'
            or type(record.get('version')) is not int or record['version'] != 4
            or not _version_number(record.get('createdAt'))
            or not _version_number(record.get('delegationDepth'))
            or type(record.get('isSeeded')) is not bool
            or ('cwd' in record and not _cwd(cwd))
            or ('parentSession' in record and not _text(parent, 255))
            or ('origin' in record and record['origin'] != 'subagent')
            or ('agentPreset' in record and not _text(record['agentPreset'], 255))):
        raise _unsupported()
    if location.split('/')[:2] != [_project_key(cwd), _encode_id(native_id)]:
        raise _unsupported()
    return _Header(native_id, cwd, record['createdAt'], modified, parent, record['isSeeded'],
                   record.get('origin') == 'subagent')


def _event(line, seq):
    item = _record(line, _MAX_RECORD)
    kind = item.get('type')
    if (not _text(kind, 200) or item.keys() - _ROW_FIELDS or type(item.get('seq')) is not int
            or item['seq'] != seq or not _version_number(item.get('time')) or 'data' not in item
            or ('ignorable' in item and item['ignorable'] is not True)):
        raise _unsupported()
    if kind not in _EVENTS and (item.get('ignorable') is not True or 'surfaceOp' in item
                                or 'sourceEventSeqs' in item):
        raise _unsupported()
    return item


def _visible_text(message, role, producer):
    if (not isinstance(message, dict) or message.get('role') != role
            or not isinstance(message.get('source'), dict) or not isinstance(message.get('content'), list)):
        raise _unsupported()
    kind = message['source'].get('kind')
    if not _text(kind, 255) or kind == 'plugin':
        raise _unsupported()
    if kind != producer:
        return ''
    result = []
    for block in message['content']:
        if not isinstance(block, dict):
            raise _unsupported()
        if block.get('type') == 'text':
            value = block.get('text')
            if not isinstance(value, str):
                raise _unsupported()
            if value:
                # Unicode surrogates can be stored by the JS producer as JSON
                # escapes, but cannot form UTF-8; handle them without leaking a traceback.
                result.append(re.sub('[\ud800-\udfff]', '\ufffd', value))
    return '\n\n'.join(result)


class _EventScan:
    def __init__(self, header, prefix_size):
        self.created_at = header.created_at
        self.last_ms = 0 if header.seeded else header.created_at
        self.last_commit_ms = header.created_at
        self.ordered = True
        self.contexts = {header.cwd: None} if header.cwd else {}
        self.complete = bool(header.cwd)
        self.warnings = set()
        self.messages = []
        self.characters = 0
        self.title = ''
        self.turn = ''
        self._prefix = hashlib.sha256()
        self.prefix_digest = self._prefix.hexdigest() if prefix_size == 0 else None
        self.prefix_size = prefix_size
        self.seed_digest = None
        self.seed_size = None
        self.related = {}

    def add(self, event, line, *, messages):
        kind, seq, data = event['type'], event['seq'], event['data']
        self.ordered = self.ordered and event['time'] >= self.last_ms
        self.created_at = min(self.created_at, event['time'])
        self.last_ms = max(self.last_ms, event['time'])
        self.last_commit_ms = max(self.last_commit_ms, self.last_ms)
        if kind not in _EVENTS:
            self.complete = False
            self.warnings.add('unknown_event_skipped')
        if kind == 'session/end-seed':
            if not isinstance(data, dict) or data.get('inherited', True) is not True:
                raise _unsupported()
            if data.get('inherited') is True:
                self.seed_size = seq
                self.seed_digest = self._prefix.hexdigest()
        self._prefix.update(line)
        if seq + 1 == self.prefix_size:
            self.prefix_digest = self._prefix.hexdigest()
        if kind == 'working-directory/change':
            if not isinstance(data, dict) or not _cwd(data.get('cwd')):
                raise _unsupported()
            self.contexts[data['cwd']] = None
            if len(self.contexts) > _MAX_CONTEXTS:
                raise _budget()
        elif kind in ('turn/start', 'turn/end'):
            if not isinstance(data, dict) or not _version_number(data.get('turn')):
                raise _unsupported()
            self.turn = str(data['turn']) if kind == 'turn/start' else ''
        elif kind == 'session/title':
            if not isinstance(data, dict) or not _text(data.get('title'), 4096):
                raise _unsupported()
            self.title = data['title']
        elif kind in ('user/message', 'assistant/message'):
            if kind == 'user/message' and event.get('surfaceOp') == 'append':
                self._related_sessions(data)
            if messages:
                self._append_message(event)

    def _related_sessions(self, data):
        if not isinstance(data, dict) or not isinstance(data.get('source'), dict):
            raise _unsupported()
        source = data['source']
        kind = source.get('kind')
        if kind == 'session-reference':
            if 'references' in source:
                references = source['references']
                if not isinstance(references, list):
                    raise _unsupported()
                if len(references) > _MAX_ANCESTORS:
                    raise _budget()
                ids = [ref.get('sessionId') if isinstance(ref, dict) else None for ref in references]
            else:
                # The released migrations can retain the original singular source shape.
                ids = [source.get('sessionId')]
        elif isinstance(kind, str) and kind in _SESSION_SENDERS:
            ids = [source.get('senderSessionId')]
        elif kind == 'team-message':
            ids = [None]  # A team member ID is not a local session identity.
        else:
            return
        if not ids or any(not _text(native_id, 255) for native_id in ids):
            self.complete = False
            self.warnings.add('related_context_unverified')
        for native_id in ids:
            if _text(native_id, 255):
                self.related[native_id] = None
        if len(self.related) > _MAX_ANCESTORS:
            raise _budget()

    def _append_message(self, event):
        operation = event.get('surfaceOp')
        if operation != 'append':
            if (not isinstance(operation, dict) or operation.get('op') != 'replace'
                    or not _version_number(operation.get('startSeq'))
                    or not _version_number(operation.get('endSeq'))
                    or not operation['startSeq'] <= operation['endSeq'] < event['seq']):
                raise _unsupported()
            return
        kind = event['type']
        if kind == 'assistant/message':
            data = event['data']
            if not isinstance(data, dict) or not _version_number(data.get('turn')):
                raise _unsupported()
            role, turn = 'assistant', str(data['turn'])
            text = _visible_text(data.get('message'), role, 'model')
        else:
            role, turn = 'user', self.turn
            text = _visible_text(event['data'], role, 'user')
        if text.strip():
            self.characters += len(text)
            if self.characters > _MAX_CHARACTERS or len(self.messages) >= _MAX_MESSAGES:
                raise _budget()
            self.messages.append(Message(role, text, f"seq:{event['seq']}", _iso(event['time']), turn))


class _NativeLocations:
    """Resolve only IDs needed for a selected session and its provenance."""

    def __init__(self, adapter):
        self.adapter = adapter
        self.cache = {}

    def get(self, encoded_id, default=()):
        if encoded_id not in self.cache:
            found = self.adapter._index(native_ids=(encoded_id,))
            self.cache[encoded_id] = found.get(encoded_id, default)
        return self.cache[encoded_id]


class Adapter:
    """A pinned adapter for the dsh-v0.2.2-rc.3 local persistence generation."""

    project_partition_complete = False

    def __init__(self, root: SourceRoot, version: str):
        if version not in (_VERSION, 'dsh-v' + _VERSION):
            raise _unsupported()
        self.root = root
        self.warnings = ()

    def _index(self, *, native_ids=None, directory_filter=None):
        locations = defaultdict(list)
        count = 0
        selected_ids = frozenset(native_ids) if native_ids is not None else None
        listing = self.root.iter_entries if selected_ids is not None else self.root.entries
        for directory, kind in listing(select=directory_filter):
            if kind != 'dir' or not (directory == '_no-cwd' or (directory.startswith('--')
                                                                and directory.endswith('--'))):
                continue
            selected = selected_ids.__contains__ if selected_ids is not None else None
            for native, child_kind in listing(directory, select=selected):
                count += 1
                if count > _MAX_ENTRIES:
                    raise _budget()
                if child_kind == 'dir' and _ENCODED_ID.fullmatch(native):
                    locations[native].append(f'{directory}/{native}')
        return locations

    def _location(self, directory):
        logs = []
        for name, kind in self.root.entries(directory):
            match = _GENERATION.fullmatch(name) if kind == 'file' else None
            if match:
                version = int(match[1] or 0)
                if version <= _MAX_INTEGER:
                    logs.append((version, bool(match[2]), f'{directory}/{name}'))
        if not logs:
            return None
        if len({item[1] for item in logs}) != 1:
            raise _unsupported()
        version, compressed, path = max(logs)
        if version != 4:
            raise _unsupported()
        return path, compressed

    def _unique_location(self, paths):
        actual = [found for candidate in paths if (found := self._location(candidate)) is not None]
        if len(actual) > 1:
            raise _unsupported()
        return actual[0] if actual else None

    def _describe_at(self, location):
        path, compressed = location
        with self.root.open(path) as stream:
            cut = _FileCut(stream)
            if compressed:
                with closing(_frames(cut, _MAX_HEADER)) as frames:
                    first = next(frames, None)
                if first is not None and first.count(b'\n') != 1:
                    raise _unsupported()
            else:
                first = stream.readline(_MAX_HEADER + 1)
                if len(first) > _MAX_HEADER:
                    raise _budget()
                if not first.endswith(b'\n'):
                    first = None
            result = _header(first, path, _iso(cut.stamp[2] // 1_000_000))
            cut.verify()
        if result.subagent:
            return None
        return Thread(result.native_id, updated_at=result.modified_at,
                      contexts=(result.cwd,) if result.cwd else (),
                      ancestors=(result.parent,) if result.parent else (),
                      agent='deepseek_harness', surface='local_session')

    def discover(self):
        warnings = set()
        for paths in self._index().values():
            try:
                location = self._unique_location(paths)
                if location:
                    thread = self._describe_at(location)
                    if thread is not None:
                        yield thread
            except AccessError as error:
                warnings.add(error.code)
        self.warnings = tuple(sorted(warnings))

    def discover_project(self, project_roots, *, explicit_ids=(), excluded_roots=(), denied_ids=()):
        # Directory slugs are lossy. When the local store fits within the small
        # full-partition header budget, verify every session header directly so
        # clean projects can report exact partition completeness; otherwise fall
        # back to slug filtering without charging foreign session budgets.
        self.project_partition_complete = False
        self.warnings = ('association_unverified',)
        explicit = frozenset(_encode_id(native) for native in explicit_ids)
        denied = frozenset(_encode_id(native) for native in denied_ids)
        root_paths = tuple(Path(str(root)) for root in project_roots)
        excluded_paths = tuple(Path(str(root)) for root in excluded_roots)
        full_cap = min(_MAX_FULL_PARTITION_ENTRIES, _MAX_ENTRIES)
        locations = defaultdict(list)
        total_entries = 0
        exceeded = False
        unverifiable = False
        for directory, kind in self.root.iter_entries():
            if kind != 'dir' or not (directory == '_no-cwd' or (
                    directory.startswith('--') and directory.endswith('--'))):
                continue
            for native, child_kind in self.root.iter_entries(directory):
                total_entries += 1
                if total_entries > full_cap:
                    exceeded = True
                    break
                if child_kind == 'dir':
                    if _ENCODED_ID.fullmatch(native):
                        locations[native].append(f'{directory}/{native}')
                    else:
                        unverifiable = True
            if exceeded:
                break
        if not exceeded:
            for encoded, paths in locations.items():
                if encoded in denied:
                    continue
                try:
                    location = self._unique_location(paths)
                    thread = self._describe_at(location) if location is not None else None
                except AccessError:
                    unverifiable = True
                    continue
                if thread is None:
                    continue
                is_explicit = thread.native_id in explicit_ids
                if not is_explicit:
                    if not any(Path(context).is_relative_to(root)
                               for context in thread.contexts for root in root_paths):
                        continue
                    if any(Path(context).is_relative_to(excluded)
                           for context in thread.contexts for excluded in excluded_paths):
                        continue
                yield replace(thread, location=location[0])
            if not unverifiable:
                self.project_partition_complete = True
                self.warnings = ()
            return

        keys = tuple(_project_key(str(root)) for root in project_roots)

        def selected(name):
            return any(name == key or name.startswith(key[:-2] + '-') for key in keys)

        for directory, kind in self.root.iter_entries(select=lambda name: selected(name) or bool(explicit)):
            if kind != 'dir' or not (directory == '_no-cwd' or (
                    directory.startswith('--') and directory.endswith('--'))):
                continue
            in_project = selected(directory)

            def candidate(name):
                return name not in denied and _ENCODED_ID.fullmatch(name) is not None and (
                    in_project or name in explicit)

            for native, child_kind in self.root.iter_entries(directory, select=candidate):
                if child_kind != 'dir':
                    continue
                try:
                    location = self._unique_location((f'{directory}/{native}',))
                    thread = self._describe_at(location) if location is not None else None
                    if thread is not None:
                        if thread.native_id not in explicit_ids and any(
                                Path(context).is_relative_to(excluded)
                                for context in thread.contexts for excluded in excluded_paths):
                            continue
                        yield replace(thread, location=location[0])
                except AccessError:
                    # A lossy slug cannot attribute a malformed header to a project.
                    continue

    def describe_project(self, native_id):
        encoded = _encode_id(native_id)
        location = self._unique_location(self._index(native_ids=(encoded,)).get(encoded, ()))
        thread = self._describe_at(location) if location else None
        return replace(thread, location=location[0]) if thread is not None else None

    def describe(self, native_id):
        location = self._unique_location(self._index().get(_encode_id(native_id), ()))
        return self._describe_at(location) if location else None

    def _scan(self, location, *, messages, prefix_size=None):
        path, compressed = location
        with self.root.open(path) as stream, closing(_lines(cut := _FileCut(stream), compressed)) as lines:
            if cut.remaining > _MAX_FILE:
                raise _budget()
            first = next(lines, None)
            header = _header(first, path, _iso(cut.stamp[2] // 1_000_000))
            scan = _EventScan(header, prefix_size)
            digest = hashlib.sha256(first)
            consumed = len(first)
            for seq, line in enumerate(lines):
                if line is None:
                    scan.warnings.add('incomplete_tail_omitted')
                    break
                consumed += len(line)
                if consumed > _MAX_DECODED or seq >= _MAX_EVENTS:
                    raise _budget()
                scan.add(_event(line, seq), line, messages=messages)
                digest.update(line)
            proof = (path, cut.committed, cut.physical_digest()) if messages else None
            cut.verify()
        current = self._unique_location((path.rsplit('/', 1)[0],))
        if current != location:
            raise _unstable()
        if header.seeded != (scan.seed_size is not None):
            raise _unsupported()
        return header, scan, digest.hexdigest(), cut.stamp[0], proof

    def _parents(self, locations, child, child_scan):
        seen = {child.native_id}
        while child.parent is not None:
            parent = child.parent
            if parent in seen or len(seen) > _MAX_ANCESTORS:
                raise _unsupported()
            seen.add(parent)
            parent_location = self._unique_location(locations.get(_encode_id(parent), ()))
            if parent_location is None:
                yield parent, None, False
                return
            parent_header, parent_scan, _, _, _ = self._scan(parent_location, messages=False,
                                                             prefix_size=child_scan.seed_size)
            if child.seeded:
                verified = child_scan.seed_digest == parent_scan.prefix_digest
            else:
                verified = child.subagent
            yield parent, parent_scan, verified
            child, child_scan = parent_header, parent_scan
        if child.seeded:
            yield None, None, False

    def _provenance(self, locations, header, scan):
        earliest = scan.created_at
        latest = scan.last_commit_ms
        ordered = scan.ordered
        contexts = dict(scan.contexts)
        ancestors = {}
        related = dict(scan.related)
        warnings = set(scan.warnings)
        complete = scan.complete

        def observe(native_id, other):
            nonlocal complete, earliest, latest, ordered
            if native_id != header.native_id:
                ancestors[native_id] = None
            if other is not None:
                earliest = min(earliest, other.created_at)
                latest = max(latest, other.last_commit_ms)
                ordered = ordered and other.ordered
                contexts.update(other.contexts)
                related.update(other.related)
                warnings.update(other.warnings)
                complete = complete and other.complete
            if len(ancestors) > _MAX_ANCESTORS or len(contexts) > _MAX_CONTEXTS:
                raise _budget()

        def parents(child, child_scan):
            nonlocal complete
            for native_id, other, verified in self._parents(locations, child, child_scan):
                if native_id is not None:
                    observe(native_id, other)
                if not verified:
                    complete = False
                    warnings.add('parent_unverified')

        parents(header, scan)
        while related:
            native_id = next(iter(related))
            related.pop(native_id)
            if native_id == header.native_id or native_id in ancestors:
                continue
            location = self._unique_location(locations.get(_encode_id(native_id), ()))
            if location is None:
                observe(native_id, None)
                complete = False
                warnings.add('related_context_unverified')
                continue
            other_header, other, _, _, _ = self._scan(location, messages=False)
            observe(native_id, other)
            parents(other_header, other)
        return tuple(contexts), tuple(ancestors), complete, tuple(sorted(warnings)), earliest, latest if ordered else None

    def snapshot(self, thread):
        locations = _NativeLocations(self) if thread.location else self._index()
        location = self._unique_location(locations.get(_encode_id(thread.native_id), ()))
        if location is None:
            raise AccessError('The DeepSeek Harness session is unavailable.', code='source_unavailable')
        header, scan, revision, identity, proof = self._scan(location, messages=True)
        if header.subagent or header.native_id != thread.native_id:
            raise _unsupported()
        contexts, ancestors, complete, warnings, earliest, latest = self._provenance(locations, header, scan)
        return Projection(tuple(scan.messages), revision, identity, contexts, ancestors,
                          complete, warnings, title=scan.title, prefix=proof, origin_ns=earliest * 1_000_000,
                          last_ns=(latest + 1) * 1_000_000 - 1 if latest is not None else None)
