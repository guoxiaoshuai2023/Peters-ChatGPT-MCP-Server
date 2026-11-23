"""Verify Antigravity Desktop 2.33.0's native SQLite-v1 trajectory.

Local Desktop selects the workspace on StartCascade. An ordinary continuation
addresses the existing cascade; workspace or agent overrides and forks have
distinct native shapes. Verify the complete, supported lifecycle before
associating its public projection with the trajectory's creation workspaces.
"""

from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import struct

from .agent_history_source import _stamp
from .catalog import AccessError


MAX_STEPS = 50_000
MAX_BLOB = 8 * 1024 * 1024
SOURCE_NAMES = {2: 'MODEL', 4: 'USER_EXPLICIT', 5: 'SYSTEM'}
# Only these step shapes have been verified against this desktop build.
STEP_NAMES = {14: 'USER_INPUT', 15: 'PLANNER_RESPONSE', 17: 'ERROR_MESSAGE', 132: 'GENERIC'}
STEP_SLOTS = {14: 19, 15: 20, 17: 24, 132: 140}
STEP_SOURCES = {14: 4, 15: 2, 17: 5, 132: 2}
METADATA_FIELDS = {
    14: {1, 3, 12, 20, 26, 35},
    15: {1, 3, 6, 7, 8, 9, 11, 12, 20, 26, 32, 35},
    17: {1, 3, 8, 12, 20, 26, 35},
    132: {1, 3, 4, 6, 7, 8, 11, 12, 20, 26, 32, 35, 38},
}
MCP_NAME = re.compile(rb'[A-Za-z0-9_-]{1,128}')


class EvidenceIssue(Exception):
    """A fixed diagnostic code, safe for the local operator."""


def require(condition, reason='native_format_unverified'):
    if not condition:
        raise EvidenceIssue(reason)


@dataclass(frozen=True)
class Assessment:
    state: str
    reason: str
    steps: int = 0
    executions: int = 0
    invocations: int = 0
    revision: str = ''


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        require(offset < len(data))
        part = data[offset]
        offset += 1
        require(shift != 63 or part <= 1)
        value |= (part & 127) << shift
        if part < 128:
            require(shift == 0 or part != 0)
            return value, offset
    raise EvidenceIssue('native_format_unverified')


class Fields:
    """Keep only requested protobuf fields. Never decode prompt or reasoning blobs."""

    def __init__(self, data, wanted, *, allowed=None):
        require(isinstance(data, (bytes, memoryview)))
        if len(data) > MAX_BLOB:
            raise AccessError('The native trajectory exceeds the field limit.', code='resource_exhausted')
        data = memoryview(data)
        self.selected = {}
        offset = 0
        count = 0
        while offset < len(data):
            count += 1
            require(count <= MAX_STEPS)
            key, offset = _varint(data, offset)
            number, wire = key >> 3, key & 7
            require(0 < number < 2**29)
            if allowed is not None:
                require(number in allowed, 'native_lineage_or_workspace_override')
            if wire == 0:
                value, offset = _varint(data, offset)
            else:
                require(wire in (1, 2, 5))
                if wire == 2:
                    length, offset = _varint(data, offset)
                else:
                    length = 8 if wire == 1 else 4
                end = offset + length
                require(end <= len(data))
                value = data[offset:end]
                offset = end
            if number in wanted:
                self.selected.setdefault(number, []).append((wire, value))

    def many(self, number, wire=2):
        items = self.selected.get(number, ())
        require(all(kind == wire for kind, _ in items))
        return tuple(value for _, value in items)

    def one(self, number, wire=2, default=None):
        items = self.many(number, wire)
        require(len(items) <= 1)
        return items[0] if items else default


def _uuid(raw):
    from .agent_history_antigravity import _native_id
    require(isinstance(raw, memoryview) and len(raw) == 36)
    value = bytes(raw).decode('ascii', errors='replace')
    require(_native_id(value))
    return value


def _path(raw):
    from .agent_history_antigravity import _local_workspace
    require(isinstance(raw, (str, memoryview)), 'native_workspace_invalid')
    if isinstance(raw, memoryview):
        require(len(raw) <= 4096, 'native_workspace_invalid')
        try:
            raw = bytes(raw).decode('utf-8')
        except UnicodeError:
            raise EvidenceIssue('native_workspace_invalid') from None
    path = _local_workspace(raw)
    require(path is not None, 'native_workspace_invalid')
    return path


def _digest(digest, *values):
    for value in values:
        digest.update(struct.pack('>Q', len(value)))
        digest.update(value)


def _database_stamps(root, relative):
    files = []
    for path in root._sqlite_files(relative):
        with root.open(path) as stream:
            files.append((path, _stamp(os.fstat(stream.fileno()))))
    return tuple(files)


def _schema(db, tables):
    values = db.execute('SELECT name, type FROM sqlite_schema WHERE name IN ('
                        + ','.join('?' for _ in tables) + ')', tuple(tables))
    require(dict(values) == dict.fromkeys(tables, 'table'))


def _index_claim(db, thread):
    from .agent_history_antigravity import INDEX_VERSION, MAX_INDEX_FIELD_CHARS, _timestamp
    require(db.execute('PRAGMA user_version').fetchone() == (INDEX_VERSION,))
    _schema(db, ('conversation_summaries', 'conversation_parents'))
    rows = db.execute('SELECT substr(workspace_uris,1,?), substr(project_id,1,37), '
                      'parent_conversation_id, nesting_depth, step_count, not_fully_idle, killed, status, '
                      'substr(title,1,500), substr(last_modified_time,1,65) '
                      'FROM conversation_summaries WHERE conversation_id=? LIMIT 2',
                      (MAX_INDEX_FIELD_CHARS + 1, thread.native_id)).fetchall()
    require(len(rows) == 1, 'native_index_mismatch')
    raw, project, parent, depth, count, busy, killed, status, title, updated = rows[0]
    require((title if isinstance(title, str) else '') == thread.title and _timestamp(updated) == thread.updated_at,
            'native_capture_changed')
    require(not parent and depth == 0 and not thread.ancestors and not db.execute(
        'SELECT 1 FROM conversation_parents WHERE conversation_id=? LIMIT 1', (thread.native_id,)).fetchone(),
        'native_parent_history_unverified')
    if type(count) is int and count > MAX_STEPS:
        raise AccessError('The native trajectory exceeds the step limit.', code='resource_exhausted')
    require(type(count) is int and 0 < count and busy == killed == 0
            and status == 'CASCADE_RUN_STATUS_IDLE', 'native_snapshot_not_committed')
    require(project == thread.native_project_id and isinstance(raw, str) and len(raw) <= MAX_INDEX_FIELD_CHARS,
            'native_index_mismatch')
    try:
        uris = json.loads(raw)
    except (ValueError, RecursionError):
        raise EvidenceIssue('native_workspace_invalid') from None
    require(isinstance(uris, list) and 0 < len(uris) <= 64, 'native_workspace_invalid')
    paths = tuple(_path(uri) for uri in uris)
    require(len(set(paths)) == len(paths) and set(paths) == set(thread.contexts), 'native_index_mismatch')
    return set(paths), count


def _trajectory(db, thread, workspaces, digest):
    require(db.execute('PRAGMA user_version').fetchone() == (1,))
    _schema(db, ('trajectory_meta', 'trajectory_metadata_blob', 'parent_references', 'battle_mode_infos',
                 'steps', 'executor_metadata', 'gen_metadata'))
    require(not db.execute('SELECT 1 FROM parent_references LIMIT 1').fetchone()
            and not db.execute('SELECT 1 FROM battle_mode_infos LIMIT 1').fetchone(),
            'native_parent_history_unverified')
    rows = db.execute('SELECT substr(trajectory_id,1,37),substr(cascade_id,1,37),trajectory_type,source '
                      'FROM trajectory_meta LIMIT 2').fetchall()
    from .agent_history_antigravity import _native_id
    require(len(rows) == 1 and _native_id(rows[0][0])
            and rows[0][1:] == (thread.native_id, 4, 1), 'native_source_identity_mismatch')
    trajectory = rows[0][0]
    rows = db.execute('SELECT id,substr(data,1,?) FROM trajectory_metadata_blob LIMIT 2', (MAX_BLOB + 1,)).fetchall()
    require(len(rows) == 1 and rows[0][0] == 'main')
    raw = rows[0][1]
    metadata = Fields(raw, {1, 2, 3, 6, 7, 18}, allowed={1, 2, 3, 6, 7, 15, 18})
    _uuid(metadata.one(3))  # Native initialization_state_id.
    birth = _epoch(metadata.one(2))
    require(_uuid(metadata.one(6)) == thread.native_id and _uuid(metadata.one(18)) == thread.native_project_id,
            'native_source_identity_mismatch')
    folders = []
    git_roots = set()
    entries = metadata.many(1)
    uris = metadata.many(7)
    require(0 < len(entries) <= 64 and len(entries) == len(uris), 'native_workspace_invalid')
    for entry in entries:
        workspace = Fields(entry, {1, 2}, allowed={1, 2, 3, 4})
        folders.append(_path(workspace.one(1)))
        git_root = workspace.one(2)
        if git_root is not None:
            git_roots.add(_path(git_root))
    require(len(workspaces) == len(entries) and workspaces == set(folders) == {_path(uri) for uri in uris},
            'native_workspace_conflict')
    _digest(digest, trajectory.encode(), thread.native_id.encode(), raw)
    return trajectory, tuple(sorted(workspaces | git_roots)), birth


def _epoch(raw):
    stamp = Fields(raw, {1, 2})
    seconds = stamp.one(1, 0)
    nanos = stamp.one(2, 0, 0)
    require(type(seconds) is int and 0 < seconds < 253402300800 and nanos < 10**9)
    return seconds, nanos


def _step_completion(meta, kind, status, created):
    """Use recorded execution and terminal times, including work after step creation."""
    phases = [created]
    for field in (6, 7, 8):
        value = meta.one(field)
        if value is not None:
            phases.append(_epoch(value))
    transitions = Fields(meta.one(26), {1}).many(1)
    expected = {14: (3,), 15: (8, 3), 17: (3,), 132: (1, 2, status)}[kind]
    require(len(transitions) == len(expected), 'native_step_time_mismatch')
    previous = created
    for raw, state in zip(transitions, expected):
        step = Fields(raw, {1, 2}, allowed={1, 2})
        observed = _epoch(step.one(2))
        require(step.one(1, 0) == state and observed >= previous, 'native_step_time_mismatch')
        previous = observed
    require(phases == sorted(phases) and previous >= phases[-1], 'native_step_time_mismatch')
    return previous


def _planner(raw):
    if raw is not None:
        # A planner customization may itself set workspace_paths. New native
        # workspace tools, function providers and discovery-root overrides
        # require independent validation before this profile can admit them.
        value = Fields(raw, {13, 41, 42, 46, 57}, allowed={
            1, 6, 7, 13, 21, 28, 30, 32, 33, 35, 37, 41, 42, 43, 46, 47, 51, 53, 57, 58, 59,
        })
        require(value.one(41) is None, 'native_prompt_override_unverified')
        require(value.one(42) is None, 'native_dynamic_workspace_history_unverified')
        if value.one(57) is not None:
            Fields(value.one(57), set(), allowed={1, 2, 12})
        if value.one(46) is not None:
            Fields(value.one(46), set(), allowed={2, 3, 4, 5, 6, 7, 8, 10, 11})
        if value.one(13) is not None:
            Fields(value.one(13), set(), allowed={2, 4, 5, 8, 10, 11, 13, 16, 19, 23, 25, 31, 32,
                                                  33, 36, 39, 41, 42, 43, 46, 48, 50, 54, 56, 57})


def _no_dynamic(config):
    if config is not None:
        value = Fields(config, {1, 12}, allowed={1, 2, 3, 4, 7, 9, 11, 12, 13, 15})
        require(not value.many(12), 'native_dynamic_workspace_history_unverified')
        _planner(value.one(1))


def _desktop_spec(raw):
    # CustomAgentSpec also supports explicit workspace_paths, active-workspace
    # selection and nested config/prompt overrides. Accept only the desktop
    # interactive default agent, positively identified on both sides of a run.
    only_builtin = Fields(raw, {3}, allowed={3})
    builtin = Fields(only_builtin.one(3), {1}, allowed={1})
    default = Fields(builtin.one(1), {1, 3, 5}, allowed={1, 3, 5})
    require(default.one(1, 0, 0) in (0, 1) and default.one(3, 0) == 1 and default.one(5, 0) == 3,
            'native_desktop_agent_unverified')
    return hashlib.sha256(raw).digest()


def _user_body(raw, text):
    user = Fields(raw, {2, 3, 12, 13, 18}, allowed={2, 3, 4, 12, 13, 18, 19})
    for number in (12, 13):
        _no_dynamic(user.one(number))
    body = user.one(2)
    require(body is not None and len(body) > 0, 'native_visible_message_mismatch')
    item = Fields(user.one(3), {1}, allowed={1})
    require(body == item.one(1), 'native_visible_message_mismatch')
    spec = _desktop_spec(user.one(18))
    try:
        public = bytes(body).decode('utf-8')
    except UnicodeError:
        raise EvidenceIssue('native_visible_message_mismatch') from None
    if body == text:
        return False, public, spec
    # The desktop transcript wraps user input with host metadata. Pair the
    # entire string to the typed user prompt at this step in the same trajectory.
    require(text.startswith(b'<USER_REQUEST>\n' + body.tobytes() + b'\n</USER_REQUEST>'),
            'native_visible_message_mismatch')
    return True, public, spec


def _tool(meta, raw):
    call = Fields(meta.one(4), {2, 9})
    name = call.one(2)
    require(name is not None and len(name) <= 255 and call.one(9, default=name) == name,
            'native_tool_lifecycle_unverified')
    source = meta.one(38, 0)
    if source == 1 and name in (b'read_file', b'run_command'):
        return None
    require(source == 3 and bytes(name).startswith(b'mcp_') and MCP_NAME.fullmatch(name),
            'native_tool_lifecycle_unverified')
    # An MCP result is opaque text/render data. Never follow full_output_uri.
    generic = Fields(raw, {2}, allowed={1, 2})
    Fields(generic.one(2), set(), allowed={1, 3, 7})
    return bytes(name)


def _steps(db, trajectory, native_id, manifest, messages, digest, birth):
    last_commit = birth
    last_created = birth
    require(0 < len(manifest) <= MAX_STEPS, 'native_transcript_incomplete')
    rows = db.execute('SELECT idx,step_type,status,has_subtrajectory,substr(metadata,1,?),'
                      'substr(step_payload,1,?),step_format FROM steps ORDER BY idx LIMIT ?',
                      (MAX_BLOB + 1, MAX_BLOB + 1, len(manifest) + 1))
    executions = []
    generated = {}
    wrapped = {}
    public = {}
    specs = {}
    tools = {}
    seen = 0
    for expected, (idx, kind, status, nested, raw_meta, raw_step, fmt) in enumerate(rows):
        require(type(idx) is int and idx == expected and idx < len(manifest), 'native_step_sequence_mismatch')
        log_idx, log_kind, log_source, log_status, log_time = manifest[idx]
        require(idx == log_idx and STEP_NAMES.get(kind) == log_kind
                and (status == 3 and log_status == 'DONE' or kind == 132 and status == 7 and log_status == 'ERROR')
                and nested == fmt == 0, 'native_step_shape_unverified')
        meta = Fields(raw_meta, {1, 3, 4, 6, 7, 8, 12, 20, 26, 38}, allowed=METADATA_FIELDS[kind])
        source = meta.one(3, 0)
        require(SOURCE_NAMES.get(source) == log_source and source == STEP_SOURCES[kind],
                'native_step_source_mismatch')
        seconds, nanos = _epoch(meta.one(1))
        require((seconds, nanos) >= last_created and log_time in {datetime.fromtimestamp(seconds, timezone.utc).isoformat(),
                             datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos // 1000).isoformat()},
                'native_step_time_mismatch')
        last_created = (seconds, nanos)
        last_commit = max(last_commit, _step_completion(meta, kind, status, last_created))
        origin = Fields(meta.one(20), {1, 2, 3, 4}, allowed={1, 2, 3, 4})
        require(_uuid(origin.one(1)) == trajectory and origin.one(2, 0, 0) == idx
                and _uuid(origin.one(4)) == native_id, 'native_step_origin_mismatch')
        execution = _uuid(meta.one(12))
        first_in_run = not executions or execution != executions[-1]
        require(first_in_run == (kind == 14), 'native_execution_mismatch')
        executions.append(execution)
        if source == 2:
            generated[idx] = origin.one(3, 0, 0)
        slot = STEP_SLOTS[kind]
        allowed = {1, 4, 5, slot}
        if status == 7:
            allowed.add(31)  # Native error details are never projected.
        payload = Fields(raw_step, allowed, allowed=allowed)
        require(payload.one(1, 0) == kind and payload.one(4, 0) == status and payload.one(5) == raw_meta,
                'native_step_origin_mismatch')
        require(payload.one(slot) is not None)
        message = messages.get('step:' + str(idx))
        text = message.text.encode('utf-8') if message else b''
        if kind == 14:
            require(message and message.role == 'user', 'native_visible_message_mismatch')
            paired_prompt, public[idx], specs[execution] = _user_body(payload.one(slot), text)
            if paired_prompt:
                wrapped[idx] = hashlib.sha256(text).digest()
        elif kind == 15:
            response = Fields(payload.one(20), {1, 8})
            final = response.one(8)
            if final is None:
                final = response.one(1, default=b'')
            require((message is None or message.role == 'assistant') and final == text,
                    'native_visible_message_mismatch')
        else:
            require(message is None, 'native_visible_message_mismatch')
            if kind == 132:
                name = _tool(meta, payload.one(slot))
                if name is not None:
                    tools.setdefault(execution, set()).add(name)
        _digest(digest, raw_meta, raw_step)
        seen += 1
    require(seen == len(manifest), 'native_step_sequence_mismatch')
    return executions, generated, wrapped, public, specs, tools, last_commit


def _registered_tools(raw, names):
    loaded = Fields(raw, {1}, allowed={1})
    servers = set()
    for item in loaded.many(1):
        customization = Fields(item, {1, 2, 5})
        if customization.one(1, 0) == 7 and customization.one(5, 0) == 1:
            server = customization.one(2)
            if server is not None and MCP_NAME.fullmatch(server):
                servers.add(b'mcp_' + bytes(server) + b'_')
    for name in names:
        require(sum(name.startswith(prefix) and len(name) > len(prefix) for prefix in servers) == 1,
                'native_tool_lifecycle_unverified')


def _executors(db, steps, specs, tools, digest):
    ends = {}
    for i, key in enumerate(steps):
        if not i or key != steps[i - 1]:
            require(key not in ends, 'native_execution_discontinuous')
        ends[key] = i
    invocations = {}
    rows = db.execute('SELECT idx,substr(data,1,?) FROM executor_metadata ORDER BY idx LIMIT ?',
                      (MAX_BLOB + 1, len(ends) + 1))
    for index, (idx, raw) in enumerate(rows):
        require(type(idx) is int and idx == index and index < len(ends), 'native_execution_mismatch')
        value = Fields(raw, {1, 2, 3, 9, 10, 16, 17, 18}, allowed={1, 2, 3, 9, 10, 11, 16, 17, 18})
        key = _uuid(value.one(9))
        count = value.one(2, 0, 0)
        require(key not in invocations and key in ends and value.one(3, 0, 0) == ends[key]
                and value.one(1, 0) == 4 and 0 < count <= len(steps), 'native_execution_mismatch')
        _no_dynamic(value.one(10))
        _no_dynamic(value.one(17))
        resolution = Fields(value.one(16), {1, 3}, allowed={1, 3})
        require(not resolution.one(3, default=b'') and _desktop_spec(resolution.one(1)) == specs[key],
                'native_desktop_agent_unverified')
        if key in tools:
            _registered_tools(value.one(18), tools[key])
        invocations[key] = count
        _digest(digest, raw)
    require(invocations.keys() == ends.keys(), 'native_execution_mismatch')
    return invocations


def _generations(db, steps, generated, wrapped, expected, tools, digest):
    counts = Counter()
    seen = set()
    total = sum(expected.values())
    require(0 < total <= len(steps), 'native_invocations_mismatch')
    rows = db.execute('SELECT idx,substr(data,1,?) FROM gen_metadata ORDER BY idx LIMIT ?', (MAX_BLOB + 1, total + 1))
    for index, (idx, raw) in enumerate(rows):
        require(type(idx) is int and idx == index and idx < total, 'native_invocations_mismatch')
        value = Fields(raw, {1, 2, 3, 4}, allowed={1, 2, 3, 4, 8})
        _planner(value.one(3))
        execution = _uuid(value.one(4))
        require(execution in expected, 'native_invocations_mismatch')
        counts[execution] += 1
        positions = value.one(2)
        require(positions is not None and len(positions) > 0, 'native_invocations_mismatch')
        offset = 0
        while offset < len(positions):
            i, offset = _varint(positions, offset)
            require(i not in seen and i < len(steps) and steps[i] == execution and generated.get(i) == idx,
                    'native_invocations_mismatch')
            seen.add(i)
        if wrapped or tools.get(execution):
            model = Fields(value.one(1, default=b''), {2, 8})
            for raw_tool in model.many(8) if tools.get(execution) else ():
                definition = Fields(raw_tool, {1})
                name = definition.one(1)
                if name is not None and len(name) <= 255:
                    tools[execution].discard(bytes(name))
            for raw_prompt in model.many(2):
                prompt = Fields(raw_prompt, {2, 3, 18})
                i = prompt.one(18, 0, 0)
                if i in wrapped and prompt.one(2, 0) == 1:
                    text = prompt.one(3)
                    if text is not None and hashlib.sha256(text).digest() == wrapped[i]:
                        del wrapped[i]
        _digest(digest, raw)
    require(counts == expected and seen == generated.keys(), 'native_invocations_mismatch')
    require(not wrapped, 'native_visible_message_mismatch')
    require(not any(tools.values()), 'native_tool_lifecycle_unverified')


def capture(adapter, thread):
    """Return a bound public projection for the positively identified desktop lifecycle."""
    from .agent_history_antigravity import INDEX, _native_id
    require(adapter.version == '2.33.0' and _native_id(thread.native_id), 'native_profile_unverified')
    native = f'conversations/{thread.native_id}.db'
    root = adapter.root
    index_identity = root.identity_for(INDEX)
    before = _database_stamps(root, native)
    manifest = []
    projection = adapter._snapshot(thread, manifest)
    require(not projection.warnings, 'native_transcript_incomplete')
    digest = hashlib.sha256()
    messages = {message.position: message for message in projection.messages}
    with root.sqlite(INDEX) as db:
        workspaces, count = _index_claim(db, thread)
    require(count == len(manifest), 'native_step_sequence_mismatch')
    with root.sqlite(native) as db:
        trajectory, contexts, birth = _trajectory(db, thread, workspaces, digest)
        steps, generated, wrapped, public, specs, tools, last = _steps(db, trajectory, thread.native_id, manifest,
                                                                      messages, digest, birth)
        executors = _executors(db, steps, specs, tools, digest)
        _generations(db, steps, generated, wrapped, executors, tools, digest)
    require(projection == adapter.snapshot(thread), 'native_capture_changed')
    # Concurrent saves in another project may advance the shared index WAL.
    # Recheck only this session's claims and parent link on a fresh snapshot.
    with root.sqlite(INDEX) as db:
        current_claim = _index_claim(db, thread)
    if (current_claim != (workspaces, count) or root.identity_for(INDEX) != index_identity
            or _database_stamps(root, native) != before):
        raise AccessError('The native history snapshot changed during capture.', code='waiting_source_stable')
    _digest(digest, projection.revision.encode('ascii'))
    # Bind physical store and transcript replacement independently of their bytes.
    identity = hashlib.sha256(repr((root.identity, index_identity, before[0][1][:3], projection.identity)).encode()).hexdigest()
    revision = digest.hexdigest()
    observation = Assessment('workspace_verified', 'desktop_default_agent_trajectory',
                             len(steps), len(executors), sum(executors.values()), revision)
    safe_messages = tuple(replace(item, text=public[int(item.position.removeprefix('step:'))]) if item.role == 'user'
                          else item for item in projection.messages)
    return observation, replace(projection, messages=safe_messages, contexts=contexts, context_complete=True,
                                identity=identity, revision=revision, prefix=None,
                                origin_ns=birth[0] * 1_000_000_000 + birth[1], last_ns=last[0] * 1_000_000_000 + last[1])
