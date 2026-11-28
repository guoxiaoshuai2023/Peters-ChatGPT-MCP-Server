"""Invariant-driven verifier for Antigravity Desktop native SQLite-v1 trajectories.

Security boundary enforced (fail-closed):
1. Three-way identity & workspace agreement: conversation_summaries.db ==
   trajectory_meta == trajectory_metadata_blob (cascade_id, project_id, all
   workspace URIs + git roots; zero parent_references, zero battle_mode_infos,
   top-level nesting_depth == 0, killed == 0, local desktop source == 1).
2. Zero dynamic workspace overrides, prompt overrides, or non-desktop agent
   specs across USER_INPUT.{12,13,18}, executor_metadata.{10,16,17}, and
   gen_metadata.3 (planner).
3. Dual-track visible message integrity: every public message (USER_INPUT /
   PLANNER_RESPONSE) matches 1-to-1 between native SQLite steps and the paired
   transcript(s), including Checkpoint-cleared (status=5) steps via USER_INPUT.3
   items and PLANNER_RESPONSE text; non-public steps never emit visible text.
4. Full child-subagent containment: every referenced or linked child subagent
   must belong to the same parent, project and workspaces, must not be denied,
   must accept no external USER_INPUT, and must carry no workspace overrides.
5. TOCTOU stability: index, trajectory DB stamps, and transcripts are rechecked
   before binding the final projection.
"""

from collections import Counter, OrderedDict
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
MAX_GEN_BLOB = 32 * 1024 * 1024
_MAX_CAPTURE_CACHE = 32
_MAX_CAPTURE_CACHE_BYTES = 16 * 1024 * 1024
_CAPTURE_CACHE = OrderedDict()
_CAPTURE_CACHE_BYTES = 0
SOURCE_NAMES = {2: 'MODEL', 4: 'USER_EXPLICIT', 5: 'SYSTEM'}
STEP_NAMES = {14: 'USER_INPUT', 15: 'PLANNER_RESPONSE', 17: 'ERROR_MESSAGE',
              23: 'CHECKPOINT', 101: 'SYSTEM_MESSAGE', 132: 'GENERIC'}
STEP_SLOTS = {14: 19, 15: 20, 17: 24, 101: 114, 132: 140}
STEP_SOURCES = {14: 4, 15: 2, 17: 5, 101: 5, 132: 2}
MCP_NAME = re.compile(rb'[A-Za-z0-9_-]{1,128}')
_USER_REQUEST_WRAP = re.compile(rb'\A<USER_REQUEST>\n(.*?)\n</USER_REQUEST>', re.DOTALL)
_RESPONSE_LANG_FORBIDDEN = frozenset('/\\:<>\x00')
NORMAL_TERMINATION_REASON = 4
# Legitimate Antigravity 2.33-2.36 non-normal ExecutorTerminationReason values:
# 1=ERROR, 2=USER_CANCELED, 3=MAX_INVOCATIONS, 6=MAX_FORCED_INVOCATIONS,
# 7=EARLY_CONTINUE, 8=TERMINAL_STEP_TYPE, 11=MAX_TOKEN_BUDGET_EXCEEDED.
# 0=UNSPECIFIED, 9=TERMINAL_CUSTOM_HOOK, 10=INJECTED_RESPONSE, 12=CHAINED
# and any unknown enum value remain strictly fail-closed.
NON_NORMAL_TERMINATION_REASONS = frozenset({1, 2, 3, 6, 7, 8, 11})
RESOLUTION_POLICY_VALUES = frozenset({0, 1, 2})
CUSTOMIZATION_INHERITANCE_MODES = frozenset({0, 1, 2, 3})
SENSITIVITY_LEVELS = frozenset({0, 100, 200, 300, 400, 500, 600, 700})


def _gen_blob_limit():
    return max(MAX_BLOB, MAX_GEN_BLOB) if MAX_BLOB >= 8 * 1024 * 1024 else MAX_BLOB


class EvidenceIssue(Exception):
    """A fixed diagnostic code, safe for the local operator."""

    def __init__(self, reason='native_format_unverified', detail=''):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def require(condition, reason='native_format_unverified', detail=''):
    if not condition:
        raise EvidenceIssue(reason, detail)


@dataclass(frozen=True)
class Assessment:
    state: str
    reason: str
    steps: int = 0
    executions: int = 0
    invocations: int = 0
    revision: str = ''
    detail: str = ''


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

    def __init__(self, data, wanted, *, allowed=None, max_bytes=None, path=''):
        require(isinstance(data, (bytes, memoryview)))
        limit = MAX_BLOB if max_bytes is None else max_bytes
        if len(data) > limit:
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
                require(
                    number in allowed,
                    'native_lineage_or_workspace_override',
                    f'{path}.{number}' if path else f'field.{number}',
                )
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

    def many(self, number, wire=2, *, reason='native_format_unverified', detail=''):
        items = self.selected.get(number, ())
        require(all(kind == wire for kind, _ in items), reason, detail)
        return tuple(value for _, value in items)

    def one(self, number, wire=2, default=None, *, reason='native_format_unverified', detail=''):
        items = self.many(number, wire, reason=reason, detail=detail)
        require(len(items) <= 1, reason, detail)
        return items[0] if items else default


def _uuid(raw):
    from .agent_history_antigravity import _native_id
    require(isinstance(raw, memoryview) and len(raw) == 36)
    value = bytes(raw).decode('ascii', errors='replace')
    require(_native_id(value))
    return value


def _try_uuid(raw):
    from .agent_history_antigravity import _native_id
    if not isinstance(raw, (bytes, memoryview)) or len(raw) != 36:
        return None
    try:
        value = bytes(raw).decode('ascii')
    except UnicodeError:
        return None
    return value if _native_id(value) else None


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
    require(type(count) is int and 0 < count and type(busy) is int and busy in (0, 1) and killed == 0
            and status in ('CASCADE_RUN_STATUS_IDLE', 'CASCADE_RUN_STATUS_RUNNING'),
            'native_snapshot_not_committed')
    require(project == thread.native_project_id and isinstance(raw, str) and len(raw) <= MAX_INDEX_FIELD_CHARS,
            'native_index_mismatch')
    try:
        uris = json.loads(raw)
    except (ValueError, RecursionError):
        raise EvidenceIssue('native_workspace_invalid') from None
    require(isinstance(uris, list) and 0 < len(uris) <= 64, 'native_workspace_invalid')
    paths = tuple(_path(uri) for uri in uris)
    require(len(set(paths)) == len(paths) and set(paths) == set(thread.contexts), 'native_index_mismatch')
    return set(paths), count, busy, status == 'CASCADE_RUN_STATUS_RUNNING'


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
    metadata = Fields(raw, {1, 2, 3, 6, 7, 18})
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
        workspace = Fields(entry, {1, 2})
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
    require(phases == sorted(phases), 'native_step_time_mismatch')
    raw_transitions = meta.one(26)
    transitions = Fields(raw_transitions, {1}).many(1) if raw_transitions is not None else ()
    if status == 3 and kind in STEP_SLOTS:
        require(len(transitions) >= 1, 'native_step_time_mismatch')
        previous = created
        last_state = None
        for raw in transitions:
            step = Fields(raw, {1, 2})
            observed = _epoch(step.one(2))
            require(observed >= previous, 'native_step_time_mismatch')
            previous = observed
            last_state = step.one(1, 0)
        require(last_state == 3 and previous >= phases[-1], 'native_step_time_mismatch')
        return previous
    latest = phases[-1]
    for raw in transitions:
        step = Fields(raw, {1, 2})
        ts_raw = step.one(2)
        if ts_raw is not None:
            ts = _epoch(ts_raw)
            if ts > latest:
                latest = ts
    return latest


def _check_bool_field(fields, number, path):
    value = fields.one(number, 0, reason='native_lineage_or_workspace_override', detail=f'{path}.{number}')
    if value is not None:
        require(value in (0, 1), 'native_lineage_or_workspace_override', f'{path}.{number}={value}')


def _check_int32_field(fields, number, path, *, maximum=2**31 - 1):
    value = fields.one(number, 0, reason='native_lineage_or_workspace_override', detail=f'{path}.{number}')
    if value is not None:
        require(0 <= value <= maximum, 'native_lineage_or_workspace_override', f'{path}.{number}={value}')


def _check_enum_field(fields, number, valid_values, path):
    value = fields.one(number, 0, reason='native_lineage_or_workspace_override', detail=f'{path}.{number}')
    if value is not None:
        require(value in valid_values, 'native_lineage_or_workspace_override', f'{path}.{number}={value}')


def _check_response_language(raw, path):
    if raw is None:
        return
    require(isinstance(raw, memoryview) and len(raw) <= 64,
            'native_lineage_or_workspace_override', path)
    try:
        text = bytes(raw).decode('utf-8')
    except UnicodeError:
        raise EvidenceIssue('native_lineage_or_workspace_override', path) from None
    require(
        all(ord(ch) >= 0x20 and ord(ch) != 0x7f and ch not in _RESPONSE_LANG_FORBIDDEN for ch in text),
        'native_lineage_or_workspace_override',
        path,
    )


def _check_media_compression(raw, path):
    if raw is None:
        return
    cfg = Fields(raw, {1, 2, 3, 4}, allowed={1, 2, 3, 4}, path=path)
    for number in (1, 2, 3, 4):
        _check_int32_field(cfg, number, path)


def _check_model_or_alias(raw, path):
    if raw is None:
        return
    cfg = Fields(raw, {1, 2}, allowed={1, 2}, path=path)
    for number in (1, 2):
        _check_int32_field(cfg, number, path)


def _check_plan_execute(raw, path):
    if raw is None:
        return
    cfg = Fields(raw, {1}, allowed={1}, path=path)
    _check_int32_field(cfg, 1, path)


def _check_component_resolution_policy(raw, path):
    if raw is None:
        return
    # Closed ComponentResolutionPolicy: {1: unknown_component_policy, 2: empty_component_policy}
    # each strictly in ResolutionPolicy {0: UNSPECIFIED, 1: IGNORE, 2: ERROR}.
    policy = Fields(raw, {1, 2}, allowed={1, 2}, path=path)
    _check_enum_field(policy, 1, RESOLUTION_POLICY_VALUES, path)
    _check_enum_field(policy, 2, RESOLUTION_POLICY_VALUES, path)


def _check_declarative_mixin(raw, path):
    if raw is None:
        return
    # Redline fields 1 (providers) and 12 (resolved_customizations) remain strictly fail-closed.
    mixin = Fields(raw, {9, 10}, allowed={2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, path=path)
    _check_component_resolution_policy(
        mixin.one(9, reason='native_lineage_or_workspace_override', detail=f'{path}.9'),
        f'{path}.9',
    )
    _check_bool_field(mixin, 10, path)


def _check_customization_discovery(raw, path):
    if raw is None:
        return
    # Redline fields 3..11 (mcp, plugins, profiles, override_workspace_path, rules,
    # agent_path, hooks, plugin_name, workflows) remain strictly fail-closed.
    disc = Fields(raw, {14}, allowed={1, 2, 12, 14}, path=path)
    _check_enum_field(disc, 14, CUSTOMIZATION_INHERITANCE_MODES, path)


def _check_tool_config(raw, path):
    if raw is None:
        return
    # Redline fields such as 22 (description_override_map), 37 (workspace_api),
    # and 47 (skill_search) remain strictly fail-closed.
    tool = Fields(
        raw,
        {29, 43, 46, 49, 50, 51},
        allowed={2, 4, 5, 8, 10, 11, 13, 16, 19, 23, 25, 29, 31, 32,
                 33, 36, 39, 41, 42, 43, 46, 48, 49, 50, 51, 54, 56, 57},
        path=path,
    )
    for number in (29, 46, 49, 50, 51):
        _check_bool_field(tool, number, path)
    _check_int32_field(tool, 43, path)


def _planner(raw, *, child=False, path='planner'):
    if raw is None:
        return
    if child:
        # Built-in subagents (browser, research, self) have distinct non-security
        # tool/model configs. Strictly forbid prompt overrides, workspace path
        # overrides (42.11), and discovery root overrides (57.6).
        value = Fields(raw, {41, 42, 57})
        require(value.one(41) is None, 'native_prompt_override_unverified', f'{path}.41')
        override = value.one(42)
        if override is not None:
            override_fields = Fields(override, {11})
            require(not override_fields.many(11), 'native_dynamic_workspace_history_unverified', f'{path}.42.11')
        discovery = value.one(57)
        if discovery is not None:
            disc_fields = Fields(discovery, {6})
            require(not disc_fields.many(6), 'native_dynamic_workspace_history_unverified', f'{path}.57.6')
        return
    # Parent desktop trajectories preserve strict fail-closed checks on every redline
    # field (2/26/36/44 alternate planners, 27 custom_model_info_override, 39/40 custom_agent,
    # 41 prompt overrides, 42 customization_config, 54 loop_error_model_message,
    # 56 completion_config_override) while validating audited harmless 2.33-2.36 fields.
    value = Fields(
        raw,
        {13, 14, 15, 25, 41, 42, 46, 48, 55, 57, 60, 61},
        allowed={
            1, 6, 7, 13, 14, 15, 21, 25, 28, 30, 32, 33, 35, 37,
            41, 42, 43, 46, 47, 48, 51, 53, 55, 57, 58, 59, 60, 61,
        },
        path=path,
    )
    require(value.one(41) is None, 'native_prompt_override_unverified', f'{path}.41')
    require(value.one(42) is None, 'native_dynamic_workspace_history_unverified', f'{path}.42')
    _check_int32_field(value, 14, path)
    _check_model_or_alias(
        value.one(15, reason='native_lineage_or_workspace_override', detail=f'{path}.15'),
        f'{path}.15',
    )
    for number in (25, 48, 55):
        _check_bool_field(value, number, path)
    _check_plan_execute(
        value.one(60, reason='native_lineage_or_workspace_override', detail=f'{path}.60'),
        f'{path}.60',
    )
    _check_response_language(
        value.one(61, reason='native_lineage_or_workspace_override', detail=f'{path}.61'),
        f'{path}.61',
    )
    _check_customization_discovery(
        value.one(57, reason='native_lineage_or_workspace_override', detail=f'{path}.57'),
        f'{path}.57',
    )
    _check_declarative_mixin(
        value.one(46, reason='native_lineage_or_workspace_override', detail=f'{path}.46'),
        f'{path}.46',
    )
    _check_tool_config(
        value.one(13, reason='native_lineage_or_workspace_override', detail=f'{path}.13'),
        f'{path}.13',
    )


def _no_dynamic(config, *, child=False, path='cascade_config'):
    if config is not None:
        if child:
            value = Fields(config, {1, 12})
        else:
            value = Fields(
                config,
                {1, 6, 8, 10, 12, 14},
                allowed={1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                path=path,
            )
            for number in (6, 8, 10):
                _check_bool_field(value, number, path)
            _check_media_compression(
                value.one(14, reason='native_lineage_or_workspace_override', detail=f'{path}.14'),
                f'{path}.14',
            )
        require(not value.many(12), 'native_dynamic_workspace_history_unverified', f'{path}.12')
        _planner(value.one(1), child=child, path=f'{path}.1')


def _desktop_spec(raw):
    # CustomAgentSpec supports explicit workspace_paths, active-workspace
    # selection and nested config/prompt overrides. Accept only the desktop
    # interactive default agent, positively identified on both sides of a run.
    only_builtin = Fields(raw, {3}, allowed={3})
    builtin = Fields(only_builtin.one(3), {1}, allowed={1})
    default = Fields(builtin.one(1), {1, 3, 5}, allowed={1, 3, 5})
    require(default.one(1, 0, 0) in (0, 1) and default.one(3, 0) == 1 and default.one(5, 0) == 3,
            'native_desktop_agent_unverified')
    return hashlib.sha256(raw).digest()


def _user_body(raw, text, *, status=3):
    # Tolerate benign attachment metadata (field 9) and standard UI fields while
    # enforcing all workspace-override (12, 13) and desktop-spec (18) invariants.
    user = Fields(raw, {2, 3, 9, 12, 13, 18})
    for number in (12, 13):
        _no_dynamic(user.one(number), path=f'user_input.{number}')
    # Validate wire integrity of attachment entries without opening local paths.
    for attachment in user.many(9):
        Fields(attachment, set())
    items = user.many(3)
    item_texts = []
    for item_raw in items:
        item_f = Fields(item_raw, {1})
        piece = item_f.one(1)
        if piece is not None:
            item_texts.append(bytes(piece))
    body_mv = user.one(2)
    spec_raw = user.one(18)

    if status == 5:
        # Checkpoint-compacted USER_INPUT: Antigravity clears field 2/12/13/18
        # while retaining field 3 items. Cross-check against transcript_full.
        spec = _desktop_spec(spec_raw) if spec_raw is not None else None
        body = bytes(body_mv) if body_mv is not None else b''.join(item_texts)
        if body:
            if body == text:
                try:
                    return False, body.decode('utf-8'), spec, True
                except UnicodeError:
                    raise EvidenceIssue('native_visible_message_mismatch') from None
            wrapped_match = _USER_REQUEST_WRAP.match(text)
            if wrapped_match:
                inner = wrapped_match.group(1)
                # Accept exact match or slash-command chip prefix (e.g. "/cmd \n<body>") strictly inside <USER_REQUEST>.
                if inner == body or (inner.startswith(b'/') and inner.endswith(body)):
                    try:
                        return True, inner.decode('utf-8'), spec, True
                    except UnicodeError:
                        raise EvidenceIssue('native_visible_message_mismatch') from None
            raise EvidenceIssue('native_visible_message_mismatch')
        # Hypothetical full-prune fallback: only accept cleanly extracted user text.
        require(bool(text), 'native_visible_message_mismatch')
        wrapped_match = _USER_REQUEST_WRAP.match(text)
        extracted = wrapped_match.group(1) if wrapped_match else text
        require(bool(extracted), 'native_visible_message_mismatch')
        try:
            public = extracted.decode('utf-8')
        except UnicodeError:
            raise EvidenceIssue('native_visible_message_mismatch') from None
        return bool(wrapped_match), public, spec, True

    # Normal committed USER_INPUT (status == 3)
    require(body_mv is not None and len(body_mv) > 0, 'native_visible_message_mismatch')
    body = bytes(body_mv)
    if len(items) == 1:
        require(len(item_texts) == 1 and body == item_texts[0], 'native_visible_message_mismatch')
    elif items:
        require(body in item_texts or body == b''.join(item_texts), 'native_visible_message_mismatch')
    spec = _desktop_spec(spec_raw)
    try:
        public = body.decode('utf-8')
    except UnicodeError:
        raise EvidenceIssue('native_visible_message_mismatch') from None
    if body == text:
        return False, public, spec, False
    require(text.startswith(b'<USER_REQUEST>\n' + body + b'\n</USER_REQUEST>'),
            'native_visible_message_mismatch')
    return True, public, spec, False


def _extract_invoke_child(raw):
    """Extract spawned child conversation UUID from an invoke_subagent step payload."""
    try:
        generic = Fields(raw, {2})
        result_raw = generic.one(2)
        if result_raw is None:
            return None
        result = Fields(result_raw, {6})
        any_raw = result.one(6)
        if any_raw is None:
            return None
        any_f = Fields(any_raw, {2})
        payload = any_f.one(2)
        if payload is None:
            return None
        invoke = Fields(payload, {2})
        resp = invoke.one(2)
        if resp is None:
            return None
        return _try_uuid(Fields(resp, {1}).one(1))
    except (EvidenceIssue, AccessError):
        return None


def _extract_system_child(raw, native_id):
    """Extract referenced child/sender conversation UUID from a SYSTEM_MESSAGE payload."""
    try:
        item = Fields(raw, {3, 4})
        agent_raw = item.one(4)
        if agent_raw is None:
            return None
        agent = Fields(agent_raw, {3, 12})
        sender_uuid = _try_uuid(agent.one(3))
        if sender_uuid and sender_uuid != native_id:
            return sender_uuid
        meta_raw = agent.one(12)
        if meta_raw is not None:
            src_raw = Fields(meta_raw, {1}).one(1)
            if src_raw is not None:
                orig_uuid = _try_uuid(Fields(src_raw, {1}).one(1))
                if orig_uuid and orig_uuid != native_id:
                    return orig_uuid
    except (EvidenceIssue, AccessError):
        return None
    return None


def _tool(meta, raw, *, status=3, events=None, index=None, artifact_roots=()):
    """Strict built-in descriptor helper retained for unit-level event verification."""
    from .agent_history_antigravity_events import BUILTINS, builtin
    call = Fields(meta.one(4), {2, 9})
    name = call.one(2)
    require(name is not None and len(name) <= 255 and call.one(9, default=name) == name,
            'native_tool_lifecycle_unverified')
    source = meta.one(38, 0)
    if source == 1 and name in (b'read_file', b'run_command'):
        return None
    if source == 1 and bytes(name) in BUILTINS:
        builtin(bytes(name), meta.one(4), raw, status, events, index, artifact_roots=artifact_roots)
        return None
    require(source == 3 and bytes(name).startswith(b'mcp_') and MCP_NAME.fullmatch(name),
            'native_tool_lifecycle_unverified')
    generic = Fields(raw, {2}, allowed={1, 2})
    Fields(generic.one(2), set(), allowed={1, 3, 7})
    return bytes(name)


def _tool_check(meta, raw, *, status=3, related_children=None):
    """Validate tool-call security boundaries without brittle built-in whitelisting."""
    call_raw = meta.one(4)
    if call_raw is None:
        return None
    call = Fields(call_raw, {2, 9})
    name = call.one(2)
    require(name is not None and len(name) <= 255 and call.one(9, default=name) == name,
            'native_tool_lifecycle_unverified')
    source = meta.one(38, 0)
    if source == 1:
        # Built-in Antigravity IDE tool: never allow spoofing an mcp_* tool as built-in.
        require(not bytes(name).startswith(b'mcp_'), 'native_tool_lifecycle_unverified')
        if name == b'invoke_subagent' and status == 3 and raw is not None:
            child = _extract_invoke_child(raw)
            if child and related_children is not None:
                related_children.add(child)
        return None
    if source == 3:
        require(bytes(name).startswith(b'mcp_') and MCP_NAME.fullmatch(name),
                'native_tool_lifecycle_unverified')
        # Keep strict MCP opaque-result validation (never follow full_output_uri).
        if raw is not None and status == 3:
            generic = Fields(raw, {2}, allowed={1, 2})
            if generic.one(2) is not None:
                Fields(generic.one(2), set(), allowed={1, 3, 7})
        return bytes(name)
    # In compacted status=5 steps tool metadata may be cleared (source == 0)
    if status == 5 and source in (0, None):
        return None
    raise EvidenceIssue('native_tool_lifecycle_unverified')


def _drain(gen):
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def _steps_iter(db, trajectory, native_id, count, messages, digest, birth, *, is_running=False, manifest_indices=None):
    last_commit = birth
    last_created = birth
    require(0 < count <= MAX_STEPS, 'native_transcript_incomplete')
    rows = db.execute('SELECT idx,step_type,status,has_subtrajectory,substr(metadata,1,?),'
                      'substr(step_payload,1,?),step_format FROM steps ORDER BY idx LIMIT ?',
                      (MAX_BLOB + 1, MAX_BLOB + 1, count + 1))
    executions = []
    generated = {}
    wrapped = {}
    public = {}
    specs = {}
    tools = {}
    errors = {}
    error_steps_by_exec = {}
    step_completions = {}
    pending_tools = []
    call_records = []
    related_children = set()
    verified_message_positions = set()
    compacted_public = False
    active_tail = False
    last_checkpoint = -1
    seen = 0

    for expected, (idx, kind, status, nested, raw_meta, raw_step, fmt) in enumerate(rows):
        if seen and seen % 256 == 0:
            yield {'phase': 'scanning'}
        if expected == count:
            # Trajectory DB already has rows beyond conversation_summaries.step_count
            # (active-write index flush lag): fail closed as retryable waiting_source_stable.
            raise EvidenceIssue('native_index_lagging', f'steps.count>index.step_count(index={count})')
        require(type(idx) is int and idx == expected and idx < count,
                'native_step_sequence_mismatch', f'steps[{expected}].idx={idx}')
        require(nested == 0 and fmt == 0, 'native_step_shape_unverified')
        meta = Fields(raw_meta, {1, 3, 4, 6, 7, 8, 12, 20, 26, 32, 33, 38})
        source = meta.one(3, 0)
        if kind in STEP_SOURCES:
            require(source == STEP_SOURCES[kind], 'native_step_source_mismatch')
        else:
            # Unknown future non-public step types may never claim USER_EXPLICIT provenance.
            require(source != 4, 'native_step_source_mismatch')
        created_at = _epoch(meta.one(1))
        origin = Fields(meta.one(20), {1, 2, 3, 4})
        require(_uuid(origin.one(1)) == trajectory and origin.one(2, 0, 0) == idx
                and _uuid(origin.one(4)) == native_id, 'native_step_origin_mismatch')
        raw_exec = meta.one(12)
        if raw_exec is None and kind in (17, 23):
            execution = None
        else:
            execution = _uuid(raw_exec)
        prev_exec = next((e for e in reversed(executions) if e is not None), None)
        first_in_run = execution is not None and execution != prev_exec
        started_raw = meta.one(32)
        completed_raw = meta.one(8)
        # Mid-execution interrupting/queued USER_INPUT: Antigravity records the original
        # submit time in created_at (1) alongside explicit dequeue/commit times in
        # started_at (32) and completed_at (8) within the active execution.
        is_mid_run_user = (
            kind == 14
            and execution is not None
            and not first_in_run
            and execution == prev_exec
            and started_raw is not None
            and completed_raw is not None
        )
        if is_mid_run_user:
            started_at = _epoch(started_raw)
            completed_at = _epoch(completed_raw)
            require(
                birth <= created_at <= started_at <= completed_at,
                'native_step_time_mismatch',
                f'steps[{idx}].mid_run_user_time',
            )
            step_completed = _step_completion(meta, kind, status, created_at)
            require(
                step_completed >= last_created,
                'native_step_time_mismatch',
                f'steps[{idx}].mid_run_user_commit<last_created',
            )
            last_created = max(last_created, created_at)
        else:
            require(
                created_at >= last_created,
                'native_step_time_mismatch',
                f'steps[{idx}].created<last_created',
            )
            last_created = created_at
            step_completed = _step_completion(meta, kind, status, last_created)
        step_completions[idx] = step_completed
        last_commit = max(last_commit, step_completed)

        if kind == 14:
            require(
                execution is not None and (first_in_run or is_mid_run_user),
                'native_execution_mismatch',
                f'steps[{idx}].user_input_exec',
            )
        elif first_in_run and prev_exec is not None:
            if execution not in specs and prev_exec in specs:
                specs[execution] = specs[prev_exec]
        executions.append(execution)
        if source == 2:
            generated[idx] = origin.one(3, 0, 0)
        if kind == 23:
            last_checkpoint = idx

        payload_wanted = {1, 4, 5}
        slot = STEP_SLOTS.get(kind)
        if slot is not None:
            payload_wanted.add(slot)
        payload = Fields(raw_step, payload_wanted)
        require(payload.one(1, 0) == kind and payload.one(4, 0) == status and payload.one(5) == raw_meta,
                'native_step_origin_mismatch')

        pos = 'step:' + str(idx)
        message = messages.get(pos)
        text = message.text.encode('utf-8') if message else b''

        if kind == 14:
            if status in (3, 5):
                require(manifest_indices is None or idx in manifest_indices, 'native_transcript_incomplete')
                require(message is not None, 'native_transcript_incomplete')
                require(message.role == 'user', 'native_visible_message_mismatch')
                slot_raw = payload.one(19)
                require(slot_raw is not None, 'native_visible_message_mismatch')
                paired_prompt, pub_text, spec, was_compacted = _user_body(slot_raw, text, status=status)
                public[idx] = pub_text
                if spec is not None:
                    if is_mid_run_user and execution in specs:
                        require(spec == specs[execution], 'native_desktop_agent_unverified', f'steps[{idx}].mid_run_spec_mismatch')
                    specs[execution] = spec
                if paired_prompt and not was_compacted:
                    wrapped[idx] = hashlib.sha256(text).digest()
                if was_compacted:
                    compacted_public = True
                verified_message_positions.add(pos)
            else:
                require(message is None, 'native_visible_message_mismatch')
                active_tail = True
        elif kind == 15:
            call_records.append((idx, kind, meta, payload))
            if status in (3, 5):
                require(manifest_indices is None or idx in manifest_indices, 'native_transcript_incomplete')
                slot_raw = payload.one(20)
                require(slot_raw is not None, 'native_step_shape_unverified')
                response = Fields(slot_raw, {1, 8})
                final = response.one(8)
                if final is None:
                    final = response.one(1, default=b'')
                final_bytes = bytes(final)
                if final_bytes and message is None:
                    raise EvidenceIssue('native_transcript_incomplete')
                require((message is None or message.role == 'assistant') and final_bytes == text,
                        'native_visible_message_mismatch')
                if message is not None:
                    verified_message_positions.add(pos)
                    if status == 5:
                        compacted_public = True
            else:
                require(message is None, 'native_visible_message_mismatch')
                active_tail = True
        else:
            # Non-public steps MUST NEVER emit visible messages.
            require(message is None, 'native_visible_message_mismatch')
            if kind == 132:
                call_records.append((idx, kind, meta, payload))
                name = _tool_check(meta, payload.one(140), status=status, related_children=related_children)
                if name is not None:
                    tools.setdefault(execution, set()).add(name)
                if status == 1:
                    if is_running and idx == count - 1:
                        active_tail = True
                    else:
                        pending_tools.append(idx)
                elif status in (2, 6) and idx == count - 1:
                    active_tail = True
            elif kind == 101:
                child = _extract_system_child(payload.one(114), native_id)
                if child:
                    related_children.add(child)
            elif kind == 17:
                errors[idx] = origin.one(3, 0, 0)
                if execution is not None:
                    error_steps_by_exec.setdefault(execution, []).append(idx)
        _digest(digest, raw_meta, raw_step)
        seen += 1

    require(seen == count, 'native_step_sequence_mismatch')
    # Every visible message from the transcript must be backed by a verified DB public step.
    require(verified_message_positions == set(messages.keys()), 'native_visible_message_mismatch')
    return (executions, generated, wrapped, public, specs, tools, last_commit,
            related_children, compacted_public, active_tail, errors, last_checkpoint,
            pending_tools, step_completions, error_steps_by_exec, call_records)


def _steps(db, trajectory, native_id, count, messages, digest, birth, *, is_running=False, manifest_indices=None):
    return _drain(_steps_iter(
        db, trajectory, native_id, count, messages, digest, birth,
        is_running=is_running, manifest_indices=manifest_indices,
    ))


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


def _executors(db, steps, specs, tools, digest, *, is_running=False):
    ends = {}
    order = []
    for i, key in enumerate(steps):
        if key is None:
            continue
        if not order or key != order[-1]:
            require(key not in ends, 'native_execution_discontinuous')
            order.append(key)
        ends[key] = i
    invocations = {}
    exec_statuses = {}
    rows = db.execute('SELECT idx,substr(data,1,?) FROM executor_metadata ORDER BY idx LIMIT ?',
                      (MAX_BLOB + 1, len(ends) + 1))
    for index, (idx, raw) in enumerate(rows):
        require(type(idx) is int and idx == index and index < len(ends),
                'native_execution_mismatch', f'executor[{index}].idx={idx}')
        # Allow audited scalar/enum telemetry fields (4, 5, 13, 19) and execution_error (12)
        # while strictly forbidding redline fields (8 gen_svc_request, 14/15 snapshots) and
        # enforcing workspace overrides (10, 17), desktop agent spec (16), and MCP tools (18).
        exec_path = f'executor[{idx}]'
        value = Fields(
            raw,
            {1, 2, 3, 4, 5, 9, 10, 12, 13, 16, 17, 18, 19},
            allowed={1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 16, 17, 18, 19},
            path=exec_path,
        )
        for number in (4, 13):
            _check_bool_field(value, number, exec_path)
        _check_int32_field(value, 5, exec_path, maximum=len(steps))
        _check_enum_field(value, 19, SENSITIVITY_LEVELS, exec_path)
        key = _uuid(value.one(9))
        count = value.one(2, 0, 0)
        end_pos = value.one(3, 0, 0)
        exec_status = value.one(1, 0)
        has_error_msg = value.one(12) is not None
        valid_status = (
            exec_status == NORMAL_TERMINATION_REASON
            or exec_status in NON_NORMAL_TERMINATION_REASONS
        )
        require(
            key not in invocations and key in ends and end_pos == ends[key]
            and valid_status and 0 <= count <= len(steps),
            'native_execution_mismatch',
            f'{exec_path}.termination_reason={exec_status},end={end_pos},count={count}',
        )
        _no_dynamic(value.one(10), path=f'{exec_path}.10')
        _no_dynamic(value.one(17), path=f'{exec_path}.17')
        resolution = Fields(value.one(16), {1, 3}, allowed={1, 3}, path=f'{exec_path}.16')
        resolved_spec = _desktop_spec(resolution.one(1))
        require(not resolution.one(3, default=b''), 'native_desktop_agent_unverified', f'{exec_path}.16.3')
        if key in specs:
            require(resolved_spec == specs[key], 'native_desktop_agent_unverified', f'{exec_path}.16.spec_mismatch')
        if key in tools:
            _registered_tools(value.one(18), tools[key])
        invocations[key] = (count, has_error_msg, exec_status)
        exec_statuses[key] = exec_status
        _digest(digest, raw)
    if is_running:
        # An in-flight final execution may not have written its terminal executor_metadata row yet.
        required_keys = set(order[:-1]) if order else set()
        require(required_keys <= invocations.keys(), 'native_execution_mismatch', 'executor.missing_closed_run')
    else:
        require(invocations.keys() == ends.keys(), 'native_execution_mismatch', 'executor.missing_run')
    return invocations, ends, exec_statuses


def _unpack_expected_executor(raw_exp):
    if isinstance(raw_exp, tuple):
        if len(raw_exp) >= 3:
            return raw_exp[0], bool(raw_exp[1]), raw_exp[2]
        if len(raw_exp) == 2:
            return raw_exp[0], bool(raw_exp[1]), NORMAL_TERMINATION_REASON
    return raw_exp, False, NORMAL_TERMINATION_REASON


def _generations_iter(db, steps, generated, wrapped, expected, tools, digest, *,
                      errors=None, compacted_public=False, is_running=False, last_checkpoint=-1):
    errors = errors or {}
    counts = Counter()
    err_counts = Counter()
    seen, matched_prompts = set(), set()
    starts = {}
    gen_limit = _gen_blob_limit()
    rows = db.execute('SELECT idx,substr(data,1,?) FROM gen_metadata ORDER BY idx LIMIT ?',
                      (gen_limit + 1, len(steps) + 1))
    need_model_bytes = bool(wrapped) or any(tools.values())
    wanted = {1, 2, 3, 4, 5} if need_model_bytes else {2, 3, 4, 5}
    all_executions = {k for k in steps if k is not None}
    for index, (idx, raw) in enumerate(rows):
        if index and index % 64 == 0:
            yield {'phase': 'scanning'}
        require(type(idx) is int and idx == index and idx < len(steps), 'native_invocations_mismatch')
        value = Fields(raw, wanted, max_bytes=gen_limit)
        _planner(value.one(3), path=f'gen_metadata[{idx}].3')
        execution = _uuid(value.one(4))
        require(execution in all_executions, 'native_invocations_mismatch')
        if not is_running:
            require(execution in expected, 'native_invocations_mismatch')
        error = value.one(5)
        if error is None:
            counts[execution] += 1
        else:
            require(bool(error), 'native_invocations_mismatch')
            err_counts[execution] += 1
        positions = value.one(2)
        error_position = None
        if positions is not None and len(positions) > 0:
            offset, previous = 0, -1
            while offset < len(positions):
                i, offset = _varint(positions, offset)
                require(previous < i < len(steps) and i not in seen and steps[i] == execution,
                        'native_invocations_mismatch')
                starts.setdefault(idx, i)
                if i in errors:
                    if not compacted_public:
                        require(errors[i] == idx and error is not None and offset == len(positions),
                                'native_invocations_mismatch')
                    error_position = i
                elif not compacted_public and i in generated:
                    require(generated.get(i) == idx, 'native_invocations_mismatch')
                previous = i
                seen.add(i)
            if not compacted_public and not is_running:
                exp_val = expected.get(execution)
                _, had_exec_err, exec_status = _unpack_expected_executor(exp_val) if exp_val is not None else (0, False, NORMAL_TERMINATION_REASON)
                if error_position is not None:
                    require(error is not None, 'native_invocations_mismatch', f'gen_metadata[{idx}].error_without_flag')
                elif not had_exec_err and exec_status == NORMAL_TERMINATION_REASON:
                    require(error is None, 'native_invocations_mismatch', f'gen_metadata[{idx}].error_without_step')
        if need_model_bytes and (wrapped or tools.get(execution)):
            model = Fields(value.one(1, default=b''), {1, 2, 8}, max_bytes=gen_limit)
            for raw_tool in model.many(8) if tools.get(execution) else ():
                definition = Fields(raw_tool, {1}, max_bytes=gen_limit)
                name = definition.one(1)
                if name is not None and len(name) <= 255:
                    tools[execution].discard(bytes(name))
            for raw_prompt in model.many(2):
                prompt = Fields(raw_prompt, {2, 3, 18}, max_bytes=gen_limit)
                i = prompt.one(18, 0, 0)
                if i in wrapped:
                    role = prompt.one(2, 0)
                    text = prompt.one(3)
                    if (18 not in prompt.selected and role == 5 and text and model.one(1) == text
                            and text[:14] != b'<USER_REQUEST>'):
                        continue
                    require((idx not in starts or i < starts[idx]) and role == 1 and text is not None
                            and hashlib.sha256(text).digest() == wrapped[i], 'native_visible_message_mismatch')
                    matched_prompts.add(i)
        _digest(digest, raw)
    if not compacted_public and not is_running:
        # Strict invocation count accounting for clean non-compacted idle trajectories.
        # Every invocation on a non-normal terminal status without execution_error (field 12)
        # must still be strictly accounted for by gen_metadata (ok + err); zero unverified skipping.
        for key, raw_exp in expected.items():
            exp_count, had_exec_err, exec_status = _unpack_expected_executor(raw_exp)
            if had_exec_err:
                require(
                    counts[key] <= exp_count <= counts[key] + err_counts[key] + 1,
                    'native_invocations_mismatch',
                    f'executor.invocations(status={exec_status},exp={exp_count},ok={counts[key]},err={err_counts[key]})',
                )
            elif exec_status == 1:
                require(
                    err_counts[key] >= 1 and counts[key] <= exp_count <= counts[key] + err_counts[key],
                    'native_invocations_mismatch',
                    f'executor.invocations(status=1,exp={exp_count},ok={counts[key]},err={err_counts[key]})',
                )
            elif exec_status in NON_NORMAL_TERMINATION_REASONS:
                require(
                    counts[key] <= exp_count <= counts[key] + err_counts[key],
                    'native_invocations_mismatch',
                    f'executor.invocations(status={exec_status},exp={exp_count},ok={counts[key]},err={err_counts[key]})',
                )
            else:
                require(
                    counts[key] == exp_count,
                    'native_invocations_mismatch',
                    f'executor.invocations(status={exec_status},exp={exp_count},ok={counts[key]},err={err_counts[key]})',
                )
        for i in sorted(errors.keys() - seen, reverse=True):
            idx = errors[i]
            if i + 1 < len(steps) and steps[i] is not None and steps[i] == steps[i + 1]:
                require(starts.get(idx) == i + 1, 'native_invocations_mismatch')
                starts[idx] = i
    required_wrapped = {i for i in wrapped if i > last_checkpoint}
    require(required_wrapped <= matched_prompts, 'native_visible_message_mismatch')
    require(not any(tools.values()), 'native_tool_lifecycle_unverified')


def _generations(db, steps, generated, wrapped, expected, tools, digest, *,
                 errors=None, compacted_public=False, is_running=False, last_checkpoint=-1):
    return _drain(_generations_iter(
        db, steps, generated, wrapped, expected, tools, digest,
        errors=errors, compacted_public=compacted_public, is_running=is_running,
        last_checkpoint=last_checkpoint,
    ))


def _optional_file_stamp(root, relative):
    try:
        with root.open(relative) as stream:
            return _stamp(os.fstat(stream.fileno()))
    except AccessError:
        return None


def _capture_stamps(root, index_rel, native_id, transcript_rel, child_ids=()):
    index_stamps = _database_stamps(root, index_rel)
    native_stamps = _database_stamps(root, f'conversations/{native_id}.db')
    compact_rel = transcript_rel or f'brain/{native_id}/.system_generated/logs/transcript.jsonl'
    full_rel = compact_rel.removesuffix('transcript.jsonl') + 'transcript_full.jsonl'
    transcript_stamps = (
        _optional_file_stamp(root, compact_rel),
        _optional_file_stamp(root, full_rel),
    )
    child_stamps = tuple(
        (cid, _database_stamps(root, f'conversations/{cid}.db'))
        for cid in child_ids
    )
    return index_stamps, native_stamps, transcript_stamps, child_stamps


def capture_iter(adapter, thread, *, excluded_related=()):
    """Cooperative generator variant of capture() yielding bounded scanning checkpoints."""
    global _CAPTURE_CACHE_BYTES
    from .agent_history_antigravity import INDEX, _native_id, _supports_native_sqlite
    require(_supports_native_sqlite(adapter.version) and _native_id(thread.native_id), 'native_profile_unverified')
    native = f'conversations/{thread.native_id}.db'
    root = adapter.root
    patched = '_snapshot' in adapter.__dict__ or 'snapshot' in adapter.__dict__
    excl_key = tuple(sorted(excluded_related))
    base_key = (
        root.identity,
        adapter.version,
        thread.native_id,
        thread.location,
        thread.title,
        thread.updated_at,
        thread.native_project_id,
        thread.contexts,
        thread.ancestors,
        excl_key,
        MAX_STEPS,
        MAX_BLOB,
        MAX_GEN_BLOB,
    )
    if not patched:
        cached = _CAPTURE_CACHE.get(base_key)
        if cached is not None:
            c_weight, c_stamps, c_obs, c_proj = cached
            try:
                live_stamps = _capture_stamps(root, INDEX, thread.native_id, thread.location, c_proj.related_threads)
            except AccessError:
                live_stamps = None
            if live_stamps == c_stamps:
                _CAPTURE_CACHE.move_to_end(base_key)
                return c_obs, c_proj
            # Live stamp drifted: evict stale entry and run a full fresh verification.
            _CAPTURE_CACHE.pop(base_key, None)
            _CAPTURE_CACHE_BYTES -= c_weight
    index_identity = root.identity_for(INDEX)
    try:
        before_index_stamps, before, before_transcript_stamps, _ = _capture_stamps(
            root, INDEX, thread.native_id, thread.location, ()
        )
    except AccessError:
        before_index_stamps = before_transcript_stamps = None
        before = _database_stamps(root, native)
    yield {'phase': 'scanning'}
    manifest = []
    if patched or not hasattr(adapter, '_snapshot_iter'):
        projection = adapter._snapshot(thread, manifest)
    else:
        projection = yield from adapter._snapshot_iter(thread, manifest)
    # Reject corrupted or truncated transcripts; allow missing_steps (non-public
    # steps omitted by Antigravity) and unfinished_messages_omitted on active threads.
    fatal_warnings = set(projection.warnings) - {'missing_steps', 'unfinished_messages_omitted'}
    require(not fatal_warnings, 'native_transcript_incomplete')
    digest = hashlib.sha256()
    messages = {message.position: message for message in projection.messages}
    yield {'phase': 'scanning'}
    with root.sqlite(INDEX) as db:
        claim = _index_claim(db, thread)
        indexed_children = {
            row[0] for row in db.execute(
                'SELECT conversation_id FROM conversation_summaries WHERE parent_conversation_id = ?',
                (thread.native_id,),
            ) if _native_id(row[0])
        }
    workspaces, count, busy, is_running = claim
    manifest_indices = {row[0] for row in manifest}
    paired = projection.identity.startswith('paired:')
    from .agent_history_antigravity_commit import (
        check_call_position,
        verify_closed_executors,
        verify_discarded_proposals,
    )
    yield {'phase': 'scanning'}
    with root.sqlite(native) as db:
        yield {'phase': 'scanning'}
        trajectory, contexts, birth = _trajectory(db, thread, workspaces, digest)
        (steps, generated, wrapped, public, specs, tools, last,
         related_children, compacted_public, active_tail, errors, last_checkpoint,
         pending_tools, step_completions, error_steps_by_exec, call_records) = yield from _steps_iter(
            db, trajectory, thread.native_id, count, messages, digest, birth,
            is_running=is_running, manifest_indices=manifest_indices
        )
        yield {'phase': 'scanning'}
        discarded = verify_discarded_proposals(
            db, pending_tools, paired=paired, manifest_indices=manifest_indices
        )
        if discarded:
            for c_idx, c_kind, c_meta, c_payload in call_records:
                check_call_position(discarded, c_idx, c_kind, c_meta, c_payload)
        yield {'phase': 'scanning'}
        executors, exec_ends, exec_statuses = _executors(db, steps, specs, tools, digest, is_running=is_running)
        verify_closed_executors(
            db, exec_ends, exec_statuses, step_completions, error_steps_by_exec,
            require_explicit_stop=bool(discarded),
        )
        yield {'phase': 'scanning'}
        yield from _generations_iter(db, steps, generated, wrapped, executors, tools, digest,
                                     errors=errors, compacted_public=compacted_public, is_running=is_running,
                                     last_checkpoint=last_checkpoint)

    all_children = sorted(related_children | indexed_children)
    senders = b''
    if all_children:
        from . import agent_history_antigravity_relations as _rel
        require(not any(cid in excluded_related for cid in all_children), 'native_parent_history_unverified')
        try:
            before_child_stamps = tuple(
                (cid, _database_stamps(root, f'conversations/{cid}.db'))
                for cid in all_children
            )
        except AccessError:
            before_child_stamps = None
        yield {'phase': 'scanning'}
        if getattr(_rel.verify_senders, '_is_default', False):
            senders = yield from _rel.verify_senders_iter(
                root, thread, contexts, all_children, birth, last, excluded_related=excluded_related
            )
        else:
            senders = _rel.verify_senders(
                root, thread, contexts, all_children, birth, last, excluded_related=excluded_related
            )
        require(isinstance(senders, bytes) and len(senders) == 32, 'native_parent_history_unverified')
        _digest(digest, senders)
    else:
        before_child_stamps = ()

    # TOCTOU re-verification: confirm transcripts, children, index & trajectory DB did not drift.
    yield {'phase': 'scanning'}
    if (projection.identity.startswith('paired:') or projection.warnings
            or any(row[3] == 'RUNNING' for row in manifest)):
        if patched or not hasattr(adapter, '_snapshot_iter'):
            current_projection = adapter._snapshot(thread, [])
        else:
            current_projection = yield from adapter._snapshot_iter(thread, [])
    else:
        if patched or not hasattr(adapter, 'snapshot_iter'):
            current_projection = adapter.snapshot(thread)
        else:
            current_projection = yield from adapter.snapshot_iter(thread)
    require(projection == current_projection, 'native_capture_changed')
    if all_children:
        from . import agent_history_antigravity_relations as _rel
        yield {'phase': 'scanning'}
        if getattr(_rel.verify_senders, '_is_default', False):
            rechecked_senders = yield from _rel.verify_senders_iter(
                root, thread, contexts, all_children, birth, last, excluded_related=excluded_related
            )
        else:
            rechecked_senders = _rel.verify_senders(
                root, thread, contexts, all_children, birth, last, excluded_related=excluded_related
            )
        require(senders == rechecked_senders, 'native_capture_changed')
    yield {'phase': 'scanning'}
    with root.sqlite(INDEX) as db:
        current_claim = _index_claim(db, thread)
    if (current_claim != claim or root.identity_for(INDEX) != index_identity
            or _database_stamps(root, native) != before):
        raise AccessError('The native history snapshot changed during capture.', code='waiting_source_stable')

    _digest(digest, projection.revision.encode('ascii'))
    identity = hashlib.sha256(repr((root.identity, index_identity, before[0][1][:3], projection.identity)).encode()).hexdigest()
    revision = digest.hexdigest()
    observation = Assessment('workspace_verified', 'desktop_default_agent_trajectory',
                             len(steps), len(executors), sum(c[0] for c in executors.values()), revision)
    safe_messages = tuple(
        replace(item, text=public[int(item.position.removeprefix('step:'))]) if item.role == 'user' else item
        for item in projection.messages
    )
    out_warnings = set(projection.warnings)
    if compacted_public:
        out_warnings.add('compacted_steps_from_transcript')
    if is_running or active_tail or (busy and not discarded):
        out_warnings.add('thread_in_progress')
    out_projection = replace(
        projection,
        messages=safe_messages,
        contexts=contexts,
        context_complete=True,
        warnings=tuple(sorted(out_warnings)),
        identity=identity,
        revision=revision,
        prefix=None,
        related_threads=tuple(all_children),
        origin_ns=birth[0] * 1_000_000_000 + birth[1],
        last_ns=last[0] * 1_000_000_000 + last[1],
    )
    expected_stamps = (
        (before_index_stamps, before, before_transcript_stamps, before_child_stamps)
        if (before_index_stamps is not None and before_child_stamps is not None)
        else None
    )
    if not patched and not is_running and expected_stamps is not None:
        try:
            final_stamps = _capture_stamps(root, INDEX, thread.native_id, thread.location, out_projection.related_threads)
        except AccessError:
            final_stamps = None
        if final_stamps == expected_stamps:
            weight = sum(4 * len(m.text) + 256 for m in out_projection.messages) + 4096
            if weight <= _MAX_CAPTURE_CACHE_BYTES // 2:
                old = _CAPTURE_CACHE.pop(base_key, None)
                if old is not None:
                    _CAPTURE_CACHE_BYTES -= old[0]
                while _CAPTURE_CACHE and (
                    len(_CAPTURE_CACHE) >= _MAX_CAPTURE_CACHE
                    or _CAPTURE_CACHE_BYTES + weight > _MAX_CAPTURE_CACHE_BYTES
                ):
                    _, (ev_weight, _, _, _) = _CAPTURE_CACHE.popitem(last=False)
                    _CAPTURE_CACHE_BYTES -= ev_weight
                _CAPTURE_CACHE[base_key] = (weight, final_stamps, observation, out_projection)
                _CAPTURE_CACHE_BYTES += weight
    return observation, out_projection


def capture(adapter, thread, *, excluded_related=()):
    """Return a bound public projection for the positively identified desktop trajectory."""
    return _drain(capture_iter(adapter, thread, excluded_related=excluded_related))
