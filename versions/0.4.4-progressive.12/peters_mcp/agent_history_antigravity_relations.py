"""Verify one-hop native delivery from an inherited Desktop self subagent.

Only the parent's public messages are projected. The child's native startup,
execution and outgoing send authenticate the receipt embedded in the parent.
"""
from hashlib import sha256
import json
from collections import defaultdict

from .agent_history_antigravity import INDEX, INDEX_VERSION, MAX_INDEX_FIELD_CHARS, _native_id
from .agent_history_antigravity_events import TYPE_URL, verified_arguments
from .agent_history_antigravity_native import (
    Fields, MAX_BLOB, MAX_STEPS, METADATA_FIELDS, STEP_SLOTS, STEP_SOURCES,
    _database_stamps, _digest, _epoch, _generations, _no_dynamic, _path,
    _schema, _step_completion, _tool, _uuid, require,
)
from .agent_history_source import _MAX_SQLITE
from .catalog import AccessError

RELATION = 'native_parent_history_unverified'


def _summary(index, sender, parent):
    rows = index.execute(
        'SELECT project_id,substr(workspace_uris,1,?),parent_conversation_id,nesting_depth,'
        'step_count,not_fully_idle,status,killed FROM conversation_summaries WHERE conversation_id=? LIMIT 2',
        (MAX_INDEX_FIELD_CHARS + 1, sender)).fetchall()
    require(len(rows) == 1, RELATION)
    project, workspaces, owner, depth, count, busy, status, killed = rows[0]
    require(owner == parent.native_id and project == parent.native_project_id and depth == 1
            and busy == killed == 0 and status == 'CASCADE_RUN_STATUS_IDLE', RELATION)
    require(type(count) is int and 0 < count <= MAX_STEPS and isinstance(workspaces, str)
            and len(workspaces) <= MAX_INDEX_FIELD_CHARS, RELATION)
    try:
        uris = json.loads(workspaces)
    except (ValueError, RecursionError):
        require(False, RELATION)
    require(isinstance(uris, list) and len(uris) == len(parent.contexts) <= 64
            and {_path(uri) for uri in uris} == set(parent.contexts), RELATION)
    edges = list(index.execute('SELECT parent_id FROM conversation_parents WHERE conversation_id=? LIMIT 2',
                               (sender,)))
    require(not edges or edges == [(parent.native_id,)], RELATION)
    return count


def _agent_config(raw):
    spec = Fields(raw, {11, 18}, allowed={11, 18})
    _no_dynamic(spec.one(11))
    config = Fields(spec.one(18), {1, 3, 4}, allowed={1, 3, 4})
    _no_dynamic(config.one(3))
    # Local component names and prompt sections. This profile excludes custom
    # providers, source overrides, explicit workspace paths and discovery roots.
    Fields(config.one(1), set(), allowed={2, 3, 4, 5, 6, 7, 8, 10, 11})
    discovery = Fields(config.one(4), {1, 2}, allowed={1, 2, 12})
    if discovery.one(1) is not None:
        Fields(discovery.one(1), set(), allowed={5, 6})
    if discovery.one(2) is not None:
        Fields(discovery.one(2), set(), allowed={2})


def _header(db, sender, parent, contexts, digest):
    require(db.execute('PRAGMA user_version').fetchone() == (1,), RELATION)
    _schema(db, ('trajectory_meta', 'parent_references', 'battle_mode_infos', 'trajectory_metadata_blob',
                 'steps', 'gen_metadata', 'executor_metadata'))
    require(not db.execute('SELECT 1 FROM parent_references LIMIT 1').fetchone()
            and not db.execute('SELECT 1 FROM battle_mode_infos LIMIT 1').fetchone(), RELATION)
    rows = db.execute('SELECT trajectory_id,cascade_id,trajectory_type,source FROM trajectory_meta LIMIT 2').fetchall()
    require(len(rows) == 1 and _native_id(rows[0][0]) and rows[0][1:] == (sender, 4, 1), RELATION)
    trajectory = rows[0][0]
    rows = db.execute('SELECT id,substr(data,1,?) FROM trajectory_metadata_blob LIMIT 2', (MAX_BLOB + 1,)).fetchall()
    require(len(rows) == 1 and rows[0][0] == 'main', RELATION)
    raw = rows[0][1]
    tags = {1, 2, 3, 4, 5, 6, 7, 8, 10, 17, 18}
    head = Fields(raw, tags, allowed=tags | {15})
    _uuid(head.one(3))
    require(_uuid(head.one(5)) == _uuid(head.one(6)) == parent.native_id
            and _uuid(head.one(18)) == parent.native_project_id and head.one(17, 0) == 1, RELATION)
    subagent = Fields(head.one(8), {1, 4}, allowed={1, 2, 3, 4, 7, 12})
    script = Fields(head.one(4), {1, 7}, allowed={1, 7, 8})
    require(subagent.one(1) == script.one(1) == b'self' and subagent.one(4, 0) == 1, RELATION)
    _agent_config(script.one(7))
    _agent_config(head.one(10))
    folders = head.many(1)
    uris = head.many(7)
    require(len(folders) == len(uris) == len(parent.contexts)
            and {_path(uri) for uri in uris} == set(parent.contexts), RELATION)
    directory_roots = set()
    for item in folders:
        workspace = Fields(item, {1, 2}, allowed={1, 2, 3, 4})
        directory_roots.add(_path(workspace.one(1)))
        git = workspace.one(2)
        require(git is None or _path(git) in contexts, RELATION)
    require(directory_roots == set(parent.contexts), RELATION)
    _digest(digest, sender.encode(), trajectory.encode(), raw)
    return trajectory, _epoch(head.one(2))


def _incoming(raw, parent, relation, created):
    # The child's first event is the same spawn call as the parent's receipt.
    item = Fields(raw, {3, 4}, allowed={1, 2, 3, 4})
    require(item.one(3) == b'agent_message', RELATION)
    agent = Fields(item.one(4), {1, 2, 3, 6, 12}, allowed={1, 2, 3, 4, 5, 6, 10, 12})
    _uuid(agent.one(1))
    require(_uuid(agent.one(2)) == relation[0] and _uuid(agent.one(3)) == parent
            and _epoch(agent.one(6)) <= created, RELATION)
    source = Fields(Fields(agent.one(12), {1}, allowed={1}).one(1), {1, 2, 3}, allowed={1, 2, 3})
    require(_uuid(source.one(1)) == parent and source.one(2, 0, 0) == relation[3]
            and sha256(source.one(3, default=b'')).hexdigest() == relation[4], RELATION)


def _operation(meta, payload, status, parent, receipt, completion, artifact_root):
    call = meta.one(4)
    header = Fields(call, {2, 9})
    name = header.one(2)
    require(meta.one(38, 0) == 1 and name is not None and header.one(9, default=name) == name, RELATION)
    raw = payload.one(140)
    if name == b'send_message':
        require(receipt is not None and status == 3 and completion <= receipt[5]
                and sha256(call).hexdigest() == receipt[2], RELATION)
        args, result = verified_arguments(name, call, raw, {'Recipient', 'Message'})
        any_result = Fields(Fields(result, {6}, allowed={1, 3, 6, 7}).one(6), {1, 2}, allowed={1, 2})
        require(any_result.one(1) == TYPE_URL + b'SendMessage', RELATION)
        sent = Fields(any_result.one(2), {1, 3}, allowed={1, 2, 3})
        require(sent.one(1) == args['Recipient'] == parent.encode()
                and sent.one(3) == args['Message'], RELATION)
    else:
        require(receipt is None and name in (b'read_file', b'run_command', b'search_web',
                                              b'write_file', b'edit_file'), RELATION)
        if name == b'search_web' and status == 7:
            _, result = verified_arguments(name, call, raw, {'query'}, ('domain',))
            if result is not None:
                Fields(result, set(), allowed={1, 3, 7})
            require(payload.one(31) is not None, RELATION)
        else:
            _tool(meta, raw, status=status, artifact_root=artifact_root)


def _run(db, sender, parent, receipts, trajectory, count, child_birth, artifact_root, digest):
    # The observed delivery profile has one uninterrupted, locally spawned run.
    # No user continuations, cascaded senders, active tasks, or workspace changes.
    rows = db.execute('SELECT idx,step_type,status,has_subtrajectory,substr(metadata,1,?),'
                      'substr(step_payload,1,?),step_format FROM steps ORDER BY idx LIMIT ?',
                      (MAX_BLOB + 1, MAX_BLOB + 1, count + 1))
    steps, generated, errors = [], {}, {}
    spawn = next(iter(receipts.values()))
    previous = child_birth
    for i, (idx, kind, status, nested, metadata, raw, fmt) in enumerate(rows):
        require(i == idx < count and nested == fmt == 0 and kind in (15, 17, 101, 132)
                and (status == 3 or (kind, status) == (132, 7)) and (kind == 101) == (i == 0), RELATION)
        meta = Fields(metadata, {1, 3, 4, 6, 7, 8, 12, 20, 26, 38}, allowed=METADATA_FIELDS[kind])
        require(meta.one(3, 0) == STEP_SOURCES[kind], RELATION)
        key = _uuid(meta.one(12))
        require(not steps or steps[-1] == key, RELATION)
        steps.append(key)
        origin = Fields(meta.one(20), {1, 2, 3, 4}, allowed={1, 2, 3, 4})
        require(_uuid(origin.one(1)) == trajectory and origin.one(2, 0, 0) == idx
                and _uuid(origin.one(4)) == sender, RELATION)
        created = _epoch(meta.one(1))
        require(created >= previous, RELATION)
        previous = created
        completion = _step_completion(meta, kind, status, created)
        slot = STEP_SLOTS[kind]
        tags = {1, 4, 5, slot} | ({31} if status == 7 else set())
        payload = Fields(raw, tags, allowed=tags)
        require(payload.one(1, 0) == kind and payload.one(4, 0) == status
                and payload.one(5) == metadata and payload.one(slot) is not None, RELATION)
        if kind == 101:
            _incoming(payload.one(slot), parent, spawn, created)
        if kind == 132:
            _operation(meta, payload, status, parent, receipts.get(idx), completion, artifact_root)
        else:
            require(idx not in receipts, RELATION)
        if kind in (15, 132):
            generated[i] = origin.one(3, 0, 0)
        elif kind == 17:
            errors[i] = origin.one(3, 0, 0)
        _digest(digest, metadata, raw)
    require(len(steps) == count and all(0 < index < count for index in receipts), RELATION)
    from .agent_history_antigravity_commit import _final_reply
    _final_reply(db, count - 1)
    records = db.execute('SELECT idx,substr(data,1,?) FROM executor_metadata LIMIT 2',(MAX_BLOB + 1,)).fetchall()
    require(len(records) == 1 and records[0][0] == 0, RELATION)
    raw = records[0][1]
    exe = Fields(raw, {1, 2, 3, 9, 10, 17}, allowed={1, 2, 3, 9, 10, 11, 17, 18})
    require(_uuid(exe.one(9)) == steps[0] and exe.one(3, 0, 0) == count - 1 and exe.one(1, 0) == 4,
            RELATION)
    _no_dynamic(exe.one(10))
    _no_dynamic(exe.one(17))
    _digest(digest, raw)
    _generations(db, steps, generated, {}, {steps[0]: exe.one(2, 0, 0)}, {}, digest, errors=errors)


def verify_senders(root, thread, contexts, relations, birth, last):
    """Revalidate exact direct send receipts without creating references to children."""
    if len(relations) > 128:
        raise AccessError('The native receipt set exceeds the reader limit.', code='resource_exhausted')
    digest = sha256()
    remaining_bytes, remaining_steps = _MAX_SQLITE, MAX_STEPS
    groups = defaultdict(dict)
    for relation in relations:
        sender, position = relation[:2]
        require(_native_id(sender) and sender != thread.native_id and type(position) is int
                and position not in groups[sender], RELATION)
        groups[sender][position] = relation
    with root.sqlite(INDEX) as index:
        require(index.execute('PRAGMA user_version').fetchone() == (INDEX_VERSION,), RELATION)
        for sender, receipts in groups.items():
            require(len({r[3:5] for r in receipts.values()}) == 1, RELATION)
            count = _summary(index, sender, thread)
            native = f'conversations/{sender}.db'
            stamps = _database_stamps(root, native)
            remaining_bytes -= sum(stamp[3] for _, stamp in stamps)
            remaining_steps -= count
            if remaining_steps < 0 or remaining_bytes < 0:
                raise AccessError('The native receipt set exceeds the reader limit.', code='resource_exhausted')
            with root.sqlite(native) as db:
                trajectory, child_birth = _header(db, sender, thread, contexts, digest)
                require(birth <= child_birth and all(child_birth <= r[5] <= last for r in receipts.values()), RELATION)
                _run(db, sender, thread.native_id, receipts, trajectory, count, child_birth,
                     root.path / 'brain' / sender, digest)
            require(_database_stamps(root, native) == stamps, 'native_capture_changed')
            _digest(digest, repr(stamps).encode())
    return digest.digest()
