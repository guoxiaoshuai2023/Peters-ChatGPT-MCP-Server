"""Invariant-driven containment verification for Antigravity child subagents.

Only the parent's public messages are projected. Every child subagent (whether
referenced by parent events or linked via conversation_summaries.parent_conversation_id)
is verified for strict same-parent, same-project, same-workspace containment,
no external user continuations, no forks/battle-mode, and no dynamic workspace
overrides — without brittle whitelisting of benign internal subagent tool calls.
"""
from hashlib import sha256
import json

from .agent_history_antigravity import INDEX, INDEX_VERSION, MAX_INDEX_FIELD_CHARS, _native_id
from .agent_history_antigravity_native import (
    Fields, MAX_BLOB, MAX_STEPS, _database_stamps, _digest, _epoch, _no_dynamic,
    _path, _planner, _schema, _uuid, require,
)
from .agent_history_source import _MAX_SQLITE
from .catalog import AccessError

RELATION = 'native_parent_history_unverified'


def _summary(index, child_id, parent):
    rows = index.execute(
        'SELECT project_id,substr(workspace_uris,1,?),parent_conversation_id,nesting_depth,'
        'step_count,not_fully_idle,status,killed FROM conversation_summaries WHERE conversation_id=? LIMIT 2',
        (MAX_INDEX_FIELD_CHARS + 1, child_id)).fetchall()
    require(len(rows) == 1, RELATION)
    project, workspaces, owner, depth, count, busy, status, killed = rows[0]
    require(
        owner == parent.native_id
        and project == parent.native_project_id
        and type(depth) is int and 1 <= depth <= 4
        and type(busy) is int and busy in (0, 1)
        and type(killed) is int and killed in (0, 1)
        and status in ('CASCADE_RUN_STATUS_IDLE', 'CASCADE_RUN_STATUS_RUNNING'),
        RELATION,
    )
    require(type(count) is int and 0 <= count <= MAX_STEPS and isinstance(workspaces, str)
            and len(workspaces) <= MAX_INDEX_FIELD_CHARS, RELATION)
    try:
        uris = json.loads(workspaces)
    except (ValueError, RecursionError):
        require(False, RELATION)
    require(isinstance(uris, list) and len(uris) == len(parent.contexts) <= 64
            and {_path(uri) for uri in uris} == set(parent.contexts), RELATION)
    edges = list(index.execute('SELECT parent_id FROM conversation_parents WHERE conversation_id=? LIMIT 2',
                               (child_id,)))
    require(not edges or edges == [(parent.native_id,)], RELATION)
    return count


def _header(db, child_id, parent, contexts, digest):
    require(db.execute('PRAGMA user_version').fetchone() == (1,), RELATION)
    _schema(db, ('trajectory_meta', 'parent_references', 'battle_mode_infos', 'trajectory_metadata_blob',
                 'steps', 'gen_metadata', 'executor_metadata'))
    require(not db.execute('SELECT 1 FROM parent_references LIMIT 1').fetchone()
            and not db.execute('SELECT 1 FROM battle_mode_infos LIMIT 1').fetchone(), RELATION)
    rows = db.execute('SELECT trajectory_id,cascade_id,trajectory_type,source FROM trajectory_meta LIMIT 2').fetchall()
    require(len(rows) == 1 and _native_id(rows[0][0]) and rows[0][1] == child_id and rows[0][2] == 4, RELATION)
    trajectory = rows[0][0]
    rows = db.execute('SELECT id,substr(data,1,?) FROM trajectory_metadata_blob LIMIT 2', (MAX_BLOB + 1,)).fetchall()
    require(len(rows) == 1 and rows[0][0] == 'main', RELATION)
    raw = rows[0][1]
    head = Fields(raw, {1, 2, 3, 5, 6, 7, 16, 17, 18})
    # Reject forked child trajectories (field 16 in trajectory_metadata_blob).
    require(head.one(16, 0) is None and not head.many(16, 2), RELATION)
    if head.one(3) is not None:
        _uuid(head.one(3))
    # Verify parent & project identity bindings in trajectory_metadata_blob
    if head.one(5) is not None:
        require(_uuid(head.one(5)) == parent.native_id, RELATION)
    if head.one(6) is not None:
        require(_uuid(head.one(6)) in (parent.native_id, child_id), RELATION)
    require(_uuid(head.one(18)) == parent.native_project_id, RELATION)
    folders = head.many(1)
    uris = head.many(7)
    require(len(folders) == len(uris) == len(parent.contexts)
            and {_path(uri) for uri in uris} == set(parent.contexts), RELATION)
    directory_roots = set()
    for item in folders:
        workspace = Fields(item, {1, 2})
        directory_roots.add(_path(workspace.one(1)))
        git = workspace.one(2)
        require(git is None or _path(git) in contexts, RELATION)
    require(directory_roots == set(parent.contexts), RELATION)
    _digest(digest, child_id.encode(), trajectory.encode(), raw)
    birth = _epoch(head.one(2)) if head.one(2) is not None else (0, 0)
    return trajectory, birth


def _verify_child_db(db, child_id, parent, contexts, digest, gen_limit, *, receipts=(), parent_end=None):
    from .agent_history_antigravity_native import _step_completion, _try_uuid
    trajectory, child_birth = _header(db, child_id, parent, contexts, digest)
    receipt_by_pos = {r[1]: r for r in receipts}
    latest_completion = child_birth
    seen_receipts = set()
    rows = db.execute(
        'SELECT idx,step_type,status,has_subtrajectory,substr(metadata,1,?),substr(step_payload,1,?),step_format '
        'FROM steps ORDER BY idx LIMIT ?',
        (MAX_BLOB + 1, MAX_BLOB + 1, MAX_STEPS + 1),
    )
    for expected, (idx, kind, status, nested, raw_meta, raw_step, fmt) in enumerate(rows):
        require(type(idx) is int and idx == expected and nested == 0 and fmt == 0, RELATION)
        # Child subagents must never accept direct external USER_INPUT continuations.
        require(kind != 14, RELATION)
        meta = Fields(raw_meta, {1, 3, 4, 6, 7, 8, 12, 20, 26, 38})
        origin = Fields(meta.one(20), {1, 2, 4})
        require(_uuid(origin.one(1)) == trajectory and origin.one(2, 0, 0) == idx
                and _uuid(origin.one(4)) == child_id, RELATION)
        if kind == 101:
            payload = Fields(raw_step, {114})
            slot = payload.one(114)
            if slot is not None:
                sys_f = Fields(slot, {3, 4})
                if sys_f.one(3) == b'agent_message':
                    agent_raw = sys_f.one(4)
                    require(agent_raw is not None, RELATION)
                    sender = _try_uuid(Fields(agent_raw, {3}).one(3))
                    # Only the verified parent may send agent_messages to its child.
                    require(sender == parent.native_id, RELATION)
        created = _epoch(meta.one(1))
        completion = _step_completion(meta, kind, status, created)
        if idx in receipt_by_pos:
            receipt = receipt_by_pos[idx]
            require(kind == 132 and status == 3, RELATION)
            if len(receipt) >= 3 and receipt[2]:
                call_raw = meta.one(4)
                require(call_raw is not None and sha256(call_raw).hexdigest() == receipt[2], RELATION)
            if len(receipt) >= 6 and receipt[5] is not None:
                require(latest_completion <= completion <= receipt[5], RELATION)
            if parent_end is not None:
                require(completion <= parent_end, 'native_snapshot_not_committed')
            seen_receipts.add(idx)
        latest_completion = max(latest_completion, completion)
        _digest(digest, raw_meta, raw_step)
    require(seen_receipts == set(receipt_by_pos.keys()), RELATION)
    if receipts and parent_end is not None:
        require(latest_completion <= parent_end, 'native_snapshot_not_committed')
    # Check every executor_metadata row for dynamic workspace overrides.
    for _, raw in db.execute('SELECT idx,substr(data,1,?) FROM executor_metadata ORDER BY idx LIMIT ?',
                             (MAX_BLOB + 1, MAX_STEPS + 1)):
        exe = Fields(raw, {10, 17})
        _no_dynamic(exe.one(10), child=True)
        _no_dynamic(exe.one(17), child=True)
        _digest(digest, raw)
    # Check every gen_metadata row's planner config for prompt or workspace overrides.
    for _, raw in db.execute('SELECT idx,substr(data,1,?) FROM gen_metadata ORDER BY idx LIMIT ?',
                             (gen_limit + 1, MAX_STEPS + 1)):
        gen = Fields(raw, {3}, max_bytes=gen_limit)
        _planner(gen.one(3), child=True)
    return child_birth


def verify_senders(root, thread, contexts, child_items, birth, last, *, excluded_related=(), gen_limit=None):
    """Verify containment invariants for every contributing/linked child subagent."""
    from .agent_history_antigravity_native import _gen_blob_limit
    gen_limit = gen_limit if gen_limit is not None else _gen_blob_limit()
    groups = {}
    for item in child_items:
        if isinstance(item, str):
            cid = item
            require(_native_id(cid) and cid != thread.native_id, RELATION)
            groups.setdefault(cid, [])
        elif isinstance(item, tuple) and len(item) >= 2:
            cid, pos = item[0], item[1]
            require(_native_id(cid) and cid != thread.native_id and type(pos) is int, RELATION)
            receipts = groups.setdefault(cid, [])
            require(all(existing[1] != pos for existing in receipts), RELATION)
            receipts.append(item)
        else:
            require(False, RELATION)
    if len(groups) > 128 or sum(len(v) for v in groups.values()) > 128:
        raise AccessError('The native child conversation set exceeds the reader limit.', code='resource_exhausted')
    digest = sha256()
    remaining_bytes, remaining_steps = _MAX_SQLITE * 4, MAX_STEPS * 4
    with root.sqlite(INDEX) as index:
        require(index.execute('PRAGMA user_version').fetchone() == (INDEX_VERSION,), RELATION)
        for child_id in sorted(groups):
            receipts = groups[child_id]
            require(child_id not in excluded_related, RELATION)
            if receipts and len(receipts[0]) >= 5:
                require(len({r[3:5] for r in receipts}) == 1, RELATION)
            count = _summary(index, child_id, thread)
            native = f'conversations/{child_id}.db'
            stamps = _database_stamps(root, native)
            remaining_bytes -= sum(stamp[3] for _, stamp in stamps)
            remaining_steps -= count
            if remaining_steps < 0 or remaining_bytes < 0:
                raise AccessError('The native child conversation set exceeds the reader limit.',
                                  code='resource_exhausted')
            with root.sqlite(native) as db:
                child_birth = _verify_child_db(
                    db, child_id, thread, contexts, digest, gen_limit, receipts=receipts, parent_end=last
                )
                require(child_birth == (0, 0) or birth <= child_birth, RELATION)
                for receipt in receipts:
                    if len(receipt) >= 6:
                        require(child_birth <= receipt[5] <= last, RELATION)
            require(_database_stamps(root, native) == stamps, 'native_capture_changed')
            _digest(digest, repr(stamps).encode())
    return digest.digest()
