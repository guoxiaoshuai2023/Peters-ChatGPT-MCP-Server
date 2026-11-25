"""Verify Antigravity Desktop native commit boundaries and discarded tool proposals."""

from .agent_history_antigravity_native import Fields, MAX_BLOB, _epoch, _varint, require


def verify_discarded_proposal(db, index):
    """Prove a non-tail PENDING (status=1) tool step was discarded before execution.

    Invariant-driven (no hardcoded built-in tool-name list):
    1. Strictly bracketed by (index-1: PLANNER_RESPONSE DONE, index: GENERIC PENDING,
       index+1: ERROR_MESSAGE DONE) under the exact same (execution, generation).
    2. Preceding PLANNER_RESPONSE stopped with CLIENT_STREAM_ERROR (18), emitted no
       visible public text, and requested the exact raw call descriptor on step index.
    3. Step index is a built-in (source=1, non-mcp_*) call with non-empty call_id & args,
       never started/completed (no meta.32/meta.8), transitioned solely to PENDING (1),
       and carries zero tool result payload (generic.2 is absent).
    4. Timestamps satisfy proposed_at <= prev_ready <= prev_completed <= next_error_created.
    5. gen_metadata[generation] belongs to the same execution, records a non-empty error
       (field 5), and indexes [index-1, index, index+1].
    """
    require(index > 0, 'native_transcript_incomplete')
    rows = db.execute(
        'SELECT idx,step_type,status,substr(metadata,1,?),substr(step_payload,1,?) '
        'FROM steps WHERE idx BETWEEN ? AND ? ORDER BY idx LIMIT 4',
        (MAX_BLOB + 1, MAX_BLOB + 1, index - 1, index + 1),
    ).fetchall()
    expected = [(index - 1, 15, 3), (index, 132, 1), (index + 1, 17, 3)]
    require([r[:3] for r in rows] == expected, 'native_tool_lifecycle_unverified')

    keys = []
    for _, _, _, meta_raw, _ in rows:
        meta = Fields(meta_raw, {12, 20})
        source = Fields(meta.one(20), {3})
        keys.append((meta.one(12), source.one(3, 0, 0)))
    require(keys[0] is not None and keys[0] == keys[1] == keys[2] and keys[0][0] is not None,
            'native_execution_mismatch')

    planner, proposal, error = [Fields(r[4], {20, 140, 24}) for r in rows]
    response = Fields(planner.one(20), {1, 7, 8, 12})
    # STOP_REASON_CLIENT_STREAM_ERROR (18): model stream failed while proposing the call.
    requested_calls = response.many(7)
    require(response.one(12, 0) == 18 and not response.one(8, default=response.one(1))
            and len(requested_calls) >= 1, 'native_tool_lifecycle_unverified')

    meta = Fields(rows[1][3], {4, 6, 7, 8, 26, 32, 38})
    call_raw = meta.one(4)
    require(call_raw is not None, 'native_tool_lifecycle_unverified')
    call = Fields(call_raw, {1, 2, 3, 9})
    call_id = call.one(1, default=b'')
    name = call.one(2)
    require(meta.one(38, 0) == 1
            and name is not None and 0 < len(name) <= 255
            and not bytes(name).startswith(b'mcp_')
            and call.one(9, default=name) == name
            and 0 < len(call_id) <= 255
            and bool(call.one(3))
            and bytes(call_raw) in {bytes(item) for item in requested_calls},
            'native_tool_lifecycle_unverified')

    # Never started or completed; sole state transition must be PENDING (1).
    require(meta.one(32) is None and meta.one(8) is None, 'native_tool_lifecycle_unverified')
    if meta.one(6) is not None and meta.one(7) is not None:
        require(_epoch(meta.one(6)) == _epoch(meta.one(7)), 'native_tool_lifecycle_unverified')
    raw_transitions = meta.one(26)
    require(raw_transitions is not None, 'native_tool_lifecycle_unverified')
    transitions = Fields(raw_transitions, {1}).many(1)
    require(len(transitions) == 1, 'native_tool_lifecycle_unverified')
    sole = Fields(transitions[0], {1, 2})
    require(sole.one(1, 0) == 1, 'native_tool_lifecycle_unverified')
    proposed_at = _epoch(sole.one(2))

    previous = Fields(rows[0][3], {7, 8})
    next_error = Fields(rows[2][3], {1})
    prev_ready = _epoch(previous.one(7)) if previous.one(7) is not None else proposed_at
    prev_done = _epoch(previous.one(8))
    err_created = _epoch(next_error.one(1))
    require(proposed_at <= prev_ready <= prev_done <= err_created, 'native_step_time_mismatch')

    # Discarded proposal MUST NOT carry a tool result payload (field 2).
    generic_raw = proposal.one(140)
    if generic_raw is not None:
        generic = Fields(generic_raw, {1, 2})
        require(generic.one(2) is None, 'native_tool_lifecycle_unverified')

    # Closing error step must contain an error body.
    require(error.one(24) is not None, 'native_tool_lifecycle_unverified')

    # Generation metadata must prove the invocation failed with an error and covers [index-1..index+1].
    execution, generation = keys[0]
    gm_rows = db.execute('SELECT substr(data,1,?) FROM gen_metadata WHERE idx=? LIMIT 2',
                         (MAX_BLOB + 1, generation)).fetchall()
    require(len(gm_rows) == 1, 'native_invocations_mismatch')
    record = Fields(gm_rows[0][0], {2, 4, 5})
    require(record.one(4) == execution and bool(record.one(5)), 'native_invocations_mismatch')
    indices_raw = record.one(2, default=b'')
    offset = 0
    gen_steps = []
    while offset < len(indices_raw):
        val, offset = _varint(indices_raw, offset)
        gen_steps.append(val)
    require(index - 1 in gen_steps and index in gen_steps and index + 1 in gen_steps,
            'native_invocations_mismatch')
    return bytes(call_id)


def verify_discarded_proposals(db, pending_indices, *, paired, manifest_indices):
    """Validate every non-tail PENDING tool step and ensure paired logs agree on omission."""
    if not pending_indices:
        return {}
    require(paired, 'native_transcript_incomplete')
    for table in ('steps', 'gen_metadata'):
        key = [row[1:3] for row in db.execute('PRAGMA table_info(' + table + ')') if row[5]]
        require(key == [('idx', 'INTEGER')], 'native_format_unverified')
    discarded = {}
    for index in pending_indices:
        require(index not in manifest_indices, 'native_tool_lifecycle_unverified')
        require((index - 1) in manifest_indices and (index + 1) in manifest_indices,
                'native_transcript_incomplete')
        call_id = verify_discarded_proposal(db, index)
        require(call_id not in discarded, 'native_tool_lifecycle_unverified')
        discarded[call_id] = index
    return discarded


def check_call_position(discarded, index, kind, meta, payload):
    """Ensure a discarded proposal's call_id never appears at any other step."""
    if not discarded or kind not in (15, 132):
        return
    if kind == 15:
        slot = payload.one(20)
        calls = Fields(slot, {7}).many(7) if slot is not None else ()
    else:
        call = meta.one(4)
        calls = (call,) if call is not None else ()
    for call in calls:
        call_id = Fields(call, {1}).one(1)
        if call_id is not None and len(call_id) <= 255 and bytes(call_id) in discarded:
            owner = discarded[bytes(call_id)]
            expected = owner - 1 if kind == 15 else owner
            require(index == expected, 'native_tool_lifecycle_unverified')


def verify_closed_executors(db, exec_ends, exec_statuses, step_completions, error_steps_by_exec, *, require_explicit_stop=False):
    """Verify completed executors end on a terminal reply and no error finishes after final reply."""
    for exec_id, status in exec_statuses.items():
        if status != 4:
            # Non-4 errored executors (e.g. status=1 with field 12 error string) are verified by _executors.
            continue
        end_idx = exec_ends[exec_id]
        rows = db.execute(
            'SELECT step_type,status,substr(step_payload,1,?) FROM steps WHERE idx=? LIMIT 2',
            (MAX_BLOB + 1, end_idx),
        ).fetchall()
        require(len(rows) == 1, 'native_snapshot_not_committed')
        step_type, step_status, raw_payload = rows[0]
        if step_type == 15 and step_status == 3:
            # Non-compacted completed executor must terminate cleanly (no pending calls,
            # visible reply, and stop_reason == 2 whenever present or required after discarded gaps).
            response = Fields(Fields(raw_payload, {20}).one(20), {1, 7, 8, 12})
            stop_reason = response.one(12, 0)
            valid_stop = (stop_reason == 2) if (require_explicit_stop or stop_reason is not None) else True
            require(valid_stop and not response.many(7)
                    and bool(response.one(8, default=response.one(1))),
                    'native_snapshot_not_committed')
        elif step_type == 15 and step_status == 5:
            # Checkpoint-compacted final PLANNER_RESPONSE already verified via dual-track transcript match.
            pass
        elif step_type == 23 and step_status == 3 and end_idx > 0:
            # CHECKPOINT step directly closing a committed (or compacted) PLANNER_RESPONSE.
            prev = db.execute(
                'SELECT step_type,status FROM steps WHERE idx=? LIMIT 2', (end_idx - 1,)
            ).fetchall()
            require(len(prev) == 1 and prev[0][0] == 15 and prev[0][1] in (3, 5),
                    'native_snapshot_not_committed')
        else:
            require(False, 'native_snapshot_not_committed')

        final_completed = step_completions[end_idx]
        for err_idx in error_steps_by_exec.get(exec_id, ()):
            require(step_completions[err_idx] <= final_completed, 'native_step_time_mismatch')
