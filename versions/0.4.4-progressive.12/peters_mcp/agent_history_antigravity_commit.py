"""Prove the bounded, discarded-stream shape recorded by Desktop 2.33.0."""
import json

from .agent_history_antigravity_events import _unique
from .agent_history_antigravity_native import Fields, MAX_BLOB, _epoch, _varint, require


def _proposal_arguments(name, raw, generic):
    shapes = {
        b'read_file': {'Path': str, 'StartLine': int, 'EndLine': int},
        b'write_file': {'Content': str, 'Overwrite': bool, 'Path': str},
        b'run_command': {'CommandLine': str, 'WaitMsBeforeAsync': int, 'toolSummary': str},
    }
    try:
        arguments = json.loads(bytes(raw).decode(), object_pairs_hook=_unique)
        shape = shapes[name]
        require(isinstance(arguments, dict) and arguments.keys() == shape.keys(),
                'native_tool_lifecycle_unverified')
        expected = {}
        for key, value in arguments.items():
            require(type(value) is shape[key], 'native_tool_lifecycle_unverified')
            encoded = value.encode() if isinstance(value, str) else json.dumps(value).encode('ascii')
            expected[key.encode('ascii')] = encoded
    except (ValueError, RecursionError, UnicodeError):
        require(False, 'native_tool_lifecycle_unverified')
    present = {}
    for row in generic.many(1):
        entry = Fields(row, {1, 2}, allowed={1, 2})
        key, value = entry.one(1), entry.one(2)
        require(key in expected and key not in present and value is not None,
                'native_tool_lifecycle_unverified')
        present[key] = value
    require(present == expected, 'native_tool_lifecycle_unverified')


def _planned_call(db, index):
    rows = db.execute(
        'SELECT idx,step_type,status,substr(metadata,1,?),substr(step_payload,1,?) '
        'FROM steps WHERE idx BETWEEN ? AND ? ORDER BY idx LIMIT 4',
        (MAX_BLOB + 1, MAX_BLOB + 1, index - 1, index + 1),
    ).fetchall()
    expected = [(index - 1, 15, 3), (index, 132, 1), (index + 1, 17, 3)]
    require([r[:3] for r in rows] == expected, 'native_transcript_incomplete')
    keys = []
    for _, _, _, meta_raw, _ in rows:
        meta = Fields(meta_raw, {12, 20})
        source = Fields(meta.one(20), {3})
        keys.append((meta.one(12), source.one(3, 0, 0)))
    require(keys[0] == keys[1] == keys[2], 'native_execution_mismatch')
    planner, proposal, error = [Fields(r[4], {20, 140, 24}) for r in rows]
    response = Fields(planner.one(20), {1, 7, 8, 12})
    # STOP_REASON_CLIENT_STREAM_ERROR; the generator failed while emitting its
    # requested call. The archive must contain the actual request and its error.
    require(response.one(12, 0) == 18 and not response.one(8, default=response.one(1))
            and len(response.many(7)) == 1, 'native_tool_lifecycle_unverified')
    meta = Fields(rows[1][3], {4, 6, 7, 8, 32, 38})
    call_raw = meta.one(4)
    call = Fields(call_raw, {1, 2, 3, 9}, allowed={1, 2, 3, 7, 9})
    name = call.one(2)
    require(meta.one(38, 0) == 1 and name in (b'read_file', b'write_file', b'run_command')
            and call.one(9, default=name) == name and 0 < len(call.one(1, default=b'')) <= 255
            and response.one(7) == call_raw, 'native_tool_lifecycle_unverified')
    require(meta.one(32) is None and meta.one(8) is None
            and _epoch(meta.one(6)) == _epoch(meta.one(7)), 'native_tool_lifecycle_unverified')
    queued = Fields(Fields(rows[1][3], {26}).one(26), {1}).one(1)
    proposed_at = _epoch(Fields(queued, {2}).one(2))
    previous = Fields(rows[0][3], {7, 8})
    next_error = Fields(rows[2][3], {1})
    require(proposed_at <= _epoch(previous.one(7)) <= _epoch(previous.one(8)) <= _epoch(next_error.one(1)),
            'native_step_time_mismatch')
    # No started_at, completed_at, tool result, nested execution, or background
    # task. The full step shape and the sole PENDING transition are checked by _steps.
    generic = Fields(proposal.one(140), {1}, allowed={1})
    require(call.one(3), 'native_tool_lifecycle_unverified')
    _proposal_arguments(bytes(name), call.one(3), generic)
    error_body = Fields(error.one(24), {3, 4, 5}, allowed={3, 4, 5})
    detail = Fields(error_body.one(3), {2, 6}, allowed={2, 6})
    require(error_body.one(4, 0) == 1 and error_body.one(5, 0, 0) == 0
            and detail.one(2) and detail.one(6), 'native_tool_lifecycle_unverified')
    execution, generation = keys[0]
    rows = db.execute('SELECT substr(data,1,?) FROM gen_metadata WHERE idx=? LIMIT 2',
                      (MAX_BLOB + 1, generation)).fetchall()
    require(len(rows) == 1, 'native_invocations_mismatch')
    record = Fields(rows[0][0], {2, 4, 5})
    require(record.one(4) == execution and record.one(5), 'native_invocations_mismatch')
    indices = record.one(2, default=b'')
    offset = 0
    for wanted in range(index - 1, index + 2):
        actual, offset = _varint(indices, offset)
        require(actual == wanted, 'native_invocations_mismatch')
    require(offset == len(indices), 'native_invocations_mismatch')
    return bytes(call.one(1))


def check_call_position(discarded, index, kind, meta, payload):
    if not discarded or kind not in (15, 132):
        return
    if kind == 15:
        calls = Fields(payload.one(20), {7}).many(7)
    else:
        calls = (meta.one(4),)
    for call in calls:
        call_id = Fields(call, {1}).one(1)
        if call_id is not None and len(call_id) <= 255 and call_id in discarded:
            owner = discarded[call_id]
            expected = owner - 1 if kind == 15 else owner
            require(index == expected, 'native_tool_lifecycle_unverified')


def verify_cancelled_command(meta, raw):
    call = Fields(meta.one(4), {1, 2, 3, 9}, allowed={1, 2, 3, 7, 9})
    require(meta.one(38, 0) == 1 and call.one(2) == b'run_command'
            and call.one(9, default=b'run_command') == b'run_command'
            and call.one(1) and call.one(3), 'native_tool_lifecycle_unverified')
    require(_epoch(meta.one(7)) <= _epoch(meta.one(32)) <= _epoch(meta.one(8)),
            'native_step_time_mismatch')
    generic = Fields(raw, {1, 2}, allowed={1, 2})
    _proposal_arguments(b'run_command', call.one(3), generic)
    # A cancelled command retained only local render data. No result payload,
    # links or attachments are followed. Its typed task notification is required.
    result = Fields(generic.one(2), {3}, allowed={3})
    Fields(result.one(3), set(), allowed={5, 6, 7, 9, 10})


def _final_reply(db, last):
    rows = db.execute(
        'SELECT step_type,status,substr(step_payload,1,?) FROM steps WHERE idx=? LIMIT 2',
        (MAX_BLOB + 1, last),
    ).fetchall()
    require(len(rows) == 1 and rows[0][:2] == (15, 3), 'native_snapshot_not_committed')
    response = Fields(Fields(rows[0][2], {20}).one(20), {1, 7, 8, 12})
    require(response.one(12, 0) == 2 and not response.many(7)
            and response.one(8, default=response.one(1)), 'native_snapshot_not_committed')


def align_manifest(db, manifest, count, busy, paired):
    """Align every native step with both transcripts or a proved failed proposal."""
    need_pair = any(row[3] == 'RUNNING' for row in manifest)
    if len(manifest) == count and not need_pair:
        require(not busy, 'native_snapshot_not_committed')
        return manifest, {}
    require(paired and 0 < len(manifest) <= count and manifest[0][0] == 0
            and manifest[-1][0] == count - 1, 'native_transcript_incomplete')
    aligned = [None] * count
    for row in manifest:
        index = row[0]
        require(0 <= index < count and aligned[index] is None, 'native_step_sequence_mismatch')
        aligned[index] = row
    gaps = [i for i, row in enumerate(aligned) if row is None]
    require(not busy or gaps, 'native_snapshot_not_committed')
    for table in ('steps', 'gen_metadata'):
        # Bound the per-gap lookups to the primary key of the native table.
        key = [row[1:3] for row in db.execute('PRAGMA table_info(' + table + ')') if row[5]]
        require(key == [('idx', 'INTEGER')], 'native_format_unverified')
    discarded = {}
    for index in gaps:
        require(aligned[index - 1] is not None and aligned[index + 1] is not None,
                'native_transcript_incomplete')
        call_id = _planned_call(db, index)
        require(call_id not in discarded, 'native_tool_lifecycle_unverified')
        discarded[call_id] = index
    # The closed executor must have stopped without asking for any further
    # tool. Its step range, execution identity and generation accounting
    # are independently matched to every stored row by the normal verifier.
    for row, in db.execute('SELECT substr(data,1,?) FROM executor_metadata ORDER BY idx LIMIT ?',
                           (MAX_BLOB + 1, count + 1)):
        end = Fields(row, {1, 3})
        require(end.one(1, 0) == 4, 'native_snapshot_not_committed')
        _final_reply(db, end.one(3, 0, 0))
    return aligned, discarded
