"""Evidence for non-public events emitted by Antigravity Desktop 2.33.0."""

from hashlib import sha256
import json
from pathlib import PurePosixPath
import unicodedata

from .agent_history_antigravity_native import Fields, _epoch, _uuid, require


TOOL_REASON = 'native_tool_lifecycle_unverified'
RELATION_REASON = 'native_parent_history_unverified'
TYPE_URL = b'type.googleapis.com/exa.cortex.core.tools.'

# The concrete Any descriptor and the argument slots both come from the local
# desktop implementation. Opaque result text, URLs and render data are never
# projected, fetched or interpreted as instructions.
BUILTINS = {
    b'write_file': (b'FileEdit', {'Path', 'Content'}, {'Overwrite'}),
    b'edit_file': (b'FileEdit', {'Path', 'Target', 'Replacement'}, set()),
    b'search_web': (b'SearchWeb', {'query'}, {'domain'}),
    b'manage_task': (b'ManageTask', {'Action', 'TaskId'}, set()),
    b'invoke_subagent': (b'InvokeSubagent', {'Model', 'Prompt', 'Role', 'TypeName'}, set()),
    b'manage_subagents': (b'ManageSubagents', {'Action'}, set()),
}


def _unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, TOOL_REASON)
        value[key] = item
    return value


def _call_arguments(call, *, bool_keys=()):
    raw = call.one(3)
    require(raw and call.one(1) and len(call.one(1)) <= 512, TOOL_REASON)
    try:
        arguments = json.loads(bytes(raw).decode('utf8'), object_pairs_hook=_unique)
        require(isinstance(arguments, dict) and all(
            type(v) is (bool if k in bool_keys else str) for k, v in arguments.items()), TOOL_REASON)
        return {k: (v.encode('utf8') if isinstance(v, str) else b'true' if v else b'false')
                for k, v in arguments.items()}
    except (ValueError, RecursionError, UnicodeError):
        require(False, TOOL_REASON)


def verified_arguments(name, call_raw, generic_raw, required, optional=(), *, bool_keys=()):
    """Authenticate native ChatToolCall arguments against the typed generic step's argument map."""
    call = Fields(call_raw, {1, 2, 3, 9}, allowed={1, 2, 3, 7, 9})
    require(call.one(2) == name and call.one(9, default=name) == name, TOOL_REASON)
    args = _call_arguments(call, bool_keys=bool_keys)
    require(set(required) <= args.keys() <= set(required).union(optional), TOOL_REASON)
    generic = Fields(generic_raw, {1, 2}, allowed={1, 2})
    copied = {}
    for pair in generic.many(1):
        entry = Fields(pair, {1, 2}, allowed={1, 2})
        key, value = entry.one(1), entry.one(2)
        require(key is not None and len(key) <= 32 and value is not None, TOOL_REASON)
        require(key not in copied, TOOL_REASON)
        copied[bytes(key)] = value
    require(copied == {k.encode('ascii'): v for k, v in args.items()}, TOOL_REASON)
    return args, generic.one(2)


def builtin(name, call_raw, raw, status, events, index, *, artifact_roots=()):
    descriptor, required, optional = BUILTINS[name]
    args, result_raw = verified_arguments(name, call_raw, raw, required, optional, bool_keys=('Overwrite',))
    if status == 1:
        # The caller must separately prove an unexecuted proposal's terminal
        # generation failure. A type name without this proof cannot admit it.
        require(result_raw is None and name == b'write_file', TOOL_REASON)
        return
    require(status == 3, TOOL_REASON)
    result = Fields(result_raw, {6}, allowed={1, 3, 6, 7})
    any_result = Fields(result.one(6), {1, 2}, allowed={1, 2})
    require(any_result.one(1) == TYPE_URL + descriptor, TOOL_REASON)
    payload = any_result.one(2)
    if descriptor == b'FileEdit':
        edit = Fields(payload, {1, 2, 6}, allowed={1, 2, 3, 4, 6})
        require(edit.one(1, 0) in ((1, 2) if name == b'write_file' else (3,))
                and edit.one(2) == args['Path'], TOOL_REASON)
        if edit.one(6, 0) is not None:
            path = PurePosixPath(args['Path'].decode('utf-8'))
            # The action may target this conversation or its verified direct
            # parent. This check authenticates the event and never opens a file.
            private = any(unicodedata.normalize('NFC', part).casefold() == '.system_generated'
                          for part in path.parts)
            require(edit.one(6, 0) == 1 and name == b'write_file' and '..' not in path.parts
                    and not private and any(
                        root in path.parents for root in artifact_roots), TOOL_REASON)
    elif descriptor == b'SearchWeb':
        query = Fields(payload, {1, 2}, allowed={1, 2, 3, 4, 5})
        require(query.one(1) == args['query'] and query.one(2) == args.get('domain'), TOOL_REASON)
    elif descriptor == b'ManageTask':
        task = Fields(payload, {1, 2}, allowed={1, 2})
        require(args['Action'] == b'kill' and task.one(1) == b'kill' and task.one(2) == args['TaskId']
                and events is not None and args['TaskId'] in events.tasks, TOOL_REASON)
    elif descriptor == b'InvokeSubagent':
        invoke = Fields(payload, {1, 2}, allowed={1, 2})
        spec = Fields(invoke.one(1), {1, 2, 3, 4, 7, 12}, allowed={1, 2, 3, 4, 7, 12})
        require(all(spec.one(n) == args[key] for n, key in ((1, 'TypeName'), (2, 'Role'), (3, 'Prompt'), (12, 'Model')))
                and spec.one(4, 0) == 1 and spec.one(7, 0) is not None, TOOL_REASON)
        child = _uuid(Fields(invoke.one(2), {1}, allowed={1, 2, 3}).one(1))
        require(events is not None and child != events.cascade and child not in events.spawns, RELATION_REASON)
        events.spawns[child] = (index, sha256(call_raw).hexdigest())
    else:
        listing = Fields(payload, {1, 2, 3}, allowed={1, 2, 3})
        require(args['Action'] == b'list' and listing.one(1) == b'list' and events is not None, RELATION_REASON)
        children = tuple(_uuid(v) for v in listing.many(2))
        progress = [Fields(v, {1, 2}, allowed={1, 2}) for v in listing.many(3)]
        require(len(children) == len(set(children)) and all(v in events.spawns for v in children)
                and children == tuple(_uuid(v.one(1)) for v in progress)
                and all(v.one(2, 0) is not None for v in progress), RELATION_REASON)


class NativeEvents:
    def __init__(self, cascade, *, artifact_roots=()):
        self.cascade = cascade
        self.artifact_roots = artifact_roots
        self.tasks = {}
        self.closed_tasks = set()
        self.spawns = {}
        self.relations = []
        self.received = set()
        self.system_ids = set()
        self.errors = {}

    def background_task(self, index, execution, call, raw, created, completed):
        details = Fields(raw, {1, 8}, allowed={1, 2, 3, 4, 7, 8})
        task = (self.cascade + '/task-' + str(index)).encode('ascii')
        require(details.one(1) == task and created <= _epoch(details.one(8)) <= completed, TOOL_REASON)
        self.tasks[task] = (index, execution, sha256(call).digest(), completed)

    def system(self, raw, index, execution, when, completed):
        item = Fields(raw, {1, 2, 3, 4}, allowed={1, 2, 3, 4})
        kind = item.one(3)
        require(kind in (b'task_notification', b'agent_message') and item.one(1) is not None, RELATION_REASON)
        render = Fields(item.one(2), {4}, allowed={1, 4, 10})
        agent = Fields(item.one(4), {1, 2, 3, 4, 6, 10, 11, 12}, allowed={1, 2, 3, 4, 5, 6, 10, 11, 12})
        message_id = _uuid(agent.one(1))
        require(message_id not in self.system_ids, RELATION_REASON)
        require(_uuid(agent.one(2)) == self.cascade and _epoch(agent.one(6)) <= when, RELATION_REASON)
        Fields(agent.one(10), set(), allowed={1})
        metadata = Fields(agent.one(12), {1}, allowed={1})
        source = Fields(metadata.one(1), {1, 2, 3}, allowed={1, 2, 3})
        original = _uuid(source.one(1))
        position = source.one(2, 0, 0)
        raw_call = source.one(3)
        call = Fields(raw_call, {1, 2, 3, 9}, allowed={1, 2, 3, 7, 9})
        sender = agent.one(3)
        require(sender is not None and 0 < len(sender) <= 80, RELATION_REASON)
        if kind == b'task_notification':
            task = bytes(sender)
            require(original == self.cascade and task in self.tasks and task not in self.closed_tasks
                    and render.one(4, 0) == 1 and agent.one(11, 0) == 1, RELATION_REASON)
            at, owner, digest, terminal = self.tasks[task]
            require(call.one(2) == b'run_command' and position == at < index and owner == execution
                    and digest == sha256(raw_call).digest() and terminal <= when, RELATION_REASON)
            self.closed_tasks.add(task)
        else:
            require(_uuid(sender) == original and original in self.spawns and self.spawns[original][0] < index
                    and render.one(4, 0, 0) == agent.one(11, 0, 0) == 0
                    and call.one(2) == call.one(9, default=b'send_message') == b'send_message', RELATION_REASON)
            args = _call_arguments(call)
            require(args.keys() == {'Recipient', 'Message'} and args['Recipient'] == self.cascade.encode('ascii')
                    and agent.one(4) == args['Message'], RELATION_REASON)
            receipt = (original, position)
            require(receipt not in self.received, RELATION_REASON)
            self.received.add(receipt)
            spawn_index, spawn_call = self.spawns[original]
            self.relations.append((original, position, sha256(raw_call).hexdigest(), spawn_index, spawn_call, completed))
        self.system_ids.add(message_id)
