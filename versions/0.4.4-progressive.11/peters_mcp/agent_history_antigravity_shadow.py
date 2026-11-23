"""Metadata-only, operator-pinned Antigravity Hook observations.

The HMAC ledger establishes observation integrity. Hook sampling does not prove
continuous workspace membership and this module never issues history grants.
"""

from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from .agent_history_antigravity import ID_PATTERN, INDEX, _workspace_paths
from .agent_history_source import SourceRoot, _identity, _stamp
from .catalog import AccessError

EVENTS = frozenset({'SessionStart', 'PreInvocation', 'PostInvocation', 'Stop'})
CONFIG_BYTES = 32 * 1024
PAYLOAD_BYTES = 1024 * 1024
LEDGER_BYTES = 4 * 1024 * 1024
TRANSCRIPT_BYTES = 64 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}')


def _closed():
    return AccessError('The private Hook observation could not be verified.', code='shadow_evidence_unavailable')


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _private(info, *, directory=False):
    return (info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))


def _inside(left, right):
    return left.is_relative_to(right) or right.is_relative_to(left)


def _pin(value):
    if (not isinstance(value, list) or len(value) != 3 or any(type(v) is not int or v < 0 for v in value[:2])
            or value[2] is not None and (type(value[2]) not in (int, float) or not math.isfinite(value[2]) or value[2] < 0)):
        raise _closed()
    return tuple(value)


def _root(path, identity):
    if not isinstance(path, str) or not Path(path).is_absolute() or '..' in Path(path).parts:
        raise _closed()
    return SourceRoot(path, expected_identity=_pin(identity))


@dataclass(frozen=True)
class ShadowConfig:
    source_instance_id: str
    epoch: str
    profile: SourceRoot
    ledger: SourceRoot
    workspaces: tuple
    key: bytes

    @classmethod
    def load(cls, filename):
        filename = Path(filename)
        try:
            parent = SourceRoot(filename.parent)
            with parent.directory() as descriptor:
                if not _private(os.fstat(descriptor), directory=True):
                    raise _closed()
            with parent.open(filename.name) as stream:
                before = os.fstat(stream.fileno())
                if not _private(before) or before.st_size > CONFIG_BYTES:
                    raise _closed()
                raw = stream.read(CONFIG_BYTES + 1)
                if _stamp(before) != _stamp(os.fstat(stream.fileno())) or len(raw) != before.st_size:
                    raise _closed()
            value = json.loads(raw, object_pairs_hook=_unique)
            keys = {'version', 'source_instance_id', 'epoch', 'product_version', 'profile', 'profile_identity',
                    'ledger', 'ledger_identity', 'workspaces', 'hmac_key'}
            if (not isinstance(value, dict) or value.keys() != keys or type(value['version']) is not int
                    or value['version'] != 1 or value['product_version'] != '2.33.0'
                    or not isinstance(value['source_instance_id'], str) or not NAME.fullmatch(value['source_instance_id'])
                    or not isinstance(value['epoch'], str) or not HEX.fullmatch(value['epoch'])
                    or not isinstance(value['hmac_key'], str) or not HEX.fullmatch(value['hmac_key'])
                    or not isinstance(value['workspaces'], dict) or not 1 <= len(value['workspaces']) <= 8):
                raise _closed()
            profile = _root(value['profile'], value['profile_identity'])
            ledger = _root(value['ledger'], value['ledger_identity'])
            with ledger.directory() as descriptor:
                if not _private(os.fstat(descriptor), directory=True):
                    raise _closed()
            workspaces = tuple(_root(path, identity) for path, identity in value['workspaces'].items())
            protected = (profile.path, ledger.path, filename)
            if any(_inside(workspace.path, path) for workspace in workspaces for path in protected):
                raise _closed()
            if _inside(profile.path, ledger.path) or filename.is_relative_to(profile.path):
                raise _closed()
            return cls(value['source_instance_id'], value['epoch'], profile, ledger, workspaces,
                       bytes.fromhex(value['hmac_key']))
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise _closed() from None


def _path_form(reported, expected):
    if reported == str(expected):
        return 'absolute'
    if reported == expected.as_uri():
        return 'file_uri'
    if expected.is_relative_to(Path.home()) and reported == '~/' + str(expected.relative_to(Path.home())):
        return 'home_relative'
    raise _closed()


def _anchor(profile, relative):
    try:
        with profile.open(relative) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > TRANSCRIPT_BYTES:
                raise _closed()
            digest = hashlib.sha256()
            committed_digest = digest.hexdigest()
            consumed = committed = rows = 0
            while block := stream.read(min(256 * 1024, before.st_size - consumed)):
                last = block.rfind(b'\n')
                if last >= 0:
                    prefix = digest.copy()
                    prefix.update(block[:last + 1])
                    committed_digest = prefix.hexdigest()
                    committed = consumed + last + 1
                rows += block.count(b'\n')
                digest.update(block)
                consumed += len(block)
            if _stamp(before) != _stamp(os.fstat(stream.fileno())) or consumed != before.st_size:
                raise _closed()
        return {'state': 'present', 'identity': list(_identity(before)), 'committed_bytes': committed,
                'source_revision': committed_digest, 'physical_bytes': consumed, 'complete_rows': rows,
                'partial_tail': committed != consumed}
    except FileNotFoundError:
        return {'state': 'pending'}
    except AccessError as error:
        if error.code == 'source_unavailable':
            return {'state': 'pending'}
        raise


def _index(profile, native_id):
    with profile.sqlite(INDEX) as database:
        if database.execute('PRAGMA user_version').fetchone() != (3,):
            raise _closed()
        row = database.execute(
            '''SELECT substr(project_id,1,37), substr(workspace_uris,1,16385),
                      nesting_depth, substr(parent_conversation_id,1,37)
               FROM conversation_summaries WHERE conversation_id=?''', (native_id,)).fetchone()
        if row is None:
            return {'state': 'pending'}
        project, workspaces, depth, parent = row
        if ((project and (not isinstance(project, str) or not ID_PATTERN.fullmatch(project)))
                or type(depth) is not int or not 0 <= depth <= 32
                or (parent and (not isinstance(parent, str) or not ID_PATTERN.fullmatch(parent)))):
            raise _closed()
        return {'state': 'present', 'native_project_id': project, 'workspaces': list(_workspace_paths(workspaces)),
                'nesting_depth': depth, 'parent_id': parent}


def observe(config, event, payload):
    if event not in EVENTS or not isinstance(payload, dict):
        raise _closed()
    native = payload.get('conversationId')
    paths = payload.get('workspacePaths')
    allowed = {str(workspace.path): workspace for workspace in config.workspaces}
    if (not isinstance(native, str) or not ID_PATTERN.fullmatch(native) or not isinstance(paths, list)
            or not paths or len(paths) > 8 or any(not isinstance(path, str) or path not in allowed for path in paths)
            or len(set(paths)) != len(paths)):
        raise _closed()
    with config.profile.directory():
        pass
    for path in paths:
        with allowed[path].directory():
            pass
    base = config.profile.path / 'brain' / native
    log_directory = base / '.system_generated' / 'logs'
    transcript = log_directory / 'transcript_full.jsonl'
    try:
        reported_form = _path_form(payload.get('transcriptPath'), transcript)
    except AccessError:
        transcript = log_directory / 'transcript.jsonl'
        reported_form = _path_form(payload.get('transcriptPath'), transcript)
    row = {'version': 1, 'purpose': 'shadow_only', 'source_instance_id': config.source_instance_id,
           'epoch': config.epoch, 'product_version': '2.33.0', 'event': event,
           'time_ns': time.time_ns(), 'conversation_id': native, 'workspaces': sorted(paths),
           'reported_transcript_form': reported_form,
           'reported_artifact_form': _path_form(payload.get('artifactDirectoryPath'), base),
           'profile_identity': list(config.profile.identity),
           'transcript': _anchor(config.profile, str(transcript.relative_to(config.profile.path))),
           'index': _index(config.profile, native)}
    for name in ('invocationNum', 'initialNumSteps', 'executionNum'):
        if name in payload:
            number = payload[name]
            if type(number) is not int or not 0 <= number <= 1_000_000:
                raise _closed()
            row[name] = number
    if event == 'Stop':
        if type(payload.get('fullyIdle')) is not bool:
            raise _closed()
        row['fullyIdle'] = payload['fullyIdle']
    return row


def _signature(config, value):
    return hmac.new(config.key, _json(value), hashlib.sha256).hexdigest()


def _observation(config, observation):
    required = {'version', 'purpose', 'source_instance_id', 'epoch', 'product_version', 'event', 'time_ns',
                'conversation_id', 'workspaces', 'reported_transcript_form', 'reported_artifact_form',
                'profile_identity', 'transcript', 'index'}
    optional = {'invocationNum', 'initialNumSteps', 'executionNum', 'fullyIdle'}
    if (not isinstance(observation, dict) or not required <= observation.keys()
            or observation.keys() - required - optional or type(observation['version']) is not int
            or observation['version'] != 1
            or observation['purpose'] != 'shadow_only' or observation['source_instance_id'] != config.source_instance_id
            or observation['epoch'] != config.epoch or observation['product_version'] != '2.33.0'
            or observation['event'] not in EVENTS or type(observation['time_ns']) is not int
            or not isinstance(observation['conversation_id'], str) or not ID_PATTERN.fullmatch(observation['conversation_id'])
            or observation['profile_identity'] != list(config.profile.identity)
            or not isinstance(observation['workspaces'], list) or not 1 <= len(observation['workspaces']) <= 8
            or any(not isinstance(path,str) or path not in {str(root.path) for root in config.workspaces}
                   for path in observation['workspaces'])
            or any(observation[key] not in {'absolute', 'file_uri', 'home_relative'}
                   for key in ('reported_transcript_form', 'reported_artifact_form'))):
        raise _closed()
    anchor = observation['transcript']
    index = observation['index']
    if not isinstance(anchor, dict) or not isinstance(index, dict):
        raise _closed()
    if anchor.get('state') == 'pending':
        if anchor.keys() != {'state'}:
            raise _closed()
    elif (anchor.keys() != {'state', 'identity', 'committed_bytes', 'source_revision', 'physical_bytes', 'complete_rows', 'partial_tail'}
          or anchor['state'] != 'present' or not isinstance(anchor['source_revision'], str)
          or not HEX.fullmatch(anchor['source_revision']) or _pin(anchor['identity']) != tuple(anchor['identity'])
          or any(type(anchor[k]) is not int or anchor[k] < 0 for k in ('committed_bytes', 'physical_bytes', 'complete_rows'))
          or not anchor['committed_bytes'] <= anchor['physical_bytes'] <= TRANSCRIPT_BYTES
          or type(anchor['partial_tail']) is not bool):
        raise _closed()
    if index.get('state') == 'pending':
        if index.keys() != {'state'}:
            raise _closed()
    elif (index.keys() != {'state', 'native_project_id', 'workspaces', 'nesting_depth', 'parent_id'}
          or index['state'] != 'present' or not isinstance(index['workspaces'], list)
          or any(not isinstance(path, str) or not path.startswith('/') or len(path) > 4096 for path in index['workspaces'])
          or type(index['nesting_depth']) is not int or not 0 <= index['nesting_depth'] <= 32
          or any(not isinstance(index[key], str) or index[key] and not ID_PATTERN.fullmatch(index[key])
                 for key in ('native_project_id', 'parent_id'))):
        raise _closed()
    for key in ('invocationNum', 'initialNumSteps', 'executionNum'):
        if key in observation and (type(observation[key]) is not int or not 0 <= observation[key] <= 1_000_000):
            raise _closed()
    if ('fullyIdle' in observation and type(observation['fullyIdle']) is not bool
            or observation['event'] == 'Stop' and 'fullyIdle' not in observation):
        raise _closed()


def _records(config, raw):
    if len(raw) > LEDGER_BYTES or raw and not raw.endswith(b'\n'):
        raise _closed()
    rows = []
    previous = '0' * 64
    for line in raw.splitlines():
        value = json.loads(line, object_pairs_hook=_unique)
        if not isinstance(value, dict) or value.keys() != {'sequence', 'previous', 'observation', 'signature'}:
            raise _closed()
        signature = value['signature']
        signed = {name: value[name] for name in ('sequence', 'previous', 'observation')}
        observation = value['observation']
        if (type(value['sequence']) is not int or value['sequence'] != len(rows)
                or value['previous'] != previous or not isinstance(signature, str)
                or not HEX.fullmatch(signature) or not hmac.compare_digest(signature, _signature(config, signed))
                or not isinstance(observation, dict) or observation.get('purpose') != 'shadow_only'
                or observation.get('source_instance_id') != config.source_instance_id
                or observation.get('epoch') != config.epoch):
            raise _closed()
        _observation(config, observation)
        rows.append(value)
        previous = hashlib.sha256(line).hexdigest()
    return rows, previous


@contextmanager
def _ledger_file(config, *, write=False):
    with config.ledger.directory() as directory:
        if not _private(os.fstat(directory), directory=True):
            raise _closed()
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT if write else os.O_RDONLY)
        descriptor = os.open('observations.jsonl', flags, 0o600, dir_fd=directory)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            info = os.fstat(descriptor)
            if not _private(info) or info.st_size > LEDGER_BYTES:
                raise _closed()
            yield descriptor
            current = os.stat('observations.jsonl', dir_fd=directory, follow_symlinks=False)
            if _identity(current) != _identity(info) or not _private(current):
                raise _closed()
        finally:
            os.close(descriptor)


def append_observation(config, observation):
    _observation(config, observation)
    with _ledger_file(config, write=True) as descriptor:
        raw = os.read(descriptor, LEDGER_BYTES + 1)
        records, previous = _records(config, raw)
        value = {'sequence': len(records), 'previous': previous, 'observation': observation}
        line = _json({**value, 'signature': _signature(config, value)}) + b'\n'
        if len(raw) + len(line) > LEDGER_BYTES:
            raise _closed()
        os.lseek(descriptor, 0, os.SEEK_END)
        remaining = memoryview(line)
        while remaining:
            written = os.write(descriptor, remaining)
            if not written:
                raise _closed()
            remaining = remaining[written:]
        os.fsync(descriptor)


def verify_shadow(config):
    with _ledger_file(config) as descriptor:
        records, _ = _records(config, os.read(descriptor, LEDGER_BYTES + 1))
    return tuple(record['observation'] for record in records)


def _invocation_issues(samples):
    issues = set()
    if samples[0]['event'] != 'SessionStart' or sum(row['event'] == 'SessionStart' for row in samples) != 1:
        issues.add('session_start_unobserved_or_repeated')
    pending = None
    next_invocation = 0
    for sample in samples:
        event = sample['event']
        if event == 'Stop' and pending is not None:
            issues.add('invocation_missing_or_unpaired')
        if event not in {'PreInvocation', 'PostInvocation'}:
            continue
        number = sample.get('invocationNum')
        steps = sample.get('initialNumSteps')
        if number is None or steps is None:
            issues.add('invocation_counters_missing')
        if event == 'PreInvocation':
            if pending is not None or number != next_invocation:
                issues.add('invocation_missing_or_unpaired')
            pending = (number, steps)
        else:
            if pending != (number, steps) or number != next_invocation:
                issues.add('invocation_missing_or_unpaired')
            pending = None
            next_invocation += 1
    if pending is not None or next_invocation == 0:
        issues.add('invocation_missing_or_unpaired')
    if samples[-1]['event'] != 'Stop' or not samples[-1]['fullyIdle']:
        issues.add('idle_stop_not_observed_at_end')
    return issues


def _sample_issues(samples):
    issues = _invocation_issues(samples)
    if len({tuple(sorted(sample['workspaces'])) for sample in samples}) > 1:
        issues.add('workspace_change_sampled')
    lineages = set()
    previous_anchors = {}
    for sample in samples:
        index = sample['index']
        if index['state'] == 'pending':
            issues.add('index_pending_at_observation')
        else:
            if sorted(index['workspaces']) != sorted(sample['workspaces']):
                issues.add('workspace_sample_differs_from_index')
            lineages.add((index['native_project_id'], index['nesting_depth'], index['parent_id']))
            if index['parent_id'] or index['nesting_depth']:
                issues.add('parent_history_requires_separate_evidence')

        anchor = sample['transcript']
        if anchor['state'] == 'pending':
            issues.add('transcript_pending_at_observation')
            continue
        if anchor['partial_tail']:
            issues.add('transcript_partial_tail_sampled')
        identity = tuple(anchor['identity'])
        previous = previous_anchors.get(identity)
        if previous is not None:
            if (anchor['committed_bytes'] < previous['committed_bytes']
                    or anchor['complete_rows'] < previous['complete_rows']):
                issues.add('transcript_commit_rewind_sampled')
            if (anchor['committed_bytes'] == previous['committed_bytes']
                    and anchor['source_revision'] != previous['source_revision']):
                issues.add('transcript_commit_rewrite_sampled')
        previous_anchors[identity] = anchor
    if len(lineages) > 1:
        issues.add('index_lineage_change_sampled')
    if len(previous_anchors) > 1:
        issues.add('transcript_identity_change_sampled')
    return issues


def assess_shadow(config):
    """Summarize observations for a local operator without returning native IDs or paths."""
    observations = verify_shadow(config)
    sessions = defaultdict(list)
    for observation in observations:
        sessions[observation['conversation_id']].append(observation)
    issues = Counter(issue for samples in sessions.values() for issue in _sample_issues(samples))
    return {'state': 'shadow_only', 'observations': len(observations), 'can_authorize_history': False,
            'reason': 'continuous_workspace_membership_unproven', 'sessions': len(sessions),
            'sessions_by_sample_issue': dict(issues)}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--assess':
        try:
            result = assess_shadow(ShadowConfig.load(sys.argv[2]))
        except (OSError, AccessError, ValueError, TypeError, KeyError, RecursionError):
            print('{"state":"unavailable","can_authorize_history":false,"reason":"shadow_evidence_unavailable"}')
            return 1
        print(_json(result).decode('ascii'))
        return 0
    # A collector failure must not inject text or alter the Agent execution loop.
    try:
        if len(sys.argv) != 3:
            raise _closed()
        config, event = ShadowConfig.load(sys.argv[1]), sys.argv[2]
        raw = sys.stdin.buffer.read(PAYLOAD_BYTES + 1)
        if len(raw) > PAYLOAD_BYTES:
            raise _closed()
        payload = json.loads(raw, object_pairs_hook=_unique)
        append_observation(config, observe(config, event, payload))
    except (OSError, AccessError, ValueError, TypeError, KeyError, RecursionError):
        pass
    print('{}')


if __name__ == '__main__':
    sys.exit(main())
