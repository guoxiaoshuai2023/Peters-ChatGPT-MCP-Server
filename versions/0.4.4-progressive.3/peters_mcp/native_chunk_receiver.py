"""Same-plan receiver for actual native files; no network or source execution.

Only verified package code is imported by the native caller. This module checks
local bytes and ownership, not remote authorization or client receipt. Source
expiry does not destroy already received files. New plans never repair an old
session, and publication uses a same-filesystem, no-clobber hard link only.
"""
from contextlib import contextmanager
from functools import wraps
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat

PROTOCOL = 'raw-parts-v1'
PART_BYTES = 8_000_000
MAX_BYTES = 100_000_000
MAX_PARTS = 13
BLOCK = 64 * 1024
PLAN_LIMIT = 64 * 1024
LEDGER_LIMIT = 128 * 1024
MIN_FREE_BYTES = 1024 * 1024 * 1024
CONTROL_RESERVE = 1024 * 1024
ASSET_ID = 'native-chunk-receiver-v1'
ASSET_NAME = 'native_chunk_receiver.py'
MARKER = 'peters-native-chunk-receiver-v1'
PREFIX = '.native-chunk-'
_PLAN_KEYS = {'protocol_version', 'service_instance_id', 'export_id', 'source',
              'capture_version_sha256', 'total_bytes', 'total_sha256',
              'part_max_bytes', 'part_count', 'parts', 'receiver_asset',
              'expires_at_unix', 'plan_sha256'}
_LEDGER_KEYS = {'version', 'marker', 'nonce', 'plan', 'target_name',
                'output_identity', 'session_identity', 'input_root', 'input_identity',
                'file_identities', 'accepted', 'next_index', 'durable_offset',
                'pending', 'state', 'publication', 'temp_removed', 'cleanup_pending'}


class ReceiverError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ReceiverError(code)


def _safe_os(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except OSError as error:
            failure = ReceiverError('insufficient_space' if error.errno == errno.ENOSPC else 'local_io_failed')
            if hasattr(error, 'preflight'):
                failure.preflight = error.preflight
            raise failure from error
        except (TypeError, ValueError, KeyError, UnicodeError, OverflowError) as error:
            failure = ReceiverError('invalid_receiver_input')
            if hasattr(error, 'preflight'):
                failure.preflight = error.preflight
            raise failure from error
    return call


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, OverflowError, RecursionError):
        _fail('invalid_json')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('duplicate_json_key')
        result[key] = value
    return result


def _parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _value: _fail('invalid_json'))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail('invalid_json')


def _integer(value, minimum=0, maximum=MAX_BYTES):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('invalid_integer')
    return value


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        _fail('invalid_sha256')
    return value


def _text(value, maximum):
    try:
        length = len(value.encode('utf-8')) if isinstance(value, str) else maximum + 1
    except UnicodeError:
        _fail('invalid_text')
    if (not isinstance(value, str) or not value or length > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _fail('invalid_text')
    return value


def _name(value):
    _text(value, 240)
    if value in ('.', '..') or '/' in value or '\\' in value:
        _fail('invalid_filename')
    return value


def normalize_plan(value):
    """Validate the exact metadata contract without acquiring any source right."""
    if not isinstance(value, dict) or set(value) != _PLAN_KEYS:
        _fail('invalid_plan')
    raw = canonical(value)
    if len(raw) > PLAN_LIMIT:
        _fail('plan_too_large')
    if value['protocol_version'] != PROTOCOL:
        _fail('unsupported_protocol')
    for key in ('service_instance_id', 'export_id'):
        if not isinstance(value[key], str) or re.fullmatch('[a-f0-9]{32}', value[key]) is None:
            _fail('invalid_plan_identifier')
    source = value['source']
    if not isinstance(source, dict) or set(source) != {'project_id', 'worktree_id', 'path'}:
        _fail('invalid_source')
    for key in ('project_id', 'worktree_id'):
        _text(source[key], 128)
    path = _text(source['path'], 4096)
    if (PurePosixPath(path).is_absolute() or '\\' in path or str(PurePosixPath(path)) != path
            or any(part in ('', '.', '..') for part in path.split('/'))):
        _fail('invalid_source')
    _sha(value['capture_version_sha256'])
    total = _integer(value['total_bytes'])
    _sha(value['total_sha256'])
    if _integer(value['part_max_bytes']) != PART_BYTES:
        _fail('invalid_part_size')
    count = max(1, (total + PART_BYTES - 1) // PART_BYTES)
    if _integer(value['part_count'], 1, MAX_PARTS) != count:
        _fail('invalid_part_count')
    parts = value['parts']
    if not isinstance(parts, list) or len(parts) != count:
        _fail('invalid_parts')
    names = set()
    for index, part in enumerate(parts):
        if not isinstance(part, dict) or set(part) != {'index', 'offset', 'bytes', 'sha256', 'resource_name'}:
            _fail('invalid_part')
        if (_integer(part['index'], 0, MAX_PARTS - 1) != index
                or _integer(part['offset']) != index * PART_BYTES
                or _integer(part['bytes'], 0, PART_BYTES) != min(PART_BYTES, total - index * PART_BYTES)):
            _fail('invalid_part_geometry')
        _sha(part['sha256'])
        name = _name(part['resource_name'])
        if name in names:
            _fail('duplicate_part_name')
        names.add(name)
    if total == 0 and (parts[0]['sha256'] != hashlib.sha256(b'').hexdigest()
                       or value['total_sha256'] != hashlib.sha256(b'').hexdigest()):
        _fail('invalid_empty_hash')
    asset = value['receiver_asset']
    if (not isinstance(asset, dict) or set(asset) != {'asset_id', 'name', 'bytes', 'sha256'}
            or asset['asset_id'] != ASSET_ID or asset['name'] != ASSET_NAME):
        _fail('invalid_receiver_asset')
    _integer(asset['bytes'], 1, PLAN_LIMIT)
    _sha(asset['sha256'])
    _integer(value['expires_at_unix'], 1, 2**53 - 1)
    digest = _sha(value['plan_sha256'])
    expected = hashlib.sha256(canonical({k: v for k, v in value.items() if k != 'plan_sha256'})).hexdigest()
    if digest != expected:
        _fail('plan_hash_mismatch')
    # A detached copy prevents callers mutating the accepted in-memory plan.
    return _parse(raw)


def parse_plan(raw):
    """Read exact JSON text with duplicate-key checks before normalization."""
    if not isinstance(raw, (bytes, str)):
        _fail('invalid_plan')
    try:
        size = len(raw.encode('utf-8')) if isinstance(raw, str) else len(raw)
    except UnicodeError:
        _fail('invalid_json')
    if size > PLAN_LIMIT:
        _fail('plan_too_large')
    return normalize_plan(_parse(raw))


def _identity(info):
    return [info.st_dev, info.st_ino]


def _version(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def _received_stamp(info):
    # atime may legitimately change when the file is read.
    return (*_version(info), info.st_uid, info.st_gid, info.st_mode)


def _received_policy(info):
    forbidden = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (os.getuid(), 0) or info.st_mode & forbidden):
        _fail('unsafe_file')


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        _fail('descriptor_close_uncertain')


def _sync(fd, code='durability_pending'):
    try:
        os.fsync(fd)
    except OSError:
        _fail(code)


@contextmanager
def _directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        _fail('unsafe_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                _fail('unsafe_directory')
            old, fd = fd, child
            _close(old)
        yield fd
    finally:
        _close(fd)


def _directory_matches(path, fd):
    with _directory(path) as named:
        if _identity(os.fstat(named)) != _identity(os.fstat(fd)):
            _fail('directory_changed')


def _owned_directory(path, fd, code):
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o700, 0o2700):
        _fail(code)
    _directory_matches(path, fd)


def _preflight_directory_route(path, held, expected):
    view = {'configured_path': str(path), 'held_parent_identity': list(expected),
            'state': 'unknown', 'route_verified': False, 'private_owned': False}
    try:
        info = os.fstat(held)
        if _identity(info) != expected:
            view['error_code'] = 'held_parent_identity_changed'
            return view
        with _directory(path) as current:
            named = os.fstat(current)
            view['observed_parent_identity'] = _identity(named)
            view['state'] = 'verified' if _identity(named) == expected else 'changed'
            view['route_verified'] = view['state'] == 'verified'
            view['private_owned'] = all(item.st_uid == os.getuid()
                and stat.S_IMODE(item.st_mode) in (0o700, 0o2700) for item in (info, named))
    except (OSError, ReceiverError) as error:
        view['state'], view['route_verified'] = 'unknown', False
        view['error_code'] = getattr(error, 'code', 'directory_route_io_failed')
        if view['error_code'] != 'descriptor_close_uncertain':
            current = error
            for _ in range(12):
                if isinstance(current, OSError):
                    view['errno'] = current.errno
                    if current.errno == errno.ENOENT:
                        view['state'] = 'missing'
                    elif current.errno in (errno.ENOTDIR, errno.ELOOP):
                        view['state'] = 'changed'
                    break
                current = current.__cause__ or current.__context__
                if current is None:
                    break
    return view


def _preflight_snapshot(report, root, session, checkpoint):
    """Observe held entries separately from the current configured routes."""
    parents = {'output_root': root, 'session': session}
    routes = {}
    for location, binding in report['directory_bindings'].items():
        view = _preflight_directory_route(binding['configured_path'], parents[location],
                                          binding['held_parent_identity'])
        routes[location] = view
        if not view['route_verified'] or not view['private_owned']:
            report['identity_uncertain'] = True
        if view.get('error_code') == 'descriptor_close_uncertain':
            report['close_uncertain'] = True
    report['directory_routes'] = routes
    report['route_observations'].append({'checkpoint': checkpoint, 'routes': routes})
    for probe in report['probes']:
        route = routes[probe['location']]
        probe['absolute_path_route'] = dict(route)
        probe['absolute_path_route_verified'] = route['route_verified']
        held = {'observation': 'not_attempted'}
        if probe['attempted']:
            try:
                parent = parents[probe['location']]
                if _identity(os.fstat(parent)) != probe['held_parent_identity']:
                    _fail('held_parent_identity_changed')
                info = _exists(parent, probe['name'])
                if info is None:
                    held['observation'] = 'removed' if probe['cleanup_removed'] else 'missing'
                    if probe['created_confirmed'] and not probe['cleanup_removed']:
                        report['identity_uncertain'] = True
                else:
                    held['observed_identity'] = _identity(info)
                    if (probe['identity'] is None or _identity(info) != probe['identity']
                            or info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)):
                        held['observation'] = 'changed' if probe['identity'] is not None else 'unknown'
                        report['identity_uncertain'] = True
                    else:
                        held['observation'] = 'retained'
                        if probe['cleanup_removed']:
                            report['identity_uncertain'] = True
            except (OSError, ReceiverError) as error:
                held['observation'] = 'unknown'
                held['error_code'] = getattr(error, 'code', 'probe_observation_io_failed')
                held['errno'] = getattr(error, 'errno', None)
                report['identity_uncertain'] = True
        probe['held_parent_entry'] = held
        if route['route_verified'] and route['private_owned']:
            probe['observation'] = held['observation']
        else:
            probe['observation'] = 'absolute_parent_' + (
                route['state'] if not route['route_verified'] else 'unsafe')


@contextmanager
def _start_evidence():
    evidence = {'preflight': None}
    try:
        yield evidence
    except BaseException as error:
        report = evidence['preflight']
        if report is None:
            current = error.__cause__ or error.__context__
            for _ in range(12):
                if current is None:
                    break
                if hasattr(current, 'preflight'):
                    report = current.preflight
                    break
                current = current.__cause__ or current.__context__
        if report is not None and not hasattr(error, 'preflight'):
            report['start_error_after_preflight'] = {
                'type': type(error).__name__, 'code': getattr(error, 'code', None),
                'current_routes': 'not_revalidated_after_error'}
            error.preflight = report
        raise


class _ReceivedLease:
    """One read-only host input, anchored at an already-bound directory FD."""
    def __init__(self, root_path, root, path):
        self.root_path = Path(root_path)
        self.root = root
        self.path = Path(path)
        self.directories = []
        self.fd = None
        self.parent = root
        self.version = None
        self.identity = None
        self.stamp = None

    def open(self):
        if not self.path.is_absolute() or '..' in self.path.parts:
            _fail('unsafe_input_path')
        try:
            relative = self.path.relative_to(self.root_path)
        except ValueError:
            _fail('input_outside_root')
        if not relative.parts:
            _fail('unsafe_input_path')
        _directory_matches(self.root_path, self.root)
        for name in relative.parts[:-1]:
            try:
                child = os.open(_name(name), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.parent)
            except OSError:
                _fail('unsafe_directory')
            self.directories.append((self.parent, name, child, None))
            info = os.fstat(child)
            self.directories[-1] = (self.parent, name, child, _identity(info))
            self.parent = child
        try:
            self.fd = os.open(_name(self.path.name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=self.parent)
        except OSError:
            _fail('file_unavailable')
        info = os.fstat(self.fd)
        _received_policy(info)
        self.version = _version(info)
        self.identity = _identity(info)
        self.stamp = _received_stamp(info)
        self.revalidate()

    def revalidate(self):
        _directory_matches(self.root_path, self.root)
        for parent, name, child, identity in self.directories:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(current.st_mode) or _identity(current) != identity
                    or _identity(os.fstat(child)) != identity):
                _fail('input_changed')
        current = os.fstat(self.fd)
        named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if (_received_stamp(current) != self.stamp or _received_stamp(named) != self.stamp):
            _fail('input_changed')
        _received_policy(current)

    def close(self):
        pending = None
        descriptors = ([self.fd] if self.fd is not None else [])
        self.fd = None
        descriptors += [entry[2] for entry in reversed(self.directories)]
        self.directories = []
        for fd in descriptors:
            try:
                _close(fd)
            except ReceiverError as error:
                pending = pending or error
        if pending is not None:
            raise pending


@contextmanager
def _received_file(root_path, root, path):
    # This entry point never accepts writable flags, private-state or link overrides.
    lease = _ReceivedLease(root_path, root, path)
    try:
        lease.open()
        yield lease
        lease.revalidate()
    finally:
        lease.close()


@contextmanager
def _file(parent, name, *, flags=os.O_RDONLY, identity=None, private=False, links=(1,), unlinking=False):
    try:
        fd = os.open(_name(name), flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except OSError:
        _fail('file_unavailable')
    try:
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink not in links or _identity(info) != _identity(named)
                or identity is not None and _identity(info) != identity
                or private and stat.S_IMODE(info.st_mode) != 0o600):
            _fail('unsafe_file')
        yield fd
        if unlinking:
            if _exists(parent, name) is not None or os.fstat(fd).st_nlink not in (0, 1):
                _fail('file_changed')
        elif _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(os.fstat(fd)):
            _fail('file_changed')
    finally:
        _close(fd)


def _write(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view[:BLOCK])
        if written <= 0:
            _fail('short_write')
        view = view[written:]


def _hash(fd, offset, count):
    before = _version(os.fstat(fd))
    digest, position = hashlib.sha256(), 0
    while position < count:
        block = os.pread(fd, min(BLOCK, count - position), offset + position)
        if not block:
            _fail('short_read')
        digest.update(block)
        position += len(block)
    if _version(os.fstat(fd)) != before:
        _fail('file_changed')
    return digest.hexdigest()


def _copy(source, target, offset, count):
    position = 0
    while position < count:
        block = os.pread(source, min(BLOCK, count - position), position)
        if not block:
            _fail('short_read')
        os.lseek(target, offset + position, os.SEEK_SET)
        _write(target, block)
        position += len(block)


def _exists(parent, name):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _space(root, additional):
    value = os.fstatvfs(root)
    if value.f_bavail * value.f_frsize < additional + CONTROL_RESERVE + MIN_FREE_BYTES:
        _fail('insufficient_space')


def _read_control(session):
    with _file(session, 'ledger.json', private=True) as fd:
        before = _version(os.fstat(fd))
        if before[2] > LEDGER_LIMIT:
            _fail('ledger_too_large')
        chunks, count = [], 0
        while count <= LEDGER_LIMIT:
            block = os.read(fd, min(BLOCK, LEDGER_LIMIT + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
        if count != before[2] or _version(os.fstat(fd)) != before:
            _fail('ledger_changed')
    return _parse(b''.join(chunks))


def _save_control(session, ledger):
    raw = canonical(ledger)
    if len(raw) > LEDGER_LIMIT:
        _fail('ledger_too_large')
    name = '.ledger-' + secrets.token_hex(8)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
    try:
        _write(fd, raw)
        _sync(fd)
    finally:
        _close(fd)
    os.replace(name, 'ledger.json', src_dir_fd=session, dst_dir_fd=session)
    _sync(session)


def _confirm_control(session, ledger):
    """Confirm the exact visible intent before relying on an older pending.

    A preceding replace may have succeeded while its directory fsync failed.
    Visibility alone is not proof of persistence. Re-read the named inode,
    confirm its exact bytes, and sync both it and its directory before any
    receive-file mutation. No tail bytes or historical control facts are reset.
    """
    expected = canonical(ledger)
    with _file(session, 'ledger.json', private=True) as fd:
        before = _version(os.fstat(fd))
        if before[2] != len(expected):
            _fail('ledger_changed')
        position = 0
        while position < len(expected):
            block = os.read(fd, min(BLOCK, len(expected) - position))
            if not block or block != expected[position:position + len(block)]:
                _fail('ledger_changed')
            position += len(block)
        _sync(fd)
        _sync(session)
        if _version(os.fstat(fd)) != before:
            _fail('ledger_changed')


def _valid_identity(value):
    return (isinstance(value, list) and len(value) == 2
            and all(type(n) is int and n >= 0 for n in value))


def _validate_ledger(ledger, plan, session_name):
    if (not isinstance(ledger, dict) or set(ledger) != _LEDGER_KEYS
            or ledger['version'] != 1 or type(ledger['version']) is not int
            or ledger['marker'] != MARKER or not isinstance(ledger['nonce'], str)
            or session_name != PREFIX + ledger['nonce']
            or re.fullmatch('[a-f0-9]{32}', ledger['nonce']) is None
            or normalize_plan(ledger['plan']) != plan):
        _fail('invalid_ledger')
    _name(ledger['target_name'])
    for key in ('output_identity', 'session_identity', 'input_identity'):
        if not _valid_identity(ledger[key]):
            _fail('invalid_ledger')
    if (not isinstance(ledger['input_root'], str) or not Path(ledger['input_root']).is_absolute()
            or '..' in Path(ledger['input_root']).parts
            or not isinstance(ledger['file_identities'], dict)
            or set(ledger['file_identities']) != {'receive.tmp', 'lock'}
            or not all(_valid_identity(v) for v in ledger['file_identities'].values())
            or type(ledger['temp_removed']) is not bool or type(ledger['cleanup_pending']) is not bool):
        _fail('invalid_ledger')
    index = _integer(ledger['next_index'], 0, plan['part_count'])
    offset = sum(p['bytes'] for p in plan['parts'][:index])
    if _integer(ledger['durable_offset']) != offset or not isinstance(ledger['accepted'], list) or len(ledger['accepted']) != index:
        _fail('invalid_ledger_progress')
    for number, item in enumerate(ledger['accepted']):
        if (not isinstance(item, dict) or set(item) != {'index', 'input_path', 'input_identity', 'input_version', 'sha256', 'resource_name'}
                or type(item['index']) is not int or item['index'] != number
                or item['sha256'] != plan['parts'][number]['sha256']
                or item['resource_name'] != plan['parts'][number]['resource_name']
                or not _valid_identity(item['input_identity']) or not isinstance(item['input_path'], str)
                or not isinstance(item['input_version'], list) or len(item['input_version']) != 6
                or any(type(n) is not int for n in item['input_version'])):
            _fail('invalid_ledger_progress')
    pending = ledger['pending']
    if pending is not None:
        if (not isinstance(pending, dict) or set(pending) != {'index', 'input_path', 'input_identity', 'input_version'}
                or type(pending['index']) is not int or pending['index'] != index or index >= plan['part_count']
                or not isinstance(pending['input_path'], str) or not _valid_identity(pending['input_identity'])
                or not isinstance(pending['input_version'], list) or len(pending['input_version']) != 6
                or any(type(n) is not int for n in pending['input_version'])):
            _fail('invalid_pending')
    if not isinstance(ledger['state'], str) or ledger['state'] not in {'receiving', 'publishing', 'publication_pending', 'published_verified', 'cancelled'}:
        _fail('invalid_receiver_state')
    publication = ledger['publication']
    if publication is not None and (not isinstance(publication, dict)
            or set(publication) != {'target_name', 'temp_identity', 'plan_sha256'}
            or publication['target_name'] != ledger['target_name']
            or publication['temp_identity'] != ledger['file_identities']['receive.tmp']
            or publication['plan_sha256'] != plan['plan_sha256']):
        _fail('invalid_publication')
    if ((ledger['state'] in {'publishing', 'publication_pending', 'published_verified'}) != (publication is not None)
            or publication is not None and (index != plan['part_count'] or pending is not None)
            or ledger['temp_removed'] and ledger['state'] not in {'cancelled', 'published_verified'}):
        _fail('invalid_receiver_state')


def _verify_asset_at(plan, root_path, root):
    path = Path(__file__).absolute()
    with _received_file(root_path, root, path) as lease:
        info = os.fstat(lease.fd)
        asset = plan['receiver_asset']
        if info.st_size != asset['bytes'] or _hash(lease.fd, 0, info.st_size) != asset['sha256']:
            _fail('receiver_asset_mismatch')
        lease.revalidate()


def _verify_asset(plan):
    path = Path(__file__).absolute()
    with _directory(path.parent) as parent:
        _verify_asset_at(plan, path.parent, parent)


class NativeChunkReceiver:
    def __init__(self, output_root, session_name, plan, input_root):
        self.output_root = str(Path(output_root))
        self.session_name = _name(session_name)
        self.session_path = str(Path(self.output_root) / session_name)
        self.plan = normalize_plan(plan)
        self.input_root = str(Path(input_root))

    @classmethod
    def _native_input_binding(cls):
        return None

    @classmethod
    def _check_native_root(cls, path, fd):
        binding = cls._native_input_binding()
        if binding is not None:
            if str(Path(path)) != binding[0] or tuple(_identity(os.fstat(fd))) != binding[1]:
                _fail('native_input_root_mismatch')
            _directory_matches(path, fd)

    @staticmethod
    def _preflight(root, session, output_path, session_path):
        token = secrets.token_hex(16)
        names = ('.preflight-file-' + token, '.preflight-link-' + token,
                 '.preflight-published-' + token)
        bindings = {'output_root': {'configured_path': str(output_path),
                        'held_parent_identity': _identity(os.fstat(root))},
                    'session': {'configured_path': str(session_path),
                        'held_parent_identity': _identity(os.fstat(session))}}
        entries = []
        for parent, location, directory, name in (
                (session, 'session', session_path, names[0]),
                (session, 'session', session_path, names[1]),
                (root, 'output_root', output_path, names[2])):
            entries.append((parent, {'location': location, 'name': name,
                'path': str(Path(directory) / name),
                'held_parent_identity': list(bindings[location]['held_parent_identity']),
                'attempted': False, 'created_confirmed': False, 'identity': None,
                'cleanup_removed': False, 'observation': 'not_attempted'}))
        report = {'main_checks_completed': False, 'stage': 'main',
            'main_durability_uncertain': False, 'close_uncertain': False,
            'identity_uncertain': False, 'operation_uncertain': False,
            'cleanup_started': False, 'cleanup_durability_uncertain': False,
            'cleanup_durable': False, 'directory_bindings': bindings,
            'directory_routes': {}, 'route_observations': [],
            'probes': [probe for _, probe in entries]}
        fd, identity, cause = None, None, None

        def checkpoint(label):
            _preflight_snapshot(report, root, session, label)
            if report['identity_uncertain'] or report['close_uncertain']:
                _fail('directory_changed')

        def sync_main(descriptor):
            try:
                _sync(descriptor, 'publication_primitive_unavailable')
            except BaseException:
                report['main_durability_uncertain'] = True
                raise
            checkpoint('after_main_sync')

        try:
            checkpoint('before_first_probe')
            first = entries[0][1]
            first['attempted'] = True
            fd = os.open(names[0], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=session)
            first['created_confirmed'] = True
            try:
                identity = _identity(os.fstat(fd))
            except BaseException:
                report['identity_uncertain'] = True
                raise
            first['identity'] = list(identity)
            _write(fd, b'preflight')
            sync_main(fd)
            for parent, probe in entries[1:]:
                checkpoint('before_probe_link')
                probe['attempted'] = True
                os.link(names[0], probe['name'], src_dir_fd=session,
                        dst_dir_fd=parent, follow_symlinks=False)
                probe['created_confirmed'] = True
                probe['identity'] = list(identity)
            for parent, probe in entries:
                try:
                    info = os.stat(probe['name'], dir_fd=parent, follow_symlinks=False)
                    if (_identity(info) != identity or info.st_nlink != 3
                            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()):
                        _fail('publication_primitive_unavailable')
                except BaseException:
                    report['identity_uncertain'] = True
                    raise
            checkpoint('after_probe_links')
            sync_main(fd)
            sync_main(session)
            sync_main(root)
            report['main_checks_completed'] = True
        except BaseException as error:
            cause = error
            known_refusal = (isinstance(error, OSError) and error.errno in
                (errno.EPERM, errno.EACCES, errno.EXDEV, errno.EEXIST,
                 errno.ENOTSUP, errno.EOPNOTSUPP))
            report['operation_uncertain'] = not (known_refusal
                or report['main_durability_uncertain'] or report['identity_uncertain'])
        finally:
            if fd is not None:
                try:
                    _close(fd)
                except BaseException as error:
                    report['close_uncertain'] = True
                    cause = error
            _preflight_snapshot(report, root, session, 'before_cleanup')
            # A held entry is not proof its configured path still names it.
            # Unknown routes, syncs, closes or ownership preserve all remnants.
            if not any(report[key] for key in ('main_durability_uncertain',
                    'close_uncertain', 'identity_uncertain', 'operation_uncertain')):
                report['cleanup_started'], report['stage'] = True, 'cleanup'
                for parent, probe in reversed(entries):
                    if not probe['created_confirmed']:
                        continue
                    try:
                        checkpoint('before_probe_unlink')
                        os.unlink(probe['name'], dir_fd=parent)
                        probe['cleanup_removed'] = True
                    except BaseException as error:
                        cause = cause or error
                        if not report['identity_uncertain']:
                            report['operation_uncertain'] = True
                        break
                else:
                    try:
                        checkpoint('before_cleanup_sync')
                        _sync(session, 'publication_primitive_unavailable')
                        checkpoint('after_session_cleanup_sync')
                        _sync(root, 'publication_primitive_unavailable')
                        checkpoint('after_output_cleanup_sync')
                        report['cleanup_durable'] = True
                    except BaseException as error:
                        cause = cause or error
                        report['cleanup_durability_uncertain'] = True
            _preflight_snapshot(report, root, session, 'preflight_final')
        if cause is not None or report['identity_uncertain'] or report['close_uncertain']:
            if isinstance(cause, (OSError, ReceiverError)) or cause is None:
                error = ReceiverError('descriptor_close_uncertain' if report['close_uncertain']
                                      else 'publication_primitive_unavailable')
                error.preflight = report
                raise error from cause
            cause.preflight = report
            raise cause
        return report

    @classmethod
    @_safe_os
    def start(cls, plan, output_root, input_root=None, target_name=None):
        plan = normalize_plan(plan)
        output_root = str(Path(output_root))
        binding = cls._native_input_binding()
        input_root = str(Path(input_root or (binding[0] if binding is not None else output_root)))
        target_name = _name(target_name or PurePosixPath(plan['source']['path']).name)
        with _start_evidence() as evidence, _directory(input_root) as inputs, _directory(output_root) as root:
            cls._check_native_root(input_root, inputs)
            if binding is None:
                _verify_asset(plan)
            else:
                _verify_asset_at(plan, input_root, inputs)
            _owned_directory(output_root, root, 'unsafe_output_root')
            if _exists(root, target_name) is not None:
                _fail('target_exists')
            _space(root, plan['total_bytes'] * 2)
            nonce = secrets.token_hex(16)
            name = PREFIX + nonce
            cls._check_native_root(input_root, inputs)
            _owned_directory(output_root, root, 'unsafe_output_root')
            os.mkdir(name, 0o700, dir_fd=root)
            with _directory(Path(output_root) / name) as session:
                cls._check_native_root(input_root, inputs)
                _owned_directory(Path(output_root) / name, session, 'unsafe_session')
                preflight = cls._preflight(root, session, output_root, Path(output_root) / name)
                evidence['preflight'] = preflight
                identities, created = {}, []
                checkpoint, ledger_attempted, ledger_returned = 'after_preflight', False, False

                def before_state(label):
                    nonlocal checkpoint
                    checkpoint = label
                    cls._check_native_root(input_root, inputs)
                    _owned_directory(output_root, root, 'unsafe_output_root')
                    _owned_directory(Path(output_root) / name, session, 'unsafe_session')

                try:
                    for file in ('lock', 'receive.tmp'):
                        before_state('before_create_' + file)
                        fd = os.open(file, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=session)
                        record = {'name': file, 'creation_confirmed': True, 'identity': None,
                                  'current_presence': 'not_observed'}
                        created.append(record)
                        try:
                            identities[file] = _identity(os.fstat(fd))
                            record['identity'] = list(identities[file])
                            _sync(fd)
                        finally:
                            _close(fd)
                    before_state('before_initial_ledger')
                    ledger = {'version': 1, 'marker': MARKER, 'nonce': nonce, 'plan': plan,
                              'target_name': target_name, 'output_identity': _identity(os.fstat(root)),
                              'session_identity': _identity(os.fstat(session)), 'input_root': input_root,
                              'input_identity': _identity(os.fstat(inputs)), 'file_identities': identities,
                              'accepted': [], 'next_index': 0, 'durable_offset': 0, 'pending': None,
                              'state': 'receiving', 'publication': None, 'temp_removed': False,
                              'cleanup_pending': False}
                    ledger_attempted = True
                    _save_control(session, ledger)
                    ledger_returned = True
                    before_state('before_initial_output_sync')
                    _sync(root)
                    before_state('after_initial_state')
                    _directory_matches(input_root, inputs)
                except BaseException as error:
                    try:
                        _preflight_snapshot(preflight, root, session, 'private_state_write_blocked')
                    except BaseException as diagnostic_error:
                        preflight['manifest_refresh_error'] = type(diagnostic_error).__name__
                    preflight['private_state_creation'] = {
                        'checkpoint': checkpoint, 'created_files': created,
                        'ledger_write_attempted': ledger_attempted,
                        'ledger_write_returned': ledger_returned,
                        'error_code': getattr(error, 'code', None)}
                    error.preflight = preflight
                    raise
        return cls(output_root, name, plan, input_root)

    @classmethod
    @_safe_os
    def resume(cls, session_path, plan, input_root=None):
        plan = normalize_plan(plan)
        binding = cls._native_input_binding()
        if binding is None:
            _verify_asset(plan)
        else:
            input_root = str(Path(input_root or binding[0]))
            with _directory(input_root) as inputs:
                cls._check_native_root(input_root, inputs)
                _verify_asset_at(plan, input_root, inputs)
        path = Path(session_path)
        if (not path.is_absolute() or '..' in path.parts
                or re.fullmatch(re.escape(PREFIX) + '[a-f0-9]{32}', path.name) is None):
            _fail('invalid_session')
        with _directory(path.parent) as root, _directory(path) as session:
            _owned_directory(path.parent, root, 'unsafe_output_root')
            _owned_directory(path, session, 'unsafe_session')
            ledger = _read_control(session)
            _validate_ledger(ledger, plan, path.name)
        receiver = cls(str(path.parent), path.name, plan, input_root or ledger.get('input_root', ''))
        with receiver._locked() as (root, session, ledger, inputs):
            receiver._recover_cleanup(root, session, ledger)
            receiver._verify_temp(session, ledger)
            if ledger['state'] == 'receiving' and not ledger['temp_removed'] and ledger['pending'] is not None:
                _confirm_control(session, ledger)
                pending = ledger['pending']
                part = plan['parts'][pending['index']]
                with receiver._input(pending['input_path'], part, inputs) as lease:
                    if lease.identity != pending['input_identity'] or lease.version != pending['input_version']:
                        _fail('input_changed')
                    with receiver._temp(session, ledger) as target:
                        receiver._verify_pending(lease.fd, target, ledger, part)
                    lease.revalidate()
            if ledger['state'] in {'publishing', 'publication_pending'}:
                receiver._recover_publication(root, session, ledger)
            elif ledger['state'] == 'published_verified':
                receiver._verify_final(root, ledger)
        return receiver

    @contextmanager
    def _locked(self):
        with _directory(self.output_root) as root, _directory(self.input_root) as inputs, _directory(self.session_path) as session:
            type(self)._check_native_root(self.input_root, inputs)
            self._mutable_roots(root, session)
            first = _read_control(session)
            _validate_ledger(first, self.plan, self.session_name)
            with _file(session, 'lock', flags=os.O_RDWR, private=True, identity=first['file_identities']['lock']) as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _fail('receiver_busy')
                try:
                    ledger = _read_control(session)
                    _validate_ledger(ledger, self.plan, self.session_name)
                    if (ledger['file_identities']['lock'] != first['file_identities']['lock']
                            or ledger['output_identity'] != _identity(os.fstat(root))
                            or ledger['input_identity'] != _identity(os.fstat(inputs))
                            or ledger['input_root'] != self.input_root
                            or ledger['session_identity'] != _identity(os.fstat(session))):
                        _fail('receiver_identity_changed')
                    self._mutable_roots(root, session)
                    type(self)._check_native_root(self.input_root, inputs)
                    _directory_matches(self.input_root, inputs)
                    yield root, session, ledger, inputs
                    self._mutable_roots(root, session)
                    type(self)._check_native_root(self.input_root, inputs)
                    _directory_matches(self.input_root, inputs)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def _mutable_roots(self, root, session):
        _owned_directory(self.output_root, root, 'unsafe_output_root')
        _owned_directory(self.session_path, session, 'unsafe_session')

    @contextmanager
    def _temp(self, session, ledger, writable=False, unlinking=False):
        with _file(session, 'receive.tmp', flags=os.O_RDWR if writable else os.O_RDONLY,
                   private=True, identity=ledger['file_identities']['receive.tmp'],
                   links=(1, 2) if ledger['publication'] is not None else (1,), unlinking=unlinking) as fd:
            yield fd

    @contextmanager
    def _input(self, path, part, inputs):
        with _received_file(self.input_root, inputs, path) as lease:
            if (lease.version[2] != part['bytes']
                    or _hash(lease.fd, 0, part['bytes']) != part['sha256']):
                _fail('part_length_or_hash_mismatch')
            lease.revalidate()
            yield lease

    def _verify_temp(self, session, ledger):
        if ledger['temp_removed']:
            if _exists(session, 'receive.tmp') is not None:
                _fail('temporary_state_changed')
            return
        with self._temp(session, ledger) as fd:
            size = os.fstat(fd).st_size
            maximum = ledger['durable_offset']
            if ledger['pending'] is not None:
                maximum += self.plan['parts'][ledger['next_index']]['bytes']
            if not ledger['durable_offset'] <= size <= maximum:
                _fail('temporary_length_mismatch')
            for part in self.plan['parts'][:ledger['next_index']]:
                if _hash(fd, part['offset'], part['bytes']) != part['sha256']:
                    _fail('temporary_hash_mismatch')

    @staticmethod
    def _verify_pending(source, target, ledger, part):
        tail = os.fstat(target).st_size - ledger['durable_offset']
        position = 0
        while position < tail:
            length = min(BLOCK, tail - position)
            if os.pread(source, length, position) != os.pread(target, length, part['offset'] + position):
                _fail('pending_tail_mismatch')
            position += length

    def _status(self, ledger):
        published = ledger['state'] == 'published_verified'
        return {'state': ledger['state'], 'session_path': self.session_path,
                'export_id': self.plan['export_id'], 'plan_sha256': self.plan['plan_sha256'],
                'next_index': ledger['next_index'], 'received_bytes': ledger['durable_offset'],
                'total_bytes': self.plan['total_bytes'],
                'pending_part_index': None if ledger['pending'] is None else ledger['pending']['index'],
                'published': published, 'verification': 'matched' if published else 'not_complete',
                'durability': 'confirmed' if published else 'not_confirmed',
                'path': str(Path(self.output_root) / ledger['target_name']) if published else None,
                'sha256': self.plan['total_sha256'] if published else None,
                'temporary_removed': ledger['temp_removed']}

    @_safe_os
    def status(self):
        with self._locked() as (root, session, ledger, _):
            self._verify_temp(session, ledger)
            if ledger['state'] == 'published_verified':
                self._verify_final(root, ledger)
            return self._status(ledger)

    @_safe_os
    def ingest(self, index, actual_part_path):
        index = _integer(index, 0, self.plan['part_count'] - 1)
        part = self.plan['parts'][index]
        with self._locked() as (root, session, ledger, inputs):
            if ledger['state'] != 'receiving' or ledger['temp_removed']:
                _fail('receiver_not_receiving')
            self._verify_temp(session, ledger)
            if index > ledger['next_index']:
                _fail('part_out_of_order')
            duplicate = index < ledger['next_index']
            with self._input(actual_part_path, part, inputs) as lease:
                version, identity = list(lease.version), list(lease.identity)
                if duplicate:
                    with self._temp(session, ledger) as target:
                        if _hash(target, part['offset'], part['bytes']) != part['sha256']:
                            _fail('temporary_hash_mismatch')
                else:
                    # Keep a durable pending before any write. Input admission
                    # and all source closes must finish before accepted commit.
                    _space(root, (self.plan['total_bytes'] - ledger['durable_offset']) * 2)
                    lease.revalidate()
                    self._mutable_roots(root, session)
                    if ledger['pending'] is not None:
                        pending = ledger['pending']
                        if (pending['input_path'] != str(Path(actual_part_path))
                                or pending['input_identity'] != identity or pending['input_version'] != version):
                            _fail('input_changed')
                        _confirm_control(session, ledger)
                    else:
                        ledger['pending'] = {'index': index, 'input_path': str(Path(actual_part_path)),
                                             'input_identity': identity, 'input_version': version}
                        _save_control(session, ledger)
                    lease.revalidate()
                    self._mutable_roots(root, session)
                    with self._temp(session, ledger, writable=True) as target:
                        self._verify_pending(lease.fd, target, ledger, part)
                        _copy(lease.fd, target, part['offset'], part['bytes'])
                        _sync(target)
                        if _hash(target, part['offset'], part['bytes']) != part['sha256']:
                            _fail('temporary_hash_mismatch')
                        lease.revalidate()
                lease.revalidate()
            # No live source FD is referenced after the input context closes.
            # A close/check failure above preserves pending and never gets here.
            self._mutable_roots(root, session)
            _directory_matches(self.input_root, inputs)
            if duplicate:
                return {**self._status(ledger), 'appended_bytes': 0, 'actual_part_path': str(actual_part_path)}
            with self._temp(session, ledger) as target:
                if os.fstat(target).st_size != part['offset'] + part['bytes']:
                    _fail('temporary_length_mismatch')
            ledger['accepted'].append({'index': index, 'input_path': str(Path(actual_part_path)),
                                       'input_identity': identity, 'input_version': version,
                                       'sha256': part['sha256'], 'resource_name': part['resource_name']})
            ledger['next_index'] += 1
            ledger['durable_offset'] += part['bytes']
            ledger['pending'] = None
            _save_control(session, ledger)
            return {**self._status(ledger), 'appended_bytes': part['bytes'],
                    'actual_part_path': str(actual_part_path), 'expected_resource_name': part['resource_name']}

    def _verify_final(self, root, ledger):
        with _file(root, ledger['target_name'], identity=ledger['file_identities']['receive.tmp'],
                   private=True, links=(1,) if ledger['temp_removed'] else ((1, 2) if ledger['cleanup_pending'] else (2,))) as fd:
            if os.fstat(fd).st_size != self.plan['total_bytes'] or _hash(fd, 0, self.plan['total_bytes']) != self.plan['total_sha256']:
                _fail('publication_changed')

    def _recover_publication(self, root, session, ledger):
        self._mutable_roots(root, session)
        info = _exists(root, ledger['target_name'])
        if info is None or _identity(info) != ledger['file_identities']['receive.tmp']:
            _fail('publication_pending')
        self._verify_final(root, ledger)
        with self._temp(session, ledger) as fd:
            _sync(fd, 'publication_pending')
        _sync(root, 'publication_pending')
        _sync(session, 'publication_pending')
        self._mutable_roots(root, session)
        ledger['state'] = 'published_verified'
        _save_control(session, ledger)

    @_safe_os
    def finish(self):
        with self._locked() as (root, session, ledger, _):
            self._verify_temp(session, ledger)
            if ledger['state'] == 'published_verified':
                self._verify_final(root, ledger)
                return self._status(ledger)
            if ledger['state'] in {'publishing', 'publication_pending'}:
                self._recover_publication(root, session, ledger)
                return self._status(ledger)
            if ledger['state'] != 'receiving':
                _fail('receiver_not_receiving')
            if ledger['next_index'] != self.plan['part_count'] or ledger['pending'] is not None:
                _fail('receive_incomplete')
            if _exists(root, ledger['target_name']) is not None:
                _fail('target_exists')
            _space(root, 0)
            with self._temp(session, ledger) as fd:
                if _hash(fd, 0, self.plan['total_bytes']) != self.plan['total_sha256']:
                    _fail('whole_hash_mismatch')
                ledger['publication'] = {'target_name': ledger['target_name'],
                                         'temp_identity': ledger['file_identities']['receive.tmp'],
                                         'plan_sha256': self.plan['plan_sha256']}
                ledger['state'] = 'publishing'
                self._mutable_roots(root, session)
                _save_control(session, ledger)
                self._mutable_roots(root, session)
                try:
                    os.link('receive.tmp', ledger['target_name'], src_dir_fd=session,
                            dst_dir_fd=root, follow_symlinks=False)
                except FileExistsError:
                    info = _exists(root, ledger['target_name'])
                    if info is None or _identity(info) != ledger['file_identities']['receive.tmp']:
                        _fail('target_exists')
                except OSError:
                    _fail('publication_pending')
                if _identity(os.fstat(fd)) != ledger['file_identities']['receive.tmp']:
                    _fail('publication_pending')
                self._recover_publication(root, session, ledger)
            return self._status(ledger)

    def _recover_cleanup(self, root, session, ledger):
        if not ledger['cleanup_pending']:
            return
        info = _exists(session, 'receive.tmp')
        if info is not None:
            if _identity(info) != ledger['file_identities']['receive.tmp']:
                _fail('temporary_state_changed')
            return
        if ledger['state'] == 'published_verified':
            self._verify_final(root, ledger)
        _sync(session)
        ledger['temp_removed'] = True
        ledger['cleanup_pending'] = False
        _save_control(session, ledger)

    @_safe_os
    def cancel(self):
        with self._locked() as (_, session, ledger, _inputs):
            if ledger['state'] in {'publishing', 'publication_pending'}:
                _fail('publication_pending')
            if ledger['state'] == 'published_verified':
                return self._status(ledger)
            self._verify_temp(session, ledger)
            ledger['state'] = 'cancelled'
            _save_control(session, ledger)
            return self._status(ledger)

    @_safe_os
    def cleanup(self):
        with self._locked() as (root, session, ledger, _):
            self._recover_cleanup(root, session, ledger)
            if ledger['state'] in {'publishing', 'publication_pending'}:
                _fail('publication_pending')
            if ledger['state'] not in {'cancelled', 'published_verified'}:
                _fail('cancellation_required')
            if not ledger['temp_removed']:
                self._verify_temp(session, ledger)
                if ledger['state'] == 'published_verified':
                    self._verify_final(root, ledger)
                ledger['cleanup_pending'] = True
                _save_control(session, ledger)
                with self._temp(session, ledger, unlinking=True) as fd:
                    if _identity(os.stat('receive.tmp', dir_fd=session, follow_symlinks=False)) != _identity(os.fstat(fd)):
                        _fail('temporary_state_changed')
                    os.unlink('receive.tmp', dir_fd=session)
                _sync(session)
                ledger['temp_removed'] = True
                ledger['cleanup_pending'] = False
                if ledger['state'] == 'published_verified':
                    self._verify_final(root, ledger)
                _save_control(session, ledger)
            return {**self._status(ledger), 'retained': ['ledger.json', 'lock', 'inputs', 'helper', 'final']}


# Keep the original verified class independently of the loader's exported alias.
_NATIVE_BASE_RECEIVER = NativeChunkReceiver
_NATIVE_ROOT_CLASS = None
_NATIVE_ROOT_BINDING = None


def _for_native_input_root(path, expected_identity):
    """Bind this verified helper instance once without changing its public API."""
    global _NATIVE_ROOT_CLASS, _NATIVE_ROOT_BINDING
    root_path = Path(path)
    if (not root_path.is_absolute() or '..' in root_path.parts
            or not isinstance(expected_identity, (list, tuple)) or len(expected_identity) != 2
            or any(type(number) is not int or number < 0 for number in expected_identity)):
        _fail('invalid_native_input_root_binding')
    # Detached immutable values cannot be changed by mutating the caller's list.
    binding = (str(root_path), tuple(expected_identity))
    if _NATIVE_ROOT_BINDING is not None:
        if binding != _NATIVE_ROOT_BINDING:
            _fail('native_input_root_rebind')
        return _NATIVE_ROOT_CLASS

    class _NativeInputRootReceiver(_NATIVE_BASE_RECEIVER):
        @classmethod
        def _native_input_binding(cls):
            return binding

    _NATIVE_ROOT_BINDING = binding
    _NATIVE_ROOT_CLASS = _NativeInputRootReceiver
    return _NativeInputRootReceiver
