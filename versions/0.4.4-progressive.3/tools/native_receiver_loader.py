"""Load the exact received helper bytes under independently supplied release pins.

This standalone template uses only the standard library. It grants no source
permission and never executes data parts. The caller freezes this template's
bytes separately, binds the actual input-root identity from native preflight,
and supplies the release's helper pin independently of the received plan.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
from types import ModuleType


MAX_HELPER_BYTES = 64 * 1024
READ_BYTES = 8192
ASSET_ID = 'native-chunk-receiver-v1'
ASSET_NAME = 'native_chunk_receiver.py'
_ASSET_KEYS = {'asset_id', 'name', 'bytes', 'sha256'}


class LoaderError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise LoaderError(code)


def _identity(info):
    return (info.st_dev, info.st_ino)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_uid, info.st_gid,
            info.st_mode)


def _path(value):
    if not isinstance(value, (str, Path)):
        _fail('invalid_path')
    text = str(value)
    if (not text or len(text.encode('utf-8')) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in text)):
        _fail('invalid_path')
    path = Path(text)
    if not path.is_absolute() or '..' in path.parts:
        _fail('invalid_path')
    return path


def _asset(value):
    if (not isinstance(value, dict) or set(value) != _ASSET_KEYS
            or value['asset_id'] != ASSET_ID or value['name'] != ASSET_NAME
            or type(value['bytes']) is not int
            or not 1 <= value['bytes'] <= MAX_HELPER_BYTES
            or not isinstance(value['sha256'], str)
            or re.fullmatch('[a-f0-9]{64}', value['sha256']) is None):
        _fail('invalid_asset_pin')
    return dict(value)


def _root_identity(value):
    if (not isinstance(value, (tuple, list)) or len(value) != 2
            or any(type(n) is not int or n < 0 for n in value)):
        _fail('invalid_input_root_identity')
    return tuple(value)


def _received_policy(info):
    forbidden = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (os.getuid(), 0)
            or info.st_mode & forbidden):
        _fail('unsafe_received_helper')


def _routes_match(routes):
    for parent, name, child in routes:
        actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(child)
        if (not stat.S_ISDIR(actual.st_mode) or not stat.S_ISDIR(opened.st_mode)
                or _identity(actual) != _identity(opened)):
            _fail('input_directory_changed')


def _file_matches(parent, name, fd, before):
    opened = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _received_policy(opened)
    _received_policy(named)
    if _stamp(before) != _stamp(opened) or _stamp(before) != _stamp(named):
        _fail('received_helper_changed')


def _close_all(descriptors):
    """Close each owned descriptor once; an uncertain integer is never retried."""
    first_error = None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError as error:
            first_error = first_error or error
    if first_error is not None:
        raise LoaderError('descriptor_close_uncertain') from first_error


def _bind_native_receiver(module, root, root_identity):
    """Use only the verified helper's own immutable-root binding factory.

    Old approved helpers and inert loader test sources have no factory and are
    returned explicitly unqualified. A present but invalid factory is a hard
    error. This loader does not implement or patch receiver security guards.
    """
    if '_for_native_input_root' not in module.__dict__:
        return False
    factory = module.__dict__['_for_native_input_root']
    original = module.__dict__.get('NativeChunkReceiver')
    if not callable(factory) or not isinstance(original, type):
        _fail('invalid_receiver_root_binding')
    bound = factory(root, tuple(root_identity))
    if (not isinstance(bound, type) or bound is original
            or not issubclass(bound, original)):
        _fail('invalid_receiver_root_binding')
    method = getattr(bound, '_native_input_binding', None)
    if not callable(method):
        _fail('invalid_receiver_root_binding')
    binding = method()
    if (type(binding) is not tuple or len(binding) != 2
            or type(binding[0]) is not str or binding[0] != root
            or type(binding[1]) is not tuple or len(binding[1]) != 2
            or any(type(n) is not int for n in binding[1])
            or binding[1] != tuple(root_identity)
            or any(not callable(getattr(bound, name, None)) for name in
                   ('start', 'resume', 'ingest', 'status', 'finish', 'cancel', 'cleanup'))):
        _fail('invalid_receiver_root_binding')
    module.NativeChunkReceiver = bound
    return True


def load_verified_receiver(actual_helper_path, input_root,
                           expected_input_identity, expected_asset,
                           plan_receiver_asset):
    """Return ``(fresh_module, measured_evidence)`` only after safe input close.

    ``expected_asset`` comes from an independently reviewed release, while
    ``plan_receiver_asset`` is the actual authenticated plan's metadata.
    Equality of two caller-constructed dictionaries is not by itself provenance;
    the caller is responsible for preserving that independent release input.
    No persistent receiver or output is created by this function.
    """
    expected = _asset(expected_asset)
    offered = _asset(plan_receiver_asset)
    if offered != expected:
        _fail('receiver_asset_pin_mismatch')
    root_expected = _root_identity(expected_input_identity)
    root = _path(input_root)
    actual = _path(actual_helper_path)
    try:
        relative = actual.relative_to(root)
    except ValueError:
        _fail('helper_outside_input_root')
    if not relative.parts:
        _fail('helper_outside_input_root')

    descriptors, routes = [], []
    failure = None
    payload = None
    before = None
    try:
        current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for name in root.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=current)
            descriptors.append(child)
            routes.append((current, name, child))
            current = child
        root_fd = current
        if _identity(os.fstat(root_fd)) != root_expected:
            _fail('input_root_identity_mismatch')
        for name in relative.parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=current)
            descriptors.append(child)
            routes.append((current, name, child))
            current = child
        basename = relative.parts[-1]
        fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=current)
        descriptors.append(fd)
        before = os.fstat(fd)
        _received_policy(before)
        if before.st_size != expected['bytes']:
            _fail('receiver_asset_length_mismatch')
        _routes_match(routes)
        _file_matches(current, basename, fd, before)
        body = bytearray()
        while len(body) < expected['bytes']:
            block = os.read(fd, min(READ_BYTES, expected['bytes'] - len(body)))
            if not block:
                _fail('receiver_asset_short_read')
            body.extend(block)
        payload = bytes(body)
        if hashlib.sha256(payload).hexdigest() != expected['sha256']:
            _fail('receiver_asset_hash_mismatch')
        _file_matches(current, basename, fd, before)
        _routes_match(routes)
        if _identity(os.fstat(root_fd)) != root_expected:
            _fail('input_root_identity_mismatch')
    except BaseException as error:
        failure = error
    try:
        _close_all(descriptors)
    except LoaderError as error:
        # Closing is a hard gate even when verification had also failed.
        if failure is not None:
            error.__context__ = failure
        failure = error
    if failure is not None:
        if isinstance(failure, OSError):
            raise LoaderError('received_helper_io_failed') from failure
        raise failure

    # The buffer, not a new file open or a cached code object, is executable.
    # All source descriptors have already closed successfully at this point.
    module = ModuleType('_peters_received_helper_' + expected['sha256'])
    module.__file__ = str(actual)
    module.__package__ = ''
    module.__loader__ = None
    module.__spec__ = None
    code = compile(payload, str(actual), 'exec', dont_inherit=True)
    exec(code, module.__dict__)
    root_bound = _bind_native_receiver(module, str(root), root_expected)
    evidence = {
        'actual_helper_path': str(actual),
        'input_root': str(root),
        'input_root_identity': list(root_expected),
        'actual_bytes': len(payload),
        'actual_sha256': expected['sha256'],
        'uid': before.st_uid,
        'gid': before.st_gid,
        'mode_octal': oct(stat.S_IMODE(before.st_mode)),
        'nlink': before.st_nlink,
        'file_identity': list(_identity(before)),
        'security_stamp': list(_stamp(before)),
        'regular_file': True,
        'verified_source_buffer_executed': True,
        'all_input_descriptors_closed_before_execution': True,
        'independent_release_pin_matched': True,
        'actual_plan_asset_matched': True,
        'native_receiver_root_bound': root_bound,
        'native_receipt_claim': 'caller must separately retain actual host receipt',
    }
    return module, evidence
