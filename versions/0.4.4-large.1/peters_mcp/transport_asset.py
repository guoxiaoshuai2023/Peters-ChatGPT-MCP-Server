"""One fixed, verified package asset; never an arbitrary local-file export."""
import hashlib
import os
from pathlib import Path
import stat

from .catalog import AccessError
from .private_roots import _directory, _close


RECEIVER_ASSET_ID = 'native-range-receiver-v2'
RECEIVER_NAME = 'native_range_receiver.py'
RECEIVER_BYTES = 55_892
RECEIVER_SHA256 = 'c2947336638742cf3471d55a349d89238aaa21316632cc6924d47a6b7623a1db'
MAX_ASSET_BYTES = 64 * 1024
_ASSET_PATH = Path(__file__).with_name(RECEIVER_NAME)


def receiver_metadata():
    """Expected immutable package identity; no path, body or resource link."""
    return {'asset_id': RECEIVER_ASSET_ID, 'version': '2', 'name': RECEIVER_NAME,
            'bytes': RECEIVER_BYTES, 'sha256': RECEIVER_SHA256,
            'source_kind': 'trusted_package_asset', 'trust_basis': 'pinned_package_digest',
            'native_independent_hash_required': True}


def _error(code='receiver_asset_invalid'):
    return AccessError('The fixed transport receiver asset is unavailable.', code=code)


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, info.st_uid, info.st_mode)


def load_receiver_asset():
    """Read only the compile-time fixed asset through an anchored no-follow FD.

    This is called inside the parent export's verified actor/source/private
    scope. It does not import the helper on the origin or register a new repo.
    Descriptor-close failures use the existing protection pending contract.
    """
    path = _ASSET_PATH.absolute()
    parent = file = None
    try:
        if path.resolve() != path or path.name != RECEIVER_NAME:
            raise _error()
        parent = _directory(path.parent)
        anchor = os.fstat(parent)
        file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(file)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_size != RECEIVER_BYTES
                or before.st_size > MAX_ASSET_BYTES):
            raise _error()
        payload = bytearray()
        while len(payload) <= MAX_ASSET_BYTES:
            chunk = os.read(file, min(8192, MAX_ASSET_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        current_anchor = path.parent.stat(follow_symlinks=False)
        if (_version(before) != _version(os.fstat(file)) or _version(before) != _version(named)
                or (anchor.st_dev, anchor.st_ino) != (current_anchor.st_dev, current_anchor.st_ino)
                or len(payload) != RECEIVER_BYTES or hashlib.sha256(payload).hexdigest() != RECEIVER_SHA256):
            raise _error()
        return bytes(payload)
    except (OSError, ValueError, TypeError) as error:
        if isinstance(error, AccessError):
            raise
        raise _error() from None
    finally:
        pending = None
        for descriptor in (file, parent):
            if descriptor is not None:
                try:
                    _close(descriptor)
                except AccessError as error:
                    pending = pending or error
        if pending is not None:
            raise pending
