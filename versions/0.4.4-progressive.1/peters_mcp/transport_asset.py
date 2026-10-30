"""Pinned package receiver bytes, never an arbitrary source-file export."""
import hashlib
import os
from pathlib import Path
import stat

from .catalog import AccessError
from .private_roots import _directory, _close

RECEIVER_ASSET_ID = 'native-chunk-receiver-v1'
RECEIVER_NAME = 'native_chunk_receiver.py'
RECEIVER_BYTES = 37005
RECEIVER_SHA256 = '4d5590a94c5ec359e6909efd6e9bf26740428704e05f9543a3e5cf759687b54d'
MAX_ASSET_BYTES = 64 * 1024
_ASSET_PATH = Path(__file__).with_name(RECEIVER_NAME)


def receiver_metadata():
    return {'asset_id': RECEIVER_ASSET_ID, 'name': RECEIVER_NAME,
            'bytes': RECEIVER_BYTES, 'sha256': RECEIVER_SHA256}


def _error():
    return AccessError('The fixed receiver package asset is unavailable.', code='receiver_asset_invalid')


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_uid, info.st_mode)


def load_receiver_asset():
    """Caller must hold current actor/source/private scope for the parent plan.

    A close uncertainty propagates as protection_cleanup_pending; its caller
    retains the associated reservation and stops new admission. Never retry the
    uncertain integer FD and never import/execute the asset on the origin.
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
    except (OSError, ValueError, TypeError):
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
