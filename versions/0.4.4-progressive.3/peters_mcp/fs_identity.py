"""FD-backed macOS persistent identity, separate from runtime (dev, ino) pins."""
import ctypes
import fcntl
import os
from pathlib import Path
import stat
import struct
import sys
import uuid

from .catalog import AccessError

_RETURNED = 0x80000000
_CRTIME = 0x00000200
_VOL_UUID = 0x00040000
_VOL_INFO = 0x80000000  # Request control bit, not a returned attribute.
_F_GETPATH = 50
_MAX_PATH = 1024
_FIELDS = {'format', 'platform', 'volume_uuid', 'file_id', 'birthtime_ns'}
_MAX_BIRTHTIME = (2 ** 63 - 1) * 10 ** 9 + 999999999
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _error(code='identity_unsupported'):
    return AccessError('A reliable filesystem identity could not be verified.', code=code)


def validate_identity(value):
    """Validate the complete v2 wire shape; never coerce an untrusted value."""
    try:
        if (type(value) is not dict or set(value) != _FIELDS
                or type(value['format']) is not int or value['format'] != 2
                or value['platform'] != 'darwin' or type(value['volume_uuid']) is not str
                or type(value['file_id']) is not int or not 0 <= value['file_id'] < 2 ** 64
                or type(value['birthtime_ns']) is not int
                or not 0 < value['birthtime_ns'] <= _MAX_BIRTHTIME):
            raise ValueError()
        parsed = uuid.UUID(value['volume_uuid'])
        if not parsed.int or str(parsed) != value['volume_uuid']:
            raise ValueError()
        return dict(value)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise _error('identity_invalid') from None


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        raise _error('identity_cleanup_pending') from None


def _runtime(info):
    identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    # A directory's link count changes when ordinary child directories are
    # created/removed. Only regular-file hardlink changes invalidate this read.
    return identity + (info.st_nlink,) if stat.S_ISREG(info.st_mode) else identity


def _path(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise _error('identity_mismatch')
    return path


def _open(path):
    """No link is followed, including intermediate absolute components."""
    path = _path(path)
    fd = os.open('/', _DIR)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = _READ if index == len(path.parts) - 2 else _DIR
            child = os.open(part, flags, dir_fd=fd)
            previous, fd = fd, child
            _close(previous)
        return fd
    except BaseException:
        _close(fd)
        raise


class _AttrList(ctypes.Structure):
    _fields_ = [('bitmapcount', ctypes.c_uint16), ('reserved', ctypes.c_uint16),
                ('commonattr', ctypes.c_uint32), ('volattr', ctypes.c_uint32),
                ('dirattr', ctypes.c_uint32), ('fileattr', ctypes.c_uint32),
                ('forkattr', ctypes.c_uint32)]


def _library():
    if sys.platform != 'darwin':
        raise _error()
    try:
        return ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    except (OSError, AttributeError):
        raise _error() from None


def _attribute_bytes(fd, common, volume):
    try:
        function = _library().fgetattrlist
        function.argtypes = [ctypes.c_int, ctypes.POINTER(_AttrList), ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_ulong]
        function.restype = ctypes.c_int
        request = _AttrList(5, 0, common, volume, 0, 0, 0)
        output = ctypes.create_string_buffer(40)
        if function(fd, ctypes.byref(request), output, 40, 0) != 0:
            raise _error()
        return output.raw
    except (OSError, AttributeError, TypeError, ValueError, ctypes.ArgumentError):
        raise _error() from None


def _payload(raw, common, volume):
    # Darwin packs the variable attribute buffer at four-byte boundaries.
    if len(raw) != 40:
        raise _error()
    length, returned_common, returned_volume, directory, file, fork = struct.unpack_from('=6I', raw)
    if (length != 40 or returned_common != common or returned_volume != volume
            or directory or file or fork):
        raise _error()
    return raw[24:40]


def _fd_path(fd):
    raw = fcntl.fcntl(fd, _F_GETPATH, bytes(_MAX_PATH))
    if not isinstance(raw, bytes) or b'\0' not in raw:
        raise _error()
    return _path(os.fsdecode(raw.split(b'\0', 1)[0]))


def persistent_identity_fd(fd):
    """Read one held FD and re-open its path to reject replacement races.

    The caller retains ownership of fd. No runtime device number is persisted.
    """
    try:
        if sys.platform != 'darwin' or type(fd) is not int or fd < 0:
            raise _error()
        before = os.fstat(fd)
        if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
            raise _error()
        path = _fd_path(fd)
        volume = _payload(_attribute_bytes(fd, _RETURNED, _VOL_INFO | _VOL_UUID),
                          _RETURNED, _VOL_UUID)
        if not any(volume):
            raise _error()
        timespec = _payload(_attribute_bytes(fd, _RETURNED | _CRTIME, 0),
                            _RETURNED | _CRTIME, 0)
        seconds, nanoseconds = struct.unpack('=qq', timespec)
        if seconds < 0 or not 0 <= nanoseconds < 10 ** 9:
            raise _error()
        result = validate_identity({'format': 2, 'platform': 'darwin',
                                    'volume_uuid': str(uuid.UUID(bytes=volume)),
                                    'file_id': before.st_ino,
                                    'birthtime_ns': seconds * 10 ** 9 + nanoseconds})
        if _runtime(before) != _runtime(os.fstat(fd)) or _fd_path(fd) != path:
            raise _error('identity_mismatch')
        current = _open(path)
        try:
            if _runtime(os.fstat(current)) != _runtime(before):
                raise _error('identity_mismatch')
        finally:
            _close(current)
        if _runtime(before) != _runtime(os.fstat(fd)):
            raise _error('identity_mismatch')
        return result
    except AccessError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError, struct.error):
        raise _error() from None


def persistent_identity(path):
    """Safely open an absolute canonical regular file or directory."""
    fd = None
    try:
        path = _path(path)
        fd = _open(path)
        result = persistent_identity_fd(fd)
        current = _open(path)
        try:
            if _runtime(os.fstat(current)) != _runtime(os.fstat(fd)):
                raise _error('identity_mismatch')
        finally:
            _close(current)
        return result
    except AccessError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError):
        raise _error() from None
    finally:
        if fd is not None:
            _close(fd)


def boot_session_id():
    """Read the current kernel boot UUID through the fixed native sysctl API."""
    try:
        function = _library().sysctlbyname
        function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                             ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_int
        output = ctypes.create_string_buffer(128)
        length = ctypes.c_size_t(len(output))
        if function(b'kern.bootsessionuuid', output, ctypes.byref(length), None, 0) != 0:
            raise _error()
        raw = output.raw[:length.value]
        if not 2 <= length.value <= 128 or not raw.endswith(b'\0') or b'\0' in raw[:-1]:
            raise _error()
        value = raw[:-1].decode('ascii')
        parsed = uuid.UUID(value)
        if not parsed.int or value.lower() != str(parsed):
            raise _error()
        return str(parsed)
    except AccessError:
        raise
    except (OSError, ValueError, AttributeError, TypeError, UnicodeError, ctypes.ArgumentError):
        raise _error() from None
