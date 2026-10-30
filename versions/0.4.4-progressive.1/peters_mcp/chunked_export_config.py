"""Strict private policy for bounded, opt-in original-byte part delivery."""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import stat

from .catalog import AccessError
from .private_roots import _directory, _close

PROTOCOL_VERSION = 'raw-parts-v1'
PART_MAX_BYTES = 8_000_000
MAX_CHUNKED_BYTES = 100_000_000
PARENT_SECONDS = 3600
DELIVERY_SECONDS = 600


def _error(code='chunked_export_config_invalid'):
    return AccessError('Chunked original export configuration is unavailable.', code=code)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, info.st_uid, stat.S_IMODE(info.st_mode))


@dataclass(frozen=True)
class ChunkedExportConfig:
    enabled: bool = False
    max_file_bytes: int = 30_000_000
    min_free_bytes: int = 1024 * 1024 * 1024
    protocol_version: str = PROTOCOL_VERSION
    path: Path | None = None
    identity: tuple | None = field(default=None, repr=False)
    content_sha256: str | None = field(default=None, repr=False)

    def validate(self):
        if (type(self.enabled) is not bool or self.protocol_version != PROTOCOL_VERSION
                or type(self.max_file_bytes) is not int or not 1 <= self.max_file_bytes <= MAX_CHUNKED_BYTES
                or type(self.min_free_bytes) is not int or self.min_free_bytes < 0):
            raise _error()
        return self

    def current(self, *, require_enabled=True):
        current = read_chunked_export_config(self.path) if self.path is not None else self.validate()
        if current != self:
            raise _error('scope_changed')
        if require_enabled and not current.enabled:
            raise _error('export_disabled')
        value = [self.protocol_version, self.enabled, self.max_file_bytes, self.min_free_bytes,
                 self.content_sha256, self.identity]
        return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                         separators=(',', ':')).encode()).hexdigest()


def read_chunked_export_config(path):
    if path is None:
        return ChunkedExportConfig()
    path, fd = Path(os.path.abspath(path)), None
    try:
        parent = _directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            _close(parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > 65536):
            raise _error()
        raw = bytearray()
        while len(raw) <= 65536:
            block = os.read(fd, min(8192, 65537 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)) or _stamp(before) != _stamp(path.lstat()):
            raise _error()
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise _error()
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) != {
                'version', 'enabled', 'max_file_bytes', 'min_free_bytes', 'protocol_version'}
                or type(data['version']) is not int or data['version'] != 1):
            raise _error()
        return ChunkedExportConfig(data['enabled'], data['max_file_bytes'], data['min_free_bytes'],
            data['protocol_version'], path, _stamp(before), hashlib.sha256(raw).hexdigest()).validate()
    except AccessError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise _error() from None
    finally:
        if fd is not None:
            _close(fd)
