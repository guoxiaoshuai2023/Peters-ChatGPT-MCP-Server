"""Read-only bounded streaming for plain and Codex-compressed JSONL sources."""

from contextlib import closing
import os
import sys
import time

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from .catalog import AccessError

BLOCK_BYTES = 256 * 1024


class RolloutFD(int):
    """An owned OS descriptor with encoding metadata, usable by fstat/pread."""

    def __new__(cls, fd, *, compressed=False):
        instance = super().__new__(cls, fd)
        instance.compressed = compressed
        return instance


class _BoundedFD:
    def __init__(self, fd, size):
        self.fd, self.size, self.offset = fd, size, 0

    def read(self, size):
        size = min(size, self.size - self.offset)
        if size <= 0:
            return b''
        data = os.pread(self.fd, size, self.offset)
        if not data:
            raise AccessError('History was truncated during reading.', code='source_changed')
        self.offset += len(data)
        return data


def chunks(fd, size):
    """Yield decoded blocks; never write a decompressed source or cache to disk."""
    raw = _BoundedFD(fd, size)
    if not getattr(fd, 'compressed', False):
        while data := raw.read(BLOCK_BYTES):
            yield data
        return
    try:
        # Bound both the decompressor window and each output block. The worker
        # also enforces elapsed-time/RSS budgets, including decompression bombs.
        with zstd.ZstdFile(raw, 'rb', options={zstd.DecompressionParameter.window_log_max: 25}) as source:
            while data := source.read(BLOCK_BYTES):
                yield data
    except (EOFError, zstd.ZstdError):
        raise AccessError('Compressed history is incomplete, invalid or exceeds its decoder budget.',
                          code='unverifiable_source') from None


def read_range_iter(fd, length, offset):
    """Read an already-authorized tool record by decoded offset, with IO yields."""
    if not getattr(fd, 'compressed', False):
        return os.pread(fd, length, offset)
    result, position, consumed, started = [], 0, 0, time.monotonic()
    with closing(chunks(fd, os.fstat(fd).st_size)) as source:
        for block in source:
            end = position + len(block)
            if end > offset:
                result.append(block[max(0, offset - position):max(0, offset + length - position)])
            position = end
            if position >= offset + length:
                break
            consumed += len(block)
            if consumed >= 16 * 1024 * 1024 or time.monotonic() - started >= 1.5:
                yield {'phase': 'reading_item'}
                consumed, started = 0, time.monotonic()
    return b''.join(result)
