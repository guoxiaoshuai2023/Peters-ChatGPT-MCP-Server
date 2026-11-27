"""Bounded-memory, original-byte file reception into an already owned empty spool.

This module neither publishes nor closes the caller's output descriptor. A returned
receipt proves reception/framing and a synced spool, NOT writer exit or a durable
receive_complete transaction. The coordinator must establish those separately.
No URLs, file IDs, header values, exception text, or secrets enter receipts/errors.
"""

import errno
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field


CHUNK_BYTES = 64 * 1024
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QUOTED = rb'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t -~\x80-\xff])*"'
_CHUNK_HEADER = re.compile(rb"([0-9a-fA-F]+)(?:[ \t]*;[ \t]*" + _TOKEN +
                           rb"(?:[ \t]*=[ \t]*(?:" + _TOKEN + rb"|" + _QUOTED + rb"))?)*[ \t]*\r\n\Z")
_TRAILER = re.compile(rb"(" + _TOKEN + rb"):[\t \x21-\x7e\x80-\xff]*\r\n\Z")


class NativeFile(BaseModel):
    """The four-field native fileParams object; references stay in process memory."""
    model_config = ConfigDict(extra="forbid")
    download_url: str = Field(repr=False)
    file_id: str = Field(repr=False)
    mime_type: str = ""
    file_name: str = ""


class SourceError(ValueError):
    def __init__(self, code, *, bytes_received=0):
        self.code = code
        self.bytes_received = bytes_received
        super().__init__(code)


def _fail(code):
    raise SourceError(code)


def _reference(file):
    try:
        if not isinstance(file, NativeFile):
            file = NativeFile.model_validate(file)
        if (not file.file_id or len(file.file_id) > 1024 or len(file.mime_type) > 160
                or len(file.file_name) > 1024 or len(file.download_url) > 16384
                or any(ord(c) < 32 or ord(c) == 127 for c in file.file_id + file.mime_type + file.file_name)):
            raise ValueError()
        parsed = _url(file.download_url)
        return file, parsed
    except (ValueError, TypeError, AttributeError):
        raise SourceError("invalid_file_reference") from None


def _url(url):
    try:
        if (not isinstance(url, str) or len(url) > 16384 or "\\" in url
                or any(ord(c) < 33 or ord(c) == 127 for c in url)):
            raise ValueError()
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or not _HOST.fullmatch(parsed.hostname)
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError()
        return parsed
    except (ValueError, TypeError):
        raise SourceError("source_not_approved") from None


def _expected(expected_sha256, expected_size_bytes):
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or
                                       not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        _fail("invalid_expected_hash")
    if expected_size_bytes is not None and (type(expected_size_bytes) is not int or expected_size_bytes < 0):
        _fail("invalid_expected_length")


def source_identity(file):
    """Selection identity only: same file_id is NOT immutable content evidence."""
    file, parsed = _reference(file)
    value = json.dumps([parsed.hostname, file.file_id], separators=(",", ":"), ensure_ascii=True)
    return {"selection_sha256": hashlib.sha256(value.encode()).hexdigest(),
            "source_evidence_kind": "reference_only", "content_identity_verified": False}


def retry_policy(expected_sha256=None):
    """No provider immutability adapter or Range support is claimed in this version.

    A caller must additionally stop the prior writer, recheck authorization and
    CAS the source revision. A new URL alone never resumes an existing attempt.
    """
    _expected(expected_sha256, None)
    allowed = expected_sha256 is not None
    return {"same_job_retry_allowed": allowed, "range_resume_allowed": False,
            "action": "restart_from_zero_verify_bound_hash" if allowed else "needs_new_content_request"}


def _public_address(value):
    try:
        address = ipaddress.ip_address(value)
        if (not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified
                or getattr(address, "ipv4_mapped", None) or getattr(address, "sixtofour", None)
                or getattr(address, "teredo", None) or (address.version == 6 and any(address in network for network in (
                    ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))))):
            raise ValueError()
        return str(address)
    except (ValueError, TypeError):
        raise SourceError("source_nonpublic") from None


def _address(host, allowed_hosts, resolver, progress, connect_timeout):
    if not isinstance(allowed_hosts, dict) or host not in allowed_hosts or len(allowed_hosts) > 64:
        _fail("source_not_approved")
    if any(not isinstance(key, str) or not _HOST.fullmatch(key) for key in allowed_hosts):
        _fail("source_policy_invalid")
    candidates = allowed_hosts[host]
    if candidates is None:
        # libc resolver timeouts are platform-specific. Its helper owns no output
        # FD and is daemonized so an unresponsive DNS lookup cannot pin this
        # receive process at shutdown. It never opens a file or starts a child.
        replies = queue.Queue(maxsize=1)

        def resolve():
            try:
                replies.put((True, resolver(host, 443, type=socket.SOCK_STREAM)))
            except Exception:
                replies.put((False, None))

        threading.Thread(target=resolve, daemon=True, name="file-source-dns").start()
        deadline = time.monotonic() + connect_timeout
        while True:
            progress.check_stop()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("source_dns_timeout")
            try:
                ok, records = replies.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if not ok:
                _fail("source_unavailable")
            candidates = [record[4][0] for record in records]
            break
    if not isinstance(candidates, (list, tuple)) or not 1 <= len(candidates) <= 32:
        _fail("source_unavailable")
    # Validate every answer before choosing ONE fixed address. No proxy discovery,
    # alternate DNS lookup during connection, or private-address fallback.
    addresses = sorted({_public_address(value) for value in candidates},
                       key=lambda value: (ipaddress.ip_address(value).version, value))
    return addresses[0]


class _Progress:
    def __init__(self, idle_timeout, stop):
        self.idle_timeout, self.stop = idle_timeout, stop
        self.last_data = time.monotonic()

    def check_stop(self):
        try:
            stopped = self.stop is not None and (self.stop.is_set() if hasattr(self.stop, "is_set") else self.stop())
        except SourceError as exc:
            # Only fixed signals emitted by the trusted receiver's stop policy
            # may cross this boundary; never forward arbitrary exception codes.
            if exc.code in {"insufficient_space", "transfer_cancelled"}:
                raise SourceError(exc.code) from None
            raise SourceError("stop_check_failed") from None
        except Exception:
            raise SourceError("stop_check_failed") from None
        if stopped:
            _fail("transfer_cancelled")

    def mark_data(self):
        self.last_data = time.monotonic()

    def remaining(self):
        self.check_stop()
        remaining = self.idle_timeout - (time.monotonic() - self.last_data)
        if remaining <= 0:
            _fail("transfer_idle_timeout")
        return remaining


class _WireReader:
    """HTTPResponse-compatible bounded reader with cancellable raw socket reads.

    socket.makefile cannot reliably resume after a polling timeout. Read the raw
    TLS socket instead, allowing short timeout polls without losing buffered data.
    Framing/header trickles do not reset the actual file-data progress deadline.
    """
    def __init__(self, sock, progress):
        self.sock, self.progress = sock, progress
        self.buffer = bytearray()
        self.closed = False
        self.header_mode, self.header_bytes = True, 0

    def _fill(self):
        if self.closed:
            return False
        while True:
            self.sock.settimeout(min(0.25, self.progress.remaining()))
            try:
                chunk = self.sock.recv(CHUNK_BYTES)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            self.progress.remaining()
            if not chunk:
                return False
            self.buffer.extend(chunk)
            return True

    def read1(self, size):
        self.progress.check_stop()
        if not self.buffer and not self._fill():
            return b""
        result = bytes(self.buffer[:size])
        del self.buffer[:len(result)]
        return result

    def read(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.read1(size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)

    def readline(self, limit):
        while True:
            self.progress.remaining()
            end = self.buffer.find(b"\n", 0, limit)
            if end >= 0 or len(self.buffer) >= limit:
                size = end + 1 if end >= 0 else limit
                break
            if not self._fill():
                size = min(len(self.buffer), limit)
                break
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        if self.header_mode:
            if not result.endswith(b"\r\n"):
                _fail("response_headers_incomplete")
            self.header_bytes += len(result)
            if self.header_bytes > 32768:
                _fail("response_headers_too_large")
        return result

    def close(self):
        self.closed = True
        self.buffer.clear()

    def flush(self):
        pass  # Read-only adapter; HTTPResponse.close() invokes this hook.


class _ReaderSocket:
    def __init__(self, reader):
        self.reader = reader

    def makefile(self, *args, **kwargs):
        return self.reader


class _Response(http.client.HTTPResponse):
    def __init__(self, sock, progress, **kwargs):
        self.wire = _WireReader(sock, progress)
        super().__init__(_ReaderSocket(self.wire), **kwargs)

    def _read_status(self):
        version, status, reason = super()._read_status()
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            _fail("response_protocol_unsupported")
        return version, status, reason

    def begin(self):
        super().begin()
        if self.headers.defects or any("\r" in value or "\n" in value for _, value in self.headers.items()):
            _fail("response_headers_invalid")
        self.wire.header_mode = False
        # HTTPConnection normally closes its socket immediately for a response
        # with Connection: close, relying on makefile's separate lifetime. Our
        # raw TLS reader owns no duplicate socket: retain it until outer cleanup.
        # Connections are never reused, and framing is validated independently.
        self.will_close = False


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, connect_timeout, progress):
        super().__init__(host, 443, timeout=connect_timeout, context=ssl.create_default_context())
        self.address, self.progress = address, progress
        self.response_class = lambda sock, **kwargs: _Response(sock, progress, **kwargs)

    def connect(self):
        connection = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host,
                                                  suppress_ragged_eofs=False)
        except BaseException:
            connection.close()
            raise


def _framing(response):
    headers = response.headers
    encoding = headers.get_all("Content-Encoding", [])
    length = headers.get_all("Content-Length", [])
    transfer = headers.get_all("Transfer-Encoding", [])
    if len(encoding) > 1 or (encoding and encoding[0].strip().lower() != "identity"):
        _fail("response_encoding_unsupported")
    if len(length) > 1 or len(transfer) > 1 or (length and transfer):
        _fail("response_framing_invalid")
    if headers.get_all("Content-Range", []):
        _fail("unexpected_partial_response")
    if transfer:
        if transfer[0].strip().lower() != "chunked" or response.version != 11:
            _fail("response_framing_invalid")
        return "chunked", None
    if length:
        value = length[0].strip()
        if not re.fullmatch(r"[0-9]+", value):
            _fail("response_framing_invalid")
        try:
            return "content_length", int(value)
        except ValueError:
            _fail("response_framing_invalid")
    # This adapter intentionally does not infer whole-object completion from
    # close-delimited EOF. A separately verified closure adapter can be added.
    _fail("completion_unverifiable")


def _body(response, framing, length, progress):
    stream = response.fp
    if framing == "content_length":
        remaining = length
        while remaining:
            progress.check_stop()
            chunk = stream.read1(min(CHUNK_BYTES, remaining))
            if not chunk:
                _fail("transfer_incomplete")
            remaining -= len(chunk)
            yield chunk
        return
    while True:
        line = stream.readline(8193)
        match = _CHUNK_HEADER.fullmatch(line) if len(line) <= 8192 else None
        if match is None:
            _fail("chunk_framing_invalid")
        size = int(match[1], 16)
        if size == 0:
            trailer_bytes = 0
            for _ in range(65):
                trailer = stream.readline(8193)
                trailer_bytes += len(trailer)
                if len(trailer) > 8192 or trailer_bytes > 32768:
                    _fail("chunk_trailer_invalid")
                if trailer == b"\r\n":
                    return
                field = _TRAILER.fullmatch(trailer)
                if field is None or field[1].lower() in {
                        b"content-length", b"transfer-encoding", b"content-encoding", b"content-range",
                        b"host", b"authorization", b"proxy-authorization"}:
                    _fail("chunk_trailer_invalid")
            _fail("chunk_trailer_invalid")
        while size:
            progress.check_stop()
            chunk = stream.read1(min(CHUNK_BYTES, size))
            if not chunk:
                _fail("transfer_incomplete")
            size -= len(chunk)
            yield chunk
        if stream.read(2) != b"\r\n":
            _fail("chunk_framing_invalid")


def receive_file(file, output, allowed_hosts, *, expected_sha256=None, expected_size_bytes=None,
                 stop=None, on_checkpoint=None, connect_timeout=10, idle_timeout=20,
                 checkpoint_bytes=1024 * 1024, max_redirects=3,
                 _connector=None, _resolver=None):
    """Receive a single whole response, no implicit retry or Range concatenation.

    output: caller-owned empty regular FD or binary file object with fileno/write/
    flush; it stays open. on_checkpoint(dict) is called only after flush+fsync,
    including an offset-0 checkpoint for a valid empty file. Callback failure stops
    reception. stop is an Event or zero-argument checker. No total byte/time cap.
    The underscored connector/resolver are in-process test seams, never options
    parsed from policy, an MCP request, environment, or URL.
    """
    count, connection, response = 0, None, None
    try:
        file, parsed = _reference(file)
        _expected(expected_sha256, expected_size_bytes)
        if (type(max_redirects) is not int or not 0 <= max_redirects <= 5
                or type(checkpoint_bytes) is not int or checkpoint_bytes <= 0
                or isinstance(connect_timeout, bool) or not 0 < connect_timeout <= 120
                or isinstance(idle_timeout, bool) or not 0 < idle_timeout <= 600):
            _fail("source_settings_invalid")
        descriptor = output if type(output) is int else output.fileno()
        info = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0
                or os.lseek(descriptor, 0, os.SEEK_CUR) != 0 or flags & os.O_APPEND
                or flags & os.O_ACCMODE == os.O_RDONLY):
            _fail("output_not_empty_regular_file")
        writer = (lambda data: os.write(descriptor, data)) if type(output) is int else output.write
        progress = _Progress(idle_timeout, stop)
        connector, resolver = _connector or _PinnedHTTPS, _resolver or socket.getaddrinfo
        for redirects in range(max_redirects + 1):
            progress.check_stop()
            address = _address(parsed.hostname, allowed_hosts, resolver, progress, connect_timeout)
            progress.check_stop()
            connection = connector(parsed.hostname, address, connect_timeout, progress)
            target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            connection.request("GET", target, headers={"Accept-Encoding": "identity",
                                                       "User-Agent": "Synthetic-Original-File/1",
                                                       "Connection": "close"})
            progress.mark_data()  # Start the header deadline after bounded connect/send.
            response = connection.getresponse()
            if response.status not in {301, 302, 303, 307, 308}:
                break
            locations = response.headers.get_all("Location", [])
            if len(locations) != 1 or redirects == max_redirects:
                _fail("source_redirect_rejected")
            parsed = _url(urljoin(parsed.geturl(), locations[0]))
            response.close(); response = None
            connection.close(); connection = None
        if response.status in {401, 403, 404, 410}:
            _fail("file_reference_unavailable")
        if response.status in {408, 425, 429} or 500 <= response.status <= 599:
            _fail("source_temporarily_unavailable")
        if response.status != 200:
            _fail("source_response_rejected")
        framing, declared = _framing(response)
        if expected_size_bytes is not None and declared is not None and declared != expected_size_bytes:
            _fail("expected_length_mismatch")
        digest, durable = hashlib.sha256(), 0

        def checkpoint():
            if type(output) is not int:
                output.flush()
            os.fsync(descriptor)
            current = os.fstat(descriptor)
            if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                    or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or current.st_size != count):
                _fail("output_identity_changed")
            if on_checkpoint is not None:
                try:
                    on_checkpoint({"durable_offset": count, "prefix_sha256": digest.hexdigest()})
                except Exception:
                    raise SourceError("checkpoint_failed") from None

        for chunk in _body(response, framing, declared, progress):
            progress.check_stop()
            if expected_size_bytes is not None and count + len(chunk) > expected_size_bytes:
                _fail("expected_length_mismatch")
            view = memoryview(chunk)
            while view:
                progress.check_stop()
                written = writer(view)
                if type(written) is not int or not 0 < written <= len(view):
                    _fail("output_write_failed")
                digest.update(view[:written])
                count += written
                view = view[written:]
            progress.check_stop()
            if count - durable >= checkpoint_bytes:
                checkpoint()
                durable = count
            progress.mark_data()
        progress.check_stop()
        if expected_size_bytes is not None and count != expected_size_bytes:
            _fail("expected_length_mismatch")
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            _fail("hash_mismatch")
        checkpoint()
        progress.check_stop()
        return {"protocol_complete": True, "bytes": count, "download_sha256": digest.hexdigest(),
                "http_version": "HTTP/1.1" if response.version == 11 else "HTTP/1.0", "framing": framing,
                "expected_hash_matched": True if expected_sha256 is not None else None,
                "expected_size_matched": True if expected_size_bytes is not None else None,
                "source_evidence_kind": "caller_hash_constraint" if expected_sha256 is not None else "reference_only",
                "expected_hash_provenance": "caller_supplied" if expected_sha256 is not None else None,
                "file_fsynced": True, "writer_exit_verified": False, "receive_complete_persisted": False}
    except SourceError as exc:
        raise SourceError(exc.code, bytes_received=count) from None
    except ssl.SSLEOFError:
        raise SourceError("transfer_incomplete", bytes_received=count) from None
    except ssl.SSLError:
        raise SourceError("source_tls_failed", bytes_received=count) from None
    except (socket.timeout, TimeoutError):
        raise SourceError("source_timeout", bytes_received=count) from None
    except OSError as exc:
        code = "insufficient_space" if exc.errno in {errno.ENOSPC, errno.EDQUOT} else (
            "filesystem_file_limit" if exc.errno == errno.EFBIG else "source_or_output_io_failed")
        raise SourceError(code, bytes_received=count) from None
    except (ValueError, TypeError, AttributeError, http.client.HTTPException):
        raise SourceError("source_protocol_failed", bytes_received=count) from None
    except Exception:
        raise SourceError("source_internal_error", bytes_received=count) from None
    finally:
        for handle in (response, connection):
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
