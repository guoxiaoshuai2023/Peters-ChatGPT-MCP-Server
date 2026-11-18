"""Synthetic wire/TLS tests. Test transport injection never relaxes URL policy."""

from datetime import datetime, timedelta, timezone
import errno
import hashlib
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import tracemalloc
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from peters_mcp.file_source import (
    CHUNK_BYTES, NativeFile, SourceError, _PinnedHTTPS, _Response,
    receive_file, retry_policy, source_identity,
)


HOST = "files.example.test"
PUBLIC_IP = "8.8.8.8"
FILE = NativeFile(download_url="https://files.example.test/source?secret=synthetic-signature",
                  file_id="synthetic-file-id", file_name="arbitrary.bin")


def wire(body=b"", headers=None, status=200):
    if headers is None:
        headers = [("Content-Length", str(len(body)))]
    return (f"HTTP/1.1 {status} Synthetic\r\n".encode() +
            b"".join(f"{name}: {value}\r\n".encode() for name, value in headers) + b"\r\n" + body)


class WireSocket:
    def __init__(self, data, *, eof_error=None, step=CHUNK_BYTES, delay=0):
        self.data, self.offset = data, 0
        self.eof_error, self.step, self.delay = eof_error, step, delay

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        if self.delay:
            time.sleep(self.delay)
        if self.offset == len(self.data) and self.eof_error:
            raise self.eof_error
        end = min(len(self.data), self.offset + min(size, self.step))
        result = self.data[self.offset:end]
        self.offset = end
        return result


class WireConnection:
    def __init__(self, sock, progress):
        self.sock, self.progress = sock, progress
        self.request_values = None
        self.closed = False

    def request(self, method, target, headers):
        self.request_values = (method, target, headers)

    def getresponse(self):
        response = _Response(self.sock, self.progress, method="GET")
        response.begin()
        return response

    def close(self):
        self.closed = True


class ShortWriter:
    def __init__(self, file, chunk=7, after_write=None):
        self.file, self.chunk, self.after_write = file, chunk, after_write

    def fileno(self):
        return self.file.fileno()

    def write(self, data):
        count = os.write(self.fileno(), data[:self.chunk])
        if self.after_write:
            self.after_write()
        return count

    def flush(self):
        self.file.flush()


class FileSourceTests(unittest.TestCase):
    def setUp(self):
        self.output = tempfile.NamedTemporaryFile(mode="w+b")
        self.addCleanup(self.output.close)
        self.connections, self.calls = [], []

    def connector(self, replies, **socket_options):
        iterator = iter(replies)

        def connect(host, address, timeout, progress):
            self.calls.append((host, address))
            result = WireConnection(WireSocket(next(iterator), **socket_options), progress)
            self.connections.append(result)
            return result
        return connect

    def receive(self, reply, **kwargs):
        options = {"allowed_hosts": {HOST: [PUBLIC_IP]}, "_connector": self.connector([reply])}
        options.update(kwargs)
        return receive_file(FILE, self.output, **options)

    def error(self, code, reply, **kwargs):
        with self.assertRaises(SourceError) as raised:
            self.receive(reply, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn("synthetic-signature", str(raised.exception))
        self.assertNotIn("https://", str(raised.exception))
        return raised.exception

    def test_native_schema_and_reference_retry_do_not_claim_content_identity(self):
        schema = NativeFile.model_json_schema()
        self.assertEqual(set(schema["properties"]), {"download_url", "file_id", "mime_type", "file_name"})
        self.assertEqual(set(schema["required"]), {"download_url", "file_id"})
        same = FILE.model_copy(update={"download_url": "https://files.example.test/new?secret=different"})
        self.assertEqual(source_identity(FILE), source_identity(same))
        self.assertFalse(source_identity(FILE)["content_identity_verified"])
        self.assertNotIn("synthetic-signature", repr(FILE))
        self.assertFalse(retry_policy()["same_job_retry_allowed"])
        self.assertTrue(retry_policy("a" * 64)["same_job_retry_allowed"])
        self.assertFalse(retry_policy("a" * 64)["range_resume_allowed"])

    def test_original_binary_bytes_length_and_hash_preserved(self):
        body = b"\x00\xff\xef\xbb\xbf\r\n" * 40
        digest = hashlib.sha256(body).hexdigest()
        receipt = self.receive(wire(body), expected_sha256=digest, expected_size_bytes=len(body))
        self.output.seek(0)
        self.assertEqual(self.output.read(), body)
        self.assertEqual(receipt["download_sha256"], digest)
        self.assertEqual(receipt["bytes"], len(body))
        self.assertTrue(receipt["protocol_complete"])
        self.assertTrue(receipt["expected_hash_matched"])
        self.assertFalse(receipt["writer_exit_verified"])
        self.assertFalse(receipt["receive_complete_persisted"])
        self.assertFalse(self.output.closed)
        self.assertTrue(all(connection.closed for connection in self.connections))
        self.assertNotIn("synthetic", repr(receipt))

    def test_legal_empty_content_length_has_explicit_completion(self):
        checkpoints = []
        receipt = self.receive(wire(), expected_size_bytes=0, on_checkpoint=checkpoints.append)
        self.assertTrue(receipt["protocol_complete"])
        self.assertEqual(receipt["bytes"], 0)
        self.assertEqual(checkpoints[0]["durable_offset"], 0)
        self.assertIsNone(receipt["expected_hash_matched"])

    def test_chunked_without_length_and_valid_trailer_preserves_bytes(self):
        body = b'3;name="a;b"\r\nabc\r\n2\r\n\x00\xff\r\n0\r\nX-Synthetic: yes\r\n\r\n'
        receipt = self.receive(wire(body, [("Transfer-Encoding", "chunked")]))
        self.assertEqual(receipt["framing"], "chunked")
        self.output.seek(0)
        self.assertEqual(self.output.read(), b"abc\x00\xff")

    def test_empty_chunked_is_complete(self):
        self.assertEqual(self.receive(wire(b"0\r\n\r\n", [("Transfer-Encoding", "chunked")]))["bytes"], 0)

    def test_truncated_length_never_completes(self):
        self.error("transfer_incomplete", wire(b"abc", [("Content-Length", "4")]))

    def test_empty_payload_does_not_hide_incomplete_or_invalid_headers(self):
        for response in (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
                         b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n"):
            with self.subTest(response=response):
                self.error("response_headers_incomplete", response)
        self.error("response_headers_invalid", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                   b"Invalid header\r\n\r\n")

    def test_integer_fd_is_borrowed_and_stop_checker_error_is_sanitized(self):
        receipt = receive_file(FILE, self.output.fileno(), {HOST: [PUBLIC_IP]},
                               _connector=self.connector([wire(b"borrowed")]))
        self.assertEqual(receipt["bytes"], 8)
        self.assertGreater(os.fstat(self.output.fileno()).st_ino, 0)
        with tempfile.NamedTemporaryFile(mode="w+b") as empty:
            def check():
                raise RuntimeError("private-stop-callback-secret")
            with self.assertRaises(SourceError) as raised:
                receive_file(FILE, empty, {HOST: [PUBLIC_IP]}, stop=check)
            self.assertEqual(str(raised.exception), "stop_check_failed")

    def test_duplicate_or_ambiguous_lengths_and_encodings_rejected(self):
        for headers in ([('Content-Length', '0'), ('Content-Length', '0')],
                        [('Content-Length', '0, 0')], [('Content-Length', '-1')],
                        [('Content-Length', '+1')], [('Transfer-Encoding', 'chunked'), ('Content-Length', '0')],
                        [('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')]):
            with self.subTest(headers=headers):
                self.error("response_framing_invalid", wire(b"", headers))
        self.error("response_encoding_unsupported", wire(b"", [('Content-Length', '0'), ('Content-Encoding', 'gzip')]))

    def test_chunk_termination_and_trailer_eof_strictness(self):
        for body, code in ((b"3\r\nabcXX0\r\n\r\n", "chunk_framing_invalid"),
                           (b"3\r\nabc\r\n", "chunk_framing_invalid"),
                           (b"3\r\nab", "transfer_incomplete"),
                           (b"0\r\n", "chunk_trailer_invalid"),
                           (b"0\r\nX-Field: yes\r\n", "chunk_trailer_invalid"),
                           (b"0\r\n\n", "chunk_trailer_invalid"),
                           (b"0\r\nContent-Length: 0\r\n\r\n", "chunk_trailer_invalid")):
            with self.subTest(body=body), tempfile.NamedTemporaryFile(mode="w+b") as output:
                with self.assertRaises(SourceError) as raised:
                    receive_file(FILE, output, {HOST: [PUBLIC_IP]},
                                 _connector=self.connector([wire(body, [("Transfer-Encoding", "chunked")])]))
                self.assertEqual(raised.exception.code, code)

    def test_tls_unexpected_eof_does_not_complete(self):
        connect = self.connector([wire(b"ab", [("Content-Length", "3")])],
                                 eof_error=ssl.SSLEOFError("synthetic private URL secret"))
        self.error("transfer_incomplete", b"", _connector=connect)

    def test_unverifiable_close_delimited_is_rejected_before_body_write(self):
        self.error("completion_unverifiable", wire(b"ambiguous", [("Connection", "close")]))
        self.assertEqual(os.fstat(self.output.fileno()).st_size, 0)

    def test_expected_constraints_and_partial_responses(self):
        self.error("expected_length_mismatch", wire(b"abc"), expected_size_bytes=4)
        self.error("source_response_rejected", wire(b"", status=206))
        self.error("unexpected_partial_response", wire(b"", [('Content-Length', '0'), ('Content-Range', 'bytes 0-0/1')]))
        self.error("hash_mismatch", wire(b"abc"), expected_sha256="a" * 64)

    def test_large_file_stream_is_bounded_and_checkpoints_follow_fsync(self):
        payload = b"a" * (9 * 1024 * 1024 + 11)
        reply = wire(payload)
        checkpoints = []
        fsyncs = []
        real_sync = os.fsync

        def synced(fd):
            real_sync(fd)
            fsyncs.append(os.fstat(fd).st_size)

        def checkpoint(record):
            self.assertEqual(record["durable_offset"], fsyncs[-1])
            checkpoints.append(record)

        tracemalloc.start()
        try:
            with patch("peters_mcp.file_source.os.fsync", side_effect=synced):
                receipt = self.receive(reply, on_checkpoint=checkpoint)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(receipt["bytes"], len(payload))
        self.assertEqual(receipt["download_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertLess(peak, 2 * 1024 * 1024)
        self.assertGreater(len(checkpoints), 8)

    def test_partial_writes_are_completed_and_zero_writes_rejected(self):
        raw = b"abcdef\x00\xff" * 1000
        writer = ShortWriter(self.output)
        receipt = receive_file(FILE, writer, {HOST: [PUBLIC_IP]}, _connector=self.connector([wire(raw)]))
        self.assertEqual(receipt["download_sha256"], hashlib.sha256(raw).hexdigest())
        self.output.seek(0)
        self.assertEqual(self.output.read(), raw)
        with tempfile.NamedTemporaryFile(mode="w+b") as empty:
            with self.assertRaises(SourceError) as raised:
                receive_file(FILE, ShortWriter(empty, chunk=0), {HOST: [PUBLIC_IP]},
                             _connector=self.connector([wire(b"a")]))
            self.assertEqual(raised.exception.code, "output_write_failed")

    def test_checkpoint_exception_and_cancellation_never_return_complete(self):
        def bad_checkpoint(record):
            raise RuntimeError("secret callback message")
        self.error("checkpoint_failed", wire(b"x"), on_checkpoint=bad_checkpoint)
        with tempfile.NamedTemporaryFile(mode="w+b") as empty:
            event = threading.Event()
            writer = ShortWriter(empty, after_write=event.set)
            with self.assertRaises(SourceError) as raised:
                receive_file(FILE, writer, {HOST: [PUBLIC_IP]}, stop=event,
                             _connector=self.connector([wire(b"x" * 1000)]))
            self.assertEqual(raised.exception.code, "transfer_cancelled")
            self.assertFalse(empty.closed)
        event = threading.Event(); event.set()
        with tempfile.NamedTemporaryFile(mode="w+b") as empty:
            with self.assertRaisesRegex(SourceError, "transfer_cancelled"):
                receive_file(FILE, empty, {HOST: [PUBLIC_IP]}, stop=event)

    def test_space_failure_is_classified_without_exception_details(self):
        with patch("peters_mcp.file_source.os.fsync", side_effect=OSError(errno.ENOSPC, "secret location")):
            self.error("insufficient_space", wire(b"x"))

    def test_real_source_preserves_only_fixed_receiver_stop_signals(self):
        def no_space():
            raise SourceError('insufficient_space')

        self.error('insufficient_space', wire(b'x'), stop=no_space)
        self.assertFalse(self.connections)
        self.assertEqual(os.fstat(self.output.fileno()).st_size, 0)

        def unsafe_error():
            raise SourceError('private-dynamic-secret')

        self.error('stop_check_failed', wire(b'x'), stop=unsafe_error)

    def test_temporary_http_failures_and_expired_references_are_distinct(self):
        for status in (408, 425, 429, 500, 502, 503, 504, 599):
            with self.subTest(status=status):
                self.error('source_temporarily_unavailable', wire(b'secret-error-body', status=status))
        for status in (401, 403, 404, 410):
            with self.subTest(status=status):
                self.error('file_reference_unavailable', wire(b'secret-error-body', status=status))
        self.assertEqual(os.fstat(self.output.fileno()).st_size, 0)

    def test_approved_redirect_rechecks_every_hop_and_forwards_no_credentials(self):
        replies = [wire(headers=[("Location", "https://next.example.test/file?secret=next")], status=302), wire(b"ok")]
        connector = self.connector(replies)
        receipt = self.receive(b"", allowed_hosts={HOST: [PUBLIC_IP], "next.example.test": ["1.1.1.1"]},
                               _connector=connector)
        self.assertEqual(receipt["bytes"], 2)
        self.assertEqual(self.calls, [(HOST, PUBLIC_IP), ("next.example.test", "1.1.1.1")])
        for connection in self.connections:
            method, target, headers = connection.request_values
            self.assertEqual(method, "GET")
            self.assertEqual(set(headers), {"Accept-Encoding", "User-Agent", "Connection"})
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)

    def test_redirect_private_unknown_host_and_loops_rejected(self):
        for location in ("http://files.example.test/file", "https://127.0.0.1/file",
                         "https://169.254.169.254/latest", "https://unknown.example.test/file"):
            with self.subTest(location=location):
                self.error("source_not_approved", wire(headers=[("Location", location)], status=302))
        self.error("source_redirect_rejected", b"", max_redirects=1,
                   _connector=self.connector([wire(headers=[("Location", "/next")], status=302)] * 2))

    def test_dns_and_explicit_addresses_must_all_be_public_and_are_pinned_once(self):
        for values in (["127.0.0.1"], [PUBLIC_IP, "198.18.0.1"], ["::ffff:8.8.8.8"], ["169.254.169.254"]):
            with self.subTest(values=values):
                self.error("source_nonpublic", wire(), allowed_hosts={HOST: values})
        resolutions = []

        def resolver(host, port, **kwargs):
            resolutions.append((host, port))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 443))]

        self.receive(wire(), allowed_hosts={HOST: None}, _resolver=resolver)
        self.assertEqual(resolutions, [(HOST, 443)])
        self.assertEqual(self.calls[-1], (HOST, PUBLIC_IP))

    def test_no_data_progress_timeout_in_headers_and_no_total_task_deadline(self):
        slow_header = self.connector([wire(b"data")], step=1, delay=0.005)
        self.error("transfer_idle_timeout", b"", idle_timeout=0.015, _connector=slow_header)
        # Resetting actual data progress permits a stream to exceed its idle budget.
        body = b"abcdef"
        header = wire(b"", [("Content-Length", str(len(body)))])

        class Drip(WireSocket):
            def recv(self, size):
                if self.offset < len(header):
                    size = len(header) - self.offset
                else:
                    time.sleep(0.01)
                    size = 1
                return super().recv(size)

        def connect(host, address, timeout, progress):
            return WireConnection(Drip(header + body), progress)

        started = time.monotonic()
        result = self.receive(b"", _connector=connect, idle_timeout=0.04)
        self.assertGreater(time.monotonic() - started, 0.04)
        self.assertEqual(result["bytes"], len(body))

    def test_dns_wait_has_a_bound_and_stop_checker_can_interrupt(self):
        release = threading.Event()

        def resolver(*args, **kwargs):
            release.wait(0.5)
            return []

        try:
            self.error("source_dns_timeout", wire(), allowed_hosts={HOST: None},
                       _resolver=resolver, connect_timeout=0.02)
        finally:
            release.set()

    def test_existing_output_and_hardlinks_are_not_modified(self):
        self.output.write(b"prior"); self.output.flush()
        self.error("output_not_empty_regular_file", wire(b"new"))
        self.output.seek(0)
        self.assertEqual(self.output.read(), b"prior")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "spool"
            with target.open("w+b") as output:
                os.link(target, Path(directory) / "another-name")
                with self.assertRaisesRegex(SourceError, "output_not_empty_regular_file"):
                    receive_file(FILE, output, {HOST: [PUBLIC_IP]},
                                 _connector=self.connector([wire(b"new")]))
                self.assertEqual(os.fstat(output.fileno()).st_size, 0)

    def test_real_loopback_tls_uses_hostname_and_connection_close_keeps_body_readable(self):
        # Loopback exists ONLY in this in-process connector seam. The ordinary
        # public-address validator above still executes and refuses private IPs.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                    .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
                    .sign(key, hashes.SHA256()))
            for filename, data in (("cert.pem", cert.public_bytes(serialization.Encoding.PEM)),
                                   ("key.pem", key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
                fd = os.open(base / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as file:
                    file.write(data)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(base / "cert.pem", base / "key.pem")
            names = []
            context.sni_callback = lambda sock, server_name, ctx: names.append(server_name)
            listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
            listener.settimeout(3)
            address = listener.getsockname()
            body = b"\x00\xffreal-tls\r\n" * 10000
            failures = []

            def serve():
                try:
                    sock, _ = listener.accept()
                    with context.wrap_socket(sock, server_side=True) as tls:
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            request.extend(tls.recv(1024))
                        tls.sendall(wire(body, [("Content-Length", str(len(body))), ("Connection", "close")]))
                except Exception:
                    failures.append(True)

            thread = threading.Thread(target=serve, daemon=True); thread.start()

            def connect(host, fixed_ip, timeout, progress):
                self.assertEqual((host, fixed_ip), (HOST, PUBLIC_IP))
                conn = _PinnedHTTPS(host, fixed_ip, timeout, progress)
                conn._context = ssl.create_default_context(cafile=str(base / "cert.pem"))

                def local_connect():
                    raw = socket.create_connection(address, timeout)
                    conn.sock = conn._context.wrap_socket(raw, server_hostname=host, suppress_ragged_eofs=False)

                conn.connect = local_connect
                return conn

            try:
                receipt = self.receive(b"", _connector=connect)
            finally:
                thread.join(3); listener.close()
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures)
            self.assertEqual(names, [HOST])
            self.assertEqual(receipt["download_sha256"], hashlib.sha256(body).hexdigest())
            self.output.seek(0)
            self.assertEqual(self.output.read(), body)


if __name__ == "__main__":
    unittest.main()
