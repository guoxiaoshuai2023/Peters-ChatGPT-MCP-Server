"""Only synthetic receiver children and private temporary files."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest

from peters_mcp.file_receiver import ReceiverHandle, atomic_json, Isolated, _send, MAX_MESSAGE
from peters_mcp.file_source import SourceError


def synthetic_receive(file, output, allowed_hosts, *, expected_sha256=None, expected_size_bytes=None,
                      stop=None, on_checkpoint=None):
    """Constructor-only spawn-safe transport seam, never registered as a tool."""
    identity = file['file_id']
    if identity == 'expired':
        raise SourceError('file_reference_unavailable')
    size = expected_size_bytes if expected_size_bytes is not None else 32
    pattern = b'\x00\xffsynthetic\r\n'
    digest = hashlib.sha256()
    count = 0
    while count < size:
        if stop and stop():
            raise SourceError('transfer_cancelled')
        block = (pattern * 6000)[:min(65536, size - count)]
        view = memoryview(block)
        while view:
            written = os.write(output, view)
            digest.update(view[:written])
            count += written
            view = view[written:]
        if identity == 'slow':
            time.sleep(.04)
    os.fsync(output)
    if on_checkpoint:
        on_checkpoint({'durable_offset': count, 'prefix_sha256': digest.hexdigest()})
    if expected_sha256 and expected_sha256 != digest.hexdigest():
        raise SourceError('hash_mismatch')
    return {'protocol_complete': True, 'file_fsynced': True, 'bytes': count,
            'download_sha256': digest.hexdigest(), 'http_version': 'synthetic', 'framing': 'synthetic_complete',
            'expected_hash_matched': True if expected_sha256 else None,
            'expected_hash_provenance': 'caller_supplied' if expected_sha256 else None,
            'source_evidence_kind': 'caller_hash_constraint' if expected_sha256 else 'reference_only'}


class ReceiverTests(unittest.TestCase):
    def test_control_frame_contains_policy_and_long_reference_but_is_bounded(self):
        class Sink:
            def sendall(self, raw):
                self.raw = raw
        sink = Sink()
        _send(sink, {'sources': {'synthetic': 'x' * 65500},
                     'file': {'download_url': 'https://files.example.invalid/' + 'x' * 16000}})
        self.assertLessEqual(len(sink.raw), MAX_MESSAGE)
        with self.assertRaises(Isolated):
            _send(sink, {'oversized': 'x' * MAX_MESSAGE})

    def test_permit_gate_completion_and_actual_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            payload = directory / 'payload'
            payload.touch(mode=0o600)
            info = payload.stat()
            handle = ReceiverHandle.spawn(directory, 'synthetic-attempt', 1, 1,
                                          [info.st_dev, info.st_ino], receiver=synthetic_receive, min_free_bytes=0)
            try:
                self.assertEqual(handle.command('status')['state'], 'awaiting_permission')
                self.assertEqual(payload.stat().st_size, 0)
                handle.permit({'file_id': 'normal', 'download_url': 'https://files.example.invalid/a'}, {}, None, 32)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = handle.command('status')
                    if state['state'] == 'received':
                        break
                    time.sleep(.02)
                self.assertEqual(state['state'], 'received')
                self.assertTrue(state['writer_closed'])
                self.assertFalse(handle.exited())
                self.assertTrue(handle.release())
                self.assertTrue(handle.exited())
                self.assertEqual(hashlib.sha256(payload.read_bytes()).hexdigest(), state['receipt']['download_sha256'])
            finally:
                handle.stop(1, force_owned=True)
                handle.dispose()

    def test_cancel_and_unknown_instance_never_signal_another_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            payload = directory / 'payload'
            payload.touch(mode=0o600)
            info = payload.stat()
            handle = ReceiverHandle.spawn(directory, 'slow-attempt', 1, 1,
                                          [info.st_dev, info.st_ino], receiver=synthetic_receive, min_free_bytes=0)
            try:
                wrong = dict(handle.ticket, identity={**handle.ticket['identity'], 'start_usec': -1})
                with self.assertRaises(Isolated):
                    ReceiverHandle(wrong).command('stop')
                handle.permit({'file_id': 'slow', 'download_url': 'https://files.example.invalid/a'}, {}, None, 20 * 1024 * 1024)
                self.assertTrue(handle.stop(3))
                self.assertTrue(handle.exited())
                self.assertLess(payload.stat().st_size, 20 * 1024 * 1024)
            finally:
                handle.stop(1, force_owned=True)
                handle.dispose()


if __name__ == '__main__':
    unittest.main()
