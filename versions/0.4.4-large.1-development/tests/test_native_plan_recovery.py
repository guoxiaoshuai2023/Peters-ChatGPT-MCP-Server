"""Portable native receiver recovery using genuine synthetic local part files."""
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from peters_mcp import native_range_receiver as helper


def file_hash(path):
    digest, count = hashlib.sha256(), 0
    with Path(path).open('rb') as source:
        while block := source.read(helper.BLOCK):
            count += len(block)
            digest.update(block)
    return count, digest.hexdigest()


class NativePlanRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-plan-recovery-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.inputs = self.root / 'native-inputs'
        self.old_output = self.root / 'old-output'
        self.new_output = self.root / 'new-output'
        for path in (self.inputs, self.old_output, self.new_output):
            path.mkdir(mode=0o700)
        self.original = self.root / 'external-synthetic.zip'
        def chunk(kind, data):
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
        self.png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 4, 4, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress((b'\0' + bytes((60, 120, 180)) * 4) * 4)) + chunk(b'IEND', b''))
        empty = io.BytesIO()
        with zipfile.ZipFile(empty, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('visual.png', self.png)
            archive.writestr('payload.bin', b'')
        with zipfile.ZipFile(self.original, 'x', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('visual.png', self.png)
            remaining = 2_400_000 - empty.tell()
            with archive.open('payload.bin', 'w') as payload:
                while remaining:
                    block = os.urandom(min(helper.BLOCK, remaining))
                    payload.write(block)
                    remaining -= len(block)
        self.bytes, self.sha = file_hash(self.original)
        self.assertEqual(self.bytes, 2_400_000)
        old_id, new_id = secrets.token_hex(16), secrets.token_hex(16)
        parts = []
        for index in range(3):
            name = f'original-{old_id}-part-{index:04d}.samplebin'
            self.copy_range(self.inputs / name, index * 800_000, 800_000)
            count, sha = file_hash(self.inputs / name)
            parts.append({'part_index': index, 'offset': index * 800_000,
                'bytes': count, 'sha256': sha, 'resource_name': name})
        self.old_plan = {'export_id': old_id, 'bytes': self.bytes, 'sha256': self.sha,
            'source': {'project_id': 'synthetic-project', 'worktree_id': 'synthetic-main',
                       'path': 'build/deliverables/synthetic.zip'}, 'parts': parts}
        self.new_plan = copy.deepcopy(self.old_plan)
        self.new_plan['export_id'] = new_id
        for part in self.new_plan['parts']:
            part['resource_name'] = f'original-{new_id}-part-{part["part_index"]:04d}.samplebin'
        self.old = helper.NativeRangeReceiver.start(self.old_plan, str(self.old_output),
            target_name='old-synthetic.zip', input_root=str(self.inputs))
        for index in (0, 1):
            self.old.ingest(index, str(self.old_path(index)))
        self.target = 'recovered-' + secrets.token_hex(8) + '.zip'

    def copy_range(self, path, offset, count):
        source = os.open(self.original, os.O_RDONLY | os.O_NOFOLLOW)
        target = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            position = 0
            while position < count:
                block = os.pread(source, min(helper.BLOCK, count - position), offset + position)
                helper._write(target, block)
                position += len(block)
            os.fsync(target)
        finally:
            os.close(target)
            os.close(source)

    def old_path(self, index):
        return self.inputs / self.old_plan['parts'][index]['resource_name']

    def new_path(self, index):
        return self.inputs / self.new_plan['parts'][index]['resource_name']

    def recover(self, *, plan=None, paths=None):
        return helper.NativeRangeReceiver.recover_new_plan(self.old.session_path,
            self.old_plan, plan or self.new_plan,
            paths if paths is not None else {i: str(self.old_path(i)) for i in (0, 1)},
            output_dir=str(self.new_output), input_root=str(self.inputs), target_name=self.target)

    def incomplete_session(self):
        names = list(self.new_output.glob('.native-range-*'))
        self.assertEqual(len(names), 1)
        return str(names[0])

    def finish(self, receiver):
        last = self.new_plan['parts'][2]
        self.copy_range(self.new_path(2), last['offset'], last['bytes'])
        receiver.ingest(2, str(self.new_path(2)))
        receipt = receiver.finish(require_zip=True)
        self.assertEqual(file_hash(receipt['file_path']), (self.bytes, self.sha))
        with zipfile.ZipFile(receipt['file_path']) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.read('visual.png'), self.png)
        self.assertEqual(receipt['state'], 'published_verified')
        self.assertTrue(receipt['whole_file_independently_reread'])
        self.assertTrue(receipt['zip_crc_checked'])
        return receipt

    def fail_writes_once(self, target_path, *, exit_process=None):
        original, failed = helper._write, []
        def fail(fd, data):
            if target_path.exists():
                named, actual = target_path.stat(), os.fstat(fd)
                if (named.st_dev, named.st_ino) == (actual.st_dev, actual.st_ino) and not failed:
                    failed.append(True)
                    original(fd, data[:1111])
                    os.fsync(fd)
                    if exit_process is not None:
                        os._exit(exit_process)
                    raise OSError(errno.EIO, 'synthetic interrupted write')
            return original(fd, data)
        return patch.object(helper, '_write', fail)

    def test_fresh_plan_reuses_actual_prefix_and_final_whole_with_persistent_mapping(self):
        previous = self.old.status()
        receiver = self.recover()
        status = receiver.status()
        self.assertNotEqual(status['receiver_nonce'], previous['receiver_nonce'])
        self.assertEqual(status['received_bytes'], 1_600_000)
        self.assertEqual(status['recovery']['state'], 'ready')
        self.assertEqual(self.old.status(), previous)
        self.assertEqual(receiver.ingest(0, str(self.new_path(0)))['appended_bytes'], 0)
        receiver = helper.NativeRangeReceiver.resume_recovery(receiver.session_path, self.new_plan)
        receipt = self.finish(receiver)
        mapping = json.loads(Path(receipt['recovery']['mapping_path']).read_text())
        self.assertTrue(mapping['original_complete'])
        self.assertEqual(mapping['binding']['old_export_id'], self.old_plan['export_id'])
        self.assertEqual(mapping['binding']['new_export_id'], self.new_plan['export_id'])
        self.assertEqual(mapping['binding']['prefix_bytes'], 1_600_000)
        self.assertEqual(receiver.finish(require_zip=True), receipt)
        self.old.cancel()
        self.old.cleanup()
        cleanup = receiver.cleanup()
        self.assertTrue(Path(cleanup['recovery_mapping_path']).exists())
        self.assertTrue(Path(receipt['file_path']).exists())
        self.assertTrue(self.old_path(0).exists())
        self.assertTrue(self.new_path(0).exists())

    def test_normal_alias_write_interruption_resumes_owned_partial_same_nonce(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError):
                self.recover()
        session = self.incomplete_session()
        nonce = Path(session).name.removeprefix(helper.PREFIX)
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        receiver = helper.NativeRangeReceiver.resume_recovery(session, self.new_plan)
        self.assertEqual(receiver.status()['receiver_nonce'], nonce)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.finish(receiver)

    def test_durable_intent_before_initial_journal_recovers_without_missing_bytes(self):
        original = helper._control_save
        interrupted = []
        def stop(session, name, value):
            if name == helper.RECOVERY_CONTROL and not interrupted:
                interrupted.append(True)
                raise OSError(errno.EIO, 'synthetic before initial journal')
            return original(session, name, value)
        with patch.object(helper, '_control_save', stop):
            with self.assertRaises(OSError):
                self.recover()
        session = self.incomplete_session()
        self.assertFalse(self.new_path(0).exists())
        self.assertFalse((Path(session) / helper.RECOVERY_CONTROL).exists())
        receiver = helper.NativeRangeReceiver.resume_recovery(session, self.new_plan)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.finish(receiver)

    def test_real_process_exit_during_alias_copy_then_normal_resume_success(self):
        arguments = self.root / 'arguments.json'
        arguments.write_text(json.dumps({'old_session': self.old.session_path,
            'old_plan': self.old_plan, 'new_plan': self.new_plan,
            'paths': {str(i): str(self.old_path(i)) for i in (0, 1)},
            'output': str(self.new_output), 'inputs': str(self.inputs), 'target': self.target}))
        child = r'''import json,os,sys
from pathlib import Path
from peters_mcp import native_range_receiver as h
v=json.loads(Path(sys.argv[1]).read_text()); p=Path(v['inputs'])/v['new_plan']['parts'][0]['resource_name']; original=h._write
def stop(fd,data):
    if p.exists():
        a,b=p.stat(),os.fstat(fd)
        if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino):
            original(fd,data[:1111]);os.fsync(fd);os._exit(37)
    return original(fd,data)
h._write=stop
h.NativeRangeReceiver.recover_new_plan(v['old_session'],v['old_plan'],v['new_plan'],{int(i):p for i,p in v['paths'].items()},output_dir=v['output'],input_root=v['inputs'],target_name=v['target'])
'''
        environment = os.environ.copy()
        environment['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
        result = subprocess.run([sys.executable, '-B', '-c', child, str(arguments)],
                                env=environment, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 37, result.stderr.decode())
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        receiver = helper.NativeRangeReceiver.resume_recovery(self.incomplete_session(), self.new_plan)
        self.finish(receiver)

    def test_receiver_pending_append_interruption_resumes_without_duplicate_bytes(self):
        original = helper._write
        failed = []
        def fail(fd, data):
            for path in self.new_output.glob('.native-range-*/receive.tmp'):
                named, actual = path.stat(), os.fstat(fd)
                if (named.st_dev, named.st_ino) == (actual.st_dev, actual.st_ino) and not failed:
                    failed.append(True)
                    original(fd, data[:1111]); os.fsync(fd)
                    raise OSError(errno.EIO, 'synthetic interrupted receiver append')
            return original(fd, data)
        with patch.object(helper, '_write', fail):
            with self.assertRaises(OSError):
                self.recover()
        session = self.incomplete_session()
        self.assertEqual((Path(session) / 'receive.tmp').stat().st_size, 1111)
        receiver = helper.NativeRangeReceiver.resume_recovery(session, self.new_plan)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.assertEqual(receiver.ingest(0, str(self.new_path(0)))['appended_bytes'], 0)
        self.finish(receiver)

    def test_durable_accepted_commit_before_journal_progress_reconciles_normally(self):
        original = helper.NativeRangeReceiver._save
        stopped = []
        def save(session, ledger):
            original(session, ledger)
            if 'recovery_binding' in ledger and ledger['accepted'] == [0] and not stopped:
                stopped.append(True)
                raise OSError(errno.EIO, 'synthetic after accepted fsync')
        with patch.object(helper.NativeRangeReceiver, '_save', staticmethod(save)):
            with self.assertRaises(OSError):
                self.recover()
        receiver = helper.NativeRangeReceiver.resume_recovery(self.incomplete_session(), self.new_plan)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.finish(receiver)

    def test_unknown_alias_created_before_owner_commit_is_preserved_and_refused(self):
        original = helper._control_save
        def stop(session, name, value):
            if name == helper.RECOVERY_CONTROL and value['aliases'][0]['phase'] == 'copying':
                raise OSError(errno.EIO, 'synthetic before ownership journal commit')
            return original(session, name, value)
        with patch.object(helper, '_control_save', stop):
            with self.assertRaises(OSError):
                self.recover()
        session = self.incomplete_session()
        with self.assertRaises(helper.ReceiverError) as error:
            helper.NativeRangeReceiver.resume_recovery(session, self.new_plan)
        self.assertEqual(error.exception.code, 'recovery_alias_ownership_unconfirmed')
        receiver = helper.NativeRangeReceiver.resume(session, self.new_plan)
        receiver.cancel()
        with self.assertRaises(helper.ReceiverError):
            receiver.cleanup()
        self.assertTrue(self.new_path(0).exists())
        self.assertTrue(Path(session).exists())

    def test_known_partial_alias_cancel_cleanup_keeps_inputs_and_mapping(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError):
                self.recover()
        receiver = helper.NativeRangeReceiver.resume(self.incomplete_session(), self.new_plan)
        receiver.cancel()
        result = receiver.cleanup()
        mapping = json.loads(Path(result['recovery_mapping_path']).read_text())
        self.assertFalse(mapping['original_complete'])
        self.assertEqual(mapping['receiver_state'], 'cancelled')
        self.assertEqual(mapping['journal']['aliases'][0]['phase'], 'copying')
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        self.assertTrue(self.old_path(0).exists())
        self.assertFalse(Path(receiver.session_path).exists())

    def test_changed_partial_alias_cannot_be_overwritten_or_completed(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError):
                self.recover()
        with self.new_path(0).open('r+b') as alias:
            alias.write(b'changed')
        with self.assertRaises(helper.ReceiverError) as error:
            helper.NativeRangeReceiver.resume_recovery(self.incomplete_session(), self.new_plan)
        self.assertEqual(error.exception.code, 'uncommitted_bytes_changed')
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        self.assertFalse((self.new_output / self.target).exists())

    def test_current_new_plan_scope_and_export_must_match_on_resume(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError):
                self.recover()
        for kind in ('scope', 'id'):
            altered = copy.deepcopy(self.new_plan)
            if kind == 'scope':
                altered['source']['project_id'] = 'synthetic-other'
            else:
                altered['export_id'] = secrets.token_hex(16)
            with self.assertRaises(helper.ReceiverError) as error:
                helper.NativeRangeReceiver.resume_recovery(self.incomplete_session(), altered)
            self.assertEqual(error.exception.code, 'recovery_new_plan_binding_changed')

    def test_existing_alias_scope_hash_or_missing_prefix_refuse_before_mutation(self):
        for kind in ('scope', 'whole_sha', 'part_sha', 'missing'):
            altered = copy.deepcopy(self.new_plan)
            paths = {i: str(self.old_path(i)) for i in (0, 1)}
            if kind == 'scope': altered['source']['path'] = 'other/synthetic.zip'
            if kind == 'whole_sha': altered['sha256'] = '0' * 64
            if kind == 'part_sha': altered['parts'][0]['sha256'] = '0' * 64
            if kind == 'missing': paths.pop(1)
            with self.assertRaises(helper.ReceiverError): self.recover(plan=altered, paths=paths)
            self.assertEqual(list(self.new_output.iterdir()), [])
        self.new_path(0).write_bytes(b'keep-existing')
        with self.assertRaises(helper.ReceiverError) as error: self.recover()
        self.assertEqual(error.exception.code, 'recovery_alias_already_exists')
        self.assertEqual(self.new_path(0).read_bytes(), b'keep-existing')

    def test_old_pending_tail_excluded_and_cancelled_old_session_supported(self):
        pending = Path(self.old.session_path) / 'receive.tmp'
        with self.fail_writes_once(pending):
            with self.assertRaises(OSError): self.old.ingest(2, str(self.old_path(2)))
        self.assertEqual(pending.stat().st_size, 1_601_111)
        self.old.cancel()
        receiver = self.recover()
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.assertEqual(receiver.status()['recovery']['old_pending_part_excluded'], 2)
        self.finish(receiver)

    def test_real_old_failed_publication_cannot_be_bypassed_by_new_nonce(self):
        self.old.ingest(2, str(self.old_path(2)))
        with patch.object(helper.os, 'link', side_effect=OSError(errno.EIO, 'synthetic publish failure')):
            with self.assertRaises(OSError): self.old.finish(require_zip=True)
        with self.assertRaises(helper.ReceiverError) as error: self.recover()
        self.assertEqual(error.exception.code, 'recovery_old_publication_requires_resolution')
        self.assertEqual(list(self.new_output.iterdir()), [])
        self.assertEqual(self.old.status()['state'], 'publishing')

    def test_space_and_new_target_preflight_refuse_without_aliases(self):
        fake = type('Space', (), {'f_bavail': 0, 'f_frsize': 1})()
        with patch.object(helper.os, 'fstatvfs', return_value=fake):
            with self.assertRaises(helper.ReceiverError) as error: self.recover()
        self.assertEqual(error.exception.code, 'insufficient_space')
        self.assertEqual(list(self.new_output.iterdir()), [])
        self.target = 'old-synthetic.zip'
        with self.assertRaises(helper.ReceiverError) as error: self.recover()
        self.assertEqual(error.exception.code, 'recovery_new_target_required')


if __name__ == '__main__':
    unittest.main()
