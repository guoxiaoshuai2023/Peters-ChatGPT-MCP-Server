"""Detached native-prefix recovery boundaries; synthetic bytes, no web claims."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from peters_mcp import native_range_receiver as h
from test_native_plan_recovery import NativePlanRecoveryTests as _Fixture
_fixture_setup = _Fixture.setUp
_fixture_copy = _Fixture.copy_range
_fixture_old_path = _Fixture.old_path
_fixture_new_path = _Fixture.new_path
_fixture_finish = _Fixture.finish
_fixture_fail = _Fixture.fail_writes_once
del _Fixture  # Do not rediscover the imported fixture's existing test class here.


class DetachedPrefixTests(unittest.TestCase):
    copy_range = _fixture_copy
    old_path = _fixture_old_path
    new_path = _fixture_new_path
    finish = _fixture_finish
    fail_writes_once = _fixture_fail

    def setUp(self):
        _fixture_setup(self)
        self.missing_old_session = self.old.session_path
        shutil.rmtree(self.missing_old_session)
        self.assertFalse(Path(self.missing_old_session).exists())

    def sources(self, count=2):
        return {i: {'path': str(self.old_path(i)), 'source_export_id': self.old_plan['export_id']}
                for i in range(count)}

    def recover(self, *, plan=None, sources=None, plans=None, old_root=None, target=None):
        return h.NativeRangeReceiver.recover_detached_prefix(
            plans if plans is not None else {self.old_plan['export_id']: self.old_plan},
            plan if plan is not None else self.new_plan,
            sources if sources is not None else self.sources(),
            old_input_root=str(old_root or self.inputs), output_dir=str(self.new_output),
            input_root=str(self.inputs), target_name=target or self.target)

    def session(self):
        names = list(self.new_output.glob('.native-range-*'))
        self.assertEqual(len(names), 1)
        return str(names[0])

    def assert_untouched(self):
        self.assertEqual(list(self.new_output.iterdir()), [])
        self.assertFalse(self.new_path(0).exists())
        self.assertFalse(self.new_path(1).exists())

    def test_missing_real_old_ledger_normal_whole_zip_and_persistent_provenance(self):
        old_before = [self.old_path(i).read_bytes() for i in (0, 1)]
        receiver = self.recover()
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.assertEqual(receiver.status()['parts_verified'], 2)
        self.assertEqual(receiver.ingest(0, str(self.new_path(0)))['appended_bytes'], 0)
        receiver = h.NativeRangeReceiver.resume_recovery(receiver.session_path, self.new_plan)
        receipt = self.finish(receiver)
        self.assertEqual(receipt['recovery']['recovery_mode'], 'detached_materialized_prefix')
        self.assertIsNone(receipt['recovery']['old_receiver_nonce'])
        self.assertFalse(receipt['recovery']['old_receiver_progress_claimed'])
        mapping = json.loads(Path(receipt['recovery']['mapping_path']).read_text())
        self.assertEqual(mapping['binding']['sources'][0]['source_export_id'], self.old_plan['export_id'])
        self.assertIsNone(mapping['binding']['old_session_path'])
        self.assertEqual([self.old_path(i).read_bytes() for i in (0, 1)], old_before)
        self.assertFalse(Path(self.missing_old_session).exists())
        receiver.cleanup()
        self.assertTrue(self.old_path(0).exists())
        self.assertTrue(self.new_path(0).exists())

    def mixed(self):
        second = copy.deepcopy(self.old_plan)
        second['export_id'] = secrets.token_hex(16)
        for part in second['parts']:
            part['resource_name'] = f'original-{second["export_id"]}-part-{part["part_index"]:04d}.samplebin'
        path = self.inputs / second['parts'][2]['resource_name']
        self.old_path(2).rename(path)
        sources = self.sources()
        sources[2] = {'path': str(path), 'source_export_id': second['export_id']}
        return sources, {self.old_plan['export_id']: self.old_plan, second['export_id']: second}

    def test_mixed_a0_a1_b2_all_actual_bytes_match_full_independent_zip(self):
        sources, plans = self.mixed()
        receiver = self.recover(sources=sources, plans=plans)
        self.assertEqual(receiver.status()['received_bytes'], self.bytes)
        receipt = receiver.finish(require_zip=True)
        path = Path(receipt['file_path'])
        self.assertEqual(path.stat().st_size, self.bytes)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.sha)
        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.read('visual.png'), self.png)
        self.assertEqual(receipt['recovery']['source_export_ids'], sorted(plans))
        self.assertTrue(Path(sources[2]['path']).exists())

    def test_source_scope_whole_piece_sha_geometry_and_id_change_refuse_before_mutation(self):
        cases = []
        for key in ('project_id', 'worktree_id', 'path'):
            changed = copy.deepcopy(self.new_plan); changed['source'][key] += '-different'; cases.append(changed)
        changed = copy.deepcopy(self.new_plan); changed['sha256'] = '0' * 64; cases.append(changed)
        changed = copy.deepcopy(self.new_plan); changed['parts'][0]['sha256'] = '1' * 64; cases.append(changed)
        changed = copy.deepcopy(self.new_plan)
        changed['parts'][0]['bytes'] -= 1; changed['parts'][1]['offset'] -= 1; changed['parts'][1]['bytes'] += 1
        cases.append(changed)
        changed = copy.deepcopy(self.new_plan); changed['export_id'] = self.old_plan['export_id']; cases.append(changed)
        for plan in cases:
            with self.assertRaises(h.ReceiverError): self.recover(plan=plan)
            self.assert_untouched()

    def test_mixed_provenance_missing_wrong_name_wrong_scope_or_conflicting_id_refuse(self):
        sources, plans = self.mixed()
        incomplete = dict(plans); incomplete.pop(sources[2]['source_export_id'])
        with self.assertRaises(h.ReceiverError): self.recover(sources=sources, plans=incomplete)
        wrong = copy.deepcopy(sources); wrong[2]['source_export_id'] = self.old_plan['export_id']
        with self.assertRaises(h.ReceiverError): self.recover(sources=wrong, plans=plans)
        bad = copy.deepcopy(plans); bad[sources[2]['source_export_id']]['source']['worktree_id'] = 'different'
        with self.assertRaises(h.ReceiverError): self.recover(sources=sources, plans=bad)
        bad = copy.deepcopy(plans); bad[sources[2]['source_export_id']]['export_id'] = self.old_plan['export_id']
        with self.assertRaises(h.ReceiverError): self.recover(sources=sources, plans=bad)
        self.assert_untouched()

    def test_noncontiguous_bool_empty_extra_plan_or_extra_source_fields_refuse(self):
        bad = [{1: self.sources()[1]}, {True: self.sources()[1]}, {}, {0: dict(self.sources()[0], extra=True)}]
        for sources in bad:
            with self.assertRaises(h.ReceiverError): self.recover(sources=sources)
            self.assert_untouched()
        plans = {self.old_plan['export_id']: self.old_plan, secrets.token_hex(16): self.old_plan}
        with self.assertRaises(h.ReceiverError): self.recover(plans=plans)
        self.assert_untouched()

    def test_missing_wrong_bytes_outside_root_and_symlink_source_refuse(self):
        sources = self.sources(); sources[0]['path'] = str(self.inputs / 'missing.samplebin')
        with self.assertRaises(h.ReceiverError): self.recover(sources=sources)
        outside = self.root / self.old_path(0).name
        outside.write_bytes(self.old_path(0).read_bytes())
        sources = self.sources(); sources[0]['path'] = str(outside)
        with self.assertRaises(h.ReceiverError): self.recover(sources=sources)
        self.old_path(0).unlink(); self.old_path(0).symlink_to(outside)
        with self.assertRaises(h.ReceiverError): self.recover()
        self.old_path(0).unlink(); self.old_path(0).write_bytes(b'wrong')
        with self.assertRaises(h.ReceiverError): self.recover()
        self.assert_untouched()

    def test_alias_and_target_collision_no_overwrite_and_multiple_source_links_refuse(self):
        self.new_path(0).write_bytes(b'sentinel')
        with self.assertRaises(h.ReceiverError): self.recover()
        self.assertEqual(self.new_path(0).read_bytes(), b'sentinel')
        self.new_path(0).unlink()
        target = self.new_output / self.target; target.write_bytes(b'target sentinel')
        with self.assertRaises(h.ReceiverError): self.recover()
        self.assertEqual(target.read_bytes(), b'target sentinel'); target.unlink()
        os.link(self.old_path(0), self.root / 'other-link')
        with self.assertRaises(h.ReceiverError): self.recover()
        self.assert_untouched()

    def test_owned_partial_alias_same_inode_normal_resume_success(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        inode = self.new_path(0).stat().st_ino
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        receiver = h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(self.new_path(0).stat().st_ino, inode)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.finish(receiver)

    def child_exit_during_copy(self, receive=False):
        args = self.root / 'synthetic-child-args.json'
        args.write_text(json.dumps({'plans': {self.old_plan['export_id']: self.old_plan},
            'new_plan': self.new_plan, 'sources': self.sources(), 'inputs': str(self.inputs),
            'output': str(self.new_output), 'target': self.target, 'receive': receive}))
        code = r'''import json,os,sys
from pathlib import Path
from peters_mcp import native_range_receiver as h
v=json.loads(Path(sys.argv[1]).read_text()); original=h._write
alias=Path(v['inputs'])/v['new_plan']['parts'][0]['resource_name']
def stop(fd,data):
    paths=list(Path(v['output']).glob('.native-range-*/receive.tmp')) if v['receive'] else [alias]
    for p in paths:
        if p.exists() and h._identity(p.stat())==h._identity(os.fstat(fd)):
            original(fd,data[:1111]);os.fsync(fd);os._exit(37)
    return original(fd,data)
h._write=stop
h.NativeRangeReceiver.recover_detached_prefix(v['plans'],v['new_plan'],{int(i):row for i,row in v['sources'].items()},old_input_root=v['inputs'],output_dir=v['output'],input_root=v['inputs'],target_name=v['target'])
'''
        env = os.environ.copy(); env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
        result = subprocess.run([sys.executable, '-B', '-c', code, str(args)], env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 37, result.stderr.decode())
        path = Path(self.session()) / 'receive.tmp' if receive else self.new_path(0)
        self.assertEqual(path.stat().st_size, 1111)
        receiver = h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        self.finish(receiver)

    def test_real_child_process_stopped_during_alias_then_normal_resume_complete(self):
        self.child_exit_during_copy()

    def test_real_child_process_stopped_during_receive_pending_then_normal_resume_complete(self):
        self.child_exit_during_copy(receive=True)

    def test_alias_owner_unknown_before_fsync_gap_preserved_and_refused(self):
        original, stopped = h._control_save, []
        def stop(session, name, value):
            if name == h.RECOVERY_CONTROL and value['aliases'][0]['phase'] == 'copying' and not stopped:
                stopped.append(True); raise OSError(errno.EIO, 'synthetic before ownership fsync')
            return original(session, name, value)
        with patch.object(h, '_control_save', stop):
            with self.assertRaises(OSError): self.recover()
        inode = self.new_path(0).stat().st_ino
        self.assertEqual(self.new_path(0).stat().st_size, 0)
        with self.assertRaises(h.ReceiverError) as error:
            h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(error.exception.code, 'recovery_alias_ownership_unconfirmed')
        self.assertEqual(self.new_path(0).stat().st_ino, inode)

    def test_unknown_or_changed_alias_cannot_be_adopted_or_overwritten(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        with self.new_path(0).open('r+b') as file: file.write(b'X')
        with self.assertRaises(h.ReceiverError): h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(self.new_path(0).read_bytes()[0], ord('X'))
        self.new_path(0).rename(self.root / 'kept-known-partial')
        self.new_path(0).write_bytes(b'foreign')
        with self.assertRaises(h.ReceiverError): h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(self.new_path(0).read_bytes(), b'foreign')

    def test_source_changed_after_intent_refuses(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        with self.old_path(0).open('r+b') as file: file.write(b'X')
        with self.assertRaises(h.ReceiverError): h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(self.new_path(0).stat().st_size, 1111)

    def test_source_root_replaced_after_intent_same_names_and_bytes_refuses(self):
        separate = self.root / 'old-materialized-root'; separate.mkdir(mode=0o700)
        sources = self.sources()
        for i in (0, 1):
            path = separate / self.old_path(i).name
            self.old_path(i).rename(path); sources[i]['path'] = str(path)
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover(sources=sources, old_root=separate)
        kept = self.root / 'kept-old-materialized-root'; separate.rename(kept)
        separate.mkdir(mode=0o700)
        for i in (0, 1):
            (separate / Path(sources[i]['path']).name).write_bytes((kept / Path(sources[i]['path']).name).read_bytes())
        with self.assertRaises(h.ReceiverError) as error:
            h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(error.exception.code, 'recovery_preserved_root_changed')
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        self.assertTrue(kept.exists())

    def test_ready_detached_prefix_no_longer_depends_on_old_root_for_rest_and_cleanup(self):
        separate = self.root / 'old-materialized-root'; separate.mkdir(mode=0o700)
        sources = self.sources()
        for i in (0, 1):
            path = separate / self.old_path(i).name
            self.old_path(i).rename(path); sources[i]['path'] = str(path)
        receiver = self.recover(sources=sources, old_root=separate)
        self.assertEqual(receiver.status()['recovery']['state'], 'ready')
        separate.rename(self.root / 'archived-materialized-root')
        self.assertFalse(separate.exists())
        receiver = h.NativeRangeReceiver.resume_recovery(receiver.session_path, self.new_plan)
        self.assertEqual(receiver.status()['received_bytes'], 1_600_000)
        receipt = self.finish(receiver)
        self.assertEqual(receipt['recovery']['reused_prefix_bytes'], 1_600_000)
        self.assertTrue(receiver.cleanup()['final_and_materialized_inputs_preserved'])

    def test_cancel_cleanup_keeps_known_partial_even_when_old_root_unavailable(self):
        separate = self.root / 'old-materialized-root'; separate.mkdir(mode=0o700)
        sources = self.sources()
        for i in (0, 1):
            path = separate / self.old_path(i).name
            self.old_path(i).rename(path); sources[i]['path'] = str(path)
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover(sources=sources, old_root=separate)
        receiver = h.NativeRangeReceiver.resume(self.session(), self.new_plan)
        receiver.cancel()
        separate.rename(self.root / 'archived-materialized-root')
        with self.assertRaises(h.ReceiverError) as error:
            h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(error.exception.code, 'receiver_not_accepting')
        cleanup = receiver.cleanup()
        self.assertTrue(Path(cleanup['recovery_mapping_path']).exists())
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        self.assertFalse(Path(receiver.session_path).exists())

    def test_low_disk_before_and_after_partial_refuses_without_fabrication(self):
        none = type('Space', (), {'f_bavail': 0, 'f_frsize': 1})()
        with patch.object(h.os, 'fstatvfs', return_value=none):
            with self.assertRaises(h.ReceiverError): self.recover()
        self.assert_untouched()
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        with patch.object(h.os, 'fstatvfs', return_value=none):
            with self.assertRaises(h.ReceiverError): h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(self.new_path(0).stat().st_size, 1111)
        self.finish(h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan))

    def test_cancelled_detached_receiver_not_automatically_restarted(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        receiver = h.NativeRangeReceiver.resume(self.session(), self.new_plan)
        receiver.cancel()
        with self.assertRaises(h.ReceiverError) as error:
            h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan)
        self.assertEqual(error.exception.code, 'receiver_not_accepting')
        with self.assertRaises(h.ReceiverError): receiver.finish()
        cleanup = receiver.cleanup()
        self.assertTrue(Path(cleanup['recovery_mapping_path']).exists())
        self.assertTrue(self.old_path(0).exists())
        self.assertTrue(self.new_path(0).exists())

    def test_resume_new_scope_or_export_changed_refuses(self):
        with self.fail_writes_once(self.new_path(0)):
            with self.assertRaises(OSError): self.recover()
        for field in ('scope', 'export'):
            changed = copy.deepcopy(self.new_plan)
            if field == 'scope': changed['source']['path'] = 'other/unchanged-name.zip'
            else: changed['export_id'] = secrets.token_hex(16)
            with self.assertRaises(h.ReceiverError): h.NativeRangeReceiver.resume_recovery(self.session(), changed)
        self.finish(h.NativeRangeReceiver.resume_recovery(self.session(), self.new_plan))

    def test_source_root_symlink_or_unsafe_target_is_rejected(self):
        alias = self.root / 'symlink-root'; alias.symlink_to(self.inputs, target_is_directory=True)
        with self.assertRaises(h.ReceiverError): self.recover(old_root=alias)
        with self.assertRaises(h.ReceiverError): self.recover(target='../escape')
        self.assert_untouched()


if __name__ == '__main__':
    unittest.main()
