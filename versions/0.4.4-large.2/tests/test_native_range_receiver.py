"""Actual local materialized-part receiver boundaries; not web receipt claims."""
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from peters_mcp.native_range_receiver import NativeRangeReceiver, ReceiverError, normalize_plan, BLOCK

class NativeReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='native-receiver-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()
        self.inputs=self.root/'materialized';self.inputs.mkdir()
        self.output=self.root/'outputs';self.output.mkdir()
        self.data=os.urandom(BLOCK*3+500)
        parts=[];length=BLOCK+21
        for index,offset in enumerate(range(0,len(self.data),length)):
            raw=self.data[offset:offset+length];name='original-synthetic-part-'+str(index).zfill(4)+'.samplebin'
            (self.inputs/name).write_bytes(raw)
            parts.append({'part_index':index,'offset':offset,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'resource_name':name})
        self.plan={'bytes':len(self.data),'sha256':hashlib.sha256(self.data).hexdigest(),'source':{'path':'build/deliverables/synthetic-original.bin'},'parts':parts}
    def receiver(self,**kwargs):
        return NativeRangeReceiver.start(self.plan,self.output,target_name='received.bin',input_root=self.inputs,**kwargs)
    def path(self,index):return str(self.inputs/self.plan['parts'][index]['resource_name'])
    def all_parts(self,receiver):
        for part in self.plan['parts']:receiver.ingest(part['part_index'],self.path(part['part_index']))
    def test_actual_parts_repeat_resume_final_hash_and_no_clobber(self):
        receiver=self.receiver();first=receiver.ingest(0,self.path(0));duplicate=receiver.ingest(0,self.path(0))
        self.assertEqual(duplicate['appended_bytes'],0);self.assertEqual(duplicate['received_bytes'],first['received_bytes'])
        resumed=NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
        for part in self.plan['parts'][1:]:resumed.ingest(part['part_index'],self.path(part['part_index']))
        receipt=resumed.finish();self.assertEqual(receipt['state'],'published_verified')
        self.assertEqual((self.output/'received.bin').read_bytes(),self.data)
        self.assertEqual(receipt['sha256'],hashlib.sha256(self.data).hexdigest());self.assertEqual(resumed.finish(),receipt)
        with self.assertRaises(ReceiverError) as error:self.receiver()
        self.assertEqual(error.exception.code,'target_exists')
        self.assertTrue(resumed.cleanup()['final_and_materialized_inputs_preserved'])
        self.assertFalse(Path(resumed.session_path).exists());self.assertEqual((self.output/'received.bin').read_bytes(),self.data)
        self.assertEqual(json.loads(Path(receipt['receipt_path']).read_text()),receipt)
    def test_wrong_missing_order_and_hash_never_append(self):
        receiver=self.receiver()
        for index,path in [(1,self.path(1)),(0,str(self.inputs/'missing.samplebin'))]:
            with self.assertRaises(ReceiverError):receiver.ingest(index,path)
        wrong=self.inputs/self.plan['parts'][0]['resource_name'];wrong.write_bytes(b'wrong')
        with self.assertRaises(ReceiverError):receiver.ingest(0,str(wrong))
        self.assertEqual(receiver.status()['received_bytes'],0);self.assertEqual((Path(receiver.session_path)/'receive.tmp').stat().st_size,0)
        with self.assertRaises(ReceiverError):receiver.finish()
        self.assertFalse((self.output/'received.bin').exists())
    def test_symlinks_outside_root_target_collision_and_temp_replacement_rejected(self):
        receiver=self.receiver();original=self.inputs/self.plan['parts'][0]['resource_name'];raw=original.read_bytes()
        outside=self.root/'outside';outside.mkdir();(outside/original.name).write_bytes(raw)
        with self.assertRaises(ReceiverError):receiver.ingest(0,str(outside/original.name))
        original.unlink();original.symlink_to(outside/original.name)
        with self.assertRaises(ReceiverError):receiver.ingest(0,str(original))
        temp=Path(receiver.session_path)/'receive.tmp';temp.unlink();temp.write_bytes(b'');temp.chmod(0o600)
        with self.assertRaises(ReceiverError):receiver.status()
        with self.assertRaises(ReceiverError):receiver.cleanup()
        with self.assertRaises(ReceiverError):NativeRangeReceiver.start(self.plan,self.output,target_name='../escape')
    def test_interrupted_pending_append_resumes_same_actual_part_without_duplicate_bytes(self):
        receiver=self.receiver();nonce=receiver.status()['receiver_nonce'];target=Path(receiver.session_path)/'receive.tmp'
        identity=(target.stat().st_dev,target.stat().st_ino)
        from peters_mcp import native_range_receiver as helper
        original=helper._write;interrupted=[]
        def fail(fd,data):
            info=os.fstat(fd)
            if (info.st_dev,info.st_ino)==identity and not interrupted:
                interrupted.append(True);original(fd,data[:1111]);os.fsync(fd);raise OSError(errno.EIO,'synthetic interruption')
            return original(fd,data)
        with patch('peters_mcp.native_range_receiver._write',fail):
            with self.assertRaises(OSError):receiver.ingest(0,self.path(0))
        self.assertEqual(target.stat().st_size,1111)
        resumed=NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
        self.assertEqual(resumed.status()['receiver_nonce'],nonce);self.assertEqual(resumed.status()['pending_part_index'],0)
        resumed.ingest(0,self.path(0))
        for part in self.plan['parts'][1:]:resumed.ingest(part['part_index'],self.path(part['part_index']))
        self.assertEqual(Path(resumed.finish()['file_path']).read_bytes(),self.data)
    def test_corrupt_pending_or_committed_bytes_fail_without_synthesizing_or_truncating(self):
        receiver=self.receiver();receiver.ingest(0,self.path(0));temp=Path(receiver.session_path)/'receive.tmp'
        with temp.open('r+b') as file:file.write(b'X')
        with self.assertRaises(ReceiverError):NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
        self.assertEqual(temp.stat().st_size,self.plan['parts'][0]['bytes']);self.assertFalse((self.output/'received.bin').exists())
    def test_xb_publication_interruption_keeps_owned_identity_then_resume_success(self):
        receiver=self.receiver();self.all_parts(receiver)
        from peters_mcp import native_range_receiver as helper
        original=helper._write;interrupted=[]
        def fail(fd,data):
            info=os.fstat(fd);target=self.output/'received.bin'
            if target.exists() and info.st_ino==target.stat().st_ino and not interrupted:
                interrupted.append(True);original(fd,data[:2222]);os.fsync(fd);raise OSError(errno.EIO,'synthetic copy interruption')
            return original(fd,data)
        with patch('peters_mcp.native_range_receiver.os.link',side_effect=OSError(errno.EOPNOTSUPP,'synthetic unsupported')),patch('peters_mcp.native_range_receiver._write',fail):
            with self.assertRaises(OSError):receiver.finish()
        self.assertEqual((self.output/'received.bin').stat().st_size,2222);self.assertNotEqual(receiver.status()['state'],'published')
        self.assertFalse((Path(receiver.session_path)/'receipt.json').exists())
        resumed=NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs);receipt=resumed.finish()
        self.assertEqual(receipt['publication_method'],'xb_copy');self.assertEqual(Path(receipt['file_path']).read_bytes(),self.data);resumed.cleanup()
    def test_actual_link_before_ledger_commit_recovers_same_inode_without_overwrite(self):
        receiver=self.receiver();self.all_parts(receiver)
        actual=os.link
        def interrupted(*args,**kwargs):
            actual(*args,**kwargs)
            raise OSError(errno.EIO,'synthetic after-link interruption')
        with patch('peters_mcp.native_range_receiver.os.link',interrupted):
            with self.assertRaises(OSError):receiver.finish()
        self.assertEqual((self.output/'received.bin').read_bytes(),self.data)
        resumed=NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
        self.assertEqual(resumed.finish()['publication_method'],'link')
        resumed.cleanup()
        self.assertEqual((self.output/'received.bin').read_bytes(),self.data)

    def test_ledger_changed_between_load_and_lock_cannot_escape_or_change_target(self):
        receiver=self.receiver();original=NativeRangeReceiver._load;calls=[]
        def changed(fd):
            value=original(fd);calls.append(1)
            if len(calls)==2:value['target_name']='../escape.bin'
            return value
        with patch('peters_mcp.native_range_receiver.NativeRangeReceiver._load',staticmethod(changed)):
            with self.assertRaises(ReceiverError) as error:receiver.status()
        self.assertEqual(error.exception.code,'session_binding_changed')
        self.assertFalse((self.root/'escape.bin').exists())

    def test_owned_setgid_session_resume_same_nonce_and_part_succeeds_without_chmod_parent(self):
        # Native /mnt/data may be SGID. Only this synthetic test's own newly
        # created directories are changed; the helper never chmods any parent.
        before_parent=self.output.stat().st_mode
        receiver=self.receiver();session=Path(receiver.session_path)
        session.chmod(0o2700)
        self.assertEqual(session.stat().st_mode & 0o7777,0o2700)
        nonce=receiver.status()['receiver_nonce']
        resumed=NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
        self.assertEqual(resumed.status()['receiver_nonce'],nonce)
        for part in self.plan['parts']:resumed.ingest(part['part_index'],self.path(part['part_index']))
        receipt=resumed.finish()
        self.assertEqual(Path(receipt['file_path']).read_bytes(),self.data)
        self.assertEqual(session.stat().st_mode & 0o7777,0o2700)
        self.assertEqual(self.output.stat().st_mode,before_parent)
        resumed.cleanup()
        self.assertEqual(self.output.stat().st_mode,before_parent)

    def test_session_setuid_sticky_and_group_world_access_remain_rejected(self):
        for bits in (0o1700,0o4700,0o6700,0o710,0o701,0o770,0o777,0o2710,0o2701):
            receiver=self.receiver();session=Path(receiver.session_path)
            session.chmod(bits)
            with self.assertRaises(ReceiverError) as error:receiver.status()
            self.assertEqual(error.exception.code,'unsafe_session')
            with self.assertRaises(ReceiverError):NativeRangeReceiver.resume(receiver.session_path,self.plan,input_root=self.inputs)
            # Restore only this test's own control directory for exact cleanup.
            session.chmod(0o700);receiver.cancel();receiver.cleanup()

    def test_existing_target_during_receive_is_never_overwritten(self):
        receiver=self.receiver();self.all_parts(receiver);target=self.output/'received.bin';target.write_bytes(b'preexisting synthetic sentinel')
        with self.assertRaises(ReceiverError):receiver.finish()
        self.assertEqual(target.read_bytes(),b'preexisting synthetic sentinel')
    def test_space_failures_do_not_append_or_change_global_permissions(self):
        fake=type('Space',(),{'f_bavail':0,'f_frsize':1})()
        with patch('peters_mcp.native_range_receiver.os.fstatvfs',return_value=fake):
            with self.assertRaises(ReceiverError):self.receiver()
        receiver=self.receiver()
        with patch('peters_mcp.native_range_receiver.os.fstatvfs',return_value=fake):
            with self.assertRaises(ReceiverError):receiver.ingest(0,self.path(0))
        self.assertEqual(receiver.status()['received_bytes'],0)
    def test_cancel_cleanup_preserves_inputs_and_refuses_unlisted_or_replaced_files(self):
        receiver=self.receiver();receiver.ingest(0,self.path(0));receiver.cancel()
        with self.assertRaises(ReceiverError):receiver.finish()
        unknown=Path(receiver.session_path)/'unknown';unknown.write_bytes(b'keep')
        with self.assertRaises(ReceiverError):receiver.cleanup()
        self.assertTrue(unknown.exists());unknown.unlink();receiver.cleanup();self.assertTrue(Path(self.path(0)).exists())
    def test_plan_boundaries_and_ledger_nonce_tampering_rejected(self):
        for part_index in (True,'0',-1):
            altered=json.loads(json.dumps(self.plan));altered['parts'][0]['part_index']=part_index
            with self.assertRaises(ReceiverError):normalize_plan(altered)
        altered=json.loads(json.dumps(self.plan));altered['parts'][1]['offset']-=1
        with self.assertRaises(ReceiverError):normalize_plan(altered)
        receiver=self.receiver();ledger=Path(receiver.session_path)/'ledger.json';data=json.loads(ledger.read_text());data['nonce']='0'*32
        ledger.write_text(json.dumps(data));ledger.chmod(0o600)
        with self.assertRaises(ReceiverError):receiver.status()

if __name__=='__main__':unittest.main()
