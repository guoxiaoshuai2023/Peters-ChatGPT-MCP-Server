"""Portable real-SDK 24 MB receiver regression; never web acceptance claims."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tracemalloc
import unittest
from tests import test_raw_range_transport as ranges
from peters_mcp.native_range_receiver import NativeRangeReceiver

class NativeReceiverSdkTests(unittest.TestCase):
    setUp=ranges.RealRangeSDKTests.setUp
    rpc=ranges.RealRangeSDKTests.rpc
    call=ranges.RealRangeSDKTests.call
    wait_released=ranges.RealRangeSDKTests.wait_released
    prepare=ranges.RealRangeSDKTests.prepare

    def test_real_sdk_24m_parts_receiver_resume_repeat_zip_and_exact_publication(self):
        expected,image=ranges.create_external_zip(self.repo/'original.zip',24_000_000)
        metadata=self.prepare()
        plan=json.loads(self.call('get_file_export_transport_plan',{'export_id':metadata['export_id']})['content'][0]['text'])
        inputs=self.root/'materialized-local-parts';inputs.mkdir()
        outputs=self.root/'independent-native-receiver';outputs.mkdir()
        self.assertFalse((outputs/'received-original.zip').exists())
        paths=[]
        for part in plan['parts']:
            result=self.call('materialize_file_export_part',{'export_id':metadata['export_id'],'part_index':part['part_index']})
            resource=result['content'][1]
            response=self.rpc('resources/read',{'uri':resource['uri']})
            raw=base64.b64decode(response.json()['result']['contents'][0]['blob'],validate=True)
            self.assertEqual(len(raw),part['bytes']);self.assertEqual(hashlib.sha256(raw).hexdigest(),part['sha256'])
            path=inputs/resource['name']
            with path.open('xb') as output:output.write(raw)
            paths.append(str(path));del raw,response
            self.wait_released()
        tracemalloc.start(1)
        try:
            base,_=tracemalloc.get_traced_memory()
            receiver=NativeRangeReceiver.start(plan,outputs,target_name='received-original.zip',input_root=inputs)
            receiver.ingest(0,paths[0])
            self.assertEqual(receiver.ingest(0,paths[0])['appended_bytes'],0)
            receiver=NativeRangeReceiver.resume(receiver.session_path,plan,input_root=inputs)
            for index in (1,2):receiver.ingest(index,paths[index])
            receipt=receiver.finish(require_zip=True)
            peak=tracemalloc.get_traced_memory()[1]-base
            self.assertLess(peak,2*1024*1024)
            self.assertEqual(receipt['bytes'],24_000_000);self.assertEqual(receipt['sha256'],expected)
            self.assertTrue(receipt['zip_crc_checked']);self.assertTrue(receipt['whole_file_independently_reread'])
            actual=hashlib.sha256()
            with Path(receipt['file_path']).open('rb') as final:
                for block in iter(lambda:final.read(65536),b''):actual.update(block)
            self.assertEqual(actual.hexdigest(),expected)
            self.assertEqual(json.loads((Path(receiver.session_path)/'receipt.json').read_text()),receipt)
            receiver.cleanup()
            self.assertTrue(Path(receipt['file_path']).exists())
            print('LOCAL_24M_NATIVE_RECEIVER_EVIDENCE',{'bytes':receipt['bytes'],'sha_match':True,
                  'zip_crc_checked':True,'helper_traced_peak_delta_bytes':peak,'local_sdk_not_web':True})
        finally:tracemalloc.stop()
        self.call('cancel_file_export',{'export_id':metadata['export_id']})

if __name__=='__main__':unittest.main()
