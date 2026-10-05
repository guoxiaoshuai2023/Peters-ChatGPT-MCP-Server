"""Independent standard JSON/base64 checks and fail-closed response templates."""
import base64
import json
from types import SimpleNamespace
import unittest
from peters_mcp.file_export import STREAM_CHUNK
from peters_mcp.file_export_tools import _Exchange, _stream_template
from tests.test_export_protocol import ExportProtocolTests

class TemplateValidationTests(unittest.TestCase):
    def setUp(self):
        self.marker = bytes(range(24))
        self.marker64 = base64.b64encode(self.marker).decode()
        self.uri = 'peters-export://' + 'a' * 32
        self.exchange = _Exchange(None, 1, lease=SimpleNamespace(marker=self.marker),
            request_id=17, resource_uri=self.uri, template_expected=True)
    def template(self, request_id=17):
        return {'jsonrpc':'2.0','id':request_id,'result':{
            'resultType':'complete','cacheScope':'private','ttlMs':0,
            'contents':[{'uri':self.uri,'mimeType':'application/octet-stream','blob':self.marker64}]}}
    def test_preserves_sdk_id_and_valid_json_for_base64_padding_boundaries(self):
        for request_id in (17, 0, 'quotes" slash/ Unicode中\nnewline'):
            self.exchange.request_id = request_id
            prefix,suffix = _stream_template(json.dumps(self.template(request_id)).encode(),self.exchange)
            for original in (b'',b'a',b'ab',b'abc',bytes(range(255))):
                received = json.loads(prefix+base64.b64encode(original)+suffix)
                self.assertEqual(received['id'],request_id)
                self.assertIs(type(received['id']),type(request_id))
                self.assertEqual(base64.b64decode(received['result']['contents'][0]['blob']),original)
                self.assertEqual(received['result']['cacheScope'],'private')
                self.assertEqual(received['result']['ttlMs'],0)
    def test_rejects_wrong_id_uri_blob_multiple_contents_and_public_cache(self):
        changes=[lambda v:v.update(id='17'),lambda v:v.update(id=True),
            lambda v:v['result']['contents'][0].update(uri='peters-export://'+'b'*32),
            lambda v:v['result']['contents'][0].update(blob='untrusted'),
            lambda v:v['result']['contents'].append(dict(v['result']['contents'][0])),
            lambda v:v['result'].update(cacheScope='public'),lambda v:v['result'].update(ttlMs=1000),
            lambda v:v['result'].update(ttlMs=False),lambda v:v['result'].update(resultType='input_required'),
            lambda v:v['result'].update(unrecognized='no'),lambda v:v['result']['contents'][0].update(text='no')]
        for change in changes:
            value=self.template();change(value)
            with self.assertRaises(ValueError):_stream_template(json.dumps(value).encode(),self.exchange)
    def test_duplicate_keys_oversize_and_marker_collision_are_rejected(self):
        body=json.dumps(self.template()).encode()
        with self.assertRaises(ValueError):_stream_template(body.replace(b'"id": 17',b'"id": 17, "id": 17'),self.exchange)
        with self.assertRaises(ValueError):_stream_template(body+b' '*16384,self.exchange)
        self.exchange.request_id=self.marker64
        with self.assertRaises(ValueError):_stream_template(json.dumps(self.template(self.marker64)).encode(),self.exchange)
        with self.assertRaises(ValueError):_stream_template(b'{broken',self.exchange)
    def test_nonfinite_json_metadata_is_rejected(self):
        for special in (float('nan'), float('inf'), -float('inf')):
            value=self.template();value['result']['_meta']={'invalid':special}
            with self.assertRaises(ValueError):_stream_template(json.dumps(value).encode(),self.exchange)
            value=self.template();value['result']['contents'][0]['_meta']={'invalid':special}
            with self.assertRaises(ValueError):_stream_template(json.dumps(value).encode(),self.exchange)

class RealStreamBoundaryTests(ExportProtocolTests):
    def test_actual_sdk_padding_chunk_boundaries_ids_and_content_length(self):
        for index,size in enumerate((0,1,2,3,STREAM_CHUNK-1,STREAM_CHUNK,STREAM_CHUNK+1)):
            with self.subTest(size=size):
                pattern=b'actual source\x00binary/+'
                original=(pattern*((size+len(pattern)-1)//len(pattern)))[:size]
                (self.repo/'original.zip').write_bytes(original)
                metadata,link=self.exported(key='boundary-'+str(index))
                request_id='actual"ID中\n'+str(size) if index%2 else index
                response=self.rpc('resources/read',{'uri':link['uri']},request_id=request_id)
                self.assertEqual(response.status_code,200,response.text[:200])
                self.assertEqual(int(response.headers['content-length']),len(response.content))
                result=response.json();self.assertEqual(result['id'],request_id)
                self.assertIs(type(result['id']),type(request_id))
                self.assertEqual(base64.b64decode(result['result']['contents'][0]['blob']),original)
                self.assertEqual(result['result']['cacheScope'],'private')
                self.wait_released()
                cancelled=self.call('cancel_file_export',{'export_id':metadata['export_id']})
                self.assertFalse(cancelled.get('isError'))
if __name__=='__main__':unittest.main()
