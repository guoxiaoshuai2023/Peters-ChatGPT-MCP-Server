import asyncio
import base64
import hashlib
import io
import json
import logging
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from mcp.client import Client
from peters_mcp.audit import audit_actor, audit_request_id
from peters_mcp.catalog import Catalog
from peters_mcp.catalog import AccessError, INTERNAL_DELIVERY_PREFIX
from peters_mcp.delivery_policy import DeliveryPolicy
from peters_mcp.delivery_store import DeliveryStore
from peters_mcp.server import create_server
from peters_mcp.workspaces import RepositoryRegistry


class DeliveryToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'repo'; self.repo.mkdir()
        subprocess.run(['/usr/bin/git','init','-q','-b','main',str(self.repo)],check=True)
        (self.repo/'docs/packages').mkdir(parents=True)
        projects = self.base/'projects.json'
        projects.write_text(json.dumps({'projects':[{'id':'synthetic','name':'Synthetic','root':str(self.repo),
                                'repository_id':RepositoryRegistry.identity(self.repo)}]}))
        self.catalog = Catalog.from_config(projects)
        config=self.base/'delivery.json'
        config.write_text(json.dumps({'version':1,'state_directory':str(self.base/'state'),
            'targets':[{'id':'test-packages','label':'Synthetic packages','project_id':'synthetic','parent_directory':'docs/packages'}],
            'sources':{'files.example.com':None},'limits':{}}))
        self.policy = DeliveryPolicy(config,self.catalog)
        self.raw_files = {'plan-v1.0.md': b'\xef\xbb\xbf# Synthetic plan\r\n'+b'x'*58416,
                          'config.json':b'{"synthetic":true}\r\n'}
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            for name,data in self.raw_files.items():archive.writestr(name,data)
        self.archive=stream.getvalue()
        self.sha=hashlib.sha256(self.archive).hexdigest()
        self.logs=io.StringIO()
        audit=logging.Logger('test.delivery');audit.addHandler(logging.StreamHandler(self.logs))
        def download(file,destination,expected_sha256,sources,limits):
            with destination.open('xb') as output:output.write(self.archive)
            return {'size_bytes':len(self.archive),'sha256':self.sha}
        self.store=DeliveryStore(self.policy.state_directory,self.policy,downloader=download,audit=audit)
        self.addCleanup(self.store.close)
        self.server=create_server(self.catalog,audit,packages=self.store)
        self.actor=hashlib.sha256(b'verified synthetic actor').hexdigest()
        self.reference={'download_url':'https://files.example.com/asset?signature=PRIVATE_QUERY',
                        'file_id':'PRIVATE_FILE_REFERENCE'}

    @staticmethod
    def data(result):
        if result.is_error:raise AssertionError(result.content)
        return json.loads(result.content[0].text)

    def test_native_file_schema_write_annotations_and_missing_actor(self):
        async def run():
            async with Client(self.server) as client:
                tools={t.name:t for t in (await client.list_tools()).tools}
                self.assertEqual(len(tools),14)
                self.assertFalse(tools['stage_file_package'].annotations.read_only_hint)
                self.assertFalse(tools['commit_delivery'].annotations.read_only_hint)
                self.assertTrue(tools['inspect_delivery'].annotations.read_only_hint)
                stage=tools['stage_file_package'].model_dump(by_alias=True)
                self.assertEqual(stage['_meta']['openai/fileParams'],['file'])
                schema=stage['inputSchema'];key=schema['properties']['file']['$ref'].split('/')[-1]
                file=schema['$defs'][key]
                self.assertEqual(set(file['required']),{'download_url','file_id'})
                self.assertEqual(set(file['properties']),{'download_url','file_id','file_name','mime_type'})
                commit=tools['commit_delivery'].input_schema
                self.assertTrue({'destination','manifest','archive_sha256','preparation'} <= set(commit['required']))
                denied=await client.call_tool('get_delivery_capabilities')
                self.assertTrue(denied.is_error)
                self.assertIn('delivery_actor_required',denied.content[0].text)
        asyncio.run(run())
        self.assertFalse(list((self.repo/'docs/packages').iterdir()))

    def test_publication_temporary_tree_cannot_be_read_through_legacy_file_tools(self):
        name = INTERNAL_DELIVERY_PREFIX + 'a' * 32
        private = self.repo/'docs/packages'/name
        private.mkdir(); (private/'partial.md').write_text('partial original')
        with self.assertRaises(AccessError):
            self.catalog.read_file('synthetic', f'docs/packages/{name}/partial.md')
        listing = self.catalog.list_files('synthetic', 'docs/packages')
        self.assertFalse(listing['entries'])
        self.assertFalse(self.catalog.search('synthetic', 'partial original')['matches'])
        ordinary = self.repo/'.ordinary'; ordinary.mkdir();(ordinary/'readme.md').write_text('allowed')
        self.assertEqual(self.catalog.read_file('synthetic','.ordinary/readme.md')['text'],'allowed')

    def test_native_stage_frozen_preview_commit_readback_and_audit(self):
        async def run():
            async with Client(self.server) as client:
                cap=self.data(await client.call_tool('get_delivery_capabilities'))
                self.assertEqual(cap['targets'][0]['target_id'],'test-packages')
                begun=self.data(await client.call_tool('stage_file_package',{
                    'file':self.reference,'target_id':'test-packages','version_directory':'test-v1.0','expected_sha256':self.sha}))
                for _ in range(200):
                    preview=self.data(await client.call_tool('inspect_delivery',{'delivery_id':begun['delivery_id']}))
                    if preview['status']!='receiving':break
                    await asyncio.sleep(0.005)
                self.assertEqual(preview['status'],'ready',preview)
                self.assertFalse(list((self.repo/'docs/packages').iterdir()))
                args=preview['commit_arguments']
                self.assertEqual(args['destination'],str(self.repo/'docs/packages/test-v1.0'))
                self.assertEqual({x['path'] for x in args['manifest']},set(self.raw_files))
                page=self.data(await client.call_tool('inspect_delivery',{
                    'delivery_id':begun['delivery_id'],'file_path':'config.json'}))
                self.assertEqual(base64.b64decode(page['file']['bytes_base64']),self.raw_files['config.json'])
                changed=await client.call_tool('commit_delivery',{**args,'destination':str(self.base/'outside')})
                self.assertTrue(changed.is_error)
                self.assertFalse((self.base/'outside').exists())
                done=self.data(await client.call_tool('commit_delivery',args))
                self.assertEqual(done['status'],'completed')
                for name,raw in self.raw_files.items():
                    self.assertEqual((self.repo/'docs/packages/test-v1.0'/name).read_bytes(),raw)
                again=self.data(await client.call_tool('commit_delivery',args))
                self.assertEqual(again['status'],'completed')
                self.assertEqual(len(list((self.repo/'docs/packages').iterdir())),1)
                return begun['delivery_id']
        actor=audit_actor.set(self.actor); request=audit_request_id.set('1'*32)
        try: delivery_id=asyncio.run(run())
        finally:audit_request_id.reset(request);audit_actor.reset(actor)
        logs=self.logs.getvalue()
        for marker in ('PRIVATE_QUERY','PRIVATE_FILE_REFERENCE','Synthetic plan',str(self.repo)):
            self.assertNotIn(marker,logs)
        records=[json.loads(line) for line in logs.splitlines()]
        self.assertTrue(any(r.get('phase')=='download_verified' for r in records))
        self.assertTrue(any(r.get('phase')=='package_verified' for r in records))
        self.assertTrue(all(r.get('request_id')=='1'*32 for r in records))
        self.assertIn(delivery_id,logs)


if __name__=='__main__':unittest.main()
