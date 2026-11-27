import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mcp import Client
from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse

from peters_mcp.catalog import AccessError
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_context import actor_digest, current_file_actor, verified_file_actor
from peters_mcp.file_tools import register_file_tools
from peters_mcp.private_roots import PrivateRootRegistry
from peters_mcp.server import _protected_history_operation


class FileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.control = self.base/'control'; self.control.mkdir(mode=0o700)
        self.spool = self.base/'spool'
        self.repo = self.base/'repo'; self.repo.mkdir()
        self.home = self.base/'history'; self.home.mkdir()
        self.policy = self.base/'history.json'
        self.policy.write_text(json.dumps({'codex_home':str(self.home)}))
        self.history = SimpleNamespace(config_path=self.policy)
        self.registry = PrivateRootRegistry(self.control,allowed_roots=[self.spool])
        self.registry.initialize()
        self.registry.register_pending(self.spool,read_roots=[self.repo,self.home])
        self.registry.activate(self.spool,read_roots=[self.repo,self.home])

    def test_separate_history_source_and_disabled_history_are_safe(self):
        with _protected_history_operation(self.history,self.registry):
            pass
        with _protected_history_operation(SimpleNamespace(config_path=None),self.registry):
            pass

    def test_history_source_cannot_read_private_root_or_its_parent(self):
        for source in (self.spool,self.control,self.base):
            self.policy.write_text(json.dumps({'codex_home':str(source)}))
            with self.subTest(source=source.name), self.assertRaisesRegex(AccessError,'private_path'):
                with _protected_history_operation(self.history,self.registry):
                    self.fail('Private source passed to history parser')

    def test_history_policy_change_refuses_result_after_operation(self):
        with self.assertRaisesRegex(AccessError,'scope_changed'):
            with _protected_history_operation(self.history,self.registry):
                self.policy.write_text(json.dumps({'codex_home':str(self.repo)}))

    def test_unknown_private_manifest_closes_separate_reader(self):
        (self.control/'private-roots.json').write_text('broken')
        with self.assertRaises(AccessError):
            with _protected_history_operation(self.history,self.registry):
                self.fail('Unknown private roots were ignored')

    def test_history_config_fifo_is_rejected_without_blocking_or_retaining_guard(self):
        self.policy.unlink()
        os.mkfifo(self.policy)
        with self.assertRaisesRegex(AccessError,'private_protection_unavailable'):
            with _protected_history_operation(self.history,self.registry):
                self.fail('A FIFO reached the history worker')
        self.policy.unlink()
        self.policy.write_text(json.dumps({'codex_home':str(self.home)}))
        with _protected_history_operation(self.history,self.registry):
            pass

    def test_history_config_regular_symlink_remains_compatible(self):
        actual=self.base/'actual-history.json'
        self.policy.rename(actual)
        self.policy.symlink_to(actual)
        with _protected_history_operation(self.history,self.registry):
            pass

    def test_verified_cloudflare_actor_is_request_scoped_and_not_header_claim(self):
        seen=[]
        class Verifier:
            def verify(self,token):
                return {'iss':'https://issuer.example.test','sub':token}
        async def app(scope,receive,send):
            seen.append(current_file_actor())
            await JSONResponse({'ok':True})(scope,receive,send)
        wrapped=AccessMiddleware(app,Verifier())
        async def run(subject):
            async def receive():return {'type':'http.request','body':b'','more_body':False}
            async def send(message):pass
            await wrapped({'type':'http','headers':[(b'cf-access-jwt-assertion',subject.encode()),
                (b'x-actor',b'forged')],'method':'GET','path':'/'},receive,send)
            self.assertIsNone(verified_file_actor.get())
        asyncio.run(run('first'));asyncio.run(run('second'))
        self.assertEqual(seen,[actor_digest('https://issuer.example.test',s) for s in ('first','second')])
        with self.assertRaisesRegex(AccessError,'authentication_required'):
            current_file_actor()

    def test_receiver_import_does_not_require_kqueue_for_readonly_inspection(self):
        code = """import select
if hasattr(select, 'kqueue'): del select.kqueue
import peters_mcp.file_receiver as receiver
try: receiver.ExitBarrier({'pid': 1})
except receiver.Isolated: pass
else: raise AssertionError('unsupported adapter was not rejected')
"""
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,
                              cwd=Path(__file__).resolve().parent.parent,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_native_file_schema_annotations_no_actor_argument_and_rollback_tools(self):
        async def check():
            server=MCPServer('synthetic schema',log_level='CRITICAL')
            register_file_tools(server,SimpleNamespace())
            async with Client(server) as client:
                listing=await client.list_tools()
                tools={t.name:t for t in listing.tools}
                self.assertEqual(len(tools),6)
                tool=tools['save_generated_file'];schema=tool.input_schema
                self.assertNotIn('actor',schema['properties'])
                self.assertEqual(tool.meta['openai/fileParams'],['file'])
                file_schema=schema['properties']['file']
                if '$ref' in file_schema:
                    file_schema=schema['$defs'][file_schema['$ref'].split('/')[-1]]
                self.assertEqual(set(file_schema['properties']),{'download_url','file_id','file_name','mime_type'})
                self.assertEqual(set(file_schema['required']),{'download_url','file_id'})
                self.assertFalse(tool.annotations.read_only_hint)
                self.assertTrue(tools['cancel_file_save'].annotations.destructive_hint)
                denied=await client.call_tool('get_write_capabilities')
                self.assertTrue(denied.is_error)
                self.assertIn('authentication_required',str(denied.content))
                invalid={'file':{'download_url':'https://a.example.test/?sig=SECRET_SENTINEL'},
                         'project_id':'demo','worktree_id':'main','path':'x.bin','target_version':'v',
                         'destination_display':'demo/x.bin','request_key':'invalid'}
                for args in (invalid, {'file':invalid['file']}):
                    result=await client.call_tool('save_generated_file',args)
                    self.assertTrue(result.is_error)
                    self.assertNotIn('SECRET_SENTINEL',str(result.content))
                    self.assertNotIn('a.example.test',str(result.content))
            rollback=MCPServer('synthetic rollback',log_level='CRITICAL')
            register_file_tools(rollback,SimpleNamespace(),inspection_only=True)
            async with Client(rollback) as client:
                self.assertEqual({t.name for t in (await client.list_tools()).tools},
                                 {'get_write_capabilities','get_file_save_status'})
        asyncio.run(check())


if __name__=='__main__':unittest.main()
