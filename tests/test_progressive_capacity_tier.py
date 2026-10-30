"""Focused capacity checks run in a separate frozen-package interpreter.

No production service or 100 MB transfer is started by these tests. The sparse
oversize file only exercises the admission rejection before snapshot creation.
"""
import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
FROZEN = REPO / 'versions/0.4.4-progressive.2'

ISOLATED_TESTS = r'''
import asyncio, copy, hashlib, json, os, plistlib, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

REPO = Path(sys.argv[1]); FROZEN = REPO/'versions/0.4.4-progressive.2'
sys.path[:0] = [str(FROZEN/'tests'), str(FROZEN/'tools'), str(FROZEN)]
import peters_mcp.chunked_export_config as policy
from peters_mcp.catalog import AccessError
from peters_mcp.file_export import FileExportService, ExportConfig, ExportLimits
import test_file_export as baseline
from test_native_chunk_receiver import make_plan, signed
from test_progressive_maintenance import ProgressiveFixture, m
assert Path(policy.__file__).resolve().is_relative_to(FROZEN)
assert Path(m.__file__).resolve().is_relative_to(FROZEN)

def source_module(name, path):
    module=ModuleType(name); module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec',dont_inherit=True),module.__dict__)
    return module
renderer=source_module('capacity_renderer_tests',REPO/'tools/render_capacity_acceptance.py')

def data(size=100000000):
    return {'run_label':'capacity-synthetic','project_id':'synthetic','worktree_id':'main',
            'source_path':'acceptance/source.zip','expected_bytes':size,'expected_sha256':'a'*64,
            'expected_png_sha256':'b'*64,'package_fingerprint':'c'*64,'config_sha256':'d'*64,
            'legacy_source_path':'acceptance/small.zip','legacy_expected_bytes':8192,
            'legacy_expected_sha256':'e'*64,'configured_max_file_bytes':size,
            'part_hashes':['f'*64]*((size+7999999)//8000000)}

class RendererTests(unittest.TestCase):
    def render(self, values=None, **kwargs):
        return renderer.render_prompt((FROZEN/'tools/native_receiver_loader.py').read_bytes(),
            kwargs.get('loader_sha',renderer.LOADER_SHA256),
            kwargs.get('asset',renderer.EXPECTED_ASSET),values if values is not None else data())

    def test_hundred_megabytes_derive_thirteen_parts_and_reuse_exact_loader(self):
        result=self.render(); d=result['acceptance_data']
        self.assertEqual(d['part_count'],13)
        self.assertEqual([p['bytes'] for p in d['parts']],[8000000]*12+[4000000])
        self.assertIn('def load_actual_received_helper',result['control_code'])
        self.assertEqual(result['loader_sha256'],renderer.LOADER_SHA256)
        self.assertEqual(result['common_control_sha256'],hashlib.sha256(result['common_control_code'].encode()).hexdigest())
        compile(result['control_code'],'public-control','exec')

    def test_default_thirty_megabytes_is_metadata_only_compatibility(self):
        d=data(30000000);d.pop('configured_max_file_bytes')
        result=self.render(d)['acceptance_data']
        self.assertEqual(result['configured_max_file_bytes'],30000000)
        self.assertEqual([p['bytes'] for p in result['parts']],[8000000]*3+[6000000])

    def test_inconsistent_geometry_limits_types_paths_and_pins_are_rejected(self):
        mutations=[('part_count',12),('parts',[{'index':0,'offset':0,'bytes':100000000}]),
                   ('expected_bytes',99999999),('configured_max_file_bytes',100000001),
                   ('configured_max_file_bytes',True),('source_path','../escape.zip'),
                   ('source_path','/absolute.zip'),('run_label','break\nmessage'),
                   ('run_label','break```fence'),('expected_sha256','a'*63),
                   ('part_hashes',['f'*64])]
        for key,value in mutations:
            d=data();d[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.render(d)
        with self.assertRaises(ValueError):self.render(loader_sha='0'*64)
        asset=dict(renderer.EXPECTED_ASSET,sha256='0'*64)
        with self.assertRaises(ValueError):self.render(asset=asset)

    def test_text_data_cannot_become_executable_python(self):
        d=data();d['run_label']='x\");raise RuntimeError(\"injected\")#'
        result=self.render(d)
        self.assertNotIn(d['run_label'],result['control_code'])
        self.assertIn(json.dumps(d['run_label']),result['prompt'])
        compile(result['control_code'],'trusted-control','exec')

    def test_cli_no_overwrite_and_validation_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); asset=root/'asset.json'; values=root/'data.json';out=root/'code.py.txt'
            asset.write_text(json.dumps(renderer.EXPECTED_ASSET));values.write_text(json.dumps(data()))
            command=[sys.executable,'-B',str(REPO/'tools/render_capacity_acceptance.py'),
                '--expected-loader-sha256',renderer.LOADER_SHA256,'--expected-asset-manifest',str(asset),
                '--acceptance-data',str(values),'--format','code','--output',str(out)]
            first=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(first.returncode,0,first.stderr)
            before=out.read_bytes();self.assertEqual(out.stat().st_mode&0o777,0o600)
            second=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(second.returncode,0);self.assertEqual(out.read_bytes(),before)
            values.write_text(json.dumps(dict(data(),part_count=12)));bad=root/'bad.py.txt'
            rejected=subprocess.run(command[:-1]+[str(bad)],capture_output=True,text=True)
            self.assertNotEqual(rejected.returncode,0);self.assertFalse(bad.exists())

class NativeControlTests(unittest.TestCase):
    def test_shared_a_then_b_persists_real_small_io_duplicate_and_resume(self):
        # Tiny local bytes qualify only control semantics, not native transport.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();inputs=root/'inputs';output=root/'output'
            inputs.mkdir();output.mkdir(mode=0o700)
            helper=inputs/'native_chunk_receiver.py';helper.write_bytes((FROZEN/'peters_mcp/native_chunk_receiver.py').read_bytes())
            source=b'focused A before B persistence test'
            actual=inputs/'actual.bin';actual.write_bytes(source);actual.chmod(0o600)
            plan=make_plan(source);expected=plan['parts']
            result=renderer.render_prompt((FROZEN/'tools/native_receiver_loader.py').read_bytes(),
                         renderer.LOADER_SHA256,renderer.EXPECTED_ASSET,data())
            ns={};exec(compile(result['control_code'],'published-control','exec'),ns)
            identity=[inputs.stat().st_dev,inputs.stat().st_ino]
            module,evidence=ns['load_actual_received_helper'](str(helper),str(inputs),identity,plan['receiver_asset'])
            self.assertTrue(evidence['native_receiver_root_bound'])
            run=ns['CapacityRun'].configure(plan,module,str(inputs),identity,str(output),'focused',expected,time.time()-1)
            with patch.object(run.receiver,'ingest',wraps=run.receiver.ingest) as ingest:
                a=run.A(0,str(actual));self.assertEqual(ingest.call_count,0)
            self.assertFalse(a['ingest_called']);self.assertTrue(a['receipt']['readback_exact'])
            saved=Path(a['receipt']['path']).read_bytes()
            self.assertEqual(hashlib.sha256(saved).hexdigest(),a['receipt']['buffer_sha256'])
            with self.assertRaises(RuntimeError):run.B(0,'0'*64)
            self.assertEqual(run.receiver.status()['received_bytes'],0)
            with self.assertRaises(FileExistsError):run.A(0,str(actual))
            self.assertEqual(Path(a['receipt']['path']).read_bytes(),saved)
            b=run.B(0,a['receipt']['buffer_sha256'])
            self.assertEqual(b['acceptance']['duplicate_result']['appended_bytes'],0)
            self.assertTrue(b['acceptance']['new_object_resume']['new_object'])
            self.assertEqual(b['acceptance']['status_after_ingest']['received_bytes'],len(source))
            finished=run.receiver.finish()
            self.assertEqual(Path(finished['path']).read_bytes(),source)

class SDKEnvironmentTests(unittest.TestCase):
    def test_allocator_profiles_copy_parent_and_preserve_unrelated_environment(self):
        sdk=source_module('capacity_sdk_profile_tests',REPO/'tools/rehearse_progressive_release.py')
        parent={'MallocNanoZone':'0','PATH':'/synthetic/bin','UNRELATED':'keep'}
        original=dict(parent)
        for profile in (None,'inherit'):
            result=sdk.child_environment(profile,parent=parent)
            self.assertEqual(result,original);self.assertIsNot(result,parent)
        selected=sdk.child_environment('system-default',parent=parent)
        self.assertEqual(selected,{'PATH':'/synthetic/bin','UNRELATED':'keep'})
        self.assertEqual(parent,original)
        absent={'PATH':'/synthetic/bin','UNRELATED':'keep'}
        self.assertEqual(sdk.child_environment('system-default',parent=absent),absent)
        for profile in ('unknown','',False,1):
            with self.subTest(profile=profile),self.assertRaises((ValueError,TypeError)):
                sdk.child_environment(profile,parent=parent)
        self.assertEqual(parent,original)
        with patch.dict(os.environ,{'MallocNanoZone':'0','CAPACITY_PROFILE_TEST':'untouched'}):
            before=dict(os.environ)
            inherited=sdk.child_environment(None)
            self.assertEqual(inherited,before);self.assertIsNot(inherited,os.environ)
            self.assertEqual(sdk.child_environment(),before)
            self.assertEqual(sdk.child_environment('inherit'),before)
            selected=sdk.child_environment('system-default')
            self.assertEqual(selected,{k:v for k,v in before.items() if k!='MallocNanoZone'})
            self.assertEqual(dict(os.environ),before)

    def test_sdk_tier_default_and_exact_integer_boundaries(self):
        import argparse
        sdk=source_module('capacity_sdk_tier_tests',REPO/'tools/rehearse_progressive_release.py')
        self.assertEqual(sdk.DEFAULT_TIER_BYTES,30000000)
        for value,expected in ((30000000,30000000),('30000000',30000000),
                               (8192,8192),('100000000',100000000),(100000000,100000000)):
            self.assertEqual(sdk.tier_byte_count(value),expected)
        for value in (None,True,False,30000000.0,'30000000.0',8191,100000001):
            with self.subTest(value=value),self.assertRaises(argparse.ArgumentTypeError):
                sdk.tier_byte_count(value)

class SDKRSSProfileTests(unittest.TestCase):
    def test_rss_profile_requires_exact_hundred_megabytes_and_system_allocator(self):
        import argparse
        sdk=source_module('capacity_sdk_rss_profiles',REPO/'tools/rehearse_progressive_release.py')
        self.assertEqual(sdk.rss_extra_limit(),134217728)
        for profile in (None,'128m'):
            self.assertEqual(sdk.rss_extra_limit(profile),134217728)
            self.assertEqual(sdk.rss_extra_limit(profile,100000000,'system-default'),134217728)
        self.assertEqual(sdk.rss_extra_limit('capacity100-256m',100000000,'system-default'),268435456)
        for tier in (30000000,50000000,70000000,99999999,100000001,True,False,100000000.0):
            with self.subTest(tier=tier),self.assertRaises((ValueError,TypeError,argparse.ArgumentTypeError)):
                sdk.rss_extra_limit('capacity100-256m',tier,'system-default')
        for allocator in (None,'inherit','unknown'):
            with self.subTest(allocator=allocator),self.assertRaises((ValueError,TypeError)):
                sdk.rss_extra_limit('capacity100-256m',100000000,allocator)
        for profile in ('unknown','256m','',False,1):
            with self.subTest(profile=profile),self.assertRaises((ValueError,TypeError)):
                sdk.rss_extra_limit(profile,100000000,'system-default')

    def test_sampled_and_native_highwater_gates_reject_one_byte_above_each_limit(self):
        sdk=source_module('capacity_sdk_rss_gates',REPO/'tools/rehearse_progressive_release.py')
        baseline=10000000
        def measured(extra):
            sampler=sdk.ResidentSampler(12345)
            sampler.samples=[{'started_monotonic':t,'observed_monotonic':t,
                'observed_at_unix':1700000000+t,'rss_bytes':baseline+(extra if i==1 else 0),
                'probe_seconds':0.0} for i,t in enumerate((1.0,1.02,1.04))]
            return sampler
        # Default calls retain the original 128 MiB behavior without new kwargs.
        self.assertEqual(measured(134217728).validate(1.0,1.04,baseline)['extra_bytes'],134217728)
        with self.assertRaisesRegex(RuntimeError,'rss_sampled_extra_limit_exceeded'):
            measured(134217729).validate(1.0,1.04,baseline)
        self.assertEqual(sdk.native_highwater_bound(baseline,baseline+1,baseline+134217728)
            ['conservative_lifetime_peak_above_current_baseline_bytes'],134217728)
        with self.assertRaisesRegex(RuntimeError,'native_highwater_above_current_baseline_limit_exceeded'):
            sdk.native_highwater_bound(baseline,baseline+1,baseline+134217729)
        limit=sdk.rss_extra_limit('capacity100-256m',100000000,'system-default')
        self.assertEqual(measured(limit).validate(1.0,1.04,baseline,extra_limit_bytes=limit)['extra_bytes'],limit)
        with self.assertRaisesRegex(RuntimeError,'rss_sampled_extra_limit_exceeded'):
            measured(limit+1).validate(1.0,1.04,baseline,extra_limit_bytes=limit)
        self.assertEqual(sdk.native_highwater_bound(baseline,baseline+1,baseline+limit,extra_limit_bytes=limit)
            ['conservative_lifetime_peak_above_current_baseline_bytes'],limit)
        with self.assertRaisesRegex(RuntimeError,'native_highwater_above_current_baseline_limit_exceeded'):
            sdk.native_highwater_bound(baseline,baseline+1,baseline+limit+1,extra_limit_bytes=limit)

class ConfigTests(unittest.TestCase):
    def test_hundred_megabytes_configuration_accepts_exact_ceiling(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'config.json'
            d={'version':1,'enabled':True,'max_file_bytes':100000000,'min_free_bytes':1073741824,'protocol_version':'raw-parts-v1'}
            path.write_text(json.dumps(d));path.chmod(0o600)
            self.assertEqual(policy.read_chunked_export_config(path).max_file_bytes,100000000)
            path.write_text(json.dumps(dict(d,max_file_bytes=100000001)))
            with self.assertRaises(AccessError):policy.read_chunked_export_config(path)

class CapacityAdmissionTests(unittest.IsolatedAsyncioTestCase):
    setUp=baseline.ExportTests.setUp
    asyncTearDown=baseline.ExportTests.asyncTearDown
    actor_for=baseline.ExportTests.actor_for
    make_service=baseline.ExportTests.make_service
    async def test_oversize_source_rejected_before_snapshot_or_budget_charge(self):
        service=FileExportService(self.catalog,ExportConfig(True,self.spool,min_free_bytes=0),
            chunked_config=policy.ChunkedExportConfig(True,max_file_bytes=100000000,min_free_bytes=0),
            limits=ExportLimits(close_seconds=.2),monotonic=self.clock.monotonic,wall_clock=self.clock.wall)
        service.start();self.services.append(service)
        path=self.root/'original.bin'
        with path.open('xb') as f:f.truncate(100000001)
        before=service.diagnostics();cap=service.capabilities(self.actor)
        with self.assertRaises(AccessError) as raised:
            await service.prepare_chunked_export(self.actor,'synthetic','main','original.bin',
                cap['service_instance_id'],cap['request_window_id'],'too-large')
        self.assertEqual(raised.exception.code,'client_ingestion_unverified')
        self.assertEqual(service.diagnostics()['snapshot_reservations'],before['snapshot_reservations'])
        self.assertEqual(service._written_total,0)
        self.assertEqual(service._records,{})

class ConfigSwitchTests(unittest.TestCase):
    def test_same_packages_thirty_hundred_thirty_plans_and_immutable_configs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();f=ProgressiveFixture(root);f.prepare()
            package_pins=copy.deepcopy(f.plan['packages'])
            old=f.config;old_raw=old.read_bytes();db=f.base.database.read_bytes()
            def activate(plan,digest,switch):
                m.switch_stop(plan,digest,f.base.host)
                m.migration_apply(plan,digest,f.base.host)
                return m.runtime_switch(plan,digest,'candidate',switch,f.base.host)
            activate(f.plan,f.digest,'activate-thirty')
            hundred=root/'hundred.json';f.base.json(hundred,dict(json.loads(old_raw),max_file_bytes=100000000))
            new_raw=hundred.read_bytes()
            def prepare(previous,previous_sha,config,operation):
                path=root/(operation+'.json');bindings=root/(operation+'-bindings.json')
                result=m.prepare_code_switch(previous,previous_sha,'candidate',f.packages/'candidate',
                    f.packages/'rollback',f.maintenance/'manifest.json',config,'c'*64,operation,path,bindings,host=f.base.host)
                return path,result['plan_sha256'],json.loads(path.read_bytes())
            p100,h100,d100=prepare(f.plan_path,f.digest,hundred,'capacity-hundred')
            activate(d100,h100,'activate-hundred')
            p30,h30,d30=prepare(p100,h100,old,'capacity-back-thirty')
            self.assertEqual(d100['packages'],package_pins);self.assertEqual(d30['packages'],package_pins)
            for plan in (d100,d30):
                for name in ('manifest','projects'):
                    self.assertEqual(plan['targets'][name]['sha256'],plan['targets'][name]['after_sha256'])
            args100=plistlib.loads(m.decoded(d100['definitions']['candidate']['raw']))['ProgramArguments']
            args30=plistlib.loads(m.decoded(d30['definitions']['candidate']['raw']))['ProgramArguments']
            differences=[(a,b) for a,b in zip(args100,args30) if a!=b]
            self.assertEqual(differences,[(str(hundred),str(old))])
            self.assertEqual(old.read_bytes(),old_raw);self.assertEqual(hundred.read_bytes(),new_raw)
            self.assertEqual(f.base.database.read_bytes(),db)
            f.base.json(old,dict(json.loads(old_raw),max_file_bytes=100000000))
            with self.assertRaisesRegex(m.MaintenanceError,'nonmigration_configuration_changed'):m.check_anchors(d100)

suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in
    (RendererTests,NativeControlTests,SDKEnvironmentTests,SDKRSSProfileTests,ConfigTests,CapacityAdmissionTests,ConfigSwitchTests))
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'frozen_policy_module':policy.__file__,'frozen_maintenance_module':m.__file__,
                  'isolated_tests_run':result.testsRun,'passed':result.wasSuccessful()}))
sys.exit(0 if result.wasSuccessful() else 1)
'''

class IsolatedCapacityTests(unittest.TestCase):
    def test_capacity_tier_in_frozen_subprocess(self):
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        result = subprocess.run([sys.executable, '-B', '-c', ISOLATED_TESTS, str(REPO)],
                                cwd=FROZEN, env=env, capture_output=True, text=True)
        print(result.stdout, end='')
        print(result.stderr, end='')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main(verbosity=2)
