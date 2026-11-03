"""Export-only configuration and conservative sharing with existing save jobs."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_config import load_file_service
from peters_mcp.file_context import export_actor_from_verified
from peters_mcp.file_export import load_export_service, read_export_config, PROFILE_ID, MAX_ORIGINAL_BYTES
from peters_mcp.file_jobs import FileSaveService
from peters_mcp.file_setup import bootstrap_file_service
import time


class ExportConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.catalog = Catalog([Project('synthetic', 'Synthetic', self.repo)])
        self.files_path = self.root / 'files.json'
        self.path = self.root / 'exports.json'
        self.control, self.spool = self.root / 'control', self.root / 'spool'
        self.files_data = {'version':1, 'enabled':False, 'control_directory':str(self.control),
            'spool_roots':[str(self.spool)], 'sources':{}, 'special_exceptions':[],
            'min_free_bytes':2097152, 'max_workers':2}
        self.data = {'version':1,'enabled':True,'spool_root':str(self.spool),
            'profile_id':PROFILE_ID,'max_file_bytes':MAX_ORIGINAL_BYTES,'min_free_bytes':0}
        self.save()
        self.actor = export_actor_from_verified('https://issuer.example.invalid','owner',time.time()+60)

    def save(self):
        for path, data in ((self.path, self.data), (self.files_path, self.files_data)):
            path.write_text(json.dumps(data)); path.chmod(0o600)

    def infrastructure(self):
        bootstrap_file_service(self.files_path, self.catalog)
        _, inspector = load_file_service(self.files_path, self.catalog)
        self.addCleanup(inspector.close)
        return inspector

    def test_default_off_and_disabled_never_create_infrastructure(self):
        self.assertIsNone(load_export_service(None, self.catalog))
        self.data['enabled'] = False; self.save()
        self.assertIsNone(load_export_service(self.path, self.catalog))
        self.assertFalse(self.control.exists())
        self.assertFalse(self.spool.exists())
        self.data['enabled'] = True; self.save()
        with self.assertRaisesRegex(AccessError, 'private_protection_unavailable'):
            load_export_service(self.path, self.catalog)
        self.assertFalse(self.control.exists())

    def test_enabled_export_with_write_disabled_retains_floor_and_no_sql_writer(self):
        inspector = self.infrastructure()
        service = load_export_service(self.path, self.catalog, files=inspector)
        self.addCleanup(service.close)
        self.assertEqual(service.min_free_bytes, self.files_data['min_free_bytes'])
        self.assertTrue(inspector.inspection_only)
        self.assertFalse((self.control / 'file-jobs.sqlite3').exists())
        self.assertEqual(service._threads, [])
        service.start()
        self.assertEqual(service.capabilities(self.actor)['max_original_bytes'], MAX_ORIGINAL_BYTES)
        self.assertFalse((self.control / 'file-jobs.sqlite3').exists())

    def test_explicit_rollback_suppresses_export_even_with_enabled_policy(self):
        self.assertIsNone(load_export_service(self.path, self.catalog, inspection_only=True))
        with patch('peters_mcp._file_release_mode.INSPECTION_ONLY', True):
            self.assertIsNone(load_export_service(self.path, self.catalog))
        self.assertFalse(self.control.exists())

    def test_write_enable_is_independent_but_changed_infrastructure_closes_reads(self):
        inspector = self.infrastructure()
        service = load_export_service(self.path, self.catalog, files=inspector)
        self.addCleanup(service.close)
        service.start()
        self.files_data['enabled'] = True; self.save()
        self.assertIn('request_window_id', service.capabilities(self.actor))
        self.files_data['enabled'] = False
        self.files_data['min_free_bytes'] += 1; self.save()
        with self.assertRaisesRegex(AccessError, 'file_config_changed'):
            service.capabilities(self.actor)
        self.assertFalse((self.control / 'file-jobs.sqlite3').exists())

    def test_export_configuration_revocation_and_private_alias(self):
        inspector = self.infrastructure()
        service = load_export_service(self.path, self.catalog, files=inspector)
        self.addCleanup(service.close)
        self.data['enabled'] = False; self.save()
        with self.assertRaisesRegex(AccessError, 'export_disabled'):
            service.capabilities(self.actor)
        alias = self.root / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(AccessError):
            read_export_config(alias / 'exports.json')

    def test_strict_schema_permissions_and_profile_bound(self):
        for key, value in [('max_file_bytes',MAX_ORIGINAL_BYTES+1),('enabled',1),
                           ('min_free_bytes',-1),('profile_id','unverified')]:
            old=self.data[key]; self.data[key]=value; self.save()
            with self.subTest(key=key), self.assertRaises(AccessError): read_export_config(self.path)
            self.data[key]=old
        self.save(); self.path.chmod(0o644)
        with self.assertRaises(AccessError): read_export_config(self.path)
        self.path.chmod(0o600)
        self.path.write_text(json.dumps(self.data)[:-1]+',"enabled":false}')
        with self.assertRaises(AccessError): read_export_config(self.path)

    def test_existing_job_space_is_read_only_and_unknown_or_full_is_conservative(self):
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE jobs (body TEXT)')
        owner=SimpleNamespace(db=db,_db_lock=threading.RLock())
        def row(state='accepted',size=12,**more):
            db.execute('INSERT INTO jobs VALUES (?)',(json.dumps(dict(state=state,
                expected_size_bytes=size,published=False,**more)),)); db.commit()
        row(); row(size=20); row(state='completed',size=99)
        row(size=888,complete={'bytes':888}); row(state='cancelled',size=999)
        before=db.total_changes
        self.assertEqual(FileSaveService.pending_space_reservation(owner),32)
        self.assertEqual(db.total_changes,before)
        row(size=None)
        self.assertIsNone(FileSaveService.pending_space_reservation(owner))
        db.execute('DELETE FROM jobs')
        for _ in range(65): row()
        self.assertIsNone(FileSaveService.pending_space_reservation(owner))
        db.execute('DROP TABLE jobs')
        self.assertIsNone(FileSaveService.pending_space_reservation(owner))

if __name__=='__main__': unittest.main()
