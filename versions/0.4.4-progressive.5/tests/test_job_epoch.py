"""Epoch isolation uses real temporary Git/private roots and receiver processes."""
import asyncio
import copy
import hashlib
import json
import sqlite3
import time
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.server.mcpserver import MCPServer

from peters_mcp.catalog import AccessError
from peters_mcp.file_jobs import FileSaveInspector
from peters_mcp.file_context import verified_file_actor
from peters_mcp.file_tools import register_file_tools
from peters_mcp import file_jobs
from tests import test_file_jobs as fixture

ACTOR = fixture.ACTOR
OTHER_BOOT = '00000000-0000-4000-8000-000000000002'


class JobEpochTests(unittest.TestCase):
    setUp = fixture.FileJobTests.setUp
    close_services = fixture.FileJobTests.close_services
    service = fixture.FileJobTests.service
    arguments = fixture.FileJobTests.arguments
    wait = fixture.FileJobTests.wait

    @staticmethod
    def snapshot(service):
        return tuple(service.db.execute('SELECT id,actor,request_key,intent,body FROM jobs ORDER BY id'))

    def replace_body(self, service, row):
        with service._db_lock, service.db:
            service.db.execute('UPDATE jobs SET body=? WHERE id=?',
                               (file_jobs._json(row), row['job_id']))

    def test_normal_claim_advances_with_receiver_and_own_intent_is_not_a_stop_gate(self):
        service = self.service()
        active = service.submit(**self.arguments(service, name='normal.bin', key='normal'))['job_id']
        isolated = service.submit(**self.arguments(service, name='isolated.bin', key='isolated'))['job_id']
        old = service._get(isolated)
        old['runtime_epoch']['boot_session'] = OTHER_BOOT
        self.replace_body(service, old)
        frozen = service.db.execute('SELECT body FROM jobs WHERE id=?', (isolated,)).fetchone()[0]
        observed = []

        def observe(phase, job_id):
            if phase == 'publish_intent' and job_id == active:
                row = service._get(active)
                claim = service._current_claim(row)
                observed.append(service.status(ACTOR, job_id=active))
                self.assertEqual(claim['attempt'], 1)
                self.assertEqual(claim['receiver_attempt'], row['receiver']['attempt'])
                self.assertEqual(service._admission_block(), 'identity_epoch_changed')

        service.fault_hook = observe
        service._run(active)
        result = service.status(ACTOR, job_id=active)
        self.assertTrue(result['saved'])
        self.assertEqual(result['verification'], 'matched')
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]['published'], 'unknown')
        self.assertFalse(observed[0]['recovery_required'])
        self.assertEqual(service.db.execute('SELECT body FROM jobs WHERE id=?', (isolated,)).fetchone()[0], frozen)
        self.assertFalse((self.repo / 'isolated.bin').exists())

    def test_cross_boot_isolation_precedes_authorization_and_every_mutating_continuation(self):
        service = self.service()
        args = self.arguments(service, expected=hashlib.sha256(b'bound').hexdigest())
        job = service.submit(**args)['job_id']
        baseline = self.snapshot(service)
        ledger = tuple(service.db.execute('SELECT * FROM ledger ORDER BY key'))
        with patch.object(file_jobs, 'boot_session_id', return_value=OTHER_BOOT), \
                patch.object(service, '_authorize', side_effect=AssertionError('must not authorize isolated job')):
            service._run(job)
            result = service.status(ACTOR, job_id=job)
            self.assertEqual((result['state'], result['error_code']),
                             ('recovery_required', 'identity_epoch_changed'))
            self.assertTrue(result['recovery_required'])
            self.assertNotIn('path', result)
            self.assertEqual(service.submit(**args)['job_id'], job)
            with self.assertRaisesRegex(AccessError, 'identity_epoch_changed'):
                service.submit(**{**args, 'request_key': 'new-key-with-same-absent-target'})
            self.assertFalse((self.repo / args['path']).exists())
            with self.assertRaisesRegex(AccessError, 'identity_epoch_changed'):
                service.refresh_source(ACTOR, job, 1, {'file_id': 'normal',
                    'download_url': 'https://files.example.invalid/new'})
            cancelled = service.cancel(ACTOR, job)
            self.assertEqual(cancelled['state'], 'recovery_required')
            self.assertTrue(cancelled['cancel_requested'])
            self.assertNotEqual(cancelled['cancel_effect'], 'prevented_publish')
            self.assertIsNone(service._cleanup_private(service._get(job)))
            service.start()
            time.sleep(.15)
            service._stop.set()
            service._thread.join(2)
            self.assertFalse(service.capabilities(ACTOR)['execution_ready'])
        self.assertEqual(self.snapshot(service), baseline)
        self.assertEqual(tuple(service.db.execute('SELECT * FROM ledger ORDER BY key')), ledger)
        self.assertEqual(list(self.spool.iterdir()), [])
        self.assertEqual(service.db.execute('PRAGMA user_version').fetchone(), (1,))

    def test_legacy_nonterminal_and_changed_volume_mapping_are_quarantined(self):
        service = self.service()
        for name, change in [('legacy', lambda row: row.pop('runtime_epoch')),
                             ('mapping', lambda row: row['runtime_epoch']['volumes'][0].__setitem__(1, -1))]:
            # Submit both before introducing either quarantined row.
            if name == 'legacy':
                jobs = [service.submit(**self.arguments(service, name=item+'.bin', key=item))['job_id']
                        for item in ('legacy', 'mapping')]
            job = jobs[0 if name == 'legacy' else 1]
            row = service._get(job)
            change(row)
            if name == 'mapping':
                # A device remap also changes the old target claim. A fresh
                # key/claim for the same absent path must still be blocked.
                row['target']['root_identity'][0] = -1
                row['spool_root']['identity'][0] = -1
                row['claim'] = file_jobs._digest([row['target']['root_identity'], 'mapping.bin'])
            self.replace_body(service, row)
        baseline = self.snapshot(service)
        for job in jobs:
            service._run(job)
            self.assertTrue(service.status(ACTOR, job_id=job)['recovery_required'])
        self.assertEqual(self.snapshot(service), baseline)
        self.assertEqual(list(self.spool.iterdir()), [])
        new_args = self.arguments(service, name='mapping.bin', key='fresh-current-device-claim')
        with self.assertRaisesRegex(AccessError, 'identity_epoch_changed'):
            service.submit(**new_args)
        self.assertEqual(self.snapshot(service), baseline)

    def test_admission_is_recomputed_at_the_new_row_commit_boundary(self):
        service = self.service()
        job = service.submit(**self.arguments(service, name='first.bin', key='first'))['job_id']
        args = self.arguments(service, name='second.bin', key='second')
        original = service._grant_versions

        def unresolved_during_resolution(target):
            authorization = original(target)
            row = service._get(job)
            row.update(state='publication_unverified', published='unknown', publish_intent={'window': True})
            service._put(row)
            return authorization

        with patch.object(service, '_grant_versions', side_effect=unresolved_during_resolution):
            with self.assertRaisesRegex(AccessError, 'publication_unverified'):
                service.submit(**args)
        self.assertEqual(service.db.execute('SELECT count(*) FROM jobs').fetchone(), (1,))
        self.assertFalse((self.repo / 'second.bin').exists())

    def test_post_rename_pre_commit_projects_unknown_and_cross_boot_never_renames_again(self):
        service = self.service()
        args = self.arguments(service, name='window.bin')
        job = service.submit(**args)['job_id']

        def crash(phase, _):
            if phase == 'renamed':
                raise SystemExit()

        service.fault_hook = crash
        service._run(job)
        raw = service._get(job)
        self.assertIs(raw['published'], False)
        self.assertTrue((self.repo / args['path']).exists())
        observed = service.status(ACTOR, job_id=job)
        self.assertEqual(observed['published'], 'unknown')
        self.assertTrue(observed['recovery_required'])
        service.close()
        restarted = self.service()
        baseline = self.snapshot(restarted)
        payload = (self.repo / args['path']).read_bytes()
        with patch.object(file_jobs, 'boot_session_id', return_value=OTHER_BOOT), \
                patch.object(file_jobs, 'publish_exclusive', side_effect=AssertionError('must not rename again')):
            restarted._run(job)
            status = restarted.status(ACTOR, job_id=job)
            self.assertEqual((status['published'], status['error_code']), ('unknown', 'identity_epoch_changed'))
            restarted.cancel(ACTOR, job)
            self.assertIsNone(restarted._cleanup_private(restarted._get(job)))
        self.assertEqual(self.snapshot(restarted), baseline)
        self.assertEqual((self.repo / args['path']).read_bytes(), payload)

    def test_same_boot_receive_complete_and_durable_publication_recover_normally(self):
        for phase in ('receive_complete', 'published_durable'):
            with self.subTest(phase=phase):
                service = self.service()
                job = service.submit(**self.arguments(service, name=phase+'.bin', key=phase))['job_id']
                epoch = copy.deepcopy(service._get(job)['runtime_epoch'])

                def crash(current, _, stop_phase=phase):
                    if current == stop_phase:
                        raise SystemExit()

                service.fault_hook = crash
                service._run(job)
                service.close()
                restarted = self.service()
                self.assertEqual(restarted._get(job)['runtime_epoch'], epoch)
                restarted._run(job)
                self.assertTrue(restarted.status(ACTOR, job_id=job)['saved'])
                restarted.close()

    def test_nineteen_legacy_terminal_rows_remain_byte_exact_and_do_not_block_admission(self):
        service = self.service()
        template = service.submit(**self.arguments(service))['job_id']
        base = service._get(template)
        with service._db_lock, service.db:
            service.db.execute('DELETE FROM jobs')
            for index in range(19):
                row = copy.deepcopy(base)
                row.pop('runtime_epoch')
                row.update(job_id=f'{index:032x}', key=f'{index:064x}', state='completed' if index < 16 else 'failed',
                           published=index < 16, writer_exited=True,
                           durability='confirmed' if index < 16 else 'pending',
                           verification='matched' if index < 16 else 'not_started')
                service.db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)',
                                   (row['job_id'], row['actor'], row['key'], row['intent'], file_jobs._json(row)))
        baseline = self.snapshot(service)
        with patch.object(service.targets, 'revalidate', side_effect=AccessError('old pin changed')):
            for row_id, *_ in baseline:
                result = service.status(ACTOR, job_id=row_id)
                self.assertFalse(result['recovery_required'])
                self.assertNotIn('path', result)
                self.assertEqual(result['current_target_observation'], 'not_checked')
            service.cancel(ACTOR, baseline[0][0])
        self.assertIsNone(service._admission_block())
        service.start()
        time.sleep(.15)
        service._stop.set()
        service._thread.join(2)
        self.assertEqual(self.snapshot(service), baseline)
        self.assertEqual(service.db.execute('PRAGMA user_version').fetchone(), (1,))

    def test_readonly_inspector_preserves_cross_epoch_unknown_without_database_mutation(self):
        service = self.service()
        job = service.submit(**self.arguments(service))['job_id']
        row = service._get(job)
        row.update(state='publishing', publish_intent={'crash_window': True})
        self.replace_body(service, row)
        service.close()
        database = self.control / 'file-jobs.sqlite3'
        baseline = database.read_bytes()
        inspector = FileSaveInspector(self.catalog, self.registry, self.control)
        try:
            with patch.object(file_jobs, 'boot_session_id', return_value=OTHER_BOOT):
                result = inspector.status(ACTOR, job_id=job)
            self.assertEqual(result['published'], 'unknown')
            self.assertTrue(result['recovery_required'])
            self.assertEqual(result['error_code'], 'identity_epoch_changed')
        finally:
            inspector.close()
        self.assertEqual(database.read_bytes(), baseline)

    def test_mcp_tools_return_epoch_status_and_reject_new_key_without_new_row(self):
        service = self.service()
        args = self.arguments(service)
        job = service.submit(**args)['job_id']
        baseline = self.snapshot(service)
        server = MCPServer('synthetic epoch tools', log_level='CRITICAL')
        register_file_tools(server, service)

        async def check():
            token = verified_file_actor.set(ACTOR)
            try:
                async with Client(server) as client:
                    status = await client.call_tool('get_file_save_status', {'job_id': job})
                    self.assertFalse(status.is_error)
                    payload = json.loads(status.content[0].text)
                    self.assertEqual(payload['state'], 'recovery_required')
                    self.assertEqual(payload['error_code'], 'identity_epoch_changed')
                    same = await client.call_tool('save_generated_file',
                        {key: value for key, value in args.items() if key != 'actor'})
                    self.assertFalse(same.is_error)
                    self.assertEqual(json.loads(same.content[0].text)['job_id'], job)
                    fresh = await client.call_tool('save_generated_file',
                        {**{key: value for key, value in args.items() if key != 'actor'},
                         'request_key': 'different-key-absent-target'})
                    self.assertTrue(fresh.is_error)
                    self.assertIn('identity_epoch_changed', fresh.content[0].text)
                    cancel = await client.call_tool('cancel_file_save', {'job_id': job})
                    self.assertFalse(cancel.is_error)
                    self.assertEqual(json.loads(cancel.content[0].text)['state'], 'recovery_required')
            finally:
                verified_file_actor.reset(token)

        with patch.object(file_jobs, 'boot_session_id', return_value=OTHER_BOOT):
            asyncio.run(check())
        self.assertEqual(self.snapshot(service), baseline)
        self.assertFalse((self.repo / args['path']).exists())

    def test_inspector_rejects_valid_wal_without_shm_and_preserves_file_set_and_bytes(self):
        service = self.service()
        service.close()
        database = self.control / 'file-jobs.sqlite3'
        writer = sqlite3.connect(database)
        try:
            self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            writer.execute("INSERT INTO ledger VALUES ('wal-fixture',1,1)")
            writer.commit()
            db_bytes = database.read_bytes()
            wal_bytes = database.with_name(database.name + '-wal').read_bytes()
            self.assertEqual(db_bytes[18:20], b'\x02\x02')
            self.assertGreater(len(wal_bytes), 32)
        finally:
            writer.close()
        # Reproduce an interrupted process's valid DB+WAL, with no SHM. Only
        # this temporary fixture is restored; the inspector must not do so.
        database.write_bytes(db_bytes)
        wal = database.with_name(database.name + '-wal')
        wal.write_bytes(wal_bytes)
        wal.chmod(0o600)
        shm = database.with_name(database.name + '-shm')
        self.assertFalse(shm.exists())
        baseline = {path.name: path.read_bytes() for path in self.control.iterdir()}
        with patch.object(file_jobs.sqlite3, 'connect', side_effect=AssertionError('SQLite must not be opened')):
            with self.assertRaisesRegex(AccessError, 'metadata_unavailable'):
                FileSaveInspector(self.catalog, self.registry, self.control)
        self.assertEqual({path.name: path.read_bytes() for path in self.control.iterdir()}, baseline)
        self.assertFalse(shm.exists())

        # Verify the captured WAL is meaningful using a separate throwaway
        # copy. SQLite may create SHM in that verifier directory only.
        verifier = self.root / 'wal-verifier'
        verifier.mkdir()
        check_db = verifier / database.name
        check_db.write_bytes(db_bytes)
        check_db.with_name(check_db.name + '-wal').write_bytes(wal_bytes)
        check = sqlite3.connect(check_db.as_uri() + '?mode=ro', uri=True)
        try:
            self.assertEqual(check.execute("SELECT valid FROM ledger WHERE key='wal-fixture'").fetchone(), (1,))
        finally:
            check.close()
        self.assertEqual({path.name: path.read_bytes() for path in self.control.iterdir()}, baseline)

    def test_inspector_rejects_rollback_journal_and_other_sidecars_before_sqlite(self):
        service = self.service()
        service.close()
        database = self.control / 'file-jobs.sqlite3'
        self.assertEqual(database.read_bytes()[18:20], b'\x01\x01')
        for suffix in ('-journal', '-wal', '-shm'):
            with self.subTest(suffix=suffix):
                sidecar = database.with_name(database.name + suffix)
                sidecar.write_bytes(b'pending-journal-evidence')
                sidecar.chmod(0o600)
                baseline = {path.name: path.read_bytes() for path in self.control.iterdir()}
                with patch.object(file_jobs.sqlite3, 'connect', side_effect=AssertionError('SQLite must not be opened')):
                    with self.assertRaisesRegex(AccessError, 'metadata_unavailable'):
                        FileSaveInspector(self.catalog, self.registry, self.control)
                self.assertEqual({path.name: path.read_bytes() for path in self.control.iterdir()}, baseline)
                sidecar.unlink()  # This iteration's own temporary fixture.


if __name__ == '__main__':
    unittest.main()
