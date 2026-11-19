"""Synthetic v2 code-switch planning and guarded pre-target abort recovery."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_identity_maintenance import Fixture, TOOLS, maintenance as m


class ProgressiveFixture:
    def __init__(self, root, ledger_entries=None, legacy_hash_only=False):
        self.base = f = Fixture(root)
        if ledger_entries is not None:
            connection = sqlite3.connect(f.database)
            connection.executemany('INSERT INTO ledger VALUES (?,?,?)', ledger_entries)
            connection.commit()
            connection.close()
        f.plan['database'] = m.database_snapshot(f.database)
        if legacy_hash_only:
            f.plan['database'].pop('ledger_entries', None)
        # The restoration target really uses the unchanged historical R7 files.
        old_tools = TOOLS.parents[1] / '0.4.3-context.4' / 'tools'
        rows = []
        for name in ('identity_maintenance.py', 'migrate_persistent_identity.py', 'switch_identity_release.py'):
            raw = (old_tools / name).read_bytes()
            (f.maintenance / name).write_bytes(raw)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': m.sha(raw)})
        f.json(f.maintenance / 'manifest.json', {'format_version': 1, 'python': list(sys.version_info[:2]),
               'dependencies': {mode: f.plan['packages'][mode]['fingerprint'] for mode in ('candidate', 'rollback')},
               'files': rows})
        f.plan['maintenance'] = m.verify_maintenance(f.maintenance / 'manifest.json')
        f.digest = m.sha(m.canonical(f.plan))
        f.json(f.plan_path, f.plan)
        f.started('previous-start')
        self.old_tools = old_tools
        self.packages = root / 'progressive-packages'
        self.packages.mkdir()
        for mode in ('candidate', 'rollback'):
            f.package(self.packages / mode, mode)
        self.maintenance = root / 'progressive-maintenance'
        self.maintenance.mkdir()
        rows = []
        for name in ('identity_maintenance.py', 'migrate_persistent_identity.py',
                     'switch_identity_release.py', 'prepare_code_switch.py'):
            raw = (TOOLS / name).read_bytes()
            (self.maintenance / name).write_bytes(raw)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': m.sha(raw)})
        f.json(self.maintenance / 'manifest.json', {'format_version': 1, 'python': list(sys.version_info[:2]),
               'dependencies': {mode: m.package_info(self.packages / mode)['fingerprint'] for mode in ('candidate', 'rollback')},
               'files': rows})
        self.config = root / 'chunked.json'
        f.json(self.config, {'version': 1, 'enabled': True, 'protocol_version': 'raw-parts-v1',
                            'max_file_bytes': 30_000_000, 'min_free_bytes': 1024 * 1024 * 1024})
        self.plan_path = root / 'progressive-plan.json'
        self.bindings_path = root / 'progressive-bindings.json'
        self.output = root / 'restore-bindings.json'
        self.arguments = (f.plan_path, f.digest, 'candidate', self.packages / 'candidate',
                          self.packages / 'rollback', self.maintenance / 'manifest.json',
                          self.config, 'c' * 64, 'progressive-operation', self.plan_path, self.bindings_path)

    def prepare(self):
        result = m.prepare_code_switch(*self.arguments, host=self.base.host)
        self.plan = json.loads(self.plan_path.read_bytes())
        self.digest = result['plan_sha256']
        return result

    def stop(self):
        return m.switch_stop(self.plan, self.digest, self.base.host)

    def abort(self, output=None):
        return m.abort_before_targets(self.plan, self.digest, output or self.output, self.base.host)

    def add_job(self, state='completed'):
        connection = sqlite3.connect(self.base.database)
        connection.execute('INSERT INTO jobs VALUES (?,?,?,?,?)',
            ('new-job', 'actor', 'new-key', 'new-intent', json.dumps({
                'state': state, 'published': state == 'completed', 'durability': 'confirmed',
                'verification': 'matched', 'writer_exited': state == 'completed'})))
        connection.commit()
        connection.close()


class ProgressiveMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='progressive-maintenance-')
        self.addCleanup(self.temporary.cleanup)
        self.f = ProgressiveFixture(Path(self.temporary.name).resolve())
        self.addCleanup(setattr, m, 'FAULT', None)

    def test_read_only_preparer_binds_real_v2_and_config_without_service_or_control_writes(self):
        f = self.f
        files = [f.base.plist, f.base.manifest, f.base.projects, f.base.database]
        before = {p: p.read_bytes() for p in files}
        controls = sorted(str(p) for p in f.base.control.rglob('*'))
        calls = (f.base.host.starts, f.base.host.stops)
        with patch.object(m, 'Lease', side_effect=AssertionError('preparer must not acquire offline locks')):
            result = f.prepare()
        self.assertEqual(result['state'], 'prepared_not_deployed')
        self.assertEqual({p: p.read_bytes() for p in files}, before)
        self.assertEqual(sorted(str(p) for p in f.base.control.rglob('*')), controls)
        self.assertEqual((f.base.host.starts, f.base.host.stops), calls)
        self.assertFalse(Path(f.plan['operation_directory']).exists())
        self.assertEqual(f.plan['previous_maintenance'], f.base.plan['maintenance'])
        for name in ('manifest', 'projects'):
            self.assertEqual(f.plan['targets'][name]['sha256'], f.plan['targets'][name]['after_sha256'])
        config = next(row for row in f.plan['unchanged'] if row['path'] == str(f.config))
        self.assertEqual(config['mode'], 0o600)
        self.assertIn('parent_identity', config)
        self.assertEqual(m.load_plan(f.plan_path, f.digest)[0], f.plan)

    def test_preparer_rejects_unbound_active_service_and_unsafe_private_config(self):
        f = self.f
        f.base.host.is_loaded = False
        with self.assertRaisesRegex(m.MaintenanceError, 'previous_origin_not_running'):
            f.prepare()
        f.base.host.is_loaded = True
        f.config.chmod(0o644)
        with self.assertRaisesRegex(m.MaintenanceError, 'chunked_configuration_invalid'):
            f.prepare()
        self.assertFalse(f.plan_path.exists())

    def test_bound_configuration_change_is_rejected(self):
        f = self.f
        f.prepare()
        config = json.loads(f.config.read_bytes())
        config['max_file_bytes'] = 50_000_000
        f.base.json(f.config, config)
        with self.assertRaisesRegex(m.MaintenanceError, 'nonmigration_configuration_changed'):
            m.check_anchors(f.plan)
        self.assertTrue(f.base.host.loaded())

    def test_legal_new_terminal_job_apply_failure_abort_and_actual_old_r7_restore(self):
        f = self.f
        f.prepare()
        f.add_job()
        current_database = f.base.database.read_bytes()
        f.stop()
        with self.assertRaisesRegex(m.MaintenanceError, 'migration_database_precondition_failed'):
            m.migration_apply(f.plan, f.digest, f.base.host)
        self.assertEqual(f.abort()['state'], 'aborted_before_targets')
        self.assertEqual(f.base.database.read_bytes(), current_database)
        bindings = json.loads(f.output.read_bytes())
        with patch.object(sys, 'path', list(sys.path)):
            spec = importlib.util.spec_from_file_location('historical_r7_for_progressive_test',
                                                          f.old_tools / 'identity_maintenance.py')
            old = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(old)
            previous, previous_sha = old.load_plan(bindings['previous_plan_path'], bindings['previous_plan_sha256'])
            challenge = old.runtime_switch(previous, previous_sha, bindings['previous_active_bundle'],
                                           bindings['restore_switch_id'], f.base.host)
            receipt = f.base.receipt(challenge, bindings['restore_switch_id'])
            self.assertEqual(old.attest_health(previous, previous_sha, bindings['restore_switch_id'],
                                              receipt, f.base.host)['state'], 'healthy')
        self.assertTrue(f.base.host.loaded())
        self.assertFalse(f.base.host.disabled())
        self.assertEqual(f.base.database.read_bytes(), current_database)
        self.assertEqual(m.database_snapshot(f.base.database)['count'], 20)

    def test_noop_targets_do_not_count_as_after_but_after_journal_does(self):
        f = self.f
        f.prepare()
        f.stop()
        self.assertEqual(m._before_code_switch_targets(f.plan)['manifest'],
                         f.plan['targets']['manifest']['after_sha256'])
        m.journal_append(Path(f.plan['operation_directory']) / 'journal.jsonl', 'AFTER_MANIFEST', f.digest)
        with self.assertRaisesRegex(m.MaintenanceError, 'transaction_already_progressed'):
            f.abort()
        self.assertTrue(f.base.host.disabled())

    def test_abort_preserves_partial_backup_before_prepared(self):
        f = self.f
        f.prepare()
        f.stop()
        def interrupted_backup(name):
            if name == 'after_create:origin.before':
                raise RuntimeError('backup interrupted')
        m.FAULT = interrupted_backup
        with self.assertRaises(RuntimeError):
            m.migration_apply(f.plan, f.digest, f.base.host)
        m.FAULT = None
        backup = Path(f.plan['operation_directory']) / 'backups/origin.before'
        raw = backup.read_bytes()
        self.assertNotIn('PREPARED', m.events(Path(f.plan['operation_directory']) / 'journal.jsonl'))
        f.abort()
        self.assertEqual(backup.read_bytes(), raw)

    def test_other_unfinished_operation_and_changed_target_binding_are_refused(self):
        f = self.f
        f.prepare()
        altered = copy.deepcopy(f.plan)
        altered['targets']['projects']['path'] = str(f.base.root / 'another-projects.json')
        with self.assertRaisesRegex(m.MaintenanceError, 'previous_code_switch_binding_changed'):
            m._code_switch_previous(altered)
        f.stop()
        other = copy.deepcopy(f.plan)
        other['operation_id'] = 'other-operation'
        other['operation_directory'] = str(f.base.control / 'identity-repair/other-operation')
        other_sha = m.sha(m.canonical(other))
        operation = m.ensure_operation(other, other_sha)
        m.journal_append(operation / 'journal.jsonl', 'MAINTENANCE_INTENT', other_sha,
                         original_effective_enabled=True)
        with self.assertRaisesRegex(m.MaintenanceError, 'another_unfinished_maintenance_operation'):
            f.abort()
        self.assertFalse(f.output.exists())

    def test_abort_refuses_partial_unknown_pending_and_live_work(self):
        for kind in ('after', 'unknown', 'prepared', 'pending', 'unsafe-job'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='progressive-refuse-') as raw:
                f = ProgressiveFixture(Path(raw).resolve())
                f.prepare()
                f.stop()
                if kind == 'after':
                    f.base.plist.write_bytes(m.decoded(f.plan['targets']['origin']['after']))
                elif kind == 'unknown':
                    f.base.plist.write_bytes(b'unknown bytes')
                elif kind == 'prepared':
                    m.journal_append(Path(f.plan['operation_directory']) / 'journal.jsonl', 'PREPARED', f.digest)
                elif kind == 'pending':
                    f.base.json(f.base.control / m.PENDING, m.pending_value(f.plan, f.digest))
                else:
                    f.add_job('processing')
                with self.assertRaises(m.MaintenanceError):
                    f.abort()
                self.assertFalse(f.output.exists())
                self.assertTrue(f.base.host.disabled())

    def test_aborted_plan_mutations_refuse_before_new_stop_or_start(self):
        f = self.f
        f.prepare()
        f.stop()
        f.abort()
        calls = (f.base.host.starts, f.base.host.stops)
        operations = [lambda: m.switch_stop(f.plan, f.digest, f.base.host),
                      lambda: m.migration_apply(f.plan, f.digest, f.base.host),
                      lambda: m.migration_apply(f.plan, f.digest, f.base.host, recover=True),
                      lambda: m.runtime_switch(f.plan, f.digest, 'candidate', 'new-switch', f.base.host),
                      lambda: m.attest_health(f.plan, f.digest, 'new-switch', f.output, f.base.host),
                      lambda: m.migration_verify(f.plan, f.digest, f.base.host)]
        for operation in operations:
            with self.assertRaisesRegex(m.MaintenanceError, 'maintenance_operation_aborted'):
                operation()
        self.assertEqual((f.base.host.starts, f.base.host.stops), calls)

    def test_intent_before_disabled_interruption_continues_only_same_original_process(self):
        f = self.f
        f.prepare()
        def interrupt(name):
            if name == 'owned_code_stop_checked':
                raise RuntimeError('synthetic interrupt')
        m.FAULT = interrupt
        with self.assertRaises(RuntimeError):
            f.stop()
        m.FAULT = None
        self.assertNotIn('DISABLED', m.events(Path(f.plan['operation_directory']) / 'journal.jsonl'))
        f.base.host.pid += 1
        with self.assertRaisesRegex(m.MaintenanceError, 'owned_stop_previous_process_changed'):
            f.stop()
        f.base.host.pid -= 1
        f.stop()
        f.abort()

    def test_bootout_finished_before_disabled_journal_is_safely_resumed(self):
        f = self.f
        f.prepare()
        actual_stop = f.base.host.stop
        def interrupted_stop(plan):
            actual_stop(plan)
            raise RuntimeError('after bootout, before DISABLED')
        with patch.object(f.base.host, 'stop', side_effect=interrupted_stop):
            with self.assertRaises(RuntimeError):
                f.stop()
        self.assertFalse(f.base.host.loaded())
        f.stop()
        f.abort()

    def test_abort_durable_boundaries_keep_one_switch_and_recreate_missing_work_output(self):
        points = ['after_create:abort-restoration.json', 'abort_restoration_durable',
                  'after_sync:journal:ABORT_INTENT', 'abort_intent_durable',
                  'after_sync:journal:ABORTED_BEFORE_TARGETS', 'abort_terminal_durable',
                  'before_create:restore-bindings.json', 'after_create:restore-bindings.json']
        for selected in points:
            with self.subTest(point=selected), tempfile.TemporaryDirectory(prefix='progressive-abort-fault-') as raw:
                f = ProgressiveFixture(Path(raw).resolve())
                f.prepare()
                f.stop()
                triggered = []
                def fault(name):
                    if name == selected and not triggered:
                        triggered.append(True)
                        raise RuntimeError('synthetic fault')
                m.FAULT = fault
                with self.assertRaises(RuntimeError):
                    f.abort()
                m.FAULT = None
                self.assertTrue(triggered)
                proof_path = Path(f.plan['operation_directory']) / 'abort-restoration.json'
                proof = proof_path.read_bytes()
                f.abort()
                self.assertEqual(proof_path.read_bytes(), proof)
                self.assertEqual(f.output.read_bytes(), proof)
                events = m.events(Path(f.plan['operation_directory']) / 'journal.jsonl')
                self.assertEqual(events.count('ABORT_INTENT'), 1)
                self.assertEqual(events.count('ABORTED_BEFORE_TARGETS'), 1)

    def test_terminal_proof_retrieval_does_not_stop_restored_service_or_overwrite_conflict(self):
        f = self.f
        f.prepare()
        f.stop()
        f.abort()
        raw = f.output.read_bytes()
        f.output.unlink()
        f.base.host.is_loaded = True
        f.base.host.is_disabled = False
        calls = (f.base.host.starts, f.base.host.stops)
        self.assertTrue(f.abort()['idempotent'])
        self.assertEqual(f.output.read_bytes(), raw)
        self.assertEqual((f.base.host.starts, f.base.host.stops), calls)
        f.output.write_bytes(b'conflicting output')
        with self.assertRaisesRegex(m.MaintenanceError, 'restoration_output_conflict'):
            f.abort()
        self.assertEqual(f.output.read_bytes(), b'conflicting output')

    def test_preparer_and_abort_cli_are_explicit_and_no_implicit_apply(self):
        f = self.f
        f.prepare()
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            m.switch_main(['abort-before-targets', '--plan', str(f.plan_path),
                           '--expected-plan-sha256', f.digest,
                           '--restoration-bindings-output', str(f.output)])
        self.assertEqual(caught.exception.code, 2)
        self.assertTrue(f.base.host.loaded())


if __name__ == '__main__':
    unittest.main()
