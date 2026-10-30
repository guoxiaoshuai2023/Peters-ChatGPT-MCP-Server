"""Regressions for lock-time authority and historical spool/ledger continuity."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_progressive_maintenance import ProgressiveFixture, m


def ledger(path, rows):
    connection = sqlite3.connect(path)
    connection.execute('DELETE FROM ledger')
    connection.executemany('INSERT INTO ledger VALUES (?,?,?)', rows)
    connection.commit()
    connection.close()


def restore_old(f):
    bindings = json.loads(f.output.read_bytes())
    with patch.object(sys, 'path', list(sys.path)):
        spec = importlib.util.spec_from_file_location('old_r7_continuity_test',
                                                      f.old_tools / 'identity_maintenance.py')
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        previous, digest = old.load_plan(bindings['previous_plan_path'], bindings['previous_plan_sha256'])
        challenge = old.runtime_switch(previous, digest, bindings['previous_active_bundle'],
                                       bindings['restore_switch_id'], f.base.host)
        receipt = f.base.receipt(challenge, bindings['restore_switch_id'])
        return old.attest_health(previous, digest, bindings['restore_switch_id'], receipt, f.base.host)


class ProgressiveContinuityTests(unittest.TestCase):
    def test_delayed_mutator_rechecks_abort_after_operator_mutex(self):
        with tempfile.TemporaryDirectory(prefix='progressive-lock-race-') as raw:
            f = ProgressiveFixture(Path(raw).resolve())
            f.prepare()
            f.stop()
            arrived, proceed = threading.Event(), threading.Event()
            actual_lock = m.operator_lock
            result = []
            @contextmanager
            def delayed_lock(plan, digest):
                if threading.current_thread().name == 'queued-stop':
                    arrived.set()
                    if not proceed.wait(10):
                        raise AssertionError('test gate timed out')
                with actual_lock(plan, digest):
                    yield
            def queued_stop():
                try:
                    result.append(f.stop())
                except BaseException as error:
                    result.append(error)
            with patch.object(m, 'operator_lock', delayed_lock):
                thread = threading.Thread(target=queued_stop, name='queued-stop')
                thread.start()
                try:
                    self.assertTrue(arrived.wait(5))
                    f.abort()
                    self.assertEqual(restore_old(f)['state'], 'healthy')
                    calls = (f.base.host.starts, f.base.host.stops)
                    journal = (Path(f.plan['operation_directory']) / 'journal.jsonl').read_bytes()
                finally:
                    proceed.set()
                    thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(result), 1)
            self.assertIsInstance(result[0], m.MaintenanceError)
            self.assertEqual(result[0].code, 'maintenance_operation_aborted')
            self.assertEqual((f.base.host.starts, f.base.host.stops), calls)
            self.assertEqual((Path(f.plan['operation_directory']) / 'journal.jsonl').read_bytes(), journal)
            self.assertTrue(f.base.host.loaded())
            self.assertFalse(f.base.host.disabled())

    def test_retained_old_spool_changes_are_rejected_before_preparation_and_abort(self):
        for moment in ('prepare', 'abort'):
            for change in ('changed', 'deleted'):
                with self.subTest(moment=moment, change=change), tempfile.TemporaryDirectory(prefix='spool-continuity-') as raw:
                    f = ProgressiveFixture(Path(raw).resolve())
                    if moment == 'abort':
                        f.prepare()
                        f.stop()
                    if change == 'changed':
                        f.base.legacy_payload.write_bytes(b'changed old retained payload')
                    else:
                        f.base.legacy_payload.unlink()
                    with self.assertRaisesRegex(m.MaintenanceError, 'legacy_spool_scene_changed'):
                        f.prepare() if moment == 'prepare' else f.abort()
                    self.assertFalse(f.output.exists())

    def test_additional_terminal_spool_item_preserves_old_restore(self):
        with tempfile.TemporaryDirectory(prefix='spool-forward-') as raw:
            f = ProgressiveFixture(Path(raw).resolve())
            f.add_job()
            item = f.base.spool / 'new-terminal-job-payload'
            item.write_bytes(b'new legitimate terminal payload')
            item.chmod(0o600)
            before = f.base.legacy_payload.read_bytes()
            f.prepare()
            f.stop()
            f.abort()
            self.assertEqual(restore_old(f)['state'], 'healthy')
            self.assertEqual(f.base.legacy_payload.read_bytes(), before)
            self.assertEqual(item.read_bytes(), b'new legitimate terminal payload')

    def test_ledger_regression_is_rejected_at_prepare_and_abort(self):
        changes = {'deletion': [], 'generation_rollback': [(':file-service', 1, 1)],
                   'same_generation_resurrection': [(':file-service', 7, 1)]}
        for moment in ('prepare', 'abort'):
            for name, entries in changes.items():
                with self.subTest(moment=moment, change=name), tempfile.TemporaryDirectory(prefix='ledger-regression-') as raw:
                    f = ProgressiveFixture(Path(raw).resolve(), [(':file-service', 7, 0)], legacy_hash_only=True)
                    if moment == 'abort':
                        f.prepare()
                        f.stop()
                    ledger(f.base.database, entries)
                    with self.assertRaisesRegex(m.MaintenanceError, 'historical_ledger_regressed'):
                        f.prepare() if moment == 'prepare' else f.abort()
                    self.assertFalse(f.output.exists())

    def test_bound_history_backup_supports_forward_ledger_changes_without_writes(self):
        with tempfile.TemporaryDirectory(prefix='ledger-forward-') as raw:
            f = ProgressiveFixture(Path(raw).resolve(), [(':file-service', 7, 0)], legacy_hash_only=True)
            self.assertNotIn('ledger_entries', f.base.plan['database'])
            backup = Path(f.base.plan['operation_directory']) / 'backups/database.before'
            backup_before = backup.read_bytes()
            ledger(f.base.database, [(':file-service', 8, 1), ('new-scope', 1, 0)])
            current = f.base.database.read_bytes()
            f.prepare()
            self.assertEqual(f.base.database.read_bytes(), current)
            self.assertEqual(f.plan['database']['ledger_entries'], [[':file-service', 8, 1], ['new-scope', 1, 0]])
            self.assertEqual(backup.read_bytes(), backup_before)
            self.assertFalse(any(Path(str(backup) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')))
            f.stop()
            ledger(f.base.database, [(':file-service', 9, 0), ('new-scope', 2, 1), ('another', 1, 1)])
            current = f.base.database.read_bytes()
            f.abort()
            self.assertEqual(restore_old(f)['state'], 'healthy')
            self.assertEqual(f.base.database.read_bytes(), current)
            self.assertEqual(backup.read_bytes(), backup_before)

    def test_hash_only_history_requires_exact_backup_without_sidecars(self):
        for change in ('modified', 'missing', 'sidecar'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='ledger-backup-') as raw:
                f = ProgressiveFixture(Path(raw).resolve(), [(':file-service', 7, 0)], legacy_hash_only=True)
                backup = Path(f.base.plan['operation_directory']) / 'backups/database.before'
                if change == 'modified':
                    backup.write_bytes(backup.read_bytes() + b'corrupt')
                elif change == 'missing':
                    backup.unlink()
                else:
                    Path(str(backup) + '-wal').write_bytes(b'')
                with self.assertRaises((m.MaintenanceError, OSError)):
                    f.prepare()
                self.assertFalse(f.plan_path.exists())


if __name__ == '__main__':
    unittest.main()
