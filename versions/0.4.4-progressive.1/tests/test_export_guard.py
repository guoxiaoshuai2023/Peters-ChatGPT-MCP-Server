"""Live same-thread health checks and synthetic activation/read barriers."""
import json
import os
import queue
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp import fs_identity
from peters_mcp.private_roots import PrivateRootRegistry


class ExportGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-guard-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool], lock_timeout=3)
        self.registry.initialize()

    def active(self):
        self.registry.register_pending(self.spool, read_roots=[])
        return self.registry.activate(self.spool, read_roots=[])

    def assert_live_health_failure(self, mutation, code='private_protection_unavailable'):
        # Catch the health failure while still holding the guard: failure only
        # at __exit__ would not stop an ongoing transfer promptly.
        checked = False
        with self.assertRaises(AccessError):
            with self.registry.read_guard() as guard:
                mutation()
                error = None
                try:
                    guard.revalidate()
                except Exception as observed:
                    error = observed
                self.assertIsInstance(error, AccessError, 'Live health check must fail with a fixed error')
                self.assertEqual(error.code, code)
                checked = True
        self.assertTrue(checked, 'Health failure occurred only when leaving the guard')

    def test_live_revalidation_and_legal_nesting_keep_same_owner(self):
        active = self.active()
        with self.registry.read_guard() as outer:
            first = outer.revalidate()
            self.assertEqual(first['generation'], active['generation'])
            self.assertRegex(first['digest'], r'^[0-9a-f]{64}$')
            with self.registry.read_guard() as inner:
                self.assertIs(inner, outer)
                self.assertEqual(inner.revalidate(), first)
                inner.check_path(self.root / 'ordinary')
                with self.assertRaises(AccessError) as caught:
                    inner.check_path(self.spool / 'private.bin')
                self.assertEqual(caught.exception.code, 'private_path')
            self.assertEqual(outer.revalidate(), first)
        with self.assertRaises(AccessError):
            outer.revalidate()

    def test_guard_cannot_be_used_by_another_thread(self):
        results = queue.Queue()

        def cross_thread(guard):
            for operation in (guard.revalidate, lambda: guard.check_path(self.root / 'ordinary')):
                try:
                    operation()
                except BaseException as error:
                    results.put(error)
                else:
                    results.put(None)

        with self.registry.read_guard() as guard:
            thread = threading.Thread(target=cross_thread, args=(guard,))
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            for _ in range(2):
                error = results.get_nowait()
                self.assertIsInstance(error, AccessError)
                self.assertEqual(error.code, 'private_protection_unavailable')
            # Foreign-thread rejection must not poison the legitimate owner.
            self.assertEqual(guard.revalidate()['generation'], 1)

    def test_uncoordinated_valid_manifest_change_is_detected_inside_guard(self):
        manifest = self.control / 'private-roots.json'

        def mutate():
            value = json.loads(manifest.read_text())
            value['generation'] += 1
            manifest.write_text(json.dumps(value))

        self.assert_live_health_failure(mutate)

    def test_corrupt_manifest_is_detected_inside_guard(self):
        self.assert_live_health_failure(
            lambda: (self.control / 'private-roots.json').write_text('{synthetic-corrupt'))

    def test_missing_manifest_is_a_fixed_health_error_inside_guard(self):
        self.assert_live_health_failure(lambda: (self.control / 'private-roots.json').unlink())

    def test_replaced_lock_anchor_is_detected_inside_guard(self):
        anchor = self.control / 'private-roots.lock'

        def mutate():
            anchor.rename(self.control / 'retired-synthetic-anchor')
            anchor.touch(mode=0o600)

        self.assert_live_health_failure(mutate)

    def test_missing_lock_anchor_is_a_fixed_health_error_inside_guard(self):
        self.assert_live_health_failure(lambda: (self.control / 'private-roots.lock').unlink())

    def test_replaced_control_anchor_is_detected_inside_guard(self):
        def mutate():
            self.control.rename(self.root / 'retired-control')
            self.control.mkdir(mode=0o700)

        self.assert_live_health_failure(mutate)

    def test_replaced_active_root_is_detected_inside_guard(self):
        self.active()

        def mutate():
            self.spool.rename(self.root / 'retired-spool')
            self.spool.mkdir(mode=0o700)

        self.assert_live_health_failure(mutate, code='private_identity_mismatch')

    def test_active_root_permissions_change_is_detected_inside_guard(self):
        self.active()
        self.assert_live_health_failure(lambda: self.spool.chmod(0o755), code='private_identity_mismatch')

    def test_native_identity_close_uncertainty_survives_live_guard_and_context_exit(self):
        self.active()
        original = fs_identity._close
        failed = []
        retries = []
        def closing(fd):
            if failed and fd == failed[0]:
                retries.append(fd)
            if not failed and os.fstat(fd).st_ino == self.control.stat().st_ino:
                # Actually close this descriptor, then report an uncertain result.
                # The protection layer must preserve its resource-owner signal.
                original(fd)
                failed.append(fd)
                raise AccessError('Synthetic native close uncertainty.', code='identity_cleanup_pending')
            return original(fd)
        with self.assertRaises(AccessError) as escaped:
            with self.registry.read_guard() as guard:
                with patch('peters_mcp.fs_identity._close', closing):
                    try:
                        guard.revalidate()
                    except AccessError as live_error:
                        self.assertEqual(live_error.code, 'protection_cleanup_pending')
                        raise
                    self.fail('Live guard accepted an unconfirmed native close')
        self.assertEqual(escaped.exception.code, 'protection_cleanup_pending')
        self.assertEqual(len(failed), 1)
        self.assertEqual(retries, [])

    def test_activation_waits_for_all_read_owners_then_succeeds(self):
        self.registry.register_pending(self.spool, read_roots=[])
        held = [threading.Event(), threading.Event()]
        release = [threading.Event(), threading.Event()]
        exited = [threading.Event(), threading.Event()]
        starting = threading.Event()
        activation_done = threading.Event()
        failures = queue.Queue()
        activation_result = []
        threads = []

        def reader(index):
            try:
                with self.registry.read_guard() as guard:
                    guard.revalidate()
                    held[index].set()
                    if not release[index].wait(3):
                        raise AssertionError('Synthetic reader was not released')
                    guard.revalidate()
            except BaseException as error:
                failures.put(error)
            finally:
                exited[index].set()

        def activate():
            try:
                starting.set()
                activation_result.append(self.registry.activate(self.spool, read_roots=[]))
            except BaseException as error:
                failures.put(error)
            finally:
                activation_done.set()

        try:
            for index in range(2):
                thread = threading.Thread(target=reader, args=(index,))
                threads.append(thread)
                thread.start()
            for event in held:
                self.assertTrue(event.wait(2), 'Synthetic reader did not acquire the guard')
            thread = threading.Thread(target=activate)
            threads.append(thread)
            thread.start()
            self.assertTrue(starting.wait(1))
            self.assertFalse(activation_done.wait(.1))
            self.assertFalse(self.spool.exists())
            release[0].set()
            self.assertTrue(exited[0].wait(2))
            self.assertFalse(activation_done.wait(.1), 'One remaining read owner was bypassed')
            self.assertFalse(self.spool.exists())
            release[1].set()
            self.assertTrue(activation_done.wait(2), 'Activation did not recover after readers exited')
        finally:
            for event in release:
                event.set()
            for thread in threads:
                thread.join(4)
                self.assertFalse(thread.is_alive(), 'Synthetic test thread remained active')
        if not failures.empty():
            raise failures.get_nowait()
        self.assertEqual(activation_result[0]['status'], 'active')
        with self.registry.read_guard() as guard:
            self.assertEqual(guard.revalidate()['generation'], activation_result[0]['generation'])
            with self.assertRaises(AccessError) as caught:
                guard.check_path(self.spool / 'synthetic.bin')
            self.assertEqual(caught.exception.code, 'private_path')


if __name__ == '__main__':
    unittest.main()
