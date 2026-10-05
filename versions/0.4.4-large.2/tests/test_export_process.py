"""Actual synthetic process exit, pending-copy ownership, and explicit recovery."""
import asyncio
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_context import export_actor_from_verified
from peters_mcp.file_export import ExportConfig, ExportLimits, FileExportService
from peters_mcp.private_roots import PrivateRootRegistry


async def _service_process(root_name, expected_hash, blocked_copy, old, connection):
    root = Path(root_name)
    repo, control, spool = root / 'repo', root / 'control', root / 'spool'
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    catalog = Catalog([Project('synthetic', 'Synthetic', repo)], private_registry=registry)
    entered = threading.Event()
    never_release = threading.Event()
    anonymous = []

    def fault(stage, value):
        if stage == 'anonymous_unlinked':
            anonymous.append(value[1])
        if blocked_copy and stage == 'copy_chunk':
            entered.set()
            # An intentional uninterruptible owner: close cannot release this
            # guard or descriptor. Only this test's actual process exit can.
            never_release.wait()

    service = FileExportService(catalog, ExportConfig(True, spool, min_free_bytes=0),
        limits=ExportLimits(close_seconds=.15), fault_hook=fault)
    actor = export_actor_from_verified('https://synthetic-process.example.test',
                                       'same-owner', time.time() + 3600)
    service.start()
    capability = service.capabilities(actor)

    async def export(cap, key):
        return await service.export_file(actor, 'synthetic', 'main', 'original.bin',
            cap['service_instance_id'], cap['request_window_id'], key, expected_hash,
            wait_seconds=0)

    async def ready(export_id):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            value = await service.get_status(actor, export_id)
            if value['state'] not in ('queued', 'preparing'):
                if value['state'] != 'ready':
                    raise AssertionError('Synthetic preparation failed: ' + value['state'])
                return value
            await asyncio.sleep(.01)
        raise AssertionError('Synthetic preparation did not complete')

    def guard_health():
        # Actual exclusive infrastructure lock is available in this new process.
        active = registry.activate(spool, read_roots=[repo])
        with registry.read_guard() as guard:
            health = guard.revalidate()
            guard.check_path(repo / 'original.bin')
            try:
                guard.check_path(spool / 'private.bin')
            except AccessError as error:
                protected = error.code == 'private_path'
            else:
                protected = False
        return {'active': active['status'], 'generation': health['generation'],
                'private_path_denied': protected}

    try:
        rejected = {}
        if old is not None:
            for label, operation in (
                ('export_id', lambda: service.get_status(actor, old['export_id'])),
                ('instance_id', lambda: export(old['capability'], 'old-effective-request')),
                ('window_id', lambda: export({**capability,
                    'request_window_id': old['capability']['request_window_id']}, 'old-window-request')),
            ):
                try:
                    await operation()
                except AccessError as error:
                    rejected[label] = error.code
                else:
                    raise AssertionError('New instance accepted old ' + label)
        accepted = await export(capability, 'new-explicit-recovery' if old else 'first-process-request')
        if blocked_copy:
            deadline = time.monotonic() + 4
            while not entered.is_set() and time.monotonic() < deadline:
                await asyncio.sleep(.01)
            if not entered.is_set() or len(anonymous) != 1:
                raise AssertionError('Synthetic copy did not reach its blocking point')
            started = time.monotonic()
            first = await asyncio.to_thread(service.close, .04)
            second = await asyncio.to_thread(service.close, .04)
            info = os.fstat(anonymous[0])
            connection.send({'event': 'pending', 'export_id': accepted['export_id'],
                'capability': capability, 'first': first, 'second': second,
                'elapsed': time.monotonic() - started, 'anonymous_fd_live': info.st_nlink == 0,
                'anonymous_size': info.st_size})
            # Parent must terminate/join this exact synthetic process. An EOF or
            # a command is never converted into a fake stopped acknowledgement.
            if connection.recv() is not None:
                raise AssertionError('Blocked-copy child cannot acknowledge graceful completion')
            raise AssertionError('Blocked-copy child exited without the required parent termination')
        value = await ready(accepted['export_id'])
        connection.send({'event': 'ready', 'capability': capability, 'value': value,
                         'rejected': rejected, 'guard': guard_health(),
                         'diagnostics': service.diagnostics()})
        if connection.recv() != 'stop':
            raise AssertionError('Unexpected synthetic control command')
        stopped = await asyncio.to_thread(service.close, 2)
        connection.send({'event': 'closed', 'result': stopped})
        if stopped['state'] != 'stopped':
            raise AssertionError('Synthetic graceful close remained pending')
    finally:
        # This does not claim stopped when the intentionally blocked owner is
        # alive; the parent cleanup still observes and joins the actual process.
        service.close(.1)


def _run_service_process(root_name, expected_hash, blocked_copy, old, connection):
    try:
        asyncio.run(_service_process(root_name, expected_hash, blocked_copy, old, connection))
    except BaseException as error:
        try:
            connection.send({'event': 'failed', 'error_type': type(error).__name__,
                             'code': getattr(error, 'code', None)})
        finally:
            raise
    finally:
        connection.close()


class ExportProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-process-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.body = b'independent synthetic recovery bytes\x00' * 5000
        self.expected_hash = hashlib.sha256(self.body).hexdigest()
        (self.repo / 'original.bin').write_bytes(self.body)
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        registry.initialize()
        registry.register_pending(self.spool, read_roots=[self.repo])
        registry.activate(self.spool, read_roots=[self.repo])

    def spawn(self, *, blocked=False, old=None):
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe()
        process = context.Process(target=_run_service_process,
            args=(str(self.root), self.expected_hash, blocked, old, child))
        process.start()
        child.close()
        self.addCleanup(parent.close)

        def cleanup():
            if process.is_alive():
                process.terminate()
            process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            self.assertFalse(process.is_alive(), 'Synthetic child remained alive after cleanup')
            process.close()

        self.addCleanup(cleanup)
        return process, parent

    def receive(self, connection, event):
        self.assertTrue(connection.poll(6), 'Synthetic child did not produce ' + event)
        result = connection.recv()
        self.assertEqual(result['event'], event, result)
        return result

    def assert_ready(self, message):
        value = message['value']
        self.assertEqual(value['state'], 'ready')
        self.assertEqual(value['sha256'], self.expected_hash)
        self.assertEqual(value['bytes'], len(self.body))
        self.assertEqual(message['diagnostics']['snapshot_fds'], 1)
        self.assertEqual(message['guard']['active'], 'active')
        self.assertTrue(message['guard']['private_path_denied'])

    def stop_and_join(self, process, connection):
        connection.send('stop')
        closed = self.receive(connection, 'closed')
        self.assertEqual(closed['result']['state'], 'stopped')
        self.assertEqual(closed['result']['snapshot_fds'], 0)
        process.join(4)
        self.assertFalse(process.is_alive(), 'Stopped report preceded actual process exit')
        self.assertEqual(process.exitcode, 0)

    def restore_after_confirmed_exit(self, process, previous):
        self.assertFalse(process.is_alive(), 'Recovery started before old process exit')
        self.assertIsNotNone(process.exitcode)
        old = {'export_id': previous.get('export_id', previous.get('value', {}).get('export_id')),
               'capability': previous['capability']}
        recovered_process, connection = self.spawn(old=old)
        recovered = self.receive(connection, 'ready')
        self.assert_ready(recovered)
        self.assertNotEqual(recovered['value']['export_id'], old['export_id'])
        self.assertNotEqual(recovered['capability']['service_instance_id'],
                            old['capability']['service_instance_id'])
        self.assertEqual(recovered['rejected'], {'export_id': 'export_unavailable',
                         'instance_id': 'instance_changed', 'window_id': 'request_window_expired'})
        self.stop_and_join(recovered_process, connection)

    def test_actual_graceful_process_exit_then_new_instance_same_hash_recovery(self):
        process, connection = self.spawn()
        previous = self.receive(connection, 'ready')
        self.assert_ready(previous)
        self.stop_and_join(process, connection)
        self.restore_after_confirmed_exit(process, previous)

    def test_blocked_copy_keeps_pending_owner_and_fd_until_actual_exit_then_recovers(self):
        process, connection = self.spawn(blocked=True)
        previous = self.receive(connection, 'pending')
        self.assertTrue(process.is_alive())
        self.assertLess(previous['elapsed'], 1)
        self.assertTrue(previous['anonymous_fd_live'])
        for diagnostics in (previous['first'], previous['second']):
            self.assertEqual(diagnostics['state'], 'shutdown_pending')
            self.assertEqual(diagnostics['prepare_owners'], 1)
            self.assertEqual(diagnostics['snapshot_reservations'], 1)
            self.assertEqual(diagnostics['snapshot_bytes_reserved'], len(self.body))
            self.assertGreaterEqual(diagnostics['auxiliary_fd_reservations'], 10)
            self.assertGreaterEqual(diagnostics['total_fd_reservations'], 11)
        # The live blocked owner still holds the actual inter-process read
        # barrier; close's timeout must not pretend to have unlocked it.
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool], lock_timeout=.1)
        with self.assertRaises(AccessError) as caught:
            registry.activate(self.spool, read_roots=[self.repo])
        self.assertEqual(caught.exception.code, 'private_protection_busy')
        process.terminate()  # Only the synthetic process created by this test.
        process.join(4)
        self.assertFalse(process.is_alive(), 'Synthetic process did not actually terminate')
        self.assertNotEqual(process.exitcode, 0)
        self.assertIsNotNone(process.exitcode)
        self.restore_after_confirmed_exit(process, previous)


if __name__ == '__main__':
    unittest.main()
