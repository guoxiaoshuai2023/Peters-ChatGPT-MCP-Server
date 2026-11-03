"""Synthetic persistent-root safety and real cross-process protection barriers."""
import json
import multiprocessing
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.private_roots import PrivateRootRegistry, validate_manifest_v2
from peters_mcp.fs_identity import persistent_identity
from peters_mcp import fs_identity


def _old_reader(control, spool, connection):
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    with registry.read_guard() as guard:
        guard.check_path(Path(spool) / 'synthetic.txt')
        connection.send(('held', guard.generation))
        connection.recv()
        # Result construction remains inside the shared barrier.
        connection.send(('result_built', guard.generation))
    connection.send(('released',))
    connection.close()


def _activator(control, spool, connection):
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    connection.send(('starting',))
    registry.register_pending(spool, read_roots=[])
    result = registry.activate(spool, read_roots=[])
    Path(spool, 'synthetic.txt').write_text('private synthetic bytes')
    connection.send(('active_with_data', result['generation']))
    connection.close()


def _late_reader(control, spool, connection):
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    with registry.read_guard() as guard:
        old_generation = guard.generation
    connection.send(('loaded_old', old_generation))
    connection.recv()
    with registry.read_guard() as guard:
        try:
            guard.check_path(Path(spool) / 'synthetic.txt')
        except AccessError as error:
            connection.send(('denied', guard.generation, error.code))
        else:
            connection.send(('unsafe', guard.generation))
    connection.close()


def _pending_crash(control, spool):
    PrivateRootRegistry(control, allowed_roots=[spool]).register_pending(spool, read_roots=[])
    os._exit(29)


def _try_lock(control, connection):
    fd = os.open(Path(control) / 'private-roots.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            connection.send('blocked')
        else:
            connection.send('acquired')
    finally:
        os.close(fd)
        connection.close()


class PrivateRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='private-root-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.root / 'spool'
        self.registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])

    def initialized(self):
        self.registry.initialize()
        return self.registry

    def active(self):
        registry = self.initialized()
        registry.register_pending(self.spool, read_roots=[])
        return registry.activate(self.spool, read_roots=[])

    def spawn(self, target, *args):
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe()
        process = context.Process(target=target, args=(*args, child))
        process.start()
        child.close()
        self.addCleanup(parent.close)
        def cleanup():
            if process.is_alive():
                process.terminate()
            process.join(5)
            self.assertFalse(process.is_alive())
            process.close()
        self.addCleanup(cleanup)
        return process, parent

    def receive(self, connection):
        self.assertTrue(connection.poll(8), 'Synthetic process did not respond')
        return connection.recv()

    def test_constructor_and_queries_never_initialize(self):
        self.assertEqual(list(self.control.iterdir()), [])
        with self.assertRaises(AccessError):
            with self.registry.read_guard():
                self.fail('Missing manifest permitted access')
        with self.assertRaises(AccessError):
            self.registry.spool_for(self.root.stat().st_dev)
        self.assertEqual(list(self.control.iterdir()), [])
        self.assertFalse(self.spool.exists())
        with self.assertRaises(AccessError):
            PrivateRootRegistry(self.root / 'missing-control', allowed_roots=[])
        self.assertFalse((self.root / 'missing-control').exists())

    def test_pending_then_empty_identity_then_active_and_read_only_selection(self):
        self.initialized()
        before = set(self.control.iterdir())
        self.assertIsNone(self.registry.spool_for(self.root.stat().st_dev))
        self.assertEqual(set(self.control.iterdir()), before)
        pending = self.registry.register_pending(self.spool, read_roots=[])
        self.assertEqual(pending['status'], 'pending')
        self.assertFalse(self.spool.exists())
        with self.registry.read_guard() as guard:
            with self.assertRaisesRegex(AccessError, 'private_path'):
                guard.check_path(self.spool / 'not-created.txt')
            guard.check_path(self.root / 'normal.txt')
        active = self.registry.activate(self.spool, read_roots=[])
        self.assertEqual(active['status'], 'active')
        self.assertEqual(active['identity'], persistent_identity(self.spool))
        self.assertEqual(self.spool.stat().st_mode & 0o777, 0o700)
        self.assertGreater(active['generation'], pending['generation'])
        before = {p.name for p in self.spool.iterdir()}
        selected = self.registry.spool_for(self.spool.stat().st_dev)
        self.assertEqual(selected['path'], str(self.spool))
        self.assertEqual(selected['identity'], [self.spool.stat().st_dev, self.spool.stat().st_ino])
        self.assertEqual(selected['parent_identity'], [self.root.stat().st_dev, self.root.stat().st_ino])
        self.assertEqual({p.name for p in self.spool.iterdir()}, before)
        self.assertIsNone(self.registry.spool_for(-1 + 2**62))
        self.assertIsNone(self.registry.spool_for(self.spool.stat().st_dev, roots=[]))

    def test_existing_read_root_overlap_in_both_directions_and_unmanaged_mkdir(self):
        self.initialized()
        for read_root in (self.root, self.spool, self.spool / 'nested'):
            with self.subTest(read_root=read_root):
                with self.assertRaisesRegex(AccessError, 'private_root_overlap'):
                    self.registry.register_pending(self.spool, read_roots=[read_root])
        unknown = self.root / 'not-allowed'
        with self.assertRaisesRegex(AccessError, 'private_root_not_allowed'):
            self.registry.register_pending(unknown, read_roots=[])
        with self.assertRaises(AccessError):
            self.registry.activate(self.spool, read_roots=[])
        self.assertFalse(self.spool.exists())
        self.assertFalse(unknown.exists())

    def test_guard_nesting_and_retained_roots_when_write_configuration_removed(self):
        self.active()
        removed = PrivateRootRegistry(self.control, allowed_roots=[])
        with removed.read_guard() as outer:
            with removed.read_guard() as inner:
                self.assertIs(outer, inner)
                with self.assertRaisesRegex(AccessError, 'private_path'):
                    removed.check_path(self.spool / 'file.bin')
                removed.check_path(self.root / 'ordinary')
            with self.assertRaisesRegex(AccessError, 'private_path'):
                outer.check_path(self.control / 'private-roots.json')
        with self.assertRaises(AccessError):
            outer.check_path(self.root / 'ordinary')
        with self.assertRaises(AccessError):
            removed.check_path(self.root / 'ordinary')
        self.assertIsNone(removed.spool_for(self.spool.stat().st_dev))
        # A later broader project can read ordinary descendants, never protected ones.
        with removed.read_guard() as guard:
            guard.check_path(self.root)
            with self.assertRaises(AccessError):
                guard.check_path(self.spool)

    def test_corrupt_deleted_or_hardlinked_manifest_is_fail_closed_not_reset(self):
        self.initialized()
        manifest = self.control / 'private-roots.json'
        original = manifest.read_bytes()
        for mode in ('corrupt', 'missing', 'hardlink'):
            with self.subTest(mode=mode):
                if mode == 'corrupt':
                    manifest.write_bytes(b'{bad')
                elif mode == 'missing':
                    manifest.unlink()
                else:
                    os.link(manifest, self.control / 'alias')
                with self.assertRaises(AccessError):
                    with self.registry.read_guard() as guard:
                        guard.check_path(self.root / 'ordinary')
                with self.assertRaises(AccessError):
                    self.registry.initialize()
                (self.control / 'alias').unlink(missing_ok=True)
                manifest.unlink(missing_ok=True)
                manifest.write_bytes(original)
                manifest.chmod(0o600)

    def test_aliases_noncanonical_roots_and_changed_active_identity(self):
        unicode_root = self.root / '\u00c9vidence'
        registry = PrivateRootRegistry(self.control, allowed_roots=[unicode_root])
        registry.initialize()
        registry.register_pending(unicode_root, read_roots=[])
        registry.activate(unicode_root, read_roots=[])
        alias = self.root / 'alias'
        alias.symlink_to(unicode_root, target_is_directory=True)
        with registry.read_guard() as guard:
            for path in (self.root / 'e\u0301VIDENCE' / 'item', alias / 'item'):
                with self.subTest(path=path), self.assertRaisesRegex(AccessError, 'private_path'):
                    guard.check_path(path)
        with self.assertRaises(AccessError):
            PrivateRootRegistry(self.control, allowed_roots=[alias])
        unicode_root.rename(self.root / 'moved')
        unicode_root.mkdir(mode=0o700)
        with self.assertRaises(AccessError):
            with registry.read_guard():
                self.fail('Replaced active root must close access')

    def test_existing_nonempty_root_rejected_and_pending_retained_after_identity_failure(self):
        self.initialized()
        self.registry.register_pending(self.spool, read_roots=[])
        self.spool.mkdir(mode=0o700)
        (self.spool / 'unowned').write_text('do not remove')
        with self.assertRaises(AccessError):
            self.registry.activate(self.spool, read_roots=[])
        self.assertEqual((self.spool / 'unowned').read_text(), 'do not remove')
        self.assertIsNone(self.registry.spool_for(self.spool.stat().st_dev))
        with self.registry.read_guard() as guard:
            with self.assertRaises(AccessError):
                guard.check_path(self.spool / 'unowned')

    def test_pending_crash_recovers_protection_and_explicit_activation(self):
        self.initialized()
        context = multiprocessing.get_context('spawn')
        process = context.Process(target=_pending_crash, args=(str(self.control), str(self.spool)))
        process.start()
        try:
            process.join(8)
            self.assertEqual(process.exitcode, 29)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            process.close()
        fresh = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        with fresh.read_guard() as guard:
            with self.assertRaises(AccessError):
                guard.check_path(self.spool / 'future')
        self.assertFalse(self.spool.exists())
        self.assertEqual(fresh.activate(self.spool, read_roots=[])['status'], 'active')

    def test_failure_after_identity_commit_never_marks_active(self):
        self.initialized()
        self.registry.register_pending(self.spool, read_roots=[])
        original = self.registry._store
        def crash_before_active(fd, data):
            if data['roots'][0]['status'] == 'active':
                raise OSError('synthetic active commit failure')
            original(fd, data)
        with patch.object(self.registry, '_store', crash_before_active):
            with self.assertRaises(AccessError):
                self.registry.activate(self.spool, read_roots=[])
        fresh = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        self.assertIsNone(fresh.spool_for(self.spool.stat().st_dev))
        self.assertEqual(fresh.activate(self.spool, read_roots=[])['status'], 'active')

    def test_real_process_barrier_drains_old_result_and_late_reader_loads_new_epoch(self):
        self.initialized()
        old, old_pipe = self.spawn(_old_reader, str(self.control), str(self.spool))
        self.assertEqual(self.receive(old_pipe), ('held', 1))
        late, late_pipe = self.spawn(_late_reader, str(self.control), str(self.spool))
        self.assertEqual(self.receive(late_pipe), ('loaded_old', 1))
        activation, activation_pipe = self.spawn(_activator, str(self.control), str(self.spool))
        self.assertEqual(self.receive(activation_pipe), ('starting',))
        self.assertFalse(activation_pipe.poll(.2))
        self.assertFalse(self.spool.exists())
        old_pipe.send('finish result')
        self.assertEqual(self.receive(old_pipe), ('result_built', 1))
        self.assertEqual(self.receive(old_pipe), ('released',))
        active = self.receive(activation_pipe)
        self.assertEqual(active[0], 'active_with_data')
        self.assertGreater(active[1], 1)
        late_pipe.send('become ready')
        denied = self.receive(late_pipe)
        self.assertEqual(denied, ('denied', active[1], 'private_path'))
        for process in (old, late, activation):
            process.join(5)
            self.assertEqual(process.exitcode, 0)

    def test_two_instances_never_reuse_stale_epoch_and_cannot_mutate_inside_guard(self):
        self.initialized()
        other = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        with other.read_guard() as guard:
            self.assertEqual(guard.generation, 1)
        self.registry.register_pending(self.spool, read_roots=[])
        with other.read_guard() as guard:
            self.assertEqual(guard.generation, 2)
            with self.assertRaisesRegex(AccessError, 'private_protection_busy'):
                other.activate(self.spool, read_roots=[])
            with self.assertRaises(AccessError):
                guard.check_path(self.spool)

    def test_control_directory_replaced_during_operation_refuses_result(self):
        self.initialized()
        moved = self.root / 'control-moved'
        try:
            with self.assertRaises(AccessError):
                with self.registry.read_guard():
                    self.control.rename(moved)
                    self.control.mkdir(mode=0o700)
                    # A response cannot escape the outer guard after anchor movement.
        finally:
            if moved.exists():
                self.control.rmdir()
                moved.rename(self.control)

    def test_generation_rollback_refused_after_successful_mutation(self):
        self.initialized()
        manifest = self.control / 'private-roots.json'
        old = manifest.read_bytes()
        self.registry.register_pending(self.spool, read_roots=[])
        manifest.write_bytes(old)
        with self.assertRaisesRegex(AccessError, 'generation moved backwards'):
            with self.registry.read_guard():
                self.fail('An observed old generation was accepted')

    def test_v1_requires_explicit_migration_and_never_changes_bytes(self):
        self.active()
        manifest = self.control / 'private-roots.json'
        data = json.loads(manifest.read_bytes())
        data['version'] = 1
        data['control_identity'] = [self.control.stat().st_dev, self.control.stat().st_ino]
        lock = self.control / 'private-roots.lock'
        data['lock_identity'] = [lock.stat().st_dev, lock.stat().st_ino]
        data['roots'][0]['identity'] = [self.spool.stat().st_dev, self.spool.stat().st_ino]
        data['roots'][0]['parent_identity'] = [self.root.stat().st_dev, self.root.stat().st_ino]
        manifest.write_text(json.dumps(data))
        original = manifest.read_bytes()
        fresh = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        with self.assertRaisesRegex(AccessError, 'private_identity_migration_required'):
            with fresh.read_guard():
                self.fail('legacy manifest opened')
        with self.assertRaisesRegex(AccessError, 'private_identity_migration_required'):
            fresh.initialize()
        self.assertEqual(manifest.read_bytes(), original)

    def test_pending_marker_closes_normal_reads_without_inspecting_its_contents(self):
        self.active()
        pending = self.control / 'identity-migration.pending.json'
        pending.write_bytes(b'no generic bypass is available')
        for operation in (self.registry.initialize, lambda: self.registry.spool_for(self.root.stat().st_dev)):
            with self.subTest(operation=operation), self.assertRaisesRegex(AccessError, 'migration_pending'):
                operation()

    def test_deleted_lock_is_never_recreated_by_explicit_initialize(self):
        self.active()
        lock = self.control / 'private-roots.lock'
        manifest = self.control / 'private-roots.json'
        original = manifest.read_bytes()
        lock.unlink()
        with self.assertRaises(AccessError):
            self.registry.initialize()
        self.assertFalse(lock.exists())
        self.assertEqual(manifest.read_bytes(), original)

    def test_new_registry_accepts_only_device_drift_and_projects_current_runtime_pairs(self):
        self.active()
        manifest = self.control / 'private-roots.json'
        before = manifest.read_bytes()
        original_fstat, original_stat = os.fstat, os.stat
        class Drift:
            def __init__(self, value):
                self._value = value
                self.st_dev = value.st_dev + 700
            def __getattr__(self, name):
                return getattr(self._value, name)
        def fstat(fd):
            return Drift(original_fstat(fd))
        def stat_path(*args, **kwargs):
            return Drift(original_stat(*args, **kwargs))
        device = self.spool.stat().st_dev + 700
        with patch('os.fstat', fstat), patch('os.stat', stat_path):
            fresh = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
            with fresh.read_guard() as guard:
                self.assertEqual(guard.generation, self.registry._highest_generation)
                with self.assertRaisesRegex(AccessError, 'private_path'):
                    guard.check_path(self.spool / 'data')
            selected = fresh.spool_for(device)
            self.assertEqual(selected['identity'], [device, self.spool.stat().st_ino])
            self.assertEqual(selected['parent_identity'], [device, self.root.stat().st_ino])
            self.assertIsNone(fresh.spool_for(device - 700))
        self.assertEqual(manifest.read_bytes(), before)
        self.assertIsInstance(json.loads(before)['roots'][0]['identity'], dict)

    def test_live_guard_allows_normal_spool_child_creation_during_stable_identity_read(self):
        self.active()
        manifest = self.control / 'private-roots.json'
        before = manifest.read_bytes()
        original = fs_identity._attribute_bytes
        spool_inode = self.spool.stat().st_ino
        observations = []
        def attributes(fd, common, volume):
            output = original(fd, common, volume)
            info = os.fstat(fd)
            if not observations and info.st_ino == spool_inode:
                (self.spool / 'normal-job').mkdir(mode=0o700)
                observations.append((info.st_nlink, os.fstat(fd).st_nlink))
            return output
        with self.registry.read_guard() as guard:
            with patch.object(fs_identity, '_attribute_bytes', attributes):
                self.assertEqual(guard.revalidate()['generation'], self.registry._highest_generation)
            with self.assertRaisesRegex(AccessError, 'private_path'):
                guard.check_path(self.spool / 'normal-job' / 'payload')
        self.assertEqual(observations, [(2, 3)])
        self.assertEqual(manifest.read_bytes(), before)

    def test_each_stable_field_change_is_refused(self):
        self.active()
        manifest = self.control / 'private-roots.json'
        original = json.loads(manifest.read_bytes())
        for anchor in ('control_identity', 'lock_identity', 'parent_identity', 'identity'):
            for field, value in [('volume_uuid', '12345678-90ab-cdef-1234-567890abcdef'),
                                 ('file_id', 1), ('birthtime_ns', 1)]:
                data = json.loads(json.dumps(original))
                location = data if anchor in {'control_identity', 'lock_identity'} else data['roots'][0]
                location[anchor][field] = value
                manifest.write_text(json.dumps(data))
                with self.subTest(anchor=anchor, field=field), self.assertRaisesRegex(AccessError, 'identity_mismatch'):
                    fresh = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
                    with fresh.read_guard():
                        self.fail('changed stable identity opened')
        manifest.write_text(json.dumps(original))

    def test_strict_schema_rejects_invalid_identity_or_duplicate_json_fields(self):
        self.active()
        manifest = self.control / 'private-roots.json'
        original = manifest.read_bytes()
        data = json.loads(original)
        for mutation in ('boolean', 'unknown', 'active-null', 'extra-row'):
            bad = json.loads(original)
            if mutation == 'boolean':
                bad['control_identity']['file_id'] = True
            elif mutation == 'unknown':
                bad['control_identity']['st_dev'] = 10
            elif mutation == 'active-null':
                bad['roots'][0]['identity'] = None
            else:
                bad['roots'][0]['extra'] = None
            manifest.write_text(json.dumps(bad))
            with self.subTest(mutation=mutation), self.assertRaises(AccessError):
                with self.registry.read_guard():
                    self.fail('invalid schema opened')
        manifest.write_bytes(original[:-1] + b',"version":2}')
        with self.assertRaises(AccessError):
            with self.registry.read_guard():
                self.fail('duplicate field opened')
        manifest.write_bytes(original)

    def test_pure_validation_reuses_held_exclusive_lock_and_preserves_pending(self):
        self.active()
        data = json.loads((self.control / 'private-roots.json').read_bytes())
        control = os.open(self.control, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock = os.open(self.control / 'private-roots.lock', os.O_RDWR | os.O_NOFOLLOW)
        pending = self.control / 'identity-migration.pending.json'
        pending.write_text('synthetic maintenance owns its exact operation marker')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for _ in range(2):
                # Validation must neither reacquire SH nor close the caller FDs.
                with patch('peters_mcp.private_roots.fcntl.flock', side_effect=AssertionError('reentered lock')):
                    self.assertIs(validate_manifest_v2(data, control, lock, control_dir=self.control), data)
                process, connection = self.spawn(_try_lock, str(self.control))
                self.assertEqual(self.receive(connection), 'blocked')
                process.join(5)
                self.assertEqual(process.exitcode, 0)
            self.assertTrue(pending.exists())
            self.assertEqual(os.fstat(control).st_ino, self.control.stat().st_ino)
            self.assertEqual(os.fstat(lock).st_ino, (self.control / 'private-roots.lock').stat().st_ino)
        finally:
            os.close(lock)
            os.close(control)

    def test_lock_hardlink_and_root_permissions_still_refused(self):
        self.active()
        lock = self.control / 'private-roots.lock'
        os.link(lock, self.control / 'lock-alias')
        with self.assertRaises(AccessError):
            with self.registry.read_guard():
                self.fail('hardlinked lock opened')
        (self.control / 'lock-alias').unlink()
        self.spool.chmod(0o755)
        with self.assertRaises(AccessError):
            with self.registry.read_guard():
                self.fail('root permissions changed')
        self.spool.chmod(0o700)
        with self.registry.read_guard():
            pass

    def test_parent_and_lock_replacement_during_guard_refuse_result(self):
        self.active()
        parent = self.root / 'spool-parent'
        parent.mkdir(mode=0o700)
        nested = parent / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool, nested])
        registry.register_pending(nested, read_roots=[])
        registry.activate(nested, read_roots=[])
        with self.assertRaises(AccessError):
            with registry.read_guard():
                parent.rename(self.root / 'moved-parent')
                parent.mkdir(mode=0o700)
                nested.mkdir(mode=0o700)
        nested.rmdir()
        parent.rmdir()
        (self.root / 'moved-parent').rename(parent)
        lock = self.control / 'private-roots.lock'
        with self.assertRaises(AccessError):
            with registry.read_guard():
                lock.rename(self.control / 'original-lock')
                lock.write_bytes(b'')
                lock.chmod(0o600)

    def test_control_descriptor_close_uncertainty_is_not_swallowed(self):
        self.initialized()
        original = os.close
        fired = False
        def close(fd):
            nonlocal fired
            info = os.fstat(fd)
            original(fd)
            if not fired and info.st_ino == self.control.stat().st_ino:
                fired = True
                raise OSError('synthetic closed but unconfirmed')
        with patch('peters_mcp.private_roots.os.close', close):
            with self.assertRaisesRegex(AccessError, 'cleanup_pending'):
                with self.registry.read_guard():
                    self.fail('uncertain close opened')


if __name__ == '__main__':
    unittest.main()
