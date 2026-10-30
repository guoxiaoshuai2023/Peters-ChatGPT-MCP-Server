"""Same-plan receiver tests use owned temporary inputs, never native/production."""
import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from peters_mcp import native_chunk_receiver as receiver
from peters_mcp import transport_asset as asset
from peters_mcp.catalog import AccessError


class InjectedCrash(Exception):
    pass


def signed(plan):
    plan = copy.deepcopy(plan)
    plan.pop('plan_sha256', None)
    plan['plan_sha256'] = hashlib.sha256(receiver.canonical(plan)).hexdigest()
    return plan


def make_plan(data):
    helper = Path(receiver.__file__).read_bytes()
    parts = []
    for i in range(max(1, (len(data) + receiver.PART_BYTES - 1) // receiver.PART_BYTES)):
        block = data[i * receiver.PART_BYTES:(i + 1) * receiver.PART_BYTES]
        parts.append({'index': i, 'offset': i * receiver.PART_BYTES, 'bytes': len(block),
                      'sha256': hashlib.sha256(block).hexdigest(), 'resource_name': 'synthetic-part-' + str(i) + '.bin'})
    return signed({'protocol_version': receiver.PROTOCOL, 'service_instance_id': '1' * 32,
                   'export_id': '2' * 32, 'source': {'project_id': 'synthetic', 'worktree_id': 'main', 'path': 'sample.zip'},
                   'capture_version_sha256': '3' * 64, 'total_bytes': len(data),
                   'total_sha256': hashlib.sha256(data).hexdigest(), 'part_max_bytes': receiver.PART_BYTES,
                   'part_count': len(parts), 'parts': parts,
                   'receiver_asset': {'asset_id': receiver.ASSET_ID, 'name': receiver.ASSET_NAME,
                                      'bytes': len(helper), 'sha256': hashlib.sha256(helper).hexdigest()},
                   'expires_at_unix': 1})


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='same-plan-receiver-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / 'inputs'
        self.output = self.root / 'output'
        self.inputs.mkdir()
        self.output.mkdir()

    def prepare(self, data=b'actual source bytes', name='target.zip'):
        plan = make_plan(data)
        paths = []
        for part in plan['parts']:
            path = self.inputs / part['resource_name']
            path.write_bytes(data[part['offset']:part['offset'] + part['bytes']])
            paths.append(path)
        r = receiver.NativeChunkReceiver.start(plan, self.output, self.inputs, name)
        return r, plan, paths

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(receiver.ReceiverError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_opaque_file_publish_duplicate_ingest_and_same_plan_resume(self):
        data = b'not parsed or executed' * 100
        r, plan, paths = self.prepare(data)
        renamed = self.inputs / 'host-renamed-actual-file.bin'
        paths[0].rename(renamed)
        first = r.ingest(0, renamed)
        self.assertEqual(first['appended_bytes'], len(data))
        other = self.inputs / 'another-actual-reference.bin'
        other.write_bytes(data)
        self.assertEqual(r.ingest(0, other)['appended_bytes'], 0)
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(r.status()['next_index'], 1)
        done = r.finish()
        self.assertEqual(done['state'], 'published_verified')
        self.assertEqual(done['durability'], 'confirmed')
        self.assertEqual(Path(done['path']).read_bytes(), data)
        self.assertEqual(r.finish(), done)

    def test_full_thirty_million_bytes_with_fixed_geometry(self):
        data = b'a' * 8_000_000 + b'b' * 8_000_000 + b'c' * 8_000_000 + b'd' * 6_000_000
        r, plan, paths = self.prepare(data)
        self.assertEqual([p['bytes'] for p in plan['parts']], [8_000_000] * 3 + [6_000_000])
        for index, path in enumerate(paths):
            r.ingest(index, path)
            if index == 0:
                r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        result = r.finish()
        target = Path(result['path'])
        self.assertEqual(target.stat().st_size, 30_000_000)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), plan['total_sha256'])

    def test_empty_file_is_one_real_zero_byte_part(self):
        r, plan, paths = self.prepare(b'')
        self.assertEqual(plan['part_count'], 1)
        self.assertEqual(r.ingest(0, paths[0])['appended_bytes'], 0)
        result = r.finish()
        self.assertTrue(result['published'])
        self.assertEqual(Path(result['path']).stat().st_size, 0)

    def partial(self, r, path):
        def interrupted(source, target, offset, count):
            os.pwrite(target, os.pread(source, 5, 0), offset)
            raise InjectedCrash()
        with patch.object(receiver, '_copy', side_effect=interrupted):
            with self.assertRaises(InjectedCrash):
                r.ingest(0, path)

    def test_partial_pending_is_reverified_against_real_input(self):
        data = b'pending-tail-contents'
        r, plan, paths = self.prepare(data)
        self.partial(r, paths[0])
        self.assertEqual(r.status()['pending_part_index'], 0)
        self.assertEqual(r.status()['received_bytes'], 0)
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(r.ingest(0, paths[0])['appended_bytes'], len(data))
        self.assertEqual(Path(r.finish()['path']).read_bytes(), data)

    def uncertain_pending(self, r, path):
        session_identity = receiver._identity(Path(r.session_path).stat())
        original = receiver._sync
        failed = False
        def fail_pending_directory(fd, code='durability_pending'):
            nonlocal failed
            if receiver._identity(os.fstat(fd)) == session_identity and not failed:
                failed = True
                raise receiver.ReceiverError('durability_pending')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=fail_pending_directory):
            self.error('durability_pending', r.ingest, 0, path)
        self.assertTrue(failed)
        self.assertEqual((Path(r.session_path) / 'receive.tmp').stat().st_size, 0)
        self.assertEqual(r.status()['pending_part_index'], 0)
        return session_identity

    def test_uncertain_pending_retry_confirms_durability_before_second_interruption(self):
        data = b'pending commit durability'
        r, plan, paths = self.prepare(data)
        session_identity = self.uncertain_pending(r, paths[0])
        successful_directory_syncs = []
        original = receiver._sync
        def observe_sync(fd, code='durability_pending'):
            original(fd, code)
            if receiver._identity(os.fstat(fd)) == session_identity:
                successful_directory_syncs.append(True)
        def interrupt_after_confirmation(source, target, offset, count):
            self.assertTrue(successful_directory_syncs, 'pending intent must be durable before any retry write')
            os.pwrite(target, os.pread(source, 3, 0), offset)
            raise InjectedCrash()
        with patch.object(receiver, '_sync', side_effect=observe_sync), patch.object(receiver, '_copy', side_effect=interrupt_after_confirmation):
            with self.assertRaises(InjectedCrash):
                r.ingest(0, paths[0])
        self.assertEqual((Path(r.session_path) / 'receive.tmp').read_bytes(), data[:3])
        resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        resumed.ingest(0, paths[0])
        self.assertEqual(Path(resumed.finish()['path']).read_bytes(), data)

    def test_uncertain_pending_resume_and_subsequent_write_each_confirm_intent(self):
        r, plan, paths = self.prepare(b'pending commit durability')
        session_identity = self.uncertain_pending(r, paths[0])
        confirmed = []
        original_sync, original_copy = receiver._sync, receiver._copy
        def observe_sync(fd, code='durability_pending'):
            original_sync(fd, code)
            if receiver._identity(os.fstat(fd)) == session_identity:
                confirmed.append(True)
        def assert_then_copy(*args):
            self.assertTrue(confirmed, 'resumed ingest must reconfirm existing pending intent')
            return original_copy(*args)
        with patch.object(receiver, '_sync', side_effect=observe_sync):
            resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
            self.assertTrue(confirmed, 'resume must confirm pending control durability')
            confirmed.clear()
            with patch.object(receiver, '_copy', side_effect=assert_then_copy):
                resumed.ingest(0, paths[0])
        self.assertTrue(resumed.finish()['published'])

    def test_repeated_pending_directory_sync_uncertainty_never_writes_data(self):
        r, _, paths = self.prepare(b'pending commit durability')
        session_identity = self.uncertain_pending(r, paths[0])
        original = receiver._sync
        def refuse_directory_sync(fd, code='durability_pending'):
            if receiver._identity(os.fstat(fd)) == session_identity:
                raise receiver.ReceiverError('durability_pending')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=refuse_directory_sync), patch.object(receiver, '_copy') as copying:
            self.error('durability_pending', r.ingest, 0, paths[0])
            copying.assert_not_called()
        self.assertEqual((Path(r.session_path) / 'receive.tmp').stat().st_size, 0)
        self.assertEqual(r.status()['pending_part_index'], 0)

    def test_changed_pending_tail_is_not_silently_truncated(self):
        r, plan, paths = self.prepare(b'pending-tail-contents')
        self.partial(r, paths[0])
        temp = Path(r.session_path) / 'receive.tmp'
        with temp.open('r+b') as f:
            f.write(b'WRONG')
        self.error('pending_tail_mismatch', receiver.NativeChunkReceiver.resume, r.session_path, plan, self.inputs)
        self.assertTrue(temp.exists())

    def test_replaced_pending_input_even_same_bytes_is_refused(self):
        r, plan, paths = self.prepare(b'pending-tail-contents')
        self.partial(r, paths[0])
        saved = paths[0].read_bytes()
        replacement = self.inputs / 'replacement.bin'
        replacement.write_bytes(saved)
        os.replace(replacement, paths[0])
        self.error('input_changed', receiver.NativeChunkReceiver.resume, r.session_path, plan, self.inputs)

    def test_bad_segment_hash_does_not_advance_ledger(self):
        r, _, paths = self.prepare(b'expected')
        paths[0].write_bytes(b'incorrect')
        self.error('part_length_or_hash_mismatch', r.ingest, 0, paths[0])
        self.assertEqual(r.status()['received_bytes'], 0)
        self.assertIsNone(r.status()['pending_part_index'])

    def test_input_mutation_during_copy_leaves_pending_not_committed(self):
        r, _, paths = self.prepare(b'expected content')
        original = receiver._copy
        def mutate(source, target, offset, count):
            original(source, target, offset, count)
            paths[0].write_bytes(b'changed content!')
        with patch.object(receiver, '_copy', side_effect=mutate):
            self.error('input_changed', r.ingest, 0, paths[0])
        self.assertEqual(r.status()['received_bytes'], 0)
        self.assertEqual(r.status()['pending_part_index'], 0)

    def test_replaced_input_name_during_copy_does_not_commit(self):
        r, _, paths = self.prepare(b'expected content')
        original = receiver._copy
        def replace(source, target, offset, count):
            original(source, target, offset, count)
            other = self.inputs / 'new.bin'
            other.write_bytes(b'expected content')
            os.replace(other, paths[0])
        with patch.object(receiver, '_copy', side_effect=replace):
            self.error('input_changed', r.ingest, 0, paths[0])
        self.assertEqual(r.status()['received_bytes'], 0)

    def test_changed_committed_temporary_file_is_detected(self):
        r, plan, paths = self.prepare(b'expected')
        r.ingest(0, paths[0])
        (Path(r.session_path) / 'receive.tmp').write_bytes(b'incorrec')
        self.error('temporary_hash_mismatch', receiver.NativeChunkReceiver.resume, r.session_path, plan, self.inputs)

    def test_out_of_order_and_boolean_indices_are_refused(self):
        r, _, paths = self.prepare(b'a' * receiver.PART_BYTES + b'b')
        self.error('part_out_of_order', r.ingest, 1, paths[1])
        self.error('invalid_integer', r.ingest, False, paths[0])
        self.error('receive_incomplete', r.finish)

    def test_source_expiry_is_not_a_local_byte_expiry(self):
        r, plan, paths = self.prepare(b'already received locally')
        self.assertEqual(plan['expires_at_unix'], 1)
        r.ingest(0, paths[0])
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertTrue(r.finish()['published'])

    def test_wrong_plan_cannot_resume_existing_session(self):
        r, plan, _ = self.prepare()
        changed = copy.deepcopy(plan)
        changed['export_id'] = '4' * 32
        changed = signed(changed)
        self.error('invalid_ledger', receiver.NativeChunkReceiver.resume, r.session_path, changed, self.inputs)

    def test_target_exists_before_start_or_finish_never_overwrites(self):
        existing = self.output / 'existing.zip'
        existing.write_bytes(b'keep')
        plan = make_plan(b'data')
        self.error('target_exists', receiver.NativeChunkReceiver.start, plan, self.output, self.inputs, 'existing.zip')
        r, _, paths = self.prepare(b'new')
        r.ingest(0, paths[0])
        target = self.output / 'target.zip'
        target.write_bytes(b'keep this too')
        self.error('target_exists', r.finish)
        self.assertEqual(target.read_bytes(), b'keep this too')

    def test_hardlink_preflight_failure_precedes_segment_receipt(self):
        plan = make_plan(b'data')
        with patch.object(receiver.os, 'link', side_effect=OSError(errno.EPERM, 'synthetic')):
            self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                       plan, self.output, self.inputs, 'target.zip')
        self.assertFalse((self.output / 'target.zip').exists())
        self.assertFalse(any(self.output.rglob('receive.tmp')))

    def test_space_floor_is_rechecked_before_each_write_and_publication(self):
        r, _, paths = self.prepare(b'actual bytes')
        with patch.object(receiver.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=1)):
            self.error('insufficient_space', r.ingest, 0, paths[0])
        self.assertIsNone(r.status()['pending_part_index'])
        r.ingest(0, paths[0])
        with patch.object(receiver.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=1)):
            self.error('insufficient_space', r.finish)
        self.assertFalse((self.output / 'target.zip').exists())
        self.assertEqual(r.status()['state'], 'receiving')

    def test_crash_after_link_can_complete_same_inode_publication(self):
        r, plan, paths = self.prepare(b'complete file')
        r.ingest(0, paths[0])
        with patch.object(r, '_recover_publication', side_effect=InjectedCrash):
            with self.assertRaises(InjectedCrash):
                r.finish()
        target = self.output / 'target.zip'
        self.assertTrue(target.exists())
        self.assertEqual(target.stat().st_ino, (Path(r.session_path) / 'receive.tmp').stat().st_ino)
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(r.status()['state'], 'published_verified')

    def test_crash_before_link_is_unresolved_not_recreated(self):
        r, plan, paths = self.prepare(b'complete file')
        r.ingest(0, paths[0])
        with patch.object(receiver.os, 'link', side_effect=InjectedCrash):
            with self.assertRaises(InjectedCrash):
                r.finish()
        self.error('publication_pending', receiver.NativeChunkReceiver.resume, r.session_path, plan, self.inputs)
        self.error('publication_pending', r.cleanup)
        self.assertFalse((self.output / 'target.zip').exists())
        self.assertTrue((Path(r.session_path) / 'receive.tmp').exists())

    def test_directory_fsync_failure_after_link_does_not_claim_durable(self):
        r, plan, paths = self.prepare(b'complete file')
        r.ingest(0, paths[0])
        root_identity = (self.output.stat().st_dev, self.output.stat().st_ino)
        original = receiver._sync
        def fail_root(fd, code='durability_pending'):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == root_identity:
                raise receiver.ReceiverError('publication_pending')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=fail_root):
            self.error('publication_pending', r.finish)
        self.assertEqual(r.status()['durability'], 'not_confirmed')
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(r.status()['durability'], 'confirmed')

    def test_whole_hash_must_match_even_when_every_part_matches(self):
        r, plan, paths = self.prepare(b'bytes')
        # A separately issued plan with internally valid part hash but incorrect
        # whole hash must not publish; it gets its own independent receiver.
        r.cancel()
        bad = copy.deepcopy(plan)
        bad['total_sha256'] = 'f' * 64
        bad = signed(bad)
        other = receiver.NativeChunkReceiver.start(bad, self.output, self.inputs, 'different.zip')
        other.ingest(0, paths[0])
        self.error('whole_hash_mismatch', other.finish)
        self.assertFalse((self.output / 'different.zip').exists())

    def test_cancel_is_local_terminal_and_cleanup_preserves_inputs(self):
        r, plan, paths = self.prepare(b'input retained')
        r.cancel()
        self.error('receiver_not_receiving', r.ingest, 0, paths[0])
        self.error('receiver_not_receiving', r.finish)
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(r.cleanup()['state'], 'cancelled')
        self.assertTrue(paths[0].exists())
        self.assertFalse((Path(r.session_path) / 'receive.tmp').exists())
        self.assertEqual(r.cleanup()['state'], 'cancelled')

    def test_cancelled_pending_cleanup_can_resume_terminal_history(self):
        r, plan, paths = self.prepare(b'cancelled pending bytes')
        self.partial(r, paths[0])
        r.cancel()
        result = r.cleanup()
        self.assertEqual(result['state'], 'cancelled')
        self.assertTrue(result['temporary_removed'])
        self.assertTrue(paths[0].exists())
        resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(resumed.status()['pending_part_index'], 0)
        self.assertTrue(resumed.status()['temporary_removed'])
        self.error('receiver_not_receiving', resumed.ingest, 0, paths[0])
        self.error('receiver_not_receiving', resumed.finish)

    def test_cancelled_pending_can_resume_without_old_input_before_cleanup(self):
        r, plan, paths = self.prepare(b'cancelled pending bytes')
        self.partial(r, paths[0])
        r.cancel()
        paths[0].unlink()
        resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(resumed.status()['state'], 'cancelled')
        self.assertEqual(resumed.status()['pending_part_index'], 0)
        self.assertFalse(resumed.status()['temporary_removed'])
        self.error('receiver_not_receiving', resumed.ingest, 0, paths[0])
        self.error('receiver_not_receiving', resumed.finish)
        self.assertTrue(resumed.cleanup()['temporary_removed'])

    def test_cancelled_pending_interrupted_cleanup_resumes_without_input(self):
        r, plan, paths = self.prepare(b'cancelled pending bytes')
        self.partial(r, paths[0])
        r.cancel()
        original = receiver._sync
        session_identity = receiver._identity(Path(r.session_path).stat())
        def fail_removed_directory(fd, code='durability_pending'):
            if (receiver._identity(os.fstat(fd)) == session_identity
                    and not (Path(r.session_path) / 'receive.tmp').exists()):
                raise receiver.ReceiverError('durability_pending')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=fail_removed_directory):
            self.error('durability_pending', r.cleanup)
        paths[0].unlink()
        resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertEqual(resumed.status()['state'], 'cancelled')
        self.assertTrue(resumed.status()['temporary_removed'])
        self.assertEqual(resumed.status()['pending_part_index'], 0)
        self.error('receiver_not_receiving', resumed.ingest, 0, paths[0])
        self.error('receiver_not_receiving', resumed.finish)
        self.assertFalse(paths[0].exists())
        self.assertFalse((Path(r.session_path) / 'receive.tmp').exists())
        self.assertEqual(resumed.cleanup()['state'], 'cancelled')

    def test_cleanup_published_keeps_final_and_unknown_files(self):
        r, plan, paths = self.prepare(b'published bytes')
        r.ingest(0, paths[0])
        target = Path(r.finish()['path'])
        unknown = Path(r.session_path) / 'unrelated.txt'
        unknown.write_bytes(b'keep')
        self.assertTrue(r.cleanup()['temporary_removed'])
        self.assertEqual(target.read_bytes(), b'published bytes')
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertTrue(unknown.exists())
        self.assertTrue(paths[0].exists())
        resumed = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertTrue(resumed.status()['published'])

    def test_cleanup_interruption_after_unlink_is_idempotently_recovered(self):
        r, plan, paths = self.prepare(b'published bytes')
        r.ingest(0, paths[0])
        target = Path(r.finish()['path'])
        original = receiver._sync
        def fail_after_unlink(fd, code='durability_pending'):
            if not (Path(r.session_path) / 'receive.tmp').exists():
                raise receiver.ReceiverError('durability_pending')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=fail_after_unlink):
            self.error('durability_pending', r.cleanup)
        r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
        self.assertTrue(r.status()['temporary_removed'])
        self.assertEqual(target.read_bytes(), b'published bytes')

    def test_input_symlink_hardlink_and_outside_root_are_refused(self):
        r, _, paths = self.prepare(b'actual')
        link = self.inputs / 'symlink.bin'
        link.symlink_to(paths[0])
        self.error('file_unavailable', r.ingest, 0, link)
        hard = self.inputs / 'hard.bin'
        os.link(paths[0], hard)
        self.error('unsafe_file', r.ingest, 0, hard)
        outside = self.root / 'outside.bin'
        outside.write_bytes(b'actual')
        self.error('input_outside_root', r.ingest, 0, outside)

    def test_session_symlink_and_missing_ledger_are_not_adopted(self):
        r, plan, _ = self.prepare()
        session = Path(r.session_path)
        moved = self.output / 'moved-session'
        session.rename(moved)
        session.symlink_to(moved, target_is_directory=True)
        self.error('unsafe_directory', receiver.NativeChunkReceiver.resume, session, plan, self.inputs)
        session.unlink()
        moved.rename(session)
        (session / 'ledger.json').unlink()
        self.error('file_unavailable', receiver.NativeChunkReceiver.resume, session, plan, self.inputs)

    def test_receiver_lock_is_single_writer(self):
        r, _, _ = self.prepare()
        with (Path(r.session_path) / 'lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.error('receiver_busy', r.status)

    def test_helper_asset_mismatch_is_rejected_before_session_creation(self):
        plan = make_plan(b'data')
        plan['receiver_asset']['sha256'] = '0' * 64
        plan = signed(plan)
        self.error('receiver_asset_mismatch', receiver.NativeChunkReceiver.start, plan, self.output, self.inputs)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_verified_helper_bytes_run_standalone_under_actual_host_filename(self):
        payload = asset.load_receiver_asset()
        metadata = asset.receiver_metadata()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), metadata['sha256'])
        helper_path = self.inputs / 'host-renamed-receiver.py'
        helper_path.write_bytes(payload)
        spec = importlib.util.spec_from_file_location('isolated_native_receiver', helper_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plan = make_plan(b'portable source')
        actual = self.inputs / 'host-original.bin'
        actual.write_bytes(b'portable source')
        r = module.NativeChunkReceiver.start(plan, self.output, self.inputs, 'portable.zip')
        r.ingest(0, actual)
        self.assertEqual(Path(r.finish()['path']).read_bytes(), b'portable source')

    def test_plan_strict_keys_types_geometry_and_hash(self):
        original = make_plan(b'data')
        changes = [({'total_bytes': True}, 'invalid_integer'),
                   ({'part_max_bytes': 8_000_001}, 'invalid_part_size'),
                   ({'part_count': 2}, 'invalid_part_count'),
                   ({'unexpected': 1}, 'invalid_plan'),
                   ({'protocol_version': 'different'}, 'unsupported_protocol'),
                   ({'plan_sha256': '0' * 64}, 'plan_hash_mismatch')]
        for fields, code in changes:
            with self.subTest(fields=fields):
                plan = copy.deepcopy(original)
                plan.update(fields)
                if 'plan_sha256' not in fields:
                    plan = signed(plan)
                self.error(code, receiver.normalize_plan, plan)
        bad = copy.deepcopy(original)
        bad['parts'][0]['offset'] = 1
        self.error('invalid_part_geometry', receiver.normalize_plan, signed(bad))

    def test_plan_json_duplicate_keys_and_unknown_ledger_fields_are_refused(self):
        plan = make_plan(b'data')
        raw = receiver.canonical(plan)
        self.assertEqual(receiver.parse_plan(raw), plan)
        duplicate = raw.replace(b'"total_bytes":4', b'"total_bytes":4,"total_bytes":4')
        self.error('duplicate_json_key', receiver.parse_plan, duplicate)
        r, plan, _ = self.prepare(b'data')
        ledger = Path(r.session_path) / 'ledger.json'
        value = json.loads(ledger.read_bytes())
        value['unknown'] = True
        ledger.write_bytes(receiver.canonical(value))
        self.error('invalid_ledger', receiver.NativeChunkReceiver.resume, r.session_path, plan, self.inputs)

    def test_excessive_json_nesting_has_safe_bounded_failure(self):
        raw = b'[' * 2000 + b'0' + b']' * 2000
        with self.assertRaises(receiver.ReceiverError) as error:
            receiver.parse_plan(raw)
        self.assertIn(error.exception.code, {'invalid_json', 'invalid_plan'})

    def test_legacy_compatible_long_source_path_and_name_metadata(self):
        plan = make_plan(b'actual')
        plan['source']['path'] = '/'.join(['x' * 100] * 30 + ['n' * 251 + '.psd'])
        plan = signed(plan)
        self.assertEqual(receiver.normalize_plan(plan)['source']['path'], plan['source']['path'])
        actual = self.inputs / 'real-host-file.bin'
        actual.write_bytes(b'actual')
        r = receiver.NativeChunkReceiver.start(plan, self.output, self.inputs, 'short-target.psd')
        r.ingest(0, actual)
        self.assertEqual(Path(r.finish()['path']).read_bytes(), b'actual')

    def test_future_capacities_use_same_plan_algorithm_without_receiving_them(self):
        for size, count in ((30_000_000, 4), (50_000_000, 7), (70_000_000, 9), (100_000_000, 13)):
            with self.subTest(size=size):
                plan = make_plan(b'data')
                plan['total_bytes'] = size
                plan['part_count'] = count
                plan['parts'] = [{'index': i, 'offset': i * receiver.PART_BYTES,
                                  'bytes': min(receiver.PART_BYTES, size - i * receiver.PART_BYTES),
                                  'sha256': 'a' * 64, 'resource_name': 'part-' + str(i)} for i in range(count)]
                self.assertEqual(receiver.normalize_plan(signed(plan))['part_count'], count)


class AssetTests(unittest.TestCase):
    def test_fixed_asset_real_bytes_match_metadata(self):
        data = asset.load_receiver_asset()
        meta = asset.receiver_metadata()
        self.assertEqual(set(meta), {'asset_id', 'name', 'bytes', 'sha256'})
        self.assertEqual(len(data), meta['bytes'])
        self.assertEqual(hashlib.sha256(data).hexdigest(), meta['sha256'])

    def test_tampered_and_linked_asset_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='receiver-asset-test-') as temporary:
            root = Path(temporary).resolve()
            path = root / asset.RECEIVER_NAME
            path.write_bytes(b'tampered')
            with patch.object(asset, '_ASSET_PATH', path):
                with self.assertRaises(AccessError) as error:
                    asset.load_receiver_asset()
                self.assertEqual(error.exception.code, 'receiver_asset_invalid')
            path.unlink()
            path.symlink_to(Path(receiver.__file__).absolute())
            with patch.object(asset, '_ASSET_PATH', path):
                with self.assertRaises(AccessError) as error:
                    asset.load_receiver_asset()
                self.assertEqual(error.exception.code, 'receiver_asset_invalid')

    def test_asset_close_uncertainty_propagates_without_retrying_fd(self):
        seen = []
        def uncertain(fd):
            seen.append(fd)
            os.close(fd)
            if len(seen) == 1:
                raise AccessError('synthetic', code='protection_cleanup_pending')
        with patch.object(asset, '_close', side_effect=uncertain):
            with self.assertRaises(AccessError) as error:
                asset.load_receiver_asset()
        self.assertEqual(error.exception.code, 'protection_cleanup_pending')
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(set(seen)), 2)


if __name__ == '__main__':
    unittest.main()
