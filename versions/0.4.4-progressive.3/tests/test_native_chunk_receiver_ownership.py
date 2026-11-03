"""Host-input and durable-admission boundaries; all filesystem data is synthetic."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp import native_chunk_receiver as receiver
from peters_mcp import transport_asset as asset
import test_native_chunk_receiver as legacy


class _Metadata:
    def __init__(self, original, fields):
        self.original, self.fields = original, fields

    def __getattr__(self, name):
        return self.fields.get(name, getattr(self.original, name))


@contextmanager
def metadata_overrides(overrides):
    """Map only specified real inodes; never mock the opener or data reads."""
    real_fstat, real_stat = os.fstat, os.stat
    def mapped(info):
        fields = overrides.get((info.st_dev, info.st_ino))
        return info if fields is None else _Metadata(info, fields)
    with patch.object(receiver.os, 'fstat', side_effect=lambda fd: mapped(real_fstat(fd))), \
            patch.object(receiver.os, 'stat', side_effect=lambda *a, **k: mapped(real_stat(*a, **k))):
        yield


class ReceivedOwnershipTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='receiver-owned-boundary-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.inputs, self.output = self.root / 'inputs', self.root / 'output'
        self.inputs.mkdir()
        self.output.mkdir(mode=0o700)

    def prepare(self, data=b'synthetic exact bytes'):
        plan = legacy.make_plan(data)
        path = self.inputs / 'actual-native.bin'
        path.write_bytes(data)
        r = receiver.NativeChunkReceiver.start(plan, self.output, self.inputs, 'final.zip')
        return r, plan, path

    def error(self, code, function, *args):
        with self.assertRaises(receiver.ReceiverError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def load_bound(self, data=b'synthetic exact bytes'):
        helper = self.inputs / 'actual-native-helper.py'
        helper.write_bytes(Path(receiver.__file__).read_bytes())
        part = self.inputs / 'actual-native.bin'
        part.write_bytes(data)
        plan = legacy.make_plan(data)
        template = Path(__file__).resolve().parents[1] / 'tools/native_receiver_loader.py'
        namespace = {'__name__': 'trusted_root_handoff_loader_test'}
        exec(compile(template.read_bytes(), str(template), 'exec'), namespace)
        expected = receiver._identity(self.inputs.stat())
        module, evidence = namespace['load_verified_receiver'](
            helper, self.inputs, expected, asset.receiver_metadata(), plan['receiver_asset'])
        self.assertIs(evidence['native_receiver_root_bound'], True)
        return module, plan, part, expected

    def ledger(self, r):
        return json.loads((Path(r.session_path) / 'ledger.json').read_bytes())

    def inode(self, path):
        info = path.stat()
        return (info.st_dev, info.st_ino)

    def test_host_root_helper_and_part_can_duplicate_resume_publish(self):
        helper = Path(receiver.__file__)
        overrides = {self.inode(helper): {'st_uid': 0}}
        with metadata_overrides(overrides):
            r, plan, path = self.prepare()
            overrides[self.inode(path)] = {'st_uid': 0}
            self.assertEqual(r.ingest(0, path)['appended_bytes'], plan['total_bytes'])
            self.assertEqual(r.ingest(0, path)['appended_bytes'], 0)
            r = receiver.NativeChunkReceiver.resume(r.session_path, plan, self.inputs)
            result = r.finish()
        self.assertEqual(result['state'], 'published_verified')
        self.assertEqual(Path(result['path']).read_bytes(), b'synthetic exact bytes')
        self.assertEqual(len(self.ledger(r)['accepted'][0]['input_version']), 6)

    def test_unknown_owner_is_rejected_before_pending(self):
        r, _, path = self.prepare()
        overrides = {self.inode(path): {'st_uid': os.getuid() + 12345}}
        with metadata_overrides(overrides):
            self.error('unsafe_file', r.ingest, 0, path)
        self.assertEqual(self.ledger(r)['next_index'], 0)
        self.assertIsNone(self.ledger(r)['pending'])

    def test_received_writable_or_special_mode_is_rejected(self):
        for mode in (0o664, 0o666, 0o4644, 0o2644, 0o1644):
            with self.subTest(mode=oct(mode)):
                r, _, path = self.prepare()
                path.chmod(mode)
                self.error('unsafe_file', r.ingest, 0, path)
                self.assertEqual(self.ledger(r)['next_index'], 0)
                self.assertIsNone(self.ledger(r)['pending'])

    def test_readonly_policy_is_not_a_single_0644_mode_whitelist(self):
        for index, mode in enumerate((0o600, 0o644, 0o444)):
            with self.subTest(mode=oct(mode)):
                data = bytes([index]) * 11
                plan = legacy.make_plan(data)
                path = self.inputs / ('actual-' + str(index))
                path.write_bytes(data)
                path.chmod(mode)
                r = receiver.NativeChunkReceiver.start(plan, self.output, self.inputs, 'final-' + str(index))
                self.assertEqual(r.ingest(0, path)['appended_bytes'], 11)
                self.assertTrue(r.finish()['published'])

    def test_fifo_and_directory_are_refused_without_blocking(self):
        r, _, _ = self.prepare()
        fifo = self.inputs / 'actual.fifo'
        os.mkfifo(fifo)
        self.error('unsafe_file', r.ingest, 0, fifo)
        directory = self.inputs / 'actual-directory'
        directory.mkdir()
        self.error('unsafe_file', r.ingest, 0, directory)
        self.assertEqual(self.ledger(r)['next_index'], 0)

    def test_nested_actual_name_is_traversed_from_bound_root(self):
        r, _, path = self.prepare()
        nested = self.inputs / 'host' / 'renamed'
        nested.mkdir(parents=True)
        actual = nested / 'received-under-another-name.bin'
        path.rename(actual)
        self.assertGreater(r.ingest(0, actual)['appended_bytes'], 0)
        self.assertTrue(r.finish()['published'])

    def test_nested_symlink_cannot_escape_or_alias_an_input_directory(self):
        r, _, path = self.prepare()
        (self.inputs / 'alias').symlink_to(self.inputs, target_is_directory=True)
        self.error('unsafe_directory', r.ingest, 0, self.inputs / 'alias' / path.name)
        self.assertIsNone(self.ledger(r)['pending'])

    def test_named_input_root_replacement_cannot_select_new_root_before_pending(self):
        r, _, path = self.prepare()
        old_input = self.root / 'old-input'
        original = r._input
        @contextmanager
        def replaced(actual, part, inputs):
            self.inputs.rename(old_input)
            self.inputs.mkdir()
            (self.inputs / path.name).write_bytes(b'synthetic exact bytes')
            with original(actual, part, inputs) as lease:
                yield lease
        with patch.object(r, '_input', replaced):
            self.error('directory_changed', r.ingest, 0, path)
        self.assertEqual(self.ledger(r)['accepted'], [])
        self.assertIsNone(self.ledger(r)['pending'])

    def test_nested_parent_replacement_after_copy_leaves_pending(self):
        r, _, path = self.prepare()
        parent = self.inputs / 'host'
        parent.mkdir()
        actual = parent / path.name
        path.rename(actual)
        original = receiver._copy
        def changed(*args):
            original(*args)
            parent.rename(self.inputs / 'moved-host')
            parent.mkdir()
            actual.write_bytes(b'synthetic exact bytes')
        with patch.object(receiver, '_copy', side_effect=changed):
            self.error('input_changed', r.ingest, 0, actual)
        ledger = self.ledger(r)
        self.assertEqual(ledger['accepted'], [])
        self.assertEqual(ledger['durable_offset'], 0)
        self.assertEqual(ledger['pending']['index'], 0)
        self.assertEqual((Path(r.session_path) / 'receive.tmp').read_bytes(), b'synthetic exact bytes')

    def test_uid_gid_mode_change_without_version_change_is_not_accepted(self):
        for field, value in (('st_uid', 0), ('st_gid', os.getgid() + 1), ('st_mode', stat.S_IFREG | 0o600)):
            with self.subTest(field=field):
                r, _, path = self.prepare()
                fields = {}
                overrides = {self.inode(path): fields}
                original = receiver._copy
                def changed(*args):
                    original(*args)
                    fields[field] = value
                with metadata_overrides(overrides), patch.object(receiver, '_copy', side_effect=changed):
                    self.error('input_changed', r.ingest, 0, path)
                ledger = self.ledger(r)
                self.assertEqual(ledger['accepted'], [])
                self.assertEqual(ledger['durable_offset'], 0)
                self.assertEqual(ledger['pending']['index'], 0)

    def test_root_private_files_remain_refused(self):
        for filename in ('ledger.json', 'lock', 'receive.tmp'):
            with self.subTest(filename=filename):
                r, _, _ = self.prepare()
                overrides = {self.inode(Path(r.session_path) / filename): {'st_uid': 0}}
                with metadata_overrides(overrides):
                    self.error('unsafe_file', r.status)

    def test_root_or_open_mode_output_and_session_remain_refused(self):
        for which, code in (('output', 'unsafe_output_root'), ('session', 'unsafe_session')):
            with self.subTest(which=which):
                r, _, _ = self.prepare()
                p = self.output if which == 'output' else Path(r.session_path)
                with metadata_overrides({self.inode(p): {'st_uid': 0}}):
                    self.error(code, r.status)
                p.chmod(0o755)
                self.error(code, r.status)
                p.chmod(0o700)

    def test_root_published_final_is_not_accepted_as_owned_state(self):
        r, _, path = self.prepare()
        r.ingest(0, path)
        final = Path(r.finish()['path'])
        with metadata_overrides({self.inode(final): {'st_uid': 0}}):
            self.error('unsafe_file', r.status)

    def test_input_close_uncertainty_preserves_pending_and_does_not_reclose_foreign_fd(self):
        r, _, path = self.prepare()
        actual_identity = self.inode(path)
        original = receiver._close
        foreign = []
        failed = []
        def uncertain(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == actual_identity and not failed:
                failed.append(fd)
                os.close(fd)
                foreign.append(os.open(os.devnull, os.O_RDONLY))
                raise receiver.ReceiverError('descriptor_close_uncertain')
            return original(fd)
        try:
            with patch.object(receiver, '_close', side_effect=uncertain):
                self.error('descriptor_close_uncertain', r.ingest, 0, path)
            self.assertEqual(len(failed), 1)
            self.assertEqual(foreign[0], failed[0])
            os.fstat(foreign[0])
        finally:
            for fd in foreign:
                os.close(fd)
        ledger = self.ledger(r)
        self.assertEqual(ledger['accepted'], [])
        self.assertEqual(ledger['pending']['index'], 0)
        self.assertEqual((Path(r.session_path) / 'receive.tmp').read_bytes(), b'synthetic exact bytes')

    def test_input_parent_close_failure_precedes_accepted_commit(self):
        r, _, path = self.prepare()
        parent = self.inputs / 'host'
        parent.mkdir()
        actual = parent / path.name
        path.rename(actual)
        actual_identity = self.inode(parent)
        original = receiver._close
        failed = []
        def uncertain(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == actual_identity and not failed:
                failed.append(fd)
                os.close(fd)
                raise receiver.ReceiverError('descriptor_close_uncertain')
            return original(fd)
        with patch.object(receiver, '_close', side_effect=uncertain):
            self.error('descriptor_close_uncertain', r.ingest, 0, actual)
        self.assertEqual(self.ledger(r)['accepted'], [])
        self.assertEqual(self.ledger(r)['pending']['index'], 0)

    def test_output_policy_change_after_input_close_stops_before_acceptance(self):
        r, _, path = self.prepare()
        original = receiver._ReceivedLease.close
        def changed(lease):
            original(lease)
            if lease.path == path:
                self.output.chmod(0o755)
        with patch.object(receiver._ReceivedLease, 'close', changed):
            self.error('unsafe_output_root', r.ingest, 0, path)
        self.assertEqual(self.ledger(r)['accepted'], [])
        self.assertEqual(self.ledger(r)['pending']['index'], 0)

    def test_actual_accepted_commit_is_preserved_when_its_acknowledgment_fails(self):
        r, _, path = self.prepare()
        original = receiver._save_control
        def uncertain(session, ledger):
            original(session, ledger)
            if ledger['next_index'] == 1:
                raise receiver.ReceiverError('durability_pending')
        with patch.object(receiver, '_save_control', side_effect=uncertain):
            self.error('durability_pending', r.ingest, 0, path)
        ledger = self.ledger(r)
        self.assertEqual(ledger['next_index'], 1)
        self.assertEqual(ledger['durable_offset'], len(b'synthetic exact bytes'))
        self.assertIsNone(ledger['pending'])
        self.assertEqual(ledger['state'], 'receiving')
        self.assertFalse((self.output / 'final.zip').exists())

    def test_cross_directory_link_preflight_is_required_before_receive_files(self):
        plan = legacy.make_plan(b'data')
        original = receiver.os.link
        crossed = []
        def refuse_cross(*args, **kwargs):
            if kwargs['src_dir_fd'] != kwargs['dst_dir_fd']:
                crossed.append(True)
                raise OSError(errno.EPERM, 'synthetic cross-directory link refusal')
            return original(*args, **kwargs)
        with patch.object(receiver.os, 'link', side_effect=refuse_cross):
            self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                       plan, self.output, self.inputs, 'final.zip')
        self.assertEqual(crossed, [True])
        self.assertFalse(any(self.output.rglob('receive.tmp')))
        self.assertFalse(any(p.name.startswith('.preflight-') for p in self.output.rglob('*')))

    def test_output_directory_fsync_preflight_failure_is_not_late_publication_failure(self):
        plan = legacy.make_plan(b'data')
        identity = self.inode(self.output)
        original = receiver._sync
        def unavailable(fd, code='durability_pending'):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == identity:
                raise receiver.ReceiverError('publication_primitive_unavailable')
            return original(fd, code)
        with patch.object(receiver, '_sync', side_effect=unavailable):
            self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                       plan, self.output, self.inputs, 'final.zip')
        self.assertFalse(any(self.output.rglob('ledger.json')))
        self.assertFalse(any(self.output.rglob('receive.tmp')))

    def test_main_preflight_sync_failures_retain_exact_owned_probe_inventory(self):
        for fail_at in (1, 2, 3, 4):
            with self.subTest(fail_at=fail_at):
                original = receiver._sync
                calls = []
                def unavailable(fd, code='durability_pending'):
                    calls.append(fd)
                    if len(calls) == fail_at:
                        raise receiver.ReceiverError('publication_primitive_unavailable')
                    return original(fd, code)
                with patch.object(receiver, '_sync', side_effect=unavailable):
                    error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                                       legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
                evidence = error.preflight
                self.assertTrue(evidence['main_durability_uncertain'])
                self.assertFalse(evidence['cleanup_started'])
                self.assertFalse(evidence['cleanup_durable'])
                created = [p for p in evidence['probes'] if p['created_confirmed']]
                self.assertEqual(len(created), 1 if fail_at == 1 else 3)
                for p in created:
                    actual = Path(p['path'])
                    self.assertTrue(actual.exists())
                    self.assertEqual(receiver._identity(actual.stat()), p['identity'])
                    self.assertEqual(p['observation'], 'retained')
                    self.assertFalse(p['cleanup_removed'])
                self.assertFalse(any(self.output.rglob('ledger.json')))

    def test_preflight_uncertain_probe_close_never_unlinks_the_probes(self):
        original = receiver._close
        seen = []
        def uncertain(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size == 9 and not seen:
                seen.append(fd)
                os.close(fd)
                raise receiver.ReceiverError('descriptor_close_uncertain')
            return original(fd)
        with patch.object(receiver, '_close', side_effect=uncertain):
            error = self.error('descriptor_close_uncertain', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertTrue(error.preflight['close_uncertain'])
        self.assertFalse(error.preflight['cleanup_started'])
        created = [p for p in error.preflight['probes'] if p['created_confirmed']]
        self.assertEqual(len(created), 3)
        self.assertTrue(all(Path(p['path']).exists() and p['observation'] == 'retained' for p in created))

    def test_preflight_changed_probe_identity_preserves_foreign_sentinel_and_owned_probes(self):
        original = receiver.os.link
        foreign = []
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs['src_dir_fd'] != kwargs['dst_dir_fd']:
                path = self.output / args[1]
                path.unlink()
                path.write_bytes(b'foreign sentinel')
                foreign.append(path)
            return result
        with patch.object(receiver.os, 'link', side_effect=changed):
            error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertEqual(foreign[0].read_bytes(), b'foreign sentinel')
        self.assertTrue(error.preflight['identity_uncertain'])
        self.assertFalse(error.preflight['cleanup_started'])
        probes = error.preflight['probes']
        self.assertEqual([p['observation'] for p in probes], ['retained', 'retained', 'changed'])
        self.assertTrue(all(Path(p['path']).exists() for p in probes))

    def test_cleanup_sync_failure_records_removed_probes_without_recreating_them(self):
        for fail_at in (5, 6):
            with self.subTest(fail_at=fail_at):
                original = receiver._sync
                calls = []
                def unavailable(fd, code='durability_pending'):
                    calls.append(fd)
                    if len(calls) == fail_at:
                        raise receiver.ReceiverError('publication_primitive_unavailable')
                    return original(fd, code)
                with patch.object(receiver, '_sync', side_effect=unavailable):
                    error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                                       legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
                evidence = error.preflight
                self.assertTrue(evidence['main_checks_completed'])
                self.assertFalse(evidence['main_durability_uncertain'])
                self.assertTrue(evidence['cleanup_started'])
                self.assertTrue(evidence['cleanup_durability_uncertain'])
                self.assertFalse(evidence['cleanup_durable'])
                for p in evidence['probes']:
                    self.assertTrue(p['cleanup_removed'])
                    self.assertEqual(p['observation'], 'removed')
                    self.assertFalse(Path(p['path']).exists())
                self.assertEqual(len(calls), fail_at)

    def test_cleanup_unlink_error_preserves_partial_removed_and_retained_facts(self):
        original = receiver.os.unlink
        calls = []
        def unavailable(name, **kwargs):
            if str(name).startswith('.preflight-'):
                calls.append(name)
                if len(calls) == 2:
                    raise OSError(errno.EIO, 'synthetic cleanup unlink error')
            return original(name, **kwargs)
        with patch.object(receiver.os, 'unlink', side_effect=unavailable):
            error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        probes = error.preflight['probes']
        self.assertEqual([p['cleanup_removed'] for p in probes], [False, False, True])
        self.assertEqual([p['observation'] for p in probes], ['retained', 'retained', 'removed'])
        self.assertEqual([Path(p['path']).exists() for p in probes], [True, True, False])
        self.assertTrue(error.preflight['operation_uncertain'])
        self.assertFalse(error.preflight['cleanup_durable'])

    def test_loader_root_handoff_cannot_adopt_a_replacement_root(self):
        module, plan, part, _ = self.load_bound()
        payload = (self.inputs / 'actual-native-helper.py').read_bytes()
        self.inputs.rename(self.root / 'original-native-root')
        self.inputs.mkdir()
        (self.inputs / 'actual-native-helper.py').write_bytes(payload)
        part.write_bytes(b'synthetic exact bytes')
        with self.assertRaises(module.ReceiverError) as caught:
            module.NativeChunkReceiver.start(plan, self.output, self.inputs, 'final.zip')
        self.assertEqual(caught.exception.code, 'native_input_root_mismatch')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_bound_receiver_normal_start_duplicate_resume_and_finish(self):
        module, plan, part, _ = self.load_bound()
        r = module.NativeChunkReceiver.start(plan, self.output, target_name='final.zip')
        self.assertEqual(r.ingest(0, part)['appended_bytes'], plan['total_bytes'])
        self.assertEqual(r.ingest(0, part)['appended_bytes'], 0)
        r = module.NativeChunkReceiver.resume(r.session_path, plan)
        self.assertTrue(r.finish()['published'])
        self.assertEqual((self.output / 'final.zip').read_bytes(), b'synthetic exact bytes')

    def test_binding_detaches_identity_list_and_refuses_rebinding(self):
        module, plan, part, expected = self.load_bound()
        immutable = (str(self.inputs), tuple(expected))
        bound = module.NativeChunkReceiver
        expected[0] += 1
        self.assertEqual(bound._native_input_binding(), immutable)
        self.assertIs(module._for_native_input_root(str(self.inputs), immutable[1]), bound)
        with self.assertRaises(module.ReceiverError) as caught:
            module._for_native_input_root(str(self.inputs), expected)
        self.assertEqual(caught.exception.code, 'native_input_root_rebind')
        r = bound.start(plan, self.output, self.inputs, 'final.zip')
        r.ingest(0, part)
        self.assertTrue(r.finish()['published'])

    def test_bound_resume_and_locked_operations_reject_replacement_root_without_writing(self):
        module, plan, part, _ = self.load_bound()
        r = module.NativeChunkReceiver.start(plan, self.output, self.inputs, 'final.zip')
        control = Path(r.session_path) / 'ledger.json'
        before = control.read_bytes()
        payload = (self.inputs / 'actual-native-helper.py').read_bytes()
        self.inputs.rename(self.root / 'original-native-root')
        self.inputs.mkdir()
        (self.inputs / 'actual-native-helper.py').write_bytes(payload)
        part.write_bytes(b'synthetic exact bytes')
        for function in (lambda: module.NativeChunkReceiver.resume(r.session_path, plan, self.inputs),
                         r.status, lambda: r.ingest(0, part), r.finish):
            with self.assertRaises(module.ReceiverError) as caught:
                function()
            self.assertEqual(caught.exception.code, 'native_input_root_mismatch')
            self.assertEqual(control.read_bytes(), before)
        self.assertFalse((self.output / 'final.zip').exists())

    def test_bound_start_rechecks_route_after_self_asset_before_first_output_write(self):
        module, plan, part, _ = self.load_bound()
        payload = (self.inputs / 'actual-native-helper.py').read_bytes()
        original = module._verify_asset_at
        def changed(*args):
            original(*args)
            self.inputs.rename(self.root / 'original-native-root')
            self.inputs.mkdir()
            (self.inputs / 'actual-native-helper.py').write_bytes(payload)
            part.write_bytes(b'synthetic exact bytes')
        with patch.object(module, '_verify_asset_at', side_effect=changed):
            with self.assertRaises(module.ReceiverError) as caught:
                module.NativeChunkReceiver.start(plan, self.output, self.inputs, 'final.zip')
        self.assertEqual(caught.exception.code, 'directory_changed')
        self.assertEqual(list(self.output.iterdir()), [])

    def route_failure_during_main_sync(self, kind, io_error):
        original = receiver._sync
        root_identity = self.inode(self.output)
        session_name = receiver.PREFIX + 'a' * 32
        detached = self.root / ('detached-' + kind)
        fired = []
        def changed(fd, code='durability_pending'):
            if receiver._identity(os.fstat(fd)) == list(root_identity) and not fired:
                fired.append(True)
                if kind == 'output':
                    self.output.rename(detached)
                    self.output.mkdir(mode=0o700)
                else:
                    (self.output / session_name).rename(detached)
                    (self.output / session_name).mkdir(mode=0o700)
                if io_error:
                    raise OSError(errno.EIO, 'synthetic main sync plus route failure')
            return original(fd, code)
        with patch.object(receiver.secrets, 'token_hex', return_value='a' * 32), \
                patch.object(receiver, '_sync', side_effect=changed):
            error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertEqual(fired, [True])
        report = error.preflight
        self.assertTrue(report['identity_uncertain'])
        self.assertFalse(report['cleanup_started'])
        self.assertEqual(report['main_durability_uncertain'], io_error)
        self.assertEqual(report['directory_routes']['output_root']['state'],
                         'changed' if kind == 'output' else 'verified')
        self.assertEqual(report['directory_routes']['session']['state'],
                         'missing' if kind == 'output' else 'changed')
        for probe in report['probes']:
            self.assertTrue(probe['created_confirmed'])
            self.assertFalse(probe['cleanup_removed'])
            self.assertEqual(probe['held_parent_entry']['observation'], 'retained')
            self.assertEqual(probe['held_parent_entry']['observed_identity'], probe['identity'])
            self.assertEqual(probe['held_parent_identity'],
                             report['directory_bindings'][probe['location']]['held_parent_identity'])
            if not probe['absolute_path_route_verified']:
                self.assertNotEqual(probe['observation'], 'retained')
        old_session = detached / session_name if kind == 'output' else detached
        for name in ('lock', 'receive.tmp', 'ledger.json'):
            self.assertFalse((old_session / name).exists())
        if kind == 'output':
            self.assertEqual(list(self.output.iterdir()), [])
            self.assertTrue(all(not Path(probe['path']).exists() for probe in report['probes']))
        else:
            self.assertEqual(list((self.output / session_name).iterdir()), [])
        return report

    def test_main_output_route_replacement_plus_eio_does_not_claim_absolute_retained(self):
        self.route_failure_during_main_sync('output', True)

    def test_main_output_route_replacement_stops_before_cleanup_and_private_state(self):
        self.route_failure_during_main_sync('output', False)

    def test_main_session_route_replacement_stops_before_cleanup_and_private_state(self):
        self.route_failure_during_main_sync('session', False)

    def test_route_replacement_before_cleanup_preserves_all_probes(self):
        original = receiver._close
        session_name = receiver.PREFIX + 'a' * 32
        detached = self.root / 'detached-before-cleanup'
        fired = []
        def changed(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size == 9 and not fired:
                original(fd)
                fired.append(True)
                self.output.rename(detached)
                self.output.mkdir(mode=0o700)
                return
            return original(fd)
        with patch.object(receiver.secrets, 'token_hex', return_value='a' * 32), \
                patch.object(receiver, '_close', side_effect=changed):
            error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertEqual(fired, [True])
        self.assertTrue(error.preflight['main_checks_completed'])
        self.assertFalse(error.preflight['cleanup_started'])
        self.assertTrue(error.preflight['identity_uncertain'])
        self.assertTrue(all(p['held_parent_entry']['observation'] == 'retained'
                            for p in error.preflight['probes']))
        self.assertTrue(all(not p['absolute_path_route_verified'] for p in error.preflight['probes']))
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse(any((detached / session_name / name).exists()
                             for name in ('lock', 'receive.tmp', 'ledger.json')))

    def test_route_replacement_between_cleanup_unlinks_preserves_actual_partial_facts(self):
        original = receiver.os.unlink
        session_name = receiver.PREFIX + 'a' * 32
        detached = self.root / 'detached-during-cleanup'
        calls = []
        def changed(name, **kwargs):
            result = original(name, **kwargs)
            if str(name).startswith('.preflight-'):
                calls.append(name)
                if len(calls) == 1:
                    self.output.rename(detached)
                    self.output.mkdir(mode=0o700)
            return result
        with patch.object(receiver.secrets, 'token_hex', return_value='a' * 32), \
                patch.object(receiver.os, 'unlink', side_effect=changed):
            error = self.error('publication_primitive_unavailable', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertEqual(len(calls), 1)
        probes = error.preflight['probes']
        self.assertEqual([p['cleanup_removed'] for p in probes], [False, False, True])
        self.assertEqual([p['held_parent_entry']['observation'] for p in probes],
                         ['retained', 'retained', 'removed'])
        self.assertTrue(all(not p['absolute_path_route_verified'] for p in probes))
        self.assertFalse(error.preflight['cleanup_durable'])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse(any((detached / session_name / name).exists()
                             for name in ('lock', 'receive.tmp', 'ledger.json')))

    def test_route_replacement_after_preflight_return_blocks_first_private_write_with_manifest(self):
        original = receiver.NativeChunkReceiver._preflight
        detached = self.root / 'detached-after-preflight'
        def changed(*args):
            report = original(*args)
            self.output.rename(detached)
            self.output.mkdir(mode=0o700)
            return report
        with patch.object(receiver.NativeChunkReceiver, '_preflight', staticmethod(changed)):
            error = self.error('directory_changed', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        report = error.preflight
        self.assertTrue(report['main_checks_completed'])
        self.assertTrue(report['cleanup_durable'])
        self.assertTrue(report['identity_uncertain'])
        self.assertEqual(report['private_state_creation']['checkpoint'], 'before_create_lock')
        self.assertEqual(report['private_state_creation']['created_files'], [])
        self.assertFalse(report['private_state_creation']['ledger_write_attempted'])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse(any(p.name in ('lock', 'receive.tmp', 'ledger.json') for p in detached.rglob('*')))

    def test_private_write_checkpoints_stop_after_late_route_change_and_preserve_created_facts(self):
        original = receiver._sync
        session_name = receiver.PREFIX + 'a' * 32
        detached = self.root / 'detached-after-lock'
        fired = []
        def changed(fd, code='durability_pending'):
            result = original(fd, code)
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size == 0 and not fired:
                fired.append(True)
                self.output.rename(detached)
                self.output.mkdir(mode=0o700)
            return result
        with patch.object(receiver.secrets, 'token_hex', return_value='a' * 32), \
                patch.object(receiver, '_sync', side_effect=changed):
            error = self.error('directory_changed', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        created = error.preflight['private_state_creation']
        self.assertEqual(created['checkpoint'], 'before_create_receive.tmp')
        self.assertEqual([p['name'] for p in created['created_files']], ['lock'])
        self.assertFalse(created['ledger_write_attempted'])
        self.assertTrue((detached / session_name / 'lock').exists())
        self.assertFalse((detached / session_name / 'receive.tmp').exists())
        self.assertFalse((detached / session_name / 'ledger.json').exists())
        self.assertEqual(list(self.output.iterdir()), [])

    def test_oserror_after_preflight_keeps_manifest_through_public_error_conversion(self):
        with patch.object(receiver, '_save_control', side_effect=OSError(errno.EIO, 'synthetic ledger IO error')):
            error = self.error('local_io_failed', receiver.NativeChunkReceiver.start,
                               legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        report = error.preflight
        self.assertTrue(report['main_checks_completed'])
        self.assertTrue(report['cleanup_durable'])
        self.assertTrue(report['private_state_creation']['ledger_write_attempted'])
        self.assertFalse(report['private_state_creation']['ledger_write_returned'])
        self.assertEqual([p['name'] for p in report['private_state_creation']['created_files']],
                         ['lock', 'receive.tmp'])

    def test_output_route_is_rechecked_before_first_session_directory_creation(self):
        original = receiver._space
        detached = self.root / 'detached-before-session'
        def changed(*args):
            original(*args)
            self.output.rename(detached)
            self.output.mkdir(mode=0o700)
        with patch.object(receiver, '_space', side_effect=changed):
            self.error('directory_changed', receiver.NativeChunkReceiver.start,
                       legacy.make_plan(b'data'), self.output, self.inputs, 'final.zip')
        self.assertEqual(list(detached.iterdir()), [])
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
