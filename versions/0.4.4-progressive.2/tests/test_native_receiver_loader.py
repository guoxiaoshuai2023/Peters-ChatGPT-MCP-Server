"""Exact-template loader tests use inert temporary code, never production."""
import ast
import builtins
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import py_compile
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def source_module(name):
    path = TOOLS / (name + '.py')
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


loader = source_module('native_receiver_loader')
renderer = source_module('render_native_acceptance_prompt')


def identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def pin(data):
    return {'asset_id': 'native-chunk-receiver-v1',
            'name': 'native_chunk_receiver.py', 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def fake_info(info, **changes):
    names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
             'st_nlink', 'st_uid', 'st_gid', 'st_mode')
    return SimpleNamespace(**{**{n: getattr(info, n) for n in names}, **changes})


def qualified_stub(factory_body=None):
    base = b'''MARKER = 1
class NativeChunkReceiver:
    @classmethod
    def start(cls, *args, **kwargs): pass
    resume = start
    def ingest(self, *args, **kwargs): pass
    status = finish = cancel = cleanup = ingest
'''
    default = '''def _for_native_input_root(path, identity):
    binding = (str(path), tuple(identity))
    class Bound(NativeChunkReceiver):
        @classmethod
        def _native_input_binding(cls): return binding
    return Bound
'''
    return base + (factory_body if factory_body is not None else default).encode('utf-8')


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-loader-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir(mode=0o700)
        self.path = self.inputs / 'actual-host-renamed-helper.py'
        self.body = b'MARKER = "verified"\n'
        self.path.write_bytes(self.body)
        self.path.chmod(0o644)
        self.expected = pin(self.body)
        builtins._PETERS_LOADER_TEST_MARKER = []
        self.addCleanup(lambda: delattr(builtins, '_PETERS_LOADER_TEST_MARKER'))

    def load(self, path=None, root=None, expected=None, offered=None, root_id=None):
        return loader.load_verified_receiver(
            str(path or self.path), str(root or self.inputs),
            root_id if root_id is not None else identity(self.inputs),
            expected if expected is not None else self.expected,
            offered if offered is not None else self.expected)

    def error(self, expected, call=None):
        with self.assertRaises(loader.LoaderError) as raised:
            (call or self.load)()
        codes = expected if isinstance(expected, tuple) else (expected,)
        self.assertIn(raised.exception.code, codes)
        return raised.exception

    def marker_source(self):
        self.body = b'import builtins\nbuiltins._PETERS_LOADER_TEST_MARKER.append("executed")\n'
        self.path.write_bytes(self.body)
        self.expected = pin(self.body)

    def test_actual_renamed_input_loads_fresh_verified_source_buffer(self):
        first, measured = self.load()
        self.assertEqual(first.MARKER, 'verified')
        self.assertEqual(first.__file__, str(self.path))
        self.assertTrue(measured['verified_source_buffer_executed'])
        self.assertTrue(measured['all_input_descriptors_closed_before_execution'])
        self.assertEqual(measured['actual_sha256'], self.expected['sha256'])
        self.assertEqual(measured['input_root_identity'], identity(self.inputs))
        self.assertIs(measured['native_receiver_root_bound'], False)
        first.MARKER = 'changed in caller namespace'
        second, _ = self.load()
        self.assertIsNot(first, second)
        self.assertEqual(second.MARKER, 'verified')
        self.assertNotIn(first.__name__, sys.modules)

    def test_helper_defined_factory_binds_immutable_copy_and_export(self):
        self.body = qualified_stub()
        self.path.write_bytes(self.body)
        self.expected = pin(self.body)
        supplied = identity(self.inputs)
        original = tuple(supplied)
        module, measured = self.load(root_id=supplied)
        self.assertIs(measured['native_receiver_root_bound'], True)
        self.assertEqual(module.NativeChunkReceiver._native_input_binding(), (str(self.inputs), original))
        supplied[1] += 1
        measured['input_root_identity'][1] += 2
        measured['input_root'] = '/not-the-verified-root'
        self.assertEqual(module.NativeChunkReceiver._native_input_binding(), (str(self.inputs), original))

    def test_present_but_nonbinding_factories_never_qualify(self):
        factories = [
            '_for_native_input_root = None\n',
            'def _for_native_input_root(path, identity): return None\n',
            'def _for_native_input_root(path, identity): return NativeChunkReceiver\n',
            '''def _for_native_input_root(path, identity):
    class Bound(NativeChunkReceiver):
        @classmethod
        def _native_input_binding(cls): return [path, identity]
    return Bound
''',
            '''def _for_native_input_root(path, identity):
    class Bound(NativeChunkReceiver):
        @classmethod
        def _native_input_binding(cls): return (path, list(identity))
    return Bound
''',
            '''def _for_native_input_root(path, identity):
    class Bound(NativeChunkReceiver):
        @classmethod
        def _native_input_binding(cls): return ("/wrong-root", tuple(identity))
    return Bound
''',
            '''def _for_native_input_root(path, identity):
    class Foreign:
        @classmethod
        def _native_input_binding(cls): return (path, tuple(identity))
        @classmethod
        def start(cls, *args, **kwargs): pass
        resume = start
        def ingest(self, *args, **kwargs): pass
        status = finish = cancel = cleanup = ingest
    return Foreign
''',
        ]
        for factory in factories:
            with self.subTest(factory=factory.splitlines()[0]):
                self.body = qualified_stub(factory)
                self.path.write_bytes(self.body)
                self.expected = pin(self.body)
                self.error('invalid_receiver_root_binding')

    def test_valid_stale_timestamp_pyc_is_not_executed(self):
        old, new = b'MARKER = "cached!!"\n', b'MARKER = "verified"\n'
        self.assertEqual(len(old), len(new))
        self.path.write_bytes(old)
        os.utime(self.path, ns=(1793330000000000000, 1793330000000000000))
        compiled = py_compile.compile(str(self.path), doraise=True,
                                      invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        self.path.write_bytes(new)
        os.utime(self.path, ns=(1793330000000000000, 1793330000000000000))
        module, measured = self.load(expected=pin(new), offered=pin(new))
        self.assertTrue(Path(compiled).exists())
        self.assertEqual(module.MARKER, 'verified')
        self.assertEqual(measured['actual_sha256'], hashlib.sha256(new).hexdigest())

    def test_same_hash_metadata_plan_cannot_replace_independent_release_pin(self):
        offered = dict(self.expected, sha256='0' * 64)
        with patch.object(loader.os, 'open', side_effect=AssertionError('must not open')):
            self.error('receiver_asset_pin_mismatch', lambda: self.load(offered=offered))

    def test_wrong_length_and_hash_do_not_execute(self):
        self.marker_source()
        self.error('receiver_asset_length_mismatch',
                   lambda: self.load(expected=dict(self.expected, bytes=len(self.body) + 1),
                                     offered=dict(self.expected, bytes=len(self.body) + 1)))
        bad = dict(self.expected, sha256='0' * 64)
        self.error('receiver_asset_hash_mismatch', lambda: self.load(expected=bad, offered=bad))
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_invalid_pin_and_root_identity_reject_before_file_open(self):
        variants = [dict(self.expected, bytes=True), dict(self.expected, bytes=0),
                    dict(self.expected, bytes=65537), dict(self.expected, sha256='A' * 64),
                    dict(self.expected, asset_id='other'), dict(self.expected, name='other.py'),
                    {**self.expected, 'extra': 1}]
        with patch.object(loader.os, 'open', side_effect=AssertionError('must not open')):
            for value in variants:
                with self.subTest(value=value):
                    self.error('invalid_asset_pin', lambda: self.load(expected=value))
            for value in ([True, 1], [-1, 2], [1], None, {'dev': 1, 'ino': 2}):
                with self.subTest(identity=value):
                    self.error('invalid_input_root_identity', lambda: loader.load_verified_receiver(
                        str(self.path), str(self.inputs), value, self.expected, self.expected))

    def test_root_identity_from_preflight_must_match(self):
        expected = identity(self.inputs)
        expected[1] += 1
        self.error('input_root_identity_mismatch', lambda: self.load(root_id=expected))

    def test_helper_outside_bound_root_is_rejected(self):
        external = self.root / 'outside.py'
        external.write_bytes(self.body)
        self.error('helper_outside_input_root', lambda: self.load(path=external))
        self.error('helper_outside_input_root', lambda: self.load(path=self.inputs))

    def test_relative_traversal_and_control_paths_rejected(self):
        for value in ('relative.py', str(self.inputs / '..' / 'else.py'), '/a\nb.py'):
            with self.subTest(path=value):
                self.error('invalid_path', lambda: self.load(path=value))

    def test_symlink_at_root_parent_or_file_is_rejected(self):
        alias = self.root / 'linked-input'
        alias.symlink_to(self.inputs, target_is_directory=True)
        self.error('received_helper_io_failed', lambda: self.load(
            path=alias / self.path.name, root=alias, root_id=identity(self.inputs)))
        nested = self.inputs / 'linked-parent'
        nested.symlink_to(self.inputs, target_is_directory=True)
        self.error('received_helper_io_failed', lambda: self.load(path=nested / self.path.name))
        linked = self.inputs / 'linked-helper.py'
        linked.symlink_to(self.path)
        self.error('received_helper_io_failed', lambda: self.load(path=linked))

    def test_hardlink_fifo_and_directory_are_not_received_code(self):
        other = self.inputs / 'hardlinked.py'
        os.link(self.path, other)
        self.error('unsafe_received_helper')
        other.unlink()
        fifo = self.inputs / 'fifo.py'
        os.mkfifo(fifo)
        self.error('unsafe_received_helper', lambda: self.load(path=fifo))
        directory = self.inputs / 'directory.py'
        directory.mkdir()
        self.error('unsafe_received_helper', lambda: self.load(path=directory))

    def test_group_world_write_and_special_bits_rejected(self):
        for mode in (0o664, 0o646, 0o4644, 0o2644, 0o1644):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                self.error('unsafe_received_helper')

    def test_ordinary_readable_modes_and_normal_atime_update_allowed(self):
        for mode in (0o600, 0o644, 0o444):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                before = self.path.stat()
                os.utime(self.path, ns=(1, before.st_mtime_ns))
                module, measured = self.load()
                self.assertEqual(module.MARKER, 'verified')
                self.assertEqual(measured['mode_octal'], oct(mode))

    def metadata(self, **changes):
        inode = identity(self.path)
        real_fstat, real_stat = os.fstat, os.stat
        def fstat(fd):
            value = real_fstat(fd)
            return fake_info(value, **changes) if [value.st_dev, value.st_ino] == inode else value
        def stat_call(*args, **kwargs):
            value = real_stat(*args, **kwargs)
            return fake_info(value, **changes) if [value.st_dev, value.st_ino] == inode else value
        return patch.object(loader.os, 'fstat', side_effect=fstat), patch.object(loader.os, 'stat', side_effect=stat_call)

    def test_root_owner_metadata_accepted_unknown_uid_rejected(self):
        # A precise metadata injection, not a claim of native or Linux testing.
        a, b = self.metadata(st_uid=0)
        with a, b:
            module, measured = self.load()
            self.assertEqual(module.MARKER, 'verified')
            self.assertEqual(measured['uid'], 0)
        a, b = self.metadata(st_uid=max(os.getuid(), 1000) + 100)
        with a, b:
            self.error('unsafe_received_helper')

    def test_file_path_replacement_after_hash_rejected_before_execution(self):
        self.marker_source()
        real_hash = hashlib.sha256
        replaced = False
        def hash_then_replace(data=b'', *args, **kwargs):
            nonlocal replaced
            value = real_hash(data, *args, **kwargs)
            if not replaced:
                replaced = True
                self.path.rename(self.path.with_suffix('.old'))
                self.path.write_bytes(self.body)
            return value
        with patch.object(loader.hashlib, 'sha256', side_effect=hash_then_replace):
            self.error('received_helper_changed')
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_input_root_replacement_during_read_rejected(self):
        self.marker_source()
        real_read = os.read
        changed = False
        def read_then_replace(fd, count):
            nonlocal changed
            data = real_read(fd, count)
            if not changed:
                changed = True
                self.inputs.rename(self.root / 'retained-old-inputs')
                self.inputs.mkdir(mode=0o700)
                self.path.write_bytes(self.body)
            return data
        with patch.object(loader.os, 'read', side_effect=read_then_replace):
            self.error('input_directory_changed')
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_descendant_parent_replacement_during_read_rejected(self):
        self.marker_source()
        parent = self.inputs / 'actual-parent'
        parent.mkdir()
        original = self.path
        self.path = parent / original.name
        original.rename(self.path)
        real_read = os.read
        changed = False
        def read_then_replace(fd, count):
            nonlocal changed
            data = real_read(fd, count)
            if not changed:
                changed = True
                parent.rename(self.inputs / 'retained-parent')
                parent.mkdir()
                self.path.write_bytes(self.body)
            return data
        with patch.object(loader.os, 'read', side_effect=read_then_replace):
            self.error('input_directory_changed')
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_source_mutation_while_reading_rejected(self):
        self.marker_source()
        real_read = os.read
        changed = False
        def read_then_mutate(fd, count):
            nonlocal changed
            data = real_read(fd, count)
            if not changed:
                changed = True
                self.path.write_bytes(self.body + b'#changed')
            return data
        with patch.object(loader.os, 'read', side_effect=read_then_mutate):
            self.error('received_helper_changed')
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_owner_gid_and_mode_changes_after_read_rejected_even_if_still_readable(self):
        real_fstat, real_stat, real_read = os.fstat, os.stat, os.read
        inode = identity(self.path)
        for field in ('st_uid', 'st_gid', 'st_mode'):
            changed = False
            def transform(info):
                if [info.st_dev, info.st_ino] != inode:
                    return info
                if field == 'st_uid':
                    return fake_info(info, st_uid=os.getuid() if changed else 0)
                if field == 'st_gid':
                    return fake_info(info, st_gid=info.st_gid + int(changed))
                return fake_info(info, st_mode=stat.S_IFREG | (0o444 if changed else 0o644))
            def read_then_change(fd, count):
                nonlocal changed
                data = real_read(fd, count)
                changed = True
                return data
            with self.subTest(field=field), patch.object(loader.os, 'fstat', side_effect=lambda fd: transform(real_fstat(fd))), patch.object(loader.os, 'stat', side_effect=lambda *a, **k: transform(real_stat(*a, **k))), patch.object(loader.os, 'read', side_effect=read_then_change):
                self.error('received_helper_changed')

    def test_io_read_and_short_read_fail_without_execution(self):
        self.marker_source()
        with patch.object(loader.os, 'read', side_effect=OSError(errno.EIO, 'injected')):
            self.error('received_helper_io_failed')
        with patch.object(loader.os, 'read', return_value=b''):
            self.error('receiver_asset_short_read')
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_uncertain_close_is_not_retried_and_prevents_execution(self):
        self.marker_source()
        inode = identity(self.path)
        real_close, real_fstat = os.close, os.fstat
        file_close_calls = []
        def close_then_raise(fd):
            info = real_fstat(fd)
            is_helper = [info.st_dev, info.st_ino] == inode
            real_close(fd)
            if is_helper:
                file_close_calls.append(fd)
                raise OSError(errno.EIO, 'injected close uncertainty')
        with patch.object(loader.os, 'close', side_effect=close_then_raise):
            self.error('descriptor_close_uncertain')
        self.assertEqual(len(file_close_calls), 1)
        self.assertEqual(builtins._PETERS_LOADER_TEST_MARKER, [])

    def test_exact_helper_limit_is_bounded(self):
        self.body = b'MARKER = 1\n' + b'#' * (65536 - len(b'MARKER = 1\n'))
        self.path.write_bytes(self.body)
        self.expected = pin(self.body)
        requested = []
        real_read = os.read
        def bounded_read(fd, count):
            requested.append(count)
            return real_read(fd, count)
        with patch.object(loader.os, 'read', side_effect=bounded_read):
            module, measured = self.load()
        self.assertEqual(module.MARKER, 1)
        self.assertEqual(measured['actual_bytes'], 65536)
        self.assertLessEqual(max(requested), loader.READ_BYTES)
        self.assertEqual(sum(requested), 65536)


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.loader_bytes = (TOOLS / 'native_receiver_loader.py').read_bytes()
        self.loader_sha = hashlib.sha256(self.loader_bytes).hexdigest()
        self.asset = pin(b'MARKER=1\n')
        self.data = {'run_label': 'synthetic-small-r1', 'stage': 'small',
                     'project_id': 'synthetic', 'worktree_id': 'main',
                     'source_path': 'acceptance/synthetic/small.zip',
                     'expected_bytes': 8192, 'expected_sha256': '1' * 64,
                     'expected_png_sha256': '2' * 64,
                     'package_fingerprint': '3' * 64, 'config_sha256': '4' * 64}

    def test_render_contains_exact_single_template_and_no_paths_yet_means_no_loading(self):
        rendered = renderer.render_loading_code(self.loader_bytes, self.loader_sha, self.asset)
        code = rendered['loading_code']
        parsed = ast.parse(code)
        node = next(n for n in parsed.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'LOADER_SOURCE' for t in n.targets))
        self.assertEqual(ast.literal_eval(node.value), self.loader_bytes)
        ns = {}
        exec(compile(code, '<rendered loading code>', 'exec'), ns)
        self.assertIsNone(ns['PARAMETERS'])
        self.assertNotIn('RECEIVER_MODULE', ns)
        self.assertTrue(callable(ns['load_actual_received_helper']))
        self.assertEqual(rendered['loading_code_sha256'], hashlib.sha256(code.encode()).hexdigest())

    def test_template_drift_rejected(self):
        for source, digest in ((self.loader_bytes + b'#changed', self.loader_sha),
                               (self.loader_bytes, '0' * 64)):
            with self.subTest(source_bytes=len(source)), self.assertRaisesRegex(ValueError, 'loader_template_mismatch'):
                renderer.render_loading_code(source, digest, self.asset)

    def test_data_with_python_syntax_is_only_data_not_execution(self):
        with tempfile.TemporaryDirectory(prefix='loader-render-injection-') as name:
            root = Path(name).resolve()
            path = root / "host'; raise RuntimeError('injected') #.py"
            payload = qualified_stub()
            path.write_bytes(payload)
            parameters = {'actual_helper_path': str(path), 'input_root': str(root),
                          'expected_input_identity': identity(root),
                          'plan_receiver_asset': pin(payload)}
            rendered = renderer.render_loading_code(self.loader_bytes, self.loader_sha,
                                                     pin(payload), parameters)
            ns = {}
            exec(compile(rendered['loading_code'], '<rendered loading code>', 'exec'), ns)
            self.assertEqual(ns['RECEIVER_MODULE'].MARKER, 1)
            self.assertEqual(ns['LOADER_EVIDENCE']['actual_helper_path'], str(path))
            self.assertIs(ns['LOADER_EVIDENCE']['native_receiver_root_bound'], True)

    def test_old_inert_helper_cannot_qualify_automatic_or_later_entry(self):
        with tempfile.TemporaryDirectory(prefix='loader-render-unbound-') as name:
            root = Path(name).resolve()
            path = root / 'old-inert-helper.py'
            data = b'MARKER=1\n'
            path.write_bytes(data)
            parameters = {'actual_helper_path': str(path), 'input_root': str(root),
                          'expected_input_identity': identity(root),
                          'plan_receiver_asset': pin(data)}
            automatic = renderer.render_loading_code(self.loader_bytes, self.loader_sha,
                                                      pin(data), parameters)
            with self.assertRaisesRegex(RuntimeError, 'native_receiver_root_binding_required'):
                exec(compile(automatic['loading_code'], '<automatic native entry>', 'exec'), {})
            later = renderer.render_loading_code(self.loader_bytes, self.loader_sha, pin(data))
            ns = {}
            exec(compile(later['loading_code'], '<later native entry>', 'exec'), ns)
            self.assertIsNone(ns['PARAMETERS'])
            with self.assertRaisesRegex(RuntimeError, 'native_receiver_root_binding_required'):
                ns['load_actual_received_helper'](**parameters)

    def test_native_entry_requires_true_not_merely_truthy_binding_evidence(self):
        rendered = renderer.render_loading_code(self.loader_bytes, self.loader_sha, self.asset)
        ns = {}
        exec(compile(rendered['loading_code'], '<binding gate>', 'exec'), ns)
        for value in (False, 1, 'true', None):
            with self.subTest(value=value):
                ns['LOADER_NAMESPACE']['load_verified_receiver'] = lambda *args: (
                    ModuleType('inert-test-only'), {'native_receiver_root_bound': value})
                with self.assertRaisesRegex(RuntimeError, 'native_receiver_root_binding_required'):
                    ns['load_actual_received_helper']('/unused.py', '/unused', [1, 2], self.asset)

    def test_native_identity_large_python_integer_is_serialized_exactly(self):
        huge = 9223372036854784013
        parameters = {'actual_helper_path': '/mnt/data/actual-helper.py',
                      'input_root': '/mnt/data', 'expected_input_identity': [1, huge],
                      'plan_receiver_asset': self.asset}
        rendered = renderer.render_loading_code(self.loader_bytes, self.loader_sha,
                                                 self.asset, parameters)
        parsed = ast.parse(rendered['loading_code'])
        node = next(n for n in parsed.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'PARAMETERS' for t in n.targets))
        actual = json.loads(ast.literal_eval(node.value.args[0]))
        self.assertEqual(actual['expected_input_identity'][1], huge)
        self.assertIs(type(actual['expected_input_identity'][1]), int)

    def test_runtime_bootstrap_checks_template_even_under_optimized_python(self):
        rendered = renderer.render_loading_code(self.loader_bytes, self.loader_sha, self.asset)
        bad = rendered['loading_code'].replace(repr(self.loader_sha), repr('0' * 64), 1)
        result = subprocess.run([sys.executable, '-O', '-c', bad], text=True,
                                capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('loader_template_mismatch', result.stderr)

    def test_prompt_has_full_source_release_data_and_bounded_finalization(self):
        rendered = renderer.render_prompt(self.loader_bytes, self.loader_sha, self.asset, self.data)
        for text in ('EXPECTED_ASSET', 'INPUT_ROOT', '最多12次', '60秒', 'receiver.cancel/cleanup',
                     '实际执行代码全文', 'native_receiver_root_bound=true',
                     'getattr(error,"preflight",None)',
                     self.data['expected_sha256'], self.data['package_fingerprint']):
            self.assertIn(text, rendered['prompt'])
        self.assertIn('本轮只签收8192字节小件', rendered['prompt'])
        large = dict(self.data, stage='30mb', expected_bytes=30_000_000)
        prompt = renderer.render_prompt(self.loader_bytes, self.loader_sha, self.asset, large)['prompt']
        self.assertIn('appended_bytes=0', prompt)
        self.assertIn('新Python对象resume', prompt)
        self.assertIn('此前相同发行', prompt)

    def test_invalid_acceptance_geometry_and_source_rejected(self):
        variants = [dict(self.data, expected_bytes=30_000_000),
                    dict(self.data, stage='70mb'), dict(self.data, source_path='../outside.zip'),
                    dict(self.data, source_path='/absolute.zip'),
                    dict(self.data, source_path='.'),
                    dict(self.data, expected_sha256='invalid')]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                renderer.render_prompt(self.loader_bytes, self.loader_sha, self.asset, value)

    def test_cli_input_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory(prefix='loader-render-json-') as name:
            path = Path(name) / 'input.json'
            for raw, expected in (('{"sha256":"a","sha256":"b"}', 'duplicate_json_key'),
                                  ('{"value":NaN}', 'invalid_json_constant')):
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with self.assertRaisesRegex(ValueError, expected):
                        renderer._read_json(path)

    def test_cli_creates_only_and_reports_exact_output_bytes(self):
        with tempfile.TemporaryDirectory(prefix='loader-render-cli-') as name:
            root = Path(name)
            asset_path, data_path, target = root / 'asset.json', root / 'data.json', root / 'message.txt'
            asset_path.write_text(json.dumps(self.asset))
            data_path.write_text(json.dumps(self.data))
            command = [sys.executable, '-B', str(TOOLS / 'render_native_acceptance_prompt.py'),
                       '--expected-loader-sha256', self.loader_sha,
                       '--expected-asset-manifest', str(asset_path),
                       '--acceptance-data', str(data_path), '--output', str(target)]
            first = subprocess.run(command, text=True, capture_output=True, timeout=15)
            self.assertEqual(first.returncode, 0, first.stderr)
            actual = target.read_bytes()
            self.assertEqual(json.loads(first.stdout)['sha256'], hashlib.sha256(actual).hexdigest())
            second = subprocess.run(command, text=True, capture_output=True, timeout=15)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(target.read_bytes(), actual)


class BoundReceiverIntegrationTests(unittest.TestCase):
    """Exercise actual helper-owned binding, not a loader-written receiver."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loader-bound-receiver-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir(mode=0o700)
        self.output = self.root / 'output'
        self.output.mkdir(mode=0o700)
        self.body = (TOOLS.parent / 'peters_mcp/native_chunk_receiver.py').read_bytes()
        self.path = self.inputs / 'actual-received-native_chunk_receiver.py'
        self.path.write_bytes(self.body)
        self.expected = pin(self.body)
        self.supplied_identity = identity(self.inputs)
        self.original_identity = tuple(self.supplied_identity)
        self.module, self.measured = loader.load_verified_receiver(
            str(self.path), str(self.inputs), self.supplied_identity,
            self.expected, dict(self.expected))
        self.assertIs(self.measured['native_receiver_root_bound'], True)
        self.data = b'correct source bytes'
        self.part = self.inputs / 'actual-received-part.bin'
        self.part.write_bytes(self.data)
        plan = {'protocol_version': 'raw-parts-v1', 'service_instance_id': '1' * 32,
                'export_id': '2' * 32, 'source': {'project_id': 'synthetic',
                'worktree_id': 'main', 'path': 'sample.zip'}, 'capture_version_sha256': '3' * 64,
                'total_bytes': len(self.data), 'total_sha256': hashlib.sha256(self.data).hexdigest(),
                'part_max_bytes': 8_000_000, 'part_count': 1,
                'parts': [{'index': 0, 'offset': 0, 'bytes': len(self.data),
                           'sha256': hashlib.sha256(self.data).hexdigest(), 'resource_name': 'part.bin'}],
                'receiver_asset': self.expected, 'expires_at_unix': 1}
        plan['plan_sha256'] = hashlib.sha256(self.module.canonical(plan)).hexdigest()
        self.plan = plan

    def replace_root(self):
        self.inputs.rename(self.root / 'retained-original-inputs')
        self.inputs.mkdir(mode=0o700)
        self.path.write_bytes(self.body)
        self.part.write_bytes(self.data)

    def rejected_start(self):
        with self.assertRaises(self.module.ReceiverError) as raised:
            self.module.NativeChunkReceiver.start(self.plan, self.output, self.inputs, 'received.zip')
        self.assertEqual(raised.exception.code, 'native_input_root_mismatch')
        self.assertEqual(list(self.output.iterdir()), [], 'root must reject before first output mutation')

    def test_root_replaced_after_loader_return_rejects_before_first_output_mutation(self):
        self.replace_root()
        self.rejected_start()

    def test_root_replaced_just_before_actual_helper_open_rejects(self):
        directory = self.module._directory
        changed = False
        @contextmanager
        def swap_before_open(path):
            nonlocal changed
            if str(path) == str(self.inputs) and not changed:
                changed = True
                self.replace_root()
            with directory(path) as fd:
                yield fd
        with patch.object(self.module, '_directory', swap_before_open):
            self.rejected_start()
        self.assertTrue(changed)

    def test_wrong_root_and_module_rebind_are_rejected(self):
        other = self.root / 'other-inputs'
        other.mkdir()
        with self.assertRaises(self.module.ReceiverError) as raised:
            self.module.NativeChunkReceiver.start(self.plan, self.output, other, 'received.zip')
        self.assertEqual(raised.exception.code, 'native_input_root_mismatch')
        with self.assertRaises(self.module.ReceiverError) as raised:
            self.module._for_native_input_root(str(other), identity(other))
        self.assertEqual(raised.exception.code, 'native_input_root_rebind')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_identity_list_or_evidence_mutation_does_not_change_actual_binding(self):
        receiver_class = self.module.NativeChunkReceiver
        self.supplied_identity[1] += 5
        self.measured['input_root_identity'][1] += 7
        self.measured['input_root'] = '/not-the-verified-root'
        self.assertEqual(receiver_class._native_input_binding(),
                         (str(self.inputs), self.original_identity))
        self.assertIs(self.module._for_native_input_root(str(self.inputs), self.original_identity), receiver_class)
        receiver = receiver_class.start(self.plan, self.output, self.inputs, 'received.zip')
        self.assertEqual(receiver.ingest(0, self.part)['appended_bytes'], len(self.data))
        self.assertEqual(receiver.ingest(0, self.part)['appended_bytes'], 0)
        receiver = receiver_class.resume(receiver.session_path, self.plan, self.inputs)
        final = receiver.finish()
        self.assertEqual(final['state'], 'published_verified')
        self.assertEqual(Path(final['path']).read_bytes(), self.data)

    def test_bound_resume_and_locked_finish_reject_replacement_root(self):
        receiver = self.module.NativeChunkReceiver.start(self.plan, self.output, self.inputs, 'received.zip')
        receiver.ingest(0, self.part)
        ledger = Path(receiver.session_path) / 'ledger.json'
        actual_ledger = ledger.read_bytes()
        self.replace_root()
        with self.assertRaises(self.module.ReceiverError) as raised:
            self.module.NativeChunkReceiver.resume(receiver.session_path, self.plan, self.inputs)
        self.assertEqual(raised.exception.code, 'native_input_root_mismatch')
        with self.assertRaises(self.module.ReceiverError) as raised:
            receiver.finish()
        self.assertEqual(raised.exception.code, 'native_input_root_mismatch')
        self.assertEqual(ledger.read_bytes(), actual_ledger)
        self.assertFalse((self.output / 'received.zip').exists())


if __name__ == '__main__':
    unittest.main()
