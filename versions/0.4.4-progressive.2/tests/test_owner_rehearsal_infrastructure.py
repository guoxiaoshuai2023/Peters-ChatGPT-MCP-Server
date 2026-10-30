"""Development-only preparation gates; no Docker process or native receipt."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('owner_linux_rehearsal', ROOT / 'tools/rehearse_native_owner_linux.py')
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)
SPEC = importlib.util.spec_from_file_location('owner_linux_runner', ROOT / 'tools/native_owner_linux_runner.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
SPEC = importlib.util.spec_from_file_location('owner_sdk_rehearsal', ROOT.parents[1] / 'tools/rehearse_progressive_release.py')
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


class OwnerRehearsalTests(unittest.TestCase):
    def cleanup_fixture(self, root, *, sampler_error=False, client_error=False,
                        blocked_stop=None, wait_timeout=False):
        ready = root / 'candidate.ready.json'
        ready.write_text(json.dumps({'pid': 4242}))
        events = []
        class Child:
            pid = 4242
            returncode = None
            waits = 0
            def poll(self):
                events.append('child.poll')
                return self.returncode
            def terminate(self):
                events.append('child.terminate')
                self.returncode = -15
            def kill(self):
                events.append('child.kill')
                self.returncode = -9
            def wait(self, timeout):
                events.append('child.wait:' + str(timeout))
                self.waits += 1
                if wait_timeout and self.waits == 1:
                    raise subprocess.TimeoutExpired('inert child', timeout)
                if self.returncode is None:
                    self.returncode = 0
                    ready.with_suffix('.stopped.json').write_text(json.dumps(
                        {'pid': self.pid, 'files': {'state': 'stopped'},
                         'export': {'state': 'stopped'}, 'rss_native_after': 1000}))
                return self.returncode
        class Sampler:
            stop_event = threading.Event()
            def stop(self):
                events.append('sampler.stop')
                if not self.stop_event.is_set():
                    raise AssertionError('sample production must freeze before stopping')
                if blocked_stop is not None:
                    blocked_stop.wait(3)
                if sampler_error:
                    raise RuntimeError('inert sampler stop failure')
            def evidence(self, _started, _ended):
                events.append('sampler.evidence')
                return {'sampler_alive_after_stop': False, 'errors': []}
        def close():
            events.append('client.close')
            if client_error:
                raise OSError('inert client close failure')
        return ready, Child(), Sampler(), SimpleNamespace(client=SimpleNamespace(close=close)), events

    def prepared(self, root):
        source = root / 'source'
        for directory in ['peters_mcp', 'tools']:
            (source / directory).mkdir(parents=True)
        helper = b'MARKER = "inert test fixture, never executed"\n'
        pin = {'asset_id': 'native-chunk-receiver-v1', 'name': 'native_chunk_receiver.py',
               'bytes': len(helper), 'sha256': hashlib.sha256(helper).hexdigest()}
        (source / 'peters_mcp/native_chunk_receiver.py').write_bytes(helper)
        (source / 'peters_mcp/transport_asset.py').write_text(
            'RECEIVER_ASSET_ID = ' + repr(pin['asset_id']) + '\n'
            'RECEIVER_NAME = ' + repr(pin['name']) + '\n'
            'RECEIVER_BYTES = ' + repr(pin['bytes']) + '\n'
            'RECEIVER_SHA256 = ' + repr(pin['sha256']) + '\n')
        loader = b'VALUE = "inert loader fixture, never executed"\n'
        (source / 'tools/native_receiver_loader.py').write_bytes(loader)
        builder = (ROOT / 'tools/generate_progressive_fixture.py').read_bytes()
        (source / 'tools/generate_progressive_fixture.py').write_bytes(builder)
        args = argparse.Namespace(source=source, old_source=source, output=root / 'prepared',
            base_reference='docker.io/library/python@sha256:' + 'a' * 64,
            expected_helper_sha256=pin['sha256'], expected_old_helper_sha256=pin['sha256'],
            expected_loader_sha256=hashlib.sha256(loader).hexdigest(),
            expected_fixture_builder_sha256=hashlib.sha256(builder).hexdigest())
        with patch.object(rehearsal.subprocess, 'run', side_effect=AssertionError('Docker forbidden in prepare')):
            with contextlib.redirect_stdout(io.StringIO()):
                rehearsal.prepare(args)
        return args

    def test_preparation_is_closed_and_file_mutation_blocks_before_docker(self):
        with tempfile.TemporaryDirectory(prefix='owner-context-gate-test-') as temporary:
            root = Path(temporary).resolve()
            args = self.prepared(root)
            manifest_sha = rehearsal.digest((args.output / 'context-manifest.json').read_bytes())
            recipe_sha = rehearsal.digest((args.output / 'run-recipe.json').read_bytes())
            manifest, recipe = rehearsal.verify_prepared(args.output, manifest_sha, recipe_sha)
            self.assertLess(manifest['total_bytes'], 100_000_000)
            self.assertEqual({x['path'] for x in manifest['files']}, rehearsal.CONTEXT_NAMES)
            self.assertEqual(recipe['runtime_flags'], rehearsal.RUNTIME_FLAGS)
            dockerfile = (args.output / 'context/Dockerfile').read_text()
            self.assertNotIn('\nRUN ', dockerfile)
            self.assertNotIn('\nADD ', dockerfile)
            self.assertEqual(dockerfile.splitlines()[1:3],
                             ['WORKDIR /opt/host-input', 'WORKDIR /opt/runner'])
            self.assertIn('USER 1000:1000', dockerfile)
            # Extra secrets/configuration cannot enter Docker through a broadened context.
            (args.output / 'context/credential.json').write_text('inert unexpected file')
            with self.assertRaisesRegex(ValueError, 'unexpected_context_file'):
                rehearsal.verify_prepared(args.output, manifest_sha, recipe_sha)
            (args.output / 'context/credential.json').unlink()
            (args.output / 'context/native_chunk_receiver.py').write_bytes(b'different bytes')
            with self.assertRaisesRegex(ValueError, 'context_file_changed'):
                rehearsal.verify_prepared(args.output, manifest_sha, recipe_sha)

    def test_workdir_allowlist_rejects_other_order_or_missing_even_when_rehashed(self):
        with tempfile.TemporaryDirectory(prefix='owner-context-workdir-test-') as temporary:
            prepared = self.prepared(Path(temporary).resolve()).output
            dockerfile = prepared / 'context/Dockerfile'
            original = dockerfile.read_text()
            cases = {
                'other': original.replace('WORKDIR /opt/host-input', 'WORKDIR /tmp/unreviewed'),
                'order': original.replace('WORKDIR /opt/host-input\nWORKDIR /opt/runner',
                                          'WORKDIR /opt/runner\nWORKDIR /opt/host-input'),
                'missing': original.replace('WORKDIR /opt/host-input\n', ''),
            }
            for name, changed in cases.items():
                with self.subTest(case=name):
                    dockerfile.write_text(changed)
                    manifest_path = prepared / 'context-manifest.json'
                    recipe_path = prepared / 'run-recipe.json'
                    manifest = json.loads(manifest_path.read_bytes())
                    item = next(x for x in manifest['files'] if x['path'] == 'Dockerfile')
                    item.update(bytes=len(changed.encode()), sha256=rehearsal.digest(changed.encode()))
                    manifest['total_bytes'] = sum(x['bytes'] for x in manifest['files'])
                    manifest_path.write_text(json.dumps(manifest))
                    manifest_sha = rehearsal.digest(manifest_path.read_bytes())
                    recipe = json.loads(recipe_path.read_bytes())
                    recipe['context_manifest_sha256'] = manifest_sha
                    recipe['dockerfile_sha256'] = item['sha256']
                    buffers = {p.name: p.read_bytes() for p in (prepared / 'context').iterdir()}
                    archive = rehearsal.closed_tar(buffers)
                    recipe['builder_input'].update(bytes=len(archive), sha256=rehearsal.digest(archive))
                    recipe_path.write_text(json.dumps(recipe))
                    recipe_sha = rehearsal.digest(recipe_path.read_bytes())
                    with patch.object(rehearsal.subprocess, 'run', side_effect=AssertionError('Docker forbidden')):
                        with self.assertRaisesRegex(ValueError, 'dockerfile_not_fixed_allowlist'):
                            rehearsal.verify_prepared(prepared, manifest_sha, recipe_sha)

    def test_wrong_derived_runtime_workdir_rejects_before_container_creation(self):
        with tempfile.TemporaryDirectory(prefix='owner-runtime-workdir-test-') as temporary:
            prepared = self.prepared(Path(temporary).resolve()).output
            commands = []
            def intercept(command, _output, _timeout, *, input_bytes=None):
                commands.append(command)
                if command[:3] == ['docker', 'image', 'inspect']:
                    if '@sha256:' in command[-1]:
                        return json.dumps([{'Os': 'linux', 'Architecture': 'arm64', 'Id': 'sha256:' + 'a' * 64}])
                    return json.dumps([{'Id': 'sha256:' + 'b' * 64,
                        'Config': {'User': '1000:1000', 'WorkingDir': '/tmp/unreviewed'}, 'Size': 1}])
                if command[:2] == ['docker', 'build']:
                    self.assertIs(type(input_bytes), bytes)
                    return 'inert build intercepted'
                raise AssertionError('Unexpected Docker operation: ' + repr(command))
            args = argparse.Namespace(prepared=prepared, apply_reviewed_context=True,
                expected_manifest_sha256=rehearsal.digest((prepared / 'context-manifest.json').read_bytes()),
                expected_recipe_sha256=rehearsal.digest((prepared / 'run-recipe.json').read_bytes()))
            with patch.object(rehearsal, 'command_record', side_effect=intercept):
                with self.assertRaises(AssertionError):
                    rehearsal.run(args)
            self.assertFalse(any(cmd[:2] == ['docker', 'create'] for cmd in commands))

    def test_run_requires_explicit_apply_and_does_not_start_docker(self):
        args = argparse.Namespace(apply_reviewed_context=False)
        with patch.object(rehearsal.subprocess, 'run', side_effect=AssertionError('Docker forbidden')):
            with self.assertRaisesRegex(ValueError, 'explicit_reviewed_context_apply_required'):
                rehearsal.run(args)

    def test_frozen_loader_mismatch_rejects_before_inert_marker_can_execute(self):
        with tempfile.TemporaryDirectory(prefix='owner-loader-order-test-') as temporary:
            root = Path(temporary).resolve()
            (root / 'tools').mkdir()
            marker = root / 'inert-marker'
            loader = root / 'tools/native_receiver_loader.py'
            raw = ('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("should never run")\n').encode()
            loader.write_bytes(raw)
            (root / 'manifest.json').write_text(json.dumps({'files': [
                {'path': 'tools/native_receiver_loader.py', 'bytes': 9, 'sha256': '0' * 64}]}))
            with self.assertRaisesRegex(ValueError, 'frozen_manifest_loader_mismatch'):
                sdk.reviewed_loader(root, loader, hashlib.sha256(raw).hexdigest())
            self.assertFalse(marker.exists())

    def test_source_loader_explicit_pin_rejects_before_execution(self):
        with tempfile.TemporaryDirectory(prefix='owner-loader-source-pin-test-') as temporary:
            root = Path(temporary).resolve()
            marker = root / 'inert-marker'
            loader = root / 'loader.py'
            loader.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            with self.assertRaisesRegex(ValueError, 'independent_loader_pin_mismatch'):
                sdk.reviewed_loader(root, loader, '0' * 64)
            self.assertFalse(marker.exists())

    def test_loader_executes_validated_buffer_when_disk_changes_after_check(self):
        with tempfile.TemporaryDirectory(prefix='owner-loader-byte-buffer-test-') as temporary:
            root = Path(temporary).resolve()
            loader = root / 'loader.py'
            original = b'VALUE = "verified bytes"\n'
            loader.write_bytes(original)
            marker = root / 'wrong-code-marker'
            compile_buffer = sdk.module_from_source_buffer
            def changed(body, path, name):
                loader.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
                return compile_buffer(body, path, name)
            with patch.object(sdk, 'module_from_source_buffer', side_effect=changed):
                module, proof = sdk.reviewed_loader(root, loader, hashlib.sha256(original).hexdigest())
            self.assertEqual(module.VALUE, 'verified bytes')
            self.assertFalse(marker.exists())
            self.assertTrue(proof['same_validated_buffer_executed'])

    def test_failed_sampler_cannot_pass_at_baseline_delta_zero(self):
        def fail(_pid):
            raise OSError('inert simulated ps failure')
        sampler = sdk.ResidentSampler(12345, probe=fail)
        start = time.monotonic()
        sampler.start()
        sampler.stop()
        self.assertTrue(sampler.evidence()['errors'])
        with self.assertRaisesRegex(RuntimeError, 'rss_measurement_incomplete'):
            sampler.validate(start, time.monotonic(), 100 * 1024 * 1024)

    def test_blocked_sampler_is_reported_alive_and_resource_gate_fails(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(_pid):
            entered.set()
            release.wait(3)
            return 100 * 1024 * 1024
        sampler = sdk.ResidentSampler(12345, probe=blocked)
        start = time.monotonic()
        sampler.start()
        self.assertTrue(entered.wait(1))
        try:
            sampler.stop()
            self.assertTrue(sampler.evidence()['sampler_alive_after_stop'])
            with self.assertRaisesRegex(RuntimeError, 'rss_measurement_incomplete'):
                sampler.validate(start, time.monotonic(), 100 * 1024 * 1024)
        finally:
            release.set()
            sampler.thread.join(1)

    def test_baseline_only_samples_without_errors_still_cannot_pass(self):
        baseline = 100 * 1024 * 1024
        sampler = sdk.ResidentSampler(12345, probe=lambda _: baseline)
        start = time.monotonic()
        sampler.samples.append({'started_monotonic': start - .01,
            'observed_monotonic': start - .009, 'observed_at_unix': time.time(),
            'rss_bytes': baseline, 'probe_seconds': .001})
        self.assertEqual(sampler.evidence()['errors'], [])
        with self.assertRaisesRegex(RuntimeError, 'rss_measurement_incomplete'):
            sampler.validate(start, start + .1, baseline)

    def test_os_resident_probe_is_bounded(self):
        with patch.object(sdk.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ps', .25)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                sdk.resident_bytes(12345)
        self.assertEqual(run.call_args.kwargs['timeout'], .25)

    def test_valid_timed_samples_and_historical_highwater_are_separate(self):
        baseline = 100 * 1024 * 1024
        sampler = sdk.ResidentSampler(12345, probe=lambda _: baseline)
        start = time.monotonic()
        sampler.start()
        time.sleep(.08)
        end = time.monotonic()
        sampler.stop()
        proof = sampler.validate(start, end, baseline)
        self.assertGreaterEqual(proof['valid_samples_during_transfer'], 2)
        self.assertEqual(proof['extra_bytes'], 0)
        # Equal historical maxima cannot mask a peak far above current residency.
        with self.assertRaisesRegex(RuntimeError, 'native_highwater_above_current_baseline'):
            sdk.native_highwater_bound(baseline, 500 * 1024 * 1024, 500 * 1024 * 1024)

    def test_post_verification_disk_mutation_cannot_reach_docker_stdin(self):
        with tempfile.TemporaryDirectory(prefix='owner-build-byte-buffer-test-') as temporary:
            root = Path(temporary).resolve()
            prepared = self.prepared(root).output
            manifest_sha = rehearsal.digest((prepared / 'context-manifest.json').read_bytes())
            recipe_sha = rehearsal.digest((prepared / 'run-recipe.json').read_bytes())
            original_dockerfile = (prepared / 'context/Dockerfile').read_bytes()
            captured = []
            def intercept(command, _output, _timeout, *, input_bytes=None):
                if command[:3] == ['docker', 'image', 'inspect']:
                    with (prepared / 'context/Dockerfile').open('ab') as f:
                        f.write(b'RUN inert-unreviewed-marker\n')
                    return json.dumps([{'Os': 'linux', 'Architecture': 'arm64', 'Id': 'sha256:' + 'b' * 64}])
                if command[:2] == ['docker', 'build']:
                    self.assertEqual(command[-1], '-')
                    self.assertIs(type(input_bytes), bytes)
                    with tarfile.open(fileobj=io.BytesIO(input_bytes)) as archive:
                        self.assertEqual(set(archive.getnames()), rehearsal.CONTEXT_NAMES)
                        self.assertTrue(all(member.isfile() and member.uid == 0 and member.mode == 0o644
                                            for member in archive.getmembers()))
                        actual = archive.extractfile('Dockerfile').read()
                    self.assertEqual(actual, original_dockerfile)
                    self.assertNotIn(b'RUN inert-unreviewed-marker', actual)
                    captured.append(hashlib.sha256(input_bytes).hexdigest())
                    raise RuntimeError('inert build interception; no Docker executed')
                raise AssertionError(command)
            args = argparse.Namespace(prepared=prepared, apply_reviewed_context=True,
                expected_manifest_sha256=manifest_sha, expected_recipe_sha256=recipe_sha)
            with patch.object(rehearsal, 'command_record', side_effect=intercept):
                with self.assertRaisesRegex(RuntimeError, 'inert build interception'):
                    rehearsal.run(args)
            recipe = json.loads((prepared / 'run-recipe.json').read_bytes())
            self.assertEqual(captured, [recipe['builder_input']['sha256']])
            self.assertIn(b'RUN inert-unreviewed-marker', (prepared / 'context/Dockerfile').read_bytes())

    def test_normal_sdk_cleanup_freezes_sampling_then_observes_real_receipt(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-normal-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root)
            result, error = sdk.close_owned_rehearsal(child, 4242, ready, http=http, sampler=sampler,
                rss_path=root / 'rss.json')
            self.assertIsNone(error)
            self.assertTrue(result['complete'])
            self.assertEqual(result['shutdown_receipt']['pid'], 4242)
            self.assertLess(events.index('sampler.stop'), events.index('child.wait:20'))
            self.assertLess(events.index('child.wait:20'), events.index('client.close'))
            self.assertNotIn('child.kill', events)
            self.assertNotIn('child.terminate', events)
            self.assertEqual(sdk.require_closed_phase('candidate', None, result, None, {}), result['shutdown_receipt'])

    def test_rss_evidence_write_failure_does_not_skip_owned_child_stop_wait(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-diagnostic-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root)
            rss = root / 'rss.json'
            original = sdk.save_new
            def fail_evidence(path, value):
                if path == rss:
                    raise OSError('inert evidence write failure')
                return original(path, value)
            with patch.object(sdk, 'save_new', side_effect=fail_evidence):
                result, error = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                    sampler=sampler, rss_path=rss)
            self.assertIn('child.wait:20', events)
            self.assertTrue(result['owned_child_waited'])
            self.assertEqual(result['shutdown_receipt']['pid'], 4242)
            self.assertFalse(result['complete'])
            self.assertIn('write_rss_evidence', [x['action'] for x in result['errors']])
            with self.assertRaises(sdk.RehearsalPhaseFailure):
                sdk.require_closed_phase('candidate', None, result, error, {})

    def test_client_close_failure_keeps_original_primary_and_closed_child(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-client-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root, client_error=True)
            result, secondary = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                sampler=sampler, rss_path=root / 'rss.json')
            self.assertIn('child.wait:20', events)
            self.assertEqual(result['shutdown_receipt']['files']['state'], 'stopped')
            primary = ValueError('inert original primary failure')
            with self.assertRaises(sdk.RehearsalPhaseFailure) as caught:
                sdk.require_closed_phase('candidate', primary, result, secondary, {'phase': 'candidate'})
            self.assertIs(caught.exception.__cause__, primary)
            self.assertEqual(caught.exception.primary['error'], 'inert original primary failure')
            self.assertEqual(caught.exception.cleanup['errors'][0]['action'], 'http_client_close')

    def test_sampler_stop_failure_still_reaches_owned_child_stop_wait(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-sampler-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root, sampler_error=True)
            result, error = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                sampler=sampler, rss_path=root / 'rss.json')
            self.assertIn('child.wait:20', events)
            self.assertTrue(result['owned_child_waited'])
            self.assertFalse(result['complete'])
            self.assertEqual(result['errors'][0]['action'], 'sampler_stop')
            with self.assertRaises(sdk.RehearsalPhaseFailure):
                sdk.require_closed_phase('candidate', None, result, error, {})

    def test_unstarted_sampler_does_not_replace_original_start_failure(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-sampler-start-') as name:
            root = Path(name).resolve()
            ready, child, _sampler, http, events = self.cleanup_fixture(root)
            sampler = sdk.ResidentSampler(4242, probe=lambda _: 100)
            result, secondary = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                sampler=sampler, rss_path=root / 'rss.json')
            self.assertIn('child.wait:20', events)
            self.assertIsNone(secondary)
            primary = RuntimeError('inert original thread-start failure')
            with self.assertRaises(sdk.RehearsalPhaseFailure) as caught:
                sdk.require_closed_phase('candidate', primary, result, secondary, {})
            self.assertIs(caught.exception.__cause__, primary)
            self.assertEqual(caught.exception.primary['error'], 'inert original thread-start failure')

    def test_blocked_sampler_stop_is_bounded_and_child_still_closes(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-blocked-') as name:
            root = Path(name).resolve()
            release = threading.Event()
            ready, child, sampler, http, events = self.cleanup_fixture(root, blocked_stop=release)
            try:
                started = time.monotonic()
                result, error = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                    sampler=sampler, rss_path=root / 'rss.json')
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertIn('child.wait:20', events)
                self.assertTrue(result['owned_child_waited'])
                self.assertFalse(result['complete'])
                self.assertIn('sampler_stop_did_not_finish_within_bound', str(error))
            finally:
                release.set()

    def test_unknown_child_identity_is_never_signalled_or_waited(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-unknown-pid-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root)
            result, error = sdk.close_owned_rehearsal(child, 9999, ready, http=http,
                sampler=sampler, rss_path=root / 'rss.json')
            self.assertFalse(any(x.startswith('child.') for x in events))
            self.assertFalse(result['owned_child_waited'])
            self.assertFalse(result['complete'])
            self.assertIn('owned_child_identity_mismatch', str(error))

    def test_owned_child_wait_timeout_uses_only_bounded_owned_fallback(self):
        with tempfile.TemporaryDirectory(prefix='owner-cleanup-wait-timeout-') as name:
            root = Path(name).resolve()
            ready, child, sampler, http, events = self.cleanup_fixture(root, wait_timeout=True)
            result, error = sdk.close_owned_rehearsal(child, 4242, ready, http=http,
                sampler=sampler, rss_path=root / 'rss.json')
            self.assertIn('child.wait:20', events)
            self.assertIn('child.kill', events)
            self.assertIn('child.wait:5', events)
            self.assertTrue(result['owned_child_waited'])
            self.assertFalse(result['complete'])
            self.assertIsInstance(error, subprocess.TimeoutExpired)
            self.assertIsNone(result['shutdown_receipt'])

    def test_failed_rehearsal_preserves_its_owned_fixture_directory(self):
        retained = None
        try:
            with self.assertRaises(ValueError) as caught:
                with sdk.owned_fixture_directory() as root:
                    retained = root
                    (root / 'inert-marker').write_text('preserved failure evidence')
                    raise ValueError('inert failure')
            self.assertEqual(caught.exception.retained_fixture_root, str(retained))
            self.assertTrue((retained / 'inert-marker').exists())
        finally:
            if retained is not None:
                (retained / 'inert-marker').unlink()
                retained.rmdir()

    def test_fixed_png_decoder_reconstructs_all_pixels_and_rejects_corruption(self):
        spec = importlib.util.spec_from_file_location('fixed_png_builder', ROOT / 'tools/generate_progressive_fixture.py')
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        image = generator.png_bytes()
        proof = runner.decode_fixed_png(image, hashlib.sha256(image).hexdigest())
        self.assertEqual(proof['fully_decoded_pixels'], 64)
        self.assertEqual(proof['size'], [8, 8])
        self.assertEqual(proof['mode'], 'RGBA')
        corrupted = image[:-1] + bytes([image[-1] ^ 1])
        # Even if a caller rehashes corrupt bytes, the independent PNG CRC must fail.
        with self.assertRaises(AssertionError):
            runner.decode_fixed_png(corrupted, hashlib.sha256(corrupted).hexdigest())


if __name__ == '__main__':
    unittest.main()
