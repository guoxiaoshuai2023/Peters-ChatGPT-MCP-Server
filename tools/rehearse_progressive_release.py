#!/usr/bin/env python3
"""Authenticated loopback/SDK progressive rehearsal, never production or native ChatGPT."""
import argparse
import ast
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import sqlite3
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from types import ModuleType
import zipfile


REPO = Path(__file__).resolve().parent.parent
PROTOCOL = '2026-07-28'
TOOLS = {'prepare_chunked_export', 'get_chunked_export_status', 'get_chunked_export_plan',
         'materialize_chunked_export_part', 'materialize_chunked_export_receiver', 'cancel_chunked_export'}


def stable_source(path, maximum=100_000_000):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('linked_test_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_size > maximum
                or before.st_mode & 0o022):
            raise ValueError('unsafe_test_input')
        body = bytearray()
        while len(body) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        stamp = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns,
                           v.st_ctime_ns, v.st_nlink, v.st_uid, v.st_gid, v.st_mode)
        if (stamp(before) != stamp(os.fstat(fd))
                or stamp(before) != stamp(path.stat(follow_symlinks=False))
                or len(body) != before.st_size):
            raise ValueError('changed_test_input')
        return bytes(body)
    finally:
        os.close(fd)


def source_record(path, body=None):
    body = stable_source(path) if body is None else body
    return {'path': str(Path(path).absolute()), 'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest()}


def module_from_source_buffer(body, path, name):
    module = ModuleType(name)
    module.__file__ = str(Path(path).absolute())
    sys.modules[name] = module
    exec(compile(body, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


def source_module(path, name):
    body = stable_source(path)
    module = module_from_source_buffer(body, path, name)
    return module, source_record(path, body)


def reviewed_loader(source, path, expected_sha256):
    """Authenticate the one read buffer before it can execute any code."""
    body = stable_source(path, 65536)
    measured = source_record(path, body)
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or measured['sha256'] != expected_sha256):
        raise ValueError('independent_loader_pin_mismatch')
    measured['independent_expected_sha256'] = expected_sha256
    measured['pin_kind'] = 'explicit_source_development_sha256'
    manifest_path = source / 'manifest.json'
    if manifest_path.exists():
        manifest_raw = stable_source(manifest_path)
        manifest = json.loads(manifest_raw)
        item = next(item for item in manifest['files'] if item['path'] == 'tools/native_receiver_loader.py')
        if (item['bytes'], item['sha256']) != (measured['bytes'], measured['sha256']):
            raise ValueError('frozen_manifest_loader_mismatch')
        measured.update(pin_kind='explicit_sha256_and_frozen_manifest',
                        manifest=source_record(manifest_path, manifest_raw))
    module = module_from_source_buffer(body, path, 'frozen_native_receiver_loader')
    measured['same_validated_buffer_executed'] = True
    return module, measured


def load_reference():
    module, _ = source_module(REPO / 'tools/rehearse_identity_release.py',
                              'progressive_rehearsal_reference')
    return module


def receiver_pin(source):
    """Read the separately selected package pin, never trust the received plan."""
    path = source / 'peters_mcp/transport_asset.py'
    raw = stable_source(path, 65536)
    values = {}
    wanted = {'RECEIVER_ASSET_ID', 'RECEIVER_NAME', 'RECEIVER_BYTES', 'RECEIVER_SHA256'}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                values[name] = ast.literal_eval(node.value)
    if set(values) != wanted:
        raise ValueError('missing_independent_package_receiver_pin')
    pin = {'asset_id': values['RECEIVER_ASSET_ID'], 'name': values['RECEIVER_NAME'],
           'bytes': values['RECEIVER_BYTES'], 'sha256': values['RECEIVER_SHA256']}
    helper = source / 'peters_mcp/native_chunk_receiver.py'
    measured = source_record(helper)
    if measured['bytes'] != pin['bytes'] or measured['sha256'] != pin['sha256']:
        raise ValueError('package_receiver_pin_mismatch')
    result = {'pin': pin, 'pin_source': source_record(path, raw), 'helper_source': measured,
              'kind': 'source_development_independent_pin'}
    manifest_path = source / 'manifest.json'
    if manifest_path.exists():
        manifest_raw = stable_source(manifest_path)
        manifest = json.loads(manifest_raw)
        records = {item['path']: item for item in manifest['files']}
        item = records['peters_mcp/native_chunk_receiver.py']
        if item['bytes'] != pin['bytes'] or item['sha256'] != pin['sha256']:
            raise ValueError('frozen_manifest_receiver_pin_mismatch')
        result.update(kind='frozen_package_independent_pin',
                      manifest=source_record(manifest_path, manifest_raw),
                      content_fingerprint=manifest['content_fingerprint'])
    return result


def save_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def exception_record(error):
    return {'type': type(error).__name__, 'error': str(error),
            'traceback': ''.join(traceback.format_exception(type(error), error, error.__traceback__))}


class RehearsalPhaseFailure(RuntimeError):
    def __init__(self, phase, primary, cleanup, partial):
        self.primary = exception_record(primary) if primary is not None else None
        self.cleanup = cleanup
        self.partial_phase = partial
        super().__init__('isolated_phase_failed:' + phase)


@contextmanager
def owned_fixture_directory():
    """Only successful, fully closed rehearsals discard their owned temp inputs."""
    root = Path(tempfile.mkdtemp(prefix='peters-progressive-http-')).resolve()
    before = root.stat(follow_symlinks=False)
    try:
        yield root
    except BaseException as error:
        error.retained_fixture_root = str(root)
        raise
    else:
        current = root.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
            raise RuntimeError('owned_fixture_root_changed_cleanup_refused')
        shutil.rmtree(root)


def bounded_sampler_stop(sampler):
    """A broken stop implementation cannot prevent owned-process cleanup."""
    finished = threading.Event()
    errors = []
    def stop():
        try:
            sampler.stop()
        except BaseException as error:
            errors.append(error)
        finally:
            finished.set()
    worker = threading.Thread(target=stop, daemon=True)
    worker.start()
    if not finished.wait(1.25):
        raise RuntimeError('sampler_stop_did_not_finish_within_bound')
    worker.join(.1)
    if worker.is_alive():
        raise RuntimeError('sampler_stop_worker_shutdown_pending')
    if errors:
        raise errors[0]


def close_owned_rehearsal(child, owned_pid, ready, *, http=None, sampler=None,
                          rss_path=None, transfer_started=None, transfer_ended=None):
    """Freeze/stop sampling with a bound, then always close the exact owned child.

    Each action records its own failure and cannot skip later actions. Signals
    are limited to the Popen object created by this rehearsal and its captured
    PID; ready metadata never grants permission to signal another process.
    """
    result = {'owned_pid': owned_pid, 'events': [], 'errors': [],
              'owned_child_waited': False, 'shutdown_receipt': None}
    first_error = None

    def attempt(name, function):
        nonlocal first_error
        result['events'].append(name)
        try:
            return True, function()
        except BaseException as error:
            if first_error is None:
                first_error = error
            result['errors'].append({'action': name, **exception_record(error)})
            return False, None

    def own_identity():
        if type(owned_pid) is not int or owned_pid <= 0 or child.pid != owned_pid:
            raise RuntimeError('owned_child_identity_mismatch')

    def own_call(method, *args, **kwargs):
        own_identity()
        return getattr(child, method)(*args, **kwargs)

    # Freeze before PID disappearance so normal shutdown cannot pollute valid
    # samples. Even a broken sampler.stop is bounded independently of the child.
    if sampler is not None:
        attempt('freeze_sampling', lambda: sampler.stop_event.set())
        attempt('sampler_stop', lambda: bounded_sampler_stop(sampler))

    valid, _ = attempt('verify_owned_child', own_identity)
    if valid:
        polled, status = attempt('poll_owned_child', lambda: own_call('poll'))
        if polled and status is None:
            def graceful_stop():
                info = json.loads(stable_source(ready, 65536))
                if type(info.get('pid')) is not int or info['pid'] != owned_pid:
                    raise RuntimeError('ready_pid_mismatch')
                stop_path = ready.with_suffix('.stop')
                if stop_path.exists():
                    if json.loads(stable_source(stop_path, 65536)) != {'pid': owned_pid}:
                        raise RuntimeError('owned_stop_request_conflict')
                else:
                    save_new(stop_path, {'pid': owned_pid})
                result['graceful_stop_requested'] = True
            requested, _ = attempt('request_pid_bound_stop', graceful_stop)
            if not requested:
                def terminate_if_still_owned():
                    if own_call('poll') is None:
                        own_call('terminate')
                attempt('terminate_owned_child_after_stop_request_failure', terminate_if_still_owned)

        waited, returncode = attempt('wait_owned_child', lambda: own_call('wait', timeout=20))
        if not waited:
            def kill_if_still_owned():
                if own_call('poll') is None:
                    own_call('kill')
            attempt('kill_owned_child_after_wait_failure', kill_if_still_owned)
            waited, returncode = attempt('wait_owned_child_after_kill', lambda: own_call('wait', timeout=5))
        if waited:
            result['wait_returncode'] = returncode
            result['owned_child_waited'] = type(returncode) is int
            def verify_exit():
                if type(returncode) is not int or returncode != 0:
                    raise RuntimeError('owned_child_exit_not_clean')
            attempt('verify_owned_child_exit', verify_exit)

        def stopped_receipt():
            receipt = json.loads(stable_source(ready.with_suffix('.stopped.json'), 65536))
            if (receipt.get('pid') != owned_pid or receipt.get('files', {}).get('state') != 'stopped'
                    or receipt.get('export') is not None and receipt['export'].get('state') != 'stopped'):
                raise RuntimeError('owned_shutdown_receipt_invalid')
            result['shutdown_receipt'] = receipt
        attempt('read_actual_owned_shutdown_receipt', stopped_receipt)

    # These independent diagnostic/client actions never bypass child shutdown.
    if sampler is not None:
        got, evidence = attempt('sampler_evidence', lambda: sampler.evidence(transfer_started, transfer_ended))
        if got:
            result['rss_evidence'] = evidence
            def verify_sampler_exit():
                if evidence.get('sampler_alive_after_stop') is not False or evidence.get('errors'):
                    raise RuntimeError('rss_sampler_shutdown_or_measurement_failed')
            attempt('verify_sampler_exit', verify_sampler_exit)
            if rss_path is not None:
                attempt('write_rss_evidence', lambda: save_new(rss_path, evidence))
    if http is not None:
        attempt('http_client_close', lambda: http.client.close())
    result['complete'] = (result['owned_child_waited'] and result['shutdown_receipt'] is not None
                          and not result['errors'])
    return result, first_error


def require_closed_phase(phase, primary, cleanup, secondary, partial):
    if primary is not None or secondary is not None or not cleanup['complete']:
        raise RehearsalPhaseFailure(phase, primary, cleanup, partial) from (
            primary if primary is not None else secondary)
    return cleanup['shutdown_receipt']


def serve(args):
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings
    from peters_mcp.catalog import Catalog
    from peters_mcp.cloudflare import AccessMiddleware
    from peters_mcp.file_config import load_file_service
    from peters_mcp.file_export import load_export_service
    from peters_mcp.history import HistoryAccess
    from peters_mcp.server import create_server
    ref = load_reference()
    root = args.fixture_root
    inspection = args.inspection_only
    catalog = Catalog.from_config(root / 'projects.json')
    history = HistoryAccess(root / 'history.json', catalog=catalog)
    _, files = load_file_service(root / 'file-config.json', catalog, history, inspection_only=inspection)
    exports = load_export_service(root / 'export-config.json', catalog, history, files=files,
                                  inspection_only=inspection, chunked_config_path=root / 'chunked-config.json')
    server = create_server(catalog, history=history, files=files,
                           file_inspection_only=inspection, exports=exports)
    app = server.streamable_http_app(host='127.0.0.1', stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=['127.0.0.1:*'], allowed_origins=['https://synthetic.example.invalid']))
    if exports is not None:
        app = exports.protocol.wrap(app)
    verifier, tokens = ref.signed_verifier()
    app = AccessMiddleware(app, verifier)
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    assert sock.getsockname()[1] not in (8765, 8766)
    instance = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False, lifespan='on'))
    def ready():
        deadline = time.monotonic() + 10
        while not instance.started and time.monotonic() < deadline:
            time.sleep(.01)
        if instance.started:
            # Synthetic, ephemeral JWT only. Never copied into the report.
            save_new(args.ready_file, {'port': sock.getsockname()[1], 'token': tokens(), 'pid': os.getpid(),
                                      'rss_native_before': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
            args.ready_file.chmod(0o600)
            stop_file = args.ready_file.with_suffix('.stop')
            measure_file = args.ready_file.with_suffix('.measure')
            metrics_file = args.ready_file.with_suffix('.metrics.json')
            shutdown_deadline = time.monotonic() + 300
            while not instance.should_exit and time.monotonic() < shutdown_deadline:
                if (measure_file.exists() and not metrics_file.exists()
                        and json.loads(measure_file.read_bytes()) == {'pid': os.getpid(), 'phase': 'before_chunked'}):
                    save_new(metrics_file, {'pid': os.getpid(), 'phase': 'before_chunked',
                        'observed_at_unix': time.time(), 'observed_monotonic': time.monotonic(),
                        'platform': sys.platform,
                        'native_maxrss': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        'native_maxrss_unit': 'bytes' if sys.platform == 'darwin' else 'KiB'})
                if stop_file.exists() and json.loads(stop_file.read_bytes()) == {'pid': os.getpid()}:
                    instance.should_exit = True
                    return
                time.sleep(.02)
            instance.should_exit = True
    threading.Thread(target=ready, daemon=True).start()
    try:
        instance.run(sockets=[sock])
    finally:
        stopped = exports.close() if exports is not None else None
        file_stop = files.close()
        save_new(args.ready_file.with_suffix('.stopped.json'), {'pid': os.getpid(), 'export': stopped, 'files': file_stop,
                 'rss_native_after': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})


def wait_ready(path, child):
    deadline = time.monotonic() + 15
    while not path.exists() and time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError('isolated_child_start_failed')
        time.sleep(.02)
    if not path.exists():
        raise RuntimeError('isolated_child_start_timeout')
    return json.loads(path.read_bytes())


def materialized(http, result, destination):
    assert not result.get('isError'), result
    refs = [item for item in result['content'] if item['type'] == 'resource_link']
    assert len(refs) == 1
    response = http.rpc('resources/read', {'uri': refs[0]['uri']})
    assert response.status_code == 200
    value = response.json()
    assert 'error' not in value, value
    contents = value['result']['contents']
    assert len(contents) == 1 and contents[0]['uri'] == refs[0]['uri']
    body = base64.b64decode(contents[0]['blob'], validate=True)
    with destination.open('xb') as stream:
        stream.write(body)
    return body, refs[0]['uri']


def resident_bytes(pid):
    result = subprocess.run(['/bin/ps', '-o', 'rss=', '-p', str(pid)], text=True,
                            capture_output=True, timeout=.25, check=True)
    value = int(result.stdout.strip()) * 1024
    if value <= 0:
        raise ValueError('invalid_resident_sample')
    return value


def current_resident_baseline(pid, probe=resident_bytes):
    values = []
    for _ in range(3):
        started = time.monotonic()
        rss = probe(pid)
        elapsed = time.monotonic() - started
        if type(rss) is not int or rss <= 0 or elapsed > .05:
            raise RuntimeError('resident_baseline_probe_invalid_or_slow')
        values.append({'started_monotonic': started, 'observed_monotonic': time.monotonic(),
                       'observed_at_unix': time.time(), 'rss_bytes': rss, 'probe_seconds': elapsed})
        time.sleep(.02)
    if max(x['rss_bytes'] for x in values) - min(x['rss_bytes'] for x in values) > 1024 * 1024:
        raise RuntimeError('resident_baseline_not_stable')
    return {'baseline_bytes': min(x['rss_bytes'] for x in values), 'samples': values,
            'maximum_allowed_spread_bytes': 1024 * 1024}


class ResidentSampler:
    """A scheduled20ms measurement whose missing evidence always fails closed."""
    def __init__(self, pid, probe=resident_bytes, interval=.02):
        self.pid, self.probe, self.interval = pid, probe, interval
        self.stop_event = threading.Event()
        self.samples, self.errors = [], []
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self):
        due = time.monotonic()
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                value = self.probe(self.pid)
                finished = time.monotonic()
                if type(value) is not int or value <= 0 or finished - started > .05:
                    raise RuntimeError('resident_probe_invalid_or_slow')
                self.samples.append({'started_monotonic': started, 'observed_monotonic': finished,
                    'observed_at_unix': time.time(), 'rss_bytes': value, 'probe_seconds': finished - started})
            except BaseException as error:
                self.errors.append({'started_monotonic': started, 'failed_monotonic': time.monotonic(),
                    'observed_at_unix': time.time(), 'type': type(error).__name__, 'error': str(error)})
                return
            due += self.interval
            self.stop_event.wait(max(0, due - time.monotonic()))

    def start(self):
        self.thread.start()

    def check_health(self):
        if self.errors or not self.thread.is_alive():
            raise RuntimeError('rss_sampler_failed_during_transfer')

    def stop(self):
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(1)

    def evidence(self, started=None, ended=None):
        samples = list(self.samples)
        gaps = [b['started_monotonic'] - a['started_monotonic'] for a, b in zip(samples, samples[1:])]
        return {'pid': self.pid, 'requested_interval_seconds': self.interval,
                'maximum_allowed_gap_seconds': .05, 'maximum_allowed_probe_seconds': .05,
                'transfer_started_monotonic': started, 'transfer_ended_monotonic': ended,
                'sampler_alive_after_stop': self.thread.is_alive(), 'samples': samples,
                'sample_count': len(samples), 'errors': list(self.errors),
                'maximum_observed_gap_seconds': max(gaps) if gaps else None}

    def validate(self, started, ended, baseline):
        evidence = self.evidence(started, ended)
        samples = evidence['samples']
        inside = [x for x in samples if started <= x['started_monotonic'] <= ended]
        if (evidence['sampler_alive_after_stop'] or evidence['errors'] or len(inside) < 2
                or not samples or samples[0]['started_monotonic'] > started + .05
                or samples[-1]['started_monotonic'] < ended - .05
                or evidence['maximum_observed_gap_seconds'] is None
                or evidence['maximum_observed_gap_seconds'] > .05
                or any(b['started_monotonic'] <= a['started_monotonic'] for a, b in zip(samples, samples[1:]))):
            raise RuntimeError('rss_measurement_incomplete')
        peak = max(x['rss_bytes'] for x in samples)
        extra = max(0, peak - baseline)
        if extra > 128 * 1024 * 1024:
            raise RuntimeError('rss_sampled_extra_limit_exceeded')
        return {'baseline_bytes': baseline, 'peak_bytes': peak, 'extra_bytes': extra,
                'valid_samples_during_transfer': len(inside), 'evidence': evidence}


def native_highwater_bound(baseline_bytes, before_bytes, after_bytes):
    if any(type(x) is not int or x <= 0 for x in (baseline_bytes, before_bytes, after_bytes)):
        raise RuntimeError('native_highwater_measurement_invalid')
    if after_bytes < before_bytes:
        raise RuntimeError('native_highwater_moved_backwards')
    upper = max(0, after_bytes - baseline_bytes)
    if upper > 128 * 1024 * 1024:
        raise RuntimeError('native_highwater_above_current_baseline_limit_exceeded')
    return {'current_resident_baseline_bytes': baseline_bytes,
            'native_highwater_before_bytes': before_bytes, 'native_highwater_after_bytes': after_bytes,
            'historical_highwater_delta_bytes_diagnostic_only': max(0, after_bytes - before_bytes),
            'conservative_lifetime_peak_above_current_baseline_bytes': upper,
            'not_a_substitute_for_valid_timed_samples': True}


def database_metadata(root):
    path = root / 'control/file-jobs.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        schema = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        ledger = db.execute('SELECT key,generation,valid FROM ledger ORDER BY key').fetchall()
        return {'user_version': db.execute('PRAGMA user_version').fetchone()[0],
                'schema_sha256': hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
                'ledger_sha256': hashlib.sha256(json.dumps(ledger, sort_keys=True).encode()).hexdigest()}


def exercise(args):
    ref = load_reference()
    report = {'kind': 'isolated_authenticated_loopback_sdk_only', 'native_chatgpt_acceptance': False,
              'source': str(args.source), 'phases': [],
              'independent_receiver': receiver_pin(args.source)}
    loader_path = args.loader or args.source / 'tools/native_receiver_loader.py'
    loader, loader_record = reviewed_loader(args.source, loader_path, args.expected_loader_sha256)
    report['loader'] = loader_record
    with owned_fixture_directory() as root:
        fixture = root / 'fixture'
        fixture.mkdir()
        ref.fixture(fixture)
        policy = {'version': 1, 'enabled': True, 'max_file_bytes': 30_000_000,
                  'min_free_bytes': 1_073_741_824, 'protocol_version': 'raw-parts-v1'}
        save_new(fixture / 'chunked-config.json', policy)
        (fixture / 'chunked-config.json').chmod(0o600)
        fixture_builder = args.fixture_builder or args.source / 'tools/generate_progressive_fixture.py'
        generator, generator_record = source_module(fixture_builder, 'fixed_fixture_generator')
        generated = [generator.make_zip(fixture / 'repo/source-30mb.zip', 30_000_000),
                     generator.make_zip(fixture / 'repo/small.zip', 8192)]
        measured_sources = {Path(item['path']).name: source_record(item['path']) for item in generated}
        for item in generated:
            actual = measured_sources[Path(item['path']).name]
            assert (actual['bytes'], actual['sha256']) == (item['bytes'], item['sha256'])
        fixture_manifest = {'purpose': 'Independent generated source measurements; not native receipt',
                            'generator': generator_record, 'files': generated,
                            'independent_source_measurements': measured_sources}
        save_new(fixture / 'source-manifest.json', fixture_manifest)
        report['fixture_manifest'] = fixture_manifest
        report['fixture_manifest_file'] = source_record(fixture / 'source-manifest.json')
        baseline = ref.database_rows(fixture)
        baseline_metadata = database_metadata(fixture)
        for phase in ('candidate', 'restart', 'rollback'):
            ready = root / (phase + '.ready.json')
            log_path = args.output.parent / (args.output.stem + '-' + phase + '.log')
            bundle_source = args.rollback_source if phase == 'rollback' and args.rollback_source else args.source
            command = [sys.executable, '-B', str(Path(__file__).resolve()), '--source', str(bundle_source),
                       '--fixture-root', str(fixture), '--ready-file', str(ready)]
            if phase == 'rollback':
                command.append('--inspection-only')
            with log_path.open('xb') as log:
                child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, cwd=args.source)
                owned_pid = child.pid
                http = None
                sampler = None
                primary_error = None
                step = None
                transfer_started = transfer_ended = None
                rss_evidence_path = args.output.with_name(args.output.stem + '-' + phase + '-rss.json')
                try:
                    state = wait_ready(ready, child)
                    http = ref.HTTP(state['port'], state['token'])
                    assert http.rpc('tools/list', token='').status_code == 401
                    listing = http.rpc('tools/list').json()['result']['tools']
                    names = {item['name'] for item in listing}
                    projects = http.tool('list_projects')
                    step = {'phase': phase, 'pid': state['pid'], 'port': state['port'],
                            'bundle_source': str(bundle_source),
                            'platform': sys.platform,
                            'native_maxrss_unit': 'bytes' if sys.platform == 'darwin' else 'KiB',
                            'native_maxrss_at_startup': state['rss_native_before'],
                            'unauthenticated_status': 401, 'baseline_rows': len(baseline)}
                    if phase == 'rollback':
                        assert not (TOOLS & names)
                        assert 'original_export' not in projects
                        step['chunked_and_export_disabled'] = True
                    else:
                        assert TOOLS <= names
                        assert projects['original_export']['max_original_bytes'] == 12_659_780
                        assert projects['chunked_export']['configured_max_file_bytes'] == 30_000_000
                        window = projects['original_export']
                        common = {'project_id': 'repo', 'worktree_id': 'main',
                                  'service_instance_id': window['service_instance_id'],
                                  'request_window_id': window['request_window_id']}
                        old = http.raw_tool('export_file', {**common, 'path': 'small.zip', 'request_key': phase + '-legacy',
                            'expected_sha256': measured_sources['small.zip']['sha256']})
                        for _ in range(100):
                            old_meta = json.loads(old['content'][0]['text'])
                            if old_meta['state'] == 'ready':
                                break
                            time.sleep(.02)
                            old = http.raw_tool('get_file_export_status', {'export_id': old_meta['export_id']})
                        old_body, _ = materialized(http, old, root / (phase + '-legacy.zip'))
                        assert hashlib.sha256(old_body).digest() == hashlib.sha256((fixture / 'repo/small.zip').read_bytes()).digest()
                        step['legacy_resource_shape_and_bytes'] = True
                        if phase == 'candidate':
                            save_new(ready.with_suffix('.measure'), {'pid': child.pid, 'phase': 'before_chunked'})
                            metrics_path = ready.with_suffix('.metrics.json')
                            deadline = time.monotonic() + 5
                            while not metrics_path.exists() and time.monotonic() < deadline:
                                time.sleep(.01)
                            measured = json.loads(metrics_path.read_bytes())
                            assert measured['pid'] == child.pid and measured['phase'] == 'before_chunked'
                            step['server_native_maxrss_before_chunked'] = measured
                            current_baseline = current_resident_baseline(child.pid)
                            baseline_rss = current_baseline['baseline_bytes']
                            step['current_resident_baseline'] = current_baseline
                            sampler = ResidentSampler(child.pid)
                            sampler.start()
                            transfer_started = time.monotonic()
                            accepted = http.tool('prepare_chunked_export', {**common, 'path': 'source-30mb.zip',
                                'request_key': 'first-chunked',
                                'expected_sha256': measured_sources['source-30mb.zip']['sha256']})
                            export_id = accepted['export_id']
                            sampler.check_health()
                            for _ in range(200):
                                status = http.tool('get_chunked_export_status', {'export_id': export_id})
                                if status['state'] == 'ready':
                                    break
                                time.sleep(.025)
                            assert status['state'] == 'ready'
                            planned = http.tool('get_chunked_export_plan', {'export_id': export_id})
                            assert planned['state'] == 'ready' and planned['export_id'] == export_id
                            plan = planned['plan']
                            assert plan['total_bytes'] == 30_000_000 and plan['part_count'] == 4
                            assert plan['total_sha256'] == measured_sources['source-30mb.zip']['sha256']
                            assert plan['receiver_asset'] == report['independent_receiver']['pin']
                            native = root / 'local-receiver'
                            native.mkdir(mode=0o700)
                            output = native / 'owned-output'
                            output.mkdir(mode=0o700)
                            code, _ = materialized(http, http.raw_tool('materialize_chunked_export_receiver',
                                                          {'export_id': export_id}), native / 'native_chunk_receiver.py')
                            assert hashlib.sha256(code).hexdigest() == report['independent_receiver']['pin']['sha256']
                            inputs_stat = native.stat()
                            module, loaded = loader.load_verified_receiver(
                                str(native / 'native_chunk_receiver.py'), str(native),
                                [inputs_stat.st_dev, inputs_stat.st_ino],
                                report['independent_receiver']['pin'], plan['receiver_asset'])
                            step['helper_load_evidence'] = loaded
                            assert loaded['native_receiver_root_bound'] is True
                            sampler.check_health()
                            receiver = module.NativeChunkReceiver.start(plan, output, input_root=native, target_name='received.zip')
                            evidence = []
                            for part in plan['parts']:
                                path = native / ('actual-received-%d.bin' % part['index'])
                                body, uri = materialized(http, http.raw_tool('materialize_chunked_export_part',
                                    {'export_id': export_id, 'part_index': part['index']}), path)
                                assert len(body) == part['bytes'] and hashlib.sha256(body).hexdigest() == part['sha256']
                                receiver.ingest(part['index'], path)
                                sampler.check_health()
                                with (fixture / 'repo/source-30mb.zip').open('rb') as original:
                                    original.seek(part['offset'])
                                    assert original.read(part['bytes']) == body
                                evidence.append({'index': part['index'], 'actual_path': str(path),
                                    'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                                    'matches_independent_source_range': True})
                                if part['index'] == 0:
                                    duplicate = receiver.ingest(0, path)
                                    assert duplicate['appended_bytes'] == 0
                                    receiver = module.NativeChunkReceiver.resume(receiver.session_path, plan, input_root=native)
                            finished = receiver.finish()
                            final = output / 'received.zip'
                            assert final.stat().st_size == 30_000_000
                            digest = hashlib.sha256(final.read_bytes()).hexdigest()
                            assert digest == plan['total_sha256'] == measured_sources['source-30mb.zip']['sha256']
                            with zipfile.ZipFile(final) as archive:
                                assert archive.testzip() is None
                            cancelled = http.tool('cancel_chunked_export', {'export_id': export_id})
                            for _ in range(100):
                                if cancelled.get('resources_released') is True:
                                    break
                                time.sleep(.025)
                                cancelled = http.tool('cancel_chunked_export', {'export_id': export_id})
                            assert cancelled['resources_released'] is True
                            transfer_ended = time.monotonic()
                            sampler.stop()
                            timed_rss = sampler.validate(transfer_started, transfer_ended, baseline_rss)
                            step.update(plan_sha256=plan['plan_sha256'], parts=evidence,
                                        whole_sha256=digest, final_status=finished,
                                        same_plan_duplicate_and_resume=True, resources_released=True,
                                        server_rss_baseline_bytes=baseline_rss,
                                        server_rss_peak_bytes=timed_rss['peak_bytes'],
                                        server_rss_extra_bytes=timed_rss['extra_bytes'],
                                        server_rss_samples=timed_rss['evidence']['sample_count'],
                                        sample_interval_seconds=.02, timed_rss_evidence=timed_rss['evidence'])
                    assert ref.database_rows(fixture) == baseline
                    assert database_metadata(fixture) == baseline_metadata
                    step['all_baseline_rows_preserved'] = True
                    step['schema_and_ledger_preserved'] = True
                    report['phases'].append(step)
                except BaseException as error:
                    primary_error = error
                finally:
                    cleanup, secondary_error = close_owned_rehearsal(child, owned_pid, ready,
                        http=http, sampler=sampler, rss_path=rss_evidence_path,
                        transfer_started=transfer_started, transfer_ended=transfer_ended)
                    closed = require_closed_phase(phase, primary_error, cleanup, secondary_error, step)
                report['phases'][-1]['owned_cleanup'] = cleanup
                report['phases'][-1]['shutdown'] = closed
                unit = report['phases'][-1]['native_maxrss_unit']
                multiplier = 1 if unit == 'bytes' else 1024
                report['phases'][-1]['server_native_maxrss_after_bytes'] = closed['rss_native_after'] * multiplier
                if phase == 'candidate':
                    before = report['phases'][-1]['server_native_maxrss_before_chunked']['native_maxrss'] * multiplier
                    report['phases'][-1]['server_native_maxrss_before_chunked_bytes'] = before
                    report['phases'][-1]['server_native_maxrss_delta_bytes'] = max(0, closed['rss_native_after'] * multiplier - before)
                    report['phases'][-1]['native_highwater_resource_bound'] = native_highwater_bound(
                        report['phases'][-1]['server_rss_baseline_bytes'], before,
                        closed['rss_native_after'] * multiplier)
        report['result'] = 'PASS'
        save_new(args.output, report)
    print(json.dumps({'result': report['result'], 'report': str(args.output),
                      'native_chatgpt_acceptance': False, 'phases': len(report['phases'])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--fixture-builder', type=Path,
                        help='Explicit synthetic fixture generator when testing a frozen runtime package.')
    parser.add_argument('--rollback-source', type=Path,
                        help='Explicit frozen compatible rollback payload for the rollback phase.')
    parser.add_argument('--loader', type=Path,
                        help='Explicit canonical reviewed loader (must match frozen manifest when present).')
    parser.add_argument('--expected-loader-sha256',
                        help='Independent reviewed loader SHA, checked before executing its exact source buffer.')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fixture-root', type=Path)
    parser.add_argument('--ready-file', type=Path)
    parser.add_argument('--inspection-only', action='store_true')
    args = parser.parse_args()
    args.source = args.source.resolve()
    if args.rollback_source is not None:
        args.rollback_source = args.rollback_source.resolve()
    if args.fixture_builder is not None:
        args.fixture_builder = args.fixture_builder.resolve()
    if args.loader is not None:
        args.loader = args.loader.resolve()
    sys.path.insert(0, str(args.source))
    if args.fixture_root:
        serve(args)
    else:
        if args.output is None:
            parser.error('--output is required for rehearsal')
        if args.expected_loader_sha256 is None:
            parser.error('--expected-loader-sha256 is required for rehearsal')
        args.output = args.output.absolute()
        try:
            exercise(args)
        except BaseException as error:
            failure = args.output.with_name(args.output.stem + '-failure.json')
            diagnostic = {'result': 'FAIL', 'native_chatgpt_acceptance': False,
                'source': str(args.source), **exception_record(error),
                'retained_fixture_root': getattr(error, 'retained_fixture_root', None)}
            if isinstance(error, RehearsalPhaseFailure):
                diagnostic.update(primary_error=error.primary, cleanup=error.cleanup,
                                  partial_phase=error.partial_phase)
            try:
                if failure.exists():
                    raise FileExistsError('failure_record_already_exists')
                save_new(failure, diagnostic)
            except BaseException as write_error:
                diagnostic['failure_record_write_error'] = exception_record(write_error)
                try:
                    print(json.dumps(diagnostic), file=sys.stderr)
                except BaseException:
                    pass  # Original phase failure is still re-raised below.
            raise


if __name__ == '__main__':
    main()
