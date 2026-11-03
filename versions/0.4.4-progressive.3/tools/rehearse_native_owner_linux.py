#!/usr/bin/env python3
"""Prepare a closed synthetic image context; run only after exact-context review.

This is a development-only Linux UID0-input/UID1000-receiver test. It never
connects production or qualifies native ChatGPT receipt. `prepare` does not
pull/build/run Docker; `run` requires both independently reviewed file hashes
and an explicit --apply-reviewed-context flag.
"""
import argparse
import ast
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import time
import traceback
from types import ModuleType

MAX_CONTEXT = 100_000_000
BASE_PATTERN = r'docker\.io/library/python@sha256:[a-f0-9]{64}'
RUNTIME_FLAGS = ['--user', '1000:1000', '--read-only', '--network', 'none',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                 '--pids-limit', '64', '--memory', '512m', '--tmpfs',
                 '/tmp:rw,nosuid,nodev,noexec,size=2147483648,mode=1777']
MARKER = 'io.peters.native-owner-run'
WORKDIR_INSTRUCTIONS = ['WORKDIR /opt/host-input', 'WORKDIR /opt/runner']
CONTEXT_NAMES = {'small.zip', 'source-30mb.zip', 'native_chunk_receiver.py',
                 'old_native_chunk_receiver.py', 'native_receiver_loader.py',
                 'native_owner_linux_runner.py', 'small-part-0000.bin',
                 'part-0000.bin', 'part-0001.bin', 'part-0002.bin', 'part-0003.bin',
                 'expected.json', 'Dockerfile'}


def stamp(v):
    return (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns,
            v.st_nlink, v.st_uid, v.st_gid, v.st_mode)


def read_regular(path, maximum=MAX_CONTEXT):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('linked_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > maximum
                or before.st_mode & 0o022):
            raise ValueError('unsafe_input')
        result = bytearray()
        while len(result) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not block:
                break
            result.extend(block)
        if (stamp(before) != stamp(os.fstat(fd))
                or stamp(before) != stamp(path.stat(follow_symlinks=False))
                or len(result) != before.st_size):
            raise ValueError('input_changed')
        return bytes(result)
    finally:
        os.close(fd)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path, raw=None):
    raw = read_regular(path) if raw is None else raw
    return {'path': str(Path(path).absolute()), 'bytes': len(raw), 'sha256': digest(raw)}


def json_new(path, value):
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')


def binary_new(path, raw):
    with path.open('xb') as f:
        f.write(raw)
    path.chmod(0o644)


def closed_tar(buffers):
    """A deterministic archive composed only of already verified immutable bytes."""
    if set(buffers) != CONTEXT_NAMES:
        raise ValueError('unexpected_tar_entry')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(buffers.items()):
            if type(raw) is not bytes:
                raise ValueError('tar_requires_immutable_bytes')
            item = tarfile.TarInfo(name)
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = item.linkname = ''
            item.mode, item.size, item.type = 0o644, len(raw), tarfile.REGTYPE
            archive.addfile(item, io.BytesIO(raw))
    return output.getvalue()


def checked_pin(source, expected_helper_sha256):
    helper = read_regular(source / 'peters_mcp/native_chunk_receiver.py', 65536)
    if digest(helper) != expected_helper_sha256:
        raise ValueError('helper_differs_from_explicit_independent_pin')
    pin_path = source / 'peters_mcp/transport_asset.py'
    pin_raw = read_regular(pin_path, 65536)
    wanted = {'RECEIVER_ASSET_ID', 'RECEIVER_NAME', 'RECEIVER_BYTES', 'RECEIVER_SHA256'}
    found = {}
    for node in ast.parse(pin_raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                found[name] = ast.literal_eval(node.value)
    if set(found) != wanted:
        raise ValueError('invalid_independent_pin_source')
    pin = {'asset_id': found['RECEIVER_ASSET_ID'], 'name': found['RECEIVER_NAME'],
           'bytes': found['RECEIVER_BYTES'], 'sha256': found['RECEIVER_SHA256']}
    if pin != {'asset_id': 'native-chunk-receiver-v1', 'name': 'native_chunk_receiver.py',
               'bytes': len(helper), 'sha256': digest(helper)}:
        raise ValueError('asset_source_pin_mismatch')
    return helper, pin, record(pin_path, pin_raw)


def prepare(args):
    if re.fullmatch(BASE_PATTERN, args.base_reference) is None:
        raise ValueError('official_python_digest_required')
    helper, pin, pin_source = checked_pin(args.source, args.expected_helper_sha256)
    old, old_pin, old_pin_source = checked_pin(args.old_source, args.expected_old_helper_sha256)
    loader_path = args.source / 'tools/native_receiver_loader.py'
    loader = read_regular(loader_path, 65536)
    if digest(loader) != args.expected_loader_sha256:
        raise ValueError('loader_differs_from_explicit_independent_pin')
    builder_path = args.source / 'tools/generate_progressive_fixture.py'
    builder = read_regular(builder_path, 65536)
    if digest(builder) != args.expected_fixture_builder_sha256:
        raise ValueError('fixture_builder_differs_from_explicit_pin')
    runner_path = Path(__file__).with_name('native_owner_linux_runner.py')
    runner = read_regular(runner_path, 65536)
    if args.output.parent.resolve() != args.output.parent or args.output.exists():
        raise ValueError('output_must_be_new_under_unlinked_parent')
    args.output.mkdir(mode=0o700)
    context = args.output / 'context'
    context.mkdir(mode=0o700)
    generator = ModuleType('verified_fixture_generator')
    generator.__file__ = str(builder_path)
    exec(compile(builder, str(builder_path), 'exec', dont_inherit=True), generator.__dict__)
    generated = {}
    for name, size in [('small.zip', 8192), ('source-30mb.zip', 30_000_000)]:
        item = generator.make_zip(context / name, size)
        item['name'] = name
        actual = record(context / name)
        assert (item['bytes'], item['sha256']) == (actual['bytes'], actual['sha256'])
        generated[name] = item
    content = {'native_chunk_receiver.py': helper, 'old_native_chunk_receiver.py': old,
               'native_receiver_loader.py': loader, 'native_owner_linux_runner.py': runner}
    for name, raw in content.items():
        binary_new(context / name, raw)
    with (context / 'small.zip').open('rb') as f:
        binary_new(context / 'small-part-0000.bin', f.read())
    with (context / 'source-30mb.zip').open('rb') as f:
        for index in range(4):
            data = f.read(8_000_000)
            assert len(data) == (8_000_000 if index < 3 else 6_000_000)
            binary_new(context / ('part-%04d.bin' % index), data)
        assert not f.read(1)
    run_id = secrets.token_hex(12)
    file_records = {}
    for path in sorted(context.iterdir()):
        v = record(path)
        file_records[path.name] = {'bytes': v['bytes'], 'sha256': v['sha256']}
    expected = {'run_id': run_id, 'kind': 'synthetic Linux ownership compatibility only',
                'receiver_asset': pin, 'old_receiver_asset': old_pin,
                'loader_sha256': digest(loader), 'fixtures': generated, 'files': file_records}
    json_new(context / 'expected.json', expected)
    copies = []
    for path in sorted(context.iterdir()):
        directory = '/opt/runner/' if path.name == 'native_owner_linux_runner.py' else '/opt/host-input/'
        copies.append('COPY --chown=0:0 --chmod=0644 ' + path.name + ' ' + directory + path.name)
    dockerfile = ('FROM ' + args.base_reference + '\n' + '\n'.join(WORKDIR_INSTRUCTIONS + copies)
                  + '\nUSER 1000:1000\nCMD ["python", "-B", "/opt/runner/native_owner_linux_runner.py"]\n')
    binary_new(context / 'Dockerfile', dockerfile.encode('ascii'))
    entries, buffers = [], {}
    for path in sorted(context.iterdir()):
        raw = read_regular(path)
        buffers[path.name] = raw
        v = record(path, raw)
        entries.append({'path': path.name, 'bytes': v['bytes'], 'sha256': v['sha256']})
    if sum(item['bytes'] for item in entries) > MAX_CONTEXT:
        raise ValueError('context_too_large')
    manifest = {'kind': 'closed_synthetic_derived_image_context', 'run_id': run_id,
        'base_reference': args.base_reference, 'source': str(args.source), 'old_source': str(args.old_source),
        'independent_receiver_asset': pin, 'independent_old_receiver_asset': old_pin,
        'independent_pin_source': pin_source, 'independent_old_pin_source': old_pin_source,
        'loader': record(loader_path, loader), 'fixture_builder': record(builder_path, builder),
        'runner': record(runner_path, runner), 'total_bytes': sum(x['bytes'] for x in entries),
        'files': entries, 'native_chatgpt_acceptance': False}
    json_new(args.output / 'context-manifest.json', manifest)
    archive = closed_tar(buffers)
    recipe = {'kind': 'review_required_before_build_or_run', 'run_id': run_id,
        'base_reference': args.base_reference, 'runtime_flags': RUNTIME_FLAGS,
        'required_image_user': '1000:1000', 'required_working_directory': '/opt/runner',
        'input_root': '/opt/host-input',
        'output_root_parent': '/tmp', 'no_host_mounts_socket_ports': True,
        'dockerfile_sha256': digest(dockerfile.encode('ascii')),
        'context_manifest_sha256': digest(read_regular(args.output / 'context-manifest.json')),
        'builder_input': {'format': 'deterministic-ustar-regular-files-only',
                          'bytes': len(archive), 'sha256': digest(archive),
                          'delivery': 'same validated in-memory tar buffer to docker build stdin'},
        'derived_image_not_built': True}
    json_new(args.output / 'run-recipe.json', recipe)
    print(json.dumps({'prepared': str(args.output), 'files': len(entries),
        'context_manifest_sha256': recipe['context_manifest_sha256'],
        'recipe_sha256': digest(read_regular(args.output / 'run-recipe.json')),
        'total_bytes': manifest['total_bytes'], 'image_built_or_run': False}))


def command_record(args, output, timeout, *, input_bytes=None):
    started = time.monotonic()
    input_record = None
    if input_bytes is not None:
        if type(input_bytes) is not bytes:
            raise ValueError('builder_input_must_be_immutable_bytes')
        input_record = {'bytes': len(input_bytes), 'sha256': digest(input_bytes),
                        'kind': 'exact verified tar buffer submitted to subprocess stdin'}
    try:
        p = subprocess.run(args, capture_output=True, text=input_bytes is None,
                           input=input_bytes, timeout=timeout)
        result = {'command': args, 'elapsed_seconds': time.monotonic() - started,
                  'exit_code': p.returncode,
                  'stdout': p.stdout.decode(errors='replace') if isinstance(p.stdout, bytes) else p.stdout,
                  'stderr': p.stderr.decode(errors='replace') if isinstance(p.stderr, bytes) else p.stderr}
    except subprocess.TimeoutExpired as e:
        result = {'command': args, 'elapsed_seconds': time.monotonic() - started, 'error': 'timeout',
                  'stdout': e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout,
                  'stderr': e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr}
    if input_record is not None:
        result['stdin_buffer'] = input_record
    json_new(output, result)
    if result.get('exit_code') != 0:
        raise RuntimeError('docker_command_failed:' + output.name)
    return result['stdout']


def verified_context_buffers(root, expected_manifest, expected_recipe):
    manifest_raw = read_regular(root / 'context-manifest.json')
    recipe_raw = read_regular(root / 'run-recipe.json')
    if digest(manifest_raw) != expected_manifest or digest(recipe_raw) != expected_recipe:
        raise ValueError('reviewed_context_or_recipe_mismatch')
    manifest, recipe = json.loads(manifest_raw), json.loads(recipe_raw)
    if (manifest['run_id'] != recipe['run_id'] or manifest['base_reference'] != recipe['base_reference']
            or recipe['runtime_flags'] != RUNTIME_FLAGS
            or recipe.get('required_working_directory') != '/opt/runner'
            or recipe['context_manifest_sha256'] != expected_manifest
            or re.fullmatch(BASE_PATTERN, manifest['base_reference']) is None
            or re.fullmatch('[a-f0-9]{24}', manifest['run_id']) is None):
        raise ValueError('invalid_reviewed_recipe')
    entries = {i['path']: i for i in manifest['files']}
    context = root / 'context'
    if set(entries) != CONTEXT_NAMES or set(entries) != {p.name for p in context.iterdir()}:
        raise ValueError('unexpected_context_file')
    buffers = {}
    for name, item in entries.items():
        raw = read_regular(context / name)
        if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
            raise ValueError('context_file_changed')
        buffers[name] = raw
    if sum(i['bytes'] for i in entries.values()) != manifest['total_bytes'] or manifest['total_bytes'] > MAX_CONTEXT:
        raise ValueError('invalid_context_total')
    lines = buffers['Dockerfile'].decode('ascii').splitlines()
    expected_copies = []
    for name in sorted(set(entries) - {'Dockerfile'}):
        directory = '/opt/runner/' if name == 'native_owner_linux_runner.py' else '/opt/host-input/'
        expected_copies.append('COPY --chown=0:0 --chmod=0644 ' + name + ' ' + directory + name)
    required = ['FROM ' + manifest['base_reference']] + WORKDIR_INSTRUCTIONS + expected_copies + [
        'USER 1000:1000', 'CMD ["python", "-B", "/opt/runner/native_owner_linux_runner.py"]']
    if lines != required or digest(buffers['Dockerfile']) != recipe['dockerfile_sha256']:
        raise ValueError('dockerfile_not_fixed_allowlist')
    archive = closed_tar(buffers)
    wanted_archive = recipe['builder_input']
    if (wanted_archive['format'] != 'deterministic-ustar-regular-files-only'
            or wanted_archive['bytes'] != len(archive) or wanted_archive['sha256'] != digest(archive)):
        raise ValueError('reviewed_tar_input_mismatch')
    return manifest, recipe, archive


def verify_prepared(root, expected_manifest, expected_recipe):
    manifest, recipe, _ = verified_context_buffers(root, expected_manifest, expected_recipe)
    return manifest, recipe


def cleanup_own_container(cid, run_id, runroot):
    """Only the exact ID and nonce we created may be stopped/removed."""
    result = {'container_id': cid, 'state': 'pending', 'records': []}
    try:
        def call(arguments, timeout):
            p = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
            row = {'command': arguments, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
            result['records'].append(row)
            return p
        p = call(['docker', 'container', 'inspect', cid], 30)
        if p.returncode != 0:
            return result
        state = json.loads(p.stdout)[0]
        if state['Id'] != cid or state['Config']['Labels'].get(MARKER) != run_id:
            result['state'] = 'identity_unverified'
            return result
        if state['State']['Running']:
            p = call(['docker', 'stop', '--time', '10', cid], 20)
            if p.returncode != 0:
                return result
        p = call(['docker', 'container', 'inspect', cid], 30)
        if p.returncode != 0:
            return result
        state = json.loads(p.stdout)[0]
        if (state['Id'] != cid or state['Config']['Labels'].get(MARKER) != run_id
                or state['State']['Running']):
            return result
        p = call(['docker', 'rm', cid], 30)
        if p.returncode == 0:
            result['state'] = 'removed'
        return result
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error))
        return result
    finally:
        json_new(runroot / 'cleanup.json', result)


def run(args):
    if not args.apply_reviewed_context:
        raise ValueError('explicit_reviewed_context_apply_required')
    manifest, recipe, build_input = verified_context_buffers(
        args.prepared, args.expected_manifest_sha256, args.expected_recipe_sha256)
    runroot = args.prepared / 'run'
    runroot.mkdir(mode=0o700)
    run_id = manifest['run_id']
    tag = 'peters-native-owner-test:' + run_id
    name = 'peters-native-owner-' + run_id
    cid = None
    report = {'kind': 'actual_linux_cross_uid_development_test', 'run_id': run_id,
              'native_chatgpt_acceptance': False, 'context_manifest_sha256': args.expected_manifest_sha256,
              'recipe_sha256': args.expected_recipe_sha256, 'runtime_flags': RUNTIME_FLAGS,
              'base_reference': manifest['base_reference'],
              'builder_stdin': {'bytes': len(build_input), 'sha256': digest(build_input),
                                'source': 'same verified closed tar memory buffer'}}
    try:
        binary_new(runroot / 'builder-stdin.tar', build_input)
        base = command_record(['docker', 'image', 'inspect', manifest['base_reference']],
                              runroot / 'base-inspect.json', 30)
        base = json.loads(base)[0]
        assert base['Os'] == 'linux' and base['Architecture'] in ('arm64', 'amd64')
        report['base_image_id'] = base['Id']
        command_record(['docker', 'build', '--pull=false', '--network=none', '--tag', tag, '-'],
                       runroot / 'build.json', 180, input_bytes=build_input)
        inspect = json.loads(command_record(['docker', 'image', 'inspect', tag],
                             runroot / 'derived-image-inspect.json', 30))[0]
        image = inspect['Id']
        assert re.fullmatch('sha256:[a-f0-9]{64}', image) and inspect['Config']['User'] == '1000:1000'
        assert inspect['Config'].get('WorkingDir') == '/opt/runner'
        report.update(derived_image_id=image, derived_image_tag=tag,
                      derived_image_size_bytes=inspect['Size'])
        created = command_record(['docker', 'create', '--name', name, '--label', MARKER + '=' + run_id]
                                 + RUNTIME_FLAGS + [image], runroot / 'create.json', 30).strip()
        assert re.fullmatch('[a-f0-9]{64}', created)
        cid = created
        state = json.loads(command_record(['docker', 'container', 'inspect', cid],
                          runroot / 'container-before.json', 30))[0]
        config, host = state['Config'], state['HostConfig']
        assert config['User'] == '1000:1000' and config['Labels'][MARKER] == run_id
        assert config.get('WorkingDir') == '/opt/runner'
        assert host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none'
        assert host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and not host['Privileged']
        assert host['Memory'] == 536870912 and host['PidsLimit'] == 64
        assert host['SecurityOpt'] == ['no-new-privileges']
        assert not host.get('Binds') and not host.get('PortBindings') and not config.get('Volumes')
        assert host['Tmpfs'] == {'/tmp': RUNTIME_FLAGS[-1].split(':', 1)[1]}
        assert not state.get('Mounts') or all(x['Type'] == 'tmpfs' and x['Destination'] == '/tmp' for x in state['Mounts'])
        output = command_record(['docker', 'start', '--attach', cid], runroot / 'start.json', 180)
        final = json.loads(command_record(['docker', 'container', 'inspect', cid],
                          runroot / 'container-after.json', 30))[0]
        assert final['Id'] == cid and final['Config']['Labels'][MARKER] == run_id
        report['container_state'] = final['State']
        assert not final['State']['Running'] and not final['State']['OOMKilled'] and final['State']['ExitCode'] == 0
        rows = [x[len('OWNER_TEST_RESULT '):] for x in output.splitlines() if x.startswith('OWNER_TEST_RESULT ')]
        assert len(rows) == 1
        outcome = json.loads(rows[0])
        assert outcome['result'] == 'PASS' and outcome['run_id'] == run_id
        assert outcome['old_receiver_reproduced']['error'] == 'unsafe_file'
        assert [x['bytes'] for x in outcome['runs']] == [8192, 30_000_000]
        report.update(result='PASS', actual_test=outcome)
    except BaseException as error:
        report.update(result='FAIL', error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
        raise
    finally:
        if cid is not None:
            cleanup = cleanup_own_container(cid, run_id, runroot)
            report['own_container_cleanup'] = cleanup['state']
            report['own_container_removed'] = cleanup['state'] == 'removed'
            if report.get('result') == 'PASS' and cleanup['state'] != 'removed':
                report['result'] = 'TEST_PASS_CLEANUP_PENDING'
        report['derived_image_retained_for_review'] = report.get('derived_image_id')
        json_new(runroot / 'report.json', report)
    if report['result'] != 'PASS':
        raise RuntimeError('linux_test_not_fully_closed:' + report['result'])
    print(json.dumps({'result': report['result'], 'report': str(runroot / 'report.json'),
                      'native_chatgpt_acceptance': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare', help='Create only closed context and manifest; no Docker actions')
    for name in ('source', 'old-source', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('base-reference', 'expected-helper-sha256', 'expected-old-helper-sha256',
                 'expected-loader-sha256', 'expected-fixture-builder-sha256'):
        p.add_argument('--' + name, required=True)
    q = sub.add_parser('run', help='Build/run exact reviewed context, only with explicit approval flag')
    q.add_argument('--prepared', type=Path, required=True)
    q.add_argument('--expected-manifest-sha256', required=True)
    q.add_argument('--expected-recipe-sha256', required=True)
    q.add_argument('--apply-reviewed-context', action='store_true', required=True)
    args = parser.parse_args()
    if args.action == 'prepare':
        args.source = args.source.absolute()
        args.old_source = args.old_source.absolute()
        args.output = args.output.absolute()
        prepare(args)
    else:
        args.prepared = args.prepared.absolute()
        run(args)


if __name__ == '__main__':
    main()
