"""Inert-fixture Linux cross-UID assertions, run only inside the reviewed image."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import struct
import sys
import tempfile
import traceback
from types import ModuleType
import zipfile
import zlib

INPUTS = Path('/opt/host-input')
RUNNER = Path('/opt/runner')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def facts(path):
    v = path.stat(follow_symlinks=False)
    return {'path': str(path), 'dev': v.st_dev, 'ino': v.st_ino,
            'bytes': v.st_size, 'uid': v.st_uid, 'gid': v.st_gid,
            'mode': oct(stat.S_IMODE(v.st_mode)), 'nlink': v.st_nlink,
            'regular': stat.S_ISREG(v.st_mode), 'symlink': stat.S_ISLNK(v.st_mode)}


def checked_root_input(path, expected):
    f = facts(path)
    assert f['uid'] == f['gid'] == 0 and f['mode'] == '0o644' and f['nlink'] == 1
    assert f['regular'] and not f['symlink'] and f['bytes'] == expected['bytes']
    f['sha256'] = digest(path)
    assert f['sha256'] == expected['sha256']
    assert not os.access(path, os.W_OK), 'UID1000 must not be able to alter root input'
    return f


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def plan_for(expected, asset, part_names):
    parts = []
    for index, name in enumerate(part_names):
        item = expected['files'][name]
        parts.append({'index': index, 'offset': index * 8_000_000,
                      'bytes': item['bytes'], 'sha256': item['sha256'],
                      'resource_name': name})
    source = expected['fixtures']['small.zip' if len(part_names) == 1 else 'source-30mb.zip']
    plan = {'protocol_version': 'raw-parts-v1', 'service_instance_id': '1' * 32,
            'export_id': '2' * 32, 'source': {'project_id': 'synthetic', 'worktree_id': 'main',
                                          'path': source['name']},
            'capture_version_sha256': '3' * 64, 'total_bytes': source['bytes'],
            'total_sha256': source['sha256'], 'part_max_bytes': 8_000_000,
            'part_count': len(parts), 'parts': parts, 'receiver_asset': asset,
            'expires_at_unix': 1}
    plan['plan_sha256'] = hashlib.sha256(canonical(plan)).hexdigest()
    return plan


def decode_fixed_png(data, expected_sha):
    """Full decoding for this fixed8x8 RGBA/filter0 fixture; not a generic viewer."""
    assert hashlib.sha256(data).hexdigest() == expected_sha
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    position, chunks, compressed = 8, [], bytearray()
    header = None
    while position < len(data):
        assert position + 12 <= len(data)
        length = struct.unpack('>I', data[position:position + 4])[0]
        assert length <= 4096 and position + length + 12 <= len(data)
        kind = data[position + 4:position + 8]
        body = data[position + 8:position + 8 + length]
        crc = struct.unpack('>I', data[position + 8 + length:position + 12 + length])[0]
        assert zlib.crc32(kind + body) == crc
        chunks.append(kind.decode('ascii'))
        if kind == b'IHDR':
            assert header is None
            header = struct.unpack('>IIBBBBB', body)
            assert header == (8, 8, 8, 6, 0, 0, 0)
        elif kind == b'IDAT':
            assert header is not None
            compressed.extend(body)
        elif kind == b'IEND':
            assert not body and position + 12 == len(data)
        else:
            raise AssertionError('unexpected fixed-fixture PNG chunk')
        position += length + 12
    assert chunks[0] == 'IHDR' and chunks[-1] == 'IEND' and chunks.count('IHDR') == 1
    inflater = zlib.decompressobj()
    raw = inflater.decompress(bytes(compressed), 8 * 33 + 1)
    assert inflater.eof and not inflater.unconsumed_tail and not inflater.unused_data
    assert len(raw) == 8 * 33
    pixels = bytearray()
    for y in range(8):
        row = raw[y * 33:(y + 1) * 33]
        assert row[0] == 0
        pixels.extend(row[1:])
    wanted = bytes(channel for y in range(8) for x in range(8) for channel in (x * 31, y * 31, 160, 255))
    assert bytes(pixels) == wanted
    return {'format': 'PNG', 'size': [8, 8], 'mode': 'RGBA', 'filter': 0,
            'fully_decoded_pixels': 64, 'decoded_pixel_sha256': hashlib.sha256(pixels).hexdigest(),
            'member_sha256': expected_sha, 'chunks': chunks,
            'scope': 'fixed synthetic fixture decoder; no native ChatGPT display claim'}


def zip_verified(path, expected):
    assert path.stat().st_size == expected['bytes'] and digest(path) == expected['sha256']
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert names == ['visual.png', 'marker.txt', 'payload.bin']
        assert not any(n.startswith('/') or '..' in Path(n).parts for n in names)
        png = decode_fixed_png(archive.read('visual.png'), expected['png_sha256'])
    return {'actual_path': str(path), 'bytes': path.stat().st_size, 'sha256': digest(path),
            'zip_crc_pass': True, 'members': names, 'png': png}


def main():
    expected = json.loads((INPUTS / 'expected.json').read_bytes())
    assert os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000
    report = {'kind': 'actual_linux_cross_uid_fixture_test', 'native_chatgpt_acceptance': False,
              'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),
              'groups': os.getgroups(), 'python': sys.version, 'platform': sys.platform,
              'inputs': [], 'runs': [], 'run_id': expected['run_id']}
    for parent in (Path('/opt'), INPUTS, RUNNER):
        v = parent.stat(follow_symlinks=False)
        assert stat.S_ISDIR(v.st_mode) and v.st_uid == 0 and stat.S_IMODE(v.st_mode) == 0o755
    report['input_root'] = facts(INPUTS)
    for name, item in expected['files'].items():
        path = RUNNER / name if name == 'native_owner_linux_runner.py' else INPUTS / name
        report['inputs'].append(checked_root_input(path, item))
    loader_path = INPUTS / 'native_receiver_loader.py'
    loader_bytes = loader_path.read_bytes()
    assert hashlib.sha256(loader_bytes).hexdigest() == expected['loader_sha256']
    loader = ModuleType('reviewed_native_loader')
    loader.__file__ = str(loader_path)
    exec(compile(loader_bytes, str(loader_path), 'exec', dont_inherit=True), loader.__dict__)
    root_info = INPUTS.stat()
    identity = [root_info.st_dev, root_info.st_ino]
    old_plan = plan_for(expected, expected['old_receiver_asset'], ['small-part-0000.bin'])
    old, old_load = loader.load_verified_receiver(str(INPUTS / 'old_native_chunk_receiver.py'), str(INPUTS),
        identity, expected['old_receiver_asset'], old_plan['receiver_asset'])
    old_output = Path(tempfile.mkdtemp(prefix='owner-old-', dir='/tmp'))
    try:
        old.NativeChunkReceiver.start(old_plan, old_output, input_root=INPUTS, target_name='old.zip')
    except old.ReceiverError as error:
        assert error.code == 'unsafe_file', error.code
        report['old_receiver_reproduced'] = {'error': error.code, 'loader': old_load,
            'output': str(old_output), 'created_children': sorted(x.name for x in old_output.iterdir())}
    else:
        raise AssertionError('old helper unexpectedly accepted root-owned native input')
    for size, names in [(8192, ['small-part-0000.bin']),
                        (30_000_000, ['part-0000.bin', 'part-0001.bin', 'part-0002.bin', 'part-0003.bin'])]:
        plan = plan_for(expected, expected['receiver_asset'], names)
        module, loaded = loader.load_verified_receiver(str(INPUTS / 'native_chunk_receiver.py'), str(INPUTS),
            identity, expected['receiver_asset'], plan['receiver_asset'])
        assert loaded['native_receiver_root_bound'] is True
        output = Path(tempfile.mkdtemp(prefix='owner-new-', dir='/tmp'))
        vfs = os.statvfs(output)
        free = vfs.f_bavail * vfs.f_frsize
        assert free >= 1_073_741_824 + size * 2 + 1_048_576
        receiver = module.NativeChunkReceiver.start(plan, output, input_root=INPUTS, target_name='received.zip')
        received = []
        for part, name in zip(plan['parts'], names):
            actual = INPUTS / name
            assert actual.stat().st_size == part['bytes'] and digest(actual) == part['sha256']
            result = receiver.ingest(part['index'], actual)
            assert result['appended_bytes'] == part['bytes']
            received.append({'index': part['index'], 'actual_path': str(actual), 'result': result})
            if part['index'] == 0:
                duplicate = receiver.ingest(0, actual)
                assert duplicate['appended_bytes'] == 0
                receiver = module.NativeChunkReceiver.resume(receiver.session_path, plan, input_root=INPUTS)
                assert receiver.status()['next_index'] == 1
        final = receiver.finish()
        assert final['state'] == 'published_verified' and final['durability'] == 'confirmed'
        file = output / 'received.zip'
        actual_fixture = expected['fixtures']['small.zip' if size == 8192 else 'source-30mb.zip']
        proof = zip_verified(file, actual_fixture)
        owned = []
        for path in [output, Path(receiver.session_path), file] + sorted(Path(receiver.session_path).iterdir()):
            v = path.stat(follow_symlinks=False)
            assert v.st_uid == v.st_gid == 1000
            if path.is_dir():
                assert stat.S_IMODE(v.st_mode) in (0o700, 0o2700)
            else:
                assert stat.S_IMODE(v.st_mode) == 0o600
            owned.append(facts(path))
        report['runs'].append({'bytes': size, 'plan': plan, 'loader': loaded,
            'free_bytes_before': free, 'parts': received, 'duplicate_part0': duplicate,
            'new_object_resume_same_session': True, 'receiver_final': final,
            'independent_final': proof, 'owned_state': owned})
    report['memory'] = {'native_maxrss': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        'native_maxrss_unit': 'KiB',
                        'cgroup_memory_current': Path('/sys/fs/cgroup/memory.current').read_text().strip(),
                        'cgroup_memory_max': Path('/sys/fs/cgroup/memory.max').read_text().strip()}
    assert report['memory']['cgroup_memory_max'] == '536870912'
    report['result'] = 'PASS'
    print('OWNER_TEST_RESULT ' + json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print('OWNER_TEST_FAILURE ' + json.dumps({'result': 'FAIL', 'type': type(error).__name__,
            'error': str(error), 'traceback': traceback.format_exc(),
            'native_chatgpt_acceptance': False}), flush=True)
        raise
