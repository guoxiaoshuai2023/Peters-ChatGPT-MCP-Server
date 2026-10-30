"""Create only two exact-size synthetic ZIP inputs and their measured manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import zipfile
import zlib


def png_bytes():
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
    pixels = b''.join(b'\x00' + b''.join(bytes((x * 31, y * 31, 160, 255)) for x in range(8)) for y in range(8))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 8, 8, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


def make_zip(path, size):
    marker = b'Peters MCP progressive raw-parts-v1 synthetic acceptance input only.\n'
    image = png_bytes()
    entries = [('visual.png', image), ('marker.txt', marker)]
    names = [name for name, _ in entries] + ['payload.bin']
    overhead = 22 + sum(76 + 2 * len(name.encode('ascii')) for name in names)
    payload_bytes = size - overhead - len(marker) - len(image)
    if payload_bytes < 0:
        raise ValueError('fixture_size_too_small')
    with path.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, (2026, 10, 29, 0, 0, 0))
                info.external_attr = 0o600 << 16
                archive.writestr(info, data)
            info = zipfile.ZipInfo('payload.bin', (2026, 10, 29, 0, 0, 0))
            info.external_attr = 0o600 << 16
            seed = hashlib.sha256(b'peters-progressive-synthetic-payload-v1').digest()
            block = seed * 2048
            with archive.open(info, 'w') as member:
                remaining = payload_bytes
                while remaining:
                    data = block[:min(remaining, len(block))]
                    member.write(data)
                    remaining -= len(data)
        stream.flush()
        os.fsync(stream.fileno())
    if path.stat().st_size != size:
        raise ValueError('fixture_length_mismatch')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None or archive.read('visual.png') != image:
            raise ValueError('fixture_integrity_failed')
    return {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest(),
            'zip_crc_pass': True, 'members': names,
            'png_sha256': hashlib.sha256(image).hexdigest(), 'png_size': [8, 8], 'png_mode': 'RGBA'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    root = args.output_directory.absolute()
    if root.parent.resolve() != root.parent:
        raise ValueError('linked_output_parent')
    root.mkdir(mode=0o700)
    items = [make_zip(root / 'small.zip', 8192), make_zip(root / 'source-30mb.zip', 30_000_000)]
    manifest = {'purpose': 'Synthetic sources only; not native receipt or capacity acceptance',
                'protocol_version': 'raw-parts-v1', 'files': items}
    with (root / 'source-manifest.json').open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
