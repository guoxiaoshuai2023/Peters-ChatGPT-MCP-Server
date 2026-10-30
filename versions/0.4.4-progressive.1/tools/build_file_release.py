#!/usr/bin/env python3
"""Build explicit portable source snapshots. Never operates a service or Git."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

DOCS = frozenset({'README.md', 'LICENSE', 'RELEASE_NOTES.md', 'REPOSITORY_ACCESS.md',
                 'CODEX_HISTORY.md', 'HISTORY_CONTINUATION.md', 'CANDIDATE_DELIVERY.md',
                 'ORIGINAL_FILE_SAVE.md', 'ORIGINAL_FILE_EXPORT.md', 'PROGRESSIVE_FILE_EXPORT.md',
                 'requirements.txt', 'requirements.lock'})
EXAMPLES = frozenset({'projects.example.json', 'history-access.example.json',
                     'original-files.example.json', 'original-exports.example.json',
                     'chunked-exports.example.json', 'deployment/access.example.json'})
REQUIRED = frozenset({'peters_mcp/__init__.py', 'peters_mcp/__main__.py',
                     'peters_mcp/cloudflare.py', 'peters_mcp/catalog.py', 'peters_mcp/private_roots.py',
                     'peters_mcp/file_config.py', 'peters_mcp/file_jobs.py', 'peters_mcp/file_tools.py',
                     'ORIGINAL_FILE_SAVE.md', 'README.md', 'RELEASE_NOTES.md', 'LICENSE',
                     'requirements.lock', 'requirements.txt'})
MARKER = 'peters_mcp/_file_release_mode.py'
LAUNCHER = 'run_release.py'
SCAN_RULES = (
    ('personal_home', re.compile(r'/(?:Users|home)/[^\s/"\'<>]+')),
    ('local_drive', re.compile(r'[A-Za-z]:[\\/]Users[\\/][^\s\\/"\']+')),
    ('conversation_identifier', re.compile(r'\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b', re.I)),
    ('temporary_endpoint', re.compile(r'https?://[^\s"\']*\.(?:trycloudflare\.com|ngrok(?:-free)?\.app)\b', re.I)),
    ('private_key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('provider_token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b')),
    ('jwt_value', re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')),
    ('signed_download', re.compile(r'https?://[^\s"\']*[?&](?:sig|signature|token|X-Amz-Signature)=[^\s"\'&]{8,}', re.I)),
)
ASSIGNMENT = re.compile(r'''(?i)\b(?:api_key|api_token|client_secret|access_token|refresh_token|password|secret|token|private_key)["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']''')
PLACEHOLDERS = frozenset({'replace-me', 'your-secret', 'example-only', '<redacted>', '<your-secret>'})
MAX_SOURCE_BYTES = 16 * 1024 * 1024  # Packaging control limit, never a saved-file size limit.


class BuildError(ValueError):
    pass


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _allowed(name):
    path = PurePosixPath(name)
    if (not isinstance(name, str) or '\\' in name or path.is_absolute() or
            any(part in ('', '.', '..') for part in name.split('/')) or str(path) != name):
        raise BuildError('invalid_selection_path')
    module = len(path.parts) == 2 and path.parts[0] == 'peters_mcp' and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', path.name)
    if name == MARKER or not (module or name in DOCS or name in EXAMPLES):
        raise BuildError('path_not_in_release_allowlist')
    return name


def scan_public(data, denied_text=()):
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise BuildError('non_text_source') from None
    for label, pattern in SCAN_RULES:
        if pattern.search(text):
            raise BuildError('privacy_scan_failed:' + label)
    if any(match.group(1).casefold() not in PLACEHOLDERS for match in ASSIGNMENT.finditer(text)):
        raise BuildError('privacy_scan_failed:credential_literal')
    if any(value and value.casefold() in text.casefold() for value in denied_text):
        raise BuildError('privacy_scan_failed:operator_denied_text')


def _read(root, name):
    path = root / name
    if path.resolve() != path:
        raise BuildError('linked_source_rejected')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_SOURCE_BYTES:
                raise BuildError('unsupported_source_file')
            raw = bytearray()
            while len(raw) <= MAX_SOURCE_BYTES:
                chunk = os.read(fd, min(65536, MAX_SOURCE_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if fields(before) != fields(after) or len(raw) != before.st_size:
                raise BuildError('source_changed_during_build')
            return bytes(raw), fields(after)
        finally:
            os.close(fd)
    except OSError:
        raise BuildError('source_unavailable') from None


def _check_runtime(files):
    if not REQUIRED <= files.keys():
        raise BuildError('required_runtime_or_document_missing')
    trees = {}
    for name, raw in files.items():
        if name.startswith('peters_mcp/') and name.endswith('.py'):
            try:
                trees[name] = ast.parse(raw)
            except (SyntaxError, ValueError):
                raise BuildError('source_python_invalid') from None
    for name, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                required = 'peters_mcp/' + node.module.replace('.', '/') + '.py'
                if required != MARKER and required not in files:
                    raise BuildError('local_import_missing_from_selection')
    for name in ('peters_mcp/__main__.py', 'peters_mcp/cloudflare.py'):
        if not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'load_file_service'
                   for node in ast.walk(trees[name])):
            raise BuildError('entrypoint_missing_private_loader')
    loader = trees['peters_mcp/file_config.py']
    names = {alias.asname or alias.name for node in ast.walk(loader)
             if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == '_file_release_mode'
             for alias in node.names if alias.name == 'INSPECTION_ONLY'}
    required_imports = {alias.name for node in ast.walk(loader)
                        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == '_file_release_mode'
                        for alias in node.names}
    config_names = {alias.asname or alias.name for node in ast.walk(loader)
                    if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == '_file_release_mode'
                    for alias in node.names if alias.name == 'REQUIRE_PRIVATE_CONFIG'}
    if ('REQUIRE_PRIVATE_CONFIG' not in required_imports or
            not any(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in config_names
                    for node in ast.walk(loader))):
        raise BuildError('loader_missing_required_config_guard')
    if not names or not any(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names
                            for node in ast.walk(loader)):
        raise BuildError('loader_missing_release_mode_consumer')
    if not any(isinstance(node, ast.ClassDef) and node.name == 'FileSaveInspector'
               for tree in trees.values() for node in ast.walk(tree)):
        raise BuildError('compatible_inspector_missing')


def _launcher():
    return b'''"""Run an explicitly configured protected release; never edit this generated launcher."""
import runpy
import sys
from pathlib import Path
from peters_mcp._file_release_mode import INSPECTION_ONLY

if __name__ == '__main__':
    args = sys.argv[1:]
    if not any(value == '--file-config' or value.startswith('--file-config=') for value in args):
        raise SystemExit('An explicit --file-config is required to retain private-root protection.')
    if INSPECTION_ONLY and '--file-inspection-only' not in args:
        args.append('--file-inspection-only')
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.argv = ['peters_mcp.cloudflare', *args]
    runpy.run_module('peters_mcp.cloudflare', run_name='__main__')
'''


def _inventory(files):
    return [{'path': name, 'bytes': len(raw), 'sha256': _sha(raw)} for name, raw in sorted(files.items())]


def build(source, destination, includes, *, snapshot_id, denied_text=()):
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if source.resolve() != source or not source.is_dir():
        raise BuildError('source_must_be_explicit_canonical_directory')
    if destination.parent.resolve() != destination.parent or not destination.parent.is_dir():
        raise BuildError('output_parent_must_be_existing_canonical_directory')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', snapshot_id):
        raise BuildError('invalid_snapshot_id')
    scan_public(snapshot_id.encode(), denied_text)
    names = [_allowed(name) for name in includes]
    if not names or len(set(names)) != len(names):
        raise BuildError('selection_empty_or_duplicated')
    selected, stamps = {}, {}
    for name in sorted(names):
        selected[name], stamps[name] = _read(source, name)
        scan_public(selected[name], denied_text)
    _check_runtime(selected)
    # No source is re-read during output. Refuse a changing input snapshot first.
    for name, raw in selected.items():
        current, stamp = _read(source, name)
        if current != raw or stamp != stamps[name]:
            raise BuildError('source_changed_during_build')
    source_fingerprint = _sha(_json(_inventory(selected)))
    bundles = {}
    for mode in ('candidate', 'rollback'):
        payload = {**selected, MARKER: ('# Generated immutable release mode.\nINSPECTION_ONLY = ' +
                                      ('True' if mode == 'rollback' else 'False') + '\nREQUIRE_PRIVATE_CONFIG = True\n').encode(),
                   LAUNCHER: _launcher()}
        inventory = _inventory(payload)
        manifest = {'format_version': 1, 'snapshot_id': snapshot_id, 'bundle_mode': mode,
                    'source_content_fingerprint': source_fingerprint,
                    'content_fingerprint': _sha(_json(inventory)), 'files': inventory,
                    'startup_module': 'peters_mcp.cloudflare',
                    'explicit_file_config_required': True, 'require_private_config': True,
                    'rollback_mode': 'inspection-only' if mode == 'rollback' else None,
                    'background_writer_enabled': False if mode == 'rollback' else 'operator-configured',
                    'deployment_status': 'prepared-not-deployed'}
        bundles[mode] = (payload, manifest)
    # Destination is exclusively created; never replace a release or arbitrary path.
    try:
        destination.mkdir(mode=0o700)
    except OSError:
        raise BuildError('destination_must_not_exist') from None
    results = {}
    for mode, (payload, manifest) in bundles.items():
        root = destination / mode
        root.mkdir(mode=0o700)
        for name, raw in payload.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
        with (root / 'manifest.json').open('xb') as stream:
            stream.write(_json(manifest))
        results[mode] = verify(root)
    return results


def verify(root):
    root = Path(root).absolute()
    if root.resolve() != root:
        raise BuildError('linked_release_rejected')
    raw, _ = _read(root, 'manifest.json')
    try:
        manifest = json.loads(raw)
        rows = manifest['files']
        mode = manifest['bundle_mode']
        if (manifest.get('format_version') != 1 or manifest.get('startup_module') != 'peters_mcp.cloudflare'
                or manifest.get('explicit_file_config_required') is not True
                or manifest.get('deployment_status') != 'prepared-not-deployed'):
            raise ValueError()
        if mode not in ('candidate', 'rollback') or rows != sorted(rows, key=lambda item: item['path']):
            raise ValueError()
        names = [row['path'] for row in rows]
        if len(set(names)) != len(names):
            raise ValueError()
        for name in names:
            if name not in (MARKER, LAUNCHER):
                _allowed(name)
        if not REQUIRED.union({MARKER, LAUNCHER}) <= set(names):
            raise ValueError()
        actual = {str(path.relative_to(root)) for path in root.rglob('*') if not path.is_dir()}
        actual_dirs = {str(path.relative_to(root)) for path in root.rglob('*') if path.is_dir()}
        expected_dirs = {str(parent) for name in names for parent in PurePosixPath(name).parents if str(parent) != '.'}
        if actual_dirs != expected_dirs:
            raise ValueError()
        if actual != set(names) | {'manifest.json'} or any(path.is_symlink() for path in root.rglob('*')):
            raise ValueError()
        for row in rows:
            content, _ = _read(root, row['path'])
            if len(content) != row['bytes'] or _sha(content) != row['sha256']:
                raise ValueError()
        marker, _ = _read(root, MARKER)
        expected = ('# Generated immutable release mode.\nINSPECTION_ONLY = ' + ('True' if mode == 'rollback' else 'False') + '\nREQUIRE_PRIVATE_CONFIG = True\n').encode()
        source_rows = [row for row in rows if row['path'] not in (MARKER, LAUNCHER)]
        if (manifest.get('require_private_config') is not True or
                manifest['source_content_fingerprint'] != _sha(_json(source_rows)) or
                marker != expected or manifest['content_fingerprint'] != _sha(_json(rows))):
            raise ValueError()
        if mode == 'rollback' and (manifest['rollback_mode'] != 'inspection-only' or manifest['background_writer_enabled'] is not False):
            raise ValueError()
        if mode == 'candidate' and (manifest['rollback_mode'] is not None or manifest['background_writer_enabled'] != 'operator-configured'):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise BuildError('release_verification_failed') from None
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--snapshot-id')
    parser.add_argument('--include', action='append', default=[])
    parser.add_argument('--deny-text-file', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    try:
        if args.verify:
            result = verify(args.verify)
        else:
            if args.source is None or args.output is None or args.snapshot_id is None:
                parser.error('--source, --output, --snapshot-id and an explicit --include selection are required')
            denied = args.deny_text_file.read_text().splitlines() if args.deny_text_file else ()
            result = build(args.source, args.output, args.include, snapshot_id=args.snapshot_id, denied_text=denied)
        print(json.dumps({key: result[key] for key in ('bundle_mode', 'content_fingerprint')}
                         if args.verify else {mode: value['content_fingerprint'] for mode, value in result.items()}, sort_keys=True))
    except (BuildError, OSError) as exc:
        parser.exit(1, str(exc) if isinstance(exc, BuildError) else 'build_io_failure')


if __name__ == '__main__':
    main()
