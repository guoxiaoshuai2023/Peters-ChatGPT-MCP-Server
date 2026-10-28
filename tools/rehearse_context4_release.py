#!/usr/bin/env python3
"""Isolated macOS HTTP release rehearsal; never opens production configuration.

Run with the existing repository venv and explicit source/frozen bundle roots.
Every service binds an OS-assigned loopback port. Synthetic RSA/JWKS keys and a
constructor-only deterministic source transport replace external identity/file
providers; the real AccessVerifier, receiver lifecycle, MCP HTTP, SQLite,
filesystem identities, original resource protocol and publication code execute.
This does not claim native ChatGPT attachment consumption or physical reboot.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import zipfile
import zlib

PROTOCOL = '2026-07-28'
ISSUER = 'https://synthetic-rehearsal.cloudflareaccess.com'
SUBJECT = 'synthetic-release-owner'
THREAD = '11111111-1111-4111-8111-111111111111'
DENIED_THREAD = '22222222-2222-4222-8222-222222222222'
MARKER = 'peters-identity-release-rehearsal-only-v1'
SOURCE = {'file_id': 'synthetic-zip', 'download_url': 'https://files.example.invalid/original.zip',
          'file_name': 'original.zip', 'mime_type': 'application/zip'}


class _DeviceView:
    """Preserve every native stat field, including integer nanosecond fields."""
    def __init__(self, value, offset):
        self._value, self.st_dev = value, value.st_dev + offset

    def __getattr__(self, name):
        return getattr(self._value, name)

    def __getitem__(self, index):
        return self.st_dev if index == 2 else self._value[index]

    def __iter__(self):
        return iter(tuple(self[index] for index in range(len(self._value))))

    def __len__(self):
        return len(self._value)


def _simulate_device():
    # Spawned receiver/history children inherit this exact synthetic environment.
    # Neither this variable nor this adapter is accepted by the service itself.
    offset = int(os.environ.get('PETERS_REHEARSAL_DEVICE_OFFSET', '0'))
    if not offset:
        return
    if os.environ.get('PETERS_SYNTHETIC_REHEARSAL') != MARKER:
        raise RuntimeError('Device simulation is restricted to the rehearsal')
    for name in ('stat', 'lstat', 'fstat'):
        original = getattr(os, name)
        def projected(*args, _original=original, **kwargs):
            return _DeviceView(_original(*args, **kwargs), offset)
        setattr(os, name, projected)


_simulate_device()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_fingerprint(root):
    return sha(canonical({str(path.relative_to(root)): sha(path.read_bytes())
                          for path in sorted((root / 'peters_mcp').rglob('*.py'))}).encode())


def original_bytes():
    """A reproducible ZIP containing marker text and an actual one-pixel PNG."""
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(b'\x00\x18\x80\xff\xff')) + chunk(b'IEND', b''))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in [('marker.txt', (MARKER + '\n').encode() * 220), ('pixel.png', png)]:
            info = zipfile.ZipInfo(name, (2026, 10, 28, 0, 0, 0))
            archive.writestr(info, data)
    return stream.getvalue()


def synthetic_receive(file, output, allowed_hosts, *, expected_sha256=None,
                      expected_size_bytes=None, stop=None, on_checkpoint=None):
    """Spawn-safe constructor seam; no production URL/SSRF policy is changed."""
    from peters_mcp.file_source import SourceError
    if os.environ.get('PETERS_REHEARSAL_PHASE') == 'restart':
        raise AssertionError('Recovery redownloaded instead of using the durable receipt')
    if file['file_id'] != SOURCE['file_id'] or file['download_url'] != SOURCE['download_url']:
        raise SourceError('file_reference_unavailable')
    body = original_bytes()
    if stop and stop():
        raise SourceError('transfer_cancelled')
    if expected_size_bytes is not None and expected_size_bytes != len(body):
        raise SourceError('expected_length_mismatch')
    if expected_sha256 is not None and expected_sha256 != sha(body):
        raise SourceError('hash_mismatch')
    view = memoryview(body)
    while view:
        written = os.write(output, view)
        view = view[written:]
    os.fsync(output)
    if on_checkpoint:
        on_checkpoint({'durable_offset': len(body), 'prefix_sha256': sha(body)})
    return {'protocol_complete': True, 'file_fsynced': True, 'bytes': len(body),
            'download_sha256': sha(body), 'http_version': 'synthetic-provider',
            'framing': 'deterministic-source-stub', 'expected_hash_matched': True,
            'expected_hash_provenance': 'caller_supplied',
            'source_evidence_kind': 'caller_hash_constraint'}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def put(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True, indent=2)
        stream.write('\n')


def database_rows(root):
    path = root / 'control/file-jobs.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        check(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'SQLite integrity')
        check(db.execute('PRAGMA user_version').fetchone()[0] == 1, 'SQLite schema')
        return {row[0]: list(row) for row in db.execute('SELECT id,actor,request_key,intent,body FROM jobs ORDER BY id')}


def preserved(root):
    baseline = json.loads((root / 'baseline.json').read_text())
    current = database_rows(root)
    check(all(current.get(key) == row for key, row in baseline.items()), 'A legacy job column/body changed')
    return {'legacy_rows': len(baseline), 'current_rows': len(current),
            'legacy_digest': sha(canonical(baseline).encode()),
            'current_digest': sha(canonical(current).encode())}


def fixture(root):
    from peters_mcp.catalog import Catalog
    from peters_mcp.file_context import actor_digest
    from peters_mcp.file_jobs import FileSaveService
    from peters_mcp.private_roots import PrivateRootRegistry
    from peters_mcp.workspaces import RepositoryRegistry
    repo, control, spool = root / 'repo', root / 'control', root / 'spool'
    repo.mkdir(); control.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/git', '-C', str(repo), 'init', '-q'], check=True, capture_output=True)
    (repo / 'TASK.md').write_text('Synthetic identity release HTTP fixture.\n')
    (repo / 'original.zip').write_bytes(original_bytes())
    pin = RepositoryRegistry.identity(repo)
    check(pin.startswith('git-v2-'), 'Fixture did not use repository pin v2')
    put(root / 'projects.json', {'projects': [{'id': 'repo', 'name': 'Synthetic rehearsal',
                                              'root': str(repo), 'repository_id': pin}]})
    home = root / 'synthetic-codex'
    (home / 'sessions').mkdir(parents=True)
    records = [
        {'type': 'session_meta', 'payload': {'id': THREAD, 'cwd': str(repo), 'history_mode': 'paginated'}},
        {'type': 'event_msg', 'payload': {'type': 'task_started', 'turn_id': 'synthetic-turn'}},
        {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant', 'phase': 'final_answer',
         'id': 'synthetic-public-message', 'content': [{'type': 'output_text', 'text': MARKER}]}},
        {'type': 'event_msg', 'payload': {'type': 'task_complete', 'turn_id': 'synthetic-turn'}},
    ]
    rollout = home / 'sessions' / ('rollout-test-' + THREAD + '.jsonl')
    rollout.write_text(''.join(canonical({'timestamp': '2026-10-28T00:00:00Z', **row}) + '\n' for row in records))
    with sqlite3.connect(home / 'state_5.sqlite') as db:
        db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, title TEXT, name TEXT, updated_at INTEGER, archived INTEGER, history_mode TEXT)')
        db.execute('INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)',
                   (THREAD, str(rollout), str(repo), 'Synthetic public history', 'Synthetic', 1, 0, 'paginated'))
    # No explicit thread grant: actual repository association is required.
    put(root / 'history.json', {'version': 2, 'codex_home': str(home), 'state_db': 'state_5.sqlite',
                               'threads': [], 'inherit_projects': True, 'denied_threads': [DENIED_THREAD]})
    registry = PrivateRootRegistry(control, allowed_roots=[spool])
    registry.initialize()
    registry.register_pending(spool, read_roots=[repo, home])
    registry.activate(spool, read_roots=[repo, home])
    check(json.loads((control / 'private-roots.json').read_text())['version'] == 2, 'Manifest is not v2')
    put(root / 'file-config.json', {'version': 1, 'enabled': True, 'control_directory': str(control),
        'spool_roots': [str(spool)], 'sources': {'files.example.invalid': ['8.8.8.8']},
        'special_exceptions': [], 'min_free_bytes': 0, 'max_workers': 2})
    from peters_mcp.file_export import PROFILE_ID, MAX_ORIGINAL_BYTES
    put(root / 'export-config.json', {'version': 1, 'enabled': True, 'spool_root': str(spool),
        'profile_id': PROFILE_ID, 'max_file_bytes': MAX_ORIGINAL_BYTES, 'min_free_bytes': 0})
    (root / 'export-config.json').chmod(0o600)
    catalog = Catalog.from_config(root / 'projects.json', private_registry=registry)
    service = FileSaveService(catalog, registry, control, {'files.example.invalid': ['8.8.8.8']},
                              autostart=False, min_free_bytes=0, _receiver=synthetic_receive)
    actor = actor_digest(ISSUER, SUBJECT)
    try:
        for index in range(19):
            target = service.inspect(actor, 'repo', 'main', 'legacy/%02d.zip' % index)
            accepted = service.submit(actor, SOURCE, 'repo', 'main', target['path'],
                target['target_version'], target['destination_display'], 'legacy-%02d' % index,
                expected_sha256=sha(original_bytes()), expected_size_bytes=len(original_bytes()))
            row = service._get(accepted['job_id'])
            row.pop('runtime_epoch')
            row.update(state='completed' if index < 16 else 'failed', published=index < 16,
                       durability='confirmed' if index < 16 else 'pending',
                       verification='matched' if index < 16 else 'not_started', writer_exited=True)
            # Explicit synthetic legacy fixture creation, before the baseline is frozen.
            with service.db:
                service.db.execute('UPDATE jobs SET body=? WHERE id=?', (canonical(row), row['job_id']))
    finally:
        check(service.close()['state'] == 'stopped', 'Seed coordinator did not stop')
    put(root / 'baseline.json', database_rows(root))
    return {'pin': pin, 'manifest_version': 2, 'runtime_device': repo.stat().st_dev,
            'manifest_sha256': sha((control / 'private-roots.json').read_bytes()),
            'projects_sha256': sha((root / 'projects.json').read_bytes()), **preserved(root)}


def signed_verifier():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from peters_mcp.cloudflare import AccessSettings, AccessVerifier
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings = AccessSettings(ISSUER, 'a' * 64, 'synthetic.example.invalid', ('owner@example.invalid',))
    verifier = AccessVerifier(settings)
    verifier.keys = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key()))
    def token(subject=SUBJECT, **changes):
        claims = {'iss': ISSUER, 'sub': subject, 'aud': settings.audience, 'iat': int(time.time()),
                  'exp': int(time.time()) + 3600, 'email': 'owner@example.invalid', **changes}
        return jwt.encode(claims, key, algorithm='RS256', headers={'kid': 'synthetic-only'})
    return verifier, token


class HTTP:
    def __init__(self, port, token):
        try:
            import httpx2 as httpx
        except ImportError:
            import httpx
        self.client = httpx.Client(base_url='http://127.0.0.1:%d' % port, timeout=30,
                                   trust_env=False)
        self.token, self.counter = token, 0

    def rpc(self, method, params=None, *, token=None):
        params = dict(params or {})
        protocol = '2025-03-26' if method == 'initialize' else PROTOCOL
        headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': protocol,
                   'mcp-method': method}
        actual_token = self.token if token is None else token
        if actual_token:
            headers['cf-access-jwt-assertion'] = actual_token
        if method in ('tools/call', 'resources/read'):
            headers['mcp-name'] = params['name' if method == 'tools/call' else 'uri']
        if method != 'initialize':
            params['_meta'] = {'io.modelcontextprotocol/protocolVersion': PROTOCOL,
                               'io.modelcontextprotocol/clientCapabilities': {}}
        self.counter += 1
        return self.client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': self.counter, 'method': method, 'params': params})

    def raw_tool(self, name, arguments=None, **options):
        response = self.rpc('tools/call', {'name': name, 'arguments': arguments or {}}, **options)
        check(response.status_code == 200, 'HTTP tool status %s: %s' % (response.status_code, response.text[:300]))
        return response.json()['result']

    def tool(self, name, arguments=None, **options):
        result = self.raw_tool(name, arguments, **options)
        check(not result.get('isError'), '%s: %s' % (name, result))
        return json.loads(result['content'][0]['text'])

    def poll(self, key, state='completed'):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            status = self.tool('get_file_save_status', {'request_key': key})
            if status['state'] == state:
                return status
            if status['state'] in {'failed', 'conflict', 'recovery_required', 'publication_unverified'}:
                detail = None
                if hasattr(self, 'files') and not self.files.inspection_only:
                    from peters_mcp.file_context import actor_digest
                    row = self.files._owned(actor_digest(ISSUER, SUBJECT), request_key=key)
                    try:
                        detail = {'persisted_epoch': row.get('runtime_epoch'), 'observed_epoch': self.files._runtime_epoch(row)}
                    except Exception as exc:
                        detail = {'epoch_error': type(exc).__name__, 'message': str(exc)}
                raise AssertionError('Unexpected job status: %s; diagnostic: %s' % (status, detail))
            time.sleep(.025)
        raise AssertionError('Job timeout: %s' % status)


@contextmanager
def running(root, inspection):
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings
    from peters_mcp.catalog import Catalog
    from peters_mcp.cloudflare import AccessMiddleware
    from peters_mcp.file_config import load_file_service
    from peters_mcp.file_export import load_export_service
    from peters_mcp.history import HistoryAccess
    from peters_mcp.server import create_server
    catalog = Catalog.from_config(root / 'projects.json')
    history = HistoryAccess(root / 'history.json', catalog=catalog)
    registry, files = load_file_service(root / 'file-config.json', catalog, history, inspection_only=inspection)
    if not inspection:
        files._receiver = synthetic_receive
    check(files.inspection_only is inspection, 'Unexpected release writer/inspector mode')
    exports = load_export_service(root / 'export-config.json', catalog, history,
                                  files=files, inspection_only=inspection)
    check((exports is None) is inspection, 'Unexpected release export mode')
    server = create_server(catalog, history=history, files=files,
                           file_inspection_only=inspection, exports=exports)
    inner = server.streamable_http_app(host='127.0.0.1', stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=['127.0.0.1:*'], allowed_origins=['https://synthetic.example.invalid']))
    if exports is not None:
        inner = exports.protocol.wrap(inner)
    verifier, tokens = signed_verifier()
    app = AccessMiddleware(inner, verifier)
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    check(port not in (8765, 8766), 'Reserved production port selected')
    config = uvicorn.Config(app, log_level='critical', access_log=False, lifespan='on')
    http_server = uvicorn.Server(config)
    thread = threading.Thread(target=http_server.run, kwargs={'sockets': [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not http_server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(.01)
    check(http_server.started, 'Synthetic HTTP startup failed')
    http = HTTP(port, tokens())
    http.files = files
    try:
        yield http, files, exports, tokens, port
    finally:
        http.client.close()
        http_server.should_exit = True
        thread.join(15)
        sock.close()
        check(not thread.is_alive(), 'HTTP lifespan did not stop')
        check(files.close()['state'] == 'stopped', 'File service shutdown was not quiescent')


def common_reads(http):
    # The 2026 HTTP protocol is handshake-free; separately exercise the SDK's
    # supported legacy initialize handshake, then use modern original resources.
    response = http.rpc('initialize', {'protocolVersion': '2025-03-26',
        'capabilities': {}, 'clientInfo': {'name': 'isolated-release-rehearsal', 'version': '1'}})
    check(response.status_code == 200 and 'result' in response.json(),
          'MCP initialize: %s %s' % (response.status_code, response.text[:1000]))
    listing = http.rpc('tools/list')
    check(listing.status_code == 200, 'MCP tools/list')
    tools = {tool['name'] for tool in listing.json()['result']['tools']}
    check({'list_projects', 'list_worktrees', 'read_file', 'read_codex_thread'} <= tools, 'Missing read tools')
    check(http.rpc('tools/list', token='').status_code == 401, 'Unauthenticated HTTP request was accepted')
    projects = http.tool('list_projects')
    check([project['id'] for project in projects['projects']] == ['repo'], 'Project scope changed')
    worktrees = http.tool('list_worktrees', {'project_id': 'repo'})
    check(any(row['id'] == 'main' and row['state'] == 'valid' for row in worktrees['worktrees']), 'v2 repository read')
    text = http.tool('read_file', {'project_id': 'repo', 'worktree_id': 'main', 'path': 'TASK.md', 'offset': 0, 'limit': 300})
    check(text['sha256'] == sha(b'Synthetic identity release HTTP fixture.\n'), 'Read SHA mismatch')
    args = {'thread_id': THREAD, 'view': 'latest_turn', 'limit': 2, 'max_chars': 3000, 'include_tool_refs': False}
    for _ in range(200):
        history = http.tool('read_codex_thread', args)
        if history['status'] != 'processing':
            break
        args = {**args, 'cursor': history['next_cursor']}
        time.sleep(.01)
    check(history['status'] == 'ready' and any(row.get('text') == MARKER for row in history['entries']),
          'Repository-inherited public history was not read')
    denied = http.raw_tool('read_codex_thread', {'thread_id': DENIED_THREAD})
    check(denied.get('isError'), 'Unauthorized history was accepted')
    sensitive = http.raw_tool('read_file', {'project_id': 'repo', 'worktree_id': 'main', 'path': '.git/config'})
    check(sensitive.get('isError'), 'Sensitive .git source was accepted')
    return {'tools': sorted(tools), 'projects': 1, 'worktrees': len(worktrees['worktrees']),
            'file_sha256': text['sha256'], 'public_history': True,
            'history_snapshot': history.get('snapshot'), 'unauthenticated_http_status': 401,
            'initialize_protocol': '2025-03-26', 'tool_resource_protocol': PROTOCOL}


def save_arguments(http, path, key):
    inspected = http.tool('inspect_file_destination', {'project_id': 'repo', 'worktree_id': 'main', 'path': path})
    return {'file': SOURCE, 'project_id': 'repo', 'worktree_id': 'main', 'path': path,
            'target_version': inspected['target_version'], 'destination_display': inspected['destination_display'],
            'request_key': key, 'expected_sha256': sha(original_bytes()), 'expected_size_bytes': len(original_bytes())}


def worker(root, phase):
    check((root / '.synthetic-rehearsal').read_text() == MARKER, 'Not a rehearsal fixture')
    check(root.is_relative_to(Path(tempfile.gettempdir()).resolve()), 'Fixture must be inside macOS temporary storage')
    if phase == 'prepare':
        return fixture(root)
    inspection = phase == 'rollback'
    before_db = sha((root / 'control/file-jobs.sqlite3').read_bytes())
    before_tree = sorted(str(path.relative_to(root)) for path in root.rglob('*'))
    if phase == 'restart':
        facts = json.loads((root / 'new-jobs.json').read_text())
        pending = json.loads(database_rows(root)[facts['restart']][-1])
        check(pending['state'] == 'ready_to_publish',
              'No durable ready_to_publish record existed at the new process boundary')
    with running(root, inspection) as (http, files, exports, tokens, port):
        report = {'phase': phase, 'port': port, 'reads': common_reads(http),
                  'runtime_device': (root / 'repo').stat().st_dev,
                  'manifest_sha256': sha((root / 'control/private-roots.json').read_bytes()),
                  'projects_sha256': sha((root / 'projects.json').read_bytes())}
        check(http.rpc('tools/list', token=tokens(email='wrong@example.invalid')).status_code == 401,
              'AccessVerifier email validation was bypassed')
        if phase == 'candidate':
            capability = http.tool('list_projects')['original_export']
            export_args = {'project_id': 'repo', 'worktree_id': 'main', 'path': 'original.zip',
                'service_instance_id': capability['service_instance_id'],
                'request_window_id': capability['request_window_id'], 'request_key': 'rehearsal-export'}
            result = http.raw_tool('export_file', export_args)
            metadata = json.loads(result['content'][0]['text'])
            check(metadata['state'] == 'ready', 'Export not ready')
            link = result['content'][1]
            response = http.rpc('resources/read', {'uri': link['uri']})
            check(response.status_code == 200, 'Original resource HTTP read')
            body = base64.b64decode(response.json()['result']['contents'][0]['blob'], validate=True)
            check(body == original_bytes(), 'Original resource bytes changed')
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                check(archive.testzip() is None, 'ZIP CRC failure')
                check(set(archive.namelist()) == {'marker.txt', 'pixel.png'}, 'ZIP members')
                png = archive.read('pixel.png')
                check(png.startswith(b'\x89PNG\r\n\x1a\n'), 'PNG magic')
                position, chunks = 8, {}
                while position < len(png):
                    size = struct.unpack_from('>I', png, position)[0]
                    kind = png[position + 4:position + 8]
                    data = png[position + 8:position + 8 + size]
                    crc = struct.unpack_from('>I', png, position + 8 + size)[0]
                    check(crc == zlib.crc32(kind + data), 'PNG chunk CRC')
                    chunks[kind] = data
                    position += size + 12
                check(position == len(png) and struct.unpack('>IIBBBBB', chunks[b'IHDR']) == (1, 1, 8, 6, 0, 0, 0), 'PNG dimensions')
                check(zlib.decompress(chunks[b'IDAT']) == b'\x00\x18\x80\xff\xff', 'PNG pixel decode')
            wrong = http.rpc('resources/read', {'uri': link['uri']}, token=tokens(subject='other-owner'))
            check('error' in wrong.json(), 'Other actor read exported resource')
            args = save_arguments(http, 'acceptance/saved.zip', 'rehearsal-complete')
            accepted = http.tool('save_generated_file', args)
            check(http.tool('save_generated_file', args)['job_id'] == accepted['job_id'], 'Accepted-key idempotency')
            files.start()
            complete = http.poll('rehearsal-complete')
            check(complete['published'] is True and complete['durability'] == 'confirmed'
                  and complete['verification'] == 'matched', 'Completion facts')
            check((root / 'repo/acceptance/saved.zip').read_bytes() == body, 'Published original bytes')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                finished = files._get(accepted['job_id'])
                if (finished.get('cleanup', {}).get('private_state') == 'completed'
                        and accepted['job_id'] not in files._claims):
                    break
                time.sleep(.02)
            else:
                raise AssertionError('Completed task cleanup did not become idle')
            original_rows = database_rows(root)
            original_sources = dict(files._sources)
            original_claims = dict(files._claims)
            receipt_cases = []
            for label, new_file in (
                    ('new_file_id', {**SOURCE, 'file_id': 'new-materialized-native-reference'}),
                    ('new_unapproved_host', {**SOURCE, 'download_url': 'https://other.example.invalid/new.zip'})):
                receipt = http.tool('save_generated_file', {**args, 'file': new_file})
                check(receipt.get('operation') == 'receipt_lookup'
                      and receipt.get('subject') == 'original_job'
                      and receipt.get('match_kind') == 'completed_bound_hash'
                      and receipt.get('job_id') == accepted['job_id']
                      and receipt.get('new_job_created') is False, 'Receipt lookup envelope')
                check(receipt.get('submitted_reference') == {'received': False, 'content_verified': False,
                      'source_policy': 'not_evaluated_no_transfer'}, 'Receipt falsely verified new source')
                old_status = receipt.get('original_job_status', {})
                check(old_status.get('job_id') == accepted['job_id'] and old_status.get('published') is True
                      and old_status.get('state') == 'completed', 'Original receipt subject')
                check(not any(k in receipt for k in ('saved', 'published', 'bytes', 'download_sha256',
                      'destination_sha256', 'expected_hash_matched')), 'New reference received old facts')
                check(database_rows(root) == original_rows and files._sources == original_sources
                      and files._claims == original_claims, 'Receipt changed jobs/source cache/claims')
                check((root / 'repo/acceptance/saved.zip').read_bytes() == body, 'Receipt changed destination')
                receipt_cases.append({'case': label, 'job_id': receipt['job_id'],
                    'operation': receipt['operation'], 'match_kind': receipt['match_kind'],
                    'new_job_created': False, 'new_reference_received': False,
                    'job_rows_source_cache_claims_unchanged': True})
            report['completed_receipt_http_cases'] = receipt_cases
            report['completed_receipt_native_client_tested'] = False
            conflict = http.raw_tool('save_generated_file', {**args, 'request_key': 'rehearsal-conflict'})
            check(conflict.get('isError') and 'target_exists' in str(conflict), 'Create-only target conflict')
            check((root / 'repo/acceptance/saved.zip').read_bytes() == body, 'Conflict changed destination')
            fault_hits = []
            def stop_after_receipt(event, job_id):
                if event == 'receive_complete' and files._get(job_id)['key'] == files._key('rehearsal-restart'):
                    fault_hits.append(job_id)
                    files._stop.set()
                    raise SystemExit('synthetic crash after durable receipt')
            files.fault_hook = stop_after_receipt
            restart_args = save_arguments(http, 'acceptance/restarted.zip', 'rehearsal-restart')
            restart = http.tool('save_generated_file', restart_args)
            pending = http.poll('rehearsal-restart', 'ready_to_publish')
            deadline = time.monotonic() + 2
            while not fault_hits and time.monotonic() < deadline:
                time.sleep(.01)
            check(fault_hits == [restart['job_id']], 'Durable receipt fault was not injected exactly once')
            check(not (root / 'repo/acceptance/restarted.zip').exists(), 'Fault seam published early')
            put(root / 'new-jobs.json', {'completed': accepted['job_id'], 'restart': restart['job_id'],
                                        'complete_arguments': args, 'restart_arguments': restart_args,
                                        'old_export_arguments': export_args, 'old_export_uri': link['uri']})
            report.update(original_sha256=sha(body), original_bytes=len(body), zip_crc='ok', png_crc_and_pixels='ok: 1x1 RGBA',
                          create_only_conflict=True, same_key_idempotent=True,
                          pending_restart_state=pending['state'], completed_job=complete,
                          receive_complete_fault_hits=len(fault_hits))
        elif phase == 'restart':
            facts = json.loads((root / 'new-jobs.json').read_text())
            files.start()
            result = http.poll('rehearsal-restart')
            check(result['published'] is True and result['durability'] == 'confirmed'
                  and result['verification'] == 'matched', 'Same-epoch recovery failed')
            check((root / 'repo/acceptance/restarted.zip').read_bytes() == original_bytes(), 'Recovered bytes')
            check(http.tool('save_generated_file', facts['complete_arguments'])['job_id'] == facts['completed'],
                  'Completed idempotency did not survive service restart')
            stale = http.raw_tool('export_file', facts['old_export_arguments'])
            check(stale.get('isError'), 'Prior export instance/window remained valid')
            check('error' in http.rpc('resources/read', {'uri': facts['old_export_uri']}).json(), 'Prior resource URI remained valid')
            report.update(recovered_job=result, stale_export_rejected=True,
                          restart_receiver_invocations='none: persisted complete receipt used')
        else:
            tools = set(report['reads']['tools'])
            check('save_generated_file' not in tools and 'export_file' not in tools
                  and 'inspect_file_destination' not in tools, 'Rollback exposed new file operations')
            capability = http.tool('get_write_capabilities')
            check(capability['write_enabled'] is False and capability['execution_ready'] is False, 'Rollback enabled writes')
            facts = json.loads((root / 'new-jobs.json').read_text())
            for key in ('completed', 'restart'):
                status = http.tool('get_file_save_status', {'job_id': facts[key]})
                check(status['published'] is True and status['state'] == 'completed', 'Rollback lost new job facts')
            legacy = json.loads((root / 'baseline.json').read_text())
            for key in legacy:
                status = http.tool('get_file_save_status', {'job_id': key})
                check(status['state'] in {'completed', 'failed'} and status['current_target_observation'] == 'not_checked',
                      'Rollback lost legacy facts')
            denied = http.rpc('tools/call', {'name': 'save_generated_file', 'arguments': facts['complete_arguments']})
            check('error' in denied.json() or denied.json().get('result', {}).get('isError'), 'Rollback accepted file write')
            report.update(readonly_inspector=True, legacy_statuses_read=19, new_statuses_read=2)
    if inspection:
        check(sha((root / 'control/file-jobs.sqlite3').read_bytes()) == before_db, 'Rollback wrote database')
        check(sorted(str(path.relative_to(root)) for path in root.rglob('*')) == before_tree, 'Rollback created filesystem entries')
        report['database_bytes_unchanged'] = True
    if phase == 'candidate':
        facts = json.loads((root / 'new-jobs.json').read_text())
        state = json.loads(database_rows(root)[facts['restart']][-1])['state']
        check(state == 'ready_to_publish', 'Candidate shutdown changed the intended restart state')
        check(not (root / 'repo/acceptance/restarted.zip').exists(), 'Candidate shutdown published the interrupted job')
        report['restart_state_after_shutdown'] = state
    report.update(preserved(root))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-root', type=Path, required=True)
    parser.add_argument('--rollback-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--phase', choices=['prepare', 'candidate', 'restart', 'rollback'], help=argparse.SUPPRESS)
    parser.add_argument('--fixture-root', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    candidate = args.candidate_root.resolve(strict=True)
    check((candidate / 'peters_mcp/fs_identity.py').is_file(), 'Candidate lacks persistent identity implementation')
    sys.path.insert(0, str(candidate))
    if args.phase:
        check(args.fixture_root is not None, 'Missing synthetic fixture')
        if os.environ.get('PETERS_REHEARSAL_EXPECT_ROLLBACK') == '1':
            from peters_mcp._file_release_mode import INSPECTION_ONLY
            check(INSPECTION_ONLY is True, 'Explicit rollback bundle is not pinned to inspection-only')
        print(canonical(worker(args.fixture_root.resolve(strict=True), args.phase)))
        return
    check(sys.platform == 'darwin', 'This rehearsal must use actual macOS filesystem identities')
    rollback = args.rollback_root.resolve(strict=True) if args.rollback_root else candidate
    fingerprints = {'candidate': source_fingerprint(candidate), 'rollback': source_fingerprint(rollback)}
    report = {'scope': 'isolated synthetic real loopback MCP HTTP; no production configuration or tunnel',
              'candidate_root': str(candidate), 'rollback_root': str(rollback),
              'python_payload_fingerprints': fingerprints,
              'rehearsal_script_sha256': sha(Path(__file__).read_bytes()),
              'rollback_mode': 'frozen bundle' if args.rollback_root else 'candidate code with explicit inspection-only construction',
              'source_provider': 'constructor-only deterministic ZIP source stub; native ChatGPT attachment untested',
              'authentication': 'real RS256 AccessVerifier with synthetic in-memory JWKS provider',
              'device_simulation': 'all Python stat/lstat/fstat st_dev + 100003 in new candidate/receiver/history processes; real FD stable identity calls retained',
              'physical_reboot': 'not performed', 'phases': []}
    with tempfile.TemporaryDirectory(prefix='peters-identity-http-') as directory:
        root = Path(directory).resolve()
        (root / '.synthetic-rehearsal').write_text(MARKER)
        for phase, bundle in [('prepare', candidate), ('candidate', candidate), ('restart', candidate), ('rollback', rollback)]:
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PETERS_SYNTHETIC_REHEARSAL=MARKER,
                       PETERS_REHEARSAL_DEVICE_OFFSET='0' if phase == 'prepare' else '100003',
                       PETERS_REHEARSAL_PHASE=phase,
                       PETERS_REHEARSAL_EXPECT_ROLLBACK='1' if phase == 'rollback' and args.rollback_root else '0')
            result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()),
                '--candidate-root', str(bundle), '--fixture-root', str(root), '--phase', phase],
                env=env, cwd=bundle, capture_output=True, text=True, timeout=100)
            if result.returncode:
                raise RuntimeError('%s phase failed (%d):\n%s\n%s' % (phase, result.returncode, result.stdout, result.stderr))
            report['phases'].append(json.loads(result.stdout.strip().splitlines()[-1]))
        check(report['phases'][-1]['current_rows'] == 21, 'Unexpected task count after rollback')
        baseline = report['phases'][0]
        for phase in report['phases'][1:]:
            check(phase['runtime_device'] == baseline['runtime_device'] + 100003, 'Missing device drift simulation')
            check(phase['manifest_sha256'] == baseline['manifest_sha256'], 'Persistent manifest changed')
            check(phase['projects_sha256'] == baseline['projects_sha256'], 'Project authorization changed')
    check(fingerprints == {'candidate': source_fingerprint(candidate), 'rollback': source_fingerprint(rollback)},
          'Python service payload changed during the rehearsal')
    report['result'] = 'PASS'
    report['synthetic_fixture_removed'] = True
    if args.output:
        put(args.output.resolve(), report)
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
