"""Trusted local/native receiver for already-materialized raw original ranges.

No networking, Base64, source execution, permission changes or missing-byte
construction. This helper cannot establish ChatGPT receipt on its own: paths
must come from actual host-materialized files. A published receipt follows an
independent whole-file length/SHA reread and real no-clobber publication.
"""
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import zipfile
import zlib

MAX_BYTES = 200_000_000
BLOCK = 64 * 1024
LEDGER_LIMIT = 128 * 1024
CONTROL_RESERVE = 1024 * 1024
MARKER = 'peters-native-range-receiver-v1'
PREFIX = '.native-range-'
RECOVERY_CONTROL = 'recovery.json'


class ReceiverError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ReceiverError(code)


def _name(value):
    if (not isinstance(value, str) or not value or value in ('.', '..')
            or '/' in value or '\\' in value or len(value.encode('utf-8')) > 240
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _fail('invalid_filename')
    return value


def _sha(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        _fail('invalid_sha256')
    return value


def _integer(value, minimum=0, maximum=MAX_BYTES):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('invalid_integer')
    return value


def normalize_plan(value):
    """Normalize only metadata; reject gaps, overlap, duplicate index and paths."""
    if not isinstance(value, dict):
        _fail('invalid_plan')
    total = _integer(value.get('parent_bytes', value.get('bytes')))
    digest = _sha(value.get('parent_sha256', value.get('sha256')))
    source_name = value.get('source_name')
    if source_name is None:
        path = value.get('source', {}).get('path')
        if not isinstance(path, str) or PurePosixPath(path).is_absolute() or '..' in path.split('/'):
            _fail('invalid_source_name')
        source_name = PurePosixPath(path).name
    source_name = _name(source_name)
    parts = value.get('parts')
    if not isinstance(parts, list) or not 1 <= len(parts) <= 128:
        _fail('invalid_parts')
    normalized, position, names = [], 0, set()
    for index, part in enumerate(parts):
        if not isinstance(part, dict) or _integer(part.get('part_index'), 0, 127) != index:
            _fail('invalid_part_order')
        offset = _integer(part.get('offset'))
        count = _integer(part.get('bytes'), 0 if total == 0 else 1)
        if offset != position or offset + count > total:
            _fail('invalid_part_bounds')
        name = _name(part.get('resource_name', part.get('resname')))
        if name in names:
            _fail('duplicate_part_filename')
        names.add(name)
        normalized.append({'part_index': index, 'offset': offset, 'bytes': count,
                           'sha256': _sha(part.get('sha256')), 'resource_name': name})
        position += count
    if position != total or total == 0 and (len(parts) != 1 or normalized[0]['bytes'] != 0):
        _fail('incomplete_plan')
    return {'source_name': source_name, 'bytes': total, 'sha256': digest, 'parts': normalized}


def _encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _identity(info):
    return [info.st_dev, info.st_ino]


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@contextmanager
def _directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        _fail('unsafe_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            for component in path.parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        except OSError:
            _fail('unsafe_directory')
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _file(directory, name, flags=os.O_RDONLY, *, identity=None, private=False, links=(1,)):
    try:
        fd = os.open(_name(name), flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        _fail('file_unavailable')
    except OSError:
        _fail('unsafe_file')
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink not in links
                or identity is not None and _identity(info) != identity
                or private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600)):
            _fail('unsafe_file')
        yield fd
    finally:
        os.close(fd)


def _write(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view[:BLOCK])
        if count <= 0:
            _fail('short_write')
        view = view[count:]


def _hash(fd, offset, count):
    before = os.fstat(fd)
    digest, position = hashlib.sha256(), 0
    while position < count:
        block = os.pread(fd, min(BLOCK, count - position), offset + position)
        if not block:
            _fail('short_read')
        digest.update(block)
        position += len(block)
    if _version(before) != _version(os.fstat(fd)):
        _fail('file_changed')
    return digest.hexdigest()


def _exists(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _source_scope(plan):
    source = plan.get('source')
    if not isinstance(source, dict):
        _fail('recovery_source_scope_missing')
    result = {key: source.get(key) for key in ('project_id', 'worktree_id', 'path')}
    if any(not isinstance(value, str) or not value for value in result.values()):
        _fail('recovery_source_scope_invalid')
    path = PurePosixPath(result['path'])
    if (path.is_absolute() or str(path) != result['path']
            or any(p in ('', '.', '..') for p in result['path'].split('/'))):
        _fail('recovery_source_scope_invalid')
    return result


def _recovery_plans(old, new):
    """Metadata comparison is not authentication; obtain plans from authorized MCP."""
    first, second = normalize_plan(old), normalize_plan(new)
    if _source_scope(old) != _source_scope(new):
        _fail('recovery_source_scope_changed')
    old_id, new_id = old.get('export_id'), new.get('export_id')
    if (not isinstance(old_id, str) or re.fullmatch('[a-f0-9]{32}', old_id) is None
            or not isinstance(new_id, str) or re.fullmatch('[a-f0-9]{32}', new_id) is None
            or old_id == new_id):
        _fail('recovery_fresh_export_id_required')
    if any(first[key] != second[key] for key in ('source_name', 'bytes', 'sha256')):
        _fail('recovery_whole_content_changed')
    if len(first['parts']) != len(second['parts']):
        _fail('recovery_part_geometry_changed')
    for before, after in zip(first['parts'], second['parts']):
        if any(before[key] != after[key] for key in ('part_index', 'offset', 'bytes', 'sha256')):
            _fail('recovery_part_content_or_geometry_changed')
    return first, second


def _control_load(session, name):
    with _file(session, name, private=True) as fd:
        before = os.fstat(fd)
        if before.st_size > LEDGER_LIMIT:
            _fail('control_too_large')
        raw = os.read(fd, LEDGER_LIMIT + 1)
        if len(raw) != before.st_size or _version(before) != _version(os.fstat(fd)):
            _fail('control_changed')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail('control_duplicate_key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(value, dict):
            _fail('invalid_control')
        return value
    except (ValueError, TypeError):
        _fail('invalid_control')


def _control_save(session, name, value):
    raw = _encoded(value)
    if len(raw) > LEDGER_LIMIT:
        _fail('control_too_large')
    temporary = '.recovery-' + secrets.token_hex(8)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
    try:
        _write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, name, src_dir_fd=session, dst_dir_fd=session)
    os.fsync(session)


class NativeRangeReceiver:
    @classmethod
    def start(cls, plan, output_dir, *, target_name=None, input_root=None, min_free_bytes=64 * 1024 * 1024):
        plan = normalize_plan(plan)
        target_name = _name(target_name or plan['source_name'])
        output_dir = str(Path(output_dir))
        input_root = str(Path(input_root or output_dir))
        minimum = _integer(min_free_bytes, 0, 2**63 - 1)
        with _directory(input_root) as input_directory:
            input_identity = _identity(os.fstat(input_directory))
        with _directory(output_dir) as root:
            if _exists(root, target_name):
                _fail('target_exists')
            free = os.fstatvfs(root).f_bavail * os.fstatvfs(root).f_frsize
            # Input files and any other originals already reduce actual free.
            # Reserve receiving bytes + possible xb publication copy + ledger.
            if free < plan['bytes'] * 2 + CONTROL_RESERVE + minimum:
                _fail('insufficient_space')
            nonce = secrets.token_hex(16)
            session_name = PREFIX + nonce
            os.mkdir(session_name, 0o700, dir_fd=root)
            session = os.open(session_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                identities = {}
                for name in ('receive.tmp', 'lock'):
                    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
                    identities[name] = _identity(os.fstat(fd))
                    os.fsync(fd)
                    os.close(fd)
                ledger = {'version': 1, 'marker': MARKER, 'nonce': nonce, 'plan': plan,
                    'plan_sha256': hashlib.sha256(_encoded(plan)).hexdigest(), 'target_name': target_name,
                    'root_identity': _identity(os.fstat(root)), 'session_identity': _identity(os.fstat(session)),
                    'file_identities': identities, 'input_root': input_root,
                    'input_root_identity': input_identity, 'min_free_bytes': minimum,
                    'accepted': [], 'received_bytes': 0, 'pending': None,
                    'state': 'receiving', 'publication': None}
                cls._save(session, ledger)
                os.fsync(root)
            finally:
                os.close(session)
        return cls(output_dir, session_name, plan, input_root)

    @classmethod
    def resume(cls, session_path, plan, *, input_root=None):
        session_path = Path(session_path)
        if not session_path.is_absolute() or not session_path.name.startswith(PREFIX):
            _fail('invalid_session')
        normalized = normalize_plan(plan)
        with _directory(session_path) as session:
            ledger = cls._load(session)
        receiver = cls(str(session_path.parent), session_path.name, normalized,
                       str(Path(input_root or ledger['input_root'])))
        with receiver._locked() as (root, session, ledger):
            receiver._recover_link(root, session, ledger)
            receiver._verify_temp(session, ledger)
            if ledger['state'] == 'published':
                receiver._verify_publication(root, ledger)
        return receiver

    @classmethod
    def _old_for_recovery(cls, session_path, normalized):
        path = Path(session_path)
        if not path.is_absolute() or not path.name.startswith(PREFIX):
            _fail('invalid_session')
        with _directory(path) as session:
            ledger = cls._load(session)
        return cls(str(path.parent), path.name, normalized, ledger['input_root'])

    @classmethod
    def recover_new_plan(cls, old_session_path, old_plan, new_plan, preserved_paths, *,
                         output_dir, input_root=None, target_name,
                         min_free_bytes=64 * 1024 * 1024):
        """New nonce/target from genuine accepted local parts and fresh authorized metadata.

        The caller obtains the fresh plan with a new request key and the known
        whole SHA from the authorized MCP; this local helper grants no source
        access. Stop old ingest first. Keep the old session/parts until recovery
        becomes ready. It never changes an old ledger or revives an old ID.
        """
        old_normal, new_normal = _recovery_plans(old_plan, new_plan)
        old = cls._old_for_recovery(old_session_path, old_normal)
        target_name = _name(target_name)
        with old._locked() as (_, old_session, previous):
            old._verify_temp(old_session, previous)
            if previous['state'] not in ('receiving', 'cancelled') or previous['publication'] is not None:
                _fail('recovery_old_publication_requires_resolution')
            if target_name == previous['target_name']:
                _fail('recovery_new_target_required')
            count = len(previous['accepted'])
            if (not isinstance(preserved_paths, dict) or set(preserved_paths) != set(range(count))
                    or any(type(index) is not int for index in preserved_paths)):
                _fail('recovery_actual_prefix_incomplete')
            paths = []
            for index in range(count):
                path = str(Path(preserved_paths[index]))
                with old._input(path, old_normal['parts'][index]) as (fd, version):
                    paths.append({'path': path, 'identity': _identity(os.fstat(fd)),
                                  'version': list(version)})
            with _directory(output_dir) as root, _directory(input_root or output_dir) as inputs:
                if os.fstat(root).st_dev != os.fstat(inputs).st_dev:
                    _fail('recovery_single_filesystem_required')
                if any(_exists(inputs, p['resource_name']) for p in new_normal['parts'][:count]):
                    _fail('recovery_alias_already_exists')
                minimum = _integer(min_free_bytes, 0, 2**63 - 1)
                alias_bytes = sum(p['bytes'] for p in new_normal['parts'][:count])
                if os.fstatvfs(root).f_bavail * os.fstatvfs(root).f_frsize < (
                        alias_bytes + new_normal['bytes'] * 2 + CONTROL_RESERVE + minimum):
                    _fail('insufficient_space')
            receiver = cls.start(new_plan, output_dir, target_name=target_name,
                                 input_root=input_root, min_free_bytes=minimum)
            with receiver._locked() as (_, session, ledger):
                binding = {'version': 1, 'old_session_path': old.session_path,
                    'old_receiver_nonce': previous['nonce'], 'old_plan': old_normal,
                    'old_export_id': old_plan['export_id'], 'new_export_id': new_plan['export_id'],
                    'source_scope': _source_scope(new_plan), 'prefix_count': count,
                    'prefix_bytes': previous['received_bytes'], 'old_pending_excluded': previous['pending'],
                    'old_root_identity': previous['root_identity'], 'old_session_identity': previous['session_identity'],
                    'old_file_identities': previous['file_identities'], 'old_input_root': previous['input_root'],
                    'old_input_root_identity': previous['input_root_identity'], 'sources': paths,
                    'new_receiver_nonce': ledger['nonce'], 'new_plan_sha256': ledger['plan_sha256'],
                    'new_target_name': target_name, 'new_root_identity': ledger['root_identity'],
                    'new_session_identity': ledger['session_identity'],
                    'new_input_root_identity': ledger['input_root_identity']}
                ledger['recovery_binding'] = binding
                cls._save(session, ledger)  # atomic immutable intent before any alias exists
                receiver._recovery_journal(session, ledger, initialize=True)
            receiver._run_recovery_locked_old(old, previous)
        return receiver

    @classmethod
    def resume_recovery(cls, session_path, new_plan, *, input_root=None):
        """Continue only recorded own alias/receive progress; never adopt an unknown file."""
        receiver = cls.resume(session_path, new_plan, input_root=input_root)
        with receiver._locked() as (_, session, ledger):
            binding = ledger.get('recovery_binding')
            if not isinstance(binding, dict):
                _fail('recovery_binding_missing')
            if (_source_scope(new_plan) != binding['source_scope']
                    or new_plan.get('export_id') != binding['new_export_id']):
                _fail('recovery_new_plan_binding_changed')
            journal = receiver._recovery_journal(session, ledger, initialize=True)
            if journal['state'] == 'ready':
                return receiver
            if ledger['state'] != 'receiving':
                _fail('receiver_not_accepting')
        old = cls._old_for_recovery(binding['old_session_path'], binding['old_plan'])
        with old._locked() as (_, old_session, previous):
            old._verify_temp(old_session, previous)
            receiver._check_recovery_old(binding, previous)
            receiver._run_recovery_locked_old(old, previous)
        return receiver

    @staticmethod
    def _check_recovery_old(binding, previous):
        if previous['state'] not in ('receiving', 'cancelled') or previous['publication'] is not None:
            _fail('recovery_old_publication_requires_resolution')
        fields = (('old_receiver_nonce', 'nonce'), ('old_plan', 'plan'),
            ('old_root_identity', 'root_identity'), ('old_session_identity', 'session_identity'),
            ('old_file_identities', 'file_identities'), ('old_input_root', 'input_root'),
            ('old_input_root_identity', 'input_root_identity'), ('prefix_bytes', 'received_bytes'))
        if (any(binding[key] != previous[field] for key, field in fields)
                or previous['accepted'] != list(range(binding['prefix_count']))):
            _fail('recovery_old_session_binding_changed')

    def _recovery_journal(self, session, ledger, *, initialize=False):
        binding = ledger.get('recovery_binding')
        if not isinstance(binding, dict):
            _fail('recovery_binding_missing')
        if (binding.get('version') != 1 or binding.get('new_receiver_nonce') != ledger['nonce']
                or binding.get('new_plan_sha256') != self.plan_hash
                or binding.get('new_target_name') != ledger['target_name']
                or binding.get('new_root_identity') != ledger['root_identity']
                or binding.get('new_session_identity') != ledger['session_identity']
                or binding.get('new_input_root_identity') != ledger['input_root_identity']):
            _fail('recovery_binding_changed')
        count = _integer(binding.get('prefix_count'), 0, len(self.plan['parts']))
        if (normalize_plan(binding.get('old_plan')) != binding['old_plan']
                or len(binding.get('sources', [])) != count
                or binding.get('prefix_bytes') != sum(p['bytes'] for p in self.plan['parts'][:count])):
            _fail('recovery_binding_changed')
        old_plan = binding['old_plan']
        if (any(old_plan[key] != self.plan[key] for key in ('source_name', 'bytes', 'sha256'))
                or len(old_plan['parts']) != len(self.plan['parts'])
                or any(any(before[key] != after[key] for key in ('part_index', 'offset', 'bytes', 'sha256'))
                       for before, after in zip(old_plan['parts'], self.plan['parts']))):
            _fail('recovery_binding_changed')
        digest = hashlib.sha256(_encoded(binding)).hexdigest()
        if not _exists(session, RECOVERY_CONTROL):
            if not initialize:
                _fail('recovery_journal_missing')
            # An atomic intent can outlive process exit before journal creation.
            # Recreate metadata only when no alias/receive bytes exist to adopt.
            with _directory(self.input_root) as inputs:
                if any(_exists(inputs, p['resource_name']) for p in self.plan['parts'][:count]):
                    _fail('recovery_alias_ownership_unconfirmed')
            if ledger['accepted'] or ledger['pending'] is not None:
                _fail('recovery_journal_missing')
            value = {'version': 1, 'binding_sha256': digest,
                     'state': 'ready' if count == 0 else 'copying',
                     'aliases': [{'phase': 'uncreated', 'identity': None} for _ in range(count)]}
            _control_save(session, RECOVERY_CONTROL, value)
        value = _control_load(session, RECOVERY_CONTROL)
        if (value.get('version') != 1 or value.get('binding_sha256') != digest
                or value.get('state') not in ('copying', 'ready')
                or not isinstance(value.get('aliases'), list) or len(value['aliases']) != count):
            _fail('recovery_journal_binding_changed')
        phases = ('uncreated', 'copying', 'copied', 'committed')
        for index, row in enumerate(value['aliases']):
            if (not isinstance(row, dict) or row.get('phase') not in phases
                    or row.get('phase') == 'uncreated' and row.get('identity') is not None
                    or row.get('phase') != 'uncreated' and
                    (not isinstance(row.get('identity'), list) or len(row['identity']) != 2
                     or any(type(n) is not int or n < 0 for n in row['identity']))):
                _fail('recovery_journal_binding_changed')
            if row['phase'] == 'committed' and index >= len(ledger['accepted']):
                _fail('recovery_progress_changed')
        if value['state'] == 'ready' and (len(ledger['accepted']) < count
                or any(row['phase'] != 'committed' for row in value['aliases'])):
            _fail('recovery_progress_changed')
        return value

    def _recovery_space(self, root, session, ledger, journal):
        expected = sum(p['bytes'] for p in self.plan['parts'][:len(ledger['accepted'])])
        maximum = expected + (self.plan['parts'][ledger['pending']]['bytes'] if ledger['pending'] is not None else 0)
        with _file(session, 'receive.tmp', identity=ledger['file_identities']['receive.tmp'], private=True) as fd:
            length = os.fstat(fd).st_size
        if not expected <= length <= maximum:
            _fail('temporary_length_changed')
        remaining = 0
        with _directory(self.input_root) as inputs:
            for index, row in enumerate(journal['aliases']):
                part = self.plan['parts'][index]
                if row['phase'] == 'uncreated':
                    if _exists(inputs, part['resource_name']):
                        _fail('recovery_alias_ownership_unconfirmed')
                    remaining += part['bytes']
                elif row['phase'] == 'copying':
                    with _file(inputs, part['resource_name'], identity=row['identity'], private=True) as fd:
                        count = os.fstat(fd).st_size
                        if not 0 <= count <= part['bytes']:
                            _fail('recovery_alias_length_changed')
                        remaining += part['bytes'] - count
        info = os.fstatvfs(root)
        required = (self.plan['bytes'] - length + self.plan['bytes'] + remaining
                    + CONTROL_RESERVE + ledger['min_free_bytes'])
        if info.f_bavail * info.f_frsize < required:
            _fail('insufficient_space')

    def _run_recovery_locked_old(self, old, previous):
        for index in range(len(previous['accepted'])):
            with self._locked() as (root, session, ledger):
                if ledger['state'] != 'receiving':
                    _fail('receiver_not_accepting')
                binding = ledger['recovery_binding']
                self._check_recovery_old(binding, previous)
                self._verify_temp(session, ledger)
                journal = self._recovery_journal(session, ledger, initialize=True)
                row = journal['aliases'][index]
                if row['phase'] == 'committed':
                    self._verify_temp(session, ledger)
                    continue
                part, source = self.plan['parts'][index], binding['sources'][index]
                self._recovery_space(root, session, ledger, journal)
                with old._input(source['path'], old.plan['parts'][index]) as (input_fd, version):
                    if (_identity(os.fstat(input_fd)) != source['identity']
                            or list(version) != source['version']):
                        _fail('recovery_preserved_part_changed')
                    with _directory(self.input_root) as inputs:
                        if row['phase'] == 'uncreated':
                            if _exists(inputs, part['resource_name']):
                                _fail('recovery_alias_ownership_unconfirmed')
                            fd = os.open(part['resource_name'], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=inputs)
                            try:
                                row['identity'] = _identity(os.fstat(fd))
                                row['phase'] = 'copying'
                                os.fsync(fd)
                                os.fsync(inputs)
                                # Persist actual ownership before the first byte.
                                _control_save(session, RECOVERY_CONTROL, journal)
                            finally:
                                os.close(fd)
                        with _file(inputs, part['resource_name'], os.O_RDWR,
                                   identity=row['identity'], private=True) as alias:
                            copied = os.fstat(alias).st_size
                            if not 0 <= copied <= part['bytes']:
                                _fail('recovery_alias_length_changed')
                            self._compare_prefix(input_fd, alias, 0, 0, copied)
                            os.lseek(alias, copied, os.SEEK_SET)
                            while copied < part['bytes']:
                                self._recovery_space(root, session, ledger, journal)
                                block = os.pread(input_fd, min(BLOCK, part['bytes'] - copied), copied)
                                if not block:
                                    _fail('part_short_read')
                                _write(alias, block)
                                copied += len(block)
                            os.fsync(alias)
                            if _hash(alias, 0, part['bytes']) != part['sha256']:
                                _fail('recovery_alias_hash_mismatch')
                            row['phase'] = 'copied'
                            row['bytes'] = copied
                            row['sha256'] = part['sha256']
                            _control_save(session, RECOVERY_CONTROL, journal)
            # Normal helper owns pending, offset/SHA, fsync, and accepted commits.
            self.ingest(index, str(Path(self.input_root) / part['resource_name']))
        with self._locked() as (_, session, ledger):
            journal = self._recovery_journal(session, ledger)
            if journal['state'] != 'ready':
                _fail('recovery_prefix_incomplete')

    def _recovery_ingest(self, session, ledger, index, path):
        if 'recovery_binding' not in ledger:
            return None
        journal = self._recovery_journal(session, ledger)
        if journal['state'] == 'copying':
            if (index >= len(journal['aliases'])
                    or journal['aliases'][index]['phase'] not in ('copied', 'committed')):
                _fail('recovery_pending')
            if Path(path) != Path(self.input_root) / self.plan['parts'][index]['resource_name']:
                _fail('recovery_alias_path_changed')
            with _directory(self.input_root) as inputs, _file(inputs, self.plan['parts'][index]['resource_name'],
                    identity=journal['aliases'][index]['identity'], private=True):
                pass
        return journal

    def _recovery_ingested(self, session, ledger, index, journal):
        if journal is None or journal['state'] == 'ready':
            return
        if index < len(ledger['accepted']):
            journal['aliases'][index]['phase'] = 'committed'
        if (len(ledger['accepted']) >= len(journal['aliases'])
                and all(row['phase'] == 'committed' for row in journal['aliases'])):
            journal['state'] = 'ready'
        _control_save(session, RECOVERY_CONTROL, journal)

    def __init__(self, output_dir, session_name, plan, input_root):
        self.output_dir, self.session_name = output_dir, _name(session_name)
        self.plan, self.input_root = plan, input_root
        self.plan_hash = hashlib.sha256(_encoded(plan)).hexdigest()

    @property
    def session_path(self):
        return str(Path(self.output_dir) / self.session_name)

    @staticmethod
    def _load(session):
        with _file(session, 'ledger.json', private=True) as fd:
            info = os.fstat(fd)
            if info.st_size > LEDGER_LIMIT:
                _fail('ledger_too_large')
            raw = os.read(fd, LEDGER_LIMIT + 1)
            if len(raw) != info.st_size:
                _fail('ledger_changed')
        try:
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        _fail('ledger_duplicate_key')
                    result[key] = value
                return result
            return json.loads(raw, object_pairs_hook=unique)
        except (ValueError, TypeError):
            _fail('invalid_ledger')

    @staticmethod
    def _save(session, ledger):
        raw = _encoded(ledger)
        if len(raw) > LEDGER_LIMIT:
            _fail('ledger_too_large')
        name = '.ledger-' + secrets.token_hex(8)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
        try:
            _write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(name, 'ledger.json', src_dir_fd=session, dst_dir_fd=session)
        os.fsync(session)

    @contextmanager
    def _locked(self):
        with _directory(self.output_dir) as root:
            session = os.open(self.session_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                info = os.fstat(session)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o700, 0o2700):
                    _fail('unsafe_session')
                ledger = self._load(session)
                nonce = self.session_name.removeprefix(PREFIX)
                if (ledger.get('marker') != MARKER or ledger.get('version') != 1
                        or ledger.get('nonce') != nonce or len(nonce) != 32
                        or any(c not in '0123456789abcdef' for c in nonce)
                        or ledger.get('plan_sha256') != self.plan_hash or ledger.get('plan') != self.plan
                        or ledger.get('input_root') != self.input_root
                        or ledger.get('root_identity') != _identity(os.fstat(root))
                        or ledger.get('session_identity') != _identity(info)):
                    _fail('session_binding_changed')
                with _directory(self.input_root) as input_directory:
                    if ledger.get('input_root_identity') != _identity(os.fstat(input_directory)):
                        _fail('input_root_changed')
                _name(ledger.get('target_name'))
                with _file(session, 'lock', os.O_RDWR, identity=ledger['file_identities']['lock'], private=True) as lock:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        _fail('receiver_busy')
                    try:
                        # Another receiver may have committed before this lock.
                        latest = self._load(session)
                        immutable = ('version', 'marker', 'nonce', 'plan', 'plan_sha256',
                            'target_name', 'root_identity', 'session_identity', 'file_identities',
                            'input_root', 'input_root_identity', 'min_free_bytes', 'recovery_binding')
                        if any(latest.get(key) != ledger.get(key) for key in immutable):
                            _fail('session_binding_changed')
                        _name(latest.get('target_name'))
                        yield root, session, latest
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                os.close(session)

    def _verify_temp(self, session, ledger):
        accepted = ledger['accepted']
        if not isinstance(accepted, list) or accepted != list(range(len(accepted))) or len(accepted) > len(self.plan['parts']):
            _fail('invalid_progress')
        expected = sum(part['bytes'] for part in self.plan['parts'][:len(accepted)])
        if ledger['received_bytes'] != expected:
            _fail('invalid_progress')
        with _file(session, 'receive.tmp', identity=ledger['file_identities']['receive.tmp'],
                   private=True, links=(1, 2) if ledger['publication'] else (1,)) as fd:
            info = os.fstat(fd)
            pending = ledger['pending']
            limit = expected
            if pending is not None:
                if len(accepted) >= len(self.plan['parts']) or pending != len(accepted):
                    _fail('invalid_pending')
                limit += self.plan['parts'][pending]['bytes']
            if not expected <= info.st_size <= limit:
                _fail('temporary_length_changed')
            for part in self.plan['parts'][:len(accepted)]:
                if _hash(fd, part['offset'], part['bytes']) != part['sha256']:
                    _fail('committed_part_changed')
            return info.st_size

    @contextmanager
    def _input(self, path, part):
        path = Path(path)
        root = Path(self.input_root)
        if not path.is_absolute() or '..' in path.parts:
            _fail('unsafe_input_path')
        try:
            relative = path.relative_to(root)
        except ValueError:
            _fail('input_outside_root')
        if path.name != part['resource_name']:
            _fail('unexpected_part_filename')
        with _directory(path.parent) as parent, _file(parent, path.name) as fd:
            before = os.fstat(fd)
            if before.st_size != part['bytes'] or _hash(fd, 0, part['bytes']) != part['sha256']:
                _fail('part_length_or_hash_mismatch')
            yield fd, _version(before)
            if _version(before) != _version(os.fstat(fd)):
                _fail('input_changed')

    def _space(self, root, ledger, current_length):
        info = os.fstatvfs(root)
        free = info.f_bavail * info.f_frsize
        remaining = self.plan['bytes'] - current_length
        copy_remaining = self.plan['bytes']
        if ledger['publication']:
            copy_remaining = 0  # exact fallback copy checks its own remaining below
        required = remaining + copy_remaining + CONTROL_RESERVE + ledger['min_free_bytes']
        if free < required:
            _fail('insufficient_space')
        return {'free_bytes': free, 'remaining_receive_bytes': remaining,
                'possible_publish_copy_bytes': copy_remaining,
                'control_reserve_bytes': CONTROL_RESERVE, 'min_free_bytes': ledger['min_free_bytes'],
                'already_materialized_parts_and_partial_reduce_reported_free': True}

    @staticmethod
    def _compare_prefix(input_fd, temporary_fd, source_offset, temp_offset, count):
        position = 0
        while position < count:
            size = min(BLOCK, count - position)
            a = os.pread(input_fd, size, source_offset + position)
            b = os.pread(temporary_fd, size, temp_offset + position)
            if len(a) != size or a != b:
                _fail('uncommitted_bytes_changed')
            position += size

    def ingest(self, part_index, path):
        index = _integer(part_index, 0, len(self.plan['parts']) - 1)
        part = self.plan['parts'][index]
        with self._locked() as (root, session, ledger):
            recovery = self._recovery_ingest(session, ledger, index, path)
            if ledger['state'] not in ('receiving', 'published'):
                _fail('receiver_not_accepting')
            length = self._verify_temp(session, ledger)
            next_index = len(ledger['accepted'])
            if ledger['state'] == 'published':
                self._verify_publication(root, ledger)
            if index > next_index:
                _fail('part_out_of_order')
            with self._input(path, part) as (input_fd, before):
                if index < next_index:
                    self._recovery_ingested(session, ledger, index, recovery)
                    return {'state': 'duplicate_verified', 'part_index': index,
                            'received_bytes': ledger['received_bytes'], 'appended_bytes': 0}
                if ledger['state'] == 'published':
                    _fail('receiver_completed')
                self._space(root, ledger, length)
                if ledger['pending'] not in (None, index):
                    _fail('pending_part_conflict')
                ledger['pending'] = index
                self._save(session, ledger)
                with _file(session, 'receive.tmp', os.O_RDWR,
                           identity=ledger['file_identities']['receive.tmp'], private=True) as temp:
                    copied = length - part['offset']
                    self._compare_prefix(input_fd, temp, 0, part['offset'], copied)
                    os.lseek(temp, length, os.SEEK_SET)
                    while copied < part['bytes']:
                        self._space(root, ledger, part['offset'] + copied)
                        block = os.pread(input_fd, min(BLOCK, part['bytes'] - copied), copied)
                        if not block:
                            _fail('part_short_read')
                        _write(temp, block)
                        copied += len(block)
                    os.fsync(temp)
                    if _hash(temp, part['offset'], part['bytes']) != part['sha256']:
                        _fail('received_part_hash_mismatch')
                if before != _version(os.fstat(input_fd)):
                    _fail('input_changed')
                ledger['accepted'].append(index)
                ledger['received_bytes'] += part['bytes']
                ledger['pending'] = None
                self._save(session, ledger)
                self._recovery_ingested(session, ledger, index, recovery)
            return {'state': 'part_received_verified', 'part_index': index,
                    'received_bytes': ledger['received_bytes'], 'part_sha256': part['sha256'],
                    'appended_bytes': part['bytes'] - (length - part['offset'])}

    def _recover_link(self, root, session, ledger):
        """Recover a real link created before its ledger commit; never adopt a copy."""
        if (ledger['state'] != 'publishing' or ledger['publication'] is not None
                or not _exists(root, ledger['target_name'])):
            return
        if ledger['pending'] is not None or len(ledger['accepted']) != len(self.plan['parts']):
            _fail('unowned_target_exists')
        with _file(session, 'receive.tmp', identity=ledger['file_identities']['receive.tmp'],
                   private=True, links=(1, 2)) as temp, _file(root, ledger['target_name'],
                   identity=ledger['file_identities']['receive.tmp'], private=True, links=(1, 2)) as final:
            if os.fstat(temp).st_size != self.plan['bytes'] or _hash(final, 0, self.plan['bytes']) != self.plan['sha256']:
                _fail('unowned_target_exists')
            ledger['publication'] = {'method': 'link', 'identity': _identity(os.fstat(temp))}
            self._save(session, ledger)

    def _verify_publication(self, root, ledger):
        publication = ledger['publication']
        if publication is None:
            _fail('publication_missing')
        with _file(root, ledger['target_name'], identity=publication['identity'], private=True, links=(1, 2)) as fd:
            if os.fstat(fd).st_size != self.plan['bytes'] or _hash(fd, 0, self.plan['bytes']) != self.plan['sha256']:
                _fail('published_file_changed')
        return publication

    def _receipt(self, ledger):
        receipt = {'version': 1, 'state': 'published_verified', 'file_path': str(Path(self.output_dir) / ledger['target_name']),
                'bytes': self.plan['bytes'], 'sha256': self.plan['sha256'],
                'parts_verified': len(self.plan['parts']), 'whole_file_independently_reread': True,
                'zip_crc_checked': ledger.get('zip_crc_checked', False),
                'publication_method': ledger['publication']['method'], 'receiver_nonce': ledger['nonce'],
                'source_of_bytes': 'provided_materialized_local_part_paths',
                'network_used': False, 'base64_reconstruction': False,
                'receipt_path': str(Path(self.output_dir) / ('.native-range-receipt-' + ledger['nonce'] + '.json'))}
        if 'recovery_binding' in ledger:
            binding = ledger['recovery_binding']
            receipt['recovery'] = {'old_export_id': binding['old_export_id'],
                'new_export_id': binding['new_export_id'], 'old_receiver_nonce': binding['old_receiver_nonce'],
                'new_receiver_nonce': ledger['nonce'], 'reused_prefix_parts': binding['prefix_count'],
                'reused_prefix_bytes': binding['prefix_bytes'],
                'binding_sha256': hashlib.sha256(_encoded(binding)).hexdigest(),
                'mapping_path': str(Path(self.output_dir) / ('.native-range-recovery-' + ledger['nonce'] + '.json'))}
        return receipt

    def _persist_recovery(self, root, session, ledger):
        if 'recovery_binding' not in ledger:
            return None
        journal = self._recovery_journal(session, ledger)
        if ledger['state'] == 'published' and journal['state'] != 'ready':
            _fail('recovery_prefix_incomplete')
        name = '.native-range-recovery-' + ledger['nonce'] + '.json'
        value = {'version': 1, 'receiver_state': ledger['state'],
                 'original_complete': ledger['state'] == 'published',
                 'binding': ledger['recovery_binding'], 'journal': journal,
                 'native_input_aliases_not_removed': True}
        raw = _encoded(value)
        if len(raw) > LEDGER_LIMIT:
            _fail('control_too_large')
        if _exists(root, name):
            with _file(root, name, private=True) as fd:
                if os.read(fd, LEDGER_LIMIT + 1) != raw:
                    _fail('recovery_evidence_changed')
        else:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                _write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(root)
        return str(Path(self.output_dir) / name)

    def _persist_receipt(self, root, session, ledger):
        self._persist_recovery(root, session, ledger)
        receipt = self._receipt(ledger)
        raw = _encoded(receipt)
        # Keep the small proof after private temp/ledger cleanup. Never overwrite
        # an existing sidecar; an exact same receipt is the idempotent case.
        name = '.native-range-receipt-' + ledger['nonce'] + '.json'
        if _exists(root, name):
            with _file(root, name, private=True) as fd:
                if os.read(fd, LEDGER_LIMIT + 1) != raw:
                    _fail('receipt_exists_or_changed')
        else:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                _write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(root)
        return receipt

    def finish(self, *, require_zip=False):
        with self._locked() as (root, session, ledger):
            if 'recovery_binding' in ledger and self._recovery_journal(session, ledger)['state'] != 'ready':
                _fail('recovery_pending')
            self._recover_link(root, session, ledger)
            self._verify_temp(session, ledger)
            if ledger['state'] == 'published':
                self._verify_publication(root, ledger)
                return self._persist_receipt(root, session, ledger)
            if ledger['state'] not in ('receiving', 'publishing'):
                _fail('receiver_not_accepting')
            if ledger['pending'] is not None or len(ledger['accepted']) != len(self.plan['parts']):
                _fail('original_incomplete')
            with _file(session, 'receive.tmp', identity=ledger['file_identities']['receive.tmp'],
                       private=True, links=(1, 2) if ledger['publication'] else (1,)) as temp:
                if os.fstat(temp).st_size != self.plan['bytes'] or _hash(temp, 0, self.plan['bytes']) != self.plan['sha256']:
                    _fail('whole_file_hash_mismatch')
                if require_zip:
                    with os.fdopen(os.dup(temp), 'rb') as source, zipfile.ZipFile(source) as archive:
                        for member in archive.infolist():
                            checksum = count = 0
                            with archive.open(member) as source_part:
                                while block := source_part.read(BLOCK):
                                    count += len(block)
                                    checksum = zlib.crc32(block, checksum)
                            if count != member.file_size or checksum & 0xffffffff != member.CRC:
                                _fail('zip_crc_mismatch')
                    ledger['zip_crc_checked'] = True
                if ledger['publication'] is None:
                    if _exists(root, ledger['target_name']):
                        _fail('target_exists')
                    ledger['state'] = 'publishing'
                    self._save(session, ledger)
                    try:
                        os.link('receive.tmp', ledger['target_name'], src_dir_fd=session, dst_dir_fd=root,
                                follow_symlinks=False)
                        ledger['publication'] = {'method': 'link', 'identity': _identity(os.fstat(temp))}
                    except OSError as error:
                        if error.errno not in (errno.EXDEV, errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS):
                            raise
                        final = os.open(ledger['target_name'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                        0o600, dir_fd=root)
                        ledger['publication'] = {'method': 'xb_copy', 'identity': _identity(os.fstat(final))}
                        os.close(final)
                    self._save(session, ledger)
                if ledger['publication']['method'] == 'xb_copy':
                    with _file(root, ledger['target_name'], os.O_RDWR,
                               identity=ledger['publication']['identity'], private=True) as final:
                        copied = os.fstat(final).st_size
                        if not 0 <= copied <= self.plan['bytes']:
                            _fail('publication_length_changed')
                        self._compare_prefix(temp, final, 0, 0, copied)
                        os.lseek(final, copied, os.SEEK_SET)
                        while copied < self.plan['bytes']:
                            info = os.fstatvfs(root)
                            if info.f_bavail * info.f_frsize < self.plan['bytes'] - copied + CONTROL_RESERVE + ledger['min_free_bytes']:
                                _fail('insufficient_space')
                            block = os.pread(temp, min(BLOCK, self.plan['bytes'] - copied), copied)
                            if not block:
                                _fail('temporary_short_read')
                            _write(final, block)
                            copied += len(block)
                        os.fsync(final)
            os.fsync(root)
            self._verify_publication(root, ledger)
            ledger['state'] = 'published'
            self._save(session, ledger)
            receipt = self._persist_receipt(root, session, ledger)
            # Receipt is a small durable object, never a URL for incomplete data.
            name = 'receipt.json'
            if not _exists(session, name):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
                try:
                    _write(fd, _encoded(receipt)); os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(session)
            return receipt

    def status(self):
        with self._locked() as (root, session, ledger):
            self._verify_temp(session, ledger)
            result = {'state': ledger['state'], 'received_bytes': ledger['received_bytes'],
                'parts_verified': len(ledger['accepted']), 'part_count': len(self.plan['parts']),
                'pending_part_index': ledger['pending'], 'receiver_nonce': ledger['nonce']}
            if 'recovery_binding' in ledger:
                journal = self._recovery_journal(session, ledger)
                result['recovery'] = {'state': journal['state'],
                    'prefix_parts': ledger['recovery_binding']['prefix_count'],
                    'prefix_bytes': ledger['recovery_binding']['prefix_bytes'],
                    'aliases_committed': sum(row['phase'] == 'committed' for row in journal['aliases']),
                    'old_pending_part_excluded': ledger['recovery_binding']['old_pending_excluded']}
            if ledger['state'] == 'published':
                self._verify_publication(root, ledger)
                result['receipt'] = self._receipt(ledger)
            return result

    def cancel(self):
        with self._locked() as (root, session, ledger):
            self._verify_temp(session, ledger)
            if ledger['state'] == 'published':
                _fail('published_file_preserved')
            ledger['state'] = 'cancelled'
            self._save(session, ledger)
            return {'state': 'cancelled', 'receiver_nonce': ledger['nonce'],
                    'cleanup_required': True, 'published_file_removed': False}

    def cleanup(self):
        """Remove only this nonce's verified temp/control files; keep final/inputs."""
        with self._locked() as (root, session, ledger):
            self._verify_temp(session, ledger)
            if ledger['state'] not in ('cancelled', 'published'):
                _fail('cleanup_requires_cancel_or_publish')
            if ledger['publication']:
                if ledger['state'] == 'published':
                    self._verify_publication(root, ledger)
                else:
                    with _file(root, ledger['target_name'], identity=ledger['publication']['identity'],
                               private=True, links=(1, 2)) as final, _file(session, 'receive.tmp',
                               identity=ledger['file_identities']['receive.tmp'], private=True, links=(1, 2)) as temp:
                        length = os.fstat(final).st_size
                        if length > self.plan['bytes']:
                            _fail('publication_length_changed')
                        self._compare_prefix(temp, final, 0, 0, length)
                    os.unlink(ledger['target_name'], dir_fd=root)
                    os.fsync(root)
            names = set(os.listdir(session))
            allowed = {'receive.tmp', 'lock', 'ledger.json', 'receipt.json'}
            recovery_path = None
            if 'recovery_binding' in ledger:
                journal = self._recovery_journal(session, ledger)
                with _directory(self.input_root) as inputs:
                    for index, row in enumerate(journal['aliases']):
                        name = self.plan['parts'][index]['resource_name']
                        if row['phase'] == 'uncreated' and _exists(inputs, name):
                            _fail('recovery_alias_ownership_unconfirmed')
                        if row['phase'] != 'uncreated' and _exists(inputs, name):
                            with _file(inputs, name, identity=row['identity'], private=True) as alias:
                                count = os.fstat(alias).st_size
                                if not 0 <= count <= self.plan['parts'][index]['bytes']:
                                    _fail('recovery_alias_length_changed')
                                if row['phase'] in ('copied', 'committed') and (
                                        count != self.plan['parts'][index]['bytes']
                                        or _hash(alias, 0, count) != self.plan['parts'][index]['sha256']):
                                    _fail('recovery_alias_hash_mismatch')
                recovery_path = self._persist_recovery(root, session, ledger)
                allowed.add(RECOVERY_CONTROL)
            if not names <= allowed:
                _fail('unexpected_session_file')
            # Verify every control entry's exact identity/content before removal.
            with _file(session, 'ledger.json', private=True) as fd:
                if os.read(fd, LEDGER_LIMIT + 1) != _encoded(ledger):
                    _fail('ledger_changed')
            if 'receipt.json' in names:
                with _file(session, 'receipt.json', private=True) as fd:
                    if os.read(fd, LEDGER_LIMIT + 1) != _encoded(self._receipt(ledger)):
                        _fail('receipt_changed')
            if RECOVERY_CONTROL in names:
                with _file(session, RECOVERY_CONTROL, private=True) as fd:
                    if os.read(fd, LEDGER_LIMIT + 1) != _encoded(journal):
                        _fail('recovery_journal_changed')
            for name in ('receipt.json', RECOVERY_CONTROL, 'receive.tmp', 'ledger.json', 'lock'):
                if name in names:
                    os.unlink(name, dir_fd=session)
            os.fsync(session)
        with _directory(self.output_dir) as root:
            info = os.stat(self.session_name, dir_fd=root, follow_symlinks=False)
            if _identity(info) != ledger['session_identity']:
                _fail('session_binding_changed')
            os.rmdir(self.session_name, dir_fd=root)
            os.fsync(root)
        result = {'state': 'own_temporary_files_removed', 'receiver_nonce': ledger['nonce'],
                  'final_and_materialized_inputs_preserved': True}
        if recovery_path is not None:
            result.update(recovery_mapping_path=recovery_path, recovery_aliases_not_removed=True)
        return result
