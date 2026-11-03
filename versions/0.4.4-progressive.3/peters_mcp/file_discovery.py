"""Current authorized source metadata and bounded, process-local discovery.

Only synchronous owners enter the private protection guard. The shared manager
lock protects cache ownership/accounting, never filesystem or policy callbacks.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
import hashlib
import hmac
import json
import mimetypes
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time

from .catalog import (AccessError, AUTH_PATHS, BLOCKED_NAMES, BLOCKED_PATTERNS,
                      Catalog, MAX_FILE_BYTES, SEARCH_SKIP_NAMES)
from .file_context import ExportActor
from .file_targets import CODEX_FIXED
from .private_roots import _directory, _key

_POLICY = 'original-export-sources-v2'
_CODEX = CODEX_FIXED | {'state_5.sqlite-journal'}
_DB_SIDECARS = tuple((*path[:-1], path[-1] + suffix)
                     for path in AUTH_PATHS if path[-1].endswith('.db')
                     for suffix in ('-wal', '-shm', '-journal'))
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_SKIP = frozenset(SEARCH_SKIP_NAMES) - {'dist', 'build'}
_CACHE_OVERHEAD = 2048  # Record, cursor id, scope/actor hashes and coverage envelope.


def _error(code, message='The authorized source is unavailable.'):
    return AccessError(message, code=code)


def _fixed_path(path):
    """A selected root cannot strip a fixed sensitive ancestor from policy."""
    parts = tuple(part.casefold() for part in Path(path).parts)
    for index, part in enumerate(parts):
        prefix = parts[:index + 1]
        if (part in BLOCKED_NAMES or any(fnmatchcase(part, p) for p in BLOCKED_PATTERNS)
                or (part == '.env' or part.startswith('.env.')) and
                   not part.endswith(('.example', '.sample', '.template', '.md'))
                or index and parts[index - 1] == '.codex' and part in _CODEX
                or any(len(prefix) >= len(p) and prefix[-len(p):] == p
                       for p in (*AUTH_PATHS, *_DB_SIDECARS))):
            raise _error('sensitive_source', 'Runtime and credential state is excluded.')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':')).encode()).hexdigest()


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def _close_owned(fd):
    # close errors can leave descriptor state uncertain. Never retry that integer:
    # it may already have been closed/reused. The caller's auxiliary owner keeps
    # its reservation and closes new admission until actual process recovery.
    try:
        os.close(fd)
    except OSError:
        raise _error('source_cleanup_pending', 'Source handle cleanup could not be confirmed.') from None


@dataclass(frozen=True)
class SourceRef:
    project_id: str
    worktree_id: str
    path: str
    root_identity: tuple
    repository_id: str | None
    policy_version: str
    scope_key: str
    size: int
    version: tuple
    mime_type: str
    mime_basis: str = 'filename_guess'

    def public(self):
        return {'project_id': self.project_id, 'worktree_id': self.worktree_id,
                'path': self.path, 'type': 'file', 'bytes': self.size,
                'version': self.version, 'modified_ns': self.version[3],
                'mime_type': self.mime_type, 'mime_basis': self.mime_basis,
                'text_read_supported': self.size <= MAX_FILE_BYTES and Catalog.is_text(self.path)}


class FileSources:
    def __init__(self, catalog, *, protected_paths=(), policy_check=None,
                 wall_clock=time.time, monotonic=time.monotonic):
        self.catalog, self.policy_check = catalog, policy_check
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self.protected_paths = tuple(Path(p) for p in protected_paths)
        self._retained_aliases = self._aliases(self.protected_paths)

    @staticmethod
    def _aliases(paths):
        try:
            aliases = set()
            for path in paths:
                path = Path(path)
                if not path.is_absolute() or '..' in path.parts:
                    raise _error('private_protection_unavailable')
                aliases.update((_key(path), _key(path.resolve())))
            return frozenset(aliases)
        except (OSError, RuntimeError, ValueError):
            raise _error('private_protection_unavailable') from None

    def _actor(self, actor):
        if not isinstance(actor, ExportActor):
            raise _error('authentication_required')
        actor.check(wall_clock=self.wall_clock, monotonic=self.monotonic)

    def _protected(self, path):
        paths = self.protected_paths
        if self.catalog._config_path is not None:
            paths += (self.catalog._config_path,)
        protected = self._retained_aliases | self._aliases(paths)
        try:
            aliases = (_key(Path(path)), _key(Path(path).resolve()))
            if any(key[:len(root)] == root for key in aliases for root in protected):
                raise _error('private_path', 'Service-owned state is excluded.')
        except AccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise _error('private_protection_unavailable') from None

    def _snapshot(self, actor, project_id, worktree_id, guard):
        self._actor(actor)
        if not isinstance(project_id, str) or not project_id or not isinstance(worktree_id, str) or not worktree_id:
            raise _error('access_denied', 'Select an explicit project and worktree.')
        health = guard.revalidate()
        if self.policy_check is None:
            external = _POLICY
        else:
            try:
                external = self.policy_check()
            except AccessError:
                raise
            except Exception:
                raise _error('private_protection_unavailable') from None
            if not isinstance(external, str) or not 1 <= len(external) <= 256:
                raise _error('private_protection_unavailable')
        with self.catalog._refresh_lock:
            try:
                self.catalog.refresh()
                project = self.catalog.projects.get(project_id)
                if project is None:
                    raise _error('access_denied')
                discovered = self.catalog.repositories.discover(project_id)
                member = next((w for w in discovered['worktrees'] if w['id'] == worktree_id), None)
                if member is None or member['state'] != 'valid':
                    raise _error('scope_changed')
                root = Path(member['root'])
                _fixed_path(root)
                identity = tuple(member['root_identity'])
                read_project = replace(project, root=root, root_identity=identity)
                self.catalog.parts(read_project, '', allow_root=True)
                self._protected(root)
                policy = _digest([_POLICY, external, self.catalog._config_digest,
                                  project.exclude, project.allow_hidden,
                                  sorted(self._retained_aliases | self._aliases(self.protected_paths))])
                scope = _digest([project_id, worktree_id, str(root), identity,
                                 member['repository_id'], discovered['fingerprint'], policy, health])
                return read_project, member['repository_id'], policy, scope
            except AccessError:
                raise
            except (OSError, RuntimeError, ValueError, KeyError, TypeError):
                raise _error('scope_changed') from None

    @contextmanager
    def scope(self, actor, project_id, worktree_id):
        self._actor(actor)
        registry = self.catalog._private_registry
        if registry is None:
            raise _error('private_protection_unavailable')
        with registry.read_guard() as guard:
            data = self._snapshot(actor, project_id, worktree_id, guard)
            view = SourceScope(self, actor, project_id, worktree_id, guard, data)
            try:
                yield view
                view.revalidate()
            finally:
                view._closed = True


class SourceScope:
    """A view borrowed only for the lifetime/thread of its source guard."""
    def __init__(self, sources, actor, project_id, worktree_id, guard, data):
        self.sources, self.actor, self.guard = sources, actor, guard
        self.project_id, self.worktree_id = project_id, worktree_id
        self.project, self.repository_id, self.policy_version, self.scope_key = data
        self.root, self.root_identity = self.project.root, self.project.root_identity
        self._thread = threading.get_ident()
        self._closed = False

    def _owner(self):
        if self._closed or threading.get_ident() != self._thread:
            raise _error('private_protection_unavailable')
        self.sources._actor(self.actor)
        self.guard.check_path(self.root)

    def revalidate(self):
        self._owner()
        current = self.sources._snapshot(self.actor, self.project_id, self.worktree_id, self.guard)
        if current[3] != self.scope_key:
            raise _error('scope_changed')
        return self.scope_key

    def _parts(self, relative, allow_root=False):
        self._owner()
        parts = self.sources.catalog.parts(self.project, relative, allow_root=allow_root)
        _fixed_path(self.root.joinpath(*parts))
        for index, part in enumerate(parts):
            if any(ord(c) == 127 for c in part):
                raise _error('access_denied')
            self.sources._protected(self.root.joinpath(*parts[:index + 1]))
        return parts

    @contextmanager
    def _open(self, relative, directory):
        parts = self._parts(relative, allow_root=directory)
        fd = None
        opened = False
        try:
            fd = _directory(self.root)
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.root_identity:
                raise _error('scope_changed')
            for index, part in enumerate(parts):
                self._owner()
                target = self.root.joinpath(*parts[:index + 1])
                self.guard.check_path(target)
                self.sources._protected(target)
                is_directory = directory or index < len(parts) - 1
                child = os.open(part, _DIR_FLAGS if is_directory else _FILE_FLAGS, dir_fd=fd)
                previous = fd
                fd = child
                _close_owned(previous)
                if is_directory:
                    try:
                        os.stat('.git', dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise _error('nested_member_required', 'Select the nested worktree explicitly.')
            if not directory:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise _error('unsupported_source_type')
            opened = True
            yield fd
        except OSError:
            # A caller's snapshot write/fsync/read is outside source opening.
            # Preserve its errno (especially ENOSPC) for the owning operation.
            if opened:
                raise
            raise _error('source_unavailable') from None
        finally:
            if fd is not None:
                owned, fd = fd, None
                _close_owned(owned)

    def open_directory(self, relative=''):
        return self._open(relative, True)

    def open_file(self, relative):
        return self._open(relative, False)

    def inspect(self, relative):
        parts = self._parts(relative)
        with self.open_directory('/'.join(parts[:-1])) as parent:
            try:
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _error('source_unavailable') from None
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise _error('unsupported_source_type')
        return SourceRef(self.project_id, self.worktree_id, '/'.join(parts), self.root_identity,
                         self.repository_id, self.policy_version, self.scope_key, info.st_size,
                         _version(info), mimetypes.types_map.get(Path(relative).suffix.lower(),
                                                               'application/octet-stream'))


@dataclass
class _Cache:
    actor: str
    query: tuple
    scope_key: str
    expires: float
    owners: int = 1
    rows: tuple = ()
    coverage: dict | None = None
    ready: bool = False
    retired: bool = False
    charge: int = 0


class FileDiscovery:
    def __init__(self, sources, *, lock, instance_id, monotonic=time.monotonic,
                 capabilities=None, max_seconds=10, max_entries=10000,
                 max_caches=4, max_actor_caches=2, cache_ttl=120,
                 max_cache_bytes=2 * 1024 * 1024, max_total_bytes=8 * 1024 * 1024):
        limits = (max_seconds, max_entries, max_caches, max_actor_caches,
                  cache_ttl, max_cache_bytes, max_total_bytes)
        if any(type(n) not in (int, float) or not 0 < n < float('inf') for n in limits):
            raise ValueError('Discovery limits must be finite and positive.')
        if any(type(n) is not int for n in (max_entries, max_caches, max_actor_caches,
                                          max_cache_bytes, max_total_bytes)):
            raise ValueError('Discovery count/byte limits must be integers.')
        self.sources, self.lock, self.instance_id = sources, lock, instance_id
        self.monotonic, self.capabilities = monotonic, capabilities
        self.max_seconds, self.max_entries = max_seconds, max_entries
        self.max_caches, self.max_actor_caches = max_caches, max_actor_caches
        self.cache_ttl, self.max_cache_bytes, self.max_total_bytes = cache_ttl, max_cache_bytes, max_total_bytes
        self._secret, self._caches, self._closed = secrets.token_bytes(32), {}, False

    @staticmethod
    def _query(project, worktree, directory, pattern, extensions, limit):
        if (not isinstance(directory, str) or len(directory) > 4096
                or not isinstance(pattern, str) or not 1 <= len(pattern) <= 128
                or any(c in pattern for c in '/\\') or any(ord(c) < 32 or ord(c) == 127 for c in pattern)
                or type(limit) is not int or not 1 <= limit <= 200):
            raise _error('access_denied', 'Invalid bounded discovery query.')
        if extensions is None:
            suffixes = ()
        else:
            if not isinstance(extensions, (list, tuple)) or len(extensions) > 32:
                raise _error('access_denied', 'Invalid extension filters.')
            if any(not isinstance(e, str) or not 2 <= len(e) <= 32 or not e.startswith('.')
                   or any(c in e for c in '/\\') or any(ord(c) < 32 or ord(c) == 127 for c in e)
                   for e in extensions):
                raise _error('access_denied', 'Invalid extension filters.')
            suffixes = tuple(sorted({e.casefold() for e in extensions}))
        return project, worktree, '' if directory == '.' else directory, pattern, suffixes, limit

    def _drop(self, cache_id):
        record = self._caches.get(cache_id)
        if record is not None and record.retired and not record.owners:
            del self._caches[cache_id]

    def _reap(self, now):
        for cache_id, record in list(self._caches.items()):
            if record.expires <= now:
                record.retired = True
            self._drop(cache_id)

    def _reserve(self, actor, query, scope_key):
        with self.lock:
            self._reap(self.monotonic())
            if self._closed:
                raise _error('discovery_cursor_unavailable')
            records = self._caches.values()
            if (len(self._caches) >= self.max_caches
                    or sum(c.actor == actor.key for c in records) >= self.max_actor_caches
                    or sum(c.charge for c in self._caches.values()) + self.max_cache_bytes > self.max_total_bytes):
                raise _error('busy', 'Discovery cache budget is occupied; retry after expiry.')
            cache_id = secrets.token_hex(16)
            record = _Cache(actor.key, query, scope_key, self.monotonic() + self.cache_ttl,
                            charge=self.max_cache_bytes)
            self._caches[cache_id] = record
            return cache_id, record

    def _cursor(self, cache_id, offset):
        payload = f'{cache_id}.{offset:x}'
        signature = hmac.new(self._secret, (str(self.instance_id) + '/' + payload).encode(), hashlib.sha256).hexdigest()
        return payload + '.' + signature

    def _acquire(self, actor, query, cursor):
        try:
            if not isinstance(cursor, str) or len(cursor) > 110:
                raise ValueError()
            cache_id, offset, signature = cursor.split('.')
            index = int(offset, 16)
            if not hmac.compare_digest(cursor, self._cursor(cache_id, index)):
                raise ValueError()
        except (ValueError, TypeError):
            raise _error('discovery_cursor_unavailable') from None
        with self.lock:
            self._reap(self.monotonic())
            record = self._caches.get(cache_id)
            if (self._closed or record is None or record.retired or not record.ready
                    or record.actor != actor.key or record.query != query
                    or not 0 <= index < len(record.rows)):
                raise _error('discovery_cursor_unavailable')
            record.owners += 1
            return cache_id, record, index

    def _scan(self, view, query):
        _, _, directory, pattern, suffixes, _ = query
        pending, rows = [directory], []
        pending_bytes = sys.getsizeof(directory) + 8
        scanned, total, skipped = 0, len(json.dumps(query).encode()) + _CACHE_OVERHEAD, 0
        if total + pending_bytes > self.max_cache_bytes:
            raise _error('resource_budget_exhausted')
        reasons, stopped = {}, None
        start, checked = self.monotonic(), self.monotonic()
        while pending and stopped is None:
            current = pending.pop()
            pending_bytes -= sys.getsizeof(current) + 8
            try:
                with view.open_directory(current) as fd, os.scandir(fd) as entries:
                    for entry in entries:
                        now = self.monotonic()
                        if now - start >= self.max_seconds:
                            stopped = 'time_limit'; break
                        if scanned >= self.max_entries:
                            stopped = 'entry_limit'; break
                        if now - checked >= 1:
                            view.revalidate(); checked = self.monotonic()
                        scanned += 1
                        relative = '/'.join(filter(None, (current, entry.name)))
                        try:
                            view._parts(relative)
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                if entry.name.casefold() in _SKIP:
                                    skipped += 1; reasons['dependency_cache'] = reasons.get('dependency_cache', 0) + 1
                                else:
                                    # Test boundary before queuing; close the child now.
                                    with view.open_directory(relative):
                                        pass
                                    charge = sys.getsizeof(relative) + 8
                                    if total + pending_bytes + charge > self.max_cache_bytes:
                                        stopped = 'cache_byte_limit'; break
                                    pending.append(relative)
                                    pending_bytes += charge
                            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                                if fnmatchcase(entry.name, pattern) and (not suffixes or Path(entry.name).suffix.casefold() in suffixes):
                                    encoded = json.dumps(view.inspect(relative).public(), ensure_ascii=True,
                                                         separators=(',', ':')).encode()
                                    charge = sys.getsizeof(encoded) + 8
                                    if total + pending_bytes + charge > self.max_cache_bytes:
                                        stopped = 'cache_byte_limit'; break
                                    rows.append(encoded); total += charge
                            else:
                                skipped += 1; reasons['special_or_linked'] = reasons.get('special_or_linked', 0) + 1
                        except AccessError as exc:
                            if (exc.code.startswith('private_') and exc.code != 'private_path'
                                    or exc.code in ('scope_changed', 'authentication_required',
                                                    'source_cleanup_pending', 'protection_cleanup_pending')):
                                raise
                            if exc.code == 'nested_member_required':
                                skipped += 1; reasons['repository_boundary'] = reasons.get('repository_boundary', 0) + 1
                            elif exc.code == 'source_unavailable':
                                skipped += 1; reasons['unavailable'] = reasons.get('unavailable', 0) + 1
                            # Fixed policy exclusions are outside the authorized scan.
                        except OSError:
                            skipped += 1; reasons['unavailable'] = reasons.get('unavailable', 0) + 1
            except AccessError as exc:
                if current == directory or exc.code not in ('source_unavailable', 'nested_member_required'):
                    raise
                reason = 'repository_boundary' if exc.code == 'nested_member_required' else 'unavailable'
                skipped += 1; reasons[reason] = reasons.get(reason, 0) + 1
        return tuple(rows), total, {'scan_complete': stopped is None and skipped == 0,
                                   'stopped_reason': stopped, 'skipped': skipped,
                                   'skipped_reasons': reasons, 'entries_scanned': scanned}

    def _page(self, view, cache_id, record, index, limit):
        with self.lock:
            if self._closed or record.retired or record.expires <= self.monotonic():
                raise _error('discovery_cursor_unavailable')
            rows = record.rows[index:index + limit]
            coverage = dict(record.coverage)
        files = []
        for encoded in rows:
            captured = json.loads(encoded)
            current = view.inspect(captured['path'])
            captured['text_read_supported'] = current.public()['text_read_supported']
            if self.capabilities is not None:
                extra = self.capabilities(current)
                if not isinstance(extra, dict) or len(json.dumps(extra).encode()) > 4096:
                    raise _error('private_protection_unavailable')
                captured.update(extra)
            files.append(captured)
        view.revalidate()
        end = index + len(rows)
        more = end < len(record.rows)
        return {'files': files, **coverage, 'has_more': more,
                'next_cursor': self._cursor(cache_id, end) if more else None,
                'metadata_basis': 'captured_stat',
                'note': 'A partial scan does not prove absence. A cursor pages only the captured bounded results; source bytes remain live.'}

    def find(self, actor, project_id, worktree_id, directory='', name_pattern='*', extensions=None,
             limit=50, cursor=''):
        if not isinstance(actor, ExportActor):
            raise _error('authentication_required')
        if not isinstance(cursor, str):
            raise _error('discovery_cursor_unavailable')
        query = self._query(project_id, worktree_id, directory, name_pattern, extensions, limit)
        cache_id = record = None
        index = 0
        try:
            if cursor:
                cache_id, record, index = self._acquire(actor, query, cursor)
            with self.sources.scope(actor, project_id, worktree_id) as view:
                if record is None:
                    # Invalid source directories cannot consume or evict cache slots.
                    with view.open_directory(directory):
                        pass
                    cache_id, record = self._reserve(actor, query, view.scope_key)
                    rows, charge, coverage = self._scan(view, query)
                    with self.lock:
                        if self._closed or record.retired or record.expires <= self.monotonic():
                            raise _error('discovery_cursor_unavailable')
                        record.rows, record.charge, record.coverage, record.ready = rows, charge, coverage, True
                elif view.scope_key != record.scope_key:
                    raise _error('scope_changed')
                result = self._page(view, cache_id, record, index, limit)
            with self.lock:
                if self._closed or record.retired or record.expires <= self.monotonic():
                    raise _error('discovery_cursor_unavailable')
                if not cursor and not result['has_more']:
                    record.retired = True
            return result
        except Exception:
            if record is not None:
                with self.lock:
                    record.retired = True
            raise
        finally:
            if record is not None:
                with self.lock:
                    record.owners -= 1
                    self._drop(cache_id)

    def reap(self):
        with self.lock:
            before = len(self._caches)
            self._reap(self.monotonic())
            return before - len(self._caches)

    def close(self):
        with self.lock:
            self._closed = True
            for cache_id, record in list(self._caches.items()):
                record.retired = True
                self._drop(cache_id)
            return self.diagnostics()

    def diagnostics(self):
        with self.lock:
            return {'cache_count': len(self._caches), 'cache_bytes': sum(c.charge for c in self._caches.values()),
                    'cache_owners': sum(c.owners for c in self._caches.values()), 'closed': int(self._closed)}
