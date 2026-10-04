"""Explicit original-file service configuration; loading never bootstraps roots.

Only a caller-provided path enables this loader. No default filenames, candidate
settings or old ZIP settings are discovered. Disabled/inspection mode retains
protection and reads existing job metadata without constructing a writer.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import re
import stat

from .catalog import AccessError
from .file_source import _HOST, _public_address, SourceError
from .private_roots import PrivateRootRegistry, _canonical, _directory, _key, _overlap, _close

_FIELDS = {'version', 'enabled', 'control_directory', 'spool_roots', 'sources',
           'special_exceptions', 'min_free_bytes', 'max_workers'}
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z')


def _error(code='file_config_invalid'):
    return AccessError('Original-file configuration is invalid or unavailable; no new writes are enabled.', code=code)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate configuration field')
        value[key] = item
    return value


@dataclass(frozen=True)
class FileConfig:
    path: Path
    enabled: bool
    control_directory: Path
    spool_roots: tuple[Path, ...]
    sources_map: dict
    special_exceptions: tuple[tuple[str, str, str], ...]
    min_free_bytes: int
    max_workers: int

    def sources(self, *, require_enabled=True):
        current = read_file_config(self.path)
        if require_enabled and not current.enabled:
            raise _error('write_not_enabled')
        # Exact provider additions do not revoke a frozen target. Infrastructure,
        # special exceptions or limits require coordinated reconfiguration instead
        # of silently retaining the old policy inside an active service.
        if replace(current, sources_map={}, enabled=self.enabled) != replace(self, sources_map={}):
            raise _error('file_config_changed')
        return {host: list(addresses) if addresses is not None else None
                for host, addresses in current.sources_map.items()}


def read_file_config(path):
    """Strict bounded read. Does not mkdir, chmod, initialize SQL or open secrets."""
    fd = None
    try:
        path = _canonical(Path(path).expanduser().absolute())
        parent = _directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            _close(parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid()
                or before.st_mode & 0o022 or before.st_size > 65536):
            raise ValueError()
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(fd, min(65537 - len(raw), 8192))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        current = path.lstat()
        def version(info):
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink
        if len(raw) != before.st_size or len(raw) > 65536 or version(before) != version(after) or version(current) != version(after):
            raise ValueError()
        data = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(data, dict) or set(data) != _FIELDS or type(data['version']) is not int
                or data['version'] != 1 or type(data['enabled']) is not bool):
            raise ValueError()
        if not isinstance(data['control_directory'], str):
            raise ValueError()
        control = _canonical(data['control_directory'])
        raw_roots = data['spool_roots']
        if not isinstance(raw_roots, list) or len(raw_roots) > 64 or any(not isinstance(p, str) for p in raw_roots):
            raise ValueError()
        roots = tuple(_canonical(p) for p in raw_roots)
        keys = [_key(control), *(_key(p) for p in roots)]
        if any(_overlap(a, b) for i, a in enumerate(keys) for b in keys[i + 1:]):
            raise ValueError()
        sources = data['sources']
        if not isinstance(sources, dict) or len(sources) > 64:
            raise ValueError()
        sources_map = {}
        for host, addresses in sources.items():
            if not isinstance(host, str) or not _HOST.fullmatch(host):
                raise ValueError()
            if addresses is None:
                sources_map[host] = None
            else:
                if (not isinstance(addresses, list) or not 1 <= len(addresses) <= 32
                        or any(not isinstance(address, str) for address in addresses)):
                    raise ValueError()
                sources_map[host] = tuple(sorted({_public_address(address) for address in addresses}))
        exceptions = data['special_exceptions']
        if not isinstance(exceptions, list) or len(exceptions) > 128:
            raise ValueError()
        triples = []
        for entry in exceptions:
            if not isinstance(entry, dict) or set(entry) != {'project_id', 'worktree_id', 'path'}:
                raise ValueError()
            project, worktree, relative = entry['project_id'], entry['worktree_id'], entry['path']
            if (not isinstance(project, str) or not _ID.fullmatch(project)
                    or not isinstance(worktree, str) or not _ID.fullmatch(worktree)
                    or not isinstance(relative, str) or not 1 <= len(relative) <= 4096
                    or any(not part or part in {'.', '..'} or '\\' in part
                           or any(ord(c) < 32 or ord(c) == 127 for c in part) for part in relative.split('/'))):
                raise ValueError()
            triples.append((project, worktree, relative))
        if len(set(triples)) != len(triples):
            raise ValueError()
        minimum, workers = data['min_free_bytes'], data['max_workers']
        if (type(minimum) is not int or not 0 <= minimum <= 2 ** 63 - 1
                or type(workers) is not int or not 1 <= workers <= 4):
            raise ValueError()
        return FileConfig(path, data['enabled'], control, roots, sources_map,
                          tuple(triples), minimum, workers)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, SourceError) as error:
        if isinstance(error, AccessError) and error.code in {'source_cleanup_pending', 'protection_cleanup_pending'}:
            raise
        raise _error() from None
    finally:
        if fd is not None:
            _close(fd)


def read_scope_roots(catalog, history=None):
    """Collect paths only, without loading project contents or history records."""
    catalog.refresh()
    roots = {Path(project.root) for project in catalog.projects.values()}
    for snapshot in catalog.repositories.discover_all().values():
        if any(entry['is_default'] and entry['state'] != 'valid' for entry in snapshot['worktrees']):
            raise _error('scope_unverifiable')
        roots.update(Path(entry['root']) for entry in snapshot['worktrees'] if entry['state'] == 'valid')
    if history is not None:
        home = history._configuration().get('home')
        if home is not None:
            roots.add(Path(home))
    return tuple(roots)


def validate_infrastructure_scope(config, catalog, history=None, *, retained_roots=()):
    roots = read_scope_roots(catalog, history)
    if history is not None:
        home = history._configuration().get('home')
        if home is not None and _overlap(_key(config.path), _key(home)):
            raise _error('private_root_overlap')
    for private in (config.control_directory, *config.spool_roots, *retained_roots):
        if any(_overlap(_key(private), _key(alias)) for root in roots for alias in (root, root.resolve())):
            raise _error('private_root_overlap')
    return roots


class _ConfigGuard:
    def __init__(self, guard, config_path):
        self._guard, self._config_path = guard, config_path

    def __getattr__(self, name):
        return getattr(self._guard, name)

    def check_path(self, path):
        self._guard.check_path(path)
        _check_config_path(path, self._config_path)

    def assert_isolated_tree(self, path):
        self._guard.assert_isolated_tree(path)
        for alias in (Path(path).absolute(), Path(path).resolve()):
            if _overlap(_key(alias), _key(self._config_path)):
                raise AccessError('The separate reader overlaps protected service configuration.', code='private_path')


def _check_config_path(path, config_path):
    target = _key(config_path)
    for alias in (Path(path).absolute(), Path(path).resolve()):
        key = _key(alias)
        if key[:len(target)] == target:
            raise AccessError('Service configuration is a fixed protected path.', code='private_path')


class ConfiguredRegistry:
    """PrivateRootRegistry-compatible binding that also protects the config file."""
    def __init__(self, registry, config_path):
        self.registry, self.config_path = registry, Path(config_path)

    def __getattr__(self, name):
        return getattr(self.registry, name)

    @contextmanager
    def read_guard(self):
        with self.registry.read_guard() as guard:
            yield _ConfigGuard(guard, self.config_path)

    def check_path(self, path):
        self.registry.check_path(path)
        _check_config_path(path, self.config_path)


def bind_registry(config, catalog):
    existing = getattr(catalog, '_private_registry', None)
    if existing is not None:
        if (not isinstance(existing, ConfiguredRegistry) or existing.config_path != config.path
                or existing.control_dir != config.control_directory
                or existing.allowed_roots != frozenset(config.spool_roots)):
            raise _error('private_protection_unavailable')
        return existing
    registry = ConfiguredRegistry(PrivateRootRegistry(config.control_directory,
                                                      allowed_roots=config.spool_roots), config.path)
    catalog.set_private_registry(registry)
    return registry


def _release_mode():
    try:
        from ._file_release_mode import INSPECTION_ONLY, REQUIRE_PRIVATE_CONFIG
    except ImportError:
        raise _error('file_release_mode_unavailable') from None
    if type(INSPECTION_ONLY) is not bool or type(REQUIRE_PRIVATE_CONFIG) is not bool:
        raise _error('file_release_mode_unavailable')
    return INSPECTION_ONLY, REQUIRE_PRIVATE_CONFIG


def _make_writer(*args, **kwargs):
    from .file_jobs import FileSaveService
    return FileSaveService(*args, **kwargs)


def _make_inspector(*args, **kwargs):
    from .file_jobs import FileSaveInspector
    return FileSaveInspector(*args, **kwargs)


def load_file_service(path, catalog, history=None, inspection_only=False):
    """Startup-only loader. Missing explicit path means no new tools or discovery.

    Inspection/disabled/rollback construction does not create or migrate SQL, take
    writer ownership, start workers, create roots, or change existing permissions.
    A missing/corrupt protection manifest is a startup error, never a reset signal.
    """
    release_inspection, require_config = _release_mode()
    if path is None:
        if require_config:
            raise _error('private_config_required')
        return None, None
    config = read_file_config(path)
    inspect = bool(inspection_only or release_inspection or not config.enabled)
    registry = bind_registry(config, catalog)
    with registry.read_guard():
        pass
    # Bootstrap enforces repo/worktree separation. History isolation must remain
    # verifiable on each startup, including rollback/history-only operation.
    protected_paths = [config.path]
    if history is not None:
        if getattr(history, 'config_path', None) is not None:
            protected_paths.append(Path(history.config_path))
        home = history._configuration().get('home')
        if home is not None:
            with registry.read_guard() as guard:
                guard.assert_isolated_tree(home)
            protected_paths.append(Path(home))
    sources = lambda: config.sources(require_enabled=not inspect)
    common = dict(special_exceptions=config.special_exceptions, protected_paths=tuple(protected_paths))
    if inspect:
        service = _make_inspector(catalog, registry, config.control_directory, sources, **common)
    else:
        service = _make_writer(catalog, registry, config.control_directory, sources,
                               min_free_bytes=config.min_free_bytes, max_workers=config.max_workers, **common)
    return registry, service
