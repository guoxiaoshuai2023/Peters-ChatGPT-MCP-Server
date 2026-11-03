"""Explicit local-operator bootstrap. Never register this module as an MCP tool."""
import argparse
import os
from pathlib import Path
import stat

from .catalog import AccessError, Catalog
from .file_config import read_file_config, bind_registry, validate_infrastructure_scope
from .private_roots import _directory, _close


def bootstrap_file_service(path, catalog, history=None):
    """Initialize only configured control/spool roots after complete scope checks.

    Existing initialized state is validated, never reset. Existing broad-permission
    directories are rejected, not chmod'ed. Parent infrastructure must exist; this
    function does not recursively manufacture new infrastructure locations.
    """
    config = read_file_config(path)
    validate_infrastructure_scope(config, catalog, history)
    control = config.control_directory
    parent = _directory(control.parent)
    try:
        created = False
        try:
            os.mkdir(control.name, 0o700, dir_fd=parent)
            created = True
            os.fsync(parent)
        except FileExistsError:
            pass
        fd = os.open(control.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise AccessError('Control directory must be owner-only; existing permissions were not changed.',
                                  code='private_protection_unavailable')
            entries = set(os.listdir(fd))
            initialized = {'private-roots.json', 'private-roots.lock'} <= entries
            if not initialized and (entries or not created):
                raise AccessError('Existing control state is incomplete or unrelated; it cannot be reset.',
                                  code='private_protection_unavailable')
        finally:
            _close(fd)
    finally:
        _close(parent)
    registry = bind_registry(config, catalog)
    if not initialized:
        registry.initialize()
    with registry.read_guard() as guard:
        # Removed configuration entries retain their private data/protection;
        # they also remain subject to bootstrap's history/read-root isolation.
        retained = tuple(Path(row['path']) for row in guard._manifest['roots'])
    validate_infrastructure_scope(config, catalog, history, retained_roots=retained)
    for root in config.spool_roots:
        roots = validate_infrastructure_scope(config, catalog, history, retained_roots=retained)
        registry.register_pending(root, read_roots=roots)
        # Catalog is bound to the same persistent registry before activation.
        # Other active processes must use this same anchor per its contract.
        roots = validate_infrastructure_scope(config, catalog, history, retained_roots=retained)
        registry.activate(root, read_roots=roots)
    return registry


def main():
    parser = argparse.ArgumentParser(description='Explicit local original-file private-root bootstrap.')
    parser.add_argument('--file-config', type=Path, required=True)
    parser.add_argument('--projects-config', type=Path, required=True)
    parser.add_argument('--history-config', type=Path)
    args = parser.parse_args()
    try:
        catalog = Catalog.from_config(args.projects_config)
        history = None
        if args.history_config is not None:
            from .history import HistoryAccess
            history = HistoryAccess(args.history_config, catalog.projects, catalog=catalog)
        bootstrap_file_service(args.file_config, catalog, history)
    except (AccessError, OSError, ValueError):
        parser.exit(1, 'Bootstrap could not verify private infrastructure; no existing state was reset.\n')
    print('Private infrastructure initialized and verified. No file-save worker was started.')


if __name__ == '__main__':
    main()
