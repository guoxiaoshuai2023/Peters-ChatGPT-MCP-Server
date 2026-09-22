"""Explicit package-write targets, separate from repository read/candidate grants."""

from contextlib import contextmanager
from dataclasses import asdict, fields, replace
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

from .catalog import AccessError, private_path_key
from .delivery_types import DeliveryLimits, DeliveryTarget

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


class DeliveryPolicy:
    def __init__(self, path, catalog):
        self.path = Path(path)
        self.catalog = catalog
        self._state_directory = self._load()[1]
        self.catalog.protect_private_tree(self._state_directory)

    @property
    def state_directory(self):
        current = self._load()[1]
        if current != self._state_directory:
            raise AccessError("Package state location changed; restart after reviewing configuration.",
                              code="delivery_policy_changed")
        return current

    def _load(self):
        try:
            self.catalog.refresh()
            if self.path.is_symlink():
                raise ValueError()
            raw = self.path.read_bytes()
            if len(raw) > 65536:
                raise ValueError()
            data = json.loads(raw)
            if (not isinstance(data, dict) or set(data) != {'version', 'state_directory', 'targets', 'sources', 'limits'}
                    or type(data['version']) is not int or data['version'] != 1):
                raise ValueError()
            state = Path(data['state_directory']).expanduser()
            read_roots = {p.root for p in self.catalog.projects.values()}
            for snapshot in self.catalog.repositories.discover_all().values():
                read_roots.update(Path(w['root']) for w in snapshot['worktrees'] if w['state'] == 'valid')
            state_key = private_path_key(state)
            root_keys = [private_path_key(root) for root in read_roots]
            if (not state.is_absolute() or state.is_symlink() or state.resolve() != state or
                    state in (Path('/'), Path.home()) or
                    any(state_key[:len(root)] == root or root[:len(state_key)] == state_key for root in root_keys)):
                raise ValueError()
            if not isinstance(data['limits'], dict) or set(data['limits']) - {f.name for f in fields(DeliveryLimits)}:
                raise ValueError()
            values = {**asdict(DeliveryLimits()), **data['limits']}
            if any(type(v) is not int or v <= 0 for v in values.values()):
                raise ValueError()
            limits = DeliveryLimits(**values)
            # Control JSON must remain below the unchanged 256 KiB request cap.
            if (limits.max_files > 100 or limits.max_depth > 32 or limits.max_manifest_bytes > 131072 or
                    limits.max_file_bytes > limits.max_package_bytes or
                    limits.max_archive_bytes + 2 * limits.max_package_bytes > limits.max_staging_bytes):
                raise ValueError()
            sources = data['sources']
            if not isinstance(sources, dict) or len(sources) > 32:
                raise ValueError()
            for host, addresses in sources.items():
                if not isinstance(host, str) or len(host) > 253 or not HOST.fullmatch(host):
                    raise ValueError()
                if addresses is not None:
                    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
                        raise ValueError()
                    for value in addresses:
                        address = ipaddress.ip_address(value)
                        if not address.is_global or getattr(address, 'ipv4_mapped', None):
                            raise ValueError()
            if not isinstance(data['targets'], list) or len(data['targets']) > 32:
                raise ValueError()
            ids = set()
            for target in data['targets']:
                if not isinstance(target, dict) or set(target) != {'id', 'label', 'project_id', 'parent_directory'}:
                    raise ValueError()
                if not isinstance(target['id'], str) or not ID.fullmatch(target['id']) or target['id'] in ids:
                    raise ValueError()
                if not isinstance(target['label'], str) or not 1 <= len(target['label']) <= 120:
                    raise ValueError()
                if target['project_id'] not in self.catalog.projects or not isinstance(target['parent_directory'], str):
                    raise ValueError()
                ids.add(target['id'])
            project_state = [{**asdict(p), 'root': str(p.root)} for p in self.catalog.projects.values()]
            version = hashlib.sha256(raw + json.dumps(project_state, sort_keys=True).encode()).hexdigest()
            return data, state, limits, version
        except (OSError, ValueError, TypeError, KeyError):
            raise AccessError("Package delivery policy is invalid or inaccessible; access is closed.",
                              code="delivery_policy_unavailable") from None

    def limits(self):
        return self._load()[2]

    def sources(self):
        return {host: tuple(addresses) if addresses is not None else None
                for host, addresses in self._load()[0]['sources'].items()}

    def resolve(self, target_id):
        data, state, limits, version = self._load()
        if state != self._state_directory:
            raise AccessError("Package state location changed; access is closed.", code="delivery_policy_changed")
        row = next((target for target in data['targets'] if target['id'] == target_id), None)
        if row is None:
            raise AccessError("Unknown package write target. Query package capabilities first.", code="delivery_target_denied")
        project = self.catalog.project(row['project_id'])
        if not project.repository_id:
            raise AccessError("Package targets require a pinned local Git repository.", code="delivery_repository_unpinned")
        entry = self.catalog.repositories.resolve(project.id)
        if Path(entry['root']) != project.root or not entry['is_default']:
            raise AccessError("Package delivery only supports the configured default work directory.",
                              code="delivery_target_denied")
        root_identity = tuple(entry['root_identity'])
        checked = replace(project, root_identity=root_identity)
        parts = self.catalog.parts(checked, row['parent_directory'])
        with self.catalog.open_path(checked, parts, directory=True) as fd:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise AccessError("Package parent must be an existing directory.", code="delivery_parent_unavailable")
            parent_identity = (info.st_dev, info.st_ino)
        if self._load()[3] != version:
            raise AccessError("Package policy changed during resolution.", code="delivery_policy_changed")
        # Unrelated projects/targets and intake-source additions do not revoke a
        # frozen write grant. Changes to this target, project policy or limits do.
        relevant = {'target': row, 'project': {**asdict(project), 'root': str(project.root)},
                    'limits': asdict(limits), 'state_directory': str(state)}
        target_version = hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()
        return DeliveryTarget(row['id'], row['label'], project.id, project.root, parts,
                              project.repository_id, root_identity, parent_identity, target_version)

    def revalidate(self, target):
        if self.resolve(target.target_id) != target:
            raise AccessError("Package target or authorization changed; review a fresh delivery.",
                              code="delivery_policy_changed")

    @contextmanager
    def open_parent(self, target):
        self.revalidate(target)
        project = replace(self.catalog.project(target.project_id), root_identity=target.root_identity)
        with self.catalog.open_path(project, target.parent_parts, directory=True) as fd:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != target.parent_identity:
                raise AccessError("Opened package parent does not match its approved identity.",
                                  code="delivery_parent_changed")
            yield fd

    def capabilities(self):
        data, _, limits, _ = self._load()
        targets = []
        for row in data['targets']:
            try:
                target = self.resolve(row['id'])
                targets.append({'target_id': target.target_id, 'label': target.label,
                                'project_id': target.project_id, 'worktree_id': 'main',
                                'parent_directory': '/'.join(target.parent_parts),
                                'absolute_parent': str(target.root.joinpath(*target.parent_parts)), 'available': True})
            except AccessError as exc:
                targets.append({'target_id': row['id'], 'available': False, 'error_code': exc.code})
        return {'enabled': any(target.get('available', False) for target in targets), 'limits': asdict(limits), 'targets': targets,
                'mode': 'new_version_directory_only', 'overwrites': False,
                'worktree_write_inheritance': False, 'source_hosts': sorted(data['sources']),
                'confirmation': 'Client must show exact target, frozen manifest and accessible file contents before each commit.'}
