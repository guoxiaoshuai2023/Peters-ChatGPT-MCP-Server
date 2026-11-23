"""Shared private-path rules for the Agent origin and its publisher."""

import hashlib
import json
from pathlib import Path

from .agent_history_policy import AgentPolicy, _key
from .catalog import AccessError, Catalog, _config_bytes
from .file_config import bind_registry, read_file_config


def canonical(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('Use verified canonical absolute paths.')
    return path


def protection_arguments(parser):
    for flag in ('file-config', 'history-config', 'agent-history-config', 'legacy-runtime', 'legacy-access-config'):
        parser.add_argument('--' + flag, type=canonical, required=True)
    parser.add_argument('--protected-path', type=canonical, action='append', default=[])


def _codex_root(path):
    document = json.loads(_config_bytes(path))
    root = canonical(document['codex_home'])
    if not root.is_dir():
        raise ValueError('The Codex history root could not be verified.')
    return root


class OriginProtections:
    def __init__(self, args, history_policy):
        self.legacy_agent_policy = history_policy
        self.legacy_codex_path = args.history_config
        self.codex_home = _codex_root(self.legacy_codex_path)
        self.files_config = args.file_config
        self.files_digest = hashlib.sha256(_config_bytes(self.files_config)).digest()
        private_roots = [args.projects.parent, args.legacy_runtime, args.file_config, *args.protected_path]
        if self.codex_home is not None:
            private_roots.append(self.codex_home)
        # The mandatory runtime root includes the live/rotated audit files.
        # The legacy credential config may be independently replaced in place.
        fixed_paths = [args.legacy_access_config, args.history_config, args.agent_history_config,
                       args.state_directory]
        self.protected_paths = tuple(private_roots + fixed_paths) + history_policy.protected_paths
        self._anchors = {p: self._identity(p) for p in private_roots}

    @staticmethod
    def _identity(path):
        info = path.stat()
        return info.st_dev, info.st_ino, info.st_mode

    def health(self):
        self.legacy_agent_policy.config()
        if (_codex_root(self.legacy_codex_path) != self.codex_home
                or hashlib.sha256(_config_bytes(self.files_config)).digest() != self.files_digest):
            raise AccessError('Restart to change protected service configuration.', code='private_protection_changed')
        for path, identity in self._anchors.items():
            if path.resolve() != path or self._identity(path) != identity:
                raise AccessError('An anchored private path changed.', code='private_protection_changed')
        return self.files_digest

    def excludes(self, path):
        absolute = Path(path).absolute()
        aliases = (_key(absolute), _key(absolute.resolve()))
        if self.legacy_agent_policy.excludes(absolute):
            return True
        for root in self.protected_paths:
            key = _key(root)
            if any(alias[:len(key)] == key for alias in aliases):
                return True
        return False


def build_protections(args, catalog=None):
    if not args.legacy_runtime.is_dir() or not (args.legacy_runtime / 'work').is_dir():
        raise ValueError('The existing origin runtime and audit directory are required.')
    if not args.legacy_access_config.is_file():
        raise ValueError('The existing Access configuration is required.')
    args.projects = canonical(args.projects)
    args.state_directory = Path(args.state_directory)
    if not args.state_directory.is_absolute() or args.state_directory.resolve() != args.state_directory:
        raise ValueError('Use the canonical protected Agent state directory.')
    if catalog is None:
        # Contains no source and runs no workers. Directory selection is
        # performed independently against each published project document.
        catalog = Catalog([], _allow_empty=True)
    registry = bind_registry(read_file_config(args.file_config), catalog)
    if (not args.state_directory.is_relative_to(registry.control_dir)
            or args.state_directory == registry.control_dir):
        raise ValueError('Agent state belongs under the shared private control root.')
    history_policy = AgentPolicy(args.agent_history_config, mode='v1')
    protections = OriginProtections(args, history_policy)
    with registry.read_guard() as guard:
        guard.revalidate()
        protections.health()
    return registry, protections


def protected_root_check(registry, protections, path):
    with registry.read_guard() as guard:
        if protections.excludes(path):
            raise AccessError('A project root is protected.', code='private_path')
        guard.check_path(path)
