"""Create-only target scope. No downloads, publication, or persistent authorization ledger."""
from contextlib import contextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import unicodedata

from .catalog import AccessError, AUTH_PATHS, BLOCKED_NAMES, BLOCKED_PATTERNS, DIRECTORY_FLAGS

POLICY_VERSION = 'original-file-targets-v1'
# Preserve the existing credential/control boundary, including known key suffixes.
FIXED_NAMES = frozenset(BLOCKED_NAMES) | frozenset({
    'id_rsa', 'id_ed25519', 'credentials.json', 'credentials.yaml', 'credentials.yml',
    'credentials.toml', 'secrets.json', 'secrets.yaml', 'secrets.yml', 'secrets.toml',
    'cookies.txt', 'cookies.json',
})
SPECIAL_NAMES = frozenset({
    'agents.md', 'claude.md', 'skill.md', 'gemini.md', 'package.json', 'pyproject.toml',
    'makefile', 'gnumakefile', 'justfile', 'taskfile.yml', 'taskfile.yaml',
    '.pre-commit-config.yaml', '.gitlab-ci.yml', 'jenkinsfile', '.travis.yml',
    '.cursorrules', '.windsurfrules', '.envrc',
})
SPECIAL_TREES = (('.github', 'workflows'), ('.github', 'actions'), ('.circleci',),
                 ('.codex',), ('.claude',), ('.cursor', 'rules'))
SPECIAL_FILES = (('.vscode', 'tasks.json'), ('.vscode', 'launch.json'))
CODEX_FIXED = frozenset({'auth.json', 'sessions', 'archived_sessions', 'history.jsonl',
                         'state_5.sqlite', 'state_5.sqlite-wal', 'state_5.sqlite-shm'})


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                             separators=(',', ':')).encode()).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino)


def _fold(value):
    return unicodedata.normalize('NFKC', value).casefold()


class TargetError(AccessError):
    def __init__(self, code, message, *, permanent=False):
        super().__init__(message, code=code)
        self.permanent = permanent


@dataclass(frozen=True)
class FrozenTarget:
    project_id: str
    repository_id: str | None
    worktree_id: str
    root: str
    root_identity: tuple[int, int]
    path: str
    destination_display: str
    relevant_policy_version: str
    target_version: str
    snapshot_key: str


@dataclass(frozen=True)
class CreatedDirectory:
    path: str
    identity: tuple[int, int]


@dataclass
class ParentHandle:
    fd: int
    name: str
    created: list[CreatedDirectory]
    parent_path: str
    missing_parts: tuple[str, ...]


class FileTargets:
    def __init__(self, catalog, *, special_exceptions=(), protected_paths=(),
                 private_guard=None, readiness=None):
        self.catalog = catalog
        self.special_exceptions = frozenset(tuple(item) for item in special_exceptions)
        if any(len(item) != 3 or not all(isinstance(v, str) and v for v in item)
               for item in self.special_exceptions):
            raise ValueError('Special exceptions must be exact project/worktree/path triples.')
        for _, _, path in self.special_exceptions:
            self._parts(path)
        self.protected_paths = tuple(Path(p).absolute() for p in protected_paths)
        self.private_guard = private_guard
        self.readiness = readiness

    @staticmethod
    def _parts(path):
        if not isinstance(path, str) or not path or len(path) > 4096:
            raise TargetError('invalid_path', 'Provide a bounded relative file path.')
        parts = tuple(path.split('/'))
        if any(not p or p in ('.', '..') or '\\' in p or
               any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
            raise TargetError('invalid_path', 'Relative paths cannot contain traversal or control characters.')
        return parts

    def _refresh(self):
        try:
            self.catalog.refresh()
        except (AccessError, OSError, ValueError):
            raise TargetError('paused_scope_unverifiable', 'Project configuration cannot be verified.') from None

    def _member(self, project_id, worktree_id):
        self._refresh()
        project = self.catalog.projects.get(project_id)
        if project is None:
            raise TargetError('scope_revoked', 'Project is not authorized.', permanent=True)
        if not isinstance(worktree_id, str) or not worktree_id:
            raise TargetError('worktree_required', 'Select an explicit actual worktree ID.')
        try:
            discovered = self.catalog.repositories.discover(project_id)
        except (AccessError, OSError):
            raise TargetError('paused_scope_unverifiable', 'Repository membership cannot be verified.') from None
        default = next((item for item in discovered['worktrees'] if item['is_default']), None)
        if default is None or default['state'] in ('unavailable', 'missing'):
            raise TargetError('paused_scope_unverifiable', 'Repository discovery is unavailable.')
        if default['state'] != 'valid':
            raise TargetError('scope_identity_changed', 'Configured repository identity changed.', permanent=True)
        member = next((item for item in discovered['worktrees'] if item['id'] == worktree_id), None)
        if member is None:
            raise TargetError('scope_revoked', 'Selected worktree is not registered.', permanent=True)
        if member['state'] in ('missing', 'unavailable'):
            raise TargetError('paused_scope_unverifiable', 'Selected worktree cannot be verified.')
        if member['state'] != 'valid':
            raise TargetError('scope_identity_changed', 'Selected worktree identity changed.', permanent=True)
        return project, member, discovered

    def _guard(self, absolute):
        protected = self.protected_paths
        if self.catalog._config_path is not None:
            protected += (self.catalog._config_path,)
        for path in protected:
            folded = tuple(_fold(p) for p in absolute.parts)
            protected_parts = tuple(_fold(p) for p in path.parts)
            if folded[:len(protected_parts)] == protected_parts:
                raise TargetError('protected_path', 'Service control or private state is protected.', permanent=True)
        if self.private_guard is not None:
            self.private_guard(absolute)

    def _policy(self, project, worktree_id, root, parts):
        special = False
        for index, part in enumerate(parts):
            folded = tuple(_fold(p) for p in parts[:index + 1])
            lower = folded[-1]
            prefix = '/'.join(parts[:index + 1])
            self._guard(root.joinpath(*parts[:index + 1]))
            if (lower in FIXED_NAMES or any(fnmatchcase(lower, p) for p in BLOCKED_PATTERNS) or
                    any(len(folded) >= len(p) and folded[-len(p):] == p for p in AUTH_PATHS) or
                    (lower == '.env' or lower.startswith('.env.')) and
                    not lower.endswith(('.example', '.sample', '.template', '.md')) or
                    index and folded[-2] == '.codex' and lower in CODEX_FIXED):
                raise TargetError('protected_path', 'Git or credential state is protected.', permanent=True)
            if any(fnmatchcase(prefix.casefold(), pattern.casefold()) or
                   fnmatchcase(part.casefold(), pattern.casefold()) for pattern in project.exclude):
                raise TargetError('path_excluded', 'Path is excluded by project policy.', permanent=True)
            special |= lower in SPECIAL_NAMES or any(
                len(folded) >= len(p) and folded[-len(p):] == p
                for p in SPECIAL_TREES + SPECIAL_FILES)
        exception = (project.id, worktree_id, '/'.join(parts)) in self.special_exceptions
        if special and not exception:
            raise TargetError('special_path_requires_exception', 'This exact rules or automation path requires an explicit exception.', permanent=True)
        return _digest({'policy': POLICY_VERSION, 'special': bool(special), 'exception': bool(special and exception)})

    def _target(self, project_id, worktree_id, path):
        parts = self._parts(path)
        project, member, _ = self._member(project_id, worktree_id)
        root = Path(member['root'])
        policy = self._policy(project, worktree_id, root, parts)
        identity = tuple(member['root_identity'])
        values = dict(project_id=project_id, repository_id=project.repository_id,
                      worktree_id=worktree_id, root=str(root), root_identity=identity,
                      path='/'.join(parts), destination_display=str(root.joinpath(*parts)),
                      relevant_policy_version=policy)
        version = _digest(values)
        key = _digest([project_id, project.repository_id, worktree_id, str(root), identity])
        return FrozenTarget(**values, target_version=version, snapshot_key=key)

    def resolve(self, project_id, worktree_id, path, target_version):
        target = self._target(project_id, worktree_id, path)
        if target.target_version != target_version:
            raise TargetError('target_version_changed', 'Target identity or relevant policy changed; inspect again.', permanent=True)
        with self.open_parent(target, create=False):
            pass
        return target

    def revalidate(self, target):
        current = self._target(target.project_id, target.worktree_id, target.path)
        if current != target:
            raise TargetError('scope_identity_changed', 'Frozen target identity or policy changed.', permanent=True)
        self._check_existing_parents(current)
        return current

    def _check_existing_parents(self, target):
        fd = None
        try:
            fd = self._open_root(target)
            for part in self._parts(target.path)[:-1]:
                try:
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    break
                os.close(fd)
                fd = child
                self._boundary(fd)
        except TargetError:
            raise
        except OSError as exc:
            code = "linked_or_unavailable_path" if exc.errno in (20, 40) else "paused_scope_unverifiable"
            raise TargetError(code, "Destination parent cannot be safely verified.") from None
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _exists(fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def _boundary(fd):
        if FileTargets._exists(fd, '.git'):
            raise TargetError('repository_boundary', 'Nested repository requires its own verified worktree selection.', permanent=True)

    def _open_root(self, target):
        fd = os.open(target.root, DIRECTORY_FLAGS)
        if _identity(os.fstat(fd)) != target.root_identity:
            os.close(fd)
            raise TargetError('scope_identity_changed', 'Working directory was replaced.', permanent=True)
        return fd

    def _check_open_parent(self, target, parts, held_fd):
        check = self._open_root(target)
        try:
            for part in parts:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=check)
                os.close(check)
                check = child
                self._boundary(check)
            if _identity(os.fstat(check)) != _identity(os.fstat(held_fd)):
                raise TargetError('parent_changed', 'Destination parent changed.', permanent=True)
        finally:
            os.close(check)

    @contextmanager
    def open_parent(self, target, *, create=False, on_created=None):
        """Open the actual parent; absent parents return fd of deepest ancestor in inspect mode.

        For publication callers MUST use create=True. The returned descriptor is
        valid only inside this context. Persist created identities via on_created.
        """
        self.revalidate(target)
        parts = self._parts(target.path)
        created = []
        fd = None
        try:
            fd = self._open_root(target)
            missing = False
            opened_parts = []
            identities = []
            for index, part in enumerate(parts[:-1]):
                self._guard(Path(target.root).joinpath(*parts[:index + 1]))
                record = None
                try:
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        missing = True
                        break
                    self.revalidate(target)
                    self._check_open_parent(target, opened_parts, fd)
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                        made = True
                    except FileExistsError:
                        made = False
                    if made:
                        os.fsync(fd)
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                    if made:
                        record = CreatedDirectory('/'.join(parts[:index + 1]), _identity(os.fstat(child)))
                        created.append(record)
                os.close(fd)
                fd = child
                self._boundary(fd)
                opened_parts.append(part)
                identities.append(_identity(os.fstat(fd)))
                if record is not None and on_created is not None:
                    on_created(record)
            if not missing and self._exists(fd, parts[-1]):
                raise TargetError('target_exists', 'Destination already exists; only new files are supported.')
            self.revalidate(target)
            # Reopen the path to detect observed directory replacement or moves.
            check = self._open_root(target)
            try:
                for part, identity in zip(opened_parts, identities):
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=check)
                    os.close(check)
                    check = child
                    self._boundary(check)
                    if _identity(os.fstat(check)) != identity:
                        raise TargetError("parent_changed", "Destination parent changed.", permanent=True)
            finally:
                os.close(check)
            yield ParentHandle(fd, parts[-1], created, str(Path(target.root).joinpath(*opened_parts)),
                               parts[len(opened_parts):-1] if missing else ())
        except TargetError:
            raise
        except OSError as exc:
            code = 'linked_or_unavailable_path' if exc.errno in (20, 40) else 'paused_scope_unverifiable'
            raise TargetError(code, 'Destination parent cannot be safely opened.') from None
        finally:
            if fd is not None:
                os.close(fd)

    def inspect(self, project_id, worktree_id, path):
        target = self._target(project_id, worktree_id, path)
        try:
            with self.open_parent(target) as parent:
                info = os.fstat(parent.fd)
                # No creation; readiness uses the deepest currently existing ancestor.
                ready = self.readiness(Path(parent.parent_path), _identity(info)) if self.readiness else {
                    'execution_ready': False, 'readiness_reason': 'private_storage_not_configured'}
        except TargetError as exc:
            if exc.code == 'repository_boundary':
                hint = self._nested_hint(target)
                if hint:
                    return {'scope_authorized': False, 'execution_ready': False,
                            'readiness_reason': 'explicit_worktree_required', 'suggested_target': hint,
                            'size_limit': None}
            if exc.code == 'target_exists':
                return {**target.__dict__, 'scope_authorized': True, 'exists': True,
                        'execution_ready': False, 'readiness_reason': 'target_exists', 'size_limit': None}
            raise
        return {**target.__dict__, 'scope_authorized': True, 'exists': False, 'size_limit': None, **ready}

    def _visible_scope(self):
        """Public Catalog visibility plus this target policy's fixed protections.

        Callers hold the complete protection guard through result construction.
        Only an identified private path is omitted; an unavailable protection
        manifest is an operation failure, never an empty capability list.
        """
        visible = []
        for summary in self.catalog.list_projects()['projects']:
            project = self.catalog.projects[summary['id']]
            try:
                self._guard(project.root)
                snapshot = self.catalog.list_worktrees(project.id)
            except AccessError as exc:
                if exc.code in {'private_path', 'protected_path'}:
                    continue
                raise
            entries = []
            for member in snapshot['worktrees']:
                if member['state'] != 'valid':
                    continue
                try:
                    self._guard(Path(member['root']))
                except AccessError as exc:
                    if exc.code in {'private_path', 'protected_path'}:
                        continue
                    raise
                entries.append(member)
            visible.append((project, entries))
        return visible

    def _nested_hint(self, target):
        with self.catalog._private_read_guard():
            absolute = Path(target.destination_display)
            try:
                self._guard(absolute)
            except AccessError as exc:
                if exc.code in {'private_path', 'protected_path'}:
                    return None
                raise
            matches = []
            for project, entries in self._visible_scope():
                for member in entries:
                    root = Path(member['root'])
                    if root in absolute.parents and root != Path(target.root):
                        matches.append((len(root.parts), {'project_id': project.id,
                                        'worktree_id': member['id'], 'path': str(absolute.relative_to(root))}))
            return max(matches, key=lambda item: item[0])[1] if matches else None

    def capabilities(self):
        with self.catalog._private_read_guard():
            self._refresh()
            projects = []
            for project, entries in self._visible_scope():
                projects.append({'project_id': project.id, 'name': project.name,
                                 'worktrees': [{'worktree_id': item['id'], 'root': item['root'],
                                               'scope_authorized': True, 'execution_ready': False,
                                               'readiness_reason': 'inspect_destination_required',
                                               'member_version': _digest([project.id, project.repository_id, item['id'],
                                                                          item['root'], item.get('root_identity')])}
                                              for item in entries]})
            return {'projects': projects, 'mode': 'create-only', 'size_limit': None,
                    'target_version_source': 'inspect_file_destination',
                    'path_rules': {'policy_version': POLICY_VERSION, 'fixed_names': sorted(FIXED_NAMES), 'fixed_patterns': BLOCKED_PATTERNS,
                                   'special_names': sorted(SPECIAL_NAMES), 'special_trees': SPECIAL_TREES,
                                   'special_files': SPECIAL_FILES, 'explicit_worktree_required': True}}

    def cleanup_created(self, target, created):
        """Remove only recorded directories that still have the same identity and are empty."""
        removed = []
        for record in sorted(created, key=lambda item: len(self._parts(item.path)), reverse=True):
            parts = self._parts(record.path)
            if not target.path.startswith(record.path + '/'):
                continue
            fd = None
            try:
                fd = self._open_root(target)
                for part in parts[:-1]:
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    self._boundary(fd)
                entry = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode) and _identity(entry) == record.identity:
                    os.rmdir(parts[-1], dir_fd=fd)
                    removed.append(record.path)
            except (OSError, TargetError):
                pass
            finally:
                if fd is not None:
                    os.close(fd)
        return removed
