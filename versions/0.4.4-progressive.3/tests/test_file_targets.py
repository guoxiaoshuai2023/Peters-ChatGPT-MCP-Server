"""Only temporary synthetic repositories; no production state or file publication."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_targets import FileTargets, TargetError
from peters_mcp.workspaces import RepositoryRegistry
from peters_mcp.private_roots import PrivateRootRegistry


class FileTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.git(self.repo, 'init', '-q')
        self.git(self.repo, '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                 'commit', '--allow-empty', '-qm', 'fixture')
        self.pin = RepositoryRegistry.identity(self.repo)
        self.catalog = Catalog([Project('repo', 'Synthetic', self.repo, repository_id=self.pin)])
        self.targets = FileTargets(self.catalog)

    @staticmethod
    def git(root, *arguments):
        return subprocess.run(['/usr/bin/git', '-C', str(root), *arguments],
                              check=True, capture_output=True, timeout=10).stdout

    def worktree(self, name='external'):
        root = self.base / name
        self.git(self.repo, 'worktree', 'add', '--detach', '-q', str(root), 'HEAD')
        entry = next(v for v in self.catalog.repositories.discover('repo')['worktrees'] if v['root'] == str(root))
        return root, entry['id']

    def freeze(self, path='new/file.bin', worktree='main', targets=None):
        targets = targets or self.targets
        info = targets.inspect('repo', worktree, path)
        return targets.resolve('repo', worktree, path, info['target_version'])

    def denied(self, path, code, targets=None):
        with self.assertRaises(TargetError) as error:
            (targets or self.targets).inspect('repo', 'main', path)
        self.assertEqual(error.exception.code, code)

    def test_private_registered_worktree_hidden_from_catalog_capabilities_and_hints(self):
        original = self.freeze()
        control = self.base / 'control'
        control.mkdir(mode=0o700)
        private = self.base / 'private-member'
        registry = PrivateRootRegistry(control, allowed_roots=[private])
        registry.initialize()
        registry.register_pending(private, read_roots=[])
        registry.activate(private, read_roots=[])
        self.git(self.repo, 'worktree', 'add', '--detach', '-q', str(private), 'HEAD')
        member = next(row['id'] for row in self.catalog.repositories.discover('repo')['worktrees']
                      if row['root'] == str(private))
        self.catalog.set_private_registry(registry)
        targets = FileTargets(self.catalog, private_guard=registry.check_path)
        catalog_view = self.catalog.list_worktrees('repo')
        file_view = targets.capabilities()
        for result in (catalog_view, file_view):
            serialized = json.dumps(result)
            self.assertNotIn(str(private), serialized)
            self.assertNotIn(member, serialized)
        self.assertEqual([row['worktree_id'] for row in file_view['projects'][0]['worktrees']], ['main'])
        hint_target = replace(original, destination_display=str(private / 'new.bin'))
        self.assertIsNone(targets._nested_hint(hint_target))
        # Registry failure must not become an apparently successful empty scope.
        (control / 'private-roots.json').write_text('corrupt synthetic manifest')
        for query in (targets.capabilities, lambda: targets._nested_hint(hint_target)):
            with self.assertRaises(AccessError) as error:
                query()
            self.assertEqual(error.exception.code, 'private_protection_unavailable')

    def test_explicit_protected_roots_are_excluded_from_scope_and_nested_hints(self):
        original = self.freeze()
        external, member = self.worktree()
        targets = FileTargets(self.catalog, protected_paths=[external])
        result = targets.capabilities()
        self.assertNotIn(str(external), json.dumps(result))
        self.assertNotIn(member, json.dumps(result))
        self.assertIsNone(targets._nested_hint(replace(original, destination_display=str(external / 'file.bin'))))
        targets = FileTargets(self.catalog, protected_paths=[self.repo])
        self.assertEqual(targets.capabilities()['projects'], [])

    def test_unknown_private_guard_error_is_not_silently_omitted(self):
        def unavailable(_):
            raise AccessError('Synthetic unavailable protection.', code='private_protection_unavailable')
        targets = FileTargets(self.catalog, private_guard=unavailable)
        with self.assertRaises(AccessError) as error:
            targets.capabilities()
        self.assertEqual(error.exception.code, 'private_protection_unavailable')

    def test_dynamic_external_worktree_inherits_scope_without_manual_list(self):
        root, member = self.worktree()
        target = self.freeze('images/原件 大文件.bin', member)
        self.assertEqual(target.root, str(root))
        self.assertIsNone(self.targets.inspect('repo', member, target.path)['size_limit'])
        self.assertIn(member, [w['worktree_id'] for w in self.targets.capabilities()['projects'][0]['worktrees']])

    def test_unrelated_members_commit_and_policy_changes_do_not_invalidate(self):
        target = self.freeze()
        self.worktree()
        self.git(self.repo, '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                 'commit', '--allow-empty', '-qm', 'unrelated commit')
        self.catalog.projects['repo'] = replace(self.catalog.projects['repo'], exclude=('unrelated/*',))
        self.assertEqual(self.targets.revalidate(target), target)

    def test_removed_member_and_recreated_root_do_not_match_frozen_target(self):
        root, member = self.worktree()
        target = self.freeze(worktree=member)
        self.git(self.repo, 'worktree', 'remove', '--force', str(root))
        with self.assertRaises(TargetError) as error:
            self.targets.revalidate(target)
        self.assertTrue(error.exception.permanent)
        self.assertEqual(error.exception.code, 'scope_revoked')
        # Hold old inode allocated so replacement identity cannot be recycled.
        root.mkdir()
        hold = self.base / 'hold'
        root.rename(hold)
        self.git(self.repo, 'worktree', 'add', '--detach', '-q', str(root), 'HEAD')
        with self.assertRaises(TargetError):
            self.targets.revalidate(target)

    def test_clone_and_forged_worktree_are_not_members(self):
        clone = self.base / 'clone'
        self.git(self.repo, 'clone', '-q', str(self.repo), str(clone))
        forged = self.base / 'forged'
        forged.mkdir()
        root, member = self.worktree()
        shutil.copyfile(root / '.git', forged / '.git')
        for candidate in (clone, forged):
            guessed = 'wt-' + __import__('hashlib').sha256(os.fsencode(candidate)).hexdigest()[:20]
            with self.assertRaises(TargetError):
                self.targets.inspect('repo', guessed, 'file.dat')
        root.rename(self.base / 'actual')
        root.symlink_to(self.base / 'actual', target_is_directory=True)
        with self.assertRaises(TargetError):
            self.targets.inspect('repo', member, 'file.dat')

    def test_default_directory_identity_is_frozen_without_repository_pin(self):
        plain = self.base / 'plain'
        plain.mkdir()
        targets = FileTargets(Catalog([Project('repo', 'Plain', plain)]))
        target = self.freeze(targets=targets)
        plain.rename(self.base / 'original')
        plain.mkdir()
        with self.assertRaises(TargetError) as error:
            targets.revalidate(target)
        self.assertEqual(error.exception.code, 'scope_identity_changed')
        self.assertTrue(error.exception.permanent)

    def test_temporary_discovery_failure_is_not_permanent_revocation(self):
        target = self.freeze()
        with patch.object(self.catalog.repositories, 'discover', side_effect=OSError()):
            with self.assertRaises(TargetError) as error:
                self.targets.revalidate(target)
        self.assertEqual(error.exception.code, 'paused_scope_unverifiable')
        self.assertFalse(error.exception.permanent)

    def test_exclude_applies_to_actual_root_prefixes_and_names(self):
        root, member = self.worktree()
        self.catalog.projects['repo'] = replace(self.catalog.projects['repo'], exclude=('private/*', '*.no', '.worktree/child'))
        for path in ('private/a.bin', 'some/A.NO'):
            with self.assertRaises(TargetError) as error:
                self.targets.inspect('repo', member, path)
            self.assertEqual(error.exception.code, 'path_excluded')
        self.assertTrue(self.targets.inspect('repo', member, 'child/file.dat')['scope_authorized'])

    def test_ordinary_hidden_binary_and_untracked_paths_have_no_read_limits(self):
        for path in ('.ordinary/image.png', 'audio.bin', 'archive.zip', 'document.pdf',
                     'README credentials discussion.md', 'arbitrary.blob', '.env.example'):
            self.assertTrue(self.targets.inspect('repo', 'main', path)['scope_authorized'])
        self.assertIsNone(self.targets.capabilities()['size_limit'])

    def test_fixed_protection_cannot_be_overridden_by_exact_exception(self):
        for path in ('.git/config', '.ssh/id_rsa', '.env.production', '.codex/auth.json',
                     '.config/gh/hosts.yml', 'credentials.json', 'private.key', 'access.token', 'cert.pem'):
            targets = FileTargets(self.catalog, special_exceptions=(('repo', 'main', path),))
            self.denied(path, 'protected_path', targets)

    def test_exact_special_exception_does_not_cover_neighbor_or_existing(self):
        self.denied('AGENTS.md', 'special_path_requires_exception')
        self.denied('.github/workflows/build.yml', 'special_path_requires_exception')
        targets = FileTargets(self.catalog, special_exceptions=(('repo', 'main', 'AGENTS.md'),))
        self.assertTrue(targets.inspect('repo', 'main', 'AGENTS.md')['scope_authorized'])
        self.denied('nested/AGENTS.md', 'special_path_requires_exception', targets)
        (self.repo / 'AGENTS.md').write_text('synthetic')
        self.assertTrue(targets.inspect('repo', 'main', 'AGENTS.md')['exists'])

    def test_existing_any_kind_is_create_conflict(self):
        for kind in ('regular', 'directory', 'link', 'fifo'):
            path = self.repo / kind
            if kind == 'regular': path.write_bytes(b'\x00\xff')
            elif kind == 'directory': path.mkdir()
            elif kind == 'link': path.symlink_to('missing')
            else: os.mkfifo(path)
            info = self.targets.inspect('repo', 'main', kind)
            self.assertTrue(info['exists'])
            with self.assertRaises(TargetError) as error:
                self.targets.resolve('repo', 'main', kind, info['target_version'])
            self.assertEqual(error.exception.code, 'target_exists')

    def test_nested_member_requires_explicit_selection_and_offers_hint(self):
        root = self.repo / 'nested'
        self.git(self.repo, 'worktree', 'add', '--detach', '-q', str(root), 'HEAD')
        result = self.targets.inspect('repo', 'main', 'nested/output.bin')
        self.assertFalse(result['scope_authorized'])
        self.assertEqual(result['suggested_target']['path'], 'output.bin')
        actual = result['suggested_target']['worktree_id']
        self.assertNotEqual(actual, 'main')
        self.assertTrue(self.targets.inspect('repo', actual, 'output.bin')['scope_authorized'])

    def test_nested_repository_added_after_freeze_blocks_open(self):
        target = self.freeze('nested/output.bin')
        (self.repo / 'nested').mkdir()
        self.git(self.repo / 'nested', 'init', '-q')
        with self.assertRaises(TargetError) as error:
            self.targets.revalidate(target)
        self.assertEqual(error.exception.code, 'repository_boundary')
        with self.assertRaises(TargetError) as error:
            with self.targets.open_parent(target, create=True): pass
        self.assertEqual(error.exception.code, 'repository_boundary')

    def test_parent_creation_race_and_owned_empty_cleanup(self):
        target = self.freeze('parents/deep/file.bin')
        created = []
        def create():
            with self.targets.open_parent(target, create=True, on_created=created.append) as parent:
                return os.fstat(parent.fd).st_ino
        with ThreadPoolExecutor(max_workers=2) as executor:
            identities = list(executor.map(lambda _: create(), range(2)))
        self.assertEqual(identities[0], identities[1])
        self.assertEqual(len(created), 2)
        self.assertEqual(len(self.targets.cleanup_created(target, list(reversed(created)))), 2)
        self.assertFalse((self.repo / 'parents').exists())

    def test_parent_move_during_creation_stops_before_next_directory(self):
        target = self.freeze('parent/child/output.bin')
        records = []
        def observe(record):
            records.append(record)
            if record.path == 'parent':
                (self.repo / 'parent').rename(self.repo / 'moved')
                (self.repo / 'parent').mkdir()
        with self.assertRaises(TargetError) as error:
            with self.targets.open_parent(target, create=True, on_created=observe):
                self.fail('Moved parent should not be returned')
        self.assertEqual(error.exception.code, 'parent_changed')
        self.assertFalse((self.repo / 'moved' / 'child').exists())
        self.assertFalse((self.repo / 'parent' / 'child').exists())
        self.assertEqual(self.targets.cleanup_created(target, records), [])

    def test_creation_callback_failure_keeps_recorded_empty_directory(self):
        target = self.freeze('one/two/output.bin')
        records = []
        def observe(record):
            records.append(record)
            raise RuntimeError('synthetic ledger unavailable')
        with self.assertRaises(RuntimeError):
            with self.targets.open_parent(target, create=True, on_created=observe): pass
        self.assertEqual([record.path for record in records], ['one'])
        self.assertFalse((self.repo / 'one' / 'two').exists())
        self.assertEqual(self.targets.cleanup_created(target, records), ['one'])

    def test_cleanup_preserves_nonempty_or_replaced_directories(self):
        target = self.freeze()
        records = []
        with self.targets.open_parent(target, create=True, on_created=records.append): pass
        (self.repo / 'new' / 'other').write_text('not ours')
        self.assertEqual(self.targets.cleanup_created(target, records), [])
        (self.repo / 'new').rename(self.repo / 'old')
        (self.repo / 'new').mkdir()
        self.assertEqual(self.targets.cleanup_created(target, records), [])

    def test_missing_parent_inspect_does_not_create_and_readiness_uses_ancestor(self):
        seen = []
        targets = FileTargets(self.catalog, readiness=lambda path, identity: seen.append((path, identity)) or {'execution_ready': True})
        info = targets.inspect('repo', 'main', 'a/b/video.mov')
        self.assertTrue(info['execution_ready'])
        self.assertFalse((self.repo / 'a').exists())
        self.assertEqual(seen[0][0], self.repo)

    def test_protected_control_paths_and_private_guard_are_rechecked(self):
        targets = FileTargets(self.catalog, protected_paths=(self.repo / 'control',))
        self.denied('control/setup.bin', 'protected_path', targets)
        self.denied('CONTROL/setup.bin', 'protected_path', targets)
        self.denied('ｃｏｎｔｒｏｌ/setup.bin', 'protected_path', targets)
        calls = []
        def guard(path):
            calls.append(path)
            if path == self.repo / 'private':
                raise TargetError('protected_path', 'Synthetic protection', permanent=True)
        targets = FileTargets(self.catalog, private_guard=guard)
        self.denied('private/data.bin', 'protected_path', targets)
        self.assertTrue(calls)

    def test_parent_link_and_invalid_paths_are_rejected(self):
        (self.repo / 'alias').symlink_to(self.base, target_is_directory=True)
        self.denied('alias/data.bin', 'linked_or_unavailable_path')
        for path in ('/absolute', '../escape', 'a//b', './x', 'a\\b', 'a\x00b'):
            self.denied(path, 'invalid_path')


if __name__ == '__main__':
    unittest.main()
