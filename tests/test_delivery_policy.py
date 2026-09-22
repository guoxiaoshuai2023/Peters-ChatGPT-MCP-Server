import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from peters_mcp.catalog import AccessError, Catalog
from peters_mcp.delivery_policy import DeliveryPolicy
from peters_mcp.workspaces import RepositoryRegistry


class DeliveryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'repo'; self.repo.mkdir()
        subprocess.run(['/usr/bin/git', 'init', '-q', '-b', 'main', str(self.repo)], check=True)
        self.parent = self.repo / 'docs/packages'; self.parent.mkdir(parents=True)
        self.project_config = self.base / 'projects.json'
        self.project = {'id': 'example', 'name': 'Example', 'root': str(self.repo),
                        'repository_id': RepositoryRegistry.identity(self.repo)}
        self.project_config.write_text(json.dumps({'projects': [self.project]}))
        self.catalog = Catalog.from_config(self.project_config)
        self.path = self.base / 'delivery.json'
        self.data = {'version': 1, 'state_directory': str(self.base / 'private-state'),
                     'targets': [{'id': 'packages', 'label': 'Synthetic packages', 'project_id': 'example',
                                  'parent_directory': 'docs/packages'}],
                     'sources': {'files.example.com': ['8.8.8.8']}, 'limits': {}}
        self.save()
        self.policy = DeliveryPolicy(self.path, self.catalog)

    def save(self):
        self.path.write_text(json.dumps(self.data))

    def test_default_root_is_pinned_and_target_is_explicit(self):
        target = self.policy.resolve('packages')
        self.assertEqual(target.root, self.repo)
        self.assertEqual(target.parent_parts, ('docs', 'packages'))
        self.assertEqual(target.repository_id, self.project['repository_id'])
        with self.policy.open_parent(target) as fd:
            self.assertGreaterEqual(fd, 0)
        self.assertEqual(self.policy.capabilities()['targets'][0]['worktree_id'], 'main')
        self.data['targets'] = []; self.save()
        self.assertFalse(self.policy.capabilities()['enabled'])
        with self.assertRaises(AccessError): self.policy.resolve('packages')

    def test_read_only_directory_cannot_inherit_package_write_permission(self):
        self.project.pop('repository_id')
        self.project_config.write_text(json.dumps({'projects': [self.project]}))
        with self.assertRaises(AccessError): self.policy.resolve('packages')

    def test_revocation_and_parent_identity_replacement_fail_closed(self):
        target = self.policy.resolve('packages')
        self.parent.rename(self.parent.with_name('old'))
        self.parent.mkdir()
        with self.assertRaises(AccessError): self.policy.revalidate(target)
        self.parent.rmdir(); self.parent.symlink_to(self.parent.with_name('old'))
        with self.assertRaises(AccessError):
            with self.policy.open_parent(target): pass

    def test_nested_repository_and_unapproved_worktree_are_not_write_targets(self):
        subprocess.run(['/usr/bin/git','init','-q',str(self.parent)],check=True)
        with self.assertRaises(AccessError): self.policy.resolve('packages')
        self.data['targets'][0]['worktree_id'] = 'external'
        self.save()
        with self.assertRaises(AccessError): self.policy.capabilities()

    def test_state_cannot_be_exposed_inside_readable_project_or_switched_live(self):
        self.data['state_directory'] = str(self.repo / 'private-state'); self.save()
        with self.assertRaises(AccessError): self.policy.capabilities()
        self.data['state_directory'] = str(self.base / 'another-state'); self.save()
        with self.assertRaises(AccessError): self.policy.resolve('packages')
        with self.assertRaises(AccessError): _ = self.policy.state_directory

    def test_sources_and_limits_are_validated_without_network(self):
        for sources in ({'*.blob.example.com':None}, {'127.0.0.1':None}, {'files.example.com':['127.0.0.1']},
                        {'files.example.com':['198.18.1.1']}, {'files.example.com':['::ffff:8.8.8.8']}):
            self.data['sources'] = sources; self.save()
            with self.subTest(sources=sources), self.assertRaises(AccessError): self.policy.capabilities()
        self.data['sources'] = {}
        for limits in ({'max_files':True}, {'max_manifest_bytes':262145}, {'unknown':1}, {'max_staging_bytes':1}):
            self.data['limits'] = limits; self.save()
            with self.subTest(limits=limits), self.assertRaises(AccessError): self.policy.capabilities()

    def add_worktree(self, path):
        subprocess.run(['/usr/bin/git', '-C', str(self.repo), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.com', 'commit', '--allow-empty', '-qm', 'Fixture'], check=True)
        subprocess.run(['/usr/bin/git', '-C', str(self.repo), 'worktree', 'add', '--detach',
                        '-q', str(path)], check=True)
        return next(w['id'] for w in self.catalog.list_worktrees('example')['worktrees']
                    if Path(w['root']) == path)

    def test_state_inside_external_worktree_is_rejected(self):
        external = self.base / 'external'
        self.add_worktree(external)
        self.data['state_directory'] = str(external / 'private-state'); self.save()
        with self.assertRaises(AccessError): DeliveryPolicy(self.path, self.catalog)

    def assert_private_reads_denied(self, project_id, prefix, worktree_id=''):
        with self.assertRaisesRegex(AccessError, 'delivery_private_staging'):
            self.catalog.read_file(project_id, prefix + 'original.md', worktree_id=worktree_id)
        with self.assertRaisesRegex(AccessError, 'delivery_private_staging'):
            self.catalog.list_files(project_id, prefix.rstrip('/'), worktree_id=worktree_id)
        with self.assertRaisesRegex(AccessError, 'delivery_private_staging'):
            self.catalog.search(project_id, 'private-fixture', directory=prefix.rstrip('/'), worktree_id=worktree_id)

    def test_new_project_grant_cannot_expose_existing_state(self):
        state = self.policy.state_directory; state.mkdir()
        (state / 'original.md').write_text('private-fixture')
        self.project_config.write_text(json.dumps({'projects': [self.project,
            {'id': 'later', 'name': 'Later', 'root': str(self.base)},
            {'id': 'direct', 'name': 'Direct', 'root': str(state)}]}))
        self.assert_private_reads_denied('later', 'private-state/')
        self.assert_private_reads_denied('direct', '')
        self.assertNotIn('private-state', [e['path'] for e in self.catalog.list_files('later')['entries']])
        self.assertEqual(self.catalog.search('later', 'private-fixture')['matches'], [])

    def test_new_external_worktree_cannot_expose_existing_state(self):
        external = self.base / 'external'
        self.data['state_directory'] = str(external / 'private-state'); self.save()
        policy = DeliveryPolicy(self.path, self.catalog)
        worktree_id = self.add_worktree(external)
        state = Path(self.data['state_directory']); state.mkdir()
        (state / 'original.md').write_text('private-fixture')
        self.assert_private_reads_denied('example', 'private-state/', worktree_id)
        self.assertEqual(self.catalog.search('example', 'private-fixture', worktree_id=worktree_id)['matches'], [])
        with self.assertRaises(AccessError): policy.capabilities()

    def test_unicode_equivalent_state_paths_remain_private(self):
        state = self.base / 'caf\u00e9-state'
        self.data['state_directory'] = str(state); self.save()
        DeliveryPolicy(self.path, self.catalog)
        state.mkdir(); (state / 'original.md').write_text('private-fixture')
        self.project_config.write_text(json.dumps({'projects': [self.project,
            {'id': 'later', 'name': 'Later', 'root': str(self.base)}]}))
        self.assert_private_reads_denied('later', 'cafe\u0301-state/')
        # Startup exclusion must use the same canonical alias comparison.
        self.data['state_directory'] = str(self.base / 'cafe\u0301-state' / 'child'); self.save()
        self.project_config.write_text(json.dumps({'projects': [self.project,
            {'id': 'alias', 'name': 'Alias', 'root': str(state)}]}))
        with self.assertRaises(AccessError): DeliveryPolicy(self.path, self.catalog)

    def test_invalid_or_linked_policy_does_not_retain_old_grant(self):
        target = self.policy.resolve('packages')
        self.path.write_text('{broken')
        with self.assertRaises(AccessError): self.policy.revalidate(target)
        self.save()
        original = self.path.with_name('original.json'); self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises(AccessError): self.policy.revalidate(target)

    def test_unrelated_target_or_source_additions_keep_existing_write_grant(self):
        target = self.policy.resolve('packages')
        self.data['sources']['another.example.com'] = None
        self.data['targets'].append({**self.data['targets'][0], 'id': 'another'})
        self.save()
        self.policy.revalidate(target)
        self.data['targets'][0]['parent_directory'] = 'docs'
        self.save()
        with self.assertRaises(AccessError): self.policy.revalidate(target)


if __name__ == '__main__': unittest.main()
