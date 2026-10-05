"""Synthetic regressions for fixed sensitive prefixes inside selected roots."""
import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import time
import unittest

from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.file_context import export_actor_from_verified
from peters_mcp.file_export import ExportConfig, FileExportService
from peters_mcp.private_roots import PrivateRootRegistry


class ExportRootPolicyTests(unittest.IsolatedAsyncioTestCase):
    CASES = (
        ('codex-root', '.codex', 'state_5.sqlite-wal'),
        ('session-root', '.codex/sessions', 'private-session.jsonl'),
        ('credentials-root', '.config/gcloud', 'credentials.db-journal'),
    )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-root-policy-')
        self.base = Path(self.temp.name).resolve()
        self.body = b'purely synthetic original bytes\x00'
        projects = []
        for project_id, relative_root, relative_file in self.CASES:
            root = self.base / relative_root
            root.mkdir(parents=True, exist_ok=True)
            (root / relative_file).write_bytes(self.body)
            projects.append(Project(project_id, 'Synthetic', root))
        self.ordinary = self.base / 'ordinary'
        self.ordinary.mkdir()
        projects.append(Project('ordinary', 'Synthetic ordinary', self.ordinary))
        self.control = self.base / 'control'
        self.control.mkdir(mode=0o700)
        self.spool = self.base / 'spool'
        registry = PrivateRootRegistry(self.control, allowed_roots=[self.spool])
        registry.initialize()
        roots = [project.root for project in projects]
        registry.register_pending(self.spool, read_roots=roots)
        registry.activate(self.spool, read_roots=roots)
        self.catalog = Catalog(projects, private_registry=registry)
        self.service = FileExportService(self.catalog,
            ExportConfig(True, self.spool, min_free_bytes=0))
        self.service.start()
        self.actor = export_actor_from_verified('https://synthetic.invalid', 'owner', time.time() + 60)

    async def asyncTearDown(self):
        stopped = await asyncio.to_thread(self.service.close, 2)
        self.assertEqual(stopped['state'], 'stopped')
        self.temp.cleanup()

    async def export(self, project_id, path, key):
        capability = await self.service.metadata(self.actor,
            lambda: self.service.capabilities(self.actor))
        deadline = time.monotonic() + 3
        while True:
            try:
                return await self.service.export_file(self.actor, project_id, 'main', path,
                    capability['service_instance_id'], capability['request_window_id'], key)
            except AccessError as error:
                if error.code != 'busy' or time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(.02)

    async def ready(self, project_id, path, key):
        result = await self.export(project_id, path, key)
        deadline = time.monotonic() + 3
        while result['state'] in ('queued', 'preparing') and time.monotonic() < deadline:
            await asyncio.sleep(.01)
            result = await self.service.get_status(self.actor, result['export_id'])
        self.assertEqual(result['state'], 'ready', result)
        return result

    async def test_find_cannot_strip_fixed_sensitive_prefix_from_selected_root(self):
        for project_id, _, relative_file in self.CASES:
            with self.subTest(project=project_id):
                try:
                    result = await self.service.find_files(self.actor, project_id, 'main')
                except AccessError as error:
                    self.assertIn(error.code, {'sensitive_source', 'access_denied'})
                else:
                    self.assertNotIn(relative_file, {row['path'] for row in result['files']})

    async def test_export_cannot_strip_fixed_sensitive_prefix_from_selected_root(self):
        for project_id, _, relative_file in self.CASES:
            with self.subTest(project=project_id):
                with self.assertRaises(AccessError) as caught:
                    await self.export(project_id, relative_file, 'blocked-' + project_id)
                self.assertIn(caught.exception.code, {'sensitive_source', 'access_denied'})

    async def test_status_revokes_old_snapshot_after_selection_moves_to_sensitive_root(self):
        original_project = self.catalog.projects['ordinary']
        for project_id, relative_root, relative_file in self.CASES:
            with self.subTest(project=project_id):
                (self.ordinary / relative_file).write_bytes(self.body)
                before = await self.ready('ordinary', relative_file, 'before-' + project_id)
                self.catalog.projects['ordinary'] = replace(original_project,
                    root=self.base / relative_root)
                revoked = await self.service.get_status(self.actor, before['export_id'])
                self.assertEqual(revoked['state'], 'revoked')
                for field in ('source', 'bytes', 'sha256', 'resource_uri', 'captured_at'):
                    self.assertNotIn(field, revoked)
                self.catalog.projects['ordinary'] = original_project
                restored = await self.service.get_status(self.actor, before['export_id'])
                self.assertEqual(restored['state'], 'revoked')

    async def test_ordinary_settings_databases_and_unknown_files_remain_readable(self):
        paths = ('.codex/settings.json', 'data/app.db', 'data/app.db-wal', 'unknown.asset')
        for path in paths:
            target = self.ordinary / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.body)
        found = await self.service.find_files(self.actor, 'ordinary', 'main')
        self.assertEqual({row['path'] for row in found['files']}, set(paths))
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                result = await self.ready('ordinary', path, 'ordinary-' + str(index))
                self.assertEqual(result['sha256'], hashlib.sha256(self.body).hexdigest())
                self.assertNotIn('resource_uri', result)
                delivery = await self.service.materialize(self.actor, result['export_id'])
                self.assertIn('resource_uri', delivery)
                await self.service.cancel(self.actor, result['export_id'])
                deadline = time.monotonic() + 3
                while self.service.diagnostics()['snapshot_reservations'] and time.monotonic() < deadline:
                    await asyncio.sleep(.01)
                self.assertEqual(self.service.diagnostics()['snapshot_reservations'], 0)
        # Selecting the settings directory itself is also valid; only its fixed
        # runtime-state children are excluded.
        settings = self.base / '.codex' / 'settings.json'
        settings.write_bytes(self.body)
        result = await self.ready('codex-root', 'settings.json', 'root-settings')
        self.assertNotIn('resource_uri', result)
        self.assertIn('resource_uri', await self.service.materialize(self.actor, result['export_id']))


if __name__ == '__main__':
    unittest.main()
