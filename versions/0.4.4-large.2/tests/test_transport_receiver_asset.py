"""Fixed package helper delivery, parent permissions and real SDK ownership."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.file_export import ExportLimits
from peters_mcp import transport_asset as asset
from tests import test_export_lifecycle as lifecycle
from tests import test_export_protocol as protocol
from tests.test_large_export_service import LargeExportFixture


class FixedAssetLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fixed-receiver-asset-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / asset.RECEIVER_NAME
        self.body = asset._ASSET_PATH.read_bytes()
        self.path.write_bytes(self.body)

    def load(self):
        with patch.object(asset, '_ASSET_PATH', self.path):
            return asset.load_receiver_asset()

    def test_exact_regular_asset_and_metadata_never_import_or_expose_paths(self):
        self.assertEqual(self.load(), self.body)
        self.assertEqual(len(self.body), asset.RECEIVER_BYTES)
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), asset.RECEIVER_SHA256)
        self.assertLessEqual(len(self.body), asset.MAX_ASSET_BYTES)
        metadata = asset.receiver_metadata()
        self.assertEqual(metadata['source_kind'], 'trusted_package_asset')
        self.assertTrue(metadata['native_independent_hash_required'])
        self.assertNotIn('path', metadata)
        self.assertNotIn('body', metadata)
        self.assertNotIn('resource_uri', metadata)

    def test_changed_truncated_symlink_hardlink_and_fifo_assets_fail_closed(self):
        self.path.write_bytes(self.body[:-1] + bytes((self.body[-1] ^ 1,)))
        with self.assertRaises(AccessError):
            self.load()
        self.path.write_bytes(self.body[:-1])
        with self.assertRaises(AccessError):
            self.load()
        self.path.write_bytes(self.body)
        other = self.path.with_name('other.py')
        os.link(self.path, other)
        with self.assertRaises(AccessError):
            self.load()
        other.unlink()
        self.path.unlink()
        self.path.symlink_to(asset._ASSET_PATH)
        with self.assertRaises(AccessError):
            self.load()
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(AccessError):
            self.load()

    def test_named_asset_replacement_during_fd_read_is_rejected(self):
        original = os.read
        replaced = False
        def replace_named(fd, count):
            nonlocal replaced
            block = original(fd, count)
            if not replaced:
                replaced = True
                replacement = self.path.with_name('replacement.py')
                replacement.write_bytes(self.body)
                replacement.replace(self.path)
            return block
        with patch.object(asset.os, 'read', replace_named), self.assertRaises(AccessError):
            self.load()

    def test_close_uncertainty_is_pending_and_does_not_skip_other_owned_fd(self):
        original = asset._close
        closed = []
        def unconfirmed_first(fd):
            closed.append(fd)
            original(fd)
            if len(closed) == 1:
                raise AccessError('Fixed synthetic close uncertainty.', code='protection_cleanup_pending')
        with patch.object(asset, '_close', unconfirmed_first), self.assertRaises(AccessError) as observed:
            self.load()
        self.assertEqual(observed.exception.code, 'protection_cleanup_pending')
        self.assertEqual(len(closed), 2)
        self.assertEqual(len(set(closed)), 2)


class ReceiverParentPolicyTests(LargeExportFixture):
    async def test_actor_parent_scope_budget_and_repeated_asset_reference(self):
        self.write(data=b'small authorized original')
        ready = await self.ready()
        plan = await self.service.get_transport_plan(self.actor, ready['export_id'])
        self.assertEqual(plan['receiver_asset'], asset.receiver_metadata())
        self.assertEqual(self.service.diagnostics()['materialization_references'], 0)
        before = self.service.diagnostics()['metadata_bytes']
        first = await self.service.materialize_receiver(self.actor, ready['export_id'])
        again = await self.service.materialize_receiver(self.actor, ready['export_id'])
        self.assertEqual(first['delivery_id'], again['delivery_id'])
        self.assertEqual(first['materialization_expires_at'], again['materialization_expires_at'])
        self.assertEqual(self.service.diagnostics()['metadata_bytes'], before + 512)
        self.assertNotIn('source', first)
        self.assertEqual(first['source_kind'], 'trusted_package_asset')
        mono = await self.service.materialize(self.actor, ready['export_id'])
        self.assertNotEqual(mono['delivery_id'], first['delivery_id'])
        self.assertEqual(mono['bytes'], len(b'small authorized original'))
        with patch('peters_mcp.file_export.load_receiver_asset') as load:
            with self.assertRaisesRegex(AccessError, 'export_unavailable'):
                await self.service.materialize_receiver(self.actor_for('other-actor'), ready['export_id'])
            load.assert_not_called()
        limited = self.make_service(limits=ExportLimits(records=1, actor_records=1, close_seconds=.2))
        limited_ready = await self.ready(service=limited)
        await limited.materialize_receiver(self.actor, limited_ready['export_id'])
        with self.assertRaisesRegex(AccessError, 'resource_budget_exhausted'):
            await limited.materialize_part(self.actor, limited_ready['export_id'], 0)

    async def test_revocation_denies_helper_before_file_read_and_restoration_never_revives(self):
        self.write()
        ready = await self.ready()
        first = await self.service.materialize_receiver(self.actor, ready['export_id'])
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=('original.bin',))
        with patch('peters_mcp.file_export.load_receiver_asset') as load:
            with self.assertRaises(AccessError):
                await self.service.materialize_receiver(self.actor, ready['export_id'])
            load.assert_not_called()
        self.catalog.projects['synthetic'] = replace(self.catalog.projects['synthetic'], exclude=())
        denied = await self.service.materialize_receiver(self.actor, ready['export_id'])
        self.assertEqual(denied['state'], 'revoked')
        self.assertNotIn('resource_uri', denied)
        with self.assertRaises(AccessError):
            self.service.open_resource(self.actor, first['delivery_id'], asyncio.get_running_loop())

    async def test_source_protection_failure_cannot_offer_trusted_asset_link(self):
        self.write()
        ready = await self.ready()
        with patch.object(self.service.registry, 'read_guard', side_effect=AccessError(
                'Fixed protection rejection.', code='private_protection_unavailable')):
            with patch('peters_mcp.file_export.load_receiver_asset') as load:
                with self.assertRaises(AccessError):
                    await self.service.materialize_receiver(self.actor, ready['export_id'])
                load.assert_not_called()


class RealReceiverSDKTests(unittest.TestCase):
    setUp = protocol.ExportProtocolTests.setUp
    rpc = protocol.ExportProtocolTests.rpc
    call = protocol.ExportProtocolTests.call
    exported = protocol.ExportProtocolTests.exported
    wait_released = protocol.ExportProtocolTests.wait_released

    def test_package_asset_enters_actual_sdk_consumer_and_imports_after_independent_hash(self):
        parent, _ = self.exported('fixed-receiver-package')
        result = self.call('materialize_file_export_receiver', {'export_id': parent['export_id']})
        metadata = json.loads(result['content'][0]['text'])
        self.assertNotIn('source', metadata)
        link = result['content'][1]
        self.assertEqual(link['name'], asset.RECEIVER_NAME)
        self.assertEqual(link['size'], asset.RECEIVER_BYTES)
        self.assertEqual(link['mimeType'], 'text/x-python')
        response = self.rpc('resources/read', {'uri': link['uri']})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(int(response.headers['content-length']), len(response.content))
        value = response.json()['result']
        self.assertEqual(value['cacheScope'], 'private')
        self.assertEqual(value['ttlMs'], 0)
        self.assertIn('no-store', response.headers['cache-control'])
        received = base64.b64decode(value['contents'][0]['blob'], validate=True)
        self.assertEqual(len(received), asset.RECEIVER_BYTES)
        self.assertEqual(hashlib.sha256(received).hexdigest(), asset.RECEIVER_SHA256)
        target = self.root / 'independent-native-receiver.py'
        self.assertFalse(target.exists())
        with target.open('xb') as output:
            output.write(received)
        measured = target.read_bytes()
        self.assertEqual(len(measured), asset.RECEIVER_BYTES)
        self.assertEqual(hashlib.sha256(measured).hexdigest(), asset.RECEIVER_SHA256)
        imported = importlib.util.spec_from_file_location('independently_verified_native_receiver', target)
        module = importlib.util.module_from_spec(imported)
        imported.loader.exec_module(module)
        self.assertEqual(module.MAX_BYTES, 200_000_000)
        self.assertTrue(callable(module.NativeRangeReceiver))
        self.wait_released()
        state = json.loads(self.call('get_file_export_status', {'export_id': parent['export_id']})['content'][0]['text'])
        self.assertFalse(state['server_stream_finished'])
        self.assertNotIn('part_streams_finished', state)
        self.assertEqual(state['client_received'], 'not_observed')
        self.assertFalse((self.repo / asset.RECEIVER_NAME).exists())

    def test_other_actor_cannot_read_helper_with_owner_delivery_id(self):
        parent, _ = self.exported('wrong-helper-actor')
        result = self.call('materialize_file_export_receiver', {'export_id': parent['export_id']})
        denied = self.rpc('resources/read', {'uri': result['content'][1]['uri']}, actor='synthetic-b')
        self.assertIn('error', denied.json())
        self.assertNotIn(asset.RECEIVER_SHA256, denied.text)
        self.assertEqual(self.service.diagnostics()['active_responses'], 0)


class RealReceiverLifecycleTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = lifecycle.ExportLifecycleTests.asyncSetUp
    cleanup_requests = lifecycle.ExportLifecycleTests.cleanup_requests
    cleanup_lifespan = lifecycle.ExportLifecycleTests.cleanup_lifespan
    track = lifecycle.ExportLifecycleTests.track
    rpc_raw = lifecycle.ExportLifecycleTests.rpc_raw
    response = staticmethod(lifecycle.ExportLifecycleTests.response)
    call = lifecycle.ExportLifecycleTests.call
    exported = lifecycle.ExportLifecycleTests.exported
    wait_for = lifecycle.ExportLifecycleTests.wait_for
    released = lifecycle.ExportLifecycleTests.released
    begin_blocked_read = lifecycle.ExportLifecycleTests.begin_blocked_read
    assert_pinned = lifecycle.ExportLifecycleTests.assert_pinned

    async def test_close_waits_for_actual_helper_sdk_asgi_exit_then_releases(self):
        parent, _ = await self.exported('helper-close-real-task')
        result = await self.call('materialize_file_export_receiver', {'export_id': parent['export_id']})
        task, gate = await self.begin_blocked_read(result['content'][1]['uri'])
        self.assert_pinned(parent['export_id'], task)
        stopped = await asyncio.to_thread(self.service.close, .05)
        self.assertEqual(stopped['state'], 'shutdown_pending')
        self.assert_pinned(parent['export_id'], task)
        gate.release.set()
        messages = await asyncio.wait_for(task, 3)
        self.assertFalse(any(m['type'] == 'http.response.body' and not m.get('more_body', False)
                             for m in messages))
        await self.released()
        await self.wait_for(lambda: self.service.diagnostics()['snapshot_fds'] == 0,
                            'Helper response retained parent FD after actual task exit')
        self.assertEqual((await asyncio.to_thread(self.service.close, 2))['state'], 'stopped')


if __name__ == '__main__':
    unittest.main()
