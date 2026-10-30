"""Real synthetic manager IO; simulated task endings are not native/SDK proof."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_file_export as baseline
from peters_mcp.catalog import AccessError
from peters_mcp.chunked_export_config import ChunkedExportConfig, PART_MAX_BYTES, read_chunked_export_config
from peters_mcp.file_export import ExportConfig, ExportLimits, FileExportService, _json, load_export_service


class ChunkedManagerTests(unittest.IsolatedAsyncioTestCase):
    setUp = baseline.ExportTests.setUp
    asyncTearDown = baseline.ExportTests.asyncTearDown
    actor_for = baseline.ExportTests.actor_for
    make_service = baseline.ExportTests.make_service
    write = baseline.ExportTests.write
    wait_until = baseline.ExportTests.wait_until
    accepted = baseline.ExportTests.accepted
    status = baseline.ExportTests.status
    ready = baseline.ExportTests.ready

    async def asyncSetUp(self):
        self.asset_bytes = b'# fixed synthetic helper; never executed\n'
        self.asset = {'asset_id': 'synthetic-helper', 'name': 'synthetic_receiver.py',
                      'bytes': len(self.asset_bytes), 'sha256': hashlib.sha256(self.asset_bytes).hexdigest()}
        module = SimpleNamespace(receiver_metadata=lambda: dict(self.asset), load_receiver_asset=lambda: self.asset_bytes)
        self.asset_patch = patch.dict(sys.modules, {'peters_mcp.transport_asset': module})
        self.asset_patch.start()
        self.addCleanup(self.asset_patch.stop)
        self.chunked = self.new_service()

    def new_service(self, *, config=None, limits=None):
        service = FileExportService(self.catalog, ExportConfig(True, self.spool, min_free_bytes=0),
            chunked_config=config or ChunkedExportConfig(True, min_free_bytes=0),
            limits=limits or ExportLimits(close_seconds=.2), monotonic=self.clock.monotonic,
            wall_clock=self.clock.wall)
        service.start()
        self.services.append(service)
        return service

    async def chunk_ready(self, data=b'synthetic original', *, key='chunk-1', actor=None, service=None):
        service, actor = service or self.chunked, actor or self.actor
        self.write(data=data)
        c = service.capabilities(actor)
        result = await service.prepare_chunked_export(actor, 'synthetic', 'main', 'original.bin',
            c['service_instance_id'], c['request_window_id'], key, hashlib.sha256(data).hexdigest(), wait_seconds=0)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = await service.get_chunked_export_status(actor, result['export_id'])
            if result['state'] not in {'queued', 'preparing'}:
                self.assertEqual(result['state'], 'ready', result)
                return result
            await asyncio.sleep(.005)
        self.fail('synthetic chunk preparation did not settle')

    async def release(self, export_id, *, service=None, actor=None):
        service, actor = service or self.chunked, actor or self.actor
        await service.cancel_chunked_export(actor, export_id)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = await service.get_chunked_export_status(actor, export_id)
            if result['resources_released']:
                self.assertFalse(result['cleanup']['snapshot_fd_open'])
                return result
            await asyncio.sleep(.005)
        self.fail('actual source FD/reservation release did not settle')

    async def transfer(self, uri, *, service=None, actor=None):
        service, actor = service or self.chunked, actor or self.actor
        lease = service.open_chunked_resource(actor, uri.split('://')[1], asyncio.get_running_loop())
        payload = await asyncio.wait_for(lease.bytes_ready(), 3)
        lease.finish_construction()
        await asyncio.wait_for(lease.wait_checked(), 3)
        await lease.before_send()
        lease.sent()
        lease.mark_transport(asgi=True, sdk=True, final_body=True)
        await self.wait_until(lambda: lease.released and lease.owner_complete)
        return payload, lease

    async def test_thirty_megabyte_plan_and_actual_ranges(self):
        data = (bytes(range(256)) * 117188)[:30_000_000]
        self.assertEqual(len(data), 30_000_000)
        ready = await self.chunk_ready(data)
        plan = (await self.chunked.get_chunked_export_plan(self.actor, ready['export_id']))['plan']
        claimed = plan.pop('plan_sha256')
        self.assertEqual(hashlib.sha256(_json(plan)).hexdigest(), claimed)
        plan['plan_sha256'] = claimed
        self.assertEqual([p['bytes'] for p in plan['parts']], [8_000_000, 8_000_000, 8_000_000, 6_000_000])
        actual = hashlib.sha256()
        for part in plan['parts']:
            item = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], part['index'])
            payload, _ = await self.transfer(item['resource_uri'])
            self.assertLessEqual(len(payload), PART_MAX_BYTES)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), part['sha256'])
            actual.update(payload)
        self.assertEqual(actual.hexdigest(), plan['total_sha256'])
        self.assertNotIn('resource_uri', ready)
        self.assertEqual(ready['client_received'], 'not_observed')
        await self.release(ready['export_id'])

    async def test_empty_and_part_boundaries(self):
        for i, size in enumerate((0, 1, PART_MAX_BYTES - 1, PART_MAX_BYTES, PART_MAX_BYTES + 1, 29_999_999)):
            ready = await self.chunk_ready(b'x' * size, key='geometry-' + str(i))
            plan = (await self.chunked.get_chunked_export_plan(self.actor, ready['export_id']))['plan']
            self.assertEqual(sum(p['bytes'] for p in plan['parts']), size)
            self.assertEqual(plan['part_count'], max(1, (size + PART_MAX_BYTES - 1) // PART_MAX_BYTES))
            self.assertEqual([p['offset'] for p in plan['parts']], [n * PART_MAX_BYTES for n in range(plan['part_count'])])
            for p in plan['parts']:
                self.assertEqual(p['sha256'], hashlib.sha256(b'x' * p['bytes']).hexdigest())
            await self.release(ready['export_id'])

    async def test_over_capacity_has_no_snapshot(self):
        self.write(data=b'x' * 30_000_001)
        c = self.chunked.capabilities(self.actor)
        with self.assertRaises(AccessError) as error:
            await self.chunked.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin',
                c['service_instance_id'], c['request_window_id'], 'too-large')
        self.assertEqual(error.exception.code, 'client_ingestion_unverified')
        self.assertEqual(self.chunked.diagnostics()['snapshot_reservations'], 0)

    async def test_cross_mode_key_and_identifier_isolation(self):
        self.write()
        legacy = await self.ready(key='same-key', service=self.chunked)
        c = self.chunked.capabilities(self.actor)
        new = await self.chunked.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin',
            c['service_instance_id'], c['request_window_id'], 'same-key')
        while new['state'] in {'queued', 'preparing'}:
            await asyncio.sleep(.005)
            new = await self.chunked.get_chunked_export_status(self.actor, new['export_id'])
        self.assertNotEqual(new['export_id'], legacy['export_id'])
        self.assertIn('resource_uri', legacy)
        self.assertNotIn('resource_uri', new)
        with self.assertRaises(AccessError): await self.chunked.get_status(self.actor, new['export_id'])
        with self.assertRaises(AccessError): await self.chunked.get_chunked_export_status(self.actor, legacy['export_id'])
        item = await self.chunked.materialize_chunked_export_part(self.actor, new['export_id'], 0)
        with self.assertRaises(AccessError): self.chunked.open_resource(self.actor, item['resource_uri'].split('://')[1], asyncio.get_running_loop())
        with self.assertRaises(AccessError): self.chunked.open_chunked_resource(self.actor, new['export_id'], asyncio.get_running_loop())

    async def test_same_key_same_intent_one_parent_changed_constraint_conflicts(self):
        data = b'bound original'
        ready = await self.chunk_ready(data)
        c = self.chunked.capabilities(self.actor)
        again = await self.chunked.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin',
            c['service_instance_id'], c['request_window_id'], 'chunk-1', hashlib.sha256(data).hexdigest())
        self.assertEqual(again['export_id'], ready['export_id'])
        with self.assertRaises(AccessError) as error:
            await self.chunked.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin',
                c['service_instance_id'], c['request_window_id'], 'chunk-1', 'a' * 64)
        self.assertEqual(error.exception.code, 'idempotency_conflict')
        self.assertEqual(self.chunked.diagnostics()['snapshot_reservations'], 1)

    async def test_repeated_materialize_has_no_read_or_issuance_cost(self):
        ready = await self.chunk_ready()
        first = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        for _ in range(10):
            self.assertEqual(await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0), first)
        slot = self.chunked._records[ready['export_id']].slots['part-0']
        self.assertEqual((slot.issued_tokens, slot.actual_reads), (1, 0))

    async def test_third_read_finishes_fourth_read_refused(self):
        ready = await self.chunk_ready()
        item = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        for _ in range(3): await self.transfer(item['resource_uri'])
        slot = self.chunked._records[ready['export_id']].slots['part-0']
        self.assertEqual(slot.actual_reads, 3)
        with self.assertRaises(AccessError) as error: await self.transfer(item['resource_uri'])
        self.assertEqual(error.exception.code, 'retry_limit_exceeded')
        with self.assertRaises(AccessError): await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)

    async def test_third_issued_token_still_readable_old_tokens_revoked(self):
        ready = await self.chunk_ready()
        old = []
        for _ in range(2):
            old.append(await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0))
            self.clock.advance(601)
        third = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        for item in old:
            with self.assertRaises(AccessError): await self.transfer(item['resource_uri'])
        self.assertEqual((await self.transfer(third['resource_uri']))[0], b'synthetic original')
        slot = self.chunked._records[ready['export_id']].slots['part-0']
        self.assertEqual((slot.issued_tokens, slot.actual_reads), (3, 1))
        self.assertEqual((await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0))['resource_uri'], third['resource_uri'])

    async def test_busy_and_sdk_draining_keep_slot_and_shared_response(self):
        ready = await self.chunk_ready()
        item = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        lease = self.chunked.open_chunked_resource(self.actor, item['resource_uri'].split('://')[1], asyncio.get_running_loop())
        await lease.bytes_ready()
        with self.assertRaises(AccessError): await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        lease.finish_construction()
        await lease.wait_checked()
        lease.mark_transport(asgi=True, final_body=True)
        await asyncio.sleep(.02)
        self.assertFalse(lease.released)
        self.assertEqual(self.chunked.diagnostics()['active_responses'], 1)
        with self.assertRaises(AccessError): await self.transfer(item['resource_uri'])
        slot = self.chunked._records[ready['export_id']].slots['part-0']
        self.assertEqual((slot.issued_tokens, slot.actual_reads), (1, 1))
        lease.mark_transport(sdk=True)
        await self.wait_until(lambda: lease.released)

    async def test_helper_slot_uses_same_actor_scope(self):
        ready = await self.chunk_ready()
        item = await self.chunked.materialize_chunked_export_receiver(self.actor, ready['export_id'])
        self.assertEqual((await self.transfer(item['resource_uri']))[0], self.asset_bytes)
        with self.assertRaises(AccessError): await self.transfer(item['resource_uri'], actor=self.actor_for('other'))
        self.assertEqual(self.chunked._records[ready['export_id']].slots['receiver'].actual_reads, 1)

    async def test_parent_deadline_is_absolute_and_fresh_actor_cannot_revive(self):
        ready = await self.chunk_ready()
        before = (await self.chunked.get_chunked_export_plan(self.actor, ready['export_id']))['plan']
        self.clock.advance(601)
        await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        self.assertEqual((await self.chunked.get_chunked_export_plan(self.actor, ready['export_id']))['plan'], before)
        self.clock.advance(3000)
        fresh = self.actor_for('owner-a')
        self.assertEqual((await self.chunked.get_chunked_export_status(fresh, ready['export_id']))['state'], 'expired')
        with self.assertRaises(AccessError): await self.chunked.materialize_chunked_export_part(fresh, ready['export_id'], 0)

    async def test_fresh_jwt_same_actor_can_continue_ready_parent(self):
        short = replace(self.actor, expires_at=self.clock.wall() + 20, deadline=20)
        ready = await self.chunk_ready(actor=short)
        self.clock.advance(21)
        fresh = self.actor_for('owner-a')
        item = await self.chunked.materialize_chunked_export_part(fresh, ready['export_id'], 0)
        with self.assertRaises(AccessError): await self.transfer(item['resource_uri'], actor=short)
        self.assertEqual((await self.transfer(item['resource_uri'], actor=fresh))[0], b'synthetic original')

    async def test_plan_copy_strict_index_and_disabled_policy(self):
        ready = await self.chunk_ready()
        result = await self.chunked.get_chunked_export_plan(self.actor, ready['export_id'])
        result['plan']['parts'][0]['offset'] = 999
        self.assertEqual((await self.chunked.get_chunked_export_plan(self.actor, ready['export_id']))['plan']['parts'][0]['offset'], 0)
        for invalid in (True, -1, 0.0, '0', 1):
            with self.assertRaises(AccessError): await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], invalid)
        disabled = self.new_service(config=ChunkedExportConfig(False, min_free_bytes=0))
        self.assertFalse(disabled.chunked_capabilities(self.actor)['enabled'])
        c = disabled.capabilities(self.actor)
        with self.assertRaises(AccessError): await disabled.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin', c['service_instance_id'], c['request_window_id'], 'disabled')

    async def test_cancel_waits_for_actual_owners_and_fd_close(self):
        ready = await self.chunk_ready()
        item = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        lease = self.chunked.open_chunked_resource(self.actor, item['resource_uri'].split('://')[1], asyncio.get_running_loop())
        await lease.bytes_ready()
        self.assertFalse((await self.chunked.cancel_chunked_export(self.actor, ready['export_id']))['resources_released'])
        lease.finish_construction(failed=True)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        result = await self.release(ready['export_id'])
        self.assertEqual(result['state'], 'cancelled')
        self.assertEqual(self.chunked.diagnostics()['snapshot_bytes_reserved'], 0)

    async def test_uncertain_close_preserves_reservation(self):
        ready = await self.chunk_ready()
        record = self.chunked._records[ready['export_id']]
        fd = record.snapshot.fd
        def hook(stage, value):
            if stage == 'before_snapshot_close' and value == fd: raise OSError('synthetic close uncertainty')
        self.chunked.fault_hook = hook
        self.known_unclosed.append(fd)
        await self.chunked.cancel_chunked_export(self.actor, ready['export_id'])
        await self.wait_until(lambda: self.chunked._uncertain_close)
        result = await self.chunked.get_chunked_export_status(self.actor, ready['export_id'])
        self.assertFalse(result['resources_released'])
        self.assertEqual(result['operation_state'], 'shutdown_pending')
        self.assertTrue(record.reserved)

    async def test_key_budget_shared_across_both_namespaces(self):
        service = self.new_service(limits=ExportLimits(keys=1, close_seconds=.2))
        self.write()
        await self.ready(service=service)
        c = service.capabilities(self.actor)
        with self.assertRaises(AccessError) as error:
            await service.prepare_chunked_export(self.actor, 'synthetic', 'main', 'original.bin', c['service_instance_id'], c['request_window_id'], 'new-key')
        self.assertEqual(error.exception.code, 'resource_budget_exhausted')
        self.assertEqual(service.diagnostics()['keys'], 1)

    async def test_cancel_release_receipt_survives_request_window_rotation(self):
        ready = await self.chunk_ready()
        self.clock.advance(901)
        self.chunked.capabilities(self.actor)
        result = await self.release(ready['export_id'])
        self.assertTrue(result['resources_released'])
        again = await self.chunked.get_chunked_export_status(self.actor, ready['export_id'])
        self.assertTrue(again['resources_released'])

    async def test_unknown_auxiliary_close_is_not_reported_released(self):
        ready = await self.chunk_ready()
        item = await self.chunked.materialize_chunked_export_receiver(self.actor, ready['export_id'])
        module = sys.modules['peters_mcp.transport_asset']
        def uncertain():
            raise AccessError('synthetic unknown asset close', code='protection_cleanup_pending')
        module.load_receiver_asset = uncertain
        lease = self.chunked.open_chunked_resource(self.actor, item['resource_uri'].split('://')[1], asyncio.get_running_loop())
        with self.assertRaises(AccessError): await lease.bytes_ready()
        lease.finish_construction(failed=True)
        lease.mark_transport(asgi=True, sdk=True)
        await self.wait_until(lambda: lease.released)
        self.assertFalse((await self.chunked.cancel_chunked_export(self.actor, ready['export_id']))['resources_released'])
        # Synthetic seam has no real uncertain FD; product keeps its reservation.
        self.chunked._pending_aux.clear()

    async def test_reissued_token_cannot_resurrect_an_older_revoked_token(self):
        ready = await self.chunk_ready()
        first = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        self.clock.advance(601)
        await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        self.clock.advance(601)
        with patch('peters_mcp.file_export.secrets.token_hex', return_value=first['resource_uri'].split('://')[1]):
            with self.assertRaises(AccessError): await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        self.assertEqual(self.chunked._records[ready['export_id']].slots['part-0'].issued_tokens, 2)

    async def test_shutdown_pending_status_does_not_bypass_source_redaction(self):
        ready = await self.chunk_ready()
        self.chunked._pending_aux.add(('metadata', 123))
        pending = await self.chunked.get_chunked_export_status(self.actor, ready['export_id'])
        for key in ('source', 'bytes', 'sha256', 'plan_sha256', 'captured_at', 'slots'):
            self.assertNotIn(key, pending)
        self.chunked._pending_aux.clear()

    async def test_parent_stream_fact_requires_every_data_part_not_helper_only(self):
        ready = await self.chunk_ready(b'x' * (PART_MAX_BYTES + 1))
        helper = await self.chunked.materialize_chunked_export_receiver(self.actor, ready['export_id'])
        await self.transfer(helper['resource_uri'])
        self.assertFalse((await self.chunked.get_chunked_export_status(self.actor, ready['export_id']))['server_stream_finished'])
        first = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 0)
        await self.transfer(first['resource_uri'])
        self.assertFalse((await self.chunked.get_chunked_export_status(self.actor, ready['export_id']))['server_stream_finished'])
        second = await self.chunked.materialize_chunked_export_part(self.actor, ready['export_id'], 1)
        await self.transfer(second['resource_uri'])
        status = await self.chunked.get_chunked_export_status(self.actor, ready['export_id'])
        self.assertTrue(status['server_stream_finished'])
        self.assertEqual(status['client_received'], 'not_observed')


class ChunkedConfigTests(unittest.TestCase):
    def test_private_configuration_identity_and_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'chunked.json'
            value = {'version': 1, 'enabled': True, 'max_file_bytes': 30_000_000,
                     'min_free_bytes': 0, 'protocol_version': 'raw-parts-v1'}
            p.write_text(json.dumps(value)); p.chmod(0o600)
            config = read_chunked_export_config(p)
            self.assertEqual(config.current(), config.current())
            p.write_text(json.dumps(value))
            with self.assertRaises(AccessError): config.current()
            p.chmod(0o644)
            with self.assertRaises(AccessError): read_chunked_export_config(p)
            p.chmod(0o600)
            for maximum in (True, 0, 100_000_001, 30_000_000.0):
                value['max_file_bytes'] = maximum; p.write_text(json.dumps(value))
                with self.assertRaises(AccessError): read_chunked_export_config(p)
            p.write_text('{"version":1,"version":1}')
            with self.assertRaises(AccessError): read_chunked_export_config(p)
        self.assertFalse(read_chunked_export_config(None).enabled)

    def test_inspection_release_checks_config_but_does_not_enable_without_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'chunked.json'
            p.write_text(json.dumps({'version': 1, 'enabled': True, 'max_file_bytes': 30_000_000,
                                    'min_free_bytes': 0, 'protocol_version': 'raw-parts-v1'}))
            p.chmod(0o600)
            with patch('peters_mcp._file_release_mode.INSPECTION_ONLY', True):
                self.assertIsNone(load_export_service(None, None, chunked_config_path=p))
            with patch('peters_mcp._file_release_mode.INSPECTION_ONLY', False):
                with self.assertRaises(AccessError): load_export_service(None, None, chunked_config_path=p)
            p.write_text('{}')
            with patch('peters_mcp._file_release_mode.INSPECTION_ONLY', True):
                with self.assertRaises(AccessError): load_export_service(None, None, chunked_config_path=p)
