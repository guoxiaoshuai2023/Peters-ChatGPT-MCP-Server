"""Fixed delivery identity stays consistent without claiming native acceptance."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp import file_export as exports
from peters_mcp import transport_asset as asset
from peters_mcp.server import create_server
from tests.test_large_export_service import LargeExportFixture


ROOT = Path(__file__).resolve().parents[1]


def contract():
    document = (ROOT / 'ORIGINAL_FILE_EXPORT.md').read_text()
    found = re.findall(r'<!-- canonical-delivery-contract:start -->\s*```json\s*(.*?)\s*```\s*'
                       r'<!-- canonical-delivery-contract:end -->', document, re.S)
    if len(found) != 1:
        raise AssertionError('Exactly one canonical contract is required.')
    return json.loads(found[0])


class DeliveryContractTests(unittest.TestCase):
    def test_canonical_digest_binds_actual_limits_and_pinned_receiver_bytes(self):
        profile = contract()
        canonical = json.dumps(profile, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), exports.PROFILE_SHA256)
        self.assertEqual(profile['profile_id'], exports.PROFILE_ID)
        self.assertEqual(profile['max_original_bytes'], exports.MAX_ORIGINAL_BYTES)
        self.assertEqual(profile['part_max_bytes'], exports.PART_MAX_BYTES)
        limits = exports.ExportLimits()
        budget = profile['budgets']
        for key, attribute in {
            'snapshot_bytes_global': 'snapshot_bytes', 'snapshot_bytes_per_actor': 'actor_snapshot_bytes',
            'snapshots_global': 'snapshots', 'snapshots_per_actor': 'actor_snapshots',
            'records_global': 'records', 'records_per_actor': 'actor_records',
            'request_keys_global': 'keys', 'request_keys_per_actor': 'actor_keys',
            'metadata_bytes': 'metadata_bytes',
        }.items():
            self.assertEqual(budget[key], getattr(limits, attribute))
        self.assertEqual(budget['serialization_bytes_per_response'], exports.SERIALIZATION_BYTES)
        self.assertEqual(budget['stream_chunk_bytes'], exports.STREAM_CHUNK)
        self.assertEqual(budget['asgi_chunk_bytes'], exports.CHUNK)
        for key, attribute in {
            'request_window': 'window_seconds', 'snapshot_ready': 'ready_seconds',
            'snapshot_absolute': 'absolute_seconds', 'materialization_reference': 'delivery_seconds',
            'active_transfer': 'transfer_seconds', 'send_idle': 'idle_seconds',
            'queued': 'queue_seconds', 'preparation': 'preparation_seconds',
            'terminal_receipt': 'window_seconds',
        }.items():
            self.assertEqual(profile['lifetimes_seconds'][key], getattr(limits, attribute))
        receiver = (ROOT / 'peters_mcp/native_range_receiver.py').read_bytes()
        self.assertEqual(len(receiver), asset.RECEIVER_BYTES)
        self.assertEqual(hashlib.sha256(receiver).hexdigest(), asset.RECEIVER_SHA256)
        self.assertEqual(profile['receiver_asset'], {
            key: asset.receiver_metadata()[key] for key in ('asset_id', 'version', 'name', 'bytes', 'sha256')})
        self.assertFalse(profile['single_attachment_primitive_verified'])
        self.assertTrue(profile['per_original_native_verification_required'])
        self.assertEqual(profile['production_qualification'],
                         'external_fixed_payload_native_and_compatibility_evidence_required')
        example = json.loads((ROOT / 'original-exports.example.json').read_text())
        self.assertEqual(example['profile_id'], exports.PROFILE_ID)
        self.assertEqual(example['max_file_bytes'], exports.MAX_ORIGINAL_BYTES)


class ProfileDeclarationTests(LargeExportFixture):
    async def test_final_identity_and_claims_do_not_invent_native_receipt(self):
        capabilities = self.service.capabilities(self.actor)
        ingestion = capabilities['client_ingestion']
        self.assertEqual(capabilities['delivery_profile_id'], exports.PROFILE_ID)
        self.assertEqual(ingestion['validation'], 'requires_native_evidence')
        self.assertEqual(ingestion['delivery_contract_sha256'], exports.PROFILE_SHA256)
        self.assertEqual(ingestion['verified_mime_types'], [])
        self.assertTrue(ingestion['verification_required'])
        self.assertEqual(ingestion['transport'], 'native_raw_part_assembly')
        self.assertEqual(ingestion['pro_compatibility'], 'not_tested')
        zip_cap = self.service.file_capabilities(SimpleNamespace(size=1, mime_type='application/zip'))
        other = self.service.file_capabilities(SimpleNamespace(size=1, mime_type='application/pdf'))
        self.assertEqual(zip_cap['client_ingestion']['validation'], 'requires_native_evidence')
        self.assertEqual(other['client_ingestion']['validation'], 'format_not_tested')
        self.write(data=b'actual small synthetic bytes')
        ready = await self.ready()
        plan = await self.service.get_transport_plan(self.actor, ready['export_id'])
        self.assertEqual(plan['delivery_mode'], 'native_raw_part_assembly')
        self.assertFalse(plan['single_attachment_primitive_verified'])
        self.assertFalse(plan['native_assembled_original_verified'])
        self.assertEqual(plan['client_received'], 'not_observed')
        self.assertEqual(self.service.diagnostics()['part_plan_pins'], 0)
        self.assertEqual(self.service.diagnostics()['materialization_references'], 0)

    def test_identity_change_requires_new_config_and_version_is_contract_only(self):
        legacy = replace(self.service.config, profile_id=exports.LEGACY_PROFILE_ID)
        legacy.validate()
        self.assertNotEqual(self.service.config.current(), legacy.current())
        with self.assertRaises(AccessError) as denied:
            replace(self.service.config,
                    profile_id='chatgpt-web-gpt56sol-high-streamed-resource-200mb-development-v1').validate()
        self.assertEqual(denied.exception.code, 'export_config_invalid')
        with self.assertRaises(AccessError):
            replace(self.service.config, max_file_bytes=200_000_001).validate()
        server = create_server(self.catalog, exports=self.service)
        self.assertEqual(server.version, contract()['server_version'])
        self.assertIn('contract digest is not a native acceptance', server.instructions)


if __name__ == '__main__':
    unittest.main()
