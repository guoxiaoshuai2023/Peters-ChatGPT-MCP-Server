"""Compressed Codex rollouts retain the same authorization and snapshot checks."""

import hashlib
import json
import os
import sqlite3
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.history_source import zstd
from peters_mcp.history_process import IsolatedHistory
from tests import test_history as explicit
from tests import test_history_inheritance as inherited
from tests.test_history_limits import complete


class CompressedHistoryTests(unittest.TestCase):
    def fixture(self, kind=inherited.InheritanceTests):
        f = kind()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.history.close)
        return f

    @staticmethod
    def compress(path):
        raw = path.read_bytes()
        compressed = path.with_suffix(path.suffix + '.zst')
        compressed.write_bytes(zstd.compress(raw))
        path.unlink()
        return compressed, raw

    def test_legacy_index_path_finds_exact_compressed_sibling_and_pages(self):
        f = self.fixture()
        path, raw = self.compress(f.thread())
        first = f.history.read_codex_thread(inherited.FIRST, limit=1)
        second = f.history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(first['snapshot']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(first['snapshot']['bytes'], len(raw))
        self.assertEqual(first['snapshot']['stored_bytes'], path.stat().st_size)
        self.assertEqual(first['snapshot']['storage_encoding'], 'zstd')
        self.assertFalse(second['appended_since_snapshot'])
        self.assertEqual(second['entries'][0]['text'], 'public final answer')
        self.assertEqual(f.history.find_codex_threads()['threads'][0]['thread_id'], inherited.FIRST)

    def test_direct_zstd_path_with_uuid_suffix_and_archive_is_supported(self):
        f = self.fixture()
        original = f.thread(archived=True)
        path = original.with_name(f'rollout-test-{inherited.FIRST}_{inherited.SECOND}.jsonl')
        original.rename(path)
        compressed, _ = self.compress(path)
        with sqlite3.connect(f.db) as db:
            db.execute('UPDATE threads SET rollout_path=? WHERE id=?', (str(compressed), inherited.FIRST))
        page = f.history.read_codex_thread(inherited.FIRST)
        self.assertTrue(page['thread']['archived'])
        self.assertEqual(len(page['entries']), 2)

    def test_concatenated_frames_preserve_old_prefix_and_detect_new_public_text(self):
        f = self.fixture()
        path, _ = self.compress(f.thread())
        first = f.history.read_codex_thread(inherited.FIRST, limit=1)
        with path.open('ab') as stream:
            stream.write(zstd.compress(inherited.encoded([inherited.message('new compressed frame')]).encode()))
        second = f.history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(first['snapshot'], second['snapshot'])
        self.assertTrue(second['appended_since_snapshot'])
        current = f.history.read_codex_thread(inherited.FIRST)
        self.assertEqual(current['entries'][-1]['text'], 'new compressed frame')

    def test_foreign_context_in_new_frame_revokes_old_cursor(self):
        f = self.fixture()
        path, _ = self.compress(f.thread())
        first = f.history.read_codex_thread(inherited.FIRST, limit=1)
        with path.open('ab') as stream:
            stream.write(zstd.compress(inherited.encoded([
                inherited.record('turn_context', {'cwd': str(f.foreign)})]).encode()))
        with self.assertRaises(AccessError):
            f.history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(f.history.find_codex_threads()['threads'], [])

    def test_corrupt_truncated_and_garbage_frames_never_return_partial_history(self):
        for mode in ('truncated', 'garbage', 'invalid'):
            with self.subTest(mode=mode):
                f = self.fixture()
                path, _ = self.compress(f.thread())
                data = path.read_bytes()
                path.write_bytes(data[:-1] if mode == 'truncated' else
                                 data + b'not-a-frame' if mode == 'garbage' else b'not-zstd')
                with self.assertRaises(AccessError) as caught:
                    f.history.read_codex_thread(inherited.FIRST)
                self.assertEqual(caught.exception.code, 'unverifiable_source')
                self.assertFalse(f.history._snapshots)

    def test_linked_compressed_sibling_cannot_bypass_safe_open(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                f = self.fixture()
                path, _ = self.compress(f.thread())
                other = f.base / 'external.zst'
                path.rename(other)
                if kind == 'symlink':
                    path.symlink_to(other)
                else:
                    os.link(other, path)
                with self.assertRaises(AccessError):
                    f.history.read_codex_thread(inherited.FIRST)

    def test_present_invalid_plain_source_cannot_fall_back_to_compressed(self):
        f = self.fixture()
        original = f.thread()
        self.compress(original)
        original.write_text(inherited.encoded([
            inherited.record('session_meta', {'id': inherited.SECOND, 'cwd': str(f.repo)})]))
        with self.assertRaises(AccessError):
            f.history.read_codex_thread(inherited.FIRST)

    def test_storage_replacement_requires_fresh_read_even_if_content_matches(self):
        f = self.fixture()
        path = f.thread()
        first = f.history.read_codex_thread(inherited.FIRST, limit=1)
        self.compress(path)
        with self.assertRaises(AccessError):
            f.history.read_codex_thread(inherited.FIRST, limit=1, cursor=first['next_cursor'])
        self.assertEqual(f.history.read_codex_thread(inherited.FIRST)['snapshot']['storage_encoding'], 'zstd')

    def test_compressed_tool_offsets_are_decoded_offsets_and_stay_filtered(self):
        f = self.fixture(explicit.HistoryTests)
        f.tool_enabled()
        f.records.insert(1, explicit.record('response_item', {
            'type': 'reasoning', 'encrypted_content': 'x' * (1024 * 1024)}))
        f.path.write_bytes(explicit.encode(f.records))
        self.compress(f.path)
        page = f.history.read_codex_thread(explicit.FIRST, include_tool_refs=True)
        item = next(e for e in page['entries'] if e['kind'] == 'tool_reference')
        result = f.history.read_codex_thread_item(explicit.FIRST, item['item_id'])
        self.assertIn('PASSED', result['text'])
        self.assertNotIn('TOPSECRET', result['text'])
        self.assertNotIn('HIDDEN_', json.dumps(page) + result['text'])

    def test_isolated_worker_reads_large_compressed_attachment_with_project_inheritance(self):
        f = self.fixture()
        path = f.thread()
        with path.open('ab') as stream:
            stream.write(b'{"type":"response_item","payload":{"type":"message","content":"')
            for _ in range(20):
                stream.write(b'x' * (1024 * 1024))
            stream.write(b'"}}\n')
        self.compress(path)
        facade = IsolatedHistory(f.history)
        self.addCleanup(facade.close)
        page = complete(facade, {'thread_id': inherited.FIRST})
        self.assertEqual(page['thread']['association']['source'], 'repository_inheritance')
        self.assertEqual(page['warnings']['oversized_record_excluded'], 1)
        self.assertEqual(len(page['entries']), 2)
        self.assertLess(facade._peak_rss, 256 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
