import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mcp.client import Client
from peters_mcp.catalog import AccessError, Catalog, Project
from peters_mcp.candidates import CandidateDelivery, MAX_DOCUMENT_BYTES, publish_exclusive
from peters_mcp.server import create_server
from peters_mcp.audit import audit_request_id


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.directory = self.root / "docs/candidates/chatgpt"
        self.directory.mkdir(parents=True)
        self.catalog = Catalog([Project("demo", "Demo", self.root,
                                        candidate_directory="docs/candidates/chatgpt")])
        self.delivery = CandidateDelivery(self.catalog)

    def prepare(self, name="plan.md", body="# 研究方案\n\n候选内容，等待项目评估。"):
        return self.delivery.prepare_candidate("demo", name, body)["save_arguments"]

    def test_preview_does_not_write_and_save_returns_exact_identity(self):
        args = self.prepare()
        self.assertEqual(list(self.directory.iterdir()), [])
        result = self.delivery.save_candidate(**args)
        raw = (self.root / result["path"]).read_bytes()
        self.assertEqual(raw, args["document"].encode())
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["classification"], "candidate_only")
        self.assertFalse(result["codex_started"])
        self.assertEqual((self.root / result["path"]).stat().st_nlink, 1)

    def test_existing_file_is_never_overwritten_including_after_preview(self):
        args = self.prepare()
        target = self.root / args["path"]
        target.write_text("user work")
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        with self.assertRaises(AccessError):
            self.prepare()
        self.assertEqual(target.read_text(), "user work")

    def test_content_target_hash_and_preparation_tampering_are_rejected(self):
        args = self.prepare()
        for changes in ({"document": "different"}, {"path": "docs/candidates/chatgpt/other.md"},
                        {"sha256": "0" * 64}, {"preparation": "fake"}, {"project_id": "other"},
                        {"document": "different", "sha256": hashlib.sha256(b"different").hexdigest()}):
            with self.subTest(changes=list(changes)), self.assertRaises(AccessError):
                self.delivery.save_candidate(**{**args, **changes})
        self.assertFalse(list(self.directory.iterdir()))

    def test_path_and_rule_filename_restrictions(self):
        for name in ("../x.md", "/tmp/x.md", "a/b.md", "x.py", "AGENTS.md", "CLAUDE.md", "SKILL.md",
                     "x\\y.md", "x\x00.md", ".md", "hidden/.env.md", "a" * 170 + ".md"):
            with self.subTest(name=name), self.assertRaises(AccessError):
                self.prepare(name)
        self.assertTrue(self.prepare("研究方案-v1.md"))
        args = self.prepare()
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**{**args, "path": "README.md"})

    def test_versioned_filenames_keep_path_and_rule_restrictions(self):
        for name in (".hidden.md", "plan..v1.md", "plan..md", "plan.v1/.md", "../plan-v1.0.md",
                     "AGENTS.md", "CLAUDE.md", "SKILL.md", "plan v1.0.md"):
            with self.subTest(name=name), self.assertRaises(AccessError):
                self.prepare(name)
        for name in ("plan-v2.1.md", "research-v1.0.3.md", "研究方案-v2.1.md"):
            with self.subTest(name=name):
                args = self.prepare(name)
                saved = self.delivery.save_candidate(**args)
                self.assertEqual(self.catalog.read_file("demo", saved['path'])['sha256'], args['sha256'])
                with self.assertRaises(AccessError):
                    self.prepare(name)

    def test_large_versioned_document_mcp_delivery_and_safe_error_audit(self):
        logs = io.StringIO()
        audit = logging.Logger("test.candidate.audit")
        audit.addHandler(logging.StreamHandler(logs))
        body = "# 合成大文档\n\n" + "合成内容。" * 3100
        self.assertGreater(len(body.encode()), 46000)

        async def run():
            async with Client(create_server(self.catalog, audit)) as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                self.assertFalse(tools['save_candidate'].annotations.read_only_hint)
                prepared = await client.call_tool("prepare_candidate", {
                    "project_id": "demo", "filename": "large-v2.1.md", "markdown": body})
                self.assertFalse(prepared.is_error)
                args = json.loads(prepared.content[0].text)['save_arguments']
                self.assertLessEqual(len(args['document'].encode()), MAX_DOCUMENT_BYTES)
                self.assertFalse(list(self.directory.iterdir()))
                saved = await client.call_tool("save_candidate", args)
                self.assertFalse(saved.is_error)
                read = await client.call_tool("read_file", {"project_id": "demo", "path": args['path']})
                self.assertEqual(json.loads(read.content[0].text)['sha256'], args['sha256'])
                failed = await client.call_tool("prepare_candidate", {
                    "project_id": "demo", "filename": "private note.md", "markdown": "PRIVATE_BODY"})
                self.assertTrue(failed.is_error)
                self.assertIn("candidate_filename_invalid", failed.content[0].text)
                oversized = await client.call_tool("prepare_candidate", {
                    "project_id": "demo", "filename": "large-v3.0.md", "markdown": "x" * MAX_DOCUMENT_BYTES})
                self.assertTrue(oversized.is_error)
                self.assertIn("candidate_document_too_large", oversized.content[0].text)
                with patch.object(CandidateDelivery, 'prepare_candidate', side_effect=RuntimeError("SECRET_EXCEPTION")):
                    unexpected = await client.call_tool("prepare_candidate", {
                        "project_id": "demo", "filename": "exception.md", "markdown": "PRIVATE_BODY"})
                    self.assertTrue(unexpected.is_error)
                    self.assertNotIn("SECRET_EXCEPTION", unexpected.content[0].text)
                return args

        token = audit_request_id.set("f" * 32)
        try:
            args = asyncio.run(run())
        finally:
            audit_request_id.reset(token)
        records = [json.loads(line) for line in logs.getvalue().splitlines()]
        failures = [r['error_code'] for r in records if not r['ok']]
        self.assertEqual(failures, ['candidate_filename_invalid', 'candidate_document_too_large', 'internal_error'])
        self.assertTrue(all(r['request_id'] == "f" * 32 for r in records))
        self.assertEqual(len({r['call_id'] for r in records}), len(records))
        for value in (body, args['preparation'], 'PRIVATE_BODY', 'private note.md', 'SECRET_EXCEPTION'):
            self.assertNotIn(value, logs.getvalue())

    def test_project_requires_explicit_write_configuration(self):
        service = CandidateDelivery(Catalog([Project("demo", "Demo", self.root)]))
        with self.assertRaises(AccessError):
            service.prepare_candidate("demo", "x.md", "hello")

    def test_links_are_refused(self):
        args = self.prepare()
        outside = self.root.parent / "external.md"
        outside.write_text("protected")
        target = self.root / args["path"]
        target.symlink_to(outside)
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertEqual(outside.read_text(), "protected")

    def test_directory_symlink_and_identity_changes_are_refused(self):
        args = self.prepare()
        moved = self.directory.with_name("old")
        self.directory.rename(moved)
        self.directory.symlink_to(moved)
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.directory.unlink()
        self.directory.mkdir()
        with self.assertRaisesRegex(AccessError, "directory changed"):
            self.delivery.save_candidate(**args)

    def test_retry_and_parallel_same_delivery_do_not_duplicate(self):
        args = self.prepare()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.delivery.save_candidate(**args), range(8)))
        self.assertEqual(sum(r["status"] == "saved" for r in results), 1)
        self.assertEqual(sum(r["status"] == "already_saved" for r in results), 7)
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_competing_previews_never_replace_each_other(self):
        first, second = self.prepare(body="first"), self.prepare(body="second")
        self.delivery.save_candidate(**first)
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**second)
        self.assertEqual((self.root / first["path"]).read_text(), first["document"])

    def test_modified_or_deleted_deliveries_are_not_recreated(self):
        args = self.prepare()
        self.delivery.save_candidate(**args)
        target = self.root / args["path"]
        target.write_text("edited by Codex")
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertEqual(target.read_text(), "edited by Codex")
        target.unlink()
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)
        self.assertFalse(target.exists())

    def test_expired_and_restarted_previews_fail_closed(self):
        args = self.prepare()
        with patch("peters_mcp.candidates.time.time", return_value=time.time() + 7200):
            with self.assertRaisesRegex(AccessError, "expired"):
                self.delivery.save_candidate(**args)
        with self.assertRaisesRegex(AccessError, "restarted"):
            CandidateDelivery(self.catalog).save_candidate(**args)

    def test_write_failure_leaves_no_partial_candidate(self):
        args = self.prepare()
        with patch("peters_mcp.candidates.os.write", side_effect=OSError("disk full")):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        self.assertEqual(list(self.directory.iterdir()), [])
        with self.assertRaises(AccessError):
            self.delivery.save_candidate(**args)

    def test_late_failure_can_be_verified_by_exact_retry(self):
        args = self.prepare()
        def late_failure(*values):
            publish_exclusive(*values)
            raise OSError("simulated lost acknowledgment")
        with patch("peters_mcp.candidates.publish_exclusive", side_effect=late_failure):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        self.assertEqual(self.delivery.save_candidate(**args)["status"], "already_saved")

    def test_publish_race_no_clobber(self):
        args = self.prepare()
        target = self.root / args["path"]
        def race(*values):
            target.write_text("concurrent user work")
            publish_exclusive(*values)
        with patch("peters_mcp.candidates.publish_exclusive", side_effect=race):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)
        self.assertEqual(target.read_text(), "concurrent user work")

    def test_late_directory_move_never_claims_success(self):
        args = self.prepare()
        def move(*values):
            self.directory.rename(self.root.parent / "moved")
            self.directory.mkdir()
            publish_exclusive(*values)
        with patch("peters_mcp.candidates.publish_exclusive", side_effect=move):
            with self.assertRaises(AccessError):
                self.delivery.save_candidate(**args)

    def test_size_and_control_character_limits(self):
        for text in ("", "\x00", "a" * MAX_DOCUMENT_BYTES):
            with self.assertRaises(AccessError):
                self.prepare(body=text)

    def test_published_file_deleted_during_verification_never_claims_success(self):
        args = self.prepare()
        original = self.delivery._existing
        calls = 0
        def deleting_check(fd, filename, raw):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.root / args["path"]).unlink()
            return original(fd, filename, raw)
        with patch.object(self.delivery, "_existing", side_effect=deleting_check):
            with self.assertRaisesRegex(AccessError, "disappeared"):
                self.delivery.save_candidate(**args)
        self.assertFalse((self.root / args["path"]).exists())

    def test_config_rejects_broad_or_missing_candidate_directory(self):
        config = self.root.parent / "config.json"
        for directory in ("docs", "../candidates", "missing/candidates", "/tmp/candidates"):
            config.write_text(json.dumps({"projects": [{"id": "demo", "name": "Demo",
                             "root": str(self.root), "candidate_directory": directory}]}))
            with self.subTest(directory=directory), self.assertRaises(AccessError):
                Catalog.from_config(config)

    def test_real_mcp_prepare_confirm_payload_save_and_readback(self):
        async def run():
            async with Client(create_server(self.catalog)) as client:
                prepared = await client.call_tool("prepare_candidate", {
                    "project_id": "demo", "filename": "mcp-test.md", "markdown": "# MCP 验证\n\nsynthetic-only"})
                self.assertFalse(prepared.is_error)
                preview = json.loads(prepared.content[0].text)
                self.assertFalse(list(self.directory.iterdir()))
                args = preview["save_arguments"]
                result = await client.call_tool("save_candidate", args)
                self.assertFalse(result.is_error)
                read = await client.call_tool("read_file", {"project_id": "demo", "path": args["path"]})
                self.assertEqual(json.loads(read.content[0].text)["sha256"], args["sha256"])
                retry = await client.call_tool("save_candidate", args)
                self.assertEqual(json.loads(retry.content[0].text)["status"], "already_saved")
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
