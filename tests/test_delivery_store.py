import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from peters_mcp.catalog import AccessError
from peters_mcp.candidates import publish_exclusive
from peters_mcp.delivery_store import DeliveryStore
from peters_mcp.delivery_types import DeliveryLimits, DeliveryTarget, OpenAIFile


class Policy:
    def __init__(self, root):
        self.root = root
        self.parent = root / "packages"
        self.parent.mkdir(parents=True)
        self.settings = DeliveryLimits()
        self.enabled = True
        self.version = "v1"
        self.initial = self.resolve("demo-target")

    def limits(self):
        return self.settings

    def sources(self):
        return {"files.example.test": ("93.184.215.14",)}

    def resolve(self, target_id):
        if target_id != "demo-target" or not self.enabled:
            raise AccessError("Target not granted.", code="target_not_granted")
        root, parent = self.root.stat(), self.parent.lstat()
        return DeliveryTarget(target_id, "Synthetic package target", "demo", self.root,
                              ("packages",), "git-synthetic", (root.st_dev, root.st_ino),
                              (parent.st_dev, parent.st_ino), self.version)

    def revalidate(self, snapshot):
        if snapshot != self.resolve(snapshot.target_id) or self.parent.is_symlink():
            raise AccessError("Target changed.", code="scope_changed")

    @contextmanager
    def open_parent(self, snapshot):
        self.revalidate(snapshot)
        fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.revalidate(snapshot)
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != snapshot.parent_identity:
                raise AccessError("Parent replaced.", code="scope_changed")
            yield fd
            self.revalidate(snapshot)
        finally:
            os.close(fd)


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as handle:
        for name, content in files.items():
            handle.writestr(name, content)
    return output.getvalue()


class DeliveryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.policy = Policy(self.root / "repo")
        self.state = self.root / "state"
        self.files = {
            "00-README.md": b"# Synthetic package\r\n",
            "nested/计划-v1.0.md": (b"# Versioned source\r\n" + b"x" * 58417),
            "run-config.json": b'\xef\xbb\xbf{"enabled": false}\r\n',
            "notes.txt": "原样交付\r\n".encode(),
            "checks.md": b"Do not execute.\n",
        }
        self.files["MANIFEST.sha256"] = "".join(hashlib.sha256(raw).hexdigest() + "  " + path + "\r\n"
                                                     for path, raw in self.files.items()).encode()
        self.raw = archive(self.files)
        self.reference = OpenAIFile(download_url="https://files.example.test/archive?private=never-store",
                                    file_id="ephemeral-never-store", file_name="synthetic-v1.0.zip")
        self.store = DeliveryStore(self.state, self.policy, downloader=self.download)
        self.addCleanup(lambda: self.store.close())

    def download(self, file, destination, expected_sha256, sources, limits):
        destination.write_bytes(self.raw)
        return {"size_bytes": len(self.raw), "sha256": hashlib.sha256(self.raw).hexdigest()}

    def receive(self, version="v1.0", actor="verified-actor"):
        result = self.store.stage(actor, self.reference, "demo-target", version, hashlib.sha256(self.raw).hexdigest())
        for _ in range(400):
            result = self.store.inspect(actor, result["delivery_id"])
            if result["status"] != "receiving":
                break
            time.sleep(0.005)
        self.assertEqual(result["status"], "ready", result)
        return result

    def commit(self, ready, actor="verified-actor"):
        return self.store.commit(actor, **ready["commit_arguments"])

    def test_original_bytes_publish_and_independent_readback(self):
        ready = self.receive()
        self.assertEqual(list(self.policy.parent.iterdir()), [])
        self.assertEqual(ready["size_bytes"], sum(map(len, self.files.values())))
        self.assertTrue(ready["user_confirmation_required"])
        self.assertEqual(ready["commit_arguments"]["destination"], str(self.policy.parent / "v1.0"))
        page = self.store.inspect("verified-actor", ready["delivery_id"], "run-config.json", limit=3)
        self.assertEqual(base64.b64decode(page["file"]["bytes_base64"]), b"\xef\xbb\xbf")
        done = self.commit(ready)
        self.assertEqual(done["status"], "completed")
        for item in done["manifest"]:
            raw = (self.policy.parent / "v1.0" / item["path"]).read_bytes()
            self.assertEqual(raw, self.files[item["path"]])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
        self.assertFalse((self.state / ready["delivery_id"]).exists())
        self.assertEqual(self.commit(ready)["delivery_id"], ready["delivery_id"])
        self.assertEqual(self.store.inspect("verified-actor", ready["delivery_id"], "notes.txt")["file"]["text"], "原样交付\r\n")
        # Signed URLs/file IDs do not survive in persistent state or receipts.
        for path in self.state.iterdir():
            if path.is_file():
                self.assertNotIn(b"never-store", path.read_bytes())

    def test_exact_large_archive_and_file_sizes(self):
        self.files = {"main-v1.0.md": b"A" * 58438, "extra.txt": b"B" * 26348}
        self.raw = archive(self.files)
        # ZIP_STORED framing size depends on the exact entry names.
        delta = 85010 - len(self.raw)
        self.files["extra.txt"] += b"B" * delta
        self.raw = archive(self.files)
        self.assertEqual(len(self.raw), 85010)
        ready = self.receive()
        self.commit(ready)
        self.assertEqual((self.policy.parent / "v1.0/main-v1.0.md").read_bytes(), b"A" * 58438)

    def test_same_intent_and_parallel_commit_are_idempotent(self):
        ready = self.receive()
        again = self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(again["delivery_id"], ready["delivery_id"])
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: self.commit(ready), range(4)))
        self.assertEqual({x["delivery_id"] for x in outcomes}, {ready["delivery_id"]})
        self.assertEqual([p.name for p in self.policy.parent.iterdir()], ["v1.0"])

    def test_existing_different_target_never_overwritten(self):
        ready = self.receive()
        existing = self.policy.parent / "v1.0"
        existing.mkdir()
        (existing / "user.txt").write_text("user work")
        with self.assertRaisesRegex(AccessError, "target_conflict"):
            self.commit(ready)
        self.assertEqual((existing / "user.txt").read_text(), "user work")
        self.assertEqual(list(existing.iterdir()), [existing / "user.txt"])

    def test_confirmation_actor_hash_manifest_and_target_binding(self):
        ready = self.receive()
        for changes in ({"target_id": "other"}, {"version_directory": "v2"}, {"archive_sha256": "0" * 64},
                        {"manifest": []}, {"preparation": "made-up"}, {"destination": str(self.root / "elsewhere")}):
            with self.subTest(changes=changes), self.assertRaises(AccessError):
                self.store.commit("verified-actor", **{**ready["commit_arguments"], **changes})
        for actor in ("", "other-actor"):
            with self.assertRaises(AccessError):
                self.commit(ready, actor)
        with self.assertRaises(AccessError):
            self.store.inspect("other-actor", ready["delivery_id"])
        self.assertEqual(list(self.policy.parent.iterdir()), [])

    def test_expired_preview_can_be_renewed_without_redownload(self):
        ready = self.receive()
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 3601):
            with self.assertRaisesRegex(AccessError, "preview_invalid"):
                self.commit(ready)
            renewed = self.store.inspect("verified-actor", ready["delivery_id"])
            self.assertNotEqual(renewed["commit_arguments"]["preparation"], ready["commit_arguments"]["preparation"])
            self.commit(renewed)

    def test_revoked_policy_and_parent_symlink_are_rejected(self):
        ready = self.receive()
        self.policy.enabled = False
        with self.assertRaises(AccessError):
            self.commit(ready)
        self.policy.enabled = True
        original = self.policy.parent.with_name("original-packages")
        self.policy.parent.rename(original)
        self.policy.parent.symlink_to(original, target_is_directory=True)
        with self.assertRaises(AccessError):
            self.commit(ready)
        self.assertEqual(list(original.iterdir()), [])

    def test_staged_corruption_prevents_any_final_publication(self):
        ready = self.receive()
        (self.state / ready["delivery_id"] / "payload/notes.txt").write_bytes(b"changed")
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.commit(ready)
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        self.assertFalse((self.policy.parent / "v1.0").exists())

    def test_completed_modified_or_deleted_is_not_recreated(self):
        ready = self.receive()
        self.commit(ready)
        path = self.policy.parent / "v1.0/notes.txt"
        path.write_bytes(b"user modified")
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.store.inspect("verified-actor", ready["delivery_id"])
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.commit(ready)
        self.assertEqual(path.read_bytes(), b"user modified")
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        import shutil
        shutil.rmtree(path.parent)
        with self.assertRaisesRegex(AccessError, "published_missing"):
            self.commit(ready)
        with self.assertRaisesRegex(AccessError, "published_missing"):
            self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        self.assertFalse(path.parent.exists())

    def test_rename_then_lost_response_recovers_across_restart(self):
        ready = self.receive()

        def rename_then_disconnect(*args):
            publish_exclusive(*args)
            raise ConnectionError("synthetic lost response")

        with patch("peters_mcp.delivery_store.publish_exclusive", side_effect=rename_then_disconnect):
            with self.assertRaises(ConnectionError):
                self.commit(ready)
        self.store.close()
        self.store = DeliveryStore(self.state, self.policy, downloader=self.download)
        result = self.store.inspect("verified-actor", ready["delivery_id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.commit(ready)["status"], "completed")
        self.assertEqual([p.name for p in self.policy.parent.iterdir()], ["v1.0"])

    def test_interrupted_download_same_delivery_safe_retry(self):
        self.store.downloader = lambda *args: (_ for _ in ()).throw(ConnectionError("synthetic private URL must not be logged"))
        result = self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        for _ in range(200):
            current = self.store.inspect("verified-actor", result["delivery_id"])
            if current["status"] != "receiving":
                break
            time.sleep(0.005)
        self.assertEqual(current["status"], "interrupted")
        self.store.close()
        self.store = DeliveryStore(self.state, self.policy, downloader=self.download)
        ready = self.receive()
        self.assertEqual(ready["delivery_id"], result["delivery_id"])
        self.commit(ready)

    def test_source_approval_failure_can_retry_without_new_delivery_or_url_storage(self):
        def blocked(*args):
            raise AccessError('Provider not approved.', code='file_source_not_approved')
        self.store.downloader = blocked
        result = self.store.stage('verified-actor', self.reference, 'demo-target', 'v1.0', hashlib.sha256(self.raw).hexdigest())
        for _ in range(200):
            status = self.store.inspect('verified-actor', result['delivery_id'])
            if status['status'] != 'receiving': break
            time.sleep(0.005)
        self.assertEqual(status['status'], 'interrupted')
        self.assertTrue(status['operator_action_required'])
        self.assertEqual(status['file_source_host'], 'files.example.test')
        self.assertNotIn('never-store', json.dumps(status))
        self.assertFalse(status['published'])
        self.store.downloader = self.download
        ready = self.receive()
        self.assertEqual(ready['delivery_id'], result['delivery_id'])
        self.commit(ready)

    def test_interrupted_copy_resumes_only_exact_owned_prefix(self):
        ready = self.receive()
        original_write = os.write
        wrote_once = False

        def interrupted_write(fd, data):
            nonlocal wrote_once
            if wrote_once:
                raise OSError("synthetic interruption")
            wrote_once = True
            return original_write(fd, data[:7])

        with patch("peters_mcp.delivery_store.os.write", side_effect=interrupted_write):
            with self.assertRaises(OSError):
                self.commit(ready)
        self.assertFalse((self.policy.parent / "v1.0").exists())
        self.store.close()
        self.store = DeliveryStore(self.state, self.policy, downloader=self.download)
        pending = self.store.inspect("verified-actor", ready["delivery_id"])
        self.assertEqual(pending["status"], "committing")
        result = self.commit(pending)
        self.assertEqual(result["status"], "completed")
        for name, raw in self.files.items():
            self.assertEqual((self.policy.parent / "v1.0" / name).read_bytes(), raw)

    def test_unrecorded_or_modified_partial_publication_is_not_overwritten(self):
        ready = self.receive()
        original_write = os.write

        def write_then_interrupt(fd, data):
            original_write(fd, data[:7])
            raise OSError("synthetic interruption")

        with patch("peters_mcp.delivery_store.os.write", side_effect=write_then_interrupt):
            with self.assertRaises(OSError):
                self.commit(ready)
        temporary = next(self.policy.parent.iterdir())
        partial = temporary / "00-README.md"
        partial.write_bytes(b"USER")
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.commit(ready)
        self.assertEqual(partial.read_bytes(), b"USER")
        self.assertFalse((self.policy.parent / "v1.0").exists())

    def test_limit_boundary_and_over_limit_fail_before_publication(self):
        self.files = {"main.md": b"x" * 1024}
        self.raw = archive(self.files)
        self.policy.settings = replace(self.policy.settings, max_file_bytes=1024, max_package_bytes=1024,
                                       max_archive_bytes=len(self.raw), max_files=1, max_depth=1)
        reserve = self.store._reservation(self.policy.resolve("demo-target"), self.policy.settings)["reserved_bytes"]
        self.policy.settings = replace(self.policy.settings, max_staging_bytes=reserve + self.store._metadata_bytes() + 65536)
        self.commit(self.receive())
        self.files["main.md"] += b"x"
        self.raw = archive(self.files)
        self.policy.settings = replace(self.policy.settings, max_archive_bytes=len(self.raw))
        result = self.store.stage("verified-actor", self.reference, "demo-target", "v2", hashlib.sha256(self.raw).hexdigest())
        for _ in range(200):
            result = self.store.inspect("verified-actor", result["delivery_id"])
            if result["status"] != "receiving":
                break
            time.sleep(0.005)
        self.assertEqual(result["status"], "failed")
        self.assertFalse((self.policy.parent / "v2").exists())

    def test_expired_unpublished_delivery_can_be_explicitly_retransferred(self):
        self.policy.settings = replace(self.policy.settings, max_staging_bytes=1000)
        with self.assertRaisesRegex(AccessError, "quota_exceeded"):
            self.receive()
        self.policy.settings = DeliveryLimits()
        ready = self.receive()
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 73 * 3600):
            expired = self.store.inspect("verified-actor", ready["delivery_id"])
            self.assertEqual(expired["status"], "expired")
            again = self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
            self.assertEqual(again["status"], "receiving")
            self.assertEqual(again["delivery_id"], ready["delivery_id"])
            for _ in range(200):
                renewed = self.store.inspect("verified-actor", ready["delivery_id"])
                if renewed["status"] != "receiving":
                    break
                time.sleep(0.005)
            self.assertEqual(renewed["status"], "ready")
            self.assertGreater(renewed["preparation_expires_at"], ready["preparation_expires_at"])
            with self.assertRaisesRegex(AccessError, "preview_invalid"):
                self.commit(ready)
        self.assertEqual(list(self.policy.parent.iterdir()), [])
        self.commit(renewed)

    def test_expired_delivery_does_not_revive_when_target_now_exists(self):
        ready = self.receive()
        target = self.policy.parent / "v1.0"
        target.mkdir()
        (target / "user.txt").write_bytes(b"owned by user")
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 73 * 3600):
            with self.assertRaisesRegex(AccessError, "target_conflict"):
                self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        self.assertEqual((target / "user.txt").read_bytes(), b"owned by user")

    def test_new_intent_releases_completed_recovery_spool_without_touching_target(self):
        ready = self.receive()

        def rename_then_disconnect(*args):
            publish_exclusive(*args)
            raise ConnectionError("synthetic lost response")

        with patch("peters_mcp.delivery_store.publish_exclusive", side_effect=rename_then_disconnect):
            with self.assertRaises(ConnectionError):
                self.commit(ready)
        recovered = self.store.inspect("verified-actor", ready["delivery_id"])
        self.assertEqual(recovered["status"], "completed")
        self.assertTrue((self.state / ready["delivery_id"]).exists())
        self.policy.settings = replace(self.policy.settings, max_staging_bytes=
                                       self.store._reservation(self.policy.resolve("demo-target"), self.policy.settings)["reserved_bytes"]
                                       + self.store._metadata_bytes() + 65536)
        original_target = self.policy.parent / "v1.0/notes.txt"
        original_target.write_bytes(b"user changed completed output")
        self.receive(version="v2")
        self.assertFalse((self.state / ready["delivery_id"]).exists())
        self.assertEqual(original_target.read_bytes(), b"user changed completed output")
        with self.assertRaisesRegex(AccessError, "content_changed"):
            self.store.inspect("verified-actor", ready["delivery_id"])
        with self.store._locked():
            self.assertEqual(self.store._get("verified-actor", ready["delivery_id"])["reserved_bytes"], 0)

    def test_policy_change_never_silently_rebinds_existing_intent(self):
        ready = self.receive()
        self.policy.version = "v2"
        with self.assertRaisesRegex(AccessError, "scope_changed"):
            self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        with self.assertRaisesRegex(AccessError, "scope_changed"):
            self.commit(ready)
        # A separately requested version forms a new review under current policy.
        fresh = self.receive(version="v2")
        self.assertNotEqual(fresh["delivery_id"], ready["delivery_id"])
        self.assertEqual(list(self.policy.parent.iterdir()), [])

    def test_unicode_manifest_budget_uses_worst_case_json_escaping(self):
        prefix = "/".join(["路" * 65] * 3)
        all_files = {prefix + "/" + "文" * 65 + f"{i:02}.md": b"x" for i in range(80)}

        def manifest(files):
            return [{"path": name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                    for name, raw in sorted(files.items())]

        def size(value, escape):
            return len(json.dumps(value, ensure_ascii=escape, separators=(",", ":")).encode())

        self.assertLess(size(manifest(all_files), False), 128 * 1024)
        self.assertGreater(size(manifest(all_files), True), 128 * 1024)
        self.files = dict(list(all_files.items())[:70])
        exact_limit = size(manifest(self.files), True)
        self.raw = archive(self.files)
        self.policy.settings = replace(self.policy.settings, max_manifest_bytes=exact_limit)
        ready = self.receive()
        self.assertEqual(size(ready["manifest"], True), exact_limit)
        # Commit applies the same escaped budget even if runtime limits tighten.
        self.policy.settings = replace(self.policy.settings, max_manifest_bytes=exact_limit - 1)
        with self.assertRaisesRegex(AccessError, "confirmation_mismatch"):
            self.commit(ready)
        self.files, self.raw = all_files, archive(all_files)
        self.policy.settings = replace(self.policy.settings, max_manifest_bytes=128 * 1024)
        result = self.store.stage("verified-actor", self.reference, "demo-target", "v2", hashlib.sha256(self.raw).hexdigest())
        for _ in range(400):
            result = self.store.inspect("verified-actor", result["delivery_id"])
            if result["status"] != "receiving":
                break
            time.sleep(0.005)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "delivery_manifest_too_large")
        self.assertEqual(list(self.policy.parent.iterdir()), [])

    def test_retained_database_and_lock_metadata_count_toward_quota(self):
        ready = self.receive()
        self.commit(ready)
        with self.store._locked():
            row = self.store._get("verified-actor", ready["delivery_id"])
            self.assertEqual(row["reserved_bytes"], 0)
            metadata = self.store._metadata_bytes()
            self.assertGreaterEqual(metadata, (self.state / "deliveries.sqlite3").stat().st_size)
            self.assertGreater(metadata, 0)
        reserve = self.store._reservation(self.policy.resolve("demo-target"), self.policy.settings)["reserved_bytes"]
        self.policy.settings = replace(self.policy.settings, max_staging_bytes=reserve + metadata - 1)
        with self.assertRaisesRegex(AccessError, "quota_exceeded.*metadata"):
            self.store.stage("verified-actor", self.reference, "demo-target", "v2", hashlib.sha256(self.raw).hexdigest())
        # Quota enforcement never discards completion tombstones or business data.
        self.assertEqual(self.store.inspect("verified-actor", ready["delivery_id"])["status"], "completed")
        self.assertTrue((self.policy.parent / "v1.0/notes.txt").is_file())

    def test_many_one_byte_files_reserve_allocation_before_download(self):
        self.files = {f"f{index:03}.txt": b"x" for index in range(100)}
        self.raw = archive(self.files)
        self.assertLessEqual(len(self.raw), 12000)
        self.policy.settings = replace(self.policy.settings, max_file_bytes=1, max_package_bytes=100,
                                       max_archive_bytes=12000, max_staging_bytes=300000)
        with patch.object(self.store, "downloader", wraps=self.download) as receiver:
            with self.assertRaisesRegex(AccessError, "quota_exceeded"):
                self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
            receiver.assert_not_called()
        self.assertFalse(any(path.is_dir() for path in self.state.iterdir()))

        reserve = self.store._reservation(self.policy.resolve("demo-target"), self.policy.settings)["reserved_bytes"]
        self.policy.settings = replace(self.policy.settings, max_staging_bytes=reserve + self.store._metadata_bytes() + 65536)
        ready = self.receive()

        def actual(path):
            info = path.stat()
            total = max(info.st_size, info.st_blocks * 512)
            if path.is_dir():
                total += sum(actual(child) for child in path.iterdir())
            return total

        physical_spool = actual(self.state / ready["delivery_id"])
        physical_state = actual(self.state)
        with self.store._locked():
            row = self.store._get("verified-actor", ready["delivery_id"])
            self.assertEqual(row["reserved_bytes"], physical_spool + row["target_reserved_bytes"] + row["metadata_reserved_bytes"])
            self.assertGreater(row["reserved_bytes"], 2 * len(self.files))
            self.assertGreaterEqual(self.store._accounted_bytes(), physical_state)
            self.assertLessEqual(self.store._accounted_bytes(), self.policy.settings.max_staging_bytes)
            self.assertLessEqual(physical_state, self.policy.settings.max_staging_bytes)
            # Even a legacy underestimated reservation cannot hide real blocks.
            row["reserved_bytes"] = 200
            self.store._put(row)
            self.assertGreaterEqual(self.store._accounted_bytes(), actual(self.state))
            row["reserved_bytes"] = physical_spool + row["target_reserved_bytes"] + row["metadata_reserved_bytes"]
            self.store._put(row)
        self.assertEqual(list(self.policy.parent.iterdir()), [])

        def checked_publication(parent_fd, temporary_name, version_directory):
            physical_total = actual(self.state) + actual(self.policy.parent / temporary_name)
            self.assertLessEqual(physical_total, self.policy.settings.max_staging_bytes)
            publish_exclusive(parent_fd, temporary_name, version_directory)

        with patch("peters_mcp.delivery_store.publish_exclusive", side_effect=checked_publication):
            self.assertEqual(self.commit(ready)["status"], "completed")

    def test_ready_reservation_growth_is_rechecked_against_quota(self):
        original = self.store._reservation

        def unexpectedly_large_allocation(target, limits, **kwargs):
            result = original(target, limits, **kwargs)
            if kwargs.get("manifest") is not None:
                result["reserved_bytes"] = limits.max_staging_bytes + 1
            return result

        with patch.object(self.store, "_reservation", side_effect=unexpectedly_large_allocation):
            result = self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
            for _ in range(200):
                result = self.store.inspect("verified-actor", result["delivery_id"])
                if result["status"] != "receiving":
                    break
                time.sleep(0.005)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "delivery_quota_exceeded")
        self.assertEqual(list(self.policy.parent.iterdir()), [])

    def test_download_source_policy_change_is_retryable_without_rebinding_target(self):
        sources = {"files.example.test": ("93.184.215.14",)}
        self.policy.sources = lambda: dict(sources)

        def change_sources_during_download(*args):
            result = self.download(*args)
            sources["extra.example.test"] = ("93.184.215.15",)
            return result

        self.store.downloader = change_sources_during_download
        result = self.store.stage("verified-actor", self.reference, "demo-target", "v1.0", hashlib.sha256(self.raw).hexdigest())
        for _ in range(200):
            result = self.store.inspect("verified-actor", result["delivery_id"])
            if result["status"] != "receiving":
                break
            time.sleep(0.005)
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(result["retryable"])
        self.assertEqual(result["error_code"], "delivery_download_policy_changed")
        self.store.downloader = self.download
        ready = self.receive()
        self.assertEqual(ready["delivery_id"], result["delivery_id"])
        sources["later.example.test"] = ("93.184.215.16",)
        self.assertEqual(self.commit(ready)["status"], "completed")

    def test_expiry_cleans_only_owned_partial_publication(self):
        ready = self.receive()
        original_write = os.write

        def write_then_interrupt(fd, data):
            original_write(fd, data[:7])
            raise OSError("synthetic interruption")

        with patch("peters_mcp.delivery_store.os.write", side_effect=write_then_interrupt):
            with self.assertRaises(OSError):
                self.commit(ready)
        self.assertEqual(len(list(self.policy.parent.iterdir())), 1)
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 73 * 3600):
            result = self.store.inspect("verified-actor", ready["delivery_id"])
            self.assertEqual(result["status"], "expired_cleanup_pending")
            self.assertEqual(len(list(self.policy.parent.iterdir())), 1)
            result = self.store.cleanup_expired("verified-actor", ready["delivery_id"])
        self.assertEqual(result["status"], "expired")
        self.assertEqual(list(self.policy.parent.iterdir()), [])

    def test_expiry_retains_unknown_partial_entries_and_replaced_spool(self):
        ready = self.receive()
        original_write = os.write

        def write_then_interrupt(fd, data):
            original_write(fd, data[:7])
            raise OSError("synthetic interruption")

        with patch("peters_mcp.delivery_store.os.write", side_effect=write_then_interrupt):
            with self.assertRaises(OSError):
                self.commit(ready)
        temporary = next(self.policy.parent.iterdir())
        (temporary / "user.txt").write_text("unrelated")
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 73 * 3600):
            result = self.store.inspect("verified-actor", ready["delivery_id"])
        self.assertEqual(result["status"], "expired_cleanup_pending")
        self.assertEqual((temporary / "user.txt").read_text(), "unrelated")
        other = self.receive(version="v2")
        directory = self.state / other["delivery_id"]
        directory.rename(self.state / "preserved-staging")
        directory.mkdir()
        (directory / "user.txt").write_text("replacement")
        with patch("peters_mcp.delivery_store.time.time", return_value=time.time() + 73 * 3600):
            result = self.store.inspect("verified-actor", other["delivery_id"])
            self.assertEqual(result["status"], "expired")
            result = self.store.cleanup_expired("verified-actor", other["delivery_id"])
        self.assertEqual(result["status"], "expired_cleanup_pending")
        self.assertEqual((directory / "user.txt").read_text(), "replacement")

    def test_chinese_preview_pages_preserve_readable_text_and_original_bytes(self):
        self.files = {"中文.md": ("中文资料\r\n" * 3000).encode()}
        self.raw = archive(self.files)
        ready = self.receive()
        received = bytearray()
        offset = 0
        while offset is not None:
            page = self.store.inspect("verified-actor", ready["delivery_id"], "中文.md", offset=offset)["file"]
            self.assertIn("text", page)
            chunk = base64.b64decode(page["bytes_base64"])
            self.assertEqual(page["text"].encode(), chunk)
            received.extend(chunk)
            offset = page["next_offset"]
        self.assertEqual(bytes(received), self.files["中文.md"])
        bad_start = self.store.inspect("verified-actor", ready["delivery_id"], "中文.md", offset=1)["file"]
        self.assertNotIn("text", bad_start)
        self.assertEqual(base64.b64decode(bad_start["bytes_base64"]), self.files["中文.md"][1:20001])

    def test_invalid_version_and_page_cannot_traverse(self):
        for name in ("../outside", "/absolute", ".hidden", "version/child", "version\\child", "a..b", "AGENTS.md"):
            with self.subTest(name=name), self.assertRaises(AccessError):
                self.store.stage("verified-actor", self.reference, "demo-target", name, hashlib.sha256(self.raw).hexdigest())
        ready = self.receive()
        with self.assertRaises(AccessError):
            self.store.inspect("verified-actor", ready["delivery_id"], "../preview.key")
        with self.assertRaises(AccessError):
            self.store.inspect("verified-actor", ready["delivery_id"], offset=-1)


if __name__ == "__main__":
    unittest.main()
