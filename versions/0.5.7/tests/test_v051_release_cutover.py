"""v0.5.1 WS-R3 tests: release_cutover interrupted-payload rollback recovery and HTTP 503/health gate."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch


def _load_cutover():
    tool = Path(__file__).resolve().parent.parent / "tools" / "release_cutover.py"
    spec = importlib.util.spec_from_file_location("release_cutover", tool)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_bundle(root: Path, snapshot_id: str, files: dict[str, bytes], *, bundle_mode: str = "candidate") -> dict:
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    for rel, content in sorted(files.items()):
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(content)
        rows.append({"path": rel, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    fp = hashlib.sha256(
        json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    ).hexdigest()
    manifest = {"snapshot_id": snapshot_id, "bundle_mode": bundle_mode, "content_fingerprint": fp, "files": rows}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


class _LoopbackStatusServer:
    def __init__(self, status_code: int):
        self.status_code = status_code
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(parent.status_code)
                self.end_headers()
                self.wfile.write(b"{}")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ReleaseCutoverTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load_cutover()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.candidate = self.root / "candidate"
        self.rollback = self.root / "rollback"
        self.runtime = self.root / "runtime"
        self.work_marker = self.runtime / "work" / "audit-marker.txt"
        self.work_marker.parent.mkdir(parents=True, exist_ok=True)
        self.work_marker.write_text("preserve-me\n", encoding="utf-8")

        self.cand_manifest = _make_bundle(
            self.candidate, "cand-0.5.1", {"README.md": b"new\n", "peters_mcp/__init__.py": b"__version__='0.5.1'\n"}
        )
        self.rb_manifest = _make_bundle(
            self.rollback, "rb-0.4.4-p12", {"README.md": b"old\n", "peters_mcp/__init__.py": b"__version__='0.4.4'\n"},
            bundle_mode="rollback",
        )

    def _switch_args(self, *, receipt=None, launch_label=None, port=None, expected_status=401, timeout=0.6):
        return argparse.Namespace(
            runtime_dir=self.runtime,
            candidate_dir=self.candidate,
            rollback_dir=self.rollback,
            policy_descriptor=None,
            python=Path("/usr/bin/python3"),
            launch_label=launch_label,
            host="127.0.0.1",
            port=port,
            receipt=receipt,
            expected_http_status=expected_status,
            restart_timeout=timeout,
        )

    def test_rollback_recovers_interrupted_runtime_with_manifest_present_and_missing_file(self):
        # Deploy candidate cleanly first
        self.mod.cmd_switch(self._switch_args(), mode="deploy")
        # Simulate interrupted/corrupted payload leaving manifest.json present while README.md is missing
        (self.runtime / "README.md").unlink()
        receipt_path = self.root / "rb-receipt.json"
        out = self.mod.cmd_switch(self._switch_args(receipt=receipt_path), mode="rollback")
        self.assertEqual(out["operation"], "rollback")
        self.assertEqual(out["previous_state"], "incomplete_or_corrupt")
        self.assertIsNone(out["previous_fingerprint"])
        self.assertIn("README.md", out["previous_error"])
        self.assertEqual(out["active_fingerprint"], self.rb_manifest["content_fingerprint"])
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(self.work_marker.read_text(encoding="utf-8"), "preserve-me\n")
        verified = self.mod._verify_payload(self.runtime, ignore_top=("work",))
        self.assertEqual(verified["content_fingerprint"], self.rb_manifest["content_fingerprint"])

    def test_rollback_recovers_interrupted_runtime_without_manifest(self):
        self.mod.cmd_switch(self._switch_args(), mode="deploy")
        (self.runtime / "manifest.json").unlink()
        (self.runtime / "README.md").unlink()
        out = self.mod.cmd_switch(self._switch_args(), mode="rollback")
        self.assertEqual(out["previous_state"], "uninitialized_or_missing_manifest")
        self.assertEqual(out["active_fingerprint"], self.rb_manifest["content_fingerprint"])
        self.assertEqual(self.work_marker.read_text(encoding="utf-8"), "preserve-me\n")

    def test_restart_probe_rejects_http_503_and_200_and_writes_no_receipt(self):
        ok_proc = subprocess.CompletedProcess(["launchctl"], 0, "", "")
        for bad_code in (503, 500, 200):
            with self.subTest(http_status=bad_code):
                srv = _LoopbackStatusServer(bad_code)
                self.addCleanup(srv.close)
                receipt_path = self.root / f"receipt-{bad_code}.json"
                with patch.object(self.mod.subprocess, "run", return_value=ok_proc), \
                     patch.object(self.mod, "_launchctl_pid", return_value=12345):
                    with self.assertRaises(RuntimeError) as caught:
                        self.mod.cmd_switch(
                            self._switch_args(receipt=receipt_path, launch_label="test.label", port=srv.port, timeout=0.6),
                            mode="rollback",
                        )
                self.assertIn(f"http_status={bad_code}", str(caught.exception))
                self.assertFalse(receipt_path.exists())

    def test_restart_probe_succeeds_only_on_expected_401_with_live_pid(self):
        ok_proc = subprocess.CompletedProcess(["launchctl"], 0, "", "")
        srv = _LoopbackStatusServer(401)
        self.addCleanup(srv.close)
        receipt_path = self.root / "receipt-401.json"
        # Missing PID must fail even with HTTP 401
        with patch.object(self.mod.subprocess, "run", return_value=ok_proc), \
             patch.object(self.mod, "_launchctl_pid", return_value=None):
            with self.assertRaises(RuntimeError):
                self.mod.cmd_switch(
                    self._switch_args(receipt=receipt_path, launch_label="test.label", port=srv.port, timeout=0.6),
                    mode="rollback",
                )
        self.assertFalse(receipt_path.exists())
        # Live PID + HTTP 401 succeeds and writes receipt
        with patch.object(self.mod.subprocess, "run", return_value=ok_proc), \
             patch.object(self.mod, "_launchctl_pid", return_value=54321):
            out = self.mod.cmd_switch(
                self._switch_args(receipt=receipt_path, launch_label="test.label", port=srv.port, timeout=1.0),
                mode="rollback",
            )
        self.assertTrue(out["service_restart"]["healthy"])
        self.assertEqual(out["service_restart"]["http_status"], 401)
        self.assertEqual(out["service_restart"]["pid"], 54321)
        self.assertTrue(receipt_path.is_file())


if __name__ == "__main__":
    unittest.main()
