#!/usr/bin/env python3
"""Parameterized, manifest-driven release preflight, status, deploy, and safe rollback tool.

Guarantees (D4):
- No hardcoded version SHAs or fixed project counts: reads expected fingerprints dynamically
  from manifest.json and verifies every payload file byte-for-byte.
- Safe rollback: code rollback NEVER reverts serving-v2/generations-state/active.json,
  never removes durable .path-tombstones.json, and never reactivates revoked permissions.
- Refuses symlinks, __pycache__ artifacts, or unverified payload drift.
- Always invokes Python with -B when checking packages so bytecode never pollutes runtime/.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_payload(root: Path, *, ignore_top: tuple[str, ...] = ()) -> dict:
    try:
        root = root.resolve()
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise RuntimeError(f"Missing or symlinked manifest.json in {root}")
        manifest = json.loads(manifest_path.read_bytes())
        if not isinstance(manifest, dict):
            raise RuntimeError(f"Invalid manifest root object in {root}")
        rows = manifest.get("files")
        if not isinstance(rows, list) or not rows:
            raise RuntimeError(f"Invalid manifest files list in {root}")
        expected_map = {}
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError(f"Invalid manifest file entry in {root}")
            rel = row["path"]
            if not isinstance(rel, str) or not rel:
                raise RuntimeError(f"Invalid manifest path entry in {root}")
            if rel in expected_map:
                raise RuntimeError(f"Duplicate manifest entry: {rel}")
            expected_map[rel] = row

        actual_files = set()
        for p in root.rglob("*"):
            rel = p.relative_to(root).as_posix()
            top = p.relative_to(root).parts[0]
            if top in ignore_top:
                continue
            if p.is_symlink():
                raise RuntimeError(f"Unexpected symlink inside payload: {rel}")
            if "__pycache__" in p.parts or p.suffix == ".pyc":
                raise RuntimeError(f"Bytecode artifact pollutes payload: {rel}")
            if p.is_file():
                actual_files.add(rel)

        expected_all = set(expected_map) | {"manifest.json"}
        extra = sorted(actual_files - expected_all)
        missing = sorted(expected_all - actual_files)
        if extra or missing:
            raise RuntimeError(f"Payload file mismatch in {root}: extra={extra[:5]} missing={missing[:5]}")

        for rel, row in expected_map.items():
            data = (root / rel).read_bytes()
            if len(data) != row["bytes"] or _sha256_bytes(data) != row["sha256"]:
                raise RuntimeError(f"Digest mismatch for {rel} in {root}")

        recomputed = _sha256_bytes(
            json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        if recomputed != manifest.get("content_fingerprint"):
            raise RuntimeError(f"Manifest content_fingerprint mismatch in {root}")
        return manifest
    except RuntimeError:
        raise
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise RuntimeError(f"Corrupt or unreadable release payload in {root}: {exc}") from exc


def _check_policy_decode(bundle_root: Path, descriptor_path: Path, python_bin: Path) -> dict:
    """Verify in a clean -B subprocess that bundle_root can decode the active v2 policy without error."""
    code = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from peters_mcp.agent_history_policy import AgentPolicy\n"
        "pol = AgentPolicy(Path(sys.argv[2]), mode='v2')\n"
        "doc, digest = pol.snapshot()\n"
        "out = {'generation_sha256': digest, 'projects': len(doc['projects']), "
        "'enabled_sources': sorted(k for k, v in doc['sources'].items() if v.get('enabled'))}\n"
        "try:\n"
        "  from peters_mcp.agent_history_admin import lint_policy\n"
        "  out['lint'] = lint_policy(doc)\n"
        "except Exception:\n"
        "  out['lint'] = None\n"
        "print(json.dumps(out))\n"
    )
    proc = subprocess.run(
        [str(python_bin), "-B", "-c", code, str(bundle_root), str(descriptor_path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Bundle {bundle_root} failed to decode policy {descriptor_path}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _check_endpoint(host: str, port: int) -> int | None:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=2)
        try:
            conn.request("POST", "/mcp", b"{}", headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()
    except OSError:
        return None


def _launchctl_pid(label: str) -> int | None:
    domain = f"gui/{os.getuid()}"
    res = subprocess.run(["/bin/launchctl", "print", f"{domain}/{label}"], capture_output=True, text=True, timeout=15)
    if res.returncode != 0:
        return None
    m = re.search(r"^\s*pid = (\d+)$", res.stdout, re.MULTILINE)
    return int(m[1]) if m else None


def _atomic_copy_file(src: Path, dst: Path) -> None:
    """Copy src to dst via a durable sibling temp file + fsync + os.replace."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    mode = stat.S_IMODE(src.stat().st_mode)
    fd, tmp = tempfile.mkstemp(dir=dst.parent, prefix=".sync-")
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dst)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _sync_payload(source_bundle: Path, runtime_dir: Path) -> dict:
    """Replace code files in runtime_dir with verified source_bundle, preserving runtime_dir/work."""
    manifest = _verify_payload(source_bundle)
    runtime_dir = runtime_dir.resolve()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    # Remove old payload files & empty dirs (NEVER touch runtime_dir/work)
    for child in list(runtime_dir.iterdir()):
        if child.name == "work":
            continue
        if child.is_symlink():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    # Copy verified payload files atomically, then commit manifest.json last.
    for row in manifest["files"]:
        rel = row["path"]
        dst = runtime_dir / rel
        _atomic_copy_file(source_bundle / rel, dst)
    _atomic_copy_file(source_bundle / "manifest.json", runtime_dir / "manifest.json")
    return _verify_payload(runtime_dir, ignore_top=("work",))


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cutover-")
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write((json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def cmd_status(args: argparse.Namespace) -> dict:
    runtime_manifest = _verify_payload(args.runtime_dir, ignore_top=("work",))
    out = {
        "operation": "status",
        "runtime_dir": str(args.runtime_dir.resolve()),
        "snapshot_id": runtime_manifest.get("snapshot_id"),
        "bundle_mode": runtime_manifest.get("bundle_mode"),
        "content_fingerprint": runtime_manifest.get("content_fingerprint"),
        "files": len(runtime_manifest.get("files") or ()),
    }
    if args.policy_descriptor:
        out["policy"] = _check_policy_decode(args.runtime_dir.resolve(), args.policy_descriptor.resolve(), args.python)
    if args.launch_label:
        out["launch_label"] = args.launch_label
        out["pid"] = _launchctl_pid(args.launch_label)
    if args.port:
        out["http_status"] = _check_endpoint(args.host, args.port)
    return out


def cmd_preflight(args: argparse.Namespace) -> dict:
    cand_manifest = _verify_payload(args.candidate_dir)
    rb_manifest = _verify_payload(args.rollback_dir)
    current_runtime = None
    if args.runtime_dir.exists() and any(c.name != "work" for c in args.runtime_dir.iterdir()):
        try:
            rt_manifest = _verify_payload(args.runtime_dir, ignore_top=("work",))
            current_runtime = {
                "state": "verified",
                "snapshot_id": rt_manifest["snapshot_id"],
                "content_fingerprint": rt_manifest["content_fingerprint"],
                "files": len(rt_manifest["files"]),
            }
        except RuntimeError as exc:
            current_runtime = {
                "state": "incomplete_or_corrupt",
                "error": str(exc),
            }
    result = {
        "operation": "preflight",
        "ok": True,
        "candidate": {
            "path": str(args.candidate_dir.resolve()),
            "snapshot_id": cand_manifest["snapshot_id"],
            "bundle_mode": cand_manifest["bundle_mode"],
            "content_fingerprint": cand_manifest["content_fingerprint"],
            "files": len(cand_manifest["files"]),
        },
        "rollback": {
            "path": str(args.rollback_dir.resolve()),
            "snapshot_id": rb_manifest["snapshot_id"],
            "bundle_mode": rb_manifest["bundle_mode"],
            "content_fingerprint": rb_manifest["content_fingerprint"],
            "files": len(rb_manifest["files"]),
        },
        "current_runtime": current_runtime,
    }
    if args.policy_descriptor:
        desc = args.policy_descriptor.resolve()
        result["candidate_policy_check"] = _check_policy_decode(args.candidate_dir.resolve(), desc, args.python)
        # Critical D4 check: prove the rollback bundle can decode the LIVE active.json without reverting permissions!
        result["rollback_policy_compat_check"] = _check_policy_decode(args.rollback_dir.resolve(), desc, args.python)
    if args.plist:
        plist_doc = plistlib.loads(args.plist.read_bytes())
        argv = plist_doc.get("ProgramArguments") or []
        if "-B" not in argv:
            raise RuntimeError(f"LaunchAgent plist {args.plist} is missing -B flag (bytecode would pollute runtime/)")
        result["plist_verified"] = {"path": str(args.plist), "label": plist_doc.get("Label"), "uses_B": True}
    return result


def _restart_launchd(
    label: str,
    host: str,
    port: int,
    *,
    expected_status: int = 401,
    timeout_s: float = 15.0,
) -> dict:
    domain = f"gui/{os.getuid()}"
    res = subprocess.run(["/bin/launchctl", "kickstart", "-k", f"{domain}/{label}"], capture_output=True, text=True, timeout=20)
    if res.returncode != 0:
        raise RuntimeError(f"launchctl kickstart failed: {res.stderr.strip()}")
    deadline = time.monotonic() + timeout_s
    last_status = None
    last_pid = None
    while True:
        status = _check_endpoint(host, port)
        pid = _launchctl_pid(label)
        if status is not None:
            last_status = status
        if pid is not None:
            last_pid = pid
        if status == expected_status and isinstance(pid, int) and pid > 0:
            return {
                "label": label,
                "pid": pid,
                "http_status": status,
                "expected_http_status": expected_status,
                "healthy": True,
            }
        if time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    raise RuntimeError(
        f"Service restart health check failed for {label} on {host}:{port}: "
        f"expected HTTP {expected_status} with live pid, observed http_status={last_status!r}, pid={last_pid!r}"
    )


def cmd_switch(args: argparse.Namespace, *, mode: str) -> dict:
    target_dir = args.candidate_dir if mode == "deploy" else args.rollback_dir
    before_fp = None
    previous_state = "uninitialized_or_missing_manifest"
    previous_error = None
    if os.path.lexists(args.runtime_dir / "manifest.json"):
        if mode == "rollback":
            # Rollback MUST recover from ANY interrupted/corrupt runtime state (including 0-byte
            # or truncated manifest.json, broken symlinks, or missing/corrupt payload files).
            try:
                before_fp = _verify_payload(args.runtime_dir, ignore_top=("work",))["content_fingerprint"]
                previous_state = "verified"
            except (RuntimeError, ValueError, KeyError, TypeError, OSError) as exc:
                before_fp = None
                previous_state = "incomplete_or_corrupt"
                previous_error = str(exc)
        else:
            before_fp = _verify_payload(args.runtime_dir, ignore_top=("work",))["content_fingerprint"]
            previous_state = "verified"
    if args.policy_descriptor:
        # Verify target bundle decodes current policy BEFORE switching (never touches policy/revocations!).
        policy_check = _check_policy_decode(target_dir.resolve(), args.policy_descriptor.resolve(), args.python)
    else:
        policy_check = None
    verified = _sync_payload(target_dir, args.runtime_dir)
    receipt = {
        "operation": mode,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "previous_state": previous_state,
        "previous_fingerprint": before_fp,
        "active_fingerprint": verified["content_fingerprint"],
        "snapshot_id": verified["snapshot_id"],
        "bundle_mode": verified["bundle_mode"],
        "files": len(verified["files"]),
        "policy_preserved_untouched": True,
        "policy_check": policy_check,
    }
    if previous_error is not None:
        receipt["previous_error"] = previous_error
    if args.launch_label and args.port:
        receipt["service_restart"] = _restart_launchd(
            args.launch_label,
            args.host,
            args.port,
            expected_status=getattr(args, "expected_http_status", 401),
            timeout_s=getattr(args, "restart_timeout", 15.0),
        )
    if args.receipt:
        _atomic_write_json(args.receipt, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--runtime-dir", type=Path, required=True)
        p.add_argument("--policy-descriptor", type=Path)
        p.add_argument("--python", type=Path, default=Path(sys.executable))
        p.add_argument("--launch-label")
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int)
        p.add_argument("--expected-http-status", type=int, default=401)
        p.add_argument("--restart-timeout", type=float, default=15.0)

    p_status = sub.add_parser("status")
    add_common(p_status)

    p_pre = sub.add_parser("preflight")
    add_common(p_pre)
    p_pre.add_argument("--candidate-dir", type=Path, required=True)
    p_pre.add_argument("--rollback-dir", type=Path, required=True)
    p_pre.add_argument("--plist", type=Path)

    p_dep = sub.add_parser("deploy")
    add_common(p_dep)
    p_dep.add_argument("--candidate-dir", type=Path, required=True)
    p_dep.add_argument("--receipt", type=Path)
    p_dep.add_argument("--confirm-cutover", action="store_true", required=True)

    p_rb = sub.add_parser("rollback")
    add_common(p_rb)
    p_rb.add_argument("--rollback-dir", type=Path, required=True)
    p_rb.add_argument("--receipt", type=Path)
    p_rb.add_argument("--confirm-rollback", action="store_true", required=True)

    args = parser.parse_args()
    try:
        if args.command == "status":
            out = cmd_status(args)
        elif args.command == "preflight":
            out = cmd_preflight(args)
        elif args.command == "deploy":
            out = cmd_switch(args, mode="deploy")
        else:
            out = cmd_switch(args, mode="rollback")
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
