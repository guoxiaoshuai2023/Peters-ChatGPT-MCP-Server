"""v0.5.5 targeted L4 remediation regression tests.

Covers:
1. Cooperative bounded step yields (`capture_iter`, `_snapshot_iter`, `_steps_iter`,
   `_generations_iter`, `verify_senders_iter`, `_record_iter`) under actual macOS
   background QoS (`/usr/sbin/taskpolicy -b`, matching launchd `ProcessType=Background`):
   a cold, multi-hundred-step paired-transcript Antigravity Desktop 2.33.0 thread
   (~150,000 visible characters) completes `find_agent_threads` -> paginated
   `read_agent_thread` to `has_more=False` without `step_timeout` or worker stops,
   even under tight `step_seconds` and `wait_seconds` continuation boundaries.
2. Unified v2 (`unified_policy`) timeout recovery semantics:
   - Synchronous / concurrent waiter wake-up on `step_timeout` returns structured
     `{"status": "processing_timeout", "continue_with": ...}` (and aggregate search
     degrades that source to `warnings=["processing_timeout"]` while delivering
     healthy sources), NEVER falsely raising `[restart_required] Project topology
     changed after history validation.`;
   - Delayed continuation poll after worker stop returns structured
     `{"status": "restart_required", "continue_with": ...}`;
   - Fresh call without stale cursor immediately spawns a new worker and recovers
     to `status="ready"`.
3. Unified v2 revocation protection across worker timeouts, restarts, and stale
   cursors: revoking a project (or adding a thread to `denied_threads`) blocks
   both unified (`find_agent_threads`, `read_agent_thread`) and legacy
   (`find_codex_threads`, `read_codex_thread`) pre-revocation `thread_ref` and
   `hp1.` processing cursors fail-closed without leaking status or content, while
   retained projects continue reading normally.
"""

from copy import deepcopy
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.testclient import TestClient

from peters_mcp.agent_history import build_core as _real_build_core
from peters_mcp.agent_history_admin import activate_preview, preview_activation, write_descriptor
from peters_mcp.agent_history_antigravity import INDEX
from peters_mcp.agent_history_antigravity_native import capture_iter
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.catalog import Catalog
from peters_mcp.cloudflare import AccessSettings, build_app
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.history_process import IsolatedHistory
from tests.test_agent_history_antigravity_native import (
    FIRST, INIT, PROJECT, SECONDS, SESSION, TIME, TRAJECTORY, desktop_spec, message, varint,
)
from tests.test_history import encode as codex_encode, message as codex_message, record as codex_record


class _HangableCoreWrapper:
    def __init__(self, inner, hang_flag: str | None):
        self._inner = inner
        self._hang_flag = Path(hang_flag) if hang_flag else None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def operation_iter(self, operation, arguments):
        if self._hang_flag is not None and arguments.get("source_id") == "antigravity" and self._hang_flag.exists():
            yield {"phase": "scanning"}
            time.sleep(0.30)
        return (yield from self._inner.operation_iter(operation, arguments))


def _toggleable_build_core(spec):
    core = _real_build_core(spec)
    return _HangableCoreWrapper(core, spec.get("hang_flag"))


def _build_large_ag_desktop_store(root: Path, proj: Path, *, turns: int = 38, body_repeat: int = 1900):
    """Create a valid 2.33.0 native trajectory with paired compact+full transcripts (~150k chars)."""
    now_ns = time.time_ns()
    sec, nanos = divmod(now_ns, 1_000_000_000)
    iso = datetime.fromtimestamp(sec, timezone.utc).replace(microsecond=nanos // 1000).isoformat()

    db_path = root / "conversations" / f"{SESSION}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    expected_messages = []
    compact_rows = []
    full_rows = []

    folders = [(1, message((1, proj.as_uri())))]
    uris = [(7, proj.as_uri())]
    header = message(
        *folders,
        (2, message((1, sec), (2, nanos))),
        (3, INIT),
        (6, SESSION),
        *uris,
        (18, PROJECT),
    )

    with sqlite3.connect(db_path) as db:
        db.executescript(
            "PRAGMA user_version=1;"
            "CREATE TABLE trajectory_meta(trajectory_id TEXT, cascade_id TEXT, trajectory_type INTEGER, source INTEGER);"
            "CREATE TABLE trajectory_metadata_blob(id TEXT, data BLOB);"
            "CREATE TABLE steps(idx INTEGER PRIMARY KEY, step_type INTEGER, status INTEGER,"
            " has_subtrajectory INTEGER, metadata BLOB, step_payload BLOB, step_format INTEGER);"
            "CREATE TABLE executor_metadata(idx INTEGER PRIMARY KEY, data BLOB);"
            "CREATE TABLE gen_metadata(idx INTEGER PRIMARY KEY, data BLOB);"
            "CREATE TABLE parent_references(idx INTEGER PRIMARY KEY, data BLOB);"
            "CREATE TABLE battle_mode_infos(idx INTEGER PRIMARY KEY, data BLOB);"
        )
        db.execute("INSERT INTO trajectory_meta VALUES(?,?,4,1)", (TRAJECTORY, SESSION))
        db.execute("INSERT INTO trajectory_metadata_blob VALUES('main',?)", (header,))

        step_idx = 0
        for turn in range(turns):
            exec_key = str(uuid.UUID(int=1000 + turn))
            u_text = f"LARGE_TRAJ 压测提问 {turn}: " + ("工程参数核对 " * 25)
            wrapped = f"<USER_REQUEST>\n{u_text}\n</USER_REQUEST>\n<ADDITIONAL_METADATA>host</ADDITIONAL_METADATA>"
            a_text = f"LARGE_TRAJ 助手详细答复 {turn}: " + ("三维打印结构强度校核结论。" * (body_repeat // 12))
            expected_messages.append(("user", u_text))
            expected_messages.append(("assistant", a_text))

            # User step (14)
            t_at = message((1, sec), (2, nanos))
            u_origin = message((1, TRAJECTORY), (2, step_idx), (3, turn), (4, SESSION))
            u_life = message((1, message((1, 3), (2, t_at))))
            u_meta = message((1, t_at), (3, 4), (12, exec_key), (20, u_origin), (26, u_life))
            u_pub = message((2, u_text), (3, message((1, u_text))), (12, b""), (18, desktop_spec()))
            u_pay = message((1, 14), (4, 3), (5, u_meta), (19, u_pub))
            db.execute("INSERT INTO steps VALUES(?,14,3,0,?,?,0)", (step_idx, u_meta, u_pay))

            compact_rows.append({
                "step_index": step_idx, "type": "USER_INPUT", "source": "USER_EXPLICIT",
                "status": "DONE", "created_at": iso, "content": wrapped,
            })
            full_rows.append(dict(compact_rows[-1]))
            u_pos = step_idx
            step_idx += 1

            # Add 14 internal planner thinking/checkpoint steps per turn (~600+ total steps)
            # Wait: keep valid invocation accounting by using non-public internal step 23 (checkpoint)
            for _ in range(14):
                c_origin = message((1, TRAJECTORY), (2, step_idx), (3, turn), (4, SESSION))
                c_life = message((1, message((1, 3), (2, t_at))))
                c_meta = message((1, t_at), (3, 1), (12, exec_key), (20, c_origin), (26, c_life))
                c_pay = message((1, 23), (4, 3), (5, c_meta))
                db.execute("INSERT INTO steps VALUES(?,23,3,0,?,?,0)", (step_idx, c_meta, c_pay))
                step_idx += 1

            # Assistant step (15) — truncated in compact transcript, intact in transcript_full.jsonl!
            a_origin = message((1, TRAJECTORY), (2, step_idx), (3, turn), (4, SESSION))
            a_life = message((1, message((1, 8), (2, t_at))), (1, message((1, 3), (2, t_at))))
            a_meta = message((1, t_at), (3, 2), (12, exec_key), (20, a_origin), (26, a_life), (6, t_at), (7, t_at), (8, t_at))
            a_pub = message((1, a_text), (3, "PRIVATE REASONING"), (8, a_text))
            a_pay = message((1, 15), (4, 3), (5, a_meta), (20, a_pub))
            db.execute("INSERT INTO steps VALUES(?,15,3,0,?,?,0)", (step_idx, a_meta, a_pay))

            prefix_a = a_text[:120]
            suffix_a = a_text[-120:]
            omitted_bytes = len(a_text.encode("utf-8")) - len(prefix_a.encode("utf-8")) - len(suffix_a.encode("utf-8"))
            compact_rows.append({
                "step_index": step_idx, "type": "PLANNER_RESPONSE", "source": "MODEL",
                "status": "DONE", "created_at": iso,
                "content": f"{prefix_a}\n<truncated {omitted_bytes} bytes>\n{suffix_a}",
                "truncated_fields": ["content"],
            })
            full_rows.append({
                "step_index": step_idx, "type": "PLANNER_RESPONSE", "source": "MODEL",
                "status": "DONE", "created_at": iso, "content": a_text,
            })

            resolution = message((1, desktop_spec()), (3, b""))
            exec_blob = message((1, 4), (2, 1), (3, step_idx), (9, exec_key), (16, resolution))
            db.execute("INSERT INTO executor_metadata VALUES(?,?)", (turn, exec_blob))

            prompt = message((2, 1), (3, wrapped), (18, u_pos))
            chat = message((1, "PRIVATE SYSTEM"), (2, prompt))
            pos_bytes = varint(step_idx)
            gen_blob = message((1, chat), (2, pos_bytes), (4, exec_key))
            db.execute("INSERT INTO gen_metadata VALUES(?,?)", (turn, gen_blob))
            step_idx += 1
        db.commit()

    with sqlite3.connect(root / INDEX) as index:
        index.executescript(
            "PRAGMA user_version=3;"
            "CREATE TABLE conversation_summaries(conversation_id TEXT PRIMARY KEY, title TEXT, last_modified_time TEXT,"
            " workspace_uris TEXT, parent_conversation_id TEXT, nesting_depth INTEGER, project_id TEXT,"
            " step_count INTEGER, not_fully_idle INTEGER, killed INTEGER, status TEXT);"
            "CREATE TABLE conversation_parents(conversation_id TEXT PRIMARY KEY, parent_id TEXT);"
        )
        index.execute(
            "INSERT INTO conversation_summaries VALUES(?,?,?,?,'',0,?,?,0,0,'CASCADE_RUN_STATUS_IDLE')",
            (SESSION, "Large Trajectory Workbench Project", iso, json.dumps([proj.as_uri()]), PROJECT, step_idx),
        )
        index.commit()

    tx_dir = root / "brain" / SESSION / ".system_generated/logs"
    tx_dir.mkdir(parents=True, exist_ok=True)
    (tx_dir / "transcript.jsonl").write_bytes(
        b"".join(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n" for r in compact_rows)
    )
    (tx_dir / "transcript_full.jsonl").write_bytes(
        b"".join(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n" for r in full_rows)
    )
    return expected_messages


class BackgroundQosAndTimeoutRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.base = Path(self.tmp).resolve()
        os.chmod(self.base, 0o700)
        self.alpha = self.base / "alpha-studio"
        self.beta = self.base / "beta-other"
        self.ag_root = self.base / "ag-profile"
        self.codex_home = self.base / "codex-home"
        self.control = self.base / "control"
        for d in (self.alpha, self.beta, self.ag_root, self.codex_home / "sessions", self.control):
            d.mkdir(parents=True, mode=0o700)

        self.expected_ag_messages = _build_large_ag_desktop_store(self.ag_root, self.alpha, turns=38, body_repeat=1900)

        # Create 2 Codex threads (one in alpha, one in beta)
        now_iso = datetime.now(timezone.utc).isoformat()
        self.alpha_codex_id = "aa111111-1111-4111-8111-111111111111"
        self.beta_codex_id = "bb222222-2222-4222-8222-222222222222"
        with sqlite3.connect(self.codex_home / "state_5.sqlite") as db:
            db.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, title TEXT, updated_at INTEGER, archived INTEGER)"
            )
            for tid, proj, label in (
                (self.alpha_codex_id, self.alpha, "Alpha Codex Control"),
                (self.beta_codex_id, self.beta, "Beta Secret Thread"),
            ):
                rp = self.codex_home / "sessions" / f"rollout-{tid}.jsonl"
                rp.write_bytes(codex_encode([
                    {**row, "timestamp": now_iso}
                    for row in (
                        codex_record("session_meta", {"id": tid, "cwd": str(proj), "timestamp": now_iso}),
                        codex_message(f"{label} prompt"),
                        codex_message(f"{label} answer", "assistant", "final", native_id="ans1"),
                    )
                ]))
                db.execute("INSERT INTO threads VALUES (?,?,?,?,?,0)", (tid, str(rp), str(proj), label, int(time.time())))
            db.commit()

        self.document = {
            "version": 2,
            "projects": [
                {"id": "alpha", "name": "Alpha", "root": str(self.alpha), "directory_identity": persistent_identity(self.alpha)},
                {"id": "beta", "name": "Beta", "root": str(self.beta), "directory_identity": persistent_identity(self.beta)},
            ],
            "sources": {
                "antigravity": {
                    "adapter": "antigravity", "root": str(self.ag_root), "format": "2.33.0",
                    "enabled": True, "instance_id": "ag-inst", "root_identity": persistent_identity(self.ag_root),
                },
                "codex": {
                    "adapter": "codex", "root": str(self.codex_home), "format": "state_5",
                    "enabled": True, "instance_id": "codex-inst", "root_identity": persistent_identity(self.codex_home),
                },
            },
            "legacy_history": {"codex_home": str(self.codex_home), "state_db": "state_5.sqlite", "tool_evidence": []},
        }
        self.store = initialize_store(self.control / "generations")
        pv, dg = preview_activation(self.document)
        self.epoch = activate_preview(self.store, pv, dg, initial=True)
        self.desc = self.control / "policy.json"
        write_descriptor(self.desc, self.store)
        self._policy_overrides = {}
        orig_init = IsolatedHistory.__init__

        def dispatch_init(inst, history, **kw):
            extra = kw.get("_spec_extra") or {}
            wp = extra.get("agent_policy")
            key = str(wp.scratch.parent) if wp is not None and getattr(wp, "scratch", None) is not None else id(getattr(history, "unified_policy", None))
            cfg = self._policy_overrides.get(key)
            if cfg is not None:
                kw["wait_seconds"] = cfg["wait_seconds"]
                kw["step_seconds"] = cfg["step_seconds"]
                hf = cfg["hang_flag"]
                if hf is not None and extra:
                    kw["_factory"] = _toggleable_build_core
                    kw["_spec_extra"] = {**extra, "hang_flag": str(hf)}
            return orig_init(inst, history, **kw)

        self.enterContext(patch.object(IsolatedHistory, "__init__", dispatch_init))

    def _make_client(self, *, wait_seconds=4.0, step_seconds=3.0, hang_flag: Path | None = None):
        policy = AgentPolicy(self.desc, mode="v2")
        scratch = Path(tempfile.mkdtemp(dir=self.base, prefix="sc-"))
        os.chmod(scratch, 0o700)
        policy.scratch = scratch
        ov = {
            "wait_seconds": wait_seconds,
            "step_seconds": step_seconds,
            "hang_flag": hang_flag,
        }
        self._policy_overrides[str(scratch)] = ov
        self._policy_overrides[id(policy)] = ov
        settings = AccessSettings("https://test-team.cloudflareaccess.com", "a" * 64, "mcp.example.com", ("owner@example.com",))
        app = build_app(Catalog.from_policy(policy), settings, agent_policy=policy)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        app.verifier.keys = Mock()
        app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        token = jwt.encode(
            {"iss": settings.team_domain, "aud": [settings.audience], "iat": now - 1, "exp": now + 600,
             "email": "owner@example.com", "sub": "owner"},
            key, algorithm="RS256", headers={"kid": "t"},
        )
        headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26",
                   "cf-access-jwt-assertion": token}
        tc = TestClient(app, base_url="https://mcp.example.com")
        tc.__enter__()
        self.addCleanup(lambda: tc.__exit__(None, None, None))
        return tc, headers

    @staticmethod
    def _rpc(tc, headers, name, arguments):
        r = tc.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments},
        })
        assert r.status_code == 200, r.status_code
        body = r.json()
        if "error" in body:
            return True, body["error"]["message"]
        res = body["result"]
        txt = res["content"][0]["text"]
        if res.get("isError"):
            return True, txt
        return False, json.loads(txt)

    def test_capture_iter_emits_multiple_cooperative_scanning_checkpoints(self):
        from peters_mcp.agent_history_antigravity import Adapter
        from peters_mcp.agent_history_source import SourceRoot

        sc = self.base / "direct-sc"
        sc.mkdir(mode=0o700)
        adapter = Adapter(SourceRoot(self.ag_root, scratch=sc), "2.33.0")
        thread = adapter.describe(SESSION)
        gen = capture_iter(adapter, thread)
        yields = []
        try:
            while True:
                yields.append(next(gen))
        except StopIteration as done:
            obs, proj = done.value
        self.assertGreaterEqual(len(yields), 10)
        self.assertTrue(all(y == {"phase": "scanning"} for y in yields))
        self.assertEqual([(m.role, m.text) for m in proj.messages], self.expected_ag_messages)

    @unittest.skipUnless(sys.platform == "darwin" and Path("/usr/sbin/taskpolicy").is_file(), "macOS taskpolicy required")
    def test_background_qos_cold_large_antigravity_find_and_full_read_without_step_timeout(self):
        """Run actual server under `/usr/sbin/taskpolicy -b` with tight wait_seconds=0.05 to force continuation + full read."""
        pkg_root = str(Path(__file__).resolve().parent.parent)
        driver = (
            "import json, os, sys, tempfile, time\n"
            "from pathlib import Path\n"
            "from types import SimpleNamespace\n"
            "from unittest.mock import Mock, patch\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "import jwt\n"
            "from starlette.testclient import TestClient\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from peters_mcp.agent_history_policy import AgentPolicy\n"
            "from peters_mcp.catalog import Catalog\n"
            "from peters_mcp.cloudflare import AccessSettings, build_app\n"
            "from peters_mcp.history_process import IsolatedHistory\n"
            "pol = AgentPolicy(Path(sys.argv[2]), mode='v2')\n"
            "sc = Path(tempfile.mkdtemp(dir=sys.argv[3], prefix='bg-sc-')); os.chmod(sc, 0o700); pol.scratch = sc\n"
            "cfg = AccessSettings('https://t.cloudflareaccess.com', 'b'*64, 'mcp.example.com', ('o@example.com',))\n"
            "orig_init = IsolatedHistory.__init__\n"
            "instances = []\n"
            "def wrap_init(inst, history, **kw):\n"
            "    kw['wait_seconds'] = 0.30\n"
            "    kw['step_seconds'] = 1.5\n"
            "    orig_init(inst, history, **kw)\n"
            "    instances.append(inst)\n"
            "with patch.object(IsolatedHistory, '__init__', wrap_init):\n"
            "    app = build_app(Catalog.from_policy(pol), cfg, agent_policy=pol)\n"
            "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "    now = int(time.time())\n"
            "    app.verifier.keys = Mock()\n"
            "    app.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())\n"
            "    tok = jwt.encode({'iss': cfg.team_domain, 'aud': [cfg.audience], 'iat': now-1, 'exp': now+600, 'email': 'o@example.com', 'sub': 'o'}, key, algorithm='RS256', headers={'kid': 'k'})\n"
            "    hdr = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-03-26', 'cf-access-jwt-assertion': tok}\n"
            "    with TestClient(app, base_url='https://mcp.example.com') as tc:\n"
            "        def call(name, args):\n"
            "            for _ in range(80):\n"
            "                r = tc.post('/mcp', headers=hdr, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}}).json()['result']\n"
            "                assert not r.get('isError'), r\n"
            "                d = json.loads(r['content'][0]['text'])\n"
            "                if d.get('status') != 'processing': return d\n"
            "                args = {**args, 'cursor': d['next_cursor']}\n"
            "            raise RuntimeError('did not converge')\n"
            "        f_spec = call('find_agent_threads', {'project_id': 'alpha', 'agent': 'antigravity', 'query': 'LARGE_TRAJ', 'limit': 10})\n"
            "        f_agg = call('find_agent_threads', {'project_id': 'alpha', 'query': 'LARGE_TRAJ', 'limit': 10})\n"
            "        tref = f_spec['threads'][0]['thread_ref']\n"
            "        cur = ''; pages = 0; parts = {}; order = []\n"
            "        while True:\n"
            "            pages += 1\n"
            "            pg = call('read_agent_thread', {'thread_ref': tref, 'cursor': cur, 'view': 'all', 'limit': 12, 'max_chars': 16000})\n"
            "            for e in pg['entries']:\n"
            "                mid = e['message_id']\n"
            "                if mid not in parts: order.append((mid, e['role'])); parts[mid] = {}\n"
            "                parts[mid][e.get('part_offset', 0)] = e['text']\n"
            "            if not pg['has_more']: break\n"
            "            cur = pg['next_cursor']\n"
            "        msgs = [[role, ''.join(parts[mid][k] for k in sorted(parts[mid]))] for mid, role in order]\n"
            "        lt_cur = ''; lt_parts = {}; lt_order = []\n"
            "        while True:\n"
            "            lpg = call('read_agent_thread', {'thread_ref': tref, 'cursor': lt_cur, 'view': 'latest_turn', 'limit': 12, 'max_chars': 16000})\n"
            "            for e in lpg['entries']:\n"
            "                mid = e['message_id']\n"
            "                if mid not in lt_parts: lt_order.append((mid, e['role'])); lt_parts[mid] = {}\n"
            "                lt_parts[mid][e.get('part_offset', 0)] = e['text']\n"
            "            if not lpg['has_more']: break\n"
            "            lt_cur = lpg['next_cursor']\n"
            "        lt_msgs = [[role, ''.join(lt_parts[mid][k] for k in sorted(lt_parts[mid]))] for mid, role in lt_order]\n"
            "        stops = [ev for inst in instances for ev in inst.diagnostic_events() if ev.get('event') == 'worker_stop' and ev.get('reason') == 'step_timeout']\n"
            "        print(json.dumps({'spec_hits': len(f_spec['threads']), 'agg_hits': len(f_agg['threads']), 'pages': pages, 'msgs': msgs, 'lt_msgs': lt_msgs, 'step_timeouts': stops}))\n"
        )
        proc = subprocess.run(
            ["/usr/sbin/taskpolicy", "-b", sys.executable, "-B", "-c", driver, pkg_root, str(self.desc), str(self.base)],
            capture_output=True, text=True, timeout=60, check=True,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(out["spec_hits"], 1)
        self.assertEqual(out["agg_hits"], 1)
        self.assertGreaterEqual(out["pages"], 7)
        self.assertEqual(out["step_timeouts"], [])
        self.assertEqual([tuple(m) for m in out["msgs"]], self.expected_ag_messages)
        self.assertEqual([tuple(m) for m in out["lt_msgs"]], self.expected_ag_messages[-2:])

    def test_v2_timeout_and_stale_continuation_return_structured_status_and_recover(self):
        """Inject a transient hang on Antigravity under v2: verify processing_timeout / restart_required & clean recovery."""
        hang_flag = self.base / "hang.flag"
        hang_flag.write_text("1", encoding="utf-8")

        tc_to, hdr_to = self._make_client(wait_seconds=0.50, step_seconds=0.06, hang_flag=hang_flag)

        # 1. Single-source Antigravity find under step_timeout -> structured processing_timeout (NOT topology error!)
        is_err, res_to = self._rpc(tc_to, hdr_to, "find_agent_threads", {
            "project_id": "alpha", "source_id": "antigravity", "query": "LARGE_TRAJ", "limit": 10,
        })
        self.assertFalse(is_err, f"Unexpected ToolError instead of structured processing_timeout: {res_to}")
        self.assertEqual(res_to["status"], "processing_timeout")
        self.assertIn("Start a fresh call", res_to["continue_with"])

        # 2. Aggregate find when Antigravity times out -> status=ready with Codex hit + antigravity warning=['processing_timeout']!
        is_err, agg_res = self._rpc(tc_to, hdr_to, "find_agent_threads", {
            "project_id": "alpha", "limit": 10,
        })
        self.assertFalse(is_err, f"Unexpected ToolError on aggregate timeout: {agg_res}")
        self.assertEqual(agg_res["status"], "ready")
        self.assertEqual([(t["source_id"], t["title"]) for t in agg_res["threads"]], [("codex", "Alpha Codex Control")])
        cov_by_src = {c["source_id"]: c for c in agg_res["coverage"]}
        self.assertEqual(cov_by_src["codex"]["state"], "complete")
        self.assertEqual(cov_by_src["antigravity"]["state"], "processing_timeout")
        self.assertIn("processing_timeout", cov_by_src["antigravity"]["warnings"])

        # 3. Delayed continuation poll after worker step_timeout -> structured restart_required (NOT topology error!)
        tc_stale, hdr_stale = self._make_client(wait_seconds=0.02, step_seconds=0.08, hang_flag=hang_flag)
        is_err, first = self._rpc(tc_stale, hdr_stale, "find_agent_threads", {
            "project_id": "alpha", "source_id": "antigravity", "query": "LARGE_TRAJ", "limit": 10,
        })
        self.assertFalse(is_err, first)
        self.assertEqual(first["status"], "processing")
        stale_cursor = first["next_cursor"]
        terminal = None
        for _ in range(25):
            time.sleep(0.10)
            is_err, poll_res = self._rpc(tc_stale, hdr_stale, "find_agent_threads", {
                "project_id": "alpha", "source_id": "antigravity", "query": "LARGE_TRAJ", "limit": 10, "cursor": stale_cursor,
            })
            self.assertFalse(is_err, f"Unexpected ToolError on stale cursor poll: {poll_res}")
            if poll_res["status"] != "processing":
                terminal = poll_res
                break
        self.assertIsNotNone(terminal)
        self.assertIn(terminal["status"], ("processing_timeout", "restart_required"))
        is_err, after_stop = self._rpc(tc_stale, hdr_stale, "find_agent_threads", {
            "project_id": "alpha", "source_id": "antigravity", "query": "LARGE_TRAJ", "limit": 10, "cursor": stale_cursor,
        })
        self.assertFalse(is_err, f"Unexpected ToolError on post-stop stale cursor: {after_stop}")
        self.assertEqual(after_stop["status"], "restart_required")
        self.assertIn("Start a fresh call", after_stop["continue_with"])

        # 4. Remove hang -> SAME server instance recovers cleanly on a fresh call!
        hang_flag.unlink()
        is_err, recovered = self._rpc(tc_to, hdr_to, "find_agent_threads", {
            "project_id": "alpha", "source_id": "antigravity", "query": "LARGE_TRAJ", "limit": 10,
        })
        self.assertFalse(is_err, recovered)
        self.assertEqual(recovered["status"], "ready")
        self.assertEqual(len(recovered["threads"]), 1)

    def test_v2_revocation_blocks_timeout_and_stale_cursors_without_status_or_data_leak(self):
        """Obtain pre-revocation thread_ref & hp1. cursors, force worker timeout/stop, revoke beta, verify fail-closed."""
        tc, hdr = self._make_client(wait_seconds=4.0, step_seconds=3.0)
        # Get beta Codex thread_ref via unified API and page-1 cursor
        is_err, b_found = self._rpc(tc, hdr, "find_agent_threads", {"project_id": "beta", "limit": 10})
        self.assertFalse(is_err, b_found)
        beta_ref = b_found["threads"][0]["thread_ref"]
        is_err, b_p1 = self._rpc(tc, hdr, "read_agent_thread", {"thread_ref": beta_ref, "limit": 1})
        self.assertFalse(is_err, b_p1)
        beta_read_cursor = b_p1["next_cursor"]

        # Also get a slow `hp1.` processing cursor on beta before revocation
        tc_slow, hdr_slow = self._make_client(wait_seconds=0.001, step_seconds=0.001)
        is_err, b_proc = self._rpc(tc_slow, hdr_slow, "find_agent_threads", {
            "project_id": "beta", "source_id": "codex", "limit": 10,
        })
        b_hp1_cursor = b_proc.get("next_cursor", "") if not is_err else ""
        is_err_leg, leg_proc = self._rpc(tc_slow, hdr_slow, "read_codex_thread", {"thread_id": self.beta_codex_id})
        leg_hp1_cursor = leg_proc.get("next_cursor", "") if not is_err_leg else ""
        time.sleep(0.05)  # allow tight step_seconds worker to stop

        # Revoke project 'beta' in live policy store!
        revoked_doc = deepcopy(self.document)
        revoked_doc["projects"] = [p for p in revoked_doc["projects"] if p["id"] != "beta"]
        pv, dg = preview_activation(revoked_doc, previous=AgentPolicy(self.desc, mode="v2").snapshot())
        activate_preview(self.store, pv, dg)

        # Every beta operation (including on the timed-out / stopped worker client!) MUST fail closed with isError=True!
        for client_pair in ((tc, hdr), (tc_slow, hdr_slow)):
            c, h = client_pair
            err1, msg1 = self._rpc(c, h, "find_agent_threads", {"project_id": "beta", "limit": 10})
            self.assertTrue(err1, msg1)
            self.assertNotIn("Beta Secret", msg1)
            err2, msg2 = self._rpc(c, h, "read_agent_thread", {"thread_ref": beta_ref})
            self.assertTrue(err2, msg2)
            self.assertNotIn("Beta Secret", msg2)
            err3, msg3 = self._rpc(c, h, "read_agent_thread", {"thread_ref": beta_ref, "limit": 1, "cursor": beta_read_cursor})
            self.assertTrue(err3, msg3)
            self.assertNotIn("Beta Secret", msg3)

        if b_hp1_cursor:
            err_hp, msg_hp = self._rpc(tc_slow, hdr_slow, "find_agent_threads", {
                "project_id": "beta", "source_id": "codex", "limit": 10, "cursor": b_hp1_cursor,
            })
            self.assertTrue(err_hp, msg_hp)
        if leg_hp1_cursor:
            err_lhp, msg_lhp = self._rpc(tc_slow, hdr_slow, "read_codex_thread", {
                "thread_id": self.beta_codex_id, "cursor": leg_hp1_cursor,
            })
            self.assertTrue(err_lhp, msg_lhp)
            self.assertNotIn("Beta Secret", msg_lhp)

        # Retained project 'alpha' still works cleanly!
        err_a, alpha_ok = self._rpc(tc, hdr, "find_agent_threads", {"project_id": "alpha", "source_id": "codex", "limit": 10})
        self.assertFalse(err_a, alpha_ok)
        self.assertEqual(len(alpha_ok["threads"]), 1)


if __name__ == "__main__":
    unittest.main()
