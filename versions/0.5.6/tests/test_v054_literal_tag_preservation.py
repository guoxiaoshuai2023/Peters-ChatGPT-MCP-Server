"""v0.5.4 targeted L4 remediation regression tests.

Covers:
1. Human-authored and assistant-authored literal `<subagent_notification>` text
   (whole-message, inline-wrapped, and unclosed open-tag followed by multi-line
   conclusions) is preserved verbatim in Codex titles, unified/legacy reads, and
   all three search entrances (`find_agent_threads` aggregate, `source_id='codex'`,
   and `find_codex_threads`), while genuine tool-provenance `<subagent_notification>`
   completion records (`provenance.type == 'tool'` / `multi_agent.*` item kinds)
   remain excluded from parent public turns and search.
2. All three non-Codex adapters (`antigravity`, `deepseek_harness`, `codeg`)
   preserve 18/18 public user/assistant messages containing closed and unclosed
   literal `<subagent_notification>` tags verbatim through `AgentHistoryService`
   without `[OMITTED: internal context]` substitution or tail truncation.
3. Existing genuine internal-context tags (`<environment_context>`,
   `<permissions_instructions>`, `<system-reminder>`) and secret/path redactions
   remain fully active.
"""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from peters_mcp.agent_history import _safe_text
from peters_mcp.agent_history_admin import activate_preview, compile_generation, preview_activation, write_descriptor
from peters_mcp.agent_history_antigravity import INDEX as AG_INDEX
from peters_mcp.agent_history_generation import initialize_store
from peters_mcp.agent_history_policy import AgentPolicy
from peters_mcp.agent_history_service import AgentHistoryService
from peters_mcp.catalog import Catalog
from peters_mcp.history import HistoryAccess
from peters_mcp.history_projection import sanitize
from peters_mcp.workspaces import repository_probe


def _drain(gen):
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def _git(cwd, *args):
    subprocess.run(
        ["/usr/bin/git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
    )


def _jsonl(records):
    return b"".join(
        json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for r in records
    )


def _iso(ns):
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


def _sha_pairs(pairs):
    return hashlib.sha256(
        json.dumps([list(p) for p in pairs], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class LiteralSubagentNotificationPreservationTests(unittest.TestCase):
    def test_codex_whole_inline_and_unclosed_literal_tags_coexist_with_tool_notification_isolation(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            root = Path(tmp_name).resolve()
            os.chmod(root, 0o700)
            proj = root / "alpha"
            proj.mkdir()
            _git(proj, "init", "-q")
            (proj / "README.md").write_text("alpha\n", encoding="utf-8")
            _git(proj, "add", "README.md")
            _git(proj, "commit", "-q", "-m", "init")

            codex_home = root / "codex-home"
            folder = codex_home / "sessions" / "2026" / "11" / "25"
            folder.mkdir(parents=True)
            state_db = codex_home / "state_5.sqlite"
            with closing(sqlite3.connect(state_db)) as db:
                db.execute(
                    "CREATE TABLE threads ("
                    "id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, cwd TEXT NOT NULL, "
                    "title TEXT, updated_at INTEGER, archived INTEGER DEFAULT 0, created_at INTEGER, "
                    "history_mode TEXT, attached_thread_parent_id TEXT, source TEXT)"
                )
                db.commit()

            state_dir = root / "generations-state"
            desc = root / "policy.json"
            store = initialize_store(state_dir)
            doc = compile_generation({
                "version": 2,
                "projects": [
                    {"id": "alpha", "name": "Alpha", "root": str(proj), "repository_id": repository_probe(proj)["repository_id"]},
                ],
                "sources": {
                    "codex": {
                        "adapter": "codex", "root": str(codex_home), "format": "local",
                        "enabled": True, "instance_id": "codex", "denied_threads": [],
                    }
                },
                "legacy_history": {"codex_home": str(codex_home), "state_db": "state_5.sqlite", "tool_evidence": []},
            })
            pv, dg = preview_activation(doc)
            activate_preview(store, pv, dg, initial=True)
            write_descriptor(desc, store)
            time.sleep(0.05)
            now_ns = time.time_ns()
            sec = int(now_ns // 1_000_000_000)
            t0 = _iso(now_ns - 4_000_000)
            t1 = _iso(now_ns - 3_000_000)

            parent_id = "11111111-1111-4111-8111-111111111111"
            child_id = "22222222-2222-4222-8222-222222222222"
            whole_id = "33333333-3333-4333-8333-333333333333"
            inline_id = "44444444-4444-4444-8444-444444444444"

            whole_user_txt = "<subagent_notification> A user typed this literal tag WholeUnique501 </subagent_notification>"
            inline_user_txt = "Before the literal tag. <subagent_notification> InlineUnique502 </subagent_notification> After the literal tag."
            unclosed_user_txt = "Explaining open tag `<subagent_notification>` spelling.\nFinal business decision UnclosedUnique503."

            # Parent P with genuine tool-generated <subagent_notification>
            p_records = [
                {"timestamp": t0, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(proj), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
                {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "pt1"}},
                {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "pt1"}},
                {"timestamp": t0, "type": "response_item", "payload": {
                    "type": "message", "id": "pu1", "role": "user",
                    "content": [{"type": "input_text", "text": "Delegate work ParentOwn500"}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "pt1", "content_item_kinds": ["user.text"],
                        "content_item_metadata": [{"provenance": {"type": "user"}}],
                    },
                }},
                {"timestamp": t0, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": parent_id, "turn_id": "pt1",
                    "item": {"type": "UserMessage", "id": "pu1", "content": [{"type": "text", "text": "Delegate work ParentOwn500"}]},
                }},
                {"timestamp": t0, "type": "response_item", "payload": {
                    "type": "message", "id": "pnotif", "role": "user",
                    "content": [{"type": "input_text", "text": f"<subagent_notification>\n{{\"agent_path\":\"{child_id}\",\"status\":{{\"completed\":\"ChildOwnReply599\"}}}}\n</subagent_notification>"}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "pt1",
                        "content_item_kinds": ["multi_agent.subagent_notification"],
                        "content_item_metadata": [{"provenance": {"type": "tool", "namespace": "multi_agent_v1"}}],
                    },
                }},
                {"timestamp": t1, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": parent_id, "turn_id": "pt1",
                    "item": {"type": "AgentMessage", "id": "pa1", "phase": "final_answer", "content": [{"type": "Text", "text": "Parent finished."}]},
                }},
                {"timestamp": t1, "type": "response_item", "payload": {
                    "type": "message", "id": "pa1", "role": "assistant", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "Parent finished."}],
                }},
            ]

            sub_src = {"subagent": {"thread_spawn": {"parent_thread_id": parent_id, "depth": 1}}}
            c_records = [
                {"timestamp": t0, "type": "session_meta", "payload": {"id": child_id, "forked_from_id": parent_id, "parent_thread_id": parent_id, "cwd": str(proj), "timestamp": t0, "cli_version": "0.171.0", "source": sub_src}},
                {"timestamp": t0, "type": "session_meta", "payload": {"id": parent_id, "cwd": str(proj), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
                {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "pt1"}},
                {"timestamp": t0, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Delegate work ParentOwn500"}]}},
                {"timestamp": t1, "type": "event_msg", "payload": {"type": "thread_settings_applied", "thread_id": child_id, "thread_settings": {}}},
                {"timestamp": t1, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "ct1"}},
                {"timestamp": t1, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "ct1"}},
                {"timestamp": t1, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": child_id, "turn_id": "ct1",
                    "item": {"type": "AgentMessage", "id": "ca1", "phase": "final_answer", "content": [{"type": "Text", "text": "ChildOwnReply599"}]},
                }},
                {"timestamp": t1, "type": "response_item", "payload": {
                    "type": "message", "id": "ca1", "role": "assistant", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "ChildOwnReply599"}],
                }},
            ]

            whole_records = [
                {"timestamp": t0, "type": "session_meta", "payload": {"id": whole_id, "cwd": str(proj), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
                {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "wt1"}},
                {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "wt1"}},
                {"timestamp": t0, "type": "response_item", "payload": {
                    "type": "message", "id": "wu1", "role": "user",
                    "content": [{"type": "input_text", "text": whole_user_txt}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "wt1", "content_item_kinds": ["user.text"],
                        "content_item_metadata": [{"provenance": {"type": "user"}}],
                    },
                }},
                {"timestamp": t0, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": whole_id, "turn_id": "wt1",
                    "item": {"type": "UserMessage", "id": "wu1", "content": [{"type": "text", "text": whole_user_txt}]},
                }},
                {"timestamp": t1, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": whole_id, "turn_id": "wt1",
                    "item": {"type": "AgentMessage", "id": "wa1", "phase": "final_answer", "content": [{"type": "Text", "text": "Literal user content received."}]},
                }},
                {"timestamp": t1, "type": "response_item", "payload": {
                    "type": "message", "id": "wa1", "role": "assistant", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "Literal user content received."}],
                }},
            ]

            inline_records = [
                {"timestamp": t0, "type": "session_meta", "payload": {"id": inline_id, "cwd": str(proj), "timestamp": t0, "cli_version": "0.171.0", "source": "cli"}},
                {"timestamp": t0, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "it1"}},
                {"timestamp": t0, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "it1"}},
                {"timestamp": t0, "type": "response_item", "payload": {
                    "type": "message", "id": "iu1", "role": "user",
                    "content": [{"type": "input_text", "text": inline_user_txt}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "it1", "content_item_kinds": ["user.text"],
                        "content_item_metadata": [{"provenance": {"type": "user"}}],
                    },
                }},
                {"timestamp": t0, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": inline_id, "turn_id": "it1",
                    "item": {"type": "UserMessage", "id": "iu1", "content": [{"type": "text", "text": inline_user_txt}]},
                }},
                {"timestamp": t0, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": inline_id, "turn_id": "it1",
                    "item": {"type": "AgentMessage", "id": "ia1", "phase": "final_answer", "content": [{"type": "Text", "text": "Example: `<subagent_notification>`\nKeep paragraph three intact."}]},
                }},
                {"timestamp": t0, "type": "response_item", "payload": {
                    "type": "message", "id": "ia1", "role": "assistant", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "Example: `<subagent_notification>`\nKeep paragraph three intact."}],
                }},
                {"timestamp": t1, "type": "event_msg", "payload": {"type": "task_started", "turn_id": "it2"}},
                {"timestamp": t1, "type": "turn_context", "payload": {"cwd": str(proj), "turn_id": "it2"}},
                {"timestamp": t1, "type": "response_item", "payload": {
                    "type": "message", "id": "iu2", "role": "user",
                    "content": [{"type": "input_text", "text": unclosed_user_txt}],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": "it2", "content_item_kinds": ["user.text"],
                        "content_item_metadata": [{"provenance": {"type": "user"}}],
                    },
                }},
                {"timestamp": t1, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": inline_id, "turn_id": "it2",
                    "item": {"type": "UserMessage", "id": "iu2", "content": [{"type": "text", "text": unclosed_user_txt}]},
                }},
                {"timestamp": t1, "type": "event_msg", "payload": {
                    "type": "item_completed", "thread_id": inline_id, "turn_id": "it2",
                    "item": {"type": "AgentMessage", "id": "ia2", "phase": "final_answer", "content": [{"type": "Text", "text": "Done."}]},
                }},
                {"timestamp": t1, "type": "response_item", "payload": {
                    "type": "message", "id": "ia2", "role": "assistant", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "Done."}],
                }},
            ]

            with closing(sqlite3.connect(state_db)) as db:
                for idx, (tid, tag, recs, title, src) in enumerate([
                    (parent_id, "p", p_records, "Delegate work ParentOwn500", "cli"),
                    (child_id, "c", c_records, "Child task", json.dumps(sub_src)),
                    (whole_id, "w", whole_records, whole_user_txt, "cli"),
                    (inline_id, "i", inline_records, inline_user_txt, "cli"),
                ], 1):
                    fp = folder / f"rollout-{tag}-{tid}.jsonl"
                    fp.write_bytes(_jsonl(recs))
                    db.execute(
                        "INSERT INTO threads VALUES (?, ?, ?, ?, ?, 0, ?, 'legacy', NULL, ?)",
                        (tid, str(fp), str(proj), title, sec + idx, sec, src),
                    )
                db.commit()

            policy = AgentPolicy(desc, mode="v2")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            policy.scratch = scratch
            catalog = Catalog.from_policy(policy)
            catalog.set_agent_history_policy(policy)
            legacy = HistoryAccess(catalog=catalog, unified_policy=policy)
            svc = AgentHistoryService(policy, legacy, local=True)
            self.addCleanup(svc.close)
            caller = {"actor": "a" * 64, "policy_actor": "local"}

            found = svc.find_agent_threads(project_id="alpha", source_id="codex", query="", limit=10)["threads"]
            self.assertEqual(len(found), 4)
            by_title = {t["title"]: t for t in found}
            self.assertIn(whole_user_txt, by_title)
            self.assertIn(inline_user_txt, by_title)

            # Whole-literal thread: both entrances return 2/2 verbatim
            exp_whole = [("user", whole_user_txt), ("assistant", "Literal user content received.")]
            u_whole = svc.read_agent_thread(by_title[whole_user_txt]["thread_ref"], view="all", limit=10)
            l_whole = _drain(legacy._read_codex_thread_iter(whole_id, view="all", caller=caller))
            self.assertEqual([(e["role"], e["text"]) for e in u_whole["entries"]], exp_whole)
            self.assertEqual([(e["role"], e["text"]) for e in l_whole["entries"]], exp_whole)
            self.assertEqual(l_whole["thread"]["title"], whole_user_txt)

            # Inline & unclosed open-tag thread: 4/4 verbatim, zero truncation
            exp_inline = [
                ("user", inline_user_txt),
                ("assistant", "Example: `<subagent_notification>`\nKeep paragraph three intact."),
                ("user", unclosed_user_txt),
                ("assistant", "Done."),
            ]
            u_inline = svc.read_agent_thread(by_title[inline_user_txt]["thread_ref"], view="all", limit=10)
            l_inline = _drain(legacy._read_codex_thread_iter(inline_id, view="all", caller=caller))
            self.assertEqual([(e["role"], e["text"]) for e in u_inline["entries"]], exp_inline)
            self.assertEqual([(e["role"], e["text"]) for e in l_inline["entries"]], exp_inline)

            # Parent still excludes tool-provenance <subagent_notification> (2/2, not 3)
            u_parent = svc.read_agent_thread(by_title["Delegate work ParentOwn500"]["thread_ref"], view="all", limit=10)
            self.assertEqual([(e["role"], e["text"]) for e in u_parent["entries"]], [
                ("user", "Delegate work ParentOwn500"),
                ("assistant", "Parent finished."),
            ])

            # Search checks across all 3 entrances!
            for q, exp_stable, exp_tid in [
                ("WholeUnique501", by_title[whole_user_txt]["stable_thread_id"], whole_id),
                ("InlineUnique502", by_title[inline_user_txt]["stable_thread_id"], inline_id),
                ("UnclosedUnique503", by_title[inline_user_txt]["stable_thread_id"], inline_id),
                ("ChildOwnReply599", by_title["Child task"]["stable_thread_id"], child_id),
                ("ParentOwn500", by_title["Delegate work ParentOwn500"]["stable_thread_id"], parent_id),
            ]:
                for kw in ({}, {"source_id": "codex"}):
                    hits = svc.find_agent_threads(project_id="alpha", query=q, limit=10, **kw)["threads"]
                    self.assertEqual([h["stable_thread_id"] for h in hits], [exp_stable], f"failed unified search for {q}")
                lhits = _drain(legacy._find_codex_threads_iter(project_id="alpha", query=q, limit=10, caller=caller))["threads"]
                self.assertEqual([h["thread_id"] for h in lhits], [exp_tid], f"failed legacy search for {q}")

    def test_antigravity_deepseek_and_codeg_preserve_18_of_18_literal_tag_messages_verbatim(self):
        expected_public = [
            ("user", "文档例子为 `<subagent_notification> 示例说明 </subagent_notification>`。末尾请保留订单编号 A29。"),
            ("assistant", "手册中这一行是 `<subagent_notification> 已完成示例 </subagent_notification>`。对应模块为公开帮助页。"),
            ("user", "我正在解释开标签 `<subagent_notification>` 的拼写。\n本周正常业务决定是周四发布中文帮助。"),
            ("assistant", "可以单独展示开标签 `<subagent_notification>`。\n正式文稿的第三段应保留联系方式示例。"),
            ("user", "普通对照。请给我两条建议。"),
            ("assistant", "保留原文和角色。"),
        ]
        expected_sha = "ccdd2caa0e8c8104ae2103416fa1dfdb2a36a830c7177a432c6eab14bae6b11f"
        self.assertEqual(_sha_pairs(expected_public), expected_sha)

        with tempfile.TemporaryDirectory() as tmp_name:
            base = Path(tmp_name).resolve()
            os.chmod(base, 0o700)
            proj = base / "proj"
            proj.mkdir()

            # 1. Antigravity 2.32.1 store
            ag_root = base / "ag-data"
            ag_root.mkdir()
            ag_cid = "10101010-1010-4010-8010-101010101010"
            with closing(sqlite3.connect(ag_root / AG_INDEX)) as db:
                db.executescript(
                    "PRAGMA user_version = 3;"
                    "CREATE TABLE conversation_summaries ("
                    "conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL, preview TEXT, "
                    "last_modified_time datetime NOT NULL, workspace_uris TEXT NOT NULL, "
                    "parent_conversation_id TEXT NOT NULL, nesting_depth INTEGER NOT NULL, raw_summary BLOB);"
                    "CREATE TABLE conversation_parents (conversation_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL);"
                )
                db.execute(
                    "INSERT INTO conversation_summaries VALUES (?, ?, '', '2026-11-25T00:00:00Z', ?, '', 0, X'00')",
                    (ag_cid, "AG Literal Discussion", json.dumps([proj.as_uri()])),
                )
                db.commit()
            ag_tx = ag_root / "brain" / ag_cid / ".system_generated" / "logs" / "transcript.jsonl"
            ag_tx.parent.mkdir(parents=True)
            ag_steps = [
                {
                    "step_index": i,
                    "type": "USER_INPUT" if role == "user" else "PLANNER_RESPONSE",
                    "source": "USER_EXPLICIT" if role == "user" else "MODEL",
                    "status": "DONE",
                    "content": txt,
                    "created_at": "2026-11-25T00:00:00Z",
                }
                for i, (role, txt) in enumerate(expected_public)
            ]
            ag_tx.write_bytes(_jsonl(ag_steps))

            # 2. DeepSeek Harness 0.2.2-rc.3 store
            ds_root = base / "ds-sessions"
            ds_id = "literal-check"
            encoded_proj = "--" + str(proj).lstrip("/").replace("/", "-") + "--"
            ds_file = ds_root / encoded_proj / ds_id / "session.v4.jsonl.zstd"
            ds_file.parent.mkdir(parents=True)
            ds_header = {
                "type": "session", "version": 4, "id": ds_id, "createdAt": 1712345678900,
                "isSeeded": False, "delegationDepth": 0, "cwd": str(proj),
            }
            ds_events = [{"type": "turn/start", "seq": 0, "time": 1712345678900, "data": {"turn": 1}}]
            seq = 1
            for role, txt in expected_public:
                if role == "user":
                    ds_events.append({
                        "type": "user/message", "seq": seq, "time": 1712345678900 + seq,
                        "surfaceOp": "append",
                        "data": {"id": f"u{seq}", "role": "user", "source": {"kind": "user"}, "content": [{"type": "text", "text": txt}]},
                    })
                else:
                    ds_events.append({
                        "type": "assistant/message", "seq": seq, "time": 1712345678900 + seq,
                        "surfaceOp": "append",
                        "data": {"turn": 1, "step": seq, "message": {"id": f"a{seq}", "role": "assistant", "source": {"kind": "model"}, "content": [{"type": "text", "text": txt}]}},
                    })
                seq += 1
            ds_events.append({"type": "turn/end", "seq": seq, "time": 1712345678900 + seq, "data": {"turn": 1, "reason": {"kind": "completed"}}})
            ds_file.write_bytes(
                zstd.compress(_jsonl([ds_header]), options={zstd.CompressionParameter.checksum_flag: 1})
                + zstd.compress(_jsonl(ds_events), options={zstd.CompressionParameter.checksum_flag: 1})
            )

            # 3. Codeg 0.45.0 store
            cg_root = base / "codeg-data"
            cg_root.mkdir()
            with closing(sqlite3.connect(cg_root / "codeg.db")) as db:
                db.executescript(
                    "CREATE TABLE folder (id INTEGER PRIMARY KEY, path TEXT NOT NULL, kind TEXT NOT NULL, parent_id INTEGER, deleted_at TEXT);"
                    "CREATE TABLE conversation (id INTEGER PRIMARY KEY, title TEXT, updated_at TEXT NOT NULL, agent_type TEXT NOT NULL, "
                    "external_id TEXT, origin_cwd TEXT, folder_id INTEGER NOT NULL, kind TEXT NOT NULL, parent_id INTEGER, deleted_at TEXT);"
                )
                db.execute("INSERT INTO folder VALUES (1, ?, 'regular', NULL, NULL)", (str(proj),))
                db.execute(
                    "INSERT INTO conversation VALUES (1, 'Codeg Literal Discussion', '2026-11-25T00:00:00+00:00', 'custom:goose', 'cg-sess-1', ?, 1, 'regular', NULL, NULL)",
                    (str(proj),),
                )
                db.commit()
            cg_tx = cg_root / "acp-transcripts" / "goose" / "cg-sess-1.jsonl"
            cg_tx.parent.mkdir(parents=True)
            cg_lines = [{"v": 1, "kind": "header", "agent": "custom:goose", "session_id": "cg-sess-1", "cwd": str(proj), "started_at_ms": 1000}]
            at_ms = 1100
            for idx in range(0, len(expected_public), 2):
                u_txt = expected_public[idx][1]
                a_txt = expected_public[idx + 1][1]
                cg_lines.extend([
                    {"t": at_ms, "k": "prompt", "p": [{"type": "text", "text": u_txt}]},
                    {"t": at_ms + 10, "k": "update", "p": {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": u_txt}}},
                    {"t": at_ms + 20, "k": "update", "p": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": a_txt}}},
                    {"t": at_ms + 30, "k": "turn_end", "p": {"stopReason": "end_turn"}},
                ])
                at_ms += 100
            cg_tx.write_bytes(_jsonl(cg_lines))

            # Wire all 3 sources into AgentHistoryService and read every page with limit=1
            projects_cfg = base / "projects.json"
            projects_cfg.write_text(json.dumps({"projects": [{"id": "demo", "name": "Demo", "root": str(proj)}]}), encoding="utf-8")
            os.chmod(projects_cfg, 0o600)
            ah_cfg = base / "agent-history.json"
            ah_cfg.write_text(json.dumps({
                "version": 1,
                "sources": {
                    "antigravity": {
                        "adapter": "antigravity", "root": str(ag_root), "format": "2.32.1",
                        "enabled": True, "inherit_projects": False, "actors": {"local": ["demo"]},
                        "threads": {ag_cid: "demo"}, "denied_threads": [],
                    },
                    "deepseek": {
                        "adapter": "deepseek_harness", "root": str(ds_root), "format": "0.2.2-rc.3",
                        "enabled": True, "inherit_projects": True, "actors": {"local": ["demo"]},
                        "threads": {}, "denied_threads": [],
                    },
                    "codeg": {
                        "adapter": "codeg", "root": str(cg_root), "format": "0.45.0",
                        "enabled": True, "inherit_projects": True, "actors": {"local": ["demo"]},
                        "threads": {}, "denied_threads": [],
                    },
                }
            }), encoding="utf-8")
            os.chmod(ah_cfg, 0o600)

            catalog = Catalog.from_config(projects_cfg)
            policy = AgentPolicy(ah_cfg)
            scratch = base / "scratch"
            scratch.mkdir(mode=0o700)
            policy.scratch = scratch
            catalog.set_agent_history_policy(policy)
            legacy = HistoryAccess(catalog=catalog)
            svc = AgentHistoryService(policy, legacy, local=True)
            self.addCleanup(svc.close)

            for source_id in ("antigravity", "deepseek", "codeg"):
                found = svc.find_agent_threads(project_id="demo", source_id=source_id, query="", limit=10)
                while found.get("status") == "processing":
                    found = svc.find_agent_threads(project_id="demo", source_id=source_id, query="", cursor=found["next_cursor"], limit=10)
                self.assertEqual(len(found["threads"]), 1, source_id)
                tref = found["threads"][0]["thread_ref"]
                entries, cur, pages = [], "", 0
                while True:
                    pages += 1
                    pg = svc.read_agent_thread(tref, cursor=cur, view="all", limit=1)
                    entries.extend(pg["entries"])
                    if not pg["has_more"]:
                        break
                    cur = pg["next_cursor"]
                got_pairs = [(e["role"], e["text"]) for e in entries]
                self.assertEqual(pages, 6, source_id)
                self.assertEqual(got_pairs, expected_public, f"{source_id} mismatch")
                self.assertEqual(_sha_pairs(got_pairs), expected_sha, source_id)

    def test_genuine_internal_tags_and_secret_redactions_stay_active(self):
        san, count = sanitize("Prefix <environment_context>secret env</environment_context> sk-1234567890abcdefXYZ")
        self.assertEqual(san, "Prefix [OMITTED: internal context] [REDACTED CREDENTIAL]")
        self.assertGreaterEqual(count, 2)
        safe = _safe_text("Path /Users/demo/project/file.py and <permissions_instructions>internal</permissions_instructions>")
        self.assertIn("[REDACTED LOCAL PATH]", safe)
        self.assertIn("[OMITTED: internal context]", safe)


if __name__ == "__main__":
    unittest.main()
