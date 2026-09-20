from hashlib import sha256
import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import sys
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.history import HistoryAccess
from peters_mcp.history_projection import project_rollout, project_tool, sanitize

FIRST = "11111111-1111-4111-8111-111111111111"
SECOND = "22222222-2222-4222-8222-222222222222"
DENIED = "33333333-3333-4333-8333-333333333333"


def record(kind, payload):
    return {"timestamp": "2026-09-20T00:00:00Z", "type": kind, "payload": payload}


def message(text, role="user", phase=None, native_id="user-1", **more):
    return record("response_item", {"type": "message", "role": role, "phase": phase,
                                    "id": native_id, "content": [{"type": "input_text", "text": text}], **more})


def encode(records):
    return b"".join((json.dumps(r, ensure_ascii=False) + "\n").encode() for r in records)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "codex"
        (self.home / "sessions").mkdir(parents=True)
        self.database = self.home / "state_5.sqlite"
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, title TEXT, name TEXT, updated_at INTEGER, archived INTEGER, history_mode TEXT)")
        self.config = Path(self.temp.name) / "history.json"
        self.records = [
            record("session_meta", {"id": FIRST, "cwd": "/worktree/one", "cli_version": "test", "history_mode": "paginated", "base_instructions": "HIDDEN_BASE"}),
            record("event_msg", {"type": "task_started", "turn_id": "turn-1"}),
            message("HIDDEN_DEVELOPER", "developer"),
            message("<environment_context>HIDDEN_RUNTIME</environment_context>"),
            message("需求：分批读取文档。", native_id="user-public"),
            record("event_msg", {"type": "item_completed", "turn_id": "turn-1", "item": {
                "type": "UserMessage", "id": "user-public", "content": [{"type": "text", "text": "需求：分批读取文档。"}]}}),
            record("response_item", {"type": "reasoning", "summary": "HIDDEN_REASONING", "encrypted_content": "HIDDEN_ENCRYPTED"}),
            message("公开进度", "assistant", "commentary", native_id="progress"),
            message("HIDDEN_ANALYSIS", "assistant", "analysis"),
            message("HIDDEN_CHANNEL", "assistant", "commentary", channel="analysis"),
            record("event_msg", {"type": "item_completed", "turn_id": "turn-1", "item": {
                "type": "CommandExecution", "id": "command-one", "command": "python -m tests", "status": "completed",
                "exit_code": 0, "stdout": "PASSED\napi_key=TOPSECRET\n", "stderr": "", "env": {"PRIVATE": "HIDDEN_ENV"}}}),
            message("最终结论：完成验证。", "assistant", "final_answer", native_id="final"),
            record("event_msg", {"type": "item_completed", "turn_id": "turn-1", "item": {
                "type": "AgentMessage", "id": "final", "phase": "final_answer", "content": [{"type": "Text", "text": "最终结论：完成验证。"}]}}),
            record("event_msg", {"type": "task_complete", "turn_id": "turn-1"}),
        ]
        self.path = self.add_thread(FIRST, self.records)
        self.second = self.add_thread(SECOND, [record("session_meta", {"id": SECOND, "cwd": "/repo/shared"}), message("第二个任务")])
        self.add_thread(DENIED, [record("session_meta", {"id": DENIED}), message("UNAUTHORIZED_BODY")])
        self.grants = [{"id": FIRST, "label": "研究", "project_id": "project", "allow_tool_results": False},
                       {"id": SECOND, "label": "第二个", "project_id": None, "allow_tool_results": False}]
        self.save_config()
        self.history = HistoryAccess(self.config, ("project",))

    def save_config(self):
        self.config.write_text(json.dumps({"version": 1, "codex_home": str(self.home),
                                          "state_db": "state_5.sqlite", "threads": self.grants}))

    def add_thread(self, tid, records):
        path = self.home / "sessions" / ("rollout-test-" + tid + ".jsonl")
        path.write_bytes(encode(records))
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)", (tid, str(path), "/repo/shared", "old title", "同名任务", 100, 0, "paginated"))
        return path

    def tool_enabled(self):
        self.grants[0]["allow_tool_results"] = True
        self.save_config()

    def test_find_same_titles_unique_ids_and_no_cwd_inferred_access(self):
        result = self.history.find_codex_threads("同名任务")
        self.assertEqual({r["thread_id"] for r in result["threads"]}, {FIRST, SECOND})
        self.assertTrue(all(r["title"] == "同名任务" for r in result["threads"]))
        self.assertNotIn(DENIED, json.dumps(result))
        filtered = self.history.find_codex_threads(project_id="project")
        self.assertEqual([r["thread_id"] for r in filtered["threads"]], [FIRST])
        self.assertEqual(filtered["threads"][0]["project_association_source"], "explicit_configuration")

    def test_public_content_search_uses_redacted_messages(self):
        result = self.history.find_codex_threads("最终结论")
        self.assertEqual([r["thread_id"] for r in result["threads"]], [FIRST])
        self.assertEqual(result["threads"][0]["match"]["in"], "public_message")
        self.assertEqual(self.history.find_codex_threads("HIDDEN_DEVELOPER")["threads"], [])

    def test_find_cursor_is_bound_to_query_filter_and_scope(self):
        first = self.history.find_codex_threads(limit=1)
        second = self.history.find_codex_threads(limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["threads"][0]["thread_id"], second["threads"][0]["thread_id"])
        self.assertFalse(second["has_more"])
        with self.assertRaises(AccessError):
            self.history.find_codex_threads(query="different", limit=1, cursor=first["next_cursor"])
        self.grants.pop()
        self.save_config()
        with self.assertRaises(AccessError):
            self.history.find_codex_threads(limit=1, cursor=first["next_cursor"])

    def test_message_pages_are_original_order_without_mirrored_duplicates(self):
        texts, ids, cursor = [], [], ""
        while True:
            page = self.history.read_codex_thread(FIRST, cursor=cursor, limit=1)
            texts.extend(e["text"] for e in page["entries"])
            ids.extend(e["message_id"] for e in page["entries"])
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        self.assertEqual(texts, ["需求：分批读取文档。", "公开进度", "最终结论：完成验证。"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(page["mirrored_messages_deduplicated"], 2)
        self.assertIsNone(page["is_running"])
        self.assertEqual(page["last_recorded_status"], "recorded_complete")

    def test_real_repeated_messages_are_preserved(self):
        rows = [record("session_meta", {"id": FIRST}), message("same", native_id="a"), message("same", native_id="b")]
        self.path.write_bytes(encode(rows))
        page = self.history.read_codex_thread(FIRST)
        self.assertEqual([m["text"] for m in page["entries"]], ["same", "same"])

    def test_long_message_is_fragmented_without_loss(self):
        text = "中文" * 255
        self.path.write_bytes(encode([record("session_meta", {"id": FIRST}), message(text)]))
        parts, cursor = [], ""
        while True:
            page = self.history.read_codex_thread(FIRST, cursor=cursor, max_chars=100)
            parts.extend(e["text"] for e in page["entries"])
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        self.assertEqual("".join(parts), text)

    def test_appends_do_not_change_existing_snapshot_pages(self):
        page = self.history.read_codex_thread(FIRST, limit=1)
        with self.path.open("ab") as stream:
            stream.write(encode([message("added later", native_id="later")]))
        rest, cursor = [], page["next_cursor"]
        while cursor:
            current = self.history.read_codex_thread(FIRST, limit=1, cursor=cursor)
            self.assertTrue(current["appended_since_snapshot"])
            rest += [m["text"] for m in current["entries"]]
            cursor = current["next_cursor"]
        self.assertNotIn("added later", rest)
        latest = self.history.read_codex_thread(FIRST)
        self.assertIn("added later", [m["text"] for m in latest["entries"]])

    def test_source_rewrite_and_missing_record_fail_explicitly(self):
        page = self.history.read_codex_thread(FIRST, limit=1)
        self.path.write_bytes(self.path.read_bytes().replace(b'python', b'PYTHON'))
        with self.assertRaisesRegex(AccessError, "changed"):
            self.history.read_codex_thread(FIRST, limit=1, cursor=page["next_cursor"])
        self.path.unlink()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_incomplete_tail_malformed_and_unknown_records_are_reported(self):
        with self.path.open("ab") as stream:
            stream.write(b'{bad json}\n')
            stream.write(encode([record("future_unknown", {"secret": "HIDDEN_FUTURE"})]))
            stream.write(b'{"type":')
        page = self.history.read_codex_thread(FIRST)
        self.assertFalse(page["complete_public_projection"])
        self.assertEqual(page["warnings"]["malformed_record_excluded"], 1)
        self.assertEqual(page["warnings"]["incomplete_tail_excluded"], 1)
        self.assertEqual(page["warnings"]["unknown_record_type_excluded"], 1)
        self.assertNotIn("HIDDEN_FUTURE", json.dumps(page))

    def test_unauthorized_cross_thread_and_forged_cursors_refused(self):
        page = self.history.read_codex_thread(FIRST, limit=1)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(DENIED)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(SECOND, limit=1, cursor=page["next_cursor"])
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, limit=1, cursor=page["next_cursor"][:-1] + "z")

    def test_tool_results_disabled_by_default(self):
        page = self.history.read_codex_thread(FIRST)
        self.assertFalse(any(e["kind"] == "tool_reference" for e in page["entries"]))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST, include_tool_refs=True)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread_item(FIRST, "guessed")

    def test_tool_item_whitelist_redaction_and_forgery_protection(self):
        self.tool_enabled()
        page = self.history.read_codex_thread(FIRST, include_tool_refs=True)
        ref = next(e for e in page["entries"] if e["kind"] == "tool_reference")
        result = self.history.read_codex_thread_item(FIRST, ref["item_id"])
        self.assertIn("PASSED", result["text"])
        self.assertNotIn("TOPSECRET", result["text"])
        self.assertNotIn("HIDDEN_ENV", result["text"])
        self.assertGreater(result["redactions"], 0)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread_item(FIRST, ref["item_id"][:-2] + "xx")
        self.grants[1]["allow_tool_results"] = True
        self.save_config()
        with self.assertRaises(AccessError):
            self.history.read_codex_thread_item(SECOND, ref["item_id"])

    def test_no_private_reasoning_instruction_or_credentials_export(self):
        self.path.write_bytes(encode(self.records + [message('password="MYSECRET"\nBearer abcdefghijk\nsk-test1234567890123456', native_id="secret")]))
        page = self.history.read_codex_thread(FIRST)
        result = json.dumps(page)
        for value in ("HIDDEN_BASE", "HIDDEN_DEVELOPER", "HIDDEN_RUNTIME", "HIDDEN_REASONING", "HIDDEN_ENCRYPTED", "HIDDEN_ANALYSIS", "HIDDEN_CHANNEL", "MYSECRET", "abcdefghijk", "sk-test1234567890123456"):
            self.assertNotIn(value, result)

    def test_reading_does_not_write_database_or_start_process(self):
        before = {p: sha256(p.read_bytes()).hexdigest() for p in (self.database, self.path, self.config)}
        with patch("subprocess.Popen", side_effect=AssertionError("No process may be started")):
            self.history.find_codex_threads("最终")
            self.history.read_codex_thread(FIRST)
        self.assertEqual(before, {p: sha256(p.read_bytes()).hexdigest() for p in before})

    def test_archived_thread_and_projectless_metadata(self):
        archive = self.home / "archived_sessions"
        archive.mkdir()
        destination = archive / self.second.name
        self.second.rename(destination)
        with sqlite3.connect(self.database) as db:
            db.execute("UPDATE threads SET rollout_path=?, archived=1, cwd=? WHERE id=?", (str(destination), "/scratch/no-project", SECOND))
        page = self.history.read_codex_thread(SECOND)
        self.assertTrue(page["thread"]["archived"])
        self.assertIsNone(page["thread"]["project_id"])
        self.assertEqual(page["thread"]["cwd"], "/scratch/no-project")

    def test_corrupt_index_identity_and_symlink_rejected(self):
        self.path.write_bytes(encode([record("session_meta", {"id": DENIED}), message("wrong")]))
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)
        self.path.unlink()
        self.path.symlink_to(self.second)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread(FIRST)

    def test_empty_allowlist_does_not_scan_any_history(self):
        self.grants = []
        self.save_config()
        with patch("peters_mcp.history.sqlite3.connect", side_effect=AssertionError("must not query")):
            result = self.history.find_codex_threads()
        self.assertEqual(result["scope_count"], 0)
        self.assertEqual(result["threads"], [])

    def test_incompatible_metadata_is_not_reported_as_empty(self):
        with sqlite3.connect(self.database) as db:
            db.execute("DROP TABLE threads")
        with self.assertRaisesRegex(AccessError, "not proven empty"):
            self.history.find_codex_threads()

    def test_tool_output_sanitizer_omits_internal_dump(self):
        text, count = sanitize('{"role":"system","content":"HIDDEN_RULE"}', tool=True)
        self.assertNotIn("HIDDEN_RULE", text)
        self.assertEqual(count, 1)

    def test_real_stdio_query_and_pagination(self):
        from mcp import StdioServerParameters
        from mcp.client import Client
        project_config = Path(self.temp.name) / "projects.json"
        project_config.write_text(json.dumps({"projects": [{"id": "project", "name": "Synthetic",
                                                           "root": str(self.home)}]}))
        async def run():
            params = StdioServerParameters(command=sys.executable,
                cwd=str(Path(__file__).resolve().parent.parent), args=["-m", "peters_mcp",
                "--config", str(project_config), "--history-config", str(self.config),
                "--audit-log", str(Path(self.temp.name) / "audit.jsonl")])
            async with Client(params) as client:
                tools = await client.list_tools()
                self.assertEqual(len(tools.tools), 10)
                result = await client.call_tool("find_codex_threads", {"query": "最终结论"})
                self.assertFalse(result.is_error)
                data = json.loads(result.content[0].text)
                self.assertEqual(data["threads"][0]["thread_id"], FIRST)
                result = await client.call_tool("read_codex_thread", {"thread_id": FIRST, "limit": 1})
                self.assertFalse(result.is_error)
                first = json.loads(result.content[0].text)
                self.assertEqual(first["entries"][0]["text"], "需求：分批读取文档。")
                result = await client.call_tool("read_codex_thread", {"thread_id": FIRST, "limit": 1,
                                                                      "cursor": first["next_cursor"]})
                self.assertFalse(result.is_error)
                self.assertEqual(json.loads(result.content[0].text)["entries"][0]["text"], "公开进度")
                result = await client.call_tool("read_codex_thread", {"thread_id": DENIED})
                self.assertTrue(result.is_error)
        asyncio.run(run())

    def test_prefixed_environment_basic_and_cookie_secrets_are_removed(self):
        raw = 'OPENAI_API_KEY=ENVSECRET\nAWS_SECRET_ACCESS_KEY=AWSSECRET\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\nCookie: session=COOKIESECRET; csrftoken=SECONDSECRET\n'
        text, count = sanitize(raw)
        for secret in ('ENVSECRET', 'AWSSECRET', 'dXNlcjpwYXNzd29yZA==', 'COOKIESECRET', 'SECONDSECRET'):
            self.assertNotIn(secret, text)
        self.assertGreaterEqual(count, 4)
        result, _ = project_tool({'type': 'CommandExecution', '_item': {'command': 'printenv', 'stdout': raw}})
        self.assertIn('omitted', result)

    def test_nested_thread_tool_output_cannot_bypass_allowlist(self):
        item = {'type': 'McpToolCall', '_item': {'server': 'codex_app', 'tool': 'read_thread',
                'arguments': {'threadId': DENIED}, 'result': {'content': [{'type': 'text', 'text': 'UNAUTHORIZED_BODY'}]}}}
        for permitted in ([], ['codex_app/read_thread']):
            result, _ = project_tool(item, permitted)
            self.assertNotIn('UNAUTHORIZED_BODY', json.dumps(result))
            self.assertIn('omitted', result)

    def test_mcp_evidence_needs_exact_source_pair_and_excludes_metadata(self):
        item = {'type': 'McpToolCall', '_item': {'server': 'synthetic', 'tool': 'lookup',
                'arguments': {}, 'result': {'content': [{'type': 'text', 'text': 'known public result'}],
                                           '_meta': {'reasoning': 'HIDDEN_META'}}}}
        self.assertIn('omitted', project_tool(item)[0])
        result, _ = project_tool(item, ['synthetic/lookup'])
        self.assertEqual(result['text_result'], 'known public result')
        self.assertNotIn('HIDDEN_META', json.dumps(result))

    def test_unknown_event_phase_flags_incompleteness(self):
        data = [record('session_meta', {'id': FIRST}), record('event_msg', {'type': 'item_completed',
                'item': {'type': 'AgentMessage', 'id': 'x', 'phase': 'new_unknown_phase', 'content': 'HIDDEN_UNKNOWN'}})]
        projection = project_rollout(encode(data), FIRST)
        self.assertFalse(projection['complete_public_projection'])
        self.assertNotIn('HIDDEN_UNKNOWN', json.dumps(projection))

    def test_same_native_id_in_other_turn_or_conflicting_text_is_not_lost(self):
        data = [record('session_meta', {'id': FIRST}),
                record('event_msg', {'type': 'task_started', 'turn_id': 'turn-1'}), message('FIRST', native_id='reused'),
                record('event_msg', {'type': 'item_completed', 'turn_id': 'turn-2',
                    'item': {'type': 'UserMessage', 'id': 'reused', 'content': 'SECOND'}}),
                record('event_msg', {'type': 'item_completed', 'turn_id': 'turn-1',
                    'item': {'type': 'UserMessage', 'id': 'reused', 'content': 'CONFLICT'}})]
        projection = project_rollout(encode(data), FIRST)
        self.assertEqual([m['text'] for m in projection['messages']], ['FIRST', 'SECOND', 'CONFLICT'])
        self.assertFalse(projection['complete_public_projection'])

    def test_tool_pagination_caps_and_binds_item(self):
        self.tool_enabled()
        records = self.records + [record('event_msg', {'type':'item_completed','turn_id':'turn-1',
            'item': {'type':'CommandExecution','id':'big','command':'run-test','stdout':'X'*70000}})]
        self.path.write_bytes(encode(records))
        page = self.history.read_codex_thread(FIRST, include_tool_refs=True)
        refs = [e for e in page['entries'] if e['kind']=='tool_reference']
        first = self.history.read_codex_thread_item(FIRST, refs[-1]['item_id'], max_chars=100)
        self.assertTrue(first['truncated_by_policy'])
        self.assertEqual(len(first['text']), 100)
        second = self.history.read_codex_thread_item(FIRST, refs[-1]['item_id'], cursor=first['next_cursor'], max_chars=100)
        self.assertEqual(second['offset'], 100)
        with self.assertRaises(AccessError):
            self.history.read_codex_thread_item(FIRST, refs[0]['item_id'], cursor=first['next_cursor'], max_chars=100)

    def test_attachments_and_compaction_are_not_claimed_complete(self):
        data = [record('session_meta', {'id':FIRST}), record('response_item', {'type':'message','role':'user','content':[
            {'type':'input_text','text':'describe image'}, {'type':'input_image','image_url':'SECRET_ATTACHMENT'}]}),
            record('compacted', {'message':'PRIVATE_COMPACTION_SUMMARY'})]
        projection = project_rollout(encode(data), FIRST)
        self.assertEqual(projection['messages'][0]['omitted_attachments'], 1)
        self.assertFalse(projection['complete_public_projection'])
        self.assertNotIn('SECRET_ATTACHMENT', json.dumps(projection))
        self.assertNotIn('PRIVATE_COMPACTION_SUMMARY', json.dumps(projection))

    def test_all_internal_codex_sources_are_excluded_from_command_results(self):
        for command, cwd in [('sqlite3 ~/.codex/state_5.sqlite', '/tmp'), ('cat ~/.codex/history.jsonl', '/tmp'),
                             ('sed -n 1p ~/.codex/archived_sessions/rollout.jsonl', '/tmp'),
                             ('cat rollout.jsonl', '/Users/demo/.codex/sessions'),
                             ('codex app-server', '/tmp'), ('cat "$CODEX_HOME/sessions/x"', '/tmp')]:
            value, _ = project_tool({'type':'CommandExecution','_item':{'command':command,'cwd':cwd,'stdout':'OTHER_CONVERSATION'}})
            self.assertIn('omitted', value)
            self.assertNotIn('OTHER_CONVERSATION', json.dumps(value))

    def test_metadata_only_is_not_reported_as_complete_empty_history(self):
        projection = project_rollout(encode([record('session_meta', {'id':FIRST,'history_mode':'paginated'})]), FIRST)
        self.assertFalse(projection['complete_public_projection'])
        self.assertIn('no_public_messages_in_source_not_proven_empty', projection['warnings'])

    def test_unknown_content_block_is_reported_not_silently_complete(self):
        data = [record('session_meta', {'id':FIRST}), record('response_item', {'type':'message','role':'user','content':[
            {'type':'new_text_format','text':'unrecognized text'}]})]
        projection=project_rollout(encode(data), FIRST)
        self.assertFalse(projection['complete_public_projection'])
        self.assertIn('unknown_message_content_excluded',projection['warnings'])

    def test_async_and_other_thread_events_never_become_public_messages(self):
        data = [record('session_meta', {'id':FIRST}), message('public root message'),
                record('event_msg', {'type':'item_completed','thread_id':FIRST,'turn_id':'t1',
                    'item':{'type':'AgentMessage','id':'async','phase':'final_answer','delivery':'async',
                            'content':[{'type':'Text','text':'UNVERIFIED_ASYNC'}]}}),
                record('event_msg', {'type':'item_completed','thread_id':DENIED,'turn_id':'t2',
                    'item':{'type':'AgentMessage','id':'foreign','phase':'final_answer',
                            'content':[{'type':'Text','text':'OTHER_THREAD_REPLY'}]}}),
                record('event_msg', {'type':'item_completed','thread_id':DENIED,
                    'item':{'type':'CommandExecution','command':'test','stdout':'OTHER_THREAD_STDOUT'}})]
        projection=project_rollout(encode(data),FIRST)
        self.assertEqual([m['text'] for m in projection['messages']],['public root message'])
        self.assertFalse(projection['tools'])
        self.assertFalse(projection['complete_public_projection'])
        for marker in ['UNVERIFIED_ASYNC','OTHER_THREAD_REPLY','OTHER_THREAD_STDOUT']:
            self.assertNotIn(marker,json.dumps(projection))


if __name__ == "__main__":
    unittest.main()
