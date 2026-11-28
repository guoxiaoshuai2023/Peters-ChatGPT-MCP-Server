"""V2 project grants at the CLI's real stdin/stdout pipes."""

import asyncio
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest

from mcp import StdioServerParameters
from mcp.client import Client

from tests.test_project_capability_gate import _ScopeFixture
from tests.test_workspaces import fixture_git, fixture_registered_worktree


class _PipeClient:
    def start_pipe(self, policy):
        self.audit = self.project.parent / "audit.jsonl"
        self.read_fd, self.write_fd = os.pipe()
        self.addCleanup(os.close, self.read_fd)
        self.addCleanup(os.close, self.write_fd)
        self.proc = subprocess.Popen(
            [sys.executable, "-B", "-m", "peters_mcp", "--transport", "stdio",
             "--history-policy-mode", "v2", "--agent-history-config", str(policy.path),
             "--audit-log", str(self.audit)], cwd=Path(__file__).resolve().parent.parent,
            stdin=subprocess.PIPE, stdout=self.write_fd, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_child)
        os.set_blocking(self.write_fd, False)
        self.buffer = bytearray()
        self.send("initialize", {"protocolVersion": "2025-11-25", "clientInfo": {
            "name": "pipe-test", "version": "1"}, "capabilities": {}}, 1)
        self.assertIn("serverInfo", self.reply()["result"])
        self.send("notifications/initialized", {})

    def stop_child(self):
        self.proc.stdin.close()
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc.stderr.close()

    def send(self, method, params, identifier=None):
        packet = {"jsonrpc": "2.0", "method": method, "params": params}
        if identifier is not None:
            packet["id"] = identifier
        self.proc.stdin.write((json.dumps(packet) + "\n").encode())
        self.proc.stdin.flush()

    def call(self, name, arguments, identifier):
        self.send("tools/call", {"name": name, "arguments": arguments}, identifier)

    def read_some(self, deadline, count=65536):
        ready, _, _ = select.select([self.read_fd], [], [], max(0, deadline - time.monotonic()))
        self.assertTrue(ready, "timed out waiting for MCP stdout; exit=%r" % self.proc.poll())
        return os.read(self.read_fd, count)

    def reply(self):
        deadline = time.monotonic() + 12
        while b"\n" not in self.buffer:
            self.buffer.extend(self.read_some(deadline))
        line, _, tail = self.buffer.partition(b"\n")
        self.buffer = tail
        return json.loads(line)

    def fill_pipe(self):
        total = 0
        for size in (65536, 1):
            while True:
                try:
                    total += os.write(self.write_fd, b"~" * size)
                except BlockingIOError:
                    break
        self.assertGreater(total, 0)
        return total

    def drain_padding(self, count):
        deadline = time.monotonic() + 3
        while count:
            chunk = self.read_some(deadline, min(65536, count))
            self.assertEqual(chunk, b"~" * len(chunk))
            count -= len(chunk)

    def wait_prepared(self, names, *, after=0):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = [json.loads(line) for line in self.audit.read_bytes()[after:].splitlines()]
            if names.issubset({row.get("tool") for row in rows if row.get("ok")}):
                return rows
            time.sleep(0.01)
        self.fail("the requested tools did not finish preparation")


class StdioDeliveryTests(_PipeClient, _ScopeFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.start_pipe(self.policy)

    def test_a_queued_read_is_refused_after_revocation_and_the_connection_can_retry(self):
        (self.project / "note.txt").write_text("original project body — 中文")
        count = self.fill_pipe()
        self.call("read_file", {"project_id": "demo", "path": "note.txt"}, "revoked")
        self.wait_prepared({"read_file"})
        self.revoke()
        self.drain_padding(count)
        denied = self.reply()
        self.assertEqual(denied["id"], "revoked")
        self.assertIn("restart_required", denied["error"]["message"])
        self.assertNotIn("original project body", str(denied))
        self.change(self.document["projects"])
        self.call("read_file", {"project_id": "demo", "path": "note.txt"}, 3)
        self.assertIn("original project body", str(self.reply()["result"]))

    def test_concurrent_project_read_and_all_projects_keep_separate_scopes(self):
        (self.project / "note.txt").write_text("unaffected read")
        count = self.fill_pipe()
        self.call("read_file", {"project_id": "demo", "path": "note.txt"}, "read")
        self.call("list_projects", {}, "list")
        self.wait_prepared({"list_projects", "read_file"})
        self.change([*self.document["projects"], {"id": "other", "name": "Other", "root": str(self.other)}])
        self.drain_padding(count)
        replies = {item["id"]: item for item in (self.reply(), self.reply())}
        self.assertIn("unaffected read", str(replies["read"]["result"]))
        self.assertIn("restart_required", replies["list"]["error"]["message"])

    def test_git_recognition_change_while_waiting_for_stdout_requires_new_read(self):
        row = fixture_registered_worktree(self.other, self.project.parent / "linked-side")
        self.change([*self.document["projects"], row])
        (self.other / "note.txt").write_text("SYNTHETIC_GIT_CONTENT")
        count = self.fill_pipe()
        self.call("read_file", {"project_id": "other", "path": "note.txt"}, "before")
        self.wait_prepared({"read_file"})
        fixture_git(self.other, "config", "core.bare", "true")
        self.drain_padding(count)
        denied = self.reply()
        self.assertEqual(denied["id"], "before")
        self.assertIn("restart_required", denied["error"]["message"])
        self.assertNotIn("SYNTHETIC_GIT_CONTENT", str(denied))
        fixture_git(self.other, "config", "core.bare", "false")
        self.call("read_file", {"project_id": "other", "path": "note.txt"}, "after")
        self.assertIn("SYNTHETIC_GIT_CONTENT", str(self.reply()["result"]))

    def test_revoking_after_a_partial_frame_closes_the_connection(self):
        (self.project / "long.txt").write_text("读" * 39990 + "LAST-BYTE")
        self.call("read_file", {"project_id": "demo", "path": "long.txt", "limit": 40000}, 2)
        first = self.read_some(time.monotonic() + 5, 80)
        self.assertTrue(first)
        self.assertNotIn(b"\n", first)
        self.revoke()
        chunks = [first]
        deadline = time.monotonic() + 8
        while self.proc.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            ready, _, _ = select.select([self.read_fd], [], [], 0.05)
            if ready:
                chunks.append(os.read(self.read_fd, 65536))
        os.set_blocking(self.read_fd, False)
        while True:
            try:
                chunks.append(os.read(self.read_fd, 65536))
            except BlockingIOError:
                break
        self.assertNotIn(b"\n", b"".join(chunks))
        self.assertNotIn(b"LAST-BYTE", b"".join(chunks))

    def test_a_nonreading_peer_cannot_hold_the_connection_or_revocation_indefinitely(self):
        (self.project / "note.txt").write_text("blocked read")
        padding = self.fill_pipe()
        self.call("read_file", {"project_id": "demo", "path": "note.txt"}, 4)
        self.wait_prepared({"read_file"})
        self.revoke()
        self.proc.wait(timeout=8)  # stdin is still open
        self.drain_padding(padding)
        self.assertFalse(select.select([self.read_fd], [], [], 0)[0])


class StdioSDKTests(_ScopeFixture, unittest.TestCase):
    def test_current_sdk_client_uses_the_same_v2_stdio_server(self):
        (self.project / "note.txt").write_text("SDK real-file content")
        params = StdioServerParameters(command=sys.executable, cwd=str(Path(__file__).resolve().parent.parent),
            args=["-B", "-m", "peters_mcp", "--history-policy-mode", "v2", "--agent-history-config",
                  str(self.policy.path), "--audit-log", str(self.project.parent / "client.audit")])

        async def run():
            async with Client(params) as client:
                result = await client.call_tool("read_file", {"project_id": "demo", "path": "note.txt"})
                self.assertFalse(result.is_error)
                self.assertIn("SDK real-file content", result.content[0].text)
        asyncio.run(run())


class MigratedStdioTests(_PipeClient, _ScopeFixture, unittest.TestCase):
    def test_old_root_reuse_with_native_body_queued_on_real_pipe(self):
        from tests.test_unified_history_delivery import migrated_desktop
        policy, old = migrated_desktop(self, self.project.parent / 'migration')
        self.start_pipe(policy)
        params = {'source_id': 'desktop', 'project_id': 'moved'}
        for attempt in range(12):
            self.call('find_agent_threads', params, 'find')
            data = json.loads(self.reply()['result']['content'][0]['text'])
            if data['status'] == 'ready':
                break
            params['cursor'] = data['next_cursor']
        self.assertEqual(len(data['threads']), 1)
        args = {'thread_ref': data['threads'][0]['thread_ref']}
        for _ in range(12):
            after = self.audit.stat().st_size
            count = self.fill_pipe()
            self.call('read_agent_thread', args, 'queued')
            rows = self.wait_prepared({'read_agent_thread'}, after=after)
            if any(row.get('tool') == 'read_agent_thread' and row.get('status') == 'ready' for row in rows):
                break
            self.drain_padding(count)
            interim = json.loads(self.reply()['result']['content'][0]['text'])
            args['cursor'] = interim['next_cursor']
        else:
            self.fail('native migration read did not reach a prepared page')
        old.mkdir()
        self.drain_padding(count)
        denied = self.reply()
        self.assertEqual(denied['id'], 'queued')
        self.assertIn('restart_required', denied['error']['message'])
        self.assertNotIn('Visible Gemini answer', str(denied))
        self.call('read_file', {'project_id': 'moved', 'path': 'visible.txt'}, 'other')
        self.assertIn('ordinary current project file', str(self.reply()['result']))
