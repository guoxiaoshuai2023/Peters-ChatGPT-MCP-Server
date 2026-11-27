import asyncio
import io
import json
import logging
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mcp import StdioServerParameters
from mcp.client import Client

from peters_mcp.catalog import Catalog, Project
from peters_mcp.server import create_server


BASE = Path(__file__).resolve().parent.parent


def data(result):
    if result.is_error:
        raise AssertionError(result.content)
    return json.loads(result.content[0].text)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("中文\nneedle evidence\n", encoding="utf-8")
        self.config = self.root / "projects.json"
        self.config.write_text(json.dumps({"projects": [
            {"id": "demo", "name": "Demo", "root": str(self.repo)}
        ]}))
        self.history_config = self.root / "history.json"
        self.history_config.write_text(json.dumps({"version": 1, "codex_home": str(self.repo),
                                                   "state_db": "state_5.sqlite", "threads": []}))

    async def assert_tools(self, client):
        listing = await client.list_tools()
        self.assertEqual({t.name for t in listing.tools}, {"list_projects", "list_files", "search", "read_file",
                                                         "prepare_candidate", "save_candidate",
                                                         "find_codex_threads", "read_codex_thread", "read_codex_thread_item", "list_worktrees"})
        for tool in listing.tools:
            annotations = tool.annotations.model_dump(by_alias=True)
            self.assertEqual(annotations["readOnlyHint"], tool.name != "save_candidate")
            self.assertFalse(annotations["destructiveHint"])
        self.assertEqual(data(await client.call_tool("list_projects"))["projects"][0]["id"], "demo")
        files = data(await client.call_tool("list_files", {"project_id": "demo"}))
        self.assertEqual(files["entries"][0]["path"], "README.md")
        matches = data(await client.call_tool("search", {"project_id": "demo", "query": "needle"}))
        self.assertEqual(matches["matches"][0]["line"], 2)
        result = data(await client.call_tool("read_file", {"project_id": "demo", "path": "README.md"}))
        self.assertEqual(result["text"], "中文\nneedle evidence\n")
        denied = await client.call_tool("read_file", {"project_id": "demo", "path": "../outside.md"})
        self.assertTrue(denied.is_error)
        invalid = await client.call_tool("read_file", {"project_id": "demo", "path": "README.md", "limit": -1})
        self.assertTrue(invalid.is_error)

    def test_in_process_client_and_audit_redaction(self):
        stream = io.StringIO()
        logger = logging.Logger("test.audit")
        logger.addHandler(logging.StreamHandler(stream))
        server = create_server(Catalog([Project("demo", "Demo", self.repo)]), logger)

        async def run():
            async with Client(server) as client:
                await self.assert_tools(client)
        asyncio.run(run())
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(len(records), 6)
        self.assertEqual(sum(not r["ok"] for r in records), 2)
        self.assertNotIn("needle", stream.getvalue())
        self.assertNotIn("outside", stream.getvalue())
        self.assertNotIn("中文", stream.getvalue())

    def test_stdio_subprocess(self):
        async def run():
            params = StdioServerParameters(
                command=sys.executable, cwd=str(BASE), args=[
                    "-m", "peters_mcp", "--config", str(self.config),
                    "--history-config", str(self.history_config),
                    "--audit-log", str(self.root / "audit.jsonl"),
                ],
            )
            async with Client(params) as client:
                await self.assert_tools(client)
        asyncio.run(run())
        self.assertTrue((self.root / "audit.jsonl").is_file())

    def test_http_modern_legacy_and_origin_host_guards(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        proc = subprocess.Popen(
            [sys.executable, "-m", "peters_mcp", "--transport", "http", "--port", str(port),
             "--config", str(self.config), "--history-config", str(self.history_config),
             "--audit-log", str(self.root / "http-audit.jsonl")],
            cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop_process, proc)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.assertIsNone(proc.poll(), "HTTP subprocess exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("HTTP server did not become ready")
        url = f"http://127.0.0.1:{port}/mcp"

        async def run():
            async with Client(url) as client:
                await self.assert_tools(client)
        asyncio.run(run())

        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "legacy-test", "version": "1"},
        }}
        with urlopen(Request(url, data=json.dumps(initialize).encode(), headers=headers), timeout=5) as response:
            body = json.load(response)
            self.assertEqual(body["result"]["protocolVersion"], "2025-11-25")
        payload = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "read_file", "arguments": {"project_id": "demo", "path": "README.md"}
        }}).encode()
        headers["MCP-Protocol-Version"] = "2025-11-25"
        with urlopen(Request(url, data=payload, headers=headers), timeout=5) as response:
            body = json.load(response)
            self.assertIn("needle", body["result"]["content"][0]["text"])
        for additional in ({"Origin": "https://untrusted.example"}, {"Host": "untrusted.example"}):
            with self.subTest(headers=additional), self.assertRaises(HTTPError) as error:
                urlopen(Request(url, data=payload, headers={**headers, **additional}), timeout=5)
            self.assertIn(error.exception.code, (400, 403, 421))
            error.exception.close()

    @staticmethod
    def stop_process(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
