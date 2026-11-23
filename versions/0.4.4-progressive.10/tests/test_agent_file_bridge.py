from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx2

from peters_mcp import agent_file_bridge as bridge


UPSTREAM = "https://agent-test.example.test/mcp"
CLIENT_ID = "ca" * 16 + ".access"
SECRET = "test-fixture-only-" + "x" * 34
VERSION = "2025-11-25"


def json_stream(payload, **headers):
    return httpx2.Response(
        200, headers={"Content-Type": "application/json", **headers},
        stream=httpx2.ByteStream(json.dumps(payload).encode()),
    )


class CredentialBindingTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)
        self.path = self.directory / "credentials.json"
        self.write()

    def write(self, **overrides):
        fields = dict(upstream=UPSTREAM, client_id=CLIENT_ID, client_secret=SECRET)
        fields.update(overrides)
        self.path.write_text(json.dumps(fields), encoding="utf-8")
        self.path.chmod(0o600)

    def test_private_bound_record_reads_without_secret_repr(self):
        record = bridge._read_credentials(self.path, os.getuid())
        self.assertEqual(record.upstream, UPSTREAM)
        self.assertNotIn(SECRET, repr(record))
        self.assertNotIn(CLIENT_ID, repr(record))

    def test_rejects_wrong_uid_directory_or_file_mode(self):
        with self.assertRaises(ValueError):
            bridge._read_credentials(self.path, os.getuid() + 1)
        self.path.chmod(0o640)
        with self.assertRaises(ValueError):
            bridge._read_credentials(self.path, os.getuid())
        self.path.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaises(ValueError):
            bridge._read_credentials(self.path, os.getuid())

    def test_rejects_links_and_paths_inside_the_workspace(self):
        linked_file = self.path.with_name("alias")
        linked_file.symlink_to(self.path)
        with self.assertRaises(OSError):
            bridge._read_credentials(linked_file, os.getuid())
        linked_dir = self.directory / "sub"
        linked_dir.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError):
            bridge._read_credentials(linked_dir / self.path.name, os.getuid())
        linked_file.unlink()
        os.link(self.path, linked_file)
        with self.assertRaises(ValueError):
            bridge._read_credentials(self.path, os.getuid())
        linked_file.unlink()
        with patch.object(bridge.Path, "cwd", return_value=self.directory):
            with self.assertRaises(ValueError):
                bridge._read_credentials(self.path, os.getuid())

    def test_altered_or_unbound_url_cannot_receive_credentials(self):
        for bad in (
            "http://agent-test.example.test/mcp",
            "https://agent-test.example.test/somewhere",
            UPSTREAM + "?query=true",
            UPSTREAM + "#fragment",
            "https://username@agent-test.example.test/mcp",
            "https://agent-test.example.test:443/mcp",
        ):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                self.write(upstream=bad)
                bridge._read_credentials(self.path, os.getuid())
        self.write(client_secret=SECRET + "\r\n")
        with self.assertRaises(ValueError):
            bridge._read_credentials(self.path, os.getuid())

    def test_launcher_uses_isolated_imports_and_reports_safe_errors(self):
        script = Path(bridge.__file__).resolve()
        fake_dependency = self.directory / "httpx2.py"
        fake_dependency.write_text("raise RuntimeError('unexpected dependency loaded')", encoding="utf-8")
        command = [sys.executable, "-I", "-B", str(script)]
        base = {**os.environ, "PYTHONPATH": str(self.directory)}
        result = subprocess.run([*command, "--help"], capture_output=True, env=base, cwd=self.directory, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"--credential-file", result.stdout)
        result = subprocess.run([*command, "--bad-argument", SECRET], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        result = subprocess.run([sys.executable, "-B", str(script), "--help"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"(-I)", result.stderr)


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.relay = bridge._Relay(bridge._Credentials(UPSTREAM, CLIENT_ID, SECRET))
        self.requests = []
        self.new_client = httpx2.Client

    def proxy(self, handler):
        def factory(**options):
            self.assertFalse(options["follow_redirects"])
            self.assertFalse(options["trust_env"])
            return self.new_client(transport=httpx2.MockTransport(handler), **options)
        return patch.object(bridge.httpx2, "Client", side_effect=factory)

    def call(self, method, request_id=1):
        request = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            request["id"] = request_id
        return self.relay.forward(request, json.dumps(request).encode())

    def test_initialize_notification_and_tools_use_bound_host_and_version(self):
        def handler(request):
            self.requests.append(request)
            self.assertEqual(str(request.url), UPSTREAM)
            self.assertEqual(request.headers["CF-Access-Client-Id"], CLIENT_ID)
            self.assertEqual(request.headers["CF-Access-Client-Secret"], SECRET)
            self.assertNotIn("cookie", request.headers)
            message = json.loads(request.content)
            if message["method"] == "initialize":
                self.assertNotIn("mcp-protocol-version", request.headers)
                return json_stream(
                    {"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": VERSION}},
                    **{"Set-Cookie": "untrusted=ignored; Secure"},
                )
            self.assertEqual(request.headers["mcp-protocol-version"], VERSION)
            if "id" not in message:
                return httpx2.Response(202)
            return json_stream({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}})

        with self.proxy(handler):
            self.assertEqual(self.call("initialize")["result"]["protocolVersion"], VERSION)
            self.assertIsNone(self.call("notifications/initialized", None))
            self.assertEqual(self.call("tools/list", "request")["result"], {"tools": []})
        self.assertEqual(len(self.requests), 3)

    def test_modern_discover_and_tools_use_per_request_metadata_without_initialize(self):
        def handler(request):
            self.requests.append(request)
            message = json.loads(request.content)
            self.assertEqual(request.headers["mcp-protocol-version"], "2026-07-28")
            self.assertEqual(request.headers["mcp-method"], message["method"])
            if message["method"] == "tools/call":
                self.assertEqual(request.headers["mcp-name"], "list_projects")
            else:
                self.assertNotIn("mcp-name", request.headers)
            return json_stream({"jsonrpc": "2.0", "id": message["id"], "result": {}})

        with self.proxy(handler):
            for method, arguments in (("server/discover", {}), ("tools/call", {"name": "list_projects"})):
                message = {"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": {**arguments, "_meta": {bridge._MODERN_VERSION_KEY: "2026-07-28"}}}
                self.assertEqual(self.relay.forward(message, json.dumps(message).encode())["result"], {})
        self.assertEqual(len(self.requests), 2)
        self.assertIsNone(self.relay.protocol_version)

    def test_modern_rejects_invalid_header_value_before_exchange(self):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "show\r\ntext", "_meta": {bridge._MODERN_VERSION_KEY: "2026-07-28"}}}
        with patch.object(bridge.httpx2, "Client") as remote, self.assertRaises(bridge._BridgeError):
            self.relay.forward(message, json.dumps(message).encode())
        remote.assert_not_called()

    def test_no_redirects_including_same_origin_and_no_credential_echo(self):
        locations = ["http://agent-test.example.test/mcp", UPSTREAM + "/other", "https://elsewhere.example.test/mcp"]
        for location in locations:
            with self.subTest(location=location):
                requests = []

                def handler(request):
                    requests.append(request)
                    return httpx2.Response(307, headers={"Location": location})

                with self.proxy(handler), self.assertRaises(bridge._BridgeError) as caught:
                    self.call("initialize")
                self.assertNotIn(location, str(caught.exception))
                self.assertEqual([str(req.url) for req in requests], [UPSTREAM])

        def leaking(_):
            return json_stream({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": SECRET}})

        with self.proxy(leaking), self.assertRaises(bridge._BridgeError) as caught:
            self.call("initialize")
        self.assertNotIn(SECRET, str(caught.exception))

    def test_auth_errors_serve_only_generic_ndjson(self):
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        lines = [request, {**request, "id": SECRET}]
        source = BytesIO(b"".join(json.dumps(message).encode() + b"\n" for message in lines))
        output = BytesIO()
        with self.proxy(lambda _: httpx2.Response(401, text=SECRET)):
            bridge._serve(source, output, self.relay)
        raw = output.getvalue()
        self.assertNotIn(SECRET.encode(), raw)
        failures = list(map(json.loads, raw.splitlines()))
        self.assertEqual([failure["id"] for failure in failures], [1, None])
        self.assertEqual([failure["error"]["code"] for failure in failures], [-32001, -32600])

    def test_rejects_streams_and_upstream_sessions(self):
        for response in (
            httpx2.Response(200, headers={"Content-Type": "text/event-stream"}),
            json_stream({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": VERSION}},
                        **{"MCP-Session-Id": "not-allowed"}),
        ):
            with self.proxy(lambda _: response), self.assertRaises(bridge._BridgeError):
                self.call("initialize")
        self.assertIsNone(self.relay.protocol_version)
