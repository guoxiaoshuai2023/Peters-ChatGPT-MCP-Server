"""Optional isolated-UID stdio bridge for the Agent file-only MCP endpoint."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit

if __name__ == "__main__" and not sys.flags.isolated:
    print("Run the Agent MCP bridge with an isolated Python interpreter (-I).", file=sys.stderr)
    raise SystemExit(2)

import httpx2

if __package__:
    from .agent_file_auth import _SERVICE_ID
else:
    # The absolute script is selected from a verified release by the operator.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from peters_mcp.agent_file_auth import _SERVICE_ID


_HOST = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_METHOD = re.compile(r"[A-Za-z0-9_./-]{1,128}")
_TOOL = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MODERN_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
_MODERN_FIRST_VERSION = "2026-07-28"
_SECRET_VALUE = re.compile(r"[\x21-\x7e]{32,256}")
_CREDENTIAL_BYTES = 4096
_REQUEST_BYTES = 262144
_RESPONSE_BYTES = 4 * 1024 * 1024
_REMOTE_TIMEOUT = httpx2.Timeout(10.0, connect=5.0, read=5.0)
_DOOR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@dataclass(frozen=True)
class _Credentials:
    upstream: str
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)


class _BridgeError(Exception):
    def __init__(self, code, public_message):
        super().__init__(public_message)
        self.code = code


class _BridgeArguments(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Invalid Agent MCP bridge options.\n")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def _not_json(_):
    raise ValueError("Invalid JSON constant.")


def _finite_json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Invalid JSON number.")
    return number


def _load_object(raw):
    result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_not_json, parse_float=_finite_json_float)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object.")
    return result


@contextmanager
def _open_directory(path):
    descriptor = os.open("/", _DOOR_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, _DOOR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def _stamp(info):
    return (info.st_mode, info.st_nlink, info.st_uid, info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _own_file(info, uid):
    return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == uid and info.st_nlink == 1 and 0 < info.st_size <= _CREDENTIAL_BYTES)


def _read_credentials(path, uid):
    path = Path(path)
    if (type(uid) is not int or uid != os.getuid() or uid != os.geteuid()
            or not path.is_absolute() or path.anchor != "/" or ".." in path.parts
            or path.is_relative_to(Path.cwd().resolve())):
        raise ValueError("The bridge requires its isolated UID and a private file outside the workspace.")
    with _open_directory(path.parent) as directory:
        folder = os.fstat(directory)
        if stat.S_IMODE(folder.st_mode) != 0o700 or folder.st_uid != uid:
            raise ValueError("The bridge requires a private credential directory.")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not _own_file(info, uid):
                raise ValueError("The bridge requires a private credential file.")
            raw = stream.read(_CREDENTIAL_BYTES + 1)
            latest = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (len(raw) != info.st_size
                    or _stamp(info) != _stamp(os.fstat(stream.fileno())) or _stamp(info) != _stamp(latest)):
                raise ValueError("The bridge credentials changed during verification.")
    stored = _load_object(raw)
    if set(stored) != {"upstream", "client_id", "client_secret"} or not all(isinstance(v, str) for v in stored.values()):
        raise ValueError("The bridge credential file is invalid.")
    url = urlsplit(stored["upstream"])
    if (not _HOST.fullmatch(url.netloc) or stored["upstream"] != f"https://{url.netloc}/mcp"
            or not _SERVICE_ID.fullmatch(stored["client_id"])
            or not _SECRET_VALUE.fullmatch(stored["client_secret"])):
        raise ValueError("The bridge credential file has an invalid destination or credential.")
    return _Credentials(**stored)


def _valid_id(value):
    return (type(value) is int or isinstance(value, str) and 0 < len(value) <= 256)


def _response_id(request):
    if isinstance(request, dict) and _valid_id(request.get("id")):
        return request["id"]
    return None


def _error(request_id, code, public_message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": public_message}}


def _has_credential(value, credentials):
    if isinstance(value, str):
        return credentials.client_secret in value or credentials.client_id in value
    if isinstance(value, dict):
        return any(_has_credential(k, credentials) or _has_credential(v, credentials) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_credential(member, credentials) for member in value)
    return False


def _remote_failure():
    return _BridgeError(-32000, "The upstream MCP request failed.")


class _Relay:
    def __init__(self, credentials):
        self.credentials = credentials
        self.protocol_version = None

    def forward(self, request, raw):
        method = request.get("method")
        if (request.get("jsonrpc") != "2.0" or not isinstance(method, str) or not _METHOD.fullmatch(method)
                or ("id" in request and not _valid_id(request["id"]))):
            raise _BridgeError(-32600, "Invalid JSON-RPC request.")
        if _has_credential(request, self.credentials):
            raise _BridgeError(-32600, "Credentials cannot be included in MCP messages.")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            "CF-Access-Client-Id": self.credentials.client_id,
            "CF-Access-Client-Secret": self.credentials.client_secret,
        }
        headers.update(self._protocol_headers(method, request))
        try:
            reply = self._exchange(method, request, raw, headers)
        except (httpx2.HTTPError, OSError, ValueError, RecursionError):
            raise _remote_failure() from None
        return reply

    def _protocol_headers(self, method, request):
        params = request.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        if isinstance(meta, dict) and _MODERN_VERSION_KEY in meta:
            version = meta[_MODERN_VERSION_KEY]
            if (not isinstance(version, str) or not _VERSION.fullmatch(version)
                    or version < _MODERN_FIRST_VERSION or method == "initialize"):
                raise _BridgeError(-32602, "Invalid MCP protocol metadata.")
            headers = {"MCP-Protocol-Version": version, "Mcp-Method": method}
            if method in {"tools/call", "prompts/get"}:
                name = params.get("name")
                if not isinstance(name, str) or not _TOOL.fullmatch(name):
                    raise _BridgeError(-32602, "Invalid MCP dispatch name.")
                headers["Mcp-Name"] = name
            return headers
        if method == "server/discover":
            raise _BridgeError(-32602, "MCP discovery requires modern protocol metadata.")
        if method == "initialize":
            if "id" not in request or self.protocol_version is not None:
                raise _BridgeError(-32600, "Invalid MCP initialization request.")
            return {}
        if self.protocol_version is None:
            raise _BridgeError(-32002, "MCP initialization is required.")
        return {"MCP-Protocol-Version": self.protocol_version}

    def _exchange(self, method, request, raw, headers):
        # A fresh client per request prevents any Set-Cookie becoming a credential.
        with httpx2.Client(timeout=_REMOTE_TIMEOUT, trust_env=False, follow_redirects=False) as client:
            deadline = time.monotonic() + 15.0
            with client.stream("POST", self.credentials.upstream, headers=headers, content=raw) as response:
                status = response.status_code
                if status in (401, 403):
                    raise _BridgeError(-32001, "The upstream MCP endpoint denied authentication or access.")
                if status == 429:
                    raise _BridgeError(-32003, "The upstream MCP endpoint is busy.")
                if "mcp-session-id" in response.headers:
                    raise _remote_failure()
                if "id" not in request:
                    if status != 202:
                        raise _remote_failure()
                    return None
                if (status not in (200, 400)
                        or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.headers.get("content-encoding", "identity").lower() != "identity"):
                    raise _remote_failure()
                data = bytearray()
                for chunk in response.iter_raw():
                    if time.monotonic() >= deadline or len(data) + len(chunk) > _RESPONSE_BYTES:
                        raise _remote_failure()
                    data.extend(chunk)
        reply = _load_object(data)
        if (reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not type(request["id"])
                or reply.get("id") != request["id"] or ("result" in reply) == ("error" in reply)
                or (status != 200 and "result" in reply)
                or set(reply) - {"jsonrpc", "id", "result", "error"} or _has_credential(reply, self.credentials)):
            raise _remote_failure()
        if "error" in reply:
            error = reply["error"]
            if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                raise _remote_failure()
        if method == "initialize" and "result" in reply:
            result = reply["result"]
            version = result.get("protocolVersion") if isinstance(result, dict) else None
            if not isinstance(version, str) or not _VERSION.fullmatch(version):
                raise _remote_failure()
            self.protocol_version = version
        return reply


def _write(stream, value):
    stream.write((json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode())
    stream.flush()


def _serve(source, output, relay):
    while raw := source.readline(_REQUEST_BYTES + 1):
        if len(raw) > _REQUEST_BYTES:
            _write(output, _error(None, -32600, "MCP message exceeds the bridge size limit."))
            return
        try:
            request = _load_object(raw)
        except (ValueError, RecursionError):
            _write(output, _error(None, -32700, "Invalid MCP JSON message."))
            continue
        try:
            reply = relay.forward(request, raw)
        except _BridgeError as error:
            if "id" in request or error.code == -32600:
                request_id = _response_id(request)
                if _has_credential(request_id, relay.credentials):
                    request_id = None
                _write(output, _error(request_id, error.code, str(error)))
        else:
            if reply is not None:
                _write(output, reply)


def main():
    parser = _BridgeArguments(description=__doc__)
    parser.add_argument("--credential-file", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int, help="Isolated operator-assigned UID.")
    args = parser.parse_args()
    try:
        credentials = _read_credentials(args.credential_file, args.uid)
        _serve(sys.stdin.buffer, sys.stdout.buffer, _Relay(credentials))
    except (OSError, ValueError, RecursionError):
        print("The Agent MCP bridge could not start or its stdio connection closed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
