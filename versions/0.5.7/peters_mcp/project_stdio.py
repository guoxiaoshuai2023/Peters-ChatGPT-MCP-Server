"""POSIX stdio transport for unified project grants. The SDK owns MCP dispatch."""

from contextlib import ExitStack, contextmanager, nullcontext
import json
import os
import stat
import time

import anyio
from mcp import types
from mcp.shared._context_streams import create_context_streams
from mcp.shared.message import SessionMessage

from . import project_guard
from .catalog import AccessError


@contextmanager
def _stdio_fds():
    """Keep the protocol descriptors private while handlers and child processes run."""
    with ExitStack() as restore:
        source = os.dup(0)
        restore.callback(os.close, source)
        target = os.dup(1)
        restore.callback(os.close, target)
        mode = os.fstat(target).st_mode
        if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or os.isatty(target)):
            raise ValueError("Unified MCP stdio needs a nonblocking output pipe, socket or terminal.")
        for fd in (source, target):
            restore.callback(os.set_blocking, fd, os.get_blocking(fd))
            os.set_blocking(fd, False)
        with open(os.devnull, "rb") as empty:
            os.dup2(empty.fileno(), 0)
        restore.callback(os.dup2, source, 0)
        os.dup2(2, 1)
        restore.callback(os.dup2, target, 1)
        yield source, target


async def _input_lines(fd):
    pending = bytearray()
    while True:
        await anyio.lowlevel.checkpoint()
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            await anyio.wait_readable(fd)
            continue
        if not data:
            if pending:
                yield bytes(pending)
            return
        segments = data.split(b"\n")
        pending.extend(segments[0])
        for segment in segments[1:]:
            yield bytes(pending)
            pending = bytearray(segment)


def _refusal(identifier):
    return (json.dumps({"jsonrpc": "2.0", "id": identifier, "error": {
        "code": -32000, "message": "[restart_required] Project policy changed or delivery expired."}},
        separators=(",", ":")) + "\n").encode()


class _Wire(anyio.abc.ObjectSendStream):
    def __init__(self, fd, policy, abort):
        self.fd = fd
        self.policy = policy
        self.abort = abort
        self.lock = anyio.Lock()
        self.closed = False

    async def aclose(self):
        self.closed = True

    async def send(self, item):
        msg = item.message
        frame = (msg.model_dump_json(by_alias=True, exclude_unset=True) + "\n").encode()
        identifier = msg.id if isinstance(msg, (types.JSONRPCResponse, types.JSONRPCError)) else None
        await self._write(frame, identifier, guarded=True)

    async def refuse(self, identifier):
        await self._write(_refusal(identifier), identifier, guarded=False)

    async def _write(self, frame, identifier, *, guarded):
        deadline = time.monotonic() + project_guard._COMMIT_SECONDS
        offset = 0
        try:
            with anyio.fail_after(max(0, deadline - time.monotonic())):
                async with self.lock:
                    while offset < len(frame):
                        if self.closed:
                            raise anyio.ClosedResourceError()
                        # A slow reader never occupies a private or policy lease.
                        await anyio.wait_writable(self.fd)
                        block = memoryview(frame)[offset:offset + 65536]
                        try:
                            lease = project_guard.stdio_delivery(self.policy, deadline) if guarded else nullcontext()
                            async with lease:
                                count = os.write(self.fd, block)
                                # Remember the real kernel handoff even if releasing
                                # a lease is interrupted by ASGI/SDK task cancellation.
                                offset += count
                        except BlockingIOError:
                            continue
                        except AccessError:
                            if offset:
                                # The peer may already hold a prefix. A second line
                                # or error appended to that prefix would corrupt framing.
                                break
                            if identifier is None:
                                return
                            frame = _refusal(identifier)
                            guarded = False
                            continue
                        if not count:
                            break
                    else:
                        return
        except (TimeoutError, OSError):
            pass
        except BaseException:
            if offset:
                self.closed = True
                self.abort()
            raise
        self.closed = True
        self.abort()
        raise anyio.ClosedResourceError()


async def _read_requests(fd, channel, catalog, output):
    async with channel:
        async for line in _input_lines(fd):
            try:
                message = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
            except ValueError as error:
                await channel.send(error)
                continue
            item = SessionMessage(message)
            if not isinstance(message, types.JSONRPCRequest):
                await channel.send(item)
                continue
            try:
                request = await anyio.to_thread.run_sync(
                    project_guard._begin_request, catalog.unified_policy, catalog._private_registry)
            except (AccessError, TimeoutError):
                await output.refuse(message.id)
                continue
            # The SDK dispatches each request in the sender's context. Its final
            # response is written from that same request task, including both eras.
            with project_guard.bind_project_request(request):
                await channel.send(item)


async def serve_project_stdio(server, catalog):
    with _stdio_fds() as (source, target):
        sender, incoming = create_context_streams(0)
        async with anyio.create_task_group() as group:
            output = _Wire(target, catalog.unified_policy, group.cancel_scope.cancel)
            group.start_soon(_read_requests, source, sender, catalog, output)
            try:
                await server.run(incoming, output, server.create_initialization_options())
            finally:
                group.cancel_scope.cancel()
