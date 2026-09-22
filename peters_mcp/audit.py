"""Request correlation shared by the HTTP boundary and synchronous MCP tools."""

from contextvars import ContextVar


audit_request_id: ContextVar[str | None] = ContextVar("peters_mcp_request_id", default=None)
