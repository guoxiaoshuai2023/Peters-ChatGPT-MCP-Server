"""Optional MCP package tools; every write requires an explicit enabled policy."""

from datetime import datetime, timezone
import json
import re
import secrets
import time

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .audit import audit_actor, audit_request_id
from .catalog import AccessError
from .delivery_types import OpenAIFile


def register_delivery_tools(server, packages, audit=None):
    def invoke(operation, *args, **kwargs):
        started = time.monotonic()
        record = {'time': datetime.now(timezone.utc).isoformat(), 'tool': operation,
                  'call_id': secrets.token_hex(8), 'ok': False}
        request_id = audit_request_id.get()
        if request_id is not None:
            record['request_id'] = request_id
        try:
            actor = audit_actor.get()
            if not isinstance(actor, str) or not re.fullmatch(r'[a-f0-9]{64}', actor):
                raise AccessError('Original-file delivery requires a verified request identity.',
                                  code='delivery_actor_required')
            if operation == 'get_delivery_capabilities':
                result = packages.policy.capabilities()
                result['service_version'] = '0.5.0'
                result['server_tools'] = ['get_delivery_capabilities', 'stage_file_package',
                                          'inspect_delivery', 'commit_delivery']
            else:
                method = {'stage_file_package': 'stage', 'inspect_delivery': 'inspect',
                          'commit_delivery': 'commit'}[operation]
                result = getattr(packages, method)(actor, *args, **kwargs)
            record['ok'] = True
            for key in ('delivery_id', 'status', 'error_code'):
                if result.get(key) is not None:
                    record[key] = result[key]
            return result
        except AccessError as exc:
            record['error_code'] = exc.code
            raise ToolError(str(exc)) from None
        except Exception:
            record['error_code'] = 'delivery_internal_error'
            raise ToolError('[delivery_internal_error] Delivery operation could not be verified. Query its state before retrying.') from None
        finally:
            record['elapsed_ms'] = round((time.monotonic() - started) * 1000)
            if audit:
                audit.info(json.dumps(record))

    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    write = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=read)
    def get_delivery_capabilities() -> dict:
        """List explicitly enabled original-file write targets and resource limits.

        These targets do not inherit repository read or worktree permissions. This
        reports server capability, not proof the client loaded or approved a write tool.
        Original packages use stage_file_package, inspect_delivery, commit_delivery.
        Small candidate Markdown remains a separate API with different semantics.
        """
        return invoke('get_delivery_capabilities')

    @server.tool(meta={'openai/fileParams': ['file']}, annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def stage_file_package(file: OpenAIFile, target_id: str, version_directory: str, expected_sha256: str) -> dict:
        """WRITE: receive an original ZIP into private staging, never the project directory.

        Select target_id from get_delivery_capabilities. Pass a native generated-file
        reference and its independently computed ZIP SHA256, not reconstructed text or
        an invented URL. This persists data and consumes local space: respect client
        write confirmation. Poll inspect_delivery for its frozen preview. No publishing,
        execution or project changes occur in this step. Exact retries reuse the same
        intent; interrupted downloads may require a refreshed native file reference.
        """
        return invoke('stage_file_package', file, target_id, version_directory, expected_sha256)

    @server.tool(annotations=read)
    def inspect_delivery(delivery_id: str, file_path: str = '', offset: int = 0, limit: int = 20000) -> dict:
        """Read delivery state, exact target, frozen manifest and optionally original text.

        For receiving, poll later; do not assume ready. For ready, show the exact target,
        all file names/sizes/SHA256, and let the user inspect each frozen file with
        file_path and byte offset. Original byte slices and readable UTF-8 text are
        returned with explicit pagination; the original bytes are unchanged. The returned
        commit_arguments include the complete manifest and a content-bound preparation,
        NOT user consent. Inspect again to renew an expired preview while staging exists.
        For completed, independently verify the published directory before claiming success.
        """
        return invoke('inspect_delivery', delivery_id, file_path, offset, limit)

    @server.tool(annotations=write)
    def commit_delivery(delivery_id: str, target_id: str, version_directory: str, manifest: list[dict],
                        archive_sha256: str, preparation: str, destination: str) -> dict:
        """WRITE: publish the reviewed original-file package as ONE new version directory.

        First display the exact target, complete manifest and accessible frozen contents.
        Pass inspect_delivery.commit_arguments unchanged, through the client's current
        per-action user confirmation; never claim the preparation proves approval. Do not
        submit an opaque ID-only confirmation or enable blanket write approval. No overwrite,
        automatic alternate path, code execution, Git action or Codex task follows. If the
        response is lost, inspect state or retry the same arguments, never create duplicates.
        """
        return invoke('commit_delivery', delivery_id, target_id, version_directory,
                      manifest, archive_sha256, preparation, destination=destination)
