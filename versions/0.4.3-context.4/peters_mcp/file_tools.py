"""Original-file tool schemas. Confirmation policy belongs to the client."""
from datetime import datetime, timezone
import json
import secrets
import time

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .catalog import AccessError
from .file_context import current_file_actor
from .file_source import NativeFile


_IDEMPOTENCY_DIAGNOSTICS = ('selection_changed', 'nonselection_intent_matches',
                            'completed_bound_hash_matches')


def register_file_tools(server, service, *, audit=None, inspection_only=False):
    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    write = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)
    cancel = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False)

    def hide_invalid_inputs(names):
        # SDK 2.2 formats Pydantic argument errors before entering our tool body.
        # Its generated outer model must omit input values, including native SAS URLs.
        for name in names:
            model = server._tool_manager.get_tool(name).fn_metadata.arg_model
            model.model_config['hide_input_in_errors'] = True
            model.model_rebuild(force=True)

    def invoke(operation, **arguments):
        trace_id, started, ok, error = secrets.token_hex(12), time.monotonic(), False, None
        result, diagnostics = None, {}
        try:
            actor = current_file_actor()
            result = getattr(service, operation)(actor, **arguments)
            ok = True
            return {**result, 'trace_id': trace_id}
        except AccessError as exc:
            error = exc.code
            values = getattr(exc, 'idempotency_diagnostics', None)
            if error == 'idempotency_conflict' and type(values) is dict:
                diagnostics = {key: values[key] for key in _IDEMPOTENCY_DIAGNOSTICS
                               if type(values.get(key)) is bool}
            raise ToolError(f'[{exc.code}] {str(exc)} (trace_id={trace_id})') from None
        except Exception:
            error = 'internal_error'
            raise ToolError(f'[internal_error] File operation could not be confirmed. Query its original request_key; do not submit a new key to assume no publication. (trace_id={trace_id})') from None
        finally:
            if audit:
                record = {'component':'original_file', 'time':datetime.now(timezone.utc).isoformat(),
                    'operation':operation, 'trace_id':trace_id, 'ok':ok, 'error_code':error,
                    'elapsed_ms':round((time.monotonic()-started)*1000)}
                record.update(diagnostics)
                if (ok and operation == 'submit' and isinstance(result, dict)
                        and result.get('operation') == 'receipt_lookup'
                        and result.get('subject') == 'original_job'
                        and result.get('match_kind') == 'completed_bound_hash'):
                    record.update(result_operation='receipt_lookup', subject='original_job',
                                  match_kind='completed_bound_hash')
                    record.update({key: True for key in _IDEMPOTENCY_DIAGNOSTICS})
                    job_id = result.get('job_id')
                    if (type(job_id) is str and len(job_id) == 32
                            and all(c in '0123456789abcdef' for c in job_id)):
                        record['job_id'] = job_id
                        original = result.get('original_job_status')
                        if type(original) is dict and original.get('job_id') == job_id:
                            status = {'job_id': job_id}
                            if original.get('state') == 'completed':
                                status['state'] = 'completed'
                            if original.get('published') is True:
                                status['published'] = True
                            record['original_job_status'] = status
                elif ok and isinstance(result, dict) and isinstance(result.get('job_id'), str):
                    record['job_id'] = result['job_id']
                    record['state'] = result.get('state')
                    record['published'] = result.get('published')
                audit.info(json.dumps(record))

    @server.tool(annotations=read)
    def get_write_capabilities() -> dict:
        """List the authenticated user's inherited repo/worktree create-only scope and execution readiness.

        This does not create directories or authorize a call. A valid repo grants its verified
        worktrees automatically; protected paths and excludes still apply. A new filesystem
        may need configured private staging. Inspect the chosen path for its target_version.
        File byte size has no fixed product cap; actual storage/protocol constraints apply.
        """
        result = invoke('capabilities')
        if inspection_only:
            result.update(write_enabled=False, mode='rollback_inspection_only')
        return result

    @server.tool(annotations=read)
    def get_file_save_status(job_id: str | None = None, request_key: str | None = None) -> dict:
        """Read an existing job or original request_key, using exactly one locator.

        Pure status: never starts downloads, resumes, hashes large files or publishes.
        accepted/processing is not saved. Report published, durability and verification
        separately; completed requires all success evidence. A lost first reply can be
        recovered by its original request_key. Current file presence is not publication history.
        """
        return invoke('status', job_id=job_id, request_key=request_key)

    if inspection_only:
        hide_invalid_inputs(('get_write_capabilities', 'get_file_save_status'))
        return

    @server.tool(annotations=read)
    def inspect_file_destination(project_id: str, worktree_id: str, path: str) -> dict:
        """Inspect one explicit worktree-relative NEW file destination without creating anything.

        Show the returned canonical destination_display and file to the user before the write
        call. Use its exact target_version. This check does not lock a path or prove approval.
        A nested registered worktree must be selected explicitly; do not silently redirect.
        """
        return invoke('inspect', project_id=project_id, worktree_id=worktree_id, path=path)

    @server.tool(meta={'openai/fileParams':['file']}, annotations=write)
    def save_generated_file(file: NativeFile, project_id: str, worktree_id: str,
                            path: str, target_version: str, destination_display: str,
                            request_key: str, expected_sha256: str | None = None,
                            expected_size_bytes: int | None = None) -> dict:
        """Save this actual native generated attachment, unchanged, as a NEW file at destination_display.

        Display the original filename, project/worktree, relative path and canonical target;
        invoke through the client's write confirmation policy. Use the inspected target_version
        and display unchanged. Do not fabricate a download URL, regenerate content, transcode,
        unzip, overwrite or silently rename. Normal hidden/binary files are supported except
        protected paths/excludes. Missing parents may be created. Reuse the same request_key
        only for the same intent; a changed file/path needs a new call and confirmation policy.
        Acceptance is durable but not completion: query status. An accepted background job
        continues after leaving chat or normal token expiry, subject to observed revocation,
        cancellation, source and resources. Supply a hash/size only if actually known.

        A changed reference may look up a completed same-epoch historical receipt only when
        the original hash and size remain bound and all other intent fields match. Its
        operation=receipt_lookup scopes original facts under original_job_status; this service
        receives or verifies no new file bytes. Different references for incomplete jobs still
        conflict. Recover a lost reply by querying the original request_key.
        """
        return invoke('submit', file=file, project_id=project_id, worktree_id=worktree_id,
                      path=path, target_version=target_version, destination_display=destination_display,
                      request_key=request_key, expected_sha256=expected_sha256,
                      expected_size_bytes=expected_size_bytes)

    @server.tool(meta={'openai/fileParams':['file']}, annotations=write)
    def refresh_file_source(job_id: str, expected_source_revision: int, file: NativeFile) -> dict:
        """Refresh a temporary native reference for the SAME accepted contents and target.

        Requires a stopped old writer and verifiable original content constraint. Never edits
        target/hash or silently swaps content; an unbound replacement needs a new content job.
        Do not invent URLs. A same-key save retry cannot refresh a reference.
        """
        return invoke('refresh_source', job_id=job_id, expected_source_revision=expected_source_revision, file=file)

    @server.tool(annotations=cancel)
    def cancel_file_save(job_id: str) -> dict:
        """Request cancellation of this user's task and safe cleanup of its private unfinished data.

        Report whether the request was durable and whether it prevented publication. A pending
        writer stop is not cancellation complete. Publication that won first remains a historical
        fact: this tool never deletes or overwrites the published target. Uncertain publication
        retains its evidence. Other users' jobs cannot be inspected or cancelled.
        """
        return invoke('cancel', job_id=job_id)

    hide_invalid_inputs(('get_write_capabilities', 'get_file_save_status', 'inspect_file_destination',
                         'save_generated_file', 'refresh_file_source', 'cancel_file_save'))
