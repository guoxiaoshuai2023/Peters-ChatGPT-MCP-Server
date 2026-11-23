# Multi-agent conversation history

## Unified project policy preview

The `0.4.4-progressive.9` development snapshot adds a v2 policy for isolated
testing. Keep the production release on its existing v1 policy until the
Antigravity automatic-attribution acceptance passes.

Start the packaged service with `--history-policy-mode v2 --agent-history-config
/absolute/private/unified-policy.json` for a v2 rehearsal. The descriptor
points to a private policy generation directory. Register verified MCP
principals once. Register each local history source with its adapter, format,
stable instance identifier and enabled state. The generation's `projects`
array supplies the project allowlist for ordinary reads and history queries.
Do not pass a separate project or legacy history configuration with v2. The
default v1 startup path and its file formats remain available.

V2 uses project attribution to filter history candidates before projecting
public messages. Project and source changes affect the existing Codex tools
as well as the common history tools. Tool evidence requires its existing
separate grant. An older Codex thread-only grant stays in migration review
until its project attribution is verified; v2 Codex reads require the
repository or directory proof. The result coverage entries distinguish complete queries,
unverified attribution, source availability, unsupported formats and work
limits. A verified conversation can still expose `missing_steps` in its read.

Use the local `peters_mcp.agent_history_admin` module to preview and review
migration, then manage private generations in the rehearsal. Keep the old
package and its matching v1 configuration together for full rollback. The
inspection-only package generated from this snapshot is for v2 package
inspection. When a source is newly registered, restart the rehearsal using
the reviewed source roots so the ordinary file tools also protect them.

Antigravity Desktop 2.33.0 has a read-only adapter and an optional
metadata-only Hook probe. The probe accepts the exact compact or full log
path for the observed native session, records append-only observations in a
private signed ledger, and grants no read access. The currently observed
Hook events leave continuous workspace membership and ancestor coverage
unverified. Treat the source coverage as incomplete. An exact, independently
verified snapshot exception can expose only its matching revision after
workspace and denial checks.

## Existing v1 startup

An operator can opt in to project-scoped saved messages with
`--agent-history-config /absolute/private/agent-history-access.local.json`.
The authenticated Cloudflare entrypoint uses the verified issuer and subject.
Local stdio uses the `local` policy key and signs references for the lifetime of
the service process. The shared tools are `find_agent_threads` and
`read_agent_thread`. Existing `find_codex_threads`, `read_codex_thread` and
`read_codex_thread_item` retain their existing policy and result shapes.

## Register a source

Start from `agent-history-access.example.json`. Use the actual canonical
absolute root on the host holding the original, then restart. Keep the source
ID stable on that host. When ready to share the source, set `enabled` and map
authorized principals to project IDs from the local project allowlist.

Omit `format` for a standalone Antigravity source to validate the local index
and native transcript schema directly. Existing explicit labels `2.32.1` and
`2.33.0` remain supported. Codeg and DeepSeek Harness require a format label.

- For stdio, `"actors": {"local": ["example-project"]}` limits access to that
  configured project through the local process.
- For Cloudflare, use the lowercase SHA-256 of UTF-8
  `json.dumps([issuer, subject], separators=(',', ':'))` as the actor key. Get
  those claims from the operator's verified Access identity.
- A per-thread grant maps the exact original ID to an allowed project in
  `threads`. Readable source and project scopes still apply. When known
  workspace or inherited history belongs to another project, access is denied.
- Set `inherit_projects` only where the reader can verify complete workspace
  history through the original. Known parents and workspace changes are
  considered. Entries in `denied_threads` take precedence.
- Codeg native links are explicit. They resolve only the mapped same-device
  source, and the target history must be independently authorized. Confirm
  the Codeg instance actually points to that native profile before enabling
  a link. A session ID can recur in a different profile.

Actor, thread, denial and source enable changes are read on the next
request and again before delivering a prepared result. Changes to the roots,
versions, adapters or links require a restart. Disabled source roots still
remain protected from the normal project, candidate and file-export tools.

## Supported readers in this candidate

| Adapter | Registered root and coverage |
| --- | --- |
| Codeg `codeg` | The same v0.45.0 desktop profile containing `codeg.db` and locally recorded ACP transcripts. Native associations currently cover explicitly mapped Codex and DeepSeek Harness IDs. External transcript roots and other agent formats require their own reader or verified support. SQLite runs on a short-lived copy. |
| DeepSeek Harness `deepseek_harness` | The v0.2.2-rc.3 sessions directory. Reads v4 JSONL or checksummed Zstandard frames with verifiable committed prefixes. Unknown newer generations stop the read. The installed Desktop had no scoped local Query Host endpoint available for validation, so this candidate uses the local log reader. |
| Google Antigravity `antigravity` | Standalone v2.32.1 and v2.33.0 desktop profiles with v3 `conversation_summaries.db` and retained `brain/<id>/.system_generated/logs/transcript.jsonl`. Continuous workspace history remains unverified. CLI, IDE and Codeg-hosted ACP history require separate readers. |

For Antigravity, the compact transcript establishes which steps can be shown.
If the native compactor truncates a visible message, the adapter can recover its
body from the sibling `transcript_full.jsonl` after checking the ordered steps,
timestamps, intact visible messages, and the retained text and omitted byte
count. If the logs agree step for step and share numbering gaps, verified text
is still recovered and the read retains `missing_steps` and incomplete coverage.
A missing or incompatible companion or a partly written record preserves the
compact projection. A read that combines both logs binds its snapshot to both files and
requires a fresh read if either file changes.

The adapters select supported user and assistant messages. Internal context,
reasoning, tool arguments, attachments, and runtime state are excluded. The
shared layer applies known-secret and local path filtering before substring
search, paging and return.

## Use and verification

Search with a project ID, optionally a query, agent or source. Pass the returned
`thread_ref` to the read tool. Default chronological paging works on every
reader. Available turn views depend on reliable boundaries. Use the same inputs
when replacing a cursor. A long message may span pages with the same
`message_id` and increasing character offsets. Cite the source, stable thread
ID and message ID. A projection digest identifies the returned visibility
snapshot and the source revision identifies the underlying version separately.

Follow `next_cursor` while processing or preparing another page. If the
projection or authorization changes, or a bounded worker expires, start a new
search. A missing or unsupported source reports incomplete coverage. The
candidate's Codeg, DeepSeek and Antigravity parsers are exercised with synthetic
versions of their native records. Real deployment acceptance requires comparing
existing and new visible threads against each application's UI, plus a single
authenticated connector query across the three sources. Antigravity native
desktop older threads require an actual retained original on the source host.

Source SQLite snapshots live transiently in `agent-history-work` next to the
explicit policy and are excluded from generic workspace tools. The operator
must use a private local directory for this policy. Keep vendor credential and
configuration directories out of authorized project and worktree roots. The service bounds the
size of copied DB/WAL pairs and retries changing snapshots with continuations.
A rollback to the previous release must retain compatible generic-file
source exclusions or use disjoint project paths before exposing the old server.
