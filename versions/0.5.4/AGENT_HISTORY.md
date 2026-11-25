# Multi-agent conversation history

## Unified project policy (`0.5.4`)

The `0.5.4` candidate builds on the `0.4.4-progressive.12` unified project policy
with productized attribution, four-source coverage honesty, append-safe
pagination, single-round bounded multi-source discovery, and exact official-view
parity across Codex normal forks, attached side-threads, and spawned subagent
sessions. Production activation remains subject to independent technical
acceptance and authenticated external ChatGPT verification.

Key behavioral guarantees in `0.5.4`:

- **Physical occupancy and tombstones**: Sibling folder edits and normal edits
  inside a project directory no longer falsely invalidate historical sessions on
  macOS APFS. Directory replacements, renames, swaps, and revocations are clamped
  by durable owner-only `.path-tombstones.json` (`0600`) stored alongside the
  generation directory without altering `active.json` rollback compatibility.
- **Antigravity dual-track verification**: Versions `2.32.1` and `2.33+` are
  validated by live SQLite schema probing and security invariants across DB and
  `transcript_full.jsonl`, including Checkpoint-compacted steps, child subagent
  containment, active `RUNNING` sessions, and deterministic `turn_id` values
  (`view=latest_turn` and `view=turn`).
- **Honest coverage and zero-leak diagnostics**: Coverage entries report exact
  states, project-scoped `unverified_project_candidates` counts, and Codeg
  `unsupported_agent_types` without revealing foreign or unauthorized titles,
  IDs, or message bodies. Use `python -m peters_mcp.agent_history_admin lint` and
  `preview-coverage` locally to inspect policy links, static exceptions, and
  per-project coverage before activation.
- **Multi-tier search and live append continuity**: `find_agent_threads` ranks
  contiguous substring matches ahead of multi-token matches and returns
  `total_project_threads` with a `browse_hint` on zero-hit filtered queries.
  Strict monotonic appends to an active thread preserve cursor pagination with
  zero duplicates or omissions while marking `appended_since_snapshot`; any
  rewrite, prefix mutation, file replacement, or revocation fails closed with
  `restart_required` or `unauthorized`.

Start the packaged service with `--history-policy-mode v2 --agent-history-config
/absolute/private/unified-policy.json` for a v2 rehearsal. The descriptor
points to a private policy generation directory with a separate owner-only
authorization anchor. Cloudflare Access supplies the verified caller identity.
Register each local history source with its adapter, format, stable instance
identifier and enabled state. The generation's `projects` array supplies the
project grants for file browsing, text reads, candidate creation, configured
original-file saves and exports, and queries across enabled history sources.
A new project receives the default candidate directory `docs/candidates/chatgpt`.
Existing operator-confirmation and create-only rules apply to file writes.
Native saves and exports still require their service-level setup.
Do not pass a separate project or legacy history configuration with v2. The
default v1 startup path and its file formats remain available.

To add a directory to an existing v2 deployment, append one entry such as
`{"id":"repo-c","name":"Repo C","root":"/srv/projects/repo-c"}` to
`projects` in the operator's policy document. For a Git repository, use its
registered repository identity so that verified external worktrees are included.
Review the generation with `agent_history_admin preview` and activate the
reviewed digest. The same ChatGPT connection can then call `list_files` and
`find_agent_threads(project_id="repo-c")`. Pass the returned `thread_ref`
to `read_agent_thread` and follow its cursor for longer sessions. Source
registrations and thread lists need no edits when a project is added.
Removing the project from the next generation withdraws these operations
and the associated write and export capabilities together.

V2 uses project attribution to filter history candidates before projecting
public messages. Project and source changes affect the existing Codex tools
as well as the common history tools. Tool evidence requires its existing
separate grant. An older Codex thread-only grant stays in migration review
until its project attribution is verified; v2 Codex reads require the
repository or directory proof. The result coverage entries distinguish complete queries,
unverified attribution, source availability, unsupported formats and work
limits. A verified conversation can still expose `missing_steps` in its read.

For a search across sources, continue with the same arguments and the returned
cursor until `has_more` is false. The page size is an upper bound. A large
page can be shortened so that each displayed result and all its matched
sources are rechecked before delivery. A single merged row that exceeds the
bounded verification window contributes `resource_exhausted` to its sources'
coverage. Other verified rows remain available through pagination.

Automatic history inheritance also verifies when the physical project occupied
the recorded path. The first grant can include existing sessions when every
directory component has evidence covering the native creation and final
commit. On macOS a rename updates the directory's change time and its
parent's directory entries. Either unchanged timestamp can establish the
named component's history. While a server or worker is running, vnode notifications track moves
and deletions through ordinary additions and edits inside those directories.
When a path crosses into a different mounted filesystem, evidence for that
edge starts with the observed mount or a previously retained interval.
For a session started in a subdirectory the full recorded working directory
must also be verified over that interval, including each component below the
registered project or linked Git checkout.
Git checkouts also require the same common Git directory at its registered
location throughout the conversation. A linked checkout includes its own
administration directory and the three verified pointer files connecting it
to that repository. This distinguishes different Git repositories that have
occupied the same working directory. The store retains verified time intervals for each physical
project and location, including across revocation and restart.

The running v2 MCP service also checkpoints registered roots and discovered
external Git checkouts without reading an agent source. Its supervised process
runs a bounded round every 30 seconds, rotating through up to 16 projects and
eight external checkouts per project within a three-second budget. It closes
one final round at normal shutdown. Newly admitted source timestamps and new
disjoint observations are retained immediately when a history query verifies
them. Repeated queries coalesce short extensions to an already recorded period.
An interruption can leave the time after the last confirmed observation
unverified. The v1 service and the configuration checker do not start this process.

A source that lacks an ordered native time span, or whose conversation crosses
an unobserved change of owner, reports `association_unverified`. Its title and
messages stay private. Directory activity before the first registration or
during a service outage can leave a gap when both ends of a named path have
changed and there is no prior observation. The operator can inspect the
reported coverage. Existing reviewed snapshot exceptions and path migrations
retain their independent evidence checks. Back up the private generation
store, its project occupancy observations and its external authorization anchor together.
Each retained observation names its physical owner. Earlier development caches
containing only time pairs require fresh evidence. Copying such a file, even
to a matching directory name, cannot establish historical ownership.

Use the local `peters_mcp.agent_history_admin` module to preview and review
migration, then manage private generations in the rehearsal. Recompile v2
policy rehearsals from approved inputs when coming from the earlier .9
preview schema. Treat the external authorization anchor as live operator
state. For recovery, the administrator must verify the exact approved
generation and current physical roots against that anchor. Keep the old
package and a matching v1 configuration that reflects current revocations
for a rehearsal of full rollback. The
inspection-only package generated from this snapshot is for v2 package
inspection. When a source is newly registered, restart the rehearsal using
the reviewed source roots so the ordinary file tools also protect them.
Changes to the project list and enable/disable changes on existing source
instances take effect on the next request. New source registrations, or a
change of source identity, root, format or links, require a service restart.

For a directory that moved, configure the exact former root, the source
instance and native project ID, and the current directory and its identity.
Use the source host's private preview to review the frozen, pre-move sessions.
Supply the latest independently established time at which the former root
belonged to the project, including the UTC offset.

```sh
python -m peters_mcp.agent_history_admin preview-path-migration \
  --descriptor "$descriptor" --document "$candidate" --source "$source" \
  --old-root "$former_directory" --before "$last_verified_time"
```

If multiple native projects used that former root, add `--native-project`
with the original project's identifier. Protect the preview as private
operator data. Its `path_migration` report lists proposed, already approved,
and pending native sessions. Check the proposed IDs against source records
and the dates of the move. Activate using the reviewed preview and digest
through the usual `activate` operation. Activation rechecks the proposed
and existing snapshots. An old template can reuse a previous grant only
when the source instance, physical roots, native project, and pinned
original still match. A `previous_approval_drifted` result requires local
review before activation. Keep current denials in place when using this
preview. When a migrated legacy exception pins only the visible transcript,
its displayed title comes from the first visible user message and its update
time comes from the last dated visible message. Either field can be empty.
A session created after the move uses normal inheritance at the
current project root. Later sessions at the former path receive no migration
grant. Removing the mapping or reusing the former location breaks access
through that mapping.

For an older exception that approved only the visible log, a migrated
conversation takes its title from the first verified user entry and its date
from the verified messages. A missing title or date is returned as an empty
string. New migration approvals also bind the native display metadata.

For automatic Antigravity history, register the local Desktop profile with
`format: "2.33.0"`. The adapter compares each candidate's v3 summary,
SQLite-v1 conversation trajectory and retained visible transcript. It checks
the originating cascade and workspace roots, step sequence, execution and
model invocation records, and the built-in desktop agent configuration for
each turn. The project must contain every verified root. A supported
top-level conversation can then be searched and read without a thread entry.
The user entry contains the original user input and the assistant entry
contains the verified visible response.

For development sessions, the adapter also checks native file-edit receipts,
local task completions and direct subagent messages. A subagent receipt must
match the parent's recorded spawn and the sender's committed native call in
the same project. The parent delivers its own public entries. Disabling a
source, withdrawing a project or denying a contributing sender prevents
delivery under that authorization.

The compact and full logs can both omit a built-in tool proposal interrupted
during generation (`step_type=132, status=1`). The adapter can return the
public conversation with `missing_steps` when the native trajectory, paired
transcripts, generation error record (`gen_metadata.5`), matching requested
call descriptor on the preceding `CLIENT_STREAM_ERROR` planner step, sole
`PENDING` state transition with zero tool result payload, error-before-final-reply
temporal ordering, and terminal completed-executor reply (`stop_reason=2`
whenever recorded or when discarded proposals exist, Checkpoint-compacted
`status=5`, or a `CHECKPOINT` closing a committed reply) independently account for the gap. A missing user message, unresolved or
executed `PENDING` tool, mismatched call ID, errorless generation, error
finishing after final reply, non-terminal completed reply, or conflicting
prompt leaves attribution unverified.

## Contract Evolutions from `0.4.4-progressive.12` (`v0.5.x`)

The following intentional product contract evolutions replace narrower `.12`
behaviors while keeping every cross-project, revocation, and commit-boundary
security invariant fail-closed:

1. **Bounded 1-round aggregate discovery (`find_agent_threads`)**: Fast source
   scans complete page 1 within the first-round scan budget and return
   `status="ready"` directly instead of forcing a wasted `status="processing"`
   continuation round-trip.
2. **Antigravity Desktop `2.33+` structural version probing**: Versions matching
   `2.(3[2-9]|[4-9][0-9]).*` (including `2.33.1`, `2.34.0`, etc.) are probed
   against native SQLite/transcript schema invariants rather than rejected solely
   by an exact version-string allowlist.
3. **Active (`CASCADE_RUN_STATUS_RUNNING` / `not_fully_idle=1`) Antigravity
   threads**: Live in-progress threads project already-committed `DONE` public
   messages with an explicit `thread_in_progress` warning (and omit uncommitted
   trailing steps). `killed=1` threads and idle threads missing required
   `executor_metadata` remain fail-closed (`unverified`). Closed idle threads
   whose `not_fully_idle=1` flag comes solely from verified discarded proposals
   report `missing_steps` without a spurious `thread_in_progress` warning.
4. **Generalized built-in Antigravity tool verification**: Built-in tools
   (`source=1`, non-`mcp_*`) are verified by security invariants rather than a
   3-tool-name allowlist (`read_file`/`write_file`/`run_command`), while
   strictly preserving `mcp_*` non-spoofing and discarded-proposal checks.
5. **Checkpoint-compacted (`status=5`) dual-track recovery**: Public steps
   compacted by Antigravity Checkpoints are cross-checked against paired
   `transcript_full.jsonl` and surfaced with the informational warning
   `compacted_steps_from_transcript`.
6. **Errored executors (`exec_status != 4` with recorded error field 12)**:
   Historical turns whose executor terminated with an explicit error are
   accepted without relaxing terminal-reply checks on normally completed
   (`exec_status == 4`) executors.
7. **Codex paginated fork prefix reconstruction, attached side-threads,
   spawned `subagent` isolation, tool-provenance notification filtering,
   multimodal wrapper deduplication, and unified `latest_turn` parity**: Normal
   sparse `paginated` Codex forks (`attached_thread` absent/false and non-`subagent`
   source) carrying verifiable native `history_base` (`thread_id`,
   `end_ordinal_exclusive`, `end_byte_offset`) reconstruct only the exact
   pre-fork public prefix of authorized same-project ancestors (excluding any
   post-fork parent appends); normal forks without verifiable cutoff evidence
   never expand unaligned parents and explicitly report
   `inherited_prefix_unverified` (`complete_public_projection=false`). Attached
   side-threads (`attached_thread=true` or `attached_thread_parent_id`) and
   native spawned subagents (`session_meta.source` / index `source` declaring
   `subagent`) still verify full parent-lineage authorization and project
   containment (failing closed on denied, cross-project, or pre-Git ancestors,
   including mid-pagination parent revocation), while projecting and indexing
   only the child session's own verified public messages (`parent_context_inlined=false`)
   in 1:1 alignment with the official Codex client so parent-only text never
   contaminates child reads or search hits. Client-generated tool-provenance
   multi-agent completion notifications (`provenance.type != "user"` or
   `multi_agent.*` item kinds) and `auto-compact-*` bridge envelopes are never
   projected as user utterances, while literal `<subagent_notification>` text
   typed by users or assistants (`provenance.type == "user"` or public
   conversation entries across all four sources) is preserved verbatim without
   tag stripping or truncation. Synthetic `<image ...>...</image>`
   text wrappers around attached image blocks are stripped before mirror
   deduplication while preserving genuine consecutive identical user sends.
   Unified `read_agent_thread(view="latest_turn")` aligns with
   `read_codex_thread` using declared `latest_turn_id` and `ambiguous_turn_ids`.

Parented sessions, unverified workspace overrides, unknown lifecycle records
and incomplete native evidence contribute incomplete coverage. An exact
historical exception still uses its pinned source identity and revision and
preserves the original visible projection and any `missing_steps` warning.
The optional Hook probe remains a local diagnostic. Use `--assess` to
inspect its observed callbacks.

## Existing v1 startup

An operator can opt in to project-scoped saved messages with
`--agent-history-config /absolute/private/agent-history-access.local.json`.
The authenticated Cloudflare entrypoint uses the verified issuer and subject.
Local stdio uses the `local` policy key and signs references for the lifetime of
the service process. The shared tools are `find_agent_threads` and
`read_agent_thread`. Existing `find_codex_threads`, `read_codex_thread` and
`read_codex_thread_item` retain their existing policy and result shapes.

## Register a source under v1

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
| Google Antigravity `antigravity` | Standalone Desktop 2.32.1 and 2.33.0 with a v3 index and retained visible transcripts. V2 automatic association also requires the supported 2.33.0 Desktop trajectory under `conversations/<id>.db`. CLI, IDE and Codeg-hosted ACP use distinct source formats. |

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
