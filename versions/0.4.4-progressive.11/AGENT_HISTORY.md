# Multi-agent conversation history

## Unified project policy preview

The `0.4.4-progressive.11` development snapshot tests a unified project policy.
Production activation requires successful native attribution and full
authenticated ChatGPT acceptance of the project tools.

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
Git checkouts also require the common repository identity and current worktree
registration. The store retains verified time intervals for each physical
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
