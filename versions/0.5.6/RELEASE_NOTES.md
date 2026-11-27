# 0.5.6 candidate (targeted Antigravity verbatim step-replay remediation over 0.5.5)

Prevents authorized Antigravity Desktop conversations from disappearing from
`find_agent_threads` when Antigravity rewrites a previously committed non-public
status record verbatim at a later transcript line, while preserving fail-closed
integrity checks across both `v1` and `v2` paths:

- **Verbatim non-public step replay deduplication (`agent_history_antigravity.py`)**:
  `_Transcript.__iter__` records exact raw-line SHA-256 digests only for
  recognized non-public internal/status records (`source in {"SYSTEM",
  "SYSTEM_SDK", "USER_IMPLICIT"}` for `USER_INPUT`/`PLANNER_RESPONSE`, and
  `source in {"MODEL", "SYSTEM", "SYSTEM_SDK", "USER_IMPLICIT"}` for other
  non-public record types; all `VISIBLE_ROLES`, `USER_EXPLICIT`, and unknown
  sources are never eligible). When an already-seen eligible non-public
  `step_index <= prior_index` reappears with an exact byte-for-byte identical
  line, the duplicate line is skipped without aborting thread parsing or
  altering `prior_index`, preserving genuine forward `missing_steps`,
  `unfinished_messages_omitted`, raw byte `revision` fingerprints, single-file
  append-only `prefix` checks, and `MAX_RECORDS` / byte budgets. Any mutated
  field (`status`, `content`, `source`, `type`, `created_at`, extra keys, or
  non-identical byte encoding), any replayed public or unknown-source step, or
  any unseen older `step_index` fails closed with `unsupported_format`.
- **Symmetric two-log replay corroboration across `v1` and `v2`**: Whenever
  `transcript_full.jsonl` exists alongside `transcript.jsonl`, `_snapshot_iter`
  corroborates both logs via `_recover_iter` and requires identical replay
  counts and position/metadata digests (`[line_index, step_index, type, source,
  status, created_at]`) across both files (allowing non-public content
  compaction differences between `compact` and `full`). One-sided replays in
  either `compact` or `full` (whether `compact` is truncated or intact),
  shifted replay positions, or incomplete trailing lines on either side of a
  paired replay fail closed symmetrically (`unsupported_format` in `v1`;
  `association_unverified` in `v2`), while single-file append semantics remain
  intact when no companion exists.
- **Verification status**: Synthetic unit, security boundary, `v1`/`v2` MCP
  title-search, paginated `next_cursor`, `latest_turn`, and revocation tests
  pass; candidate bundle remains unpromoted pending independent L4 acceptance
  and live host verification.

# 0.5.5 candidate (targeted L4 remediation over 0.5.4)

Closes macOS background-QoS (`ProcessType=Background` / `taskpolicy -b`) cold-start
step timeouts on large Antigravity Desktop conversations and restores truthful
unified `v2` timeout reporting and mid-read revocation checks:

- **Cooperative bounded Antigravity capture and projection yields**: Decomposes
  `Adapter._snapshot`, `_recover`, `capture`, `_steps`, `_generations`, child
  subagent `verify_senders`, and message sanitization `_record` into cooperative
  generator checkpoints (`capture_iter`, `snapshot_iter`,
  `snapshot_for_inheritance_iter`, `_record_iter`) while preserving all TOCTOU
  re-snapshots, SQLite WAL/SHM consistency checks, and `_CAPTURE_CACHE`
  four-group physical-stamp bindings. Cold large paired-transcript Antigravity
  Desktop sessions complete discovery, continuation, `view="all"` pagination,
  and `view="latest_turn"` reads under formal macOS background QoS without
  crossing the per-step supervisor watchdog.
- **Honest `v2` timeout status and revocation enforcement**: Marks non-data
  worker control replies (`processing_timeout`, `resource_exhausted`,
  `restart_required`, `snapshot_expired`) as `control_only` in
  `IsolatedHistory._call` so genuine worker timeouts return structured
  `processing_timeout` / `restart_required` (and degrade only the affected
  source in aggregate `find_agent_threads` with `warnings=["processing_timeout"]`)
  instead of falsely raising a topology validation error, while enforcing live
  `v2` project, source, and `denied_threads` revocations fail-closed before and
  after worker control replies.

# 0.5.4 candidate (targeted L4 remediation over 0.5.3)

Restores verbatim preservation of literal `<subagent_notification>` text in
public human and assistant messages across all four history sources while
retaining provenance-based filtering of genuine tool-generated multi-agent
completion notifications:

- **Native provenance vs. literal text separation**: Removed
  `"subagent_notification"` from shared `INTERNAL_TAGS` in `sanitize()`, so
  human-authored or assistant-authored discussions quoting closed or unclosed
  `<subagent_notification>` tags (in Codex titles/messages, Antigravity,
  DeepSeek Harness, and Codeg) remain 100% intact and searchable without
  `[OMITTED: internal context]` substitution or tail truncation. Genuine
  `wait_agent` completion notifications in Codex continue to be excluded via
  native `internal_chat_message_metadata_passthrough` provenance
  (`provenance.type != "user"` / `multi_agent.*` item kinds), preserving full
  bidirectional parent/child isolation.

# 0.5.3 candidate (targeted L4 remediation over 0.5.2)

Closes bidirectional public-view and search-attribution parity on native Codex
`subagent` / `spawn_agent` + `wait_agent` workflows while preserving all verified
`0.5.2` behaviors:

- **Codex `subagent/thread_spawn` own-turn public view and search isolation**:
  Spawned subagent sessions (`session_meta.source` / index `source` declaring
  `subagent`) continue to enforce full ancestor-chain authorization, same-project
  containment, and mid-pagination parent revocation checks (`subagent_thread=true`,
  `parent_context_inlined=false`), while excluding inline-copied ancestor replay
  prefixes from public message projection and search indexing across both
  `read_agent_thread` / `find_agent_threads` and `read_codex_thread` /
  `find_codex_threads`. Normal 1..N-hop `paginated` and inline forks retain
  verified pre-fork parent prefixes.
- **Parent multi-agent tool-notification exclusion**: Client-generated
  `role="user"` blocks carrying non-`"user"` provenance (such as `wait_agent`
  `<subagent_notification>` items with `provenance.type == "tool"` /
  `multi_agent.*` content kinds) are excluded from public user messages and
  search indexing so child-only reply text never falsely appears as a user
  utterance or search hit on the parent thread.
- **Deterministic fd-reuse check in chunked export expiry tests**:
  `tests/test_chunked_export_expiry.py` verifies snapshot inode closure across
  concurrent `'new-key'` descriptor integer reuse without relaxing `EBADF`
  assertions on non-concurrent cases.

# 0.5.2 candidate (targeted L4 remediation over 0.5.1)

Closes both L4 re-verification blockers and the Antigravity cache stamp-binding
audit finding while preserving every verified v0.5.1 capability:

- **Codex attached side-threads, `auto-compact-*` bridge filtering, and
  multimodal `<image>` wrapper deduplication**: Attached Codex Desktop sessions
  (`session_meta.attached_thread=true` or `attached_thread_parent_id`) still
  enforce full ancestor-chain authorization and same-project containment
  (including mid-pagination parent revocation checks), while projecting only
  the attached session's own verified public messages (`attached_thread=true`,
  `parent_context_inlined=false`) in 1:1 alignment with the official Codex
  client; normal non-attached `paginated` forks retain cutoff-verified pre-fork
  parent reconstruction across 1..N hops. System-generated `auto-compact-*`
  handoff envelopes are filtered unconditionally so internal compaction bridges
  are never attributed to the user. Synthetic `<image ...>...</image>` text
  wrappers surrounding attached image blocks are stripped prior to mirror
  deduplication, eliminating duplicate multimodal user entries while preserving
  genuine consecutive identical user messages and literal user `<image>` text.
- **Corrupted/truncated `manifest.json` rollback recovery**:
  `tools/release_cutover.py` writes payload files and commits `manifest.json`
  last via atomic sibling temp-file + `fsync` + `os.replace`, normalizes all
  manifest/payload decode and I/O errors in `_verify_payload`, and recovers
  cleanly via standard `rollback --confirm-rollback` from 0-byte, truncated
  mid-JSON, invalid-UTF8, missing-manifest, and partial-payload states while
  preserving `runtime/work/` and enforcing prior live revocations, expired
  `thread_ref`s, and expired `cursor`s.
- **Antigravity `_CAPTURE_CACHE` full-dependency stamp binding**: Samples
  `INDEX` (+WAL/SHM), native trajectory DB (+WAL/SHM), compact/full transcripts,
  and all related child subagent DBs (+WAL/SHM) prior to reading and requires
  strict four-group stamp equality after TOCTOU re-verification before storing
  a cache entry, closing any concurrent post-verification drift window.

# 0.5.1 candidate (L4 remediation over 0.5.0)

Addresses all L4 independent acceptance findings while preserving every
verified v0.5.0 capability and keeping all 48 pre-Git legacy threads isolated:

- **Codex paginated fork prefix reconstruction & unified `latest_turn` parity
  (H1 + H2)**: Reconstructs verified same-project pre-fork public prefixes for
  sparse `paginated` Codex forks (1-hop and N-hop chains) strictly bounded by
  native `history_base` (`thread_id`, `end_ordinal_exclusive`,
  `end_byte_offset`), preventing any post-fork parent appends from bleeding
  into forked child threads while revalidating ancestor prefix digests across
  pages. Forks missing verifiable cutoff evidence or failing cutoff alignment
  never expand unaligned parents and explicitly warn
  `inherited_prefix_unverified` (`complete_public_projection=false`); denied or
  cross-project ancestors fail closed. Unified `read_agent_thread(view="latest_turn")`
  and `supports_turns` now align with `read_codex_thread` via declared
  `latest_turn_id` and `ambiguous_turn_ids` so pre-turn bridge records without
  `turn_id` no longer cause `turn_unavailable`.
- **Restored Antigravity commit-boundary protections & explicit contract
  documentation (H3)**: Re-wired generalized invariant-driven commit-boundary
  verification in `agent_history_antigravity_commit.py`, restoring all five
  `.12` commit-boundary protections (errorless generation rejection, mismatched
  requested `call_id` rejection, error-after-final-reply temporal rejection,
  zero-result and sole-`PENDING` state transition checks on discarded proposals,
  and completed-executor terminal reply checks) while remaining generalized for
  all built-in tools, Checkpoint-compacted `status=5` steps, and errored
  non-4 executors. Closed idle threads with verified discarded proposals emit
  `missing_steps` without a spurious `thread_in_progress` warning. Documented
  all intentional `.12 -> v0.5.x` contract evolutions in `AGENT_HISTORY.md`.
- **Release cutover recovery & strict health gate (H4)**: `tools/release_cutover.py`
  rollback now recovers cleanly even when an interrupted deploy left
  `manifest.json` alongside missing or corrupted payload files (recording
  `previous_state: "incomplete_or_corrupt"` while preserving `work/` and live
  policy/revocations). Service restart probing strictly requires both a live
  PID and expected auth-gate HTTP status (`401`); HTTP `503`/`5xx`/`200` or
  timeouts fail non-zero and write no success receipt.
- **Warm query latency optimization (P1)**: Added strictly stamp-bound,
  authorization-free LRU proof, projection, and ancestor-prefix caches inside
  `HistoryAccess` (shared across transient projections while keeping legacy
  snapshot budgets isolated and always re-checking live `fstat` stamps,
  SQLite metadata, and live ACL/policy scopes), a strictly stamp-bound,
  authorization-free worker-local Antigravity `_CAPTURE_CACHE` (re-validating
  live `fstat` stamps of `INDEX`, trajectory DB + WAL/SHM, transcripts, and
  child subagent DBs on every hit while never caching in-flight threads), and
  batched Codex scope revalidation in `validate_agent_hits`. Eliminates
  repeated full-rollout disk re-scans, duplicate long-thread captures, and
  redundant `git worktree list` subprocesses, bringing real 7-project warm
  single-request P95 well below the 3.0s target.

# 0.5.0 candidate

Productized four-source agent history reliability, attribution safety, and external
ChatGPT usability derived from `0.4.4-progressive.12`:

- **Physical occupancy & durable path tombstones (D1)**: Removed false rejections
  caused by unrelated sibling or project-file edits updating parent `st_ctime_ns`
  equal to `st_mtime_ns` on macOS APFS, while preserving strict rejection of
  directory replacements, renames, copies, ancestor swaps, and symlink reuse.
  Added durable owner-only `.path-tombstones.json` (`0600`) clamping replaced or
  revoked paths while keeping `active.json` 100% compatible with `.12` rollback.
  Added bounded Codex `forked_from_id` ancestor chain resolution (`MAX_FORK_DEPTH=8`)
  and per-context subdirectory timestamp spans (`context_spans`) for mid-session
  subdirectories while keeping pre-Git threads conservatively isolated.
- **Invariant-driven Antigravity dual-track reader (D2)**: Replaced brittle
  per-field allowlists with security-invariant verification across DB and
  `transcript_full.jsonl`. Supports semver `2.32.1` and `2.33+` with live SQLite
  schema probing, Checkpoint-compacted `status=5` steps with full-transcript
  cross-verification (`compacted_steps_from_transcript`), slash-command prefixes
  strictly inside `<USER_REQUEST>`, attachments, active `RUNNING` threads
  (`thread_in_progress`), deterministic `turn_id` (`turn:<idx>`) enabling
  `view=latest_turn` and `view=turn`, invariant-driven child subagent containment
  (including killed children while strictly blocking workspace overrides, forks,
  and external user inputs), and child-aware path migration review. Eliminates
  dependency on frozen non-migration static exceptions.
- **Four-source honest coverage & policy tooling (D3)**: Codeg reports project-scoped
  `unsupported_agent_types` (such as `antigravity` ACP threads stored outside
  registered roots) and unlinked native providers honestly without leaking titles
  or bodies. DeepSeek performs bounded full-partition header verification on
  small stores so clean projects report complete coverage while corrupt or large
  stores degrade honestly. Added zero-leak `unverified_project_candidates` counts
  plus `agent_history_admin lint` and `preview-coverage`.
- **External ChatGPT UX, performance & append-safe pagination (S5)**: Empirically
  sized worker pool to 4 slots (1 per registered source), eliminating worker
  eviction churn while keeping the 256 MiB per-worker RSS limit. Bounded
  multi-source aggregate completes fast four-source queries in a single round-trip.
  Added NFKC + casefold multi-tier search (`substring` ranked ahead of `token_all`),
  zero-hit `total_project_threads` / `browse_hint`, rich thread summaries
  (`message_count`, `supports_turns`, `is_in_progress`), strict monotonic
  append-safe initial reads and mid-pagination (`appended_since_snapshot`), and
  explicit anti-hallucination tool instructions.
- **Release & rollback hygiene (D4)**: Added parameterized manifest-driven
  `tools/release_cutover.py` (`status`, `preflight`, `deploy`, `rollback`)
  ensuring code rollback never reverts policy generations or reactivates revoked
  permissions. Candidate release remains isolated pending independent acceptance.

# 0.4.4-progressive.12 development candidate

Antigravity Desktop 2.33.0 history can remain searchable after a native file
write, an interrupted tool proposal, or a supported reply from a directly
spawned subagent. Both transcripts, the native workspace, executions and
typed user and assistant records are checked. Shared log gaps remain
visible in the result. A later model context can corroborate an older user
turn at its original position. Contradictory retained evidence prevents
delivery.

# 0.4.4-progressive.11 development candidate

The same authenticated ChatGPT caller uses one allowlist for project files,
candidate saves, configured native file operations and verified history
from every enabled source. Project removal invalidates the old project
generation even if the same root is later added. A confirmed candidate
can create the default candidate directory using create-only rules.

Antigravity Desktop 2.33.0 can automatically associate supported top-level
local sessions using the saved trajectory, individual step origins and
execution records. The adapter checks these against the public transcript.
Unverified sessions retain incomplete coverage. Reviewed historical
exceptions retain their existing gap warnings.

For directory and worktree grants, v2 checks that the same physical project
occupied the recorded location throughout the conversation. It uses native
creation and completion times from the configured history source. When a
directory moves, the local migration preview can recover reviewed historical
snapshots. Reusing the former path cannot add later conversations to them.
Git attribution covers both the working directory and its repository
metadata. A newly registered repository in an existing working directory
can expose verified sessions begun under that repository. Background
observations rotate through bounded sets of registered worktrees.

Cross-source searches resume active source checks before starting another
worker. Larger pages can return a shorter sorted prefix with a continuation.
Each merged result retains its matched sources and their verification.
Codex projection and linked Codeg records use an operation-local native
snapshot. Successive project queries keep the existing legacy snapshot
capacity available for its public page and tool cursors.
The native snapshot supplies its own verified project grant if a new message
arrives during discovery. Confirmed candidate saves also pass their commit
deadline through the configured private-file registry.

Background saves, candidate creation, history workers and streamed exports
carry evidence of the verified Git worktrees through to their commit or
delivery boundary. This candidate remains in isolated verification.

Unified stdio validates authorization at each bounded kernel write. It
supports protocol output to a pipe, socket or terminal. The v1 transport
retains its existing behavior.

# 0.4.4-progressive.9 development candidate

The unified history policy uses one verified caller roster and one project
allowlist across enabled sources, including legacy Codex tools. Migration is
previewed locally. Immutable policy generations and the history response
commit check prevent stale delivery after a policy change.

Antigravity 2.33.0 attribution remains incomplete. The signed Hook observations
establish the metadata recorded at the observed callbacks. Production requires
verified workspace history through the committed native log for new sessions.

# 0.4.4-progressive.8

Standalone Antigravity policies may omit the app format label. The reader
checks the local v3 index and native transcript, while preserving the existing
caller, project and thread grants. Explicit labels `2.32.1` and `2.33.0` remain
accepted.

# 0.4.4-progressive.7

When Antigravity's compact and full logs agree step for step, matching gaps
no longer prevent recovery of verified visible text. The response still
reports `missing_steps` and incomplete coverage. Asymmetric records and
partial tails continue to disqualify companion recovery.

# 0.4.4-progressive.6

Antigravity restores truncated visible messages from the matching native full
transcript. The compact transcript anchors the visible steps and the expected
UTF-8 byte count of the omitted text. Both files bind the snapshot; changes
require a fresh read. An unavailable or incompatible companion preserves the
compact projection and its truncation warning. The tool schema, visibility
filters, and explicit Antigravity thread grants are unchanged.

# 0.4.4-progressive.5

Optional project-scoped agent history adds common search and paged reading for
Codeg, DeepSeek Harness and Antigravity, with the existing Codex reader available
through the same tools. Additional source grants default to disabled. See
[Agent history](AGENT_HISTORY.md) for the supported versions and acceptance
conditions.

# Project-wide public history 0.4.4-progressive.4

This snapshot derives from frozen 0.4.4-progressive.3. With inherit_projects
enabled, both configured directory subtrees and identity-pinned repositories
grant public-history access to existing and future Codex threads. Every saved
context and the current index cwd must resolve to one authorized project.
Directory grants never follow symlinks or authorize external worktrees.
Nested projects use the closest configured root; duplicate roots are ambiguous.
All project identities bind cursors and are revalidated before returning data.
Explicit denies, fork ancestry checks and separately authorized tool evidence
remain enforced. Defaults do not enable history or change local policy.

The public-jsonl-stream-v4 reader supports bounded in-memory Zstandard decoding
and the exact compressed sibling of a legacy .jsonl index path. Truncated or
corrupt frames fail closed. Snapshot hashes and offsets refer to decoded JSONL;
storage_encoding and stored_bytes distinguish its on-disk representation.
Missing sources have a distinct source_unavailable error.

Large excluded records up to 64 MiB receive full JSON validation with bounded
metadata projection, preserving context and fork proofs without materializing
attachments or compaction snapshots. Full record projection remains 12 MiB;
the existing worker budgets and incomplete-history warnings remain enforced.
Known public asynchronous messages retain phase, channel and thread checks;
injected harness/AGENTS blocks are excluded from public user content. Search
limit validation now exposes the existing 1-20 bound in the MCP schema.

Python below 3.14 adds pinned backports.zstd==1.8.0; newer Python uses the
standard library. No machine configuration, credentials, real conversation
data or deployment automation is included. Per-host deployment and policy
migration require that host's own validation and authorized project scope.
After migration, redundant per-thread grants should be removed so project
revocation is not bypassed by an independent explicit exception.

File/export implementations, receiver/loader bytes and durable job formats
remain the frozen .3 implementation. Earlier deployment and native-receipt
results below are historical evidence, not new acceptance for this snapshot.

# Chunked parent expiry after suspend 0.4.4-progressive.3

This candidate derives from the frozen 0.4.4-progressive.2 snapshot. A chunked
parent expires when either its original monotonic deadline or its declared
fixed Unix deadline is reached. The same rule governs admission, preparation,
status, plans, materialization, resource owners, final sends and reaping.
Expiry is terminal; polling, refreshed authentication and wall-clock rollback
do not revive an expired parent or change its immutable plan and hash.

Retirement retains the existing descriptor, pin and owner cleanup protocol.
Reservation is released only after actual preparation/response owners and
SDK/ASGI completion are confirmed. Unknown closure remains pending. The
legacy whole-resource clock and grace behavior, receiver/loader bytes,
raw-parts-v1 fields, capacity settings, permissions and persistent job schema
are unchanged. Delivery-slot timing retains its existing semantics subject
to the parent's fixed deadline; this is not a global clock replacement.

Independent-clock tests with real temporary IO validate the sleep-time
mismatch. They are not an actual-machine suspend test. This source does not
assert deployment or native receipt, nor resolve the separate platform route
selection behind ordinary attachment receipt failures. Results belong to
the execution and root version index, not a rewritten frozen package.

# Native received-input compatibility 0.4.4-progressive.2

This candidate separates host-delivered read-only helper/part files from
receiver-owned mutable files. The qualified POSIX input policy permits the
current user or UID zero, with ordinary single-link non-writable-by-others
files, exact byte pins and descriptor/path/root identity checks. UID zero is
not source authorization or proof of code authenticity. Private sessions,
control files and published output retain current-user ownership protections.

One explicitly packaged standard-library loader reads and verifies the actual
helper source buffer, then executes exactly that buffer after successful
descriptor closure. It does not use path imports or cached bytecode. Input
leases traverse the bound input-root descriptor and close successfully before
accepted progress is committed. Cross-directory session-to-output publication
primitives are preflighted before large-part receipt.

The raw-parts-v1 API, part geometry, capacity tier, legacy channel, source
authorization and persistent job schema remain as described below. This source
does not assert deployment, native receipt or 30 MB capacity qualification;
new code, true cross-UID, release, native and production gates require actual
evidence for this fingerprint.

# Progressive original export 0.4.4-progressive.1

This candidate derives from the fixed 0.4.3-context.4 source snapshot. It adds a
default-off raw-parts-v1 channel with an initial configured limit of 30,000,000
bytes and fixed 8,000,000-byte resources. The original whole-resource tools,
ResourceLink behavior and 12,659,780-byte bound remain in the legacy namespace.

New preparation/status/plan calls are metadata only. Explicit part/helper
materialization uses the standard authenticated SDK resource response and the
current source/private identity guards. Parent records and idempotency keys are
mode-bound; snapshot, metadata, space and actual response budgets are shared.
Token issuance and actual reads have separate bounded counters. No client
receipt is inferred from source readiness or send completion.

The pinned standalone receiver verifies actual helper and native part bytes,
revalidates same-plan pending/duplicate work, and publishes a fully verified
original using same-filesystem no-clobber hardlink only. Cross-new-plan prefix
recovery, missing-ledger reconstruction and copy publication fallback are not
part of this release. Native host hardlink/fsync/tool capabilities remain
explicit preflight gates.

Read-only v2 code-switch preparation and narrowly scoped owned pre-target abort
support staged origin-only activation. Durable complete restoration bindings
precede abort completion; partial transactions and committed runtime fallback
remain separate. No path restores an old database, ledger, grants or published
facts. An inspection-only compatible rollback retains protection and reads.

Protocol/helper/part geometry remain stable for later separately approved
50/70 MB configuration tiers. A higher parser ceiling is not capacity evidence.
This source archive contains no credentials, machine scope, production data or
native original. Build, implementation tests, native receipt, format use and
production activation require their own actual receipts.

The inherited context.4 baseline repairs remain part of this source; their
historical release description follows without asserting new native acceptance.

# Completed native receipt compatibility 0.4.3-context.4

This source snapshot derives from 0.4.3-context.1. It separates persistent macOS filesystem identity (volume UUID, file ID, integer birth time) from runtime device/inode checks. Protected roots and newly registered repositories survive device-number renumbering; replacement and cross-repository checks remain closed.

This update adds a narrowly scoped historical-receipt lookup for completed native-file jobs whose actor/key, target and bound hash/length constraints match. It requires a current matching epoch, a fully published/durable/verified/exited original job and read-only target validation. The nested original_job_status describes the old job only; the new reference is not received, content-verified or source-approved. No new job, transfer, source refresh, authorization change or stored-row migration occurs. Strict intent replay and ordinary status behavior remain unchanged. Safe diagnostic auditing uses fixed booleans only.

Repository pins use versioned git-v2 values. Legacy v1 pins remain exact-match only, and existing worktree selectors are unchanged. A local, plan-bound maintenance transaction adopts verified v1 anchors and migrates only the protected manifest, project pins and origin startup definition. It never automatically rebinds a failed authorization.

File jobs retain SQL schema version one and historical rows. New jobs bind a boot/device epoch. Cross-epoch unfinished work is isolated, publication uncertainty remains unknown, and aggregate new-job admission is separate from continuation of current legitimate work. Inspector checks reject unsafe SQLite sidecars without creating SHM state.

The protected Cloudflare entrypoint reports safe startup stage/error codes. Check mode starts neither file writers nor export workers and diagnoses invalid repository pins.

Candidate and compatible rollback packages share identity protection; rollback is fixed to inspection-only operation. Maintenance tooling is frozen separately, serializes operators, persists origin disable during transactions, verifies both existing locks and complete backups, and separates migration recovery from post-activation switching. Current databases and newly accepted jobs are never rolled back to an earlier backup.

Testing and deployment receipts belong to each execution. This archive does not assert that any machine has deployed it, that a client received an attachment, or that a real reboot has been accepted. No authorization, credentials or production artifacts are packaged.

The public-history scanner now strictly parses individual JSONL records up to twelve MiB, covering legitimate response items larger than the former eight-MiB record limit. Oversized, malformed, unknown and foreign-context records remain denied. The worker's existing 256-MiB resource guard and 128-MiB snapshot-cache limit are unchanged. No project or history authorization policy is added or relaxed. This code-only compatibility update retains the version-two identity infrastructure and existing job schema/facts.
