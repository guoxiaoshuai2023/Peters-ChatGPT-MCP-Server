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
