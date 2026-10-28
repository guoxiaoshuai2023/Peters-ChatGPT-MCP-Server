# Completed native receipt compatibility 0.4.3-context.4

This source snapshot derives from 0.4.3-context.1. It separates persistent macOS filesystem identity (volume UUID, file ID, integer birth time) from runtime device/inode checks. Protected roots and newly registered repositories survive device-number renumbering; replacement and cross-repository checks remain closed.

This update adds a narrowly scoped historical-receipt lookup for completed native-file jobs whose actor/key, target and bound hash/length constraints match. It requires a current matching epoch, a fully published/durable/verified/exited original job and read-only target validation. The nested original_job_status describes the old job only; the new reference is not received, content-verified or source-approved. No new job, transfer, source refresh, authorization change or stored-row migration occurs. Strict intent replay and ordinary status behavior remain unchanged. Safe diagnostic auditing uses fixed booleans only.

Repository pins use versioned git-v2 values. Legacy v1 pins remain exact-match only, and existing worktree selectors are unchanged. A local, plan-bound maintenance transaction adopts verified v1 anchors and migrates only the protected manifest, project pins and origin startup definition. It never automatically rebinds a failed authorization.

File jobs retain SQL schema version one and historical rows. New jobs bind a boot/device epoch. Cross-epoch unfinished work is isolated, publication uncertainty remains unknown, and aggregate new-job admission is separate from continuation of current legitimate work. Inspector checks reject unsafe SQLite sidecars without creating SHM state.

The protected Cloudflare entrypoint reports safe startup stage/error codes. Check mode starts neither file writers nor export workers and diagnoses invalid repository pins.

Candidate and compatible rollback packages share identity protection; rollback is fixed to inspection-only operation. Maintenance tooling is frozen separately, serializes operators, persists origin disable during transactions, verifies both existing locks and complete backups, and separates migration recovery from post-activation switching. Current databases and newly accepted jobs are never rolled back to an earlier backup.

Testing and deployment receipts belong to each execution. This archive does not assert that any machine has deployed it, that a client received an attachment, or that a real reboot has been accepted. No authorization, credentials or production artifacts are packaged.

The public-history scanner now strictly parses individual JSONL records up to twelve MiB, covering legitimate response items larger than the former eight-MiB record limit. Oversized, malformed, unknown and foreign-context records remain denied. The worker's existing 256-MiB resource guard and 128-MiB snapshot-cache limit are unchanged. No project or history authorization policy is added or relaxed. This code-only compatibility update retains the version-two identity infrastructure and existing job schema/facts.
