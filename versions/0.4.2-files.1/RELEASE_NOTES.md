# Original-file save development candidate — pending production approval

This development snapshot adds opt-in, create-only native original-file saving,
persistent private-root protection, bounded background reception, and a compatible
inspection-only rollback mode. No production upgrade is claimed by this document.
Original file bytes are not transcoded or unzipped; existing entries are never replaced.
Only macOS has been the local validation platform; other platforms require their own
publication, durability and recovery acceptance.

Candidate and rollback artifacts are built from one explicit reviewed source selection.
Generated release markers give them distinct content fingerprints. Rollback retains
private protection and the read-only inspector, forces file inspection mode even through
direct module entrypoints, and never starts file writers. Both artifacts require explicit
local private configuration; no machine configuration or credentials are bundled.
A bare historical baseline is not a compatible rollback after private storage is introduced.

Use ORIGINAL_FILE_SAVE.md for operating boundaries, approval-dependent switching,
source-completeness limitations, content fingerprints and recovery preparation.
The following history-only notes document the inherited baseline; their old rollback
recipe is superseded for original-file deployments by the protected rollback above.

## Inherited history-only baseline

### History-only release 0.4.1-history.2

Production baseline: `2d39fe2938c1f8bf022885287637396f2347e08b`. History implementation: `working-tree-at-78c2ae5`.

Only history processing, history tool routing/lifecycle, safe history diagnostics,
and the backwards-compatible optional `AccessError.code` constructor are changed.
Cloudflare authentication, candidate delivery, repository access, command entrypoints,
tunnel/service helpers and dependency lock files are byte-identical to the baseline.
No original-file package delivery modules or tools are included.

This tree contains no local configuration, credentials, original conversations or
local verification artifacts. Configuration and interpreter paths are supplied by
the local operator's deployment plan. Use an explicit history configuration path;
the default would otherwise be relative to this release tree.

Deployment requires a separately approved origin-only switch window. Existing
history cursors, pending requests and candidate preparation tokens become invalid
on restart. Already written files and original Codex logs are not modified.
Rollback uses the separately pinned baseline tree and restores its 64 MiB limit.
The development checkout must not be used as the rollback source.
