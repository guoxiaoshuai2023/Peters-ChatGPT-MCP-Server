# History-only release 0.4.1-history.1

Production baseline: `2d39fe2938c1f8bf022885287637396f2347e08b`. History implementation: `78c2ae547f40b6254a0ab762c0ad339e69fdcb0e`.

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
