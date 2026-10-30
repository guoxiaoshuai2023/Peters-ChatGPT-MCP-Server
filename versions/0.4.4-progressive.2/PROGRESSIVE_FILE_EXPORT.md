# Progressive original file export

This candidate adds the default-off `raw-parts-v1` channel on the fixed
`0.4.3-context.4` identity/history/receipt baseline. Its first configured tier is
30,000,000 bytes. A configured limit, source archive or successful build does
not establish native receipt or production capacity acceptance.

The existing whole-resource channel remains capped at 12,659,780 bytes. Its
tools, ready ResourceLink, `peters-export://` URI and expiry semantics remain.
Chunked tools use a separate request-key namespace and `peters-chunk://`
delivery references. Both channels share snapshot, metadata, disk and active
response budgets. Never pass an ID from one channel to another.

## Transport and capacity

One authorized ordinary file is captured into one private disk snapshot.
The service calculates the whole-file and per-part SHA256 values. Every part
is at most 8,000,000 bytes and uses the existing standard authenticated MCP
binary resource response. The complete original is assembled and independently
verified in the native environment. Video, PSD and ZIP bytes remain unchanged;
format interpretation is a separate client capability.

| Configured tier | Number of parts | Protocol and receiver |
| --- | ---: | --- |
| 30,000,000 bytes | 4 | raw-parts-v1 |
| 50,000,000 bytes | 7 | unchanged; separate future approval and acceptance |
| 70,000,000 bytes | 9 | unchanged; separate future approval and acceptance |

The 100,000,000-byte parser ceiling prevents unbounded metadata/offsets. It is
not a verified capacity. Future tiers use new create-only private config files
and a newly bound runtime plan, preserving the active configuration unchanged.
The protocol, helper and fixed part size need no per-tier rewrite.

## Explicit private configuration

Copy `chunked-exports.example.json` to a new file in the existing private
application-support directory. It must be owned by the current user, regular,
single-link, mode 0600, with only its documented fields. The default is disabled.
Its initialized private spool and all source permissions come from the current
original-export infrastructure. No root, account, authorization or source
allowlist is added by enabling the channel.

The authenticated Cloudflare entrypoint accepts:

```sh
python -B run_release.py --access-config /absolute/path/to/access.json \
  --config /absolute/path/to/projects.json \
  --file-config /absolute/path/to/original-files.json \
  --file-export-config /absolute/path/to/original-exports.json \
  --chunked-export-config /absolute/path/to/new-chunked-exports.json \
  --port 8766 --check
```

Retain all actual existing startup arguments. Check mode and compatible
inspection rollback start no export/file workers. The unauthenticated local
entrypoint can validate the policy with `--check`, but refuses to serve an
enabled chunked policy. Enablement and origin-only deployment use a separately
reviewed exact runtime plan and fresh authenticated health evidence.

## Native workflow

1. Read `list_projects.chunked_export` and the current original-export instance
   and request window. Explicitly choose the authorized project/worktree/path.
2. Call `prepare_chunked_export` with a fresh request key. Poll only
   `get_chunked_export_status` while preparing; both are metadata only.
3. Obtain `get_chunked_export_plan`. It binds the same snapshot, whole length
   and SHA, contiguous part geometry and hashes, helper identity and fixed
   expiry. Plan/status calls do not materialize bytes or renew the deadline.
4. Call `materialize_chunked_export_receiver`. Use the one reviewed
   `tools/native_receiver_loader.py` template, checking its actual text SHA
   against the independently reviewed release. Pass the actual received path,
   selected input root and its observed identity, the independent release
   helper pin, and the actual plan asset. The loader verifies the same bounded
   source bytes it executes after closing all input descriptors. It traverses
   from the bound input root without symlinks and does not use path imports or
   cached bytecode. Never execute business source, parts or ZIP members.
5. Create one new current-user-owned output leaf with mode 0700 (inherited
   02700 is allowed), then start its nonce session. The early preflight covers
   actual session-to-output no-clobber hardlink, file and both directory fsyncs,
   plus available space before large part receipt. Do not chmod a platform
   root or reuse a failed run's directory.
6. Sequentially call `materialize_chunked_export_part` for each index. Use
   actual received native paths, independently measure each length/SHA, and
   `ingest(index, actual_part_path)`. Host renaming is allowed; the bytes and
   selected index must match the plan. Do not guess or fabricate paths/IDs.
7. `finish()` independently verifies the assembled whole file and publishes
   only by same-filesystem no-clobber hardlink. There is no overwrite rename or
   silent copy fallback. Native caller then independently opens the final
   file and recalculates its whole length/SHA before format-specific use.
8. Preserve actual plan, part, final and source capture evidence before
   `cancel_chunked_export`. Cancellation reports released only after real
   resource owners, SDK/ASGI tasks and handles have exited. It never deletes
   native inputs or published output.

The standalone `NativeChunkReceiver` API is `start`, `resume`, `ingest`,
`status`, `finish`, `cancel` and `cleanup`. Resume binds exactly the same plan
and actual files. Duplicate ingestion revalidates both copies and appends zero
bytes. Missing/mismatched ledgers, unknown publication state and changed
identities are preserved and refused; no records are invented to continue.

Host-delivered helper and part files have a distinct read-only policy:
ordinary single-link files readable by the OS, owned by the current user or
UID zero, with no group/world write or special permission bits. This is a
bounded POSIX host profile; UID zero is not provenance or source authorization.
Private state remains current-user-owned and mode 0600. Input leases validate
the bound root, parent route, descriptor/name metadata and exact part hash,
then complete all input checks and closes before accepted progress is stored.
An error can still leave real pending bytes or uncertain committed progress;
preserve those facts rather than assuming every error means no write occurred.

`tools/render_native_acceptance_prompt.py` renders the exact loader template
with structured external data and independent release pins. Qualification
requires the actual public execution code and received file measurements,
not only a claimed loader hash. The fixed helper's own source check remains
an additional defense after verified-byte loading.

## Bounded lifetime and failure

A parent expires 3600 seconds after acceptance. Each delivery is bounded by
600 seconds and the parent deadline; each new source request and resource
lease also checks its current verified actor deadline and permissions. Neither
metadata polling nor refreshed authentication revives an expired parent.
Each part/helper slot has at most three token issuances and three actual reads,
counted separately. Repeated metadata lookup of a valid token uses no new read
attempt; busy or not-yet-exited owners retain their reservations.

Temporary same-part errors allow at most two extra reads. Integrity, identity,
scope, ledger or publication failures stop the run. Source expiry/cancellation
stops remote retrieval but cannot revoke already-held native bytes; those may
still be verified and completed under the same plan. Missing parts after source
expiry require an explicit new run from the beginning, without mixing plans.
Receiver cancellation is a separate local stop intent and forbids continuing.

An acceptance instruction may explicitly authorize bounded source-only cleanup
for its own known export after preserving a failure. That exception permits
only cancellation/status of the same bound export, never new materialization,
receiver cleanup, deletion or cancellation of unknown tasks. Keep real release
responses and exact-ID source audit; expired/cancelled alone does not prove
owners, descriptors and reservations were released.

The first-tier native qualification is limited to the actual tested host/model
and fixture. Server ready, configured capacity and `server_stream_finished`
never mean `client_received`. Native whole-file length/SHA and ZIP/PNG use,
resource release, legacy regression and production checks are separate evidence.

## Maintenance

Use `prepare_code_switch.py` for read-only v2 code-switch preparation; legacy
v1 inspect and historical fixed-job-count preparation scripts are unsuitable.
The plan binds all current rows, immutable config, stable identities and exact
candidate/rollback/maintenance bytes. The private manifest/project pins are NoOp.

Pre-target failure and committed-runtime fallback have different authority.
An independently reviewed BEFORE-only abort can restore the prior frozen
operation through a new switch and fresh health receipt. Partial transactions
remain under their exact recovery journal. No recovery restores an old database
or silently rebinds private identity. Compatible inspection rollback disables
new export and write work while preserving reads and historical job facts.
