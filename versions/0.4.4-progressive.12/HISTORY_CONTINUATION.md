# History continuation recovery

This change is limited to history reads. It does not change project grants,
OAuth, the tunnel, candidate writes, file package delivery or installed plugins.
A local candidate is not a production deployment.

## Confirmed defects and evidence limits

A processing cursor from a stopped worker returns `restart_required`. Previously,
when no request was waiting at the moment of termination, the stop cause was lost.
Existing records without a worker cause cannot retrospectively distinguish a
watchdog timeout, memory guard, worker exit or IPC failure.

Two independent regressions are fixed:

- A retained result used to lose its validation recipe after 16 newer results,
  although the worker could retain 64 tasks. The recipe now lives privately on
  its result and is released with that result. It never enters JSON or IPC.
- Verifying an older snapshot after one append used to discard the current
  projection identity and other verified prefixes. Alternating old and current
  pages could exhaust the eight-snapshot limit. Evidence is now merged only for
  the exact same path, complete file stamp, verified length and hash.

Background replay also reproduced the 3-second watchdog terminating a result
during delivery after its final checks had completed. Completed configuration
and metadata checks were previously
invisible to the watchdog until the enclosing generator yielded. The supervisor
now recognizes completion of a fixed set of synchronous checks and complete
bounded IPC responses as progress. Concurrent duplicate deliveries are covered
by the same rule. The parent drains available IPC in bounded passes before
making a watchdog decision. Short reads can leave a response incomplete with
its idle marker still queued behind it; actual incoming byte progress during
that bounded delivery is recognized without treating a partial frame as a
complete response. Each frame's size and the existing child send deadline stay
unchanged. A quiet or blocked send still times out.
It does not yield control to another history task inside the final authorization
guard. A single blocked check, parser operation or unresponsive worker still
hits the same 3-second limit. There is no periodic heartbeat and no increased
memory, snapshot, request, IPC or time limit.

Reproducing this path does not establish the cause of earlier production events
whose worker diagnostics were not recorded. A subsequent production window must
validate both actual continuation behavior and the client's tool definitions.

## Private operational diagnostics

Only fixed event/reason/stage labels, worker epochs, local task counters, the
three operation names, elapsed milliseconds, waiter/task counts, memory counters
and exit codes are emitted. No source text, paths, thread identifiers, titles,
queries, cursor signatures, credentials or exception text are included.

The in-memory event ring holds 256 records. Reasons for the last 16 stopped
worker generations are retained privately so a delayed stale cursor can be
correlated with its actual stop reason. Diagnostic sink failures do not change
read behavior. These diagnostics are separate from existing request auditing.

## Validation and rollout

Synthetic regression tests cover delayed and repeated pickup after 24 newer
responses, same-worker reads, append followed by old/current paging, revocation,
foreign context rejection, recipe release, JSON privacy, completed-check
progress, concurrent duplicate responses, and genuine check/send timeout enforcement. Real-data evidence is kept outside
Git; only explicitly authorized threads are read and no original source is
modified. Complete pagination requires a terminal `has_more=false`, contiguous
message fragments and a digest comparison; summing duplicate audit counts is
not sufficient. Latest-turn and specified-turn results must match the same
turn in the full projection.

Build the history-only candidate from the pinned rollback baseline, preserving
all non-history behavior. Keep configuration, credentials and test records out
of the release archive. Production switching and connector reconstruction need
separate authorization; source validation alone does not mark the feature live.

## ChatGPT metadata

For a developer-mode connection, OpenAI documents **Refresh**, metadata review,
and a new conversation as the schema update path:
https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata

Account **Reconnect** is not a documented equivalent of metadata refresh. If
Refresh is absent, verify the creator/developer management surface and connector
type before changing anything. Published plugins have a separate continuous
review path. Do not uninstall or rebuild an existing connection as a trial fix.
A rebuild may require OAuth login/consent, create a different connection or
client identity, and require selecting the connection again in conversations;
permission and conversation-binding migration must not be assumed.
