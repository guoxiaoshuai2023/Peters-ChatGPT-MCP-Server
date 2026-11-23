# Agent project file reading

The separate Agent origin serves `/mcp` over Streamable HTTP. Its only tools
are `list_projects`, `list_worktrees`, `list_files`, `search` and `read_file`.
The existing human origin and its v1 history and authentication stay separate.
Start this origin explicitly. A release build or a configured model alone
does not enable it.

## Prepare the isolated environment

Use a distinct loopback port, tunnel ingress, hostname and Cloudflare Access
application audience. Configure Service Auth for individual service tokens.
The origin verifies the signed Access application assertion. A cloud or
browser account, a client name, and a plain Client ID header do not grant access.
Provide the following fields in a private, owner-only endpoint JSON file.

```json
{
  "issuer": "https://example-team.cloudflareaccess.com",
  "audience": "<exact Agent application audience tag>",
  "public_hostname": "agent.example.com"
}
```

Use the exact same private projects JSON path as the human origin for a live
deployment. First carry out rehearsals using a private copy that contains only
synthetic projects. The directory that will hold Agent state must be a dedicated
child of the existing original-file control directory. It is protected from
both origins. Initialize it without enabling any Agent.

```sh
python -B -m peters_mcp.agent_file_admin \
  --projects /absolute/private/projects-active.json \
  --state-directory /absolute/control/agent-read \
  --file-config /absolute/private/original-files.local.json \
  --history-config /absolute/private/history-access.local.json \
  --agent-history-config /absolute/private/agent-history-access.local.json \
  --legacy-runtime /absolute/legacy/runtime \
  --legacy-access-config /absolute/private/access.local.json initialize
```

Keep the access JSON inside the initialized Agent state directory. Verify the
origin configuration before running without `--check`.

```sh
python -B -m peters_mcp.agent_file_origin \
  --projects /absolute/private/projects-active.json \
  --state-directory /absolute/control/agent-read \
  --access-config /absolute/control/agent-read/access.json \
  --file-config /absolute/private/original-files.local.json \
  --history-config /absolute/private/history-access.local.json \
  --agent-history-config /absolute/private/agent-history-access.local.json \
  --legacy-runtime /absolute/legacy/runtime \
  --legacy-access-config /absolute/private/access.local.json \
  --port 8877 --check
```

The shared policy directory, old runtime and audit, history sources, and both
Access configurations are excluded from this origin. Audit goes to a private
file in the Agent state directory. Record the current
human origin fingerprint and v1 configuration before adding ingress. Scope
the separate ingress to the new hostname and confirm host assertion and
audience matching. Run the human baseline smoke checks after the change.

## Review and publish authorization

The Agent roster contains one distinct binding per installation. An input
document contains an `agents` array. Each entry has an operator-selected
`id`, `enabled` boolean, `issuer`, `audience` and `client_id`. Keep secret
values in the corresponding isolated client environment. Enabling a binding
grants that instance the entire active project allowlist.

In the operator command above, replace `initialize` with
`preview --agents-input /private/roster.json` or
`preview --projects-input /private/projects-next.json`. Use
`preview --worktrees` to reverify a new working directory of an existing
project. Capture the output in an owner-only file, review the change and its
digest, then use `apply --preview /private/reviewed.json --sha256 <approved-digest>`.
The origin hot-loads authorized changes. It verifies private filesystem state before
acquiring the authorization lock, then retains both read guards through the
local ASGI response handoff. This keeps slow filesystem probes out of the
operator's revocation lock. Out-of-band project changes and
interrupted transactions stop file delivery. An interrupted operation can
only advance the exact approved transaction with `recover --sha256
<approved-digest>`. Before changing the shared project file, both `apply`
and `recover` revalidate the approved directories and Git registrations. If a
directory has been substituted, restore the approved directory identity or keep
the new listener closed while investigating the interruption. Managing an
individual Agent keeps the project file and approved Git worktrees unchanged.

Revoke an instance by publishing its disablement before switching off the
matching Access service token. A retired Client ID cannot be re-enabled.
A recovered or rotated instance needs a new access credential.

## Connect a client

Direct clients may use Streamable HTTP with the two per-instance Cloudflare
service-token headers if their credential injection has been qualified.
Where stdio is appropriate, launch the isolated relay from the verified
package using an absolute trusted Python executable.

```text
/absolute/trusted/python -I -B /absolute/verified-package/peters_mcp/agent_file_bridge.py
  --credential-file /absolute/private/agent-credential.json --uid <isolated uid>
```

The owner-only credential record has exactly `upstream` (the dedicated HTTPS
`/mcp`), `client_id` and `client_secret`. Bind it to one OS identity or
similarly isolated environment. A process that can start another instance's
relay with its credential record can use that instance. Test that each client
environment is unable to use sibling relays or existing human login material.
The relay forwards to the same origin, without taking a local file-reading
path. Record the actual SDK protocol version and transport used for each
qualified product.

## Rollback

Revoke Agent bindings at the origin, close the new ingress, stop the new
listener, then verify the human MCP entrance. If the Agent origin is
unavailable, close its ingress first. Preserve the existing v1 process,
configuration, audit directory and projects. Clean up test projects only
against the approved post-publish digest. Do not restore revoked bindings.
The authorization watermark in the protected parent of the Agent state
directory must advance with the latest committed authorization. Exclude it
from backup workflows that restore an older Agent state directory.
