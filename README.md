# mcp-gatehouse

**Project page & docs:** [nickgeorgeai.com/open-source/mcp-gatehouse](https://nickgeorgeai.com/open-source/mcp-gatehouse) · [PyPI](https://pypi.org/project/mcp-gatehouse/)

<!-- mcp-name: io.github.nickgeorgeseo/gatehouse -->

[![CI](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml/badge.svg)](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![mcp-gatehouse MCP server](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse/badges/score.svg)](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse)

[![Gatehouse MCP server](https://mcprush.com/badge/gatehouse-mcp/card.svg)](https://mcprush.com/to/gatehouse-mcp?ref=badge)

**Permission tiers, approval gates, and audit logging for MCP servers.**
The server is the gatekeeper: you decide what an AI can read, what it can
write, and what's off-limits — and every action gets logged.

Most MCP servers hand the model every tool at full strength and keep no
record of what it did. That's fine for a demo. It's not fine the day an
agent has write access to your CRM, your books, or your order system.
`mcp-gatehouse` is the missing gate, enforced **inside** the server — no
proxy, no external policy service, no dependencies beyond the official
[`mcp` SDK](https://github.com/modelcontextprotocol/python-sdk).

```
pip install mcp-gatehouse
```

![Claude Code asks to cancel order 4418; the server's approval form appears in Claude Code with the arguments; ticking Approve lets it run; the audit log shows the call pending, then ok](https://raw.githubusercontent.com/nickgeorgeseo/mcp-gatehouse/main/docs/claude-code-approval.gif)

The demo server in Claude Code: the model asks to cancel an order, the
gate asks *you* in Claude Code's own UI, and the audit log records the
call as asked, then done.

[![mcp-gatehouse demo on YouTube: the install, tiers, a cancel refused and one approved, and the audit log](https://img.youtube.com/vi/9_S4NAPcYjM/maxresdefault.jpg)](https://youtu.be/9_S4NAPcYjM)

The [1:21 demo](https://youtu.be/9_S4NAPcYjM) runs the package's demo
server in a terminal: the install, the one-decorator change, a cancel
refused and one approved, and the audit log they left. No sound.

## What you get

| | |
|---|---|
| **Permission tiers** | Every tool is declared `READ`, `WRITE`, or `DESTRUCTIVE` — and the tier also emits honest spec `ToolAnnotations` (`readOnlyHint` / `destructiveHint`), which the wrapper won't let you override to lie. |
| **Approval gates** | Tiers you choose require a sign-off before the tool runs, asked right in the MCP client (Claude Code, Cursor, VS Code) or by any callable you write: a terminal prompt, a Slack ping, a ticket. **Fails closed:** a gated tool with no approver configured is denied, not waved through. |
| **Audit log** | Append-only JSONL, one line per call — allowed, denied, failed, or cancelled — with UTC timestamps and durations, and, on servers that sign callers in, who each call was for. The answer to "what did the AI actually do, and for whom?" six months later. |
| **Redaction** | Argument keys you name (`api_key`, `password`, `token`, `client_secret`, … by default) are masked before they reach the log *or* the approver — however they're spelled: `apiKey`, `API-Key` and `api_key` are the same key. |
| **Denylist** | Block a tool outright, whatever its tier. |

## Quickstart

```python
from mcp.server.mcpserver import MCPServer
from mcp_gatehouse import (
    AccessTier, AuditLog, ElicitationApprover, Gatehouse, Policy, terminal_approver,
)

mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    # Ask in the client's own UI; prompt on the terminal if it can't show a form.
    policy=Policy(approver=ElicitationApprover(fallback=terminal_approver)),
    audit=AuditLog(path="~/order-desk/audit.jsonl"),
)

@gatehouse.tool(tier=AccessTier.READ)
def lookup_order(order_id: str) -> str:
    """Look up an order's status."""
    ...

@gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
def cancel_order(order_id: str) -> str:
    """Cancel an order. Runs only if the approver says yes."""
    ...

mcp.run()
```

That's the whole integration: build your `MCPServer` exactly as the
SDK docs show, but register tools through the gatehouse. Schema generation
(including `Annotated[..., Field(description=...)]` parameter docs),
transports, and everything else work unchanged — the guard preserves the
function's signature. Sync tools still run in a worker thread, exactly as
they would on a bare `MCPServer`.

### Approve in the client

`ElicitationApprover` puts the question in front of the person using the
MCP client, as a form with one box to tick, showing the tool, its tier and
its arguments (secrets already masked). MCP calls this elicitation. Claude
Code, Cursor and VS Code support it. The model can't answer the form, and
you run nothing beside the server.

It works under both protocol revisions in use:

- **Up to 2025-11-25** the form goes to the client mid-call and the gate
  waits for it, under `approval_timeout` like any approver.
- **From 2026-07-28** there's no channel for that. The call hands the
  question back to the client and runs when the client calls again with
  the answer. The SDK seals that round's state and binds it to the tool
  and its exact arguments. The gate also checks that the answer is to the
  question it asked, that it arrived within `approval_timeout` (an hour if
  none is set), and that each approval runs its call only once.

Anything but a ticked box (decline, cancel, closing the form, an unticked
box, a malformed answer) is a refusal. When the client can't be asked, the
`fallback` decides; with no fallback, the call is denied. A tool that runs
its own multi-round input flow, through `Resolve(...)` parameters or by
returning `InputRequiredResult`, gets the fallback too, since one call has
one such channel. Single-use is tracked per process.

Elicitation trusts the client to show the form to a person. A client or
hook set to accept forms on its own can approve too. When the approval
must come from outside the client, use an out-of-band approver instead.

### Other approvers

`terminal_approver` asks on the controlling terminal (`/dev/tty`), never
stdin — over stdio, stdin *is* the protocol pipe, so a plain `input()`
approver would corrupt it. An approver is any callable, sync or async,
that takes an `ApprovalRequest` and returns `True` to allow; sync ones run
in a worker thread from a pool of their own, so a human taking their time
doesn't stall other calls, and a pile of pending approvals can't take the
threads your sync tools need. If the approver raises (Slack down, ticket
API timing out), the call is denied and the failure is logged.

Give approvals a deadline so a sign-off nobody gives doesn't hang the call:

```python
Policy(approver=terminal_approver, approval_timeout=120)
```

Past it, the call is denied and logged as `approval timed out`. Approvers
see the deadline as `request.deadline` (a `time.monotonic()` value), and
`terminal_approver` withdraws its prompt when it passes. A sync approver
that ignores it finishes in the background and its answer is dropped. With
no timeout set, the gate waits as long as the approver takes.

Under the default policy, `DESTRUCTIVE` requires approval and everything
is audited. Gate writes too with one line:

```python
Policy(require_approval=frozenset({AccessTier.WRITE, AccessTier.DESTRUCTIVE}), ...)
```

Add your own secret-bearing keys without losing the defaults:

```python
from mcp_gatehouse import DEFAULT_REDACT
Policy(redact=DEFAULT_REDACT | {"card_pin"}, ...)
```

What the audit trail looks like:

```json
{"ts": "2026-07-16T14:02:11+00:00", "tool": "lookup_order", "tier": "read", "outcome": "ok", "arguments": {"order_id": "4417"}, "duration_ms": 0.42}
{"ts": "2026-07-16T14:02:38+00:00", "tool": "add_note", "tier": "write", "outcome": "ok", "arguments": {"order_id": "4417", "note": "call back", "api_key": "«redacted»"}, "duration_ms": 1.08}
{"ts": "2026-07-16T14:03:05+00:00", "tool": "cancel_order", "tier": "destructive", "outcome": "denied", "reason": "approver refused", "arguments": {"order_id": "4417"}}
{"ts": "2026-07-16T14:05:40+00:00", "tool": "cancel_order", "tier": "destructive", "outcome": "cancelled", "reason": "awaiting approval", "arguments": {"order_id": "4418"}}
```

`outcome` is `ok`, `denied` (`reason` says why), `error` (the tool
raised; `reason` is the exception type), `pending`, or `cancelled`.
`pending` is a call whose approval was asked in the client over the
2026-07-28 round trip: the verdict follows on a line of its own when the
client comes back, so a `pending` line with nothing after it is a question
nobody answered. `cancelled` means the client gave
up, or the server shut down, before the call finished. `reason` says
when. `awaiting approval` means the tool never ran. `tool running` comes
with `duration_ms`, and the tool may have done part of its work. A sync
tool can't be stopped partway: its worker thread runs to the end, and the
line says `ok` or `error` as usual. The gate only writes the line; the
cancellation goes on as it would without it.

### Who the call was for

On a server that signs callers in with the SDK's auth (a
`token_verifier`, over streamable HTTP or SSE), every audit line also
names the caller, taken from the access token the SDK verified for that
request:

```json
{"ts": "2026-11-05T09:14:02+00:00", "tool": "cancel_order", "tier": "destructive", "outcome": "ok", "arguments": {"order_id": "4417"}, "duration_ms": 3.1, "caller": {"client_id": "support-agent", "subject": "alice", "issuer": "https://login.example.com", "scopes": ["orders:read", "orders:write"]}}
```

It is read per request, so a token the client refreshes mid-session is
logged as the new one. Approvers get the same thing as `request.caller`
(a `Caller`), and `terminal_approver` shows it in the prompt, so whoever
signs off knows whose request it is. An approver can act on it too:

```python
async def approver(request: ApprovalRequest) -> bool:
    if request.caller is None:
        return False  # nobody signed in
    # ask_in_slack and manager_of are yours to write.
    return await ask_in_slack(request, notify=manager_of(request.caller.subject))
```

`subject` is only as good as your token verifier. Fill in
`AccessToken.subject` (and `claims` with `iss`), or the log can name only
the client application, not the person. The token itself is never
logged. Over stdio nobody signs in, so there is no `caller` and the lines
are as before.

Naming the caller isn't deciding what they may touch. Whether alice may
cancel order 4417 still has to be checked by your tool or your API.

## Try the demo

The package ships a runnable order-desk server with all three tiers wired
up. Approvals are asked in the client when it can show a form, with a
terminal prompt as the fallback. Add it to any MCP client that speaks
stdio. For Claude Code:

```bash
claude mcp add gatehouse-demo -- uvx mcp-gatehouse --audit-log /tmp/gatehouse-audit.jsonl
```

For Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gatehouse-demo": {
      "command": "uvx",
      "args": ["mcp-gatehouse", "--audit-log", "/tmp/gatehouse-audit.jsonl"]
    }
  }
}
```

Or run `mcp-gatehouse-demo` yourself after `pip install mcp-gatehouse`.
Ask the model to list the orders and cancel one, then watch the verdict
land in the audit log either way. The audit log goes to `--audit-log`, else
`$MCP_GATEHOUSE_AUDIT_LOG`, else `./audit.jsonl` — falling back to
`~/.mcp-gatehouse/audit.jsonl` when the working directory isn't writable
(desktop clients often launch servers from `/`). The server prints the
path it chose to stderr.

In a client that supports elicitation (Claude Code, Cursor, VS Code),
`cancel_order` brings up an approval form in the client: tick the box to
let it run. An approval nobody gives is denied after two minutes.

Other clients get the terminal fallback, which needs the server to have a
terminal it can ask on. Whether it gets one depends on how the client
starts it:

- **TypeScript SDK clients** (the `StdioClientTransport` in 1.x and 2.x)
  keep the server in the client's terminal session. Start such a client
  from an ordinary terminal, one not running a full-screen program, and
  the prompt appears there. An unanswered prompt is denied after two
  minutes.
- **Python SDK clients** (`stdio_client` in 1.x and 2.x), and anything
  built on them, start every server in a session of its own. The server
  has no controlling terminal even when you run the client from one, so
  it can't prompt: `cancel_order` is denied, and stderr says why.
- **Desktop apps** that launch servers in the background give them no
  terminal, and **full-screen terminal UIs** are using theirs. Denied
  too.

Every denial is the gate failing closed, as designed. Where the prompt
can't reach you, approve out-of-band instead: an approver is any callable,
so it can post to Slack, open a ticket or wait on a queue. `examples/orders_server.py` is the same server as a copyable
template.

## Design notes

- **Enforcement lives inside the server**, at the tool boundary. A proxy
  can't see your tools' semantics, and a policy service is one more thing
  to deploy. A 40-person plant doesn't have a platform team; this is a few
  small classes and a JSONL file.
- **Fail closed.** Security defaults that quietly allow are worse than none.
  That includes redaction: argument values the scrubber can't take apart
  (arbitrary objects, bytes) are replaced with an opaque placeholder rather
  than passed through, and exception *messages* stay out of the log —
  only the exception type is recorded, because error text loves to embed
  the very values you just redacted.
- **The audit log records denials, errors and cancellations**, not just
  successes — the calls that *didn't* happen are half the story, and a
  call cut off halfway may still have done something.
- **A blocking terminal approver and the stdio transport don't mix** —
  stdout/stdin are the protocol pipe. `terminal_approver` prompts on
  `/dev/tty` for exactly that reason, and denies when there's no terminal
  or a full-screen program has it in raw mode. Asking in the client
  (elicitation) sidesteps the terminal entirely. When the approval must
  not come from the client, approve out-of-band: Slack, a ticket, a queue.
- **What this is not:** authentication, transport encryption, a sandbox,
  or a check on which records a caller may touch. It logs the caller the
  SDK authenticated; your tools and APIs still decide what that caller is
  allowed to do. It's a gate inside your server, not a perimeter around
  it. See [SECURITY.md](SECURITY.md).

## Compatibility

Targets the official [`mcp` Python SDK](https://github.com/modelcontextprotocol/python-sdk)
v2.x (`mcp>=2,<3`) and Python 3.10–3.14. Ships type information
(`py.typed`). Release notes: [CHANGELOG.md](CHANGELOG.md).

| `mcp-gatehouse` | SDK | Server class |
|---|---|---|
| `0.5.x` | `mcp>=2,<3` | `MCPServer` |
| `0.4.x` | `mcp>=2,<3` | `MCPServer` |
| `0.3.x` | `mcp>=2,<3` | `MCPServer` |
| `0.2.x` | `mcp>=2,<3` | `MCPServer` |
| `0.1.x` | `mcp>=1.27,<2` | `FastMCP` |

The public API (`Gatehouse`, `Policy`, `AuditLog`, `AccessTier`) is
unchanged across that line, as promised. Porting a v1 server is two
import edits — `FastMCP` became `MCPServer` and moved to
`mcp.server.mcpserver`; see the SDK's
[migration guide](https://py.sdk.modelcontextprotocol.io/v2/migration/).

Staying on SDK v1 needs no action: `0.1.x` pins `mcp<2`, so pip keeps
resolving it. That line is closed to features but still gets security
fixes.

## Who built this

[Nick George](https://nickgeorgeai.com) — I design and run MCP servers in
production for a mid-market reverse logistics-tech company, and build them
for businesses at [nickgeorgeai.com](https://nickgeorgeai.com). This
library is the permission-and-audit discipline from those builds, extracted.
Why I built it, and how it works in plain words, is on the
[project page](https://nickgeorgeai.com/open-source/mcp-gatehouse).

If you're an owner or operator wondering what MCP even is, start with the
plain-English guide: [What is an MCP server?](https://nickgeorgeai.com/mcp)

## License

[MIT](LICENSE)
