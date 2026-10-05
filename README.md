# mcp-gatehouse

<!-- mcp-name: io.github.nickgeorgeseo/gatehouse -->

[![CI](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml/badge.svg)](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![mcp-gatehouse MCP server](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse/badges/score.svg)](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse)

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

## What you get

| | |
|---|---|
| **Permission tiers** | Every tool is declared `READ`, `WRITE`, or `DESTRUCTIVE` — and the tier also emits honest spec `ToolAnnotations` (`readOnlyHint` / `destructiveHint`), which the wrapper won't let you override to lie. |
| **Approval gates** | Tiers you choose require a sign-off before the tool runs. Your approver is any callable — a terminal prompt, a Slack ping, a ticket. **Fails closed:** a gated tool with no approver configured is denied, not waved through. |
| **Audit log** | Append-only JSONL, one line per call — allowed, denied, or failed — with UTC timestamps and durations. The answer to "what did the AI actually do?" six months later. |
| **Redaction** | Argument keys you name (`api_key`, `password`, `token`, `client_secret`, … by default) are masked before they reach the log *or* the approver — however they're spelled: `apiKey`, `API-Key` and `api_key` are the same key. |
| **Denylist** | Block a tool outright, whatever its tier. |

## Quickstart

```python
from mcp.server.mcpserver import MCPServer
from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy, terminal_approver

mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    policy=Policy(approver=terminal_approver),
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

`terminal_approver` asks on the controlling terminal (`/dev/tty`), never
stdin — over stdio, stdin *is* the protocol pipe, so a plain `input()`
approver would corrupt it. An approver is any callable, sync or async,
that takes an `ApprovalRequest` and returns `True` to allow; sync ones run
in a worker thread, so a human taking their time doesn't stall other calls.
If the approver raises (Slack down, ticket API timing out), the call is
denied and the failure is logged.

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
```

## Try the demo

The package ships a runnable order-desk server with all three tiers wired
up and a terminal-prompt approver. Add it to any MCP client that speaks
stdio — for Claude Desktop, in `claude_desktop_config.json`:

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

The approval prompt needs a terminal: a client that launches the server in
the background has none, so `cancel_order` is denied — the gate failing
closed, as designed. Run the server from a terminal to approve
interactively. `examples/orders_server.py` is the same server as a copyable
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
- **The audit log records denials and errors**, not just successes — the
  calls that *didn't* happen are half the story.
- **A blocking terminal approver and the stdio transport don't mix** —
  stdout/stdin are the protocol pipe. `terminal_approver` prompts on
  `/dev/tty` for exactly that reason (and denies when no terminal exists).
  Real deployments should approve out-of-band: Slack, a ticket, a queue.
- **What this is not:** authentication, transport encryption, or a sandbox.
  It's a gate inside your server, not a perimeter around it. See
  [SECURITY.md](SECURITY.md).

## Compatibility

Targets the official [`mcp` Python SDK](https://github.com/modelcontextprotocol/python-sdk)
v2.x (`mcp>=2,<3`) and Python 3.10–3.14. Ships type information
(`py.typed`). Release notes: [CHANGELOG.md](CHANGELOG.md).

| `mcp-gatehouse` | SDK | Server class |
|---|---|---|
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

If you're an owner or operator wondering what MCP even is, start with the
plain-English guide: [What is an MCP server?](https://nickgeorgeai.com/mcp)

## License

[MIT](LICENSE)
