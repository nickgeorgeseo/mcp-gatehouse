# Security

`mcp-gatehouse` is security *tooling*, so it gets held to its own standard.

## Reporting a vulnerability

Email **nick@nickgeorgeai.com** with the details. You'll get a reply
within 72 hours. Please don't open a public issue for anything exploitable —
give me a chance to ship the fix first.

## What this library does and doesn't do

**Does:** enforce per-tool permission tiers, gate calls behind an approver
you control, keep an append-only audit trail, and mask configured argument
keys before they reach logs or approvers.

**Doesn't:** authenticate clients, encrypt transports, sandbox tool code,
or protect against a malicious *server author*. It's a gate inside your
server, not a perimeter around it. Treat third-party MCP servers with the
same scrutiny you'd give any software you install.
