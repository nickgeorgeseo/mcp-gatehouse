# Security

`mcp-gatehouse` is security *tooling*, so it gets held to its own standard.

## Reporting a vulnerability

Email **nick@nickgeorgeai.com** with the details. You'll get a reply
within 72 hours. Please don't open a public issue for anything exploitable —
give me a chance to ship the fix first.

## What this library does and doesn't do

**Does:** refuse any tool call without a verified caller and an explicit
policy; enforce your policy on the record the call acts on, loaded by the
server and handed to the tool as checked; refuse tools, resources, prompts,
completions, and SDK extension methods and `tools/call` interceptors
registered around the gate (a resource or prompt that is
the same for every caller is served only when you open it with
`open_resource` / `open_prompt`, and still needs a verified caller); filter list results item by item; run the check and the write in
one transaction you supply; enforce per-tool permission tiers and token
scopes; gate calls behind an approver you control, bound to the record's
state; keep an append-only audit trail that names the caller; and mask
configured argument keys before they reach logs or approvers.

**Doesn't:** authenticate clients (it reads the identity the SDK's auth
verified, or the local caller a stdio server declares), write your
policies or queries, infer what the user intended (a manipulated agent can
still do what the user is allowed to: keep grants narrow and put a person
in front of what can't be undone), encrypt transports, sandbox tool code,
or protect against a malicious *server author*. It's a gate inside your server, not a perimeter around it. Treat
third-party MCP servers with the same scrutiny you'd give any software you
install.
