# mcp-gatehouse

**Project page & docs:** [nickgeorgeai.com/open-source/mcp-gatehouse](https://nickgeorgeai.com/open-source/mcp-gatehouse) · [PyPI](https://pypi.org/project/mcp-gatehouse/)

<!-- mcp-name: io.github.nickgeorgeseo/gatehouse -->

[![CI](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml/badge.svg)](https://github.com/nickgeorgeseo/mcp-gatehouse/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-gatehouse)](https://pypi.org/project/mcp-gatehouse/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![mcp-gatehouse MCP server](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse/badges/score.svg)](https://glama.ai/mcp/servers/nickgeorgeseo/mcp-gatehouse)

[![Gatehouse MCP server](https://mcprush.com/badge/gatehouse-mcp/card.svg)](https://mcprush.com/to/gatehouse-mcp?ref=badge)

**Authorization as a runtime invariant for MCP servers.** Every tool call
needs a verified caller, an explicit policy, and a decision on the record it
acts on, made by the server before the tool runs. If any of those is
missing, the call doesn't run. Around that: permission tiers, approval
gates, and an audit log of every call.

![An agent wants to cancel order 4418. The gate asks three questions before any tool runs: who's asking (a verified caller), is it allowed (the policy says it's the caller's own order), and is it safe (a person approves). The approval card for cancel_order, marked destructive, is approved, and the call runs once and is logged. Everything else fails closed: no verified caller, someone else's order, a policy that hangs past 5 seconds, a change during approval. Every call writes one audit line. Ends on pip install mcp-gatehouse.](https://raw.githubusercontent.com/nickgeorgeseo/mcp-gatehouse/main/docs/explainer.gif)

Most MCP servers hand the model every tool at full strength and keep no
record of what it did. That's fine for a demo. It's not fine the day an
agent has write access to your CRM, your books, or your order system.
`mcp-gatehouse` is the missing gate, enforced **inside** the server — no
proxy, no external policy service. It depends only on the official
[`mcp` SDK](https://github.com/modelcontextprotocol/python-sdk) and
`opentelemetry-api`, which the SDK already requires.

```
pip install mcp-gatehouse
```

> **Upgrading from 0.5?** 0.6.0 fails closed. A tool without `authorize=`
> doesn't register, and over stdio a server without `local_caller=` denies
> every call. Pin `mcp-gatehouse<0.6` until you've migrated; the
> [migration steps](https://github.com/nickgeorgeseo/mcp-gatehouse/blob/main/CHANGELOG.md#breaking-authorization-is-a-runtime-invariant)
> are one short list.

![Claude Code is asked to cancel order 4418; the server's approval form appears in Claude Code, naming who the call is for, the arguments, and the order as the server loaded it; ticking Approve lets it run. Asked to cancel order 4420, which belongs to someone else, the policy refuses it and no form appears. The audit log shows each call with its caller: pending, ok, then denied for someone else's order](https://raw.githubusercontent.com/nickgeorgeseo/mcp-gatehouse/main/docs/claude-code-approval.gif)

The demo server in Claude Code: the model asks to cancel an order, the
gate asks *you* in Claude Code's own UI, and the call runs. Then it tries
an order that isn't yours, and the policy refuses it before anyone is
asked. The audit log has a line for every call, with who it was for and
why it was refused.

[![mcp-gatehouse demo on YouTube: the install, tiers, a cancel refused and one approved, and the audit log](https://img.youtube.com/vi/9_S4NAPcYjM/maxresdefault.jpg)](https://youtu.be/9_S4NAPcYjM)

The [1:21 demo](https://youtu.be/9_S4NAPcYjM) runs the package's demo
server in a terminal: the install, the one-decorator change, a cancel
refused and one approved, and the audit log they left. No sound.

## What you get

| | |
|---|---|
| **Authorization on the record** | Every tool names a policy. The gate loads the record the call is about from the model's arguments, your policy decides on it, and the tool gets that same object. The model can't describe a record into existence or reach one that isn't the caller's. |
| **No way around the gate** | A tool without a policy doesn't register, the server refuses tools, resources, prompts, completions and SDK extension methods or interceptors registered around the gate, and a call with no verified caller is denied. Each opt-out is explicit and marked in the audit log. |
| **Check and write together** | The policy's decision and the tool's write share one transaction you supply, or the write carries the checked state in its own condition. A record that changes after the check is never acted on. |
| **Lists filtered per item** | A tool that returns records gets each one checked: what the caller may not see never reaches the model. |
| **Permission tiers** | Every tool is declared `READ`, `WRITE`, or `DESTRUCTIVE` — and the tier also emits honest spec `ToolAnnotations` (`readOnlyHint` / `destructiveHint`), which the wrapper won't let you override to lie. |
| **Approval gates** | Tiers you choose require a sign-off before the tool runs, asked right in the MCP client (Claude Code, Cursor, VS Code) or by any callable you write: a terminal prompt, a Slack ping, a ticket. **Fails closed:** a gated tool with no approver configured is denied, not waved through. |
| **Audit log** | One record per call — allowed, denied, failed, or cancelled — with UTC timestamps and durations, who each call was for, and the policy's real reason for every refusal, in a [documented schema](docs/audit-line.schema.json). Append-only JSONL by default, or any sink you give it: a function, OpenTelemetry, your logging pipeline. The answer to "what did the AI actually do, and for whom?" six months later. |
| **Redaction** | Argument keys you name (`api_key`, `password`, `token`, `client_secret`, … by default) are masked before they reach the log *or* the approver — however they're spelled: `apiKey`, `API-Key` and `api_key` are the same key. |
| **Denylist** | Block a tool outright, whatever its tier. |

## Quickstart

```python
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import (
    AccessTier, Allow, AuditLog, AuthorizationRequest, Caller, ConditionalWrite, Deny,
    ElicitationApprover, Gatehouse, Load, Policy, terminal_approver,
)

class Order(BaseModel):
    """Your record. Any Pydantic model, dataclass or mapping will do."""
    id: str
    owner: str
    status: str

mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    # Ask in the client's own UI; prompt on the terminal if it can't show a form.
    policy=Policy(approver=ElicitationApprover(fallback=terminal_approver)),
    audit=AuditLog(path="~/order-desk/audit.jsonl"),
    # Over stdio nobody signs in, so say who the calls are for.
    local_caller=Caller(client_id="local", subject="alice"),
)

def load_order(order_id: str) -> Order | None:
    """Your system of record. None means there's no such order."""
    ...

def owner_only(request: AuthorizationRequest) -> Allow | Deny:
    order = request.resources["order"]
    return Allow() if order.owner == request.caller.subject else Deny("not the owner")

@gatehouse.tool(tier=AccessTier.READ, authorize=owner_only)
def lookup_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str:
    """Look up an order's status."""
    return order.status

@gatehouse.tool(
    tier=AccessTier.DESTRUCTIVE,
    authorize=owner_only,
    consistency=ConditionalWrite(),  # the cancel's UPDATE checks the order's version
)
def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str:
    """Cancel an order. Runs only if it's the caller's and the approver says yes."""
    ...

mcp.run()
```

That's the whole integration: build your `MCPServer` exactly as the SDK
docs show, but create the gatehouse first and register every tool through
it. The model sees `order_id` and nothing else; the gate loads the order,
your policy decides on it, and the tool gets the order the policy saw.
Schema generation (including `Annotated[..., Field(description=...)]`
parameter docs), transports, and everything else work unchanged. Sync tools
still run in a worker thread, exactly as they would on a bare `MCPServer`.

## Authorization: a runtime invariant

Most servers leave authorization to each tool, and nothing notices when one
forgets. Here the server enforces it. Every call needs three things, checked
in the server before the tool runs:

1. **A verified caller.** That's the identity in the access token the SDK
   verified for the request. Over stdio, where nobody signs in, it's the
   `local_caller` you declare. An HTTP request with no verified token is
   nobody, even on a server that declares a local caller.
2. **An explicit policy.** `authorize=` is required on every tool.
3. **A decision on the record itself.** The gate loads each `Load`
   parameter from the model's arguments, gives the records to your policy,
   and hands the tool those same objects.

If any of the three is missing, the call is denied. Gatehouse doesn't know
your business rules. What it guarantees is that they run at the right
place, and that nothing gets around them:

- A tool without `authorize=` raises at registration, so the server doesn't
  start.
- The server refuses tools added around the gate. That covers
  `@mcp.tool()` and `add_tool` before or after the gate is created,
  `MCPServer(tools=...)`, extension tools, and a tool slipped into the
  registry. A refused tool is hidden from `tools/list` and denied when
  called.
- Resources, prompts and completions are other ways to the same data, and
  they have no policy: a template `orders://{order_id}` would read the
  record a tool checks, for anyone. So the server refuses them too, before
  or after the gate is created. Content that is the same for every caller
  (docs, a schema, a price list) goes through `@gatehouse.open_resource(uri)`
  or `@gatehouse.open_prompt()`, and a read without a verified caller is
  refused. These write no audit line. Anything that depends on who is
  asking belongs in a READ tool with a policy. Completions are refused
  outright: the SDK never tells the handler who is asking.
- An SDK `Extension` gets the same treatment. Its tools and resources are
  refused with the rest, and so is a server whose extension serves request
  methods of its own (`Extension.methods()`) or overrides
  `intercept_tool_call`: both answer with no policy and no audit line.
  What the gate guards is the SDK's public registration surface. Code
  that writes into the SDK's private registries (a template put straight
  into `_resource_manager._templates`), adds a low-level request handler
  after the gate, or adds request middleware to the low-level server
  (`server.middleware`, provisional in the SDK, which wraps every request,
  `tools/call` included, and can answer before the gate does), runs with
  your server's trust, like any other code you install in it.
- Nothing the gate fills can come from the model. A `Load` parameter never
  appears in the input schema, and registration fails if the SDK would put
  it there.

Each requirement has a way out, but only one you write down, and the audit
log shows it:

| Requirement | Applies to | Declared with | Deliberate opt-out | Audit line shows |
|---|---|---|---|---|
| Verified caller | every call | the SDK's auth (`token_verifier`) | `local_caller=` (stdio only) | `caller` (local ones: `"source": "local"`) |
| Policy | every tool | `authorize=` | `authorize=any_caller` | `authz: "open"` |
| Item filtering | tools returning a list of records | `authorize_items=` | `authorize_items=any_item` | `items: "open"` |
| Check and write in one unit | WRITE/DESTRUCTIVE tools that `Load` | `consistency=` (per tool, or on the `Gatehouse`) | `consistency=AcceptRace("why")` | `consistency: "accept-race"` and the reason |

### Where it sits

Three layers can say no to a tool call. They see different things, and
they don't compete:

- **Agent-framework approvals** live in the agent process, beside the
  model. They see the tool's name and the arguments the model proposed,
  and can ask a person before the call leaves the agent. They don't see
  the record, and a server reached by another client never meets them.
- **Gateways, proxies and policy services** sit in front of the server.
  They see the token, the tool name and the arguments, so they can decide
  which clients reach which tools, enforce scopes, rate-limit, and route.
  They don't see the record either, and whether the tool behind them
  checks it is up to that server.
- **The gate** is the check inside the server, on the record the call is
  about, for the caller the transport verified. The layers in front
  assume someone writes that check. This is the one that makes writing
  it mandatory: a tool without a policy doesn't register.

Use all three. An identity layer issues the token the SDK verifies and the
gate reads. A gateway narrows what reaches the server. Framework approvals
catch the agent's own mistakes early and cheaply. The gate decides on the
record, and keeps the trail. A team with a central policy engine keeps
its rules there and lets the gate call it:
[`examples/policy_opa.py`](examples/policy_opa.py) and
[`examples/policy_cerbos.py`](examples/policy_cerbos.py) send the caller,
the tool, the action and the loaded record to the engine. An engine that
can't be reached is a denial, and the model is told the call can be
retried, so "not now" doesn't read like "no". `on_unavailable=Ask` sends
those calls to your approver instead.

By design, `mcp-gatehouse` is none of the other layers. It is not a
proxy or a gateway, has no control plane, mints or exchanges no tokens,
and has no policy language: policies are Python, or a call to the engine
you already run.

It guards calls through this server, and only those. A script, a service
or another agent that reaches the database or API behind the tools
directly never meets the gate, and nothing the gate does can stop it. To
make the checks hold on every path, enforce them in the backend too. Give
the server the narrowest credential that does its work, not a shared
admin account. Have the backend check the caller itself, as
[`examples/orders_postgres.py`](examples/orders_postgres.py) does: the
`Transaction` factory sets `app.subject` from the verified caller, and
Postgres row-level security limits every query to that user's rows,
whoever connects. Don't hand other clients a credential that skips those
checks. Short-lived, narrowly scoped tokens for the services behind the
tools come from your identity provider. The gate checks the ones it
receives (`scopes=`, `request.claims`) and passes the caller on, but
doesn't issue them.

It is also not a workflow layer. The gate checks one call at a time and
keeps no workflow state, so a job that another agent picks up after a
dropped call resumes from wherever your workflow stores it, not from the
gate. Nor does it confirm what landed. `outcome: "ok"` means the tool
returned without raising; under `Transaction` it also means the commit
succeeded. For a tool that calls a calendar, a CRM or a payment service,
it means the call returned, not that the change is there. Two things
help a retry: `Load` reads the record again, so the policy decides on its
current state, not the state the last attempt saw, and a policy that
checks status refuses to cancel an order twice. Idempotency keys and
"did it land" checks belong to the tool or the workflow above it.

### Policies

A policy is any callable, sync or async, that takes an
`AuthorizationRequest` and returns one of three decisions:

- `Allow()`.
- `Deny(reason)`.
- `Ask(reason)`: a person decides. The configured approver is asked, and
  sees the reason. `Ask` with no approver is a denial, whatever
  `fail_closed` says.

Only a decision counts. A policy that returns `True`, `None` or anything
else, or that raises, has denied the call.

The request carries:

- `caller`: who the call is for;
- `resources`: the loaded records;
- `arguments`: what the model sent, read-only;
- `claims`: the verified token's claims, read-only. They go to the policy
  only and are never logged.

```python
def can_cancel(request: AuthorizationRequest) -> Decision:
    order = request.resources["order"]
    if order.owner != request.caller.subject:
        return Deny("not the owner")
    if order.status == "shipped":
        return Deny("already shipped", message=f"Order {order.id} has shipped.")
    if order.total > 500:
        return Ask("order over $500")
    return Allow()
```

The model gets the same answer for every refusal on authorization: "'X' is
not permitted for this caller." That covers a record that doesn't exist, one
that isn't theirs, and a loader or policy that failed, so it can't probe
which orders exist. The audit log records the real reason (`not found:
order`, `policy: not the owner`). `Deny(..., message=...)` tells the model
more, when that's safe to say.

`Load(loader, describe=..., fingerprint=...)`:

- The loader's parameters name the tool's arguments it loads from. A
  loader that returns `None` means not found.
- The approver sees the record, not only the arguments the model chose.
  By default that is its fields as the audit log shows them, secrets
  masked (`order: id=4417 · customer=Blue Ridge Cabinets · status=packed ·
  total=812.0`); `describe` replaces it with a line you write ("order 4417
  · Blue Ridge Cabinets · $812.00").
- An approval binds to the record's state, by default a redacted snapshot
  of it, or what `fingerprint` returns. If the record changes while a
  person decides, the call is refused rather than run on something they
  never saw. The snapshot holds masked fields as `«redacted»`, so a change
  to only a masked field (a rotated `api_key`, say) goes unseen; return
  it from `fingerprint` if it matters. On a tier that requires approval, a record must be a Pydantic
  model, a dataclass or a mapping, or have a `fingerprint`.

#### Deadlines

A call gets five seconds to load its records and reach a decision: the
loaders, the policy and any `Scope`, together. Past that it is denied,
logged as `authorization timed out: policy` (or `loading order`, or
`scope owner`), and the tool doesn't run. The model is told this isn't a
refusal and the call can be retried, so "not now" doesn't read like "no".

```python
Policy(authorization_timeout=2.0)            # every tool
@gatehouse.tool(authorize=report_policy, authorization_timeout=30)  # one tool
@gatehouse.tool(authorize=refund_policy, on_authorization_timeout=Ask)
```

`on_authorization_timeout=Ask` puts a call whose policy ran out of time
to the approver, with the reason `authorization timed out`, instead of
denying it. A refund then waits for a person rather than being lost. A
loader or `Scope` that runs out still denies: there is no record yet to
ask about. `authorization_timeout=None` turns the deadline off, and every
audit line for that tool says `"authorization_deadline": "off"`.

Python can't stop a thread. A sync loader or policy past the deadline is
abandoned: the call ends, and the thread finishes in the background with
its result dropped. Those threads are the gate's own, not the pool sync
tools draw on, so a hung policy never leaves a sync tool without a thread.
Each tool has its own 40 of them, so a policy that hangs on one tool
doesn't make another tool's authorization wait. An abandoned thread keeps
its place until it really returns, and the gate says so on stderr: a
policy that never returns can tie up at most its own tool's 40 threads,
after which that tool's calls are denied at the deadline without starting
another. Give every blocking call in a sync policy its own timeout,
shorter than the deadline.
Inside a sync `Transaction` every step runs in one thread, so the
deadline is checked between steps: a slow policy runs to the end, then
counts as late, and the transaction rolls back. That thread is the tool's
own too, one of 40 per tool, so a policy hung inside a transaction never
takes a thread from sync tools elsewhere. But it isn't abandoned: it holds
its thread, and its call, until it returns. Set the database's
statement timeout for a query that hangs there. An `async` policy that
blocks without awaiting, such as a sync HTTP call inside `async def`,
stalls the whole server, and no deadline can reach it.

### The check and the write

Loading once and handing over means the tool acts on the object that was
checked. It doesn't stop that record changing in the database between the
check and the write. A WRITE or DESTRUCTIVE tool that loads a record must
say how that window is closed:

- **`Transaction(factory)`.** `factory(caller)` returns your context
  manager, sync or async. The gate runs the load, the policy, the tool and
  the commit inside it, and a refusal or an error rolls it back.
  - Lock the row in the loader (`SELECT … FOR UPDATE`) and the decision
    still holds when the tool writes.
  - Loaders and the tool reach the transaction through
    `current_transaction()`.
  - A sync transaction runs entirely in one worker thread, so drivers tied
    to their thread are safe. Everything inside it must then be sync. With
    an async transaction, the loaders and the tool are async.
  - The gate never holds a transaction open while a person decides. It
    asks first, then opens the transaction, reloads and checks again.
- **`ConditionalWrite()`.** The write carries the checked state in its own
  condition: `UPDATE … WHERE id = ? AND version = ?`. When it matches
  nothing, the tool raises `Conflict`. The log records
  `outcome: "conflict"` and the model is told the record changed. The gate
  can't see your query, so this one is your promise.
- **`AcceptRace("why")`.** Accept the window on purpose. The reason goes on
  every audit line.

The gate guarantees that the check and the write share one unit, in that
order. Isolation (row locks, `SERIALIZABLE`) is your database's job.
[`examples/orders_postgres.py`](examples/orders_postgres.py) shows all of
it on Postgres.

### Lists

"May alice update invoice 123?" is a check. "Show alice her invoices" is a
filter, and filters belong in the data layer. The gate wires each layer to
the verified caller and backstops it:

1. **Row-level security.** The transaction factory gets the caller, so it
   can `SET LOCAL app.subject` and let Postgres RLS limit every query the
   tool runs.
2. **`Scope(fn)`.** This fills a hidden parameter with a query filter
   computed from the caller: an owner, a tenant, or the IDs a
   relationship-based engine lists. Your query uses it.
3. **`authorize_items=`**, the gate's backstop. A tool that returns a list
   of records must declare it. The gate checks each item it returned
   (`action="read"`, `resource=item`), and only `Allow` keeps one.
   - With layers 1 and 2 working, it withholds nothing.
   - The `ok` line counts `withheld`, and flags `scope_mismatch` when a
     `Scope` was in force. A nonzero count is an alarm that the query and
     the policy disagree.

The gate can only filter records it can see as items. A tool that formats
rows into a string gets the call-level check alone, so return records.
Filtering after the fetch also shrinks pages, so correct paging needs layer
1 or 2.

### Allowed isn't the same as wanted

Perfect enforcement still lets a prompt-injected agent do anything the user
is allowed to do. Authorization answers "may this happen?", not "did the
user ask for this?". The gate holds two levers:

- **Task-scoped credentials** make "allowed" as small as the task.
  - `scopes={"orders:cancel"}` on a tool denies a token without that
    scope, before anything loads.
  - A policy can read `request.claims`. It can require that the token's
    `authorization_details` (RFC 9396) name this exact order, so a token
    minted for "cancel 4417" can't cancel 4418. It can also check `act`
    (RFC 8693) to tell an agent acting for alice from alice herself.
  - Issue short-lived, down-scoped tokens per task. The gate enforces
    them; it doesn't mint them.
- **Confirmation for high-impact actions.** DESTRUCTIVE needs approval by
  default, and `Ask` adds it on your conditions. The approver sees the
  record (`describe`) and the reason, not only the model's arguments,
  which gives a person the chance to spot an action nobody asked for.
  Elicitation trusts the client to show the form to a person. For the
  tools that matter most, approve out-of-band (Slack, a ticket), where
  neither the model nor a compromised client can answer.

What no gate can do is infer intent. It limits the blast radius, puts a
person in front of what can't be undone, and keeps a trail that makes
misuse visible afterwards.

### Approve in the client

`ElicitationApprover` puts the question in front of the person using the
MCP client, as a form with one box to tick. It shows the tool and its tier,
why the policy asked, who the call is for, the arguments (secrets already
masked) and each record the call acts on, as the server loaded it:

```
Approval needed (order over $500). The AI wants to run cancel_order (destructive) for "nick" via client "local" with:
{"order_id": "4417"}
on order 4417 · Blue Ridge Cabinets · packed · $812.00
```

MCP calls this elicitation. Claude Code, Cursor and VS Code support it. The
model can't answer the form, and you run nothing beside the server.

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
returning `InputRequiredResult`, gets the fallback too from 2026-07-28,
since one call has one such channel. Up to 2025-11-25 the form goes over
its own request, separate from the tool's rounds, so the client is asked
as usual.

Used approvals are remembered in an `ApprovalStore`, so each runs its call
once. The default, `MemoryApprovalStore`, remembers per process. That is
enough while the SDK's request-state key is per process too, which it is
by default. Each process seals its questions with a key of its own, so an
approval minted before a restart, or by another replica, fails the SDK's
seal check before the gate or its store ever sees it.

Replicas behind a load balancer, or a server that should honour approvals
across a restart, need two things. First, every replica uses the same
request-state key and the same server name, which the SDK binds each
question to:

```python
from mcp.server.request_state import RequestStateSecurity

KEY = os.environ["MCP_REQUEST_STATE_KEY"]  # 32+ random bytes, the same on every replica
mcp = MCPServer("order-desk", request_state_security=RequestStateSecurity(keys=[KEY]))
```

Second, they share the store, or one approval runs its call once per
replica, and once more after each restart within `approval_timeout`. A
store is anything with `spend(nonce, expires) -> bool`. Two are examples
to copy:
[`examples/approval_store_sqlite.py`](examples/approval_store_sqlite.py),
standard library only, for replicas on one host, and
[`examples/approval_store_postgres.py`](examples/approval_store_postgres.py),
on `psycopg`, for replicas on several. Both spend each nonce once under
concurrent spenders and sweep expired ones. A store that raises denies
the call, logged as `approval store error`.

```python
ElicitationApprover(store=PostgresApprovalStore(os.environ["APPROVALS_DSN"]))
```

To rotate the key without dropping questions in flight, the SDK takes a
ring: `keys=[old, new]`, then `keys=[new, old]`, then `keys=[new]`.

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
should return by then too. One that doesn't finishes in the background, its
answer dropped, with a warning on stderr. Its thread keeps one of the tool's
40 approver threads until it returns. So an approver that never returns can
tie up at most its own tool's 40, and once they are all taken, that tool's
later approvals time out without starting more. Other tools keep their own
40. With no timeout set, the gate waits as long as the approver takes.

Under the default policy, `DESTRUCTIVE` requires approval and everything
is audited. Gate writes too with one line:

```python
policy = Policy(require_approval=frozenset({AccessTier.WRITE, AccessTier.DESTRUCTIVE}), approver=terminal_approver)
```

Add your own secret-bearing keys without losing the defaults:

```python
from mcp_gatehouse import DEFAULT_REDACT
policy = Policy(redact=DEFAULT_REDACT | {"card_pin"}, approver=terminal_approver)
```

### The audit log

One record per call, whatever happened to it:

```json
{"ts": "2026-11-06T14:02:11+00:00", "call_id": "4b1e0c9a6f2d47f1a3c85e0d2b7f9a61", "request_id": "7", "trace_id": "0af7651916cd43dd8448eb211c80319c", "span_id": "b7ad6b7169203331", "tool": "list_orders", "tier": "read", "outcome": "ok", "arguments": {}, "duration_ms": 0.31, "timings_ms": {"authorize": 0.05, "tool": 0.31, "filter": 0.04, "total": 0.42}, "withheld": 1, "caller": {"client_id": "local", "subject": "alice", "issuer": null, "scopes": [], "source": "local"}, "authz": "open"}
{"ts": "2026-11-06T14:02:38+00:00", "call_id": "…", "request_id": "8", "tool": "add_note", "tier": "write", "outcome": "ok", "arguments": {"order_id": "4417", "note": "call back", "api_key": "«redacted»"}, "duration_ms": 1.08, "caller": {…}, "authz": "allow", "resources": {"order": {"order_id": "4417"}}, "consistency": "conditional"}
{"ts": "2026-11-06T14:03:05+00:00", "tool": "cancel_order", "tier": "destructive", "outcome": "denied", "reason": "policy: someone else's order", "arguments": {"order_id": "4420"}, "caller": {…}, "authz": "deny", "resources": {"order": {"order_id": "4420"}}, "consistency": "conditional"}
{"ts": "2026-11-06T14:05:40+00:00", "tool": "cancel_order", "tier": "destructive", "outcome": "denied", "reason": "approver refused", "arguments": {"order_id": "4417"}, "caller": {…}, "authz": "ask", "resources": {"order": {"order_id": "4417"}}, "consistency": "conditional"}
```

The fields, and when each appears. The same table, as a JSON Schema the
test suite checks every line against, is
[`docs/audit-line.schema.json`](docs/audit-line.schema.json). No other
field is ever written.

| Field | Type | When |
|---|---|---|
| `ts` | string, ISO-8601 UTC | always |
| `call_id` | string, 32 hex | always: the gate's id for the call, the same on every line it writes. `ApprovalRequest.call_id` carries it to the approver |
| `request_id` | string | when a live request is behind the call: its JSON-RPC id, cut to 128 characters. The client's choice, unique only per session |
| `trace_id`, `span_id` | string, 32 and 16 hex | when the call runs in an OpenTelemetry trace: the client's `traceparent`, or a trace a configured OpenTelemetry SDK started |
| `continues` | string, 32 hex | on the round that answers a round-trip approval: the `call_id` of the `pending` line that asked, whatever the verdict |
| `tool` | string | always |
| `tier` | `"read"`, `"write"`, `"destructive"` or `null` | always; `null` only for an ungated tool |
| `outcome` | `"ok"`, `"denied"`, `"error"`, `"conflict"`, `"pending"`, `"cancelled"` | always |
| `reason` | string | every outcome but `ok`. Denials carry the gate's real reason; errors carry the exception type only, never its message; cancellations say the stage |
| `arguments` | object | always: the model's arguments after redaction. Never what the gate filled |
| `duration_ms` | number | `ok`, `conflict`, and `error` or `cancelled` lines whose reason says the tool was running |
| `timings_ms` | object: `authorize`, `approval`, `tool`, `filter`, `commit`, `total` | every line written by the tool's gate (all but the `ungated tool` and `no verified caller` denials from `call_tool`): milliseconds for each stage the call reached, and the total. `filter` only with an item policy, `commit` only with a `Transaction` |
| `caller` | object: `client_id`, `subject`, `issuer`, `scopes`, and `source: "local"` for a declared local caller | once a caller is known: every line but the `ungated tool` and `no verified caller` denials |
| `authz` | `"allow"`, `"ask"`, `"deny"`, `"open"` | once the policy decided (`open` for `any_caller`). Absent on lines written before it ran: denylist, no caller, missing scope, loader error, not found |
| `resources` | object: each `Load` parameter's name mapped to the redacted arguments it was loaded from | every line of a tool that loads records. Never the record itself |
| `items` | `"open"` | every line of a tool with `authorize_items=any_item` |
| `consistency` | `"transaction"`, `"conditional"`, `"accept-race"` | every line of a tool with `consistency=`, its own or the `Gatehouse` default |
| `consistency_reason` | string | with `"accept-race"` |
| `authorization_deadline` | `"off"` | every line of a tool with `authorization_timeout=None`: the deadline is turned off |
| `withheld` | integer | `ok` lines of a tool with an item policy: items the caller may not see, removed |
| `filter_errors` | integer | with `withheld`, when the item policy raised on some items |
| `scope_mismatch` | `true` | with `withheld`, when a `Scope` was in force: the query and the policy disagree |
| `sink_error` | string | only on the stderr copy of a line that didn't reach the sink: the exception type when the sink raised, `"queue full"`, `"sink closed"` or `"terminated"` from a `BufferedSink` |

The outcomes: `ok`, the tool ran. `denied`, the gate refused, and `reason`
says why. `error`, the tool raised, or the transaction or item filtering
failed. `conflict`, a conditional write matched nothing because the
record changed. `pending`, the approval was asked in the client over the
2026-07-28 round trip: the verdict follows on a line of its own when the
client comes back, so a `pending` line with nothing after it is a question
nobody answered. `cancelled`, the client gave up or the server shut down
before the call finished: `reason` says when. `authorizing` and `awaiting
approval` mean the tool never ran. `tool running` comes with `duration_ms`,
and the tool may have done part of its work. A sync tool can't be stopped
partway: its worker thread runs to the end, and the line says `ok` or
`error` as usual. A sync policy or loader can't be stopped either, but
the gate takes the cancellation as soon as it returns, before the tool
starts. Inside a `Transaction` that rolls the transaction back. The gate
only writes the line; the cancellation goes on as it would without it.

#### Tracing a call

`call_id` groups one call's lines; `continues` joins the two rounds of a
round-trip approval. To go further, out to the agent and the model, use
the trace. The MCP SDK opens an OpenTelemetry span for every request,
parented on the `traceparent` the client sends in the request's `_meta`,
and the gate writes that trace's `trace_id` and `span_id` on the line.
Find the line from a slow or failed span in your tracing backend, or the
span from a line. Nothing to configure: `opentelemetry-api` comes with
the SDK, and with no OpenTelemetry SDK set up the client's trace still
comes through.

The gate doesn't record model token usage, and has no field a client can
fill with it. It never sees the model, a number the client reports is
unverified, and the trace already joins the two: put token counts on the
client's LLM spans, as the OpenTelemetry GenAI conventions do
(`gen_ai.usage.input_tokens`), and they sit in the same trace as the
gate's line.

A retry by the model is a new call with a new `call_id`. The gate can't
tell it is a retry; the trace can, when the agent keeps the turn in one.

#### Sinks

`AuditLog(path=...)` appends JSON lines to a file, and `AuditLog(stream=...)`
to a text stream. `AuditLog(sink=...)` hands each record, as a dict, to
anything with a `write(record)` method:

```python
from mcp_gatehouse import AuditLog, CallableSink

AuditLog(sink=CallableSink(queue.put))                      # your own function
AuditLog(sink=CallableSink(lambda r: log.info("audit", extra=r)))  # the logging module
```

Three sinks ship with the library, none needing anything beyond it:
`JsonlSink(path=...)` or `JsonlSink(stream=...)`, which is what `path=`
and `stream=` use, `CallableSink(fn)`, and `BufferedSink`, below. For OpenTelemetry logs, copy
[`examples/audit_otel.py`](examples/audit_otel.py): one log record per
audit record, the record as the body and the fields worth filtering on as
attributes. An HTTP collector or a logging pipeline is a `CallableSink`
away.

`JsonlSink(path=...)` appends each record with one unbuffered write of
the whole line, so the file only ever holds whole lines: a write that
fails part way (a full disk) is cut back off, and that record goes to
stderr as below and never turns up in the file later as well. A stream
you pass in is written and flushed per record, and is yours to manage.

Records reach the sink one at a time, so it needn't be thread-safe. A sink
that raises doesn't lose the record and doesn't fail the call: the gate
writes the line to stderr with a `sink_error` field naming the exception
type, and goes on. Watch stderr for `sink_error` if the sink is the only
copy of the trail. `AuditLog.close()` calls the sink's `close()` when it
has one.

A sink is written on the request path, so a slow one (an HTTP collector,
a remote log) slows every call. Wrap it in `BufferedSink` to write it from
a background thread instead:

```python
AuditLog(sink=BufferedSink(CallableSink(post_to_collector), maxsize=10_000))
```

`write` puts the record on a bounded queue and returns at once; one
thread writes the queue to the inner sink in order. When the queue is
full the call doesn't wait. The record goes to stderr with
`sink_error: "queue full"` instead of the queue, so stderr is then its
only copy. Size `maxsize` for your bursts and alarm on `sink_error`.
`close()` writes everything already queued, then closes the inner sink;
it also runs at exit for a buffer nobody closed. A record written after
`close()` goes to stderr with `sink_error: "sink closed"`.

A signal's default action skips exit hooks, so on SIGTERM (`docker stop`,
systemd, or the MCP Python SDK's stdio client, which sends it 2 s after
closing stdin) the queue would go nowhere. A `BufferedSink` created on the
main thread therefore installs a SIGTERM handler, unless SIGTERM is
already handled: yours, or a web server's, is never replaced. It writes
every record still queued to stderr with `sink_error: "terminated"`, then
lets the default SIGTERM end the process. The record being written at
that moment goes to stderr too, so it may also be in the inner sink. To
drain into the inner sink instead, handle SIGTERM yourself and close the
log there:

```python
import signal
import sys

audit = AuditLog(sink=BufferedSink(CallableSink(post_to_collector), maxsize=10_000))

def on_sigterm(signum, frame):
    audit.close()  # drains the queue, then closes the inner sink
    sys.exit(0)

signal.signal(signal.SIGTERM, on_sigterm)
```

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
(a `Caller`), and `terminal_approver` names the user and the client in
its prompt, so whoever signs off knows whose request it is:

```
⚠ approval needed → cancel_order (destructive) {'order_id': '4417'}
  on order 4417 · Blue Ridge Cabinets · packed · $812.00
  asked because: order over $500
  for "alice" via client "support-agent"
allow? [y/N]
```

An approver can act on it too:

```python
async def approver(request: ApprovalRequest) -> bool:
    caller = request.caller
    if caller is None or caller.subject is None:
        return False  # no signed-in user to ask on behalf of
    # ask_in_slack and manager_of are yours to write. A subject is unique
    # only per issuer, so look people up by both.
    return await ask_in_slack(request, notify=manager_of(caller.issuer, caller.subject))
```

`subject` is only as good as your token verifier. Fill in
`AccessToken.subject` (and `claims` with `iss`), or the log can name only
the client application, not the person. Gatehouse never logs the token
itself, but it does log `client_id` and `subject` as your verifier sets
them, so keep the token out of both (some API-key setups use the key as
the client ID). A subject can be an email address or other personal
data, and `redact` doesn't cover it, since redaction applies to tool
arguments: keep the log's retention in line with that. Over stdio nobody
signs in: the lines name the `local_caller` the server declared, marked
`"source": "local"`, and without one every call is denied.

### What the gate verifies, and what it trusts

The gate checks these itself, every call: the tool was registered through
it and has a policy; the request has a caller; the loader ran and found
the record; the policy ran on that record and returned a decision; an
approval answers the question asked, about the record in the state it was
asked about, once; and nothing the gate fills came from the model. The
rest it takes on trust from something you configured. Each row says what
to do when that trust isn't acceptable.

| Taken on trust | What the gate relies on | When that isn't acceptable |
|---|---|---|
| **The token verifier** | Over HTTP the caller is whatever the SDK's `token_verifier` says: `client_id`, `subject`, `issuer`, `scopes`, `claims`. The gate never sees the token and checks no signature itself. | Use a verifier that checks signature, issuer, audience and expiry against your identity provider, and fills in `subject`. Have policies check `claims` (`act`, `authorization_details`) so a token's rights are as narrow as the task. |
| **`local_caller` over stdio** | Whoever starts the server process is that caller. The gate can't tell the user from another program running under their account. | Serve over streamable HTTP with the SDK's auth and drop `local_caller`, so each caller is a verified token. Over stdio, restrict who can run the server at the operating-system level, and keep DESTRUCTIVE tools behind an approver. |
| **The client showing elicitation forms to a person** | `ElicitationApprover` verifies that the answer is to its question, in time, once. It can't see whether a person ticked the box: a client or hook set to accept forms on its own approves too. | Use an out-of-band approver (Slack, a ticket, a queue) where neither the model nor the client can answer, as `fallback` or instead. For the tools that matter most, do that whatever the client. |
| **The `ConditionalWrite` promise** | You promise the write carries the checked state in its own condition and raises `Conflict` when it matches nothing. The gate can't read your query. | Use `Transaction(...)`: the gate runs load, policy, tool and commit in your transaction, and a row locked in the loader can't change under the write. |
| **`AcceptRace`** | You accept that the record may change between the check and the write, for the reason you gave. The gate only records it on every line. | Don't. Close the window with `Transaction(...)` or `ConditionalWrite()`; `AcceptRace` is for the cases where a race is harmless, and the audit log is where you justify that. |
| **Your loader and your policy** | The record is what the loader returned; the decision is what the policy returned. A loader that reads the wrong row, or a policy with a hole, is enforced faithfully. | Load through the database's own access control (row-level security under the caller's identity, as `examples/orders_postgres.py` does), so a wrong query returns nothing rather than someone else's record. Keep `authorize_items` on list tools and alarm on `withheld` above zero. |
| **The audit sink and the approval store** | A sink that raises gets its line on stderr; a store that raises denies the call. Where the records then go, and whether the store is shared by every replica, is the deployment's. | Ship the sink's output somewhere append-only and read `sink_error` from stderr. Share the approval store (`examples/approval_store_sqlite.py` on one host, `examples/approval_store_postgres.py` across hosts) wherever the SDK's request-state key is shared. |

## Try the demo

The package ships a runnable order-desk server with all three tiers wired
up. Every order has an owner. Over stdio the server declares that calls are
for you, the user running it, so you see and change only your orders: order
4420 is someone else's. `cancel_order` refuses an order that has shipped,
and needs your approval for the rest, asked in the client when it can show
a form, with a terminal prompt as the fallback. Above $500 the approval
says so. Add it to any MCP client that speaks
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

Claude Desktop doesn't show approval forms yet, and it starts servers
with no terminal, so there `cancel_order` is always denied (fail closed)
and stderr says why. Reads and notes work as anywhere else. To approve a
cancel, use a client with forms, such as Claude Code.

Or run `mcp-gatehouse-demo` yourself after `pip install mcp-gatehouse`.
Ask the model to list the orders, look up 4420, and cancel one, then watch
each verdict land in the audit log, with the policy's reason when it says
no. The audit log goes to `--audit-log`, else
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
so it can post to Slack, open a ticket or wait on a queue.
`examples/orders_server.py` is a trimmed copy of the demo server, as a
copyable template.

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
- **Opt out on purpose, never by omission.** As with CSRF protection in a
  web framework, the protection is on unless you switch it off for one
  tool, in writing (`any_caller`, `any_item`, `AcceptRace("why")`), and
  the audit log shows every place you did.
- **What this is not:** authentication, transport encryption, a sandbox,
  or a judge of intent. It enforces *your* policy on the record, for the
  caller the SDK authenticated, but it can't tell an action the user
  wanted from one a manipulated agent chose within their rights. Resources
  and prompts are refused unless you open them; anything per caller
  belongs in a READ tool. It's a gate inside your server,
  not a perimeter around it. See [SECURITY.md](SECURITY.md).

## Compatibility

Targets the official [`mcp` Python SDK](https://github.com/modelcontextprotocol/python-sdk)
v2.x (`mcp>=2.3,<3`) and Python 3.10–3.14. The gate guards the SDK's
tool registry, which it reaches through 2.3's internals; on an SDK where
they aren't there, creating a `Gatehouse` raises rather than run unguarded. Ships type information
(`py.typed`). Release notes: [CHANGELOG.md](CHANGELOG.md).

| `mcp-gatehouse` | SDK | Server class |
|---|---|---|
| `0.6.x` | `mcp>=2.3,<3` | `MCPServer` |
| `0.5.x` | `mcp>=2,<3` | `MCPServer` |
| `0.4.x` | `mcp>=2,<3` | `MCPServer` |
| `0.3.x` | `mcp>=2,<3` | `MCPServer` |
| `0.2.x` | `mcp>=2,<3` | `MCPServer` |
| `0.1.x` | `mcp>=1.27,<2` | `FastMCP` |

The public API (`Gatehouse`, `Policy`, `AuditLog`, `AccessTier`) is
unchanged across that line, as promised, with one deliberate exception:
0.6.0's authorization invariant. Every tool now needs `authorize=`, a
server needs a verified or declared caller, a WRITE or DESTRUCTIVE
tool that loads a record needs `consistency=`, and authorization that
takes longer than five seconds is denied. See
[CHANGELOG.md](CHANGELOG.md) for the migration. Porting a v1 server is two
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
