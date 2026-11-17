# Changelog

All notable changes to `mcp-gatehouse`. The public API (`Gatehouse`,
`Policy`, `AuditLog`, `AccessTier`) stays compatible within a minor line,
with one deliberate exception: 0.6.0's authorization invariant is
breaking, and its release notes say how to migrate.

## 0.6.1 — 2026-11-16

### A changed record says what changed

An approval that no longer applies because its record changed was refused
with "the record changed", and asking again showed the new record with
nothing marking what was different, so a person would approve the second
question as they had the first. Now:

- The refusal names each field with its old and new value: `What changed:
  order.total: 812.00 → 812.01.`
- The next question about the same call (same tool, caller and arguments)
  starts with `Changed since you were last asked: …`, in the client's form
  and on the terminal. Over the 2026-07-28 round trip, where a stale answer
  is asked again rather than refused, the question asked again does too.
- That stale answer is now on the record: the round trip's `pending` line
  reads `approval asked again: resource changed while awaiting approval`,
  with `changed` and `continues`. Before, the log showed two ordinary
  `pending` lines.
- `ApprovalRequest.changes` carries the lines for custom approvers.
- The audit line of the refusal lists the field names in `changed`. Names
  only, never values.
- `Load(changed_values=True)` lets a record with `describe=` show values in
  its change lines. The demo uses it.

A masked field is named without its values, and so is every field of a
record whose `Load` has `describe=`, unless it passes
`changed_values=True`. What changed is only shown: the approval still
binds to the record's state exactly as before, and the question's digest
leaves the change lines out, so the answer to a question that showed them
still matches. The memory is per process and lasts an hour.

## 0.6.0 — 2026-11-15

### Breaking: authorization is a runtime invariant

Every tool call now needs a verified caller, an explicit policy, and a
decision on the record it acts on. Anything missing fails closed. To
migrate a server:

- Give every tool `authorize=`: your policy, or `any_caller` where any
  verified caller may use it. A tool without one raises at registration.
- Over stdio, and for in-memory clients, declare who calls are for:
  `Gatehouse(..., local_caller=Caller(...))`. Without a token or a local
  caller, calls are denied. `local_caller` never applies to an HTTP
  request: an HTTP request without a verified token is denied even on a
  server that declares one.
- Create the `Gatehouse` before registering any tool, and register every
  tool through it. A server that already has tools is refused, and
  `@mcp.tool()`, `add_tool`, `MCPServer(tools=...)` and extension tools
  are refused on a gated server.
- Resources, prompts and completions are refused on a gated server, like
  tools registered around the gate: they reached the same data with no
  policy and no caller check. Register content that is the same for every
  caller with `@gatehouse.open_resource(uri)` or `@gatehouse.open_prompt()`
  (a verified caller is required to read it). Move anything per caller,
  including a resource template that picks a record, to a READ tool with a
  policy. A server that already has any of them when the `Gatehouse` is
  created is refused.
- A server with an SDK `Extension` that serves request methods of its own
  (`Extension.methods()`) or overrides `intercept_tool_call` is refused
  when the `Gatehouse` is created: both answered with no policy and no
  audit line, and an interceptor ran before the gate.
- A WRITE or DESTRUCTIVE tool that loads a record needs
  `consistency=`: `Transaction(...)`, `ConditionalWrite()` or
  `AcceptRace("why")`, per tool or as the `Gatehouse` default.
- A tool that returns a list of records (`list[T]`, `tuple[T, ...]` or
  `Sequence[T]` of Pydantic models, dataclasses, TypedDicts or mappings)
  needs `authorize_items=` (or `any_item`). That includes one arm of a
  union (`list[Order] | None`), items that may be records
  (`list[Order | None]`) and `type` aliases. `authorize_items` on a tool
  that returns anything else is refused.
- A `Load` parameter on a tier that requires approval must be a Pydantic
  model, a dataclass, a TypedDict or a mapping, or give
  `Load(..., fingerprint=...)`, so the approval can bind to the record's
  state. Anything else is refused at registration.
- A `Load` or `Scope` parameter can't have a default, can't be
  positional-only or variadic, and must carry the marker as its own
  `Annotated[...]` metadata, not nested in another type. A loader's
  parameters must name the tool's own arguments.
- Tool annotations must evaluate at registration. The gate reads them
  with the defining scope's locals, so local classes and loaders work.
- SDK `Resolve(...)` parameters are refused on gated tools: the SDK runs
  them before the gate.
- A custom audit class whose `record` lists fixed keywords needs
  `**kwargs`: the gate now passes `caller`, `authz`, `resources`,
  `items`, `consistency`, `withheld` and more.
- Authorization has a deadline: a loader, policy or `Scope` that takes
  longer than five seconds in total is denied. Set
  `authorization_timeout` on the tool or the Policy, or `None` to turn
  the deadline off, which the audit log then shows.
- Requires `mcp>=2.3`.

### Added

- An authorization deadline. Loaders, the policy and any `Scope` share
  `Policy.authorization_timeout` seconds, 5 by default. Past it the call
  is denied as `authorization timed out: policy` (or `loading <name>`, or
  `scope <name>`), the tool doesn't run, and the model is told the call
  can be retried. `@gatehouse.tool(authorization_timeout=...)` overrides it for
  one tool. `None` turns it off, and every audit line for that tool then
  carries `"authorization_deadline": "off"`.
- `on_authorization_timeout=Ask`, on the Policy or one tool: a policy that
  runs out of time puts the call to the approver with the reason
  `authorization timed out` instead of denying. A loader or `Scope` that
  runs out still denies.
- Sync loaders, policies and scopes run on the gate's own worker threads,
  not anyio's default pool, so hung ones can't leave sync tools without a
  thread. Each tool has its own 40, so a policy hung on one tool doesn't
  slow another tool's authorization. A sync step past the deadline is
  abandoned and finishes in the background, keeping its place until it
  does, with a warning on stderr: a policy that never returns ties up at
  most its own tool's 40 threads, and that tool's later calls are denied
  at the deadline without starting more. Inside a sync `Transaction` the deadline is checked between
  steps, and a late answer rolls the transaction back. The transaction's
  one thread is also the tool's own (40 per tool), not the default pool,
  so a policy hung inside it can't leave sync tools elsewhere without a
  thread.
- A call cancelled while the gate is authorizing doesn't start its tool,
  sync or async, inside a `Transaction` or not: the transaction rolls
  back and the line says `cancelled` with reason `authorizing`. A call
  cancelled after its tool started says `tool running`, with the tool's
  `duration_ms`.

- Audit sinks. `AuditLog(sink=...)` hands each record, as a dict, to
  anything with a `write(record)` method (the `AuditSink` protocol), as
  an alternative to `path=` and `stream=`. Two sinks ship with the
  library: `JsonlSink`, the JSON-lines file or stream that `path=` and
  `stream=` use, and `CallableSink(fn)`. A file `JsonlSink` opens gets
  each record as one unbuffered write of the whole line; a write that
  fails part way (a full disk) is cut back off, so the file holds only
  whole lines and a record sent to stderr never lands in it later. A sink that raises doesn't lose
  the record: it is written to stderr as one JSON line with a
  `sink_error` field naming the exception type, and the call goes on.
  The record's fields are documented in the README, field by field, and
  in `docs/audit-line.schema.json`, a JSON Schema the test suite checks
  every audit line against. `examples/audit_otel.py` forwards records to
  OpenTelemetry logs.
- `ApprovalStore`: where the round-trip approver remembers used
  approvals, as `spend(nonce, expires) -> bool`. `MemoryApprovalStore` is
  the default and remembers per process; `ElicitationApprover(store=...)`
  takes another. `examples/approval_store_sqlite.py` is one on SQLite,
  standard library only, for servers that share the SDK's request-state
  key across replicas or restarts; its single-use guarantee is tested
  across two processes. A store that raises denies the call, logged as
  `approval store error: <ExceptionType>`.
- `examples/approval_store_postgres.py`: the `ApprovalStore` contract on
  Postgres, for replicas on several hosts. Single use under concurrent
  spenders (primary key and `ON CONFLICT DO NOTHING`), expired rows swept
  with a grace for clock drift between replicas, and Postgres unreachable
  raises, so the gate denies. Needs `psycopg`; the library doesn't import
  it. Its tests run when `GATEHOUSE_TEST_POSTGRES_DSN` names a database,
  and skip otherwise.
- `BufferedSink(inner, *, maxsize=10_000)`: audit writes off the request
  path. `write` puts the record on a bounded queue and returns; one
  background thread writes the queue to `inner` in order. Standard
  library only. Drop policy: when the queue is full the call never
  waits; the record goes to stderr as one JSON line with
  `sink_error: "queue full"` and is not queued, so stderr is its only
  copy. `close()` drains everything written before it, then closes
  `inner`; buffers nobody closed are drained at interpreter exit. A
  record written after `close()` goes to stderr with
  `sink_error: "sink closed"`. SIGTERM skips exit hooks, so a buffer
  created on the main thread installs a SIGTERM handler when none is set
  (one already there is never replaced): records still queued go to
  stderr with `sink_error: "terminated"`, then the default SIGTERM ends
  the process. An inner sink that raises anything, even a
  `CancelledError`, loses only that record to stderr, and the buffer
  goes on.
- External policy engines as the policy behind the gate:
  `examples/policy_opa.py` and `examples/policy_cerbos.py`. Each sends
  the caller, the tool, the action and the loaded record's attributes to
  the engine over HTTP, standard library only, and maps the answer to
  `Allow`, `Deny` or `Ask`. An engine that can't be reached is
  `Deny("policy engine unavailable")`, and the model is told the
  authorization service didn't answer and the call can be retried;
  `on_unavailable=Ask` puts those calls to the approver instead. An
  engine that answers with an error or garbage, or leaves out an action
  it was asked about, is a denial either way.
  Each file carries the engine-side policy for the order-desk demo. The
  library imports neither.
- Who each call was for. On servers that sign callers in with the MCP
  SDK's auth (a `token_verifier`, over streamable HTTP or SSE), every
  audit line has a `caller` field: the verified token's `client_id`,
  `subject`, `issuer` and `scopes`, never the token itself. It is read
  per request, so a token refreshed mid-session is logged as the new
  one. Approvers get the same as `ApprovalRequest.caller`, a new
  `Caller` type, and `terminal_approver` names the user and client in
  its prompt. Names there are JSON-quoted with everything outside
  printable ASCII escaped and cut at 80 characters, so a crafted
  subject can't redraw the prompt or pass for someone else. Over stdio
  nobody signs in: lines name the declared `local_caller`, marked
  `"source": "local"`; without one, every call is denied.
- `Load(loader)`: a parameter the gate fills. It loads the record from the
  model's arguments, your policy decides on it, and the tool gets that same
  object. Hidden from the input schema, and registration fails if the SDK
  would ever expose it.
- Policies return `Allow()`, `Deny(reason)` or `Ask(reason)`. `Ask` puts
  the call to the approver with the reason, on any tier. Every refusal on
  authorization reads the same to the model, and the audit log keeps the
  real reason. A reason must be a non-empty string: `Ask(None)` raises,
  and the gate denies the call as a policy error.
- Approvals are bound to the record's state. If it changes while a person
  decides, the call is refused. The approval form and terminal prompt show
  the record and the reason: the line `Load(describe=...)` returns, or by
  default the record's fields as the audit log shows them, secrets masked.
  The form also names who the call is for, puts each record on its own
  line, and is titled "Approval" for clients that show the schema's name.
- `consistency=`: `Transaction(factory)` runs load, policy, tool and
  commit in your transaction, never held open during an approval.
  `ConditionalWrite()` with `Conflict`, and `AcceptRace(reason)`.
  `current_transaction()` reaches the handle.
- `authorize_items=` filters list results item by item, and `Scope(fn)`
  passes a caller-computed query filter to the tool. Audit lines count
  `withheld` and flag `scope_mismatch`.
- `scopes=` on a tool, and token claims for policies
  (`AuthorizationRequest.claims`, never logged).
- Audit fields `authz`, `resources`, `items`, `consistency`, `withheld`,
  `filter_errors`, `scope_mismatch`, outcome `conflict`, cancellation
  reason `authorizing`, and `"source": "local"` for the local caller.
- `examples/orders_postgres.py`: a transaction with row-level security and
  `FOR UPDATE`.
- Correlation in the audit trail. Every line has a `call_id`, the same on
  every line one call writes and on `ApprovalRequest.call_id`. Lines
  written inside a request have its JSON-RPC `request_id`, and, when the
  call runs in an OpenTelemetry trace (the client's `traceparent` in
  `_meta`, which the MCP SDK already picks up), `trace_id` and `span_id`.
  The round that answers a round-trip approval has `continues`: the
  `call_id` of the round that asked.
- `timings_ms` on every line the tool's gate writes: milliseconds spent
  authorizing, awaiting approval, in the tool, filtering items and
  committing a `Transaction`, and the total. `duration_ms` stays, and is
  the same number as `timings_ms.tool`.

### Docs

- README, "Where it sits": the gate guards calls through this server only.
  A path to the backend that skips the server never meets it, so enforce
  the same checks in the backend too (row-level security under the
  caller, as `examples/orders_postgres.py` does) and give the server the
  narrowest credential it needs.
- README: "Where it sits" places the gate next to agent-framework
  approvals and gateways and policy services, by what each layer sees,
  and says what the library is not by design.
- README: "What the gate verifies, and what it trusts" lists, in a table,
  what the gate checks itself and what it takes on trust (the SDK's token
  verifier, `local_caller` over stdio, the client showing elicitation
  forms to a person, the `ConditionalWrite` promise, `AcceptRace`, the
  loader and policy, the audit sink and approval store), and what to do
  when that trust isn't acceptable.
- README, "Where it sits": the gate is not a workflow layer. It keeps no
  workflow state and doesn't confirm that a change landed in an external
  system; what `outcome: "ok"` does and doesn't mean, and what helps a
  retry.
- README, "Approve in the client": the exact `RequestStateSecurity(keys=[...])`
  setup replicas need, and why a store alone isn't enough without it.

### Packaging

- `opentelemetry-api` is a declared dependency. The MCP SDK already
  requires it, so nothing new is installed.
- The sdist leaves out `docs/*.mp4` and `docs/*.gif`: from about 6 MB to
  about 185 KB. The wheel is unchanged, and the README links its
  recording by absolute URL, so nothing points at a missing file. The
  `.tape` sources that make the recordings stay in.

### Fixed

- A tool annotated `ctx: Context | None` no longer gets a second, hidden
  `gatehouse_context` parameter in its input schema that the model could
  fill.
- Redacted sets come out sorted, so they read the same in every process.
- `Decimal`, `date`, `datetime` and `time` values are logged and shown to
  approvers as their values, not `«opaque:…»`. They can't carry text, and
  an approval's fingerprint has to see an amount change: before, an
  approval for an $812 order still applied after the order changed to
  $99,999. The same now goes for `Enum` values (shown as their value),
  `UUID`s, IP addresses and paths. A record with a field the gate can
  still only show by its type (`bytes`, an arbitrary object) can't be
  approved without `Load(..., fingerprint=...)`: a change there would go
  unseen.
- An approver's answer approves only when it is `True`. A string, a
  response object or any other truthy value used to approve; it is now
  denied as `approver error: returned <type>`.
- The approval form in the client takes only a real tick: `"yes"`,
  `"true"` or `1` for `approve` is a malformed answer, and a refusal.
- In the approval form, the model's arguments can't add lines: line and
  paragraph separators, control and bidi characters in them are escaped,
  as they already were for the record lines, and a long argument list is
  cut so it can't push the record out of view. `terminal_approver`'s
  prompt shows them the same way: JSON on one line, cut at 400
  characters (it printed them in full, as a Python dict).
- Redaction: a `NamedTuple` is redacted by field name (a `password`
  field was logged); `bytearray` and `memoryview` are opaque like
  `bytes` (their contents were logged as numbers); infinite and NaN
  numbers are written as strings, so every audit line is strict JSON.
- `MemoryApprovalStore` remembers a spent approval for five minutes past
  its expiry, so a clock stepped back can't make it spendable again.
  `examples/approval_store_sqlite.py` does the same (`sweep_grace=`) and
  now closes its connections.

### Changed

- An audit log whose destination fails (a full disk, a closed stream, a
  sink that raises) no longer raises out of the call. The line goes to
  stderr with `sink_error`, and the call's outcome is what it would have
  been.
- On servers that sign callers in, the audit object's `record()` gets a
  `caller` keyword. `AuditLog` takes any keywords; a custom audit class
  whose `record` lists fixed keywords needs `**kwargs`, or calls fail
  with a `TypeError`.

## 0.5.0 — 2026-11-02

### Added

- `ElicitationApprover`: approval asked in the MCP client's own UI (MCP
  elicitation), as a one-box form showing the tool, its tier and its
  redacted arguments. It works under both protocol eras: mid-call over
  the back-channel up to 2025-11-25, and as an `InputRequiredResult`
  round trip from 2026-07-28. The round trip binds the approval to the
  call's exact arguments, enforces `approval_timeout`, and lets each
  approval run its call only once. A client that can't be asked hands
  over to `fallback`, or the call is denied.
- Audit outcome `pending`: the approval was asked in the client over the
  round trip, and the verdict follows on its own line.

### Changed

- The demo asks for `cancel_order`'s approval in the client when it can,
  so it works in Claude Code, Cursor and VS Code, and falls back to the
  terminal prompt elsewhere. `examples/orders_server.py` does the same.
- Registered tools that take no `Context` get a hidden `gatehouse_context`
  parameter, kept out of the tool's input schema, so the gate can reach
  the client. A tool parameter with that name is now refused at
  registration.

### Fixed

- The README said starting the client from an ordinary terminal lets you
  approve the demo's prompt. Not for clients built on the MCP Python SDK:
  its stdio client starts servers in a session of their own, with no
  controlling terminal, so `terminal_approver` always denies there. The
  README now says which clients can prompt.
- `terminal_approver`'s stderr denial says when the server has no
  controlling terminal although stderr is one, instead of a bare
  "no terminal for approval".

## 0.4.0 — 2026-10-21

### Fixed

- `terminal_approver` now prompts. It used to deny every call without
  asking, on macOS and Linux.
- `terminal_approver` denies instead of prompting when a full-screen
  program, such as an MCP client's terminal UI, is using the terminal.
- Pending approvals no longer block sync tools: sync approvers have their
  own threads, 40 per tool. An approver still blocked when the approval
  times out keeps its thread's place until it returns, with a warning on
  stderr. So one that ignores `request.deadline` ties up at most its own
  tool's 40, and approvals for other tools are unaffected.
- Cancelled calls are logged as `outcome: "cancelled"`. A call cancelled
  during approval or while an async tool ran used to leave no record.

### Added

- `Policy(approval_timeout=seconds)`: an unanswered approval is denied and
  logged as `approval timed out`. Off by default.
- `ApprovalRequest.deadline`, so an approver knows when the gate stops
  waiting.

### Changed

- Less work per call: the signature is read once and arguments are
  redacted once.
- The demo denies an approval left unanswered for two minutes.

## 0.3.1 — 2026-10-16

No code changes. Metadata only.

- The package Homepage and the MCP Registry `websiteUrl` now point to the
  project page, https://nickgeorgeai.com/open-source/mcp-gatehouse, instead
  of the general MCP guide. The README links it too.

## 0.3.0 — 2026-10-05

### Fixed

- **Sync tools no longer freeze the server.** The SDK runs sync tools in a
  worker thread, but it only ever saw the gatehouse's async guard, so a
  gated sync tool ran on the event loop and stalled every other request
  until it returned. The guard now does the thread offload itself.
- **Sync approvers no longer freeze the server either.** While a human
  considered a `terminal_approver` prompt, nothing else (reads, pings) was
  served. Approvers now run in a worker thread too; `terminal_approver`
  serializes its prompts so concurrent requests don't interleave.
- **An approver that raises is an audited denial, not a crash.** Previously
  the failure left no audit record, logged an ERROR traceback, and gave the
  model only "Error executing tool". Now it is recorded as
  `outcome: "denied"`, `reason: "approver error: <ExceptionType>"`, and the
  model is told the approver failed. Still fails closed; the exception
  message stays out of the log, as with tool errors.
- **The demo starts from any directory.** It wrote `audit.jsonl` relative to
  the working directory, so a client that launched it from `/` (desktop
  clients do) crashed with `Read-only file system`. See the new audit path
  options below.
- **Importing `mcp_gatehouse.demo` no longer creates `audit.jsonl`** as a
  side effect.

### Added

- `terminal_approver` is public: `from mcp_gatehouse import terminal_approver`.
  (`mcp_gatehouse.demo.terminal_approver` still works.)
- `DEFAULT_REDACT` is exported, so you can extend rather than replace it:
  `Policy(redact=DEFAULT_REDACT | {"card_pin"})`.
- `AuditLog.path`: the absolute path being written (`None` for streams).
  `AuditLog(path=...)` now expands `~`.
- Demo CLI: `--audit-log PATH`, `$MCP_GATEHOUSE_AUDIT_LOG`, `--version`, and
  the chosen log path printed to stderr. Without either, it falls back to
  `~/.mcp-gatehouse/audit.jsonl` when `./audit.jsonl` isn't writable.
- Demo: a `list_orders` tool (so the model can find an order ID), parameter
  descriptions on every tool, fuller tool descriptions, and server
  `instructions` / `version`.
- `py.typed`, so type checkers use the package's annotations.
- Python 3.14 support, tested in CI.

### Changed

- **Redaction ignores `_` and `-` as well as case** when matching keys, so
  `apiKey`, `API-Key` and `api_key` are all caught by `api_key`. Matching
  is still whole-key (`token_count` is not redacted).
- **More keys redacted by default:** `passwd`, `passphrase`,
  `access_token`, `refresh_token`, `id_token`, `client_secret`,
  `x_api_key`, `private_key`, `cookie`, `set_cookie`. Both changes only
  ever mask more, never less. If you relied on one of these values
  appearing in the log, pass an explicit `Policy(redact=...)`.
- `__version__` is read from the installed package metadata instead of a
  hand-kept copy.
- Quickstart uses `terminal_approver` instead of an `input()` approver,
  which reads stdin and so corrupts the stdio transport.

## 0.2.0 — 2026-09-07

- Ported to `mcp` SDK v2 (`MCPServer`, `mcp>=2,<3`). Porting a v1 server is
  two import edits; see the README's Compatibility section.
- Policy denials are raised as `GateDenied`, which is both a
  `PermissionError` and the SDK's `ToolError`, so the model sees the reason
  and the server doesn't log a crash.

## 0.1.0 — 2026-07-13

- Initial release on `mcp>=1.27,<2` (`FastMCP`): permission tiers with
  honest tool annotations, approval gates that fail closed, append-only
  JSONL audit log, argument redaction, denylist.
