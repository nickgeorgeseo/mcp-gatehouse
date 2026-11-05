# Changelog

All notable changes to `mcp-gatehouse`. The public API (`Gatehouse`,
`Policy`, `AuditLog`, `AccessTier`) stays compatible within a minor line.

## Unreleased

### Fixed

- **Configuration the gate couldn't read failed open.** `tier="destructive"`
  ran the tool with no approval, then crashed writing the audit line: no
  record, and an error that invited the model to retry.
  `Policy(require_approval={"destructive"})` gated nothing.
  `Policy(redact="api_key")` logged `api_key` in clear. Tiers are now read
  by name too (`"write"`, any case), checked when the tool is registered
  or the `Policy` is built, and anything unreadable is an error there.
- `Policy(deny="cancel_order")` blocked every tool whose name is a
  substring of it, and `require_approval=AccessTier.DESTRUCTIVE` crashed
  every call without an audit line. A single string or tier where a
  collection belongs is now refused, with the fix in the message, as are
  non-string names and a non-callable approver.
- **Tools taking `ctx: Context | None = None` couldn't be approved in the
  client.** The gate missed that `Context` (and `Optional[Context]`,
  `Annotated[Context, ...]`) while the SDK injected into it, so the gate's
  hidden `gatehouse_context` parameter showed up in the tool's schema,
  `ctx` was written to the audit log, and approval in the client was
  always denied. The gate now finds the `Context` with the SDK's own rule.
- **Redaction missed the names secrets go by**: `github_token`,
  `db_password`, `openai_api_key`, `auth_token` and the like reached the
  log and the approval form in clear. A key now also masks names that end
  in its words (`token` masks `authToken`, not `token_count`; `pin` masks
  `card_pin`, not `spin`). New defaults: `secret_key`,
  `secret_access_key`, `credential`, `credentials`. This only ever masks
  more; pass an explicit `Policy(redact=...)` if you relied on one of
  these appearing in the log.
- `bytearray` and `memoryview` arguments were logged byte by byte. They're
  opaque now, like `bytes`.
- An audit sink that raised (disk full) turned a call that ran into an
  error, so the model was told a completed call had failed, and a denial
  lost its reason. The failure is now logged at ERROR on the
  `mcp_gatehouse` logger and the call's result stands.
- Assigning `gatehouse.policy` (or `.audit`) after registering tools did
  nothing. Both are now read on every call.
- An approval nobody answered could be logged as `approver refused`, and
  the model told the approver refused. An approver that gives up at
  `request.deadline` (`terminal_approver` does) races the gate's own
  timer, and whichever finished first decided the record. A "no" at the
  deadline is now always `approval timed out`, as documented.
- `terminal_approver` refused a typed `yes`; it now takes `y` or `yes`, in
  any case. Enter and anything else still refuse.
- `mcp-gatehouse --version` and `--help` called themselves
  `mcp-gatehouse-demo`.

### Added

- `@gatehouse.read`, `@gatehouse.write` and `@gatehouse.destructive`, with
  or without parentheses.
- `gatehouse.add_tool(fn, tier=...)`, to register without a decorator.
- `annotations=` sets the hints the tier doesn't decide (`idempotentHint`,
  `openWorldHint`). Contradicting the tier's own hints is still refused;
  a misspelled hint is refused instead of dropped.
- `Gatehouse(audit=...)` takes a path, or any object with a
  `record(**event)` method (the new `AuditSink` protocol).
- `MemoryAuditLog`, which keeps records in `.events`, for tests.
- CI type-checks the package with mypy against Python 3.10.

### Changed

- `@gatehouse.tool()` with no tier still registers the tool as `READ`, but
  now warns (`FutureWarning`): that's ungated and tells clients the tool is
  read-only. A future release will require the tier.
- The demo and `examples/orders_server.py` use the tier decorators.
- The sdist no longer ships `docs/` or `.github/`.
- The Dockerfile's notes say the demo has four tools, and that a client
  that can show the approval form can approve in the container.

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
- Pending approvals no longer block sync tools: approvers have their own
  thread pool.
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
