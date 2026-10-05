# Changelog

All notable changes to `mcp-gatehouse`. The public API (`Gatehouse`,
`Policy`, `AuditLog`, `AccessTier`) stays compatible within a minor line.

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
