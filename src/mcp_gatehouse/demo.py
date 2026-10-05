"""The installable demo server: an order desk with the gate closed.

Run it with `mcp-gatehouse-demo` (or `python -m mcp_gatehouse.demo`) and
wire it into any MCP client over stdio. Four tools, three tiers:

- ``list_orders`` / ``lookup_order`` (READ) run freely.
- ``add_note`` (WRITE) runs freely under the default policy — but every
  call lands in the audit log, with the ``api_key`` argument redacted.
- ``cancel_order`` (DESTRUCTIVE) requires approval. The demo approver is a
  terminal prompt: the model asks, *you* decide, the verdict gets logged.

The audit log goes to ``--audit-log PATH``, else ``$MCP_GATEHOUSE_AUDIT_LOG``,
else ``./audit.jsonl`` — falling back to ``~/.mcp-gatehouse/audit.jsonl``
when the working directory isn't writable (desktop clients often launch
servers from ``/``). The resolved path is printed to stderr at startup.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from mcp_gatehouse import AccessTier, Approver, AuditLog, Gatehouse, Policy, __version__
from mcp_gatehouse.approvers import terminal_approver

__all__ = ["build_server", "main", "terminal_approver"]

AUDIT_ENV_VAR = "MCP_GATEHOUSE_AUDIT_LOG"
FALLBACK_AUDIT_PATH = Path.home() / ".mcp-gatehouse" / "audit.jsonl"

# A stand-in for your real system of record.
ORDERS = {
    "4417": {"customer": "Blue Ridge Cabinets", "status": "packed", "notes": []},
    "4418": {"customer": "Piedmont Supply", "status": "picking", "notes": []},
}

OrderId = Annotated[
    str, Field(description="The order's ID, e.g. '4417'. Use list_orders to find one.")
]


def build_server(audit: AuditLog, approver: Approver | None = terminal_approver) -> MCPServer:
    """The order-desk server, wired through a gatehouse. Nothing happens at
    import time — no server, no log file — until you call this."""
    mcp = MCPServer(
        "gatehouse-order-desk",
        version=__version__,
        website_url="https://github.com/nickgeorgeseo/mcp-gatehouse",
        instructions=(
            "A demo order desk behind mcp-gatehouse. Reads run freely; "
            "add_note is logged; cancel_order needs a human's approval on "
            "the server's terminal and is denied if nobody approves. Every "
            "call, allowed or denied, is written to an audit log."
        ),
    )
    gatehouse = Gatehouse(mcp, policy=Policy(approver=approver), audit=audit)

    @gatehouse.tool(tier=AccessTier.READ)
    def list_orders() -> str:
        """List every order on the desk as `id · customer · status`, one per
        line. Read-only. Start here to find the order ID that lookup_order,
        add_note and cancel_order need."""
        return "\n".join(
            f"{oid} · {o['customer']} · {o['status']}" for oid, o in ORDERS.items()
        )

    @gatehouse.tool(tier=AccessTier.READ)
    def lookup_order(order_id: OrderId) -> str:
        """Look up one order's customer, status and notes. Read-only; changes
        nothing. Returns `no order <id>` if the ID doesn't exist."""
        order = ORDERS.get(order_id)
        if order is None:
            return f"no order {order_id}"
        notes = "; ".join(order["notes"]) or "none"
        return f"{order_id} · {order['customer']} · {order['status']} · notes: {notes}"

    @gatehouse.tool(tier=AccessTier.WRITE)
    def add_note(
        order_id: OrderId,
        note: Annotated[str, Field(description="Free-text note to append, e.g. 'customer asked for a callback'.")],
        api_key: Annotated[
            str,
            Field(description="Optional credential for the order system. Its value is masked in the audit log."),
        ] = "",
    ) -> str:
        """Append a note to an order. Existing notes are kept — this never
        overwrites or cancels anything. Runs without approval, and every call
        is recorded in the audit log. To actually stop an order, use
        cancel_order."""
        if order_id not in ORDERS:
            return f"no order {order_id}"
        ORDERS[order_id]["notes"].append(note)
        return f"note added to {order_id}"

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: OrderId) -> str:
        """Cancel an order. Irreversible, so it is gated: a human must approve
        on the server's terminal before it runs. If they refuse, or there is
        no terminal, the call is denied and the refusal is logged. To record
        information without cancelling, use add_note."""
        if order_id not in ORDERS:
            return f"no order {order_id}"
        ORDERS[order_id]["status"] = "cancelled"
        return f"{order_id} cancelled"

    return mcp


def open_audit_log(path: str | None = None) -> AuditLog:
    """Open the audit log, choosing the path as the module docstring says.

    A path you asked for explicitly must work — falling back silently would
    put the trail somewhere you aren't looking. Only the implicit default
    gets a fallback.
    """
    explicit = path or os.environ.get(AUDIT_ENV_VAR)
    if explicit:
        return AuditLog(path=explicit)
    try:
        return AuditLog(path="audit.jsonl")
    except OSError:
        return AuditLog(path=FALLBACK_AUDIT_PATH)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-gatehouse-demo",
        description="Demo MCP server (stdio): an order desk behind a gatehouse.",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help=f"where to append the JSONL audit trail (default: ${AUDIT_ENV_VAR}, "
        f"else ./audit.jsonl, else {FALLBACK_AUDIT_PATH})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    audit = open_audit_log(args.audit_log)
    # stderr, never stdout: stdout is the JSON-RPC pipe.
    sys.stderr.write(f"mcp-gatehouse demo: audit log → {audit.path}\n")
    build_server(audit).run()


if __name__ == "__main__":
    main()
