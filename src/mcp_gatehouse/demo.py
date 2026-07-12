"""The installable demo server: an order desk with the gate closed.

Run it with `mcp-gatehouse-demo` (or `python -m mcp_gatehouse.demo`) and
wire it into any MCP client over stdio. Three tools, three tiers:

- ``lookup_order`` (READ) runs freely.
- ``add_note`` (WRITE) runs freely under the default policy — but every
  call lands in ``audit.jsonl``, with the ``api_key`` argument redacted.
- ``cancel_order`` (DESTRUCTIVE) requires approval. The demo approver is a
  terminal prompt: the model asks, *you* decide, the verdict gets logged.
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from mcp_gatehouse import AccessTier, ApprovalRequest, AuditLog, Gatehouse, Policy

# A stand-in for your real system of record.
ORDERS = {
    "4417": {"customer": "Blue Ridge Cabinets", "status": "packed", "notes": []},
    "4418": {"customer": "Piedmont Supply", "status": "picking", "notes": []},
}


def terminal_approver(request: ApprovalRequest) -> bool:
    """Ask whoever ran the server — on the controlling terminal, never stdio.

    Over the stdio transport, stdout/stdin ARE the JSON-RPC pipe; printing
    a prompt there would corrupt the protocol. So the prompt goes to
    ``/dev/tty``. No terminal available (Windows service, container)?
    The gate fails closed.
    """
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(
                f"\n⚠ approval needed → {request.tool} {request.arguments}\n"
                "allow? [y/N] "
            )
            tty.flush()
            return tty.readline().strip().lower() == "y"
    except OSError:
        sys.stderr.write(
            f"mcp-gatehouse demo: no terminal for approval; "
            f"denying {request.tool} (fail closed)\n"
        )
        return False


mcp = FastMCP("gatehouse-order-desk")
gatehouse = Gatehouse(
    mcp,
    policy=Policy(approver=terminal_approver),
    audit=AuditLog(path="audit.jsonl"),
)


@gatehouse.tool(tier=AccessTier.READ)
def lookup_order(order_id: str) -> str:
    """Look up an order's status."""
    order = ORDERS.get(order_id)
    if order is None:
        return f"no order {order_id}"
    return f"{order_id} · {order['customer']} · {order['status']}"


@gatehouse.tool(tier=AccessTier.WRITE)
def add_note(order_id: str, note: str, api_key: str = "") -> str:
    """Attach a note to an order. (The api_key never reaches the log.)"""
    if order_id not in ORDERS:
        return f"no order {order_id}"
    ORDERS[order_id]["notes"].append(note)
    return f"note added to {order_id}"


@gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
def cancel_order(order_id: str) -> str:
    """Cancel an order. Requires approval — the gate fails closed."""
    if order_id not in ORDERS:
        return f"no order {order_id}"
    ORDERS[order_id]["status"] = "cancelled"
    return f"{order_id} cancelled"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
