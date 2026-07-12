"""A copyable template: the demo order-desk server, spelled out.

This is the same server `mcp-gatehouse-demo` runs — copy it and swap the
ORDERS dict for your real system. The approver comes from the package
because prompting a human is trickier than it looks: over the stdio
transport, stdout/stdin are the protocol pipe, so the prompt must go to
the controlling terminal (and fail closed when there isn't one).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy
from mcp_gatehouse.demo import terminal_approver

# A stand-in for your real system of record.
ORDERS = {
    "4417": {"customer": "Blue Ridge Cabinets", "status": "packed", "notes": []},
    "4418": {"customer": "Piedmont Supply", "status": "picking", "notes": []},
}

mcp = FastMCP("order-desk")
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


if __name__ == "__main__":
    mcp.run()
