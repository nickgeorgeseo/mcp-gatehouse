"""A copyable template: the demo order-desk server, spelled out.

This is the same server `mcp-gatehouse-demo` runs — copy it and swap the
ORDERS dict for your real system. The approver comes from the package
because prompting a human is trickier than it looks: over the stdio
transport, stdout/stdin are the protocol pipe, so the prompt must go to
the controlling terminal (and fail closed when there isn't one).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy, terminal_approver

# A stand-in for your real system of record.
ORDERS = {
    "4417": {"customer": "Blue Ridge Cabinets", "status": "packed", "notes": []},
    "4418": {"customer": "Piedmont Supply", "status": "picking", "notes": []},
}

OrderId = Annotated[
    str, Field(description="The order's ID, e.g. '4417'. Use list_orders to find one.")
]

mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    policy=Policy(approver=terminal_approver),
    # Anchored to this file, not the working directory: desktop clients
    # often launch servers from `/`, where a relative path isn't writable.
    audit=AuditLog(path=Path(__file__).with_name("audit.jsonl")),
)


@gatehouse.tool(tier=AccessTier.READ)
def list_orders() -> str:
    """List every order as `id · customer · status`, one per line.
    Read-only. Start here to find an order ID."""
    return "\n".join(f"{oid} · {o['customer']} · {o['status']}" for oid, o in ORDERS.items())


@gatehouse.tool(tier=AccessTier.READ)
def lookup_order(order_id: OrderId) -> str:
    """Look up one order's customer, status and notes. Read-only."""
    order = ORDERS.get(order_id)
    if order is None:
        return f"no order {order_id}"
    notes = "; ".join(order["notes"]) or "none"
    return f"{order_id} · {order['customer']} · {order['status']} · notes: {notes}"


@gatehouse.tool(tier=AccessTier.WRITE)
def add_note(
    order_id: OrderId,
    note: Annotated[str, Field(description="Free-text note to append.")],
    api_key: Annotated[str, Field(description="Optional credential; masked in the audit log.")] = "",
) -> str:
    """Append a note to an order. Never overwrites or cancels anything;
    use cancel_order to stop an order."""
    if order_id not in ORDERS:
        return f"no order {order_id}"
    ORDERS[order_id]["notes"].append(note)
    return f"note added to {order_id}"


@gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
def cancel_order(order_id: OrderId) -> str:
    """Cancel an order. Irreversible, so a human must approve first — the
    gate fails closed. To record information instead, use add_note."""
    if order_id not in ORDERS:
        return f"no order {order_id}"
    ORDERS[order_id]["status"] = "cancelled"
    return f"{order_id} cancelled"


if __name__ == "__main__":
    mcp.run()
