"""A copyable template: the demo order-desk server, spelled out.

A trimmed copy of the server `mcp-gatehouse-demo` runs — copy it and swap the
OrderDesk for your real system. What it shows:

- Every tool names its policy. The gate loads the order from the model's
  `order_id`, gives it to the policy, and hands the tool that same order:
  the model can't describe an order into existence, or reach one that
  isn't the caller's.
- Over stdio nobody signs in, so the server declares who calls are for:
  `local_caller`. Over HTTP, use the SDK's auth instead, and the gate reads
  the caller from the verified token.
- Writes carry the version they were checked at, so a record that changed
  after the check is never overwritten (`ConditionalWrite`). With a real
  database, prefer `Transaction(...)`: see `orders_postgres.py`.
- `list_orders` returns records, and the gate withholds the ones the
  caller may not see.
"""

from __future__ import annotations

import getpass
import threading
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from mcp_gatehouse import (
    AccessTier,
    Allow,
    Ask,
    AuditLog,
    AuthorizationRequest,
    Caller,
    ConditionalWrite,
    Conflict,
    Decision,
    Deny,
    ElicitationApprover,
    Gatehouse,
    Load,
    Policy,
    any_caller,
    terminal_approver,
)

YOU = Caller(client_id="local", subject=getpass.getuser())


class Order(BaseModel):
    id: str
    customer: str
    owner: str
    status: str
    total: float
    version: int = 1
    notes: list[str] = Field(default_factory=list)


class OrderDesk:
    """A stand-in for your real system of record."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._orders = {
            o.id: o
            for o in (
                Order(id="4417", customer="Blue Ridge Cabinets", owner=YOU.subject or "", status="packed", total=812.0),
                Order(id="4418", customer="Piedmont Supply", owner=YOU.subject or "", status="picking", total=240.0),
                Order(id="4420", customer="Coastal Hardware", owner="dana", status="packed", total=95.0),
            )
        }

    def get(self, order_id: str) -> Order | None:
        with self._lock:
            order = self._orders.get(order_id)
            return None if order is None else order.model_copy(deep=True)

    def all(self) -> list[Order]:
        with self._lock:
            return [o.model_copy(deep=True) for o in self._orders.values()]

    def update(self, order: Order, **changes: object) -> None:
        """`UPDATE … WHERE id = ? AND version = ?`: no match, no write."""
        with self._lock:
            current = self._orders.get(order.id)
            if current is None or current.version != order.version:
                raise Conflict()
            self._orders[order.id] = current.model_copy(update={**changes, "version": current.version + 1})


desk = OrderDesk()


def yours(request: AuthorizationRequest) -> Decision:
    order = request.resource if request.action == "read" else request.resources["order"]
    return Allow() if order.owner == request.caller.subject else Deny("someone else's order")


def can_cancel(request: AuthorizationRequest) -> Decision:
    order: Order = request.resources["order"]
    if order.owner != request.caller.subject:
        return Deny("someone else's order")
    if order.status in ("shipped", "cancelled"):
        return Deny(order.status, message=f"Order {order.id} is {order.status}.")
    if order.total > 500:
        return Ask("order over $500")
    return Allow()


THE_ORDER = Load(desk.get, describe=lambda o: f"order {o.id} · {o.customer} · ${o.total:,.2f}")

OrderId = Annotated[
    str, Field(description="The order's ID, e.g. '4417'. Use list_orders to find one.")
]

mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    policy=Policy(approver=ElicitationApprover(fallback=terminal_approver), approval_timeout=120),
    # Anchored to this file, not the working directory: desktop clients
    # often launch servers from `/`, where a relative path isn't writable.
    audit=AuditLog(path=Path(__file__).with_name("audit.jsonl")),
    local_caller=YOU,
    consistency=ConditionalWrite(),
)


@gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=yours)
def list_orders() -> list[Order]:
    """List your orders. Read-only. Start here to find an order ID."""
    return desk.all()


@gatehouse.tool(tier=AccessTier.READ, authorize=yours)
def lookup_order(order_id: OrderId, order: Annotated[Order, THE_ORDER]) -> str:
    """Look up one of your orders. Read-only."""
    return f"{order.id} · {order.customer} · {order.status} · notes: {'; '.join(order.notes) or 'none'}"


@gatehouse.tool(tier=AccessTier.WRITE, authorize=yours)
def add_note(
    order_id: OrderId,
    note: Annotated[str, Field(description="Free-text note to append.")],
    order: Annotated[Order, THE_ORDER],
) -> str:
    """Append a note to one of your orders. Never overwrites or cancels
    anything; use cancel_order to stop an order."""
    desk.update(order, notes=[*order.notes, note])
    return f"note added to {order.id}"


@gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel)
def cancel_order(order_id: OrderId, order: Annotated[Order, THE_ORDER]) -> str:
    """Cancel one of your orders. Irreversible, so a human must approve
    first — the gate fails closed. To record information, use add_note."""
    desk.update(order, status="cancelled")
    return f"{order.id} cancelled"


if __name__ == "__main__":
    mcp.run()
