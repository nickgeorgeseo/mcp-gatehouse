"""Postgres: check and write in one transaction, and row-level security for lists.

A sketch to copy, not run in CI. It needs `pip install "psycopg[binary]"`
and a database set up like this:

    CREATE TABLE orders (
        id       text PRIMARY KEY,
        customer text    NOT NULL,
        owner    text    NOT NULL,
        status   text    NOT NULL,
        total    numeric NOT NULL,
        version  int     NOT NULL DEFAULT 1
    );
    ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
    ALTER TABLE orders FORCE ROW LEVEL SECURITY;
    CREATE POLICY own_orders ON orders
        USING (owner = current_setting('app.subject', true));
    CREATE ROLE order_desk LOGIN PASSWORD '…';
    GRANT SELECT, UPDATE ON orders TO order_desk;

and `ORDERS_DSN` pointing at it as that role. Superusers and roles with
BYPASSRLS skip row-level security even with FORCE, so never connect as one.

Verified against Postgres 16: the list shows only the caller's rows,
someone else's order reads as not found, approvals show the record, and a
row edited while a person decides is asked about again.

The three layers, strongest first:

1. **Row-level security.** The transaction tells Postgres who is asking
   (`app.subject`), so every query the loader or the tool runs sees that
   caller's rows and no others. Someone else's order doesn't load, and the
   model hears the same "not permitted" as for an order that doesn't exist.
2. **The check and the write in one transaction.** The loader locks the
   row (`FOR UPDATE`); the policy decides on it; the tool writes; the gate
   commits. A refusal or an error rolls back. Nothing can change the row in
   between.
3. **The gate's backstop.** `authorize_items` checks each order
   `list_orders` returns. With row-level security working it withholds
   nothing; if the audit log ever shows `withheld` above zero, the database
   and the policy disagree.

Over stdio, as here, calls are for the declared local user. To serve many
users, run it over streamable HTTP with the SDK's auth (`token_verifier=`,
`auth=`), drop `local_caller`, and the gate takes each caller from their
verified token.
"""

from __future__ import annotations

import contextlib
import getpass
import os
from collections.abc import Iterator
from decimal import Decimal
from typing import Annotated

import psycopg
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from mcp_gatehouse import (
    AccessTier,
    Allow,
    Ask,
    AuditLog,
    AuthorizationRequest,
    Caller,
    Decision,
    Deny,
    ElicitationApprover,
    Gatehouse,
    Load,
    Policy,
    Transaction,
    any_caller,
    current_transaction,
)

DSN = os.environ.get("ORDERS_DSN", "postgresql:///orders")


class Order(BaseModel):
    id: str
    customer: str
    owner: str
    status: str
    total: Decimal
    version: int


@contextlib.contextmanager
def transaction(caller: Caller) -> Iterator[psycopg.Connection]:
    """One transaction per call, for this caller. The gate runs the loader,
    the policy and the tool inside it, all on this thread, and exits it with
    the exception when it refuses, which rolls it back."""
    with psycopg.connect(DSN) as conn, conn.transaction():
        # Local to this transaction: row-level security sees only this caller.
        conn.execute("SELECT set_config('app.subject', %s, true)", (caller.subject or "",))
        yield conn


def load_order(order_id: str) -> Order | None:
    """Lock the row until the transaction ends, so the policy's decision
    still holds when the tool writes."""
    row = current_transaction().execute(
        "SELECT id, customer, owner, status, total, version FROM orders WHERE id = %s FOR UPDATE",
        (order_id,),
    ).fetchone()
    if row is None:
        return None
    return Order(id=row[0], customer=row[1], owner=row[2], status=row[3], total=row[4], version=row[5])


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


THE_ORDER = Load(load_order, describe=lambda o: f"order {o.id} · {o.customer} · ${o.total:,.2f}")
OrderId = Annotated[str, Field(description="The order's ID, e.g. '4417'.")]

mcp = MCPServer("order-desk-postgres")
gatehouse = Gatehouse(
    mcp,
    policy=Policy(approver=ElicitationApprover(), approval_timeout=120),
    audit=AuditLog(path="audit.jsonl"),
    local_caller=Caller(client_id="local", subject=getpass.getuser()),
    consistency=Transaction(transaction),
)


@gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=yours)
def list_orders() -> list[Order]:
    """List your orders."""
    # No WHERE owner = …: row-level security already limits this to the caller.
    rows = current_transaction().execute(
        "SELECT id, customer, owner, status, total, version FROM orders ORDER BY id"
    ).fetchall()
    return [Order(id=r[0], customer=r[1], owner=r[2], status=r[3], total=r[4], version=r[5]) for r in rows]


@gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel)
def cancel_order(order_id: OrderId, order: Annotated[Order, THE_ORDER]) -> str:
    """Cancel one of your orders. Irreversible, so a person approves first."""
    current_transaction().execute(
        "UPDATE orders SET status = 'cancelled', version = version + 1 WHERE id = %s", (order.id,)
    )
    return f"{order.id} cancelled"


if __name__ == "__main__":
    mcp.run()
