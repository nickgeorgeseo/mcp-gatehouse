"""The installable demo server: an order desk with the gate closed.

Run it with `mcp-gatehouse-demo` (or `python -m mcp_gatehouse.demo`) and
wire it into any MCP client over stdio. Nobody signs in over stdio, so the
server declares who its calls are for: you, the user running it. Every
order has an owner, and the policies decide on the order itself:

- ``list_orders`` (READ) returns your orders only: the gate checks each one
  it returned and withholds the rest, counting them in the audit log.
- ``lookup_order`` (READ) and ``add_note`` (WRITE) load the order, check
  it's yours, and hand the tool that same order. ``add_note``'s
  ``api_key`` argument is redacted in the log.
- ``cancel_order`` (DESTRUCTIVE) also refuses an order that has shipped,
  and needs your approval: in the client's own UI when the client supports
  elicitation (Claude Code, Cursor, VS Code), on the server's terminal
  otherwise. Above $500 the form says so.

Writes are conditional on the order's version, so an order that changed
after the check is never overwritten. Every call, allowed or not, lands in
the audit log.

The audit log goes to ``--audit-log PATH``, else ``$MCP_GATEHOUSE_AUDIT_LOG``,
else ``./audit.jsonl`` — falling back to ``~/.mcp-gatehouse/audit.jsonl``
when the working directory isn't writable (desktop clients often launch
servers from ``/``). The resolved path is printed to stderr at startup.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from mcp_gatehouse import (
    AccessTier,
    Allow,
    Approver,
    Ask,
    AuditLog,
    AuthorizationRequest,
    Caller,
    ConditionalWrite,
    Conflict,
    Decision,
    Deny,
    Gatehouse,
    Load,
    Policy,
    __version__,
    any_caller,
)
from mcp_gatehouse.approvers import ElicitationApprover, terminal_approver

__all__ = ["DEMO_APPROVER", "build_server", "main", "terminal_approver"]

#: Ask in the client when it can; else prompt on the server's terminal.
DEMO_APPROVER = ElicitationApprover(fallback=terminal_approver)

AUDIT_ENV_VAR = "MCP_GATEHOUSE_AUDIT_LOG"
FALLBACK_AUDIT_PATH = Path.home() / ".mcp-gatehouse" / "audit.jsonl"

#: Cancelling an order worth more than this needs the approver to know why.
APPROVAL_THRESHOLD = 500.0

# Whose order 4420 is: someone other than you, so you can watch the gate
# keep it from you.
SOMEONE_ELSE = "dana"


class Order(BaseModel):
    """One order on the desk."""

    id: str
    customer: str
    owner: str
    status: str
    total: float
    version: int = 1
    notes: list[str] = Field(default_factory=list)


class OrderDesk:
    """A stand-in for your real system of record, with a versioned write."""

    def __init__(self, you: str) -> None:
        self._lock = threading.Lock()
        self._orders = {
            order.id: order
            for order in (
                Order(id="4417", customer="Blue Ridge Cabinets", owner=you, status="packed", total=812.0),
                Order(id="4418", customer="Piedmont Supply", owner=you, status="picking", total=240.0),
                Order(id="4419", customer="Tidewater Mill", owner=you, status="shipped", total=1190.0),
                Order(id="4420", customer="Coastal Hardware", owner=SOMEONE_ELSE, status="packed", total=95.0),
            )
        }

    def get(self, order_id: str) -> Order | None:
        """The loader: a copy of the order as it is now, or ``None``."""
        with self._lock:
            order = self._orders.get(order_id)
            return None if order is None else order.model_copy(deep=True)

    def all(self) -> list[Order]:
        with self._lock:
            return [order.model_copy(deep=True) for order in self._orders.values()]

    def update(self, order: Order, **changes: object) -> None:
        """Write only if the order is still the version that was checked:
        ``UPDATE … WHERE id = ? AND version = ?``. Otherwise, ``Conflict``."""
        with self._lock:
            current = self._orders.get(order.id)
            if current is None or current.version != order.version:
                raise Conflict()
            self._orders[order.id] = current.model_copy(update={**changes, "version": current.version + 1})


OrderId = Annotated[
    str, Field(description="The order's ID, e.g. '4417'. Use list_orders to find one.")
]


def yours(request: AuthorizationRequest) -> Decision:
    """Policy for one order: only its owner may touch it."""
    order = request.resource if request.action == "read" else request.resources["order"]
    if order.owner != request.caller.subject:
        return Deny("someone else's order")
    return Allow()


def can_cancel(request: AuthorizationRequest) -> Decision:
    """Policy for cancelling: your order, not shipped, not already cancelled.
    Above the threshold, the approver is told why it's being asked."""
    order: Order = request.resources["order"]
    if order.owner != request.caller.subject:
        return Deny("someone else's order")
    if order.status == "shipped":
        return Deny("already shipped", message=f"Order {order.id} has shipped, so it can't be cancelled.")
    if order.status == "cancelled":
        return Deny("already cancelled", message=f"Order {order.id} is already cancelled.")
    if order.total > APPROVAL_THRESHOLD:
        return Ask(f"order over ${APPROVAL_THRESHOLD:,.0f}")
    return Allow()


def describe(order: Order) -> str:
    """What the approver sees the cancel will act on."""
    return f"order {order.id} · {order.customer} · {order.status} · ${order.total:,.2f}"


def build_server(
    audit: AuditLog,
    approver: Approver | None = DEMO_APPROVER,
    *,
    you: Caller | None = None,
) -> MCPServer:
    """The order-desk server, wired through a gatehouse. Nothing happens at
    import time — no server, no log file — until you call this.

    ``you`` is who calls are for over stdio, where nobody signs in: by
    default the user running the server.
    """
    you = you or Caller(client_id="local", subject=getpass.getuser())
    desk = OrderDesk(you=you.subject or "")
    mcp = MCPServer(
        "gatehouse-order-desk",
        version=__version__,
        website_url="https://github.com/nickgeorgeseo/mcp-gatehouse",
        instructions=(
            "A demo order desk behind mcp-gatehouse. Every order has an owner, "
            "and you can see and change only your own: list_orders shows them, "
            "lookup_order reads one, add_note appends to one, and cancel_order "
            "needs a human's approval, asked in this client when it supports "
            "elicitation and on the server's terminal otherwise, and is denied "
            "if nobody approves within two minutes. Every call, allowed or "
            "denied, is written to an audit log."
        ),
    )
    # An approval nobody gives is denied and logged after two minutes, rather
    # than left hanging until the client gives up.
    policy = Policy(approver=approver, approval_timeout=120)
    gatehouse = Gatehouse(
        mcp,
        policy=policy,
        audit=audit,
        local_caller=you,
        # Writes carry the version they were checked at (OrderDesk.update).
        consistency=ConditionalWrite(),
    )
    # changed_values: describe= already shows the order's fields, so a
    # change line may too ("order.total: 812.0 → 812.01"), not just name them.
    the_order = Load(desk.get, describe=describe, changed_values=True)

    # Anyone signed in may list; what they see is decided order by order.
    @gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=yours)
    def list_orders() -> list[Order]:
        """List the orders on the desk that are yours: id, customer, status,
        total and notes. Read-only. Start here to find the order ID that
        lookup_order, add_note and cancel_order need."""
        # Every order, on purpose: the gate checks each one and withholds the
        # ones that aren't yours. A real server should ask its database for
        # the caller's orders only, and let the gate catch any it got wrong.
        return desk.all()

    @gatehouse.tool(tier=AccessTier.READ, authorize=yours)
    def lookup_order(order_id: OrderId, order: Annotated[Order, the_order]) -> str:
        """Look up one of your orders: customer, status, total and notes.
        Read-only; changes nothing. Refused if the order isn't yours or
        doesn't exist."""
        notes = "; ".join(order.notes) or "none"
        return f"{order.id} · {order.customer} · {order.status} · ${order.total:,.2f} · notes: {notes}"

    @gatehouse.tool(tier=AccessTier.WRITE, authorize=yours)
    def add_note(
        order_id: OrderId,
        note: Annotated[str, Field(description="Free-text note to append, e.g. 'customer asked for a callback'.")],
        order: Annotated[Order, the_order],
        api_key: Annotated[
            str,
            Field(description="Optional credential for the order system. Its value is masked in the audit log."),
        ] = "",
    ) -> str:
        """Append a note to one of your orders. Existing notes are kept — this
        never overwrites or cancels anything. Runs without approval, and every
        call is recorded in the audit log. To actually stop an order, use
        cancel_order."""
        desk.update(order, notes=[*order.notes, note])
        return f"note added to {order.id}"

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel)
    def cancel_order(order_id: OrderId, order: Annotated[Order, the_order]) -> str:
        """Cancel one of your orders. Irreversible, so it is gated: a human
        must approve before it runs, in this client's approval form if it
        shows one, else on the server's terminal. An order that has shipped
        can't be cancelled. If the approver refuses, doesn't answer within
        two minutes, or there is nowhere to ask, the call is denied and the
        refusal is logged. To record information without cancelling, use
        add_note."""
        desk.update(order, status="cancelled")
        return f"{order.id} cancelled"

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
