"""One gated tool, line by line. Run it: python examples/gated_tool.py

Comment lines starting with ``#>`` are callouts for the recorded walkthrough
(docs/gated-tool-demo.tape); docs/typewriter.py leaves them out of the file
it writes. Read them as margin notes.
"""
# --- 1. The pieces
# A gated server is an ordinary MCPServer with a Gatehouse in front of it.
#> Any agent framework: the gate lives in the MCP server, so the client and its framework don't matter.
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

# Everything the gate needs comes from one import.
from mcp_gatehouse import (
    AccessTier, Allow, AuditLog, AuthorizationRequest, Caller, ConditionalWrite,
    Conflict, Deny, ElicitationApprover, Gatehouse, Load, Policy,
)

# --- 2. The record
# The record a call acts on. Any Pydantic model, dataclass or mapping will do.
class Order(BaseModel):
    id: str
    owner: str
    status: str
    version: int = 1  # bumped on every write, so a stale write can be refused

# A stand-in for your database: two orders, two owners.
ORDERS = {
    "4417": Order(id="4417", owner="nick", status="packed"),
    "4420": Order(id="4420", owner="dana", status="packed"),
}

# The loader. Its parameter name says which tool argument it loads from.
# None means "no such order", and the model is told nothing more than that.
#> Resource-level: the decision will be made on this loaded record, not on the model's arguments.
def load_order(order_id: str) -> Order | None:
    return ORDERS.get(order_id)

# --- 3. The policy
# A policy is a plain function. It gets the verified caller and the loaded record...
#> The same check the API would run: the rule is yours. The gate only guarantees it runs, here, every call.
def owner_only(request: AuthorizationRequest) -> Allow | Deny:
    order = request.resources["order"]
    # ...and returns a decision. Deny's reason goes to the audit log, never to the model.
    if order.owner != request.caller.subject:
        return Deny("not the owner")
    return Allow()
#> Or keep the rule in OPA or Cerbos: examples/policy_opa.py sends the caller and the loaded record to the engine. Unreachable means Deny.

# --- 4. The gate
# Build the server as the SDK docs show, then put the gate in front of it.
mcp = MCPServer("order-desk")
gatehouse = Gatehouse(
    mcp,
    # DESTRUCTIVE tools need a person's approval, asked in the client's own UI.
    #> Approval gates and tiers: the framework's mechanisms, enforced in the server instead of the prompt.
    policy=Policy(approver=ElicitationApprover()),
    #> Many replicas? ElicitationApprover(store=...) shares used approvals: one approval, one run. examples/approval_store_sqlite.py
    # One JSON line per call: allowed, denied, failed or cancelled.
    #> Audit: what did the AI do, and for whom.
    audit=AuditLog(path="audit.jsonl"),
    #> Or AuditLog(sink=...): the same record to OpenTelemetry, a queue or your logging pipeline. examples/audit_otel.py
    # Over stdio nobody signs in, so the server declares who its calls are for.
    #> Delegated identity: over HTTP the caller comes from the verified token. No god-mode service account.
    local_caller=Caller(client_id="local", subject="nick"),
)

# --- 5. A READ tool
# Register through the gate, never with @mcp.tool. The tier and the policy are both required.
#> Right by default: leave authorize= out and registration fails. Register around the gate and the tool is refused.
@gatehouse.tool(tier=AccessTier.READ, authorize=owner_only)
# The model sends order_id. It never sees `order`: the gate loads it from order_id,
# owner_only decides on it, and the tool is handed that same object.
#> Not in the prompt: nothing the gate fills can come from the model, so the boundary doesn't depend on instructions.
def lookup_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str:
    """Look up one of your orders."""
    return f"order {order.id} is {order.status}"

# --- 6. A DESTRUCTIVE tool
# Same shape. DESTRUCTIVE means a person approves before it runs, and the client
# is told the truth about it (destructiveHint) whether you like it or not.
#> Hiding the button isn't authorization: the tier can't be mislabelled, and the check runs when the tool is called.
@gatehouse.tool(
    tier=AccessTier.DESTRUCTIVE,
    authorize=owner_only,
    # The write carries the version it was checked at. A record that changed
    # between the check and the write is never overwritten.
    #> Defense in depth: the check and the write are one unit, so a stale decision is never acted on.
    consistency=ConditionalWrite(),
)
def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str:
    """Cancel one of your orders. A person approves it first."""
    # In SQL this is: UPDATE orders SET ... WHERE id = ? AND version = ?
    if ORDERS[order.id].version != order.version:
        raise Conflict()
    ORDERS[order.id] = order.model_copy(update={"status": "cancelled", "version": order.version + 1})
    return f"order {order.id} cancelled"

# --- 7. Run it
# Everything else is the plain SDK: transports, schemas, the lot.
#> Enforced at the tool level: every call passes the gate before the tool runs. The prompt never gets a vote.
if __name__ == "__main__":
    mcp.run()
