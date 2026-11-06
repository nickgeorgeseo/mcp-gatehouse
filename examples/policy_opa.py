"""Open Policy Agent as the policy behind the gate.

The gate loads the record and guarantees the check runs; OPA holds the
rules. `opa_policy(url)` is an ordinary gate policy: it sends the caller,
the tool, the action and the loaded record's attributes to OPA over HTTP
and maps OPA's answer to `Allow`, `Deny` or `Ask`. The library doesn't
import this file; copy it.

What OPA gets, as `input`:

    {
      "caller": {"client_id": "support-agent", "subject": "alice", "issuer": "...", "scopes": [...]},
      "tool": "cancel_order",
      "tier": "destructive",
      "action": "call",                # or "read" for one item of a list result
      "record": {"id": "4417", "owner": "alice", "status": "packed", "total": 812.0, ...}
    }

The model's arguments are not sent: the engine decides on the record the
server loaded, not on what the model said about it.

What OPA answers, as `result`:

    {"effect": "allow"}
    {"effect": "deny", "reason": "someone else's order"}
    {"effect": "ask", "reason": "order over $500"}

Anything else is a denial, and the audit line says what came back. OPA
unreachable, or slow past `timeout`, is `Deny("policy engine unavailable")`:
a policy that can't decide has decided no.

The engine-side policy for the order-desk demo (owner check, shipped
check, approval over $500), as `gatehouse.rego`:

    package gatehouse

    import rego.v1

    # The record this request is about.
    record := input.record

    decision := {"effect": "deny", "reason": "someone else's order"} if {
        record.owner != input.caller.subject
    } else := {"effect": "deny", "reason": "already shipped"} if {
        input.tool == "cancel_order"
        record.status in {"shipped", "cancelled"}
    } else := {"effect": "ask", "reason": "order over $500"} if {
        input.tool == "cancel_order"
        record.total > 500
    } else := {"effect": "allow"}

Run OPA with it (`opa run --server gatehouse.rego`) and the policy below
asks `POST /v1/data/gatehouse/decision`. Any tool that loads one record
can use it:

    OPA = opa_policy("http://127.0.0.1:8181")

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=OPA, consistency=ConditionalWrite())
    def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str: ...

    @gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=OPA)
    def list_orders() -> list[Order]: ...

`Deny(reason)` reaches the audit log, not the model; set `message=` in
`decide` below if the model may hear more.
"""

from __future__ import annotations

from typing import Any

from _engine_http import UNAVAILABLE, EngineError, attributes, post, record_of, subject_of

from mcp_gatehouse import Allow, Ask, AuthorizationRequest, Authorizer, Decision, Deny


def opa_policy(url: str, *, rule: str = "gatehouse/decision", timeout: float = 2.0) -> Authorizer:
    """A gate policy that asks OPA at ``url`` for ``data.<rule>``."""
    endpoint = url.rstrip("/") + "/v1/data/" + rule.strip("/")

    def decide(request: AuthorizationRequest) -> Decision:
        _, record = record_of(request)
        payload = {
            "input": {
                "caller": subject_of(request),
                "tool": request.tool,
                "tier": request.tier.value,
                "action": request.action,
                "record": attributes(record),
            }
        }
        try:
            answer = post(endpoint, payload, timeout)
        except ConnectionError:
            return UNAVAILABLE
        except EngineError as exc:
            return Deny(exc.reason)
        return to_decision(answer.get("result") if isinstance(answer, dict) else None)

    return decide


def to_decision(result: Any) -> Decision:
    """OPA's ``result`` as the gate's decision. Anything unexpected denies."""
    if not isinstance(result, dict) or "effect" not in result:
        return Deny("policy engine returned no decision")
    effect, reason = result.get("effect"), result.get("reason")
    reason = str(reason) if reason is not None else "policy engine"
    if effect == "allow":
        return Allow()
    if effect == "deny":
        return Deny(reason)
    if effect == "ask":
        return Ask(reason)
    return Deny(f"policy engine returned an unknown effect: {effect!r}")
