"""Cerbos as the policy behind the gate.

The gate loads the record and guarantees the check runs; Cerbos holds the
rules. `cerbos_policy(url)` is an ordinary gate policy: it sends the
principal, the resource (the loaded record's attributes) and the actions
to Cerbos's check API and maps the effects to `Allow`, `Deny` or `Ask`.
The library doesn't import this file; copy it.

Cerbos answers allow or deny per action and has no "ask", so the policy
checks two actions for every call: the tool's own name (`cancel_order`)
and the same with `:unattended` (`cancel_order:unattended`). Allowed on
both: `Allow`. Allowed on the first only: `Ask`, a person must approve.
Denied on the first: `Deny`. For one item of a list result the action is
`read`, with no second check. What Cerbos gets:

    {
      "requestId": "cancel_order",
      "principal": {"id": "alice", "roles": ["user"],
                    "attr": {"client_id": "support-agent", "issuer": "...", "scopes": [...]}},
      "resources": [{"actions": ["cancel_order", "cancel_order:unattended"],
                     "resource": {"kind": "order", "id": "4417",
                                  "attr": {"id": "4417", "owner": "alice", "status": "packed", "total": 812.0}}}]
    }

The model's arguments are not sent: the engine decides on the record the
server loaded. Cerbos unreachable, or slow past `timeout`, is
`Deny("policy engine unavailable")` by default: a policy that can't decide
has decided no. The model is told the authorization service didn't answer
and the call can be retried, so "not now" doesn't read like "no".
`on_unavailable=Ask` sends those calls to the approver instead, with the
reason "policy engine unavailable"; with no approver configured they are
still denied. For one item of a list result, only `Allow` shows the item,
so an unreachable engine withholds it either way. An answer without the
actions asked about is a denial.

The engine-side policy for the order-desk demo (owner check, shipped
check, approval over $500), as `order.yaml` in the Cerbos policy
directory. Deny rules win, and nothing matched is a deny:

    apiVersion: api.cerbos.dev/v1
    resourcePolicy:
      version: default
      resource: order
      rules:
        - actions: ["read", "lookup_order", "add_note", "cancel_order"]
          effect: EFFECT_ALLOW
          roles: ["user"]
          condition:
            match:
              expr: request.resource.attr.owner == request.principal.id
        - actions: ["cancel_order"]
          effect: EFFECT_DENY
          roles: ["user"]
          condition:
            match:
              expr: request.resource.attr.status in ["shipped", "cancelled"]
        - actions: ["cancel_order:unattended"]
          effect: EFFECT_ALLOW
          roles: ["user"]
          condition:
            match:
              all:
                of:
                  - expr: request.resource.attr.owner == request.principal.id
                  - expr: request.resource.attr.total <= 500
        # Every tool that may run without a person needs its own
        # ':unattended' rule; without one the tool always asks.
        - actions: ["lookup_order:unattended", "add_note:unattended"]
          effect: EFFECT_ALLOW
          roles: ["user"]
          condition:
            match:
              expr: request.resource.attr.owner == request.principal.id

Run Cerbos with it (`cerbos server --config=...`, the PDP on :3592) and
wire the policy into any tool that loads one record:

    CERBOS = cerbos_policy("http://127.0.0.1:3592", kind="order")

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=CERBOS, consistency=ConditionalWrite())
    def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str: ...

    @gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=CERBOS)
    def list_orders() -> list[Order]: ...
"""

from __future__ import annotations

from typing import Any

from _engine_http import EngineError, attributes, post, record_of, subject_of, unavailable_decision

from mcp_gatehouse import Allow, Ask, AuthorizationRequest, Authorizer, Decision, Deny

ALLOW = "EFFECT_ALLOW"
UNATTENDED = ":unattended"


def cerbos_policy(
    url: str,
    *,
    kind: str,
    roles: tuple[str, ...] = ("user",),
    timeout: float = 2.0,
    on_unavailable: type[Deny] | type[Ask] = Deny,
) -> Authorizer:
    """A gate policy that asks the Cerbos PDP at ``url`` about resources
    of ``kind``. ``roles`` are the principal's roles; Cerbos needs one.

    ``on_unavailable`` is what Cerbos unreachable decides: ``Deny`` refuses
    the call and tells the model it can retry; ``Ask`` puts it to the
    approver."""
    endpoint = url.rstrip("/") + "/api/check/resources"
    unavailable = unavailable_decision(on_unavailable)

    def decide(request: AuthorizationRequest) -> Decision:
        _, record = record_of(request)
        attrs = attributes(record)
        caller = subject_of(request)
        action = "read" if request.action == "read" else request.tool
        actions = [action] if request.action == "read" else [action, action + UNATTENDED]
        payload = {
            "requestId": request.tool,
            "principal": {
                # A subject the token didn't name can only be the client.
                "id": caller["subject"] or caller["client_id"],
                "roles": list(roles),
                "attr": {k: v for k, v in caller.items() if k != "subject"},
            },
            "resources": [
                {
                    "actions": actions,
                    "resource": {"kind": kind, "id": str(attrs.get("id", request.tool)), "attr": attrs},
                }
            ],
        }
        try:
            answer = post(endpoint, payload, timeout)
        except ConnectionError:
            return unavailable
        except EngineError as exc:
            return Deny(exc.reason)
        return to_decision(answer, actions)

    return decide


def to_decision(answer: Any, actions: list[str]) -> Decision:
    """Cerbos's check answer as the gate's decision. ``actions`` are the ones
    asked about: the action, then (for a call) its ``:unattended`` twin.
    Anything unexpected denies, including an answer that skips one."""
    try:
        (result,) = answer["results"]
        effects: dict[str, Any] = result["actions"]
    except (KeyError, TypeError, ValueError):
        return Deny("policy engine returned no decision")
    missing = [a for a in actions if a not in effects]
    if missing:
        return Deny(f"policy engine returned no decision for {missing[0]!r}")
    action = actions[0]
    if effects[action] != ALLOW:
        return Deny(f"policy engine: {effects[action]}")
    if len(actions) > 1 and effects[actions[1]] != ALLOW:
        return Ask("policy engine requires approval")
    return Allow()
