"""The gate sees through every way a parameter or return type can be
spelled: a marker behind a type alias is still the gate's to fill, and a
return type that may carry records still needs an item policy."""

from __future__ import annotations

import collections
import contextlib
import functools
import io
import json
import sys
import time
import typing
from collections.abc import Sequence
from typing import Annotated, Optional

import pytest
import typing_extensions
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import (
    AccessTier,
    Allow,
    Ask,
    AuditLog,
    AuthorizationRequest,
    Caller,
    Deny,
    Gatehouse,
    Load,
    Policy,
    Scope,
    Transaction,
    any_caller,
)

pytestmark = pytest.mark.anyio

LOCAL = Caller(client_id="test-client", subject="tester")


class Order(BaseModel):
    id: str
    owner: str


class Customer(BaseModel):
    id: str


def gated(policy: Policy | None = None, log: io.StringIO | None = None):
    mcp = MCPServer("shapes")
    gate = Gatehouse(
        mcp,
        policy=policy or Policy(require_approval=frozenset()),
        audit=AuditLog(stream=log or io.StringIO()),
        local_caller=LOCAL,
    )
    return mcp, gate


def events(log: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in log.getvalue().split("\n") if line]


# PEP 695 aliases, built without the `type` statement so this file still
# parses on 3.10 and 3.11: the backport always, the real one where it exists.
ALIASES = [typing_extensions.TypeAliasType]
if hasattr(typing, "TypeAliasType"):
    ALIASES.append(typing.TypeAliasType)


# --- markers behind aliases ------------------------------------------------------


@pytest.mark.parametrize("alias", ALIASES)
async def test_a_load_behind_a_type_alias_is_filled_by_the_gate(alias):
    store = {"1": Order(id="1", owner="someone-else")}
    LoadedOrder = alias("LoadedOrder", Annotated[Order, Load(lambda order_id: store.get(order_id))])
    mcp, gate = gated()
    seen = []

    def owners_only(request: AuthorizationRequest):
        seen.append(request.resources.get("order"))
        return Allow() if request.resources["order"].owner == request.caller.subject else Deny("not the owner")

    @gate.tool(authorize=owners_only)
    def show(order_id: str, order: LoadedOrder) -> str:  # type: ignore[valid-type]
        return order.owner

    async with Client(mcp) as client:
        (tool,) = (await client.list_tools()).tools
        result = await client.call_tool("show", {"order_id": "1", "order": {"id": "1", "owner": "tester"}})
    assert set(tool.input_schema.get("properties", {})) == {"order_id"}
    assert result.is_error and seen == [store["1"]]


@pytest.mark.parametrize("alias", ALIASES)
async def test_a_scope_behind_a_type_alias_is_not_model_input(alias):
    Owner = alias("Owner", Annotated[str, Scope(lambda request: request.caller.subject)])
    mcp, gate = gated()

    @gate.tool(authorize=any_caller)
    def search(owner: Owner) -> str:  # type: ignore[valid-type]
        return f"searched as {owner}"

    async with Client(mcp) as client:
        (tool,) = (await client.list_tools()).tools
        result = await client.call_tool("search", {"owner": "someone-else"})
    assert "owner" not in tool.input_schema.get("properties", {})
    assert result.structured_content == {"result": "searched as tester"}


@pytest.mark.parametrize("marker", [Load, Scope])
def test_the_bare_marker_class_is_refused(marker):
    _, gate = gated()
    with pytest.raises(TypeError, match=f"give it an instance: {marker.__name__}"):

        @gate.tool(authorize=any_caller)
        def show(order_id: str, order: Annotated[Order, marker]) -> str:
            return order.owner


# --- what counts as a list of records ---------------------------------------------


def register(returns, **tool):
    _, gate = gated()

    def list_orders():
        return []

    list_orders.__annotations__["return"] = returns
    gate.tool(authorize=any_caller, **tool)(list_orders)


@pytest.mark.parametrize(
    "returns",
    [
        list[Order],
        list[Optional[Order]],
        list[Order | None],
        typing_extensions.TypeAliasType("Orders", list[Order]),
        list[Order | Customer],
        list[Order] | tuple[Order, ...],
        Optional[list[Order]],
    ],
    ids=["list", "list-Optional", "list-or-None", "type-alias", "list-of-union", "list-or-tuple", "Optional-list"],
)
def test_every_spelling_of_a_list_of_records_needs_an_item_policy(returns):
    with pytest.raises(TypeError, match="authorize_items"):
        register(returns)
    register(returns, authorize_items=any_caller)  # and can be given one


def test_a_name_inside_the_return_type_is_evaluated():
    """list["Order"]: 3.11+ evaluates the name, so it's a list of records;
    3.10's get_type_hints leaves it a string, and the gate refuses what it
    can't read rather than let it through unfiltered."""
    if sys.version_info >= (3, 11):
        with pytest.raises(TypeError, match="authorize_items"):
            register(list["Order"])
        register(list["Order"], authorize_items=any_caller)
    else:
        with pytest.raises(TypeError, match="'Order', which doesn't evaluate"):
            register(list["Order"], authorize_items=any_caller)


def test_a_return_type_that_doesnt_evaluate_is_refused():
    with pytest.raises(TypeError, match="'NoSuchRecord'"):
        register(list["NoSuchRecord"])  # noqa: F821 - the point of the test


async def test_a_sequence_result_is_filtered():
    log = io.StringIO()
    mcp, gate = gated(log=log)

    def mine(request):
        return Allow() if request.resource.owner == request.caller.subject else Deny("not theirs")

    @gate.tool(authorize=any_caller, authorize_items=mine)
    def list_orders() -> Sequence[Order]:
        return collections.deque([Order(id="1", owner="tester"), Order(id="2", owner="someone-else")])

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert [o["id"] for o in result.structured_content["result"]] == ["1"]
    (line,) = events(log)
    assert line["withheld"] == 1


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
async def test_an_async_item_policy_behind_a_sync_wrapper_is_awaited():
    def logged(fn):
        @functools.wraps(fn)
        def wrapper(request):  # sync on the outside: returns the coroutine
            return fn(request)

        return wrapper

    @logged
    async def mine(request: AuthorizationRequest):
        target = request.resource if request.action == "read" else None
        return Allow() if target is None or target.owner == request.caller.subject else Deny("not theirs")

    log = io.StringIO()
    mcp, gate = gated(log=log)

    @gate.tool(authorize=mine, authorize_items=mine)
    def list_orders() -> list[Order]:
        return [Order(id="1", owner="tester"), Order(id="2", owner="someone-else")]

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert [o["id"] for o in result.structured_content["result"]] == ["1"]
    (line,) = events(log)
    assert (line["withheld"], line.get("filter_errors", 0)) == (1, 0)


# --- decisions ---------------------------------------------------------------------


@pytest.mark.parametrize("make", [lambda: Ask(None), lambda: Ask(""), lambda: Deny(None), lambda: Deny("  ")])
def test_a_decision_needs_a_reason(make):
    with pytest.raises(TypeError, match="non-empty str"):
        make()


async def test_an_ask_without_a_reason_never_runs_the_tool():
    log = io.StringIO()
    mcp, gate = gated(log=log)  # no approver, and READ needs no approval
    ran = []

    @gate.tool(tier=AccessTier.READ, authorize=lambda request: Ask(request.arguments.get("why")))
    def refund(order_id: str, why: str | None = None) -> str:
        ran.append(order_id)
        return "refunded"

    async with Client(mcp) as client:
        result = await client.call_tool("refund", {"order_id": "1"})
    assert ran == [] and result.is_error
    (line,) = events(log)
    assert (line["outcome"], line["reason"]) == ("denied", "policy error: TypeError")


async def test_an_ask_on_a_tier_without_approval_still_needs_an_approver():
    log = io.StringIO()
    mcp, gate = gated(policy=Policy(require_approval=frozenset(), fail_closed=False), log=log)
    ran = []

    @gate.tool(tier=AccessTier.READ, authorize=lambda request: Ask("a person should look"))
    def peek(order_id: str) -> str:
        ran.append(order_id)
        return "seen"

    async with Client(mcp) as client:
        result = await client.call_tool("peek", {"order_id": "1"})
    assert ran == [] and result.is_error
    (line,) = events(log)
    assert line["reason"] == "approval required, no approver configured"


async def test_a_late_deny_in_a_sync_transaction_is_still_a_deny():
    """With on_authorization_timeout=Ask a late answer becomes a question,
    but not a late no: that would put a refusal to a person."""

    @contextlib.contextmanager
    def transaction(caller):
        yield object()

    def slow_no(request):
        time.sleep(0.3)
        return Deny("not the owner")

    asked = []
    log = io.StringIO()
    policy = Policy(
        approver=lambda request: asked.append(request) or True,
        authorization_timeout=0.1,
        on_authorization_timeout=Ask,
    )
    mcp, gate = gated(policy=policy, log=log)
    ran = []

    @gate.tool(tier=AccessTier.READ, authorize=slow_no, consistency=Transaction(transaction))
    def peek(order_id: str) -> str:
        ran.append(order_id)
        return "seen"

    async with Client(mcp) as client:
        result = await client.call_tool("peek", {"order_id": "1"})
    assert ran == [] and asked == [] and result.is_error
    (line,) = events(log)
    assert line["reason"] == "policy: not the owner"
