"""Authorization as a runtime invariant.

Every call needs a verified caller, an explicit policy, and a decision on
the record it acts on. Anything missing fails closed, and nothing on the
server runs a tool around the gate. These tests use the real Gatehouse,
with every declaration spelled out.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import sys
import threading
import time
from typing import Annotated, Any

import anyio
import pytest
from mcp import Client
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.extension import Extension, ToolBinding
from mcp.server.mcpserver import Context, MCPServer, Resolve
from mcp.server.mcpserver.tools.base import Tool
from mcp.server.mcpserver.tools.tool_manager import ToolManager
from mcp.types import ElicitResult, InputRequiredResult
from pydantic import BaseModel

from mcp_gatehouse import (
    AcceptRace,
    AccessTier,
    Allow,
    ApprovalRequest,
    Ask,
    AuditLog,
    AuthorizationRequest,
    Caller,
    ConditionalWrite,
    Conflict,
    Deny,
    ElicitationApprover,
    GateDenied,
    Gatehouse,
    Load,
    Policy,
    Scope,
    Transaction,
    any_caller,
    any_item,
    current_transaction,
)
from mcp_gatehouse.approvers import _default_message

from _support import LOCAL, LOCAL_ENTRY, http_server, signed_in, token

NO_TIER_APPROVAL = Policy(require_approval=frozenset())
NOT_PERMITTED = "is not permitted for this caller"


class Order(BaseModel):
    id: str
    owner: str
    status: str = "open"
    total: float = 100.0
    version: int = 1


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def reasons(stream: io.StringIO) -> list[tuple[str, str | None]]:
    return [(e["outcome"], e.get("reason")) for e in events(stream)]


def text(result: Any) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


def gated(policy: Policy = NO_TIER_APPROVAL, *, log: io.StringIO | None = None, local: Caller | None = LOCAL,
          **gate: Any) -> tuple[MCPServer, Gatehouse]:
    mcp = MCPServer("authz-test")
    audit = AuditLog(stream=log) if log is not None else None
    return mcp, Gatehouse(mcp, policy=policy, audit=audit, local_caller=local, **gate)


def owners_only(request: AuthorizationRequest):
    order = request.resource if request.action == "read" else request.resources["order"]
    return Allow() if order.owner == request.caller.subject else Deny("not the owner")


def sneaky() -> str:
    """A tool nobody gated."""
    return "ran around the gate"


# --- a policy for every tool --------------------------------------------------


def test_a_tool_without_a_policy_does_not_register():
    mcp, gk = gated()
    with pytest.raises(TypeError, match="needs a policy"):
        @gk.tool(tier=AccessTier.READ)
        def lookup(order_id: str) -> str:
            return order_id
    assert mcp._tool_manager.list_tools() == []


def test_parentheses_and_annotations_errors_still_come_first():
    _, gk = gated()
    with pytest.raises(TypeError, match="parentheses"):
        gk.tool(lambda: None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="derived from the tier"):
        gk.tool(tier=AccessTier.READ, annotations={"readOnlyHint": False})


# --- no way around the gate ---------------------------------------------------


class ExtraTools(Extension):
    identifier = "com.example/extra"

    def tools(self):
        return (ToolBinding(fn=sneaky),)


@pytest.mark.parametrize(
    "make",
    [
        lambda: _with_decorated_tool(MCPServer("t")),
        lambda: MCPServer("t", tools=[Tool.from_function(sneaky)]),
        lambda: MCPServer("t", extensions=[ExtraTools()]),
    ],
    ids=["decorated-first", "tools=", "extensions="],
)
def test_a_server_with_tools_already_on_it_is_refused(make):
    with pytest.raises(ValueError, match="outside the gate: sneaky"):
        Gatehouse(make(), local_caller=LOCAL)


def _with_decorated_tool(mcp: MCPServer) -> MCPServer:
    mcp.tool()(sneaky)
    return mcp


def test_a_server_gets_one_gatehouse():
    mcp, _ = gated()
    with pytest.raises(ValueError, match="already has a Gatehouse"):
        Gatehouse(mcp)


@pytest.mark.anyio
async def test_registering_around_the_gate_is_refused_before_and_after_startup():
    mcp, gk = gated()

    @gk.tool(authorize=any_caller)
    def lookup(order_id: str) -> str:
        return order_id

    with pytest.raises(TypeError, match="gated"):
        mcp.tool()(sneaky)
    with pytest.raises(TypeError, match="gated"):
        mcp._tool_manager.add_tool(sneaky)
    async with Client(mcp) as client:
        with pytest.raises(TypeError, match="gated"):
            mcp.add_tool(sneaky)  # a tool added while the server runs
        names = [tool.name for tool in (await client.list_tools()).tools]
    assert names == ["lookup"]


def test_a_name_is_registered_once():
    _, gk = gated()

    @gk.tool(authorize=any_caller)
    def lookup(order_id: str) -> str:
        return order_id

    with pytest.raises(ValueError, match="already registered"):
        @gk.tool(authorize=any_caller, name="lookup")
        def other(order_id: str) -> str:
            return order_id


@pytest.mark.anyio
@pytest.mark.parametrize("connect", [{}, {"mode": "legacy"}], ids=["round-trip", "legacy"])
async def test_a_tool_slipped_into_the_registry_is_refused_and_hidden(connect):
    log, ran = io.StringIO(), []
    mcp, gk = gated(log=log)

    @gk.tool(authorize=any_caller)
    def lookup(order_id: str) -> str:
        return order_id

    def impostor(order_id: str) -> str:
        ran.append(order_id)
        return "impostor"

    tools = mcp._tool_manager._tools
    tools["sneaky"] = Tool.from_function(sneaky)
    tools["lookup"] = Tool.from_function(impostor, name="lookup")  # swapped for the gated one

    async with Client(mcp, **connect) as client:
        assert (await client.list_tools()).tools == []
        for name, arguments in (("sneaky", {}), ("lookup", {"order_id": "1"})):
            result = await client.call_tool(name, arguments)
            assert result.is_error and "not registered through the gate" in text(result)
    assert ran == []
    assert reasons(log) == [("denied", "ungated tool"), ("denied", "ungated tool")]


@pytest.mark.anyio
async def test_a_swapped_registry_runs_nothing():
    mcp, gk = gated()

    @gk.tool(authorize=any_caller)
    def lookup(order_id: str) -> str:
        return order_id

    mcp._tool_manager = ToolManager(tools=[Tool.from_function(sneaky)])
    async with Client(mcp) as client:
        result = await client.call_tool("sneaky", {})
    assert result.is_error and "not registered through the gate" in text(result)


@pytest.mark.anyio
async def test_calling_from_code_needs_a_signed_in_caller():
    """MCPServer.call_tool with no request behind it isn't stdio: the local
    caller doesn't apply, and only a verified token lets it through."""
    mcp, gk = gated()

    @gk.tool(authorize=any_caller)
    def lookup(order_id: str) -> str:
        return f"order {order_id}"

    with pytest.raises(GateDenied, match="needs a verified caller"):
        await mcp.call_tool("lookup", {"order_id": "1"})
    with signed_in(token("alice")):
        result = await mcp.call_tool("lookup", {"order_id": "1"})
    assert "order 1" in text(result)


# --- identity -----------------------------------------------------------------


@pytest.mark.anyio
async def test_anonymous_http_is_never_the_local_caller():
    """local_caller is for stdio. An HTTP request with no verified token is
    nobody, even on a server that declares a local caller."""
    log, ran = io.StringIO(), []

    def app(url: str):
        mcp, gk = gated(log=log)

        @gk.tool(authorize=any_caller)
        def lookup(order_id: str) -> str:
            ran.append(order_id)
            return order_id

        return mcp.streamable_http_app()

    async with http_server(app) as url:
        async with streamable_http_client(url) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("lookup", {"order_id": "1"})
    assert result.is_error and "needs a verified caller" in text(result)
    assert ran == []
    assert reasons(log) == [("denied", "no verified caller")]


@pytest.mark.anyio
async def test_the_local_caller_over_real_stdio(tmp_path):
    """The demo server, launched over stdio: calls are for the declared local
    user, and the log says it was local."""
    from mcp.client.stdio import StdioServerParameters, stdio_client

    audit = tmp_path / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_gatehouse.demo", "--audit-log", str(audit)]
    )
    async with Client(stdio_client(params)) as client:
        listing = text(await client.call_tool("list_orders", {}))
        other = await client.call_tool("lookup_order", {"order_id": "4420"})
    assert "4417" in listing and "4420" not in listing
    assert other.is_error and NOT_PERMITTED in text(other)
    lines = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [line["caller"]["source"] for line in lines] == ["local", "local"]
    assert lines[0]["withheld"] == 1
    assert lines[1]["reason"] == "policy: someone else's order"


@pytest.mark.anyio
async def test_a_missing_scope_is_denied_before_anything_loads():
    log, loaded = io.StringIO(), []
    mcp, gk = gated(log=log, local=None)

    def load(order_id: str) -> Order:
        loaded.append(order_id)
        return Order(id=order_id, owner="alice")

    @gk.tool(tier=AccessTier.READ, authorize=owners_only, scopes={"orders:cancel"})
    def check(order_id: str, order: Annotated[Order, Load(load)]) -> str:
        return "ok"

    with signed_in(token("alice", ("orders:read",))):
        async with Client(mcp) as client:
            refused = await client.call_tool("check", {"order_id": "1"})
    with signed_in(token("alice", ("orders:read", "orders:cancel"))):
        async with Client(mcp) as client:
            allowed = await client.call_tool("check", {"order_id": "1"})
    assert refused.is_error and "orders:cancel" in text(refused)
    assert not allowed.is_error
    assert loaded == ["1"]
    assert reasons(log)[0] == ("denied", "missing scope: orders:cancel")


@pytest.mark.anyio
async def test_token_claims_reach_the_policy_and_never_the_log():
    """A task-scoped token: its authorization_details name the one order the
    task is about, and the policy holds the call to it."""
    log = io.StringIO()
    mcp, gk = gated(log=log, local=None)

    def load(order_id: str) -> Order:
        return Order(id=order_id, owner="alice")

    def this_task_only(request: AuthorizationRequest):
        details = request.claims.get("authorization_details", [])
        order = request.resources["order"]
        if not any(d.get("type") == "order" and d.get("id") == order.id for d in details):
            return Deny("outside the token's task")
        return Allow()

    @gk.tool(tier=AccessTier.WRITE, authorize=this_task_only, consistency=AcceptRace("test"))
    def touch(order_id: str, order: Annotated[Order, Load(load)]) -> str:
        return f"touched {order.id}"

    task_token = token("alice", claims={"authorization_details": [{"type": "order", "id": "4417"}]})
    with signed_in(task_token):
        async with Client(mcp) as client:
            ok = await client.call_tool("touch", {"order_id": "4417"})
            other = await client.call_tool("touch", {"order_id": "4418"})
    assert not ok.is_error and other.is_error
    assert reasons(log) == [("ok", None), ("denied", "policy: outside the token's task")]
    assert "authorization_details" not in log.getvalue()


# --- Load: the record, loaded by the server ------------------------------------


def orders_server(log: io.StringIO, store: dict[str, Order], policy=owners_only, *,
                  gate_policy: Policy = NO_TIER_APPROVAL, local: Caller = LOCAL) -> tuple[MCPServer, list]:
    seen: list[tuple[str, Any]] = []
    mcp, gk = gated(gate_policy, log=log, local=local)

    def load_order(order_id: str) -> Order | None:
        return store.get(order_id)

    def watching(request: AuthorizationRequest):
        seen.append(("policy", request.resources.get("order")))
        return policy(request)

    @gk.tool(tier=AccessTier.WRITE, authorize=watching, consistency=AcceptRace("test"))
    def close_order(order_id: str, order: Annotated[Order, Load(load_order, describe=lambda o: f"order {o.id}")]) -> str:
        seen.append(("tool", order))
        return f"closed {order.id} for {order.owner}"

    return mcp, seen


@pytest.mark.anyio
async def test_the_model_sees_only_the_id_and_cannot_send_the_record():
    log = io.StringIO()
    store = {"1": Order(id="1", owner="tester")}
    mcp, seen = orders_server(log, store)
    async with Client(mcp) as client:
        (tool,) = (await client.list_tools()).tools
        assert set(tool.input_schema["properties"]) == {"order_id"}
        forged = {"id": "1", "owner": "mallory"}
        result = await client.call_tool("close_order", {"order_id": "1", "order": forged})
    assert text(result) == "closed 1 for tester"
    # The tool got the very object the policy decided on.
    (_, by_policy), (_, by_tool) = seen
    assert by_policy is by_tool is store["1"]


@pytest.mark.anyio
async def test_not_found_and_not_yours_read_the_same_to_the_model():
    log = io.StringIO()
    store = {"2": Order(id="2", owner="someone-else")}
    mcp, seen = orders_server(log, store)
    async with Client(mcp) as client:
        missing = await client.call_tool("close_order", {"order_id": "1"})
        theirs = await client.call_tool("close_order", {"order_id": "2"})
    assert missing.is_error and theirs.is_error
    assert text(missing) == text(theirs) and NOT_PERMITTED in text(theirs)
    # The log knows the difference.
    assert reasons(log) == [("denied", "not found: order"), ("denied", "policy: not the owner")]
    assert events(log)[1]["authz"] == "deny"
    assert events(log)[1]["resources"] == {"order": {"order_id": "2"}}
    assert [who for who, _ in seen] == ["policy"]


@pytest.mark.anyio
async def test_a_deny_can_tell_the_model_more_on_purpose():
    log = io.StringIO()
    store = {"1": Order(id="1", owner="tester", status="shipped")}

    def not_shipped(request: AuthorizationRequest):
        return Deny("shipped", message="Order 1 has shipped.")

    mcp, _ = orders_server(log, store, not_shipped)
    async with Client(mcp) as client:
        result = await client.call_tool("close_order", {"order_id": "1"})
    assert "Order 1 has shipped." in text(result)


@pytest.mark.anyio
async def test_a_loader_that_fails_is_a_refusal():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    def broken(order_id: str) -> Order:
        raise RuntimeError("db down: password=hunter2")

    @gk.tool(authorize=owners_only)
    def look(order_id: str, order: Annotated[Order, Load(broken)]) -> str:
        return "ran"

    async with Client(mcp) as client:
        result = await client.call_tool("look", {"order_id": "1"})
    assert result.is_error and NOT_PERMITTED in text(result)
    assert reasons(log) == [("denied", "loader error: RuntimeError")]
    assert "hunter2" not in log.getvalue()


@pytest.mark.anyio
async def test_context_or_none_stays_a_context_and_out_of_the_schema():
    """Before, `ctx: Context | None` slipped past the gate's Context check, and
    the gate added its own hidden parameter, which landed in the schema."""
    mcp, gk = gated()

    @gk.tool(authorize=any_caller)
    async def look(order_id: str, ctx: Context | None = None) -> str:
        return f"{order_id} {type(ctx).__name__}"

    async with Client(mcp) as client:
        (tool,) = (await client.list_tools()).tools
        assert set(tool.input_schema["properties"]) == {"order_id"}
        result = await client.call_tool("look", {"order_id": "1", "gatehouse_context": "x"})
    assert text(result) == "1 Context"


def _loader(order_id: str) -> Order:
    return Order(id=order_id, owner="x")


def _other(order: Order) -> Order:
    return order


@pytest.mark.parametrize(
    "register, message",
    [
        (lambda gk: gk.tool(authorize=any_caller)(_tool_loader_names_unknown_argument), "isn't one of the tool's arguments"),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_loader_takes_a_record), "another loaded record"),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_nested_load), "not nested"),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_load_with_default), "can't have a default"),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_two_markers), "more than one"),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_resolve), "Resolve"),
        (lambda gk: gk.tool(tier=AccessTier.WRITE, authorize=any_caller)(_tool_plain_load), "consistency="),
        (
            lambda gk: gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=any_caller, consistency=AcceptRace("t"))(_tool_opaque_load),
            "fingerprint",
        ),
        (lambda gk: gk.tool(authorize=any_caller)(_tool_returns_records), "authorize_items"),
        (lambda gk: gk.tool(authorize=any_caller, authorize_items=any_item)(_tool_plain_load), "list of records"),
    ],
    ids=[
        "unknown-argument", "loader-takes-record", "nested", "default", "two-markers", "resolve",
        "no-consistency", "opaque-on-approval-tier", "records-without-item-policy", "item-policy-without-records",
    ],
)
def test_registration_refuses_what_the_gate_cant_enforce(register, message):
    mcp, gk = gated(Policy())  # default policy: DESTRUCTIVE needs approval
    with pytest.raises((TypeError, ValueError), match=message):
        register(gk)
    assert mcp._tool_manager.list_tools() == []


def _tool_loader_names_unknown_argument(order: Annotated[Order, Load(_loader)]) -> str:
    return "x"


def _tool_loader_takes_a_record(order_id: str, order: Annotated[Order, Load(_loader)],
                                again: Annotated[Order, Load(_other)]) -> str:
    return "x"


def _tool_nested_load(order_id: str, orders: list[Annotated[Order, Load(_loader)]]) -> str:
    return "x"


def _tool_load_with_default(order_id: str, order: Annotated[Order, Load(_loader)] = None) -> str:  # type: ignore[assignment]
    return "x"


def _tool_two_markers(order_id: str, order: Annotated[Order, Load(_loader), Load(_loader)]) -> str:
    return "x"


def _tool_resolve(order_id: str, order: Annotated[Order, Resolve(_loader)]) -> str:
    return "x"


def _tool_plain_load(order_id: str, order: Annotated[Order, Load(_loader)]) -> str:
    return "x"


class Opaque:
    pass


def _opaque(order_id: str) -> Opaque:
    return Opaque()


def _tool_opaque_load(order_id: str, thing: Annotated[Opaque, Load(_opaque)]) -> str:
    return "x"


def _tool_returns_records() -> list[Order]:
    return []


# --- decisions ------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "policy, reason",
    [
        (lambda request: True, "policy returned bool"),
        (lambda request: None, "policy returned NoneType"),
        (lambda request: {"allow": True}, "policy returned dict"),
        (lambda request: 1 / 0, "policy error: ZeroDivisionError"),
    ],
    ids=["true", "none", "dict", "raises"],
)
async def test_only_a_decision_allows(policy, reason):
    log, ran = io.StringIO(), []
    mcp, gk = gated(log=log)

    @gk.tool(authorize=policy)
    def look(order_id: str) -> str:
        ran.append(order_id)
        return "ran"

    async with Client(mcp) as client:
        result = await client.call_tool("look", {"order_id": "1"})
    assert result.is_error and NOT_PERMITTED in text(result)
    assert ran == []
    assert reasons(log) == [("denied", reason)]


@pytest.mark.anyio
async def test_async_policies_work():
    mcp, gk = gated()

    async def later(request: AuthorizationRequest):
        await anyio.sleep(0)
        return Allow()

    @gk.tool(authorize=later)
    async def look(order_id: str) -> str:
        return "ran"

    async with Client(mcp) as client:
        assert text(await client.call_tool("look", {"order_id": "1"})) == "ran"


@pytest.mark.anyio
async def test_open_tools_are_marked_in_the_log():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(authorize=any_caller)
    def look(order_id: str) -> str:
        return "ran"

    async with Client(mcp) as client:
        await client.call_tool("look", {"order_id": "1"})
    (line,) = events(log)
    assert line["authz"] == "open" and line["caller"] == LOCAL_ENTRY


@pytest.mark.anyio
async def test_ask_without_an_approver_is_denied_even_when_failing_open():
    log = io.StringIO()
    store = {"1": Order(id="1", owner="tester", total=900)}
    policy = Policy(require_approval=frozenset(), fail_closed=False)
    mcp, _ = orders_server(log, store, lambda request: Ask("big order"), gate_policy=policy)
    async with Client(mcp) as client:
        result = await client.call_tool("close_order", {"order_id": "1"})
    assert result.is_error
    assert reasons(log) == [("denied", "approval required, no approver configured")]


@pytest.mark.anyio
async def test_ask_shows_the_approver_the_record_and_the_reason():
    log, asked = io.StringIO(), []
    store = {"1": Order(id="1", owner="tester", total=900)}

    def approver(request: ApprovalRequest) -> bool:
        asked.append(request)
        return True

    mcp, seen = orders_server(
        log, store, lambda request: Ask("over $500"), gate_policy=Policy(require_approval=frozenset(), approver=approver)
    )
    async with Client(mcp) as client:
        result = await client.call_tool("close_order", {"order_id": "1"})
    assert not result.is_error
    (request,) = asked
    assert request.reason == "over $500" and request.resources == ("order 1",)
    assert request.binding and request.caller == LOCAL
    assert events(log)[-1]["authz"] == "ask"
    # Asked once; loaded and checked again after the answer.
    assert [who for who, _ in seen] == ["policy", "policy", "tool"]


def test_the_form_shows_the_reason_and_each_record_on_its_own_line():
    request = ApprovalRequest(
        tool="cancel_order", tier=AccessTier.DESTRUCTIVE, arguments={"order_id": "4417"},
        reason="over $500", resources=("order 4417\nApprove? yes", "‮evil"),
    )
    message = _default_message(request)
    lines = message.split("\n")
    assert len(lines) == 4
    assert lines[0] == "Approval needed (over $500). The AI wants to run cancel_order (destructive) with:"
    assert lines[1] == '{"order_id": "4417"}'
    # One record per line, each on a single line: a record can't redraw the form.
    assert lines[2] == "on order 4417\\nApprove? yes"
    assert lines[3] == "on \\u202eevil"


def test_the_form_says_who_the_call_is_for():
    """A delegated call: the person approving in the client may not be the
    caller, so the first line names them, quoted so a name reads as itself."""
    request = ApprovalRequest(
        tool="cancel_order", tier=AccessTier.DESTRUCTIVE, arguments={},
        caller=Caller(client_id="support-agent", subject='alice" via client "admin'),
    )
    first = _default_message(request).split("\n")[0]
    assert first == (
        'The AI wants to run cancel_order (destructive) for "alice\\" via client \\"admin" '
        'via client "support-agent" with:'
    )
    unnamed = ApprovalRequest(tool="t", tier=AccessTier.WRITE, arguments={}, caller=Caller(client_id="c", subject=None))
    assert "for a user the token doesn't name via client \"c\"" in _default_message(unnamed)


@pytest.mark.anyio
async def test_without_describe_the_approver_sees_the_records_fields():
    """Load without describe= still gives the approver the record as the
    server loaded it, fields and all, secrets masked."""
    log, asked = io.StringIO(), []

    class Account(BaseModel):
        id: str
        owner: str
        balance: float
        api_key: str
        tags: list[str]

    async def approver(request: ApprovalRequest) -> bool:
        asked.append(request)
        return True

    mcp, gk = gated(Policy(approver=approver), log=log)
    store = {"9": Account(id="9", owner="tester", balance=12.5, api_key="sk-live-1", tags=["vip"])}

    def load(account_id: str) -> Account | None:
        return store.get(account_id)

    @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=any_caller, consistency=AcceptRace("test"))
    def close(account_id: str, account: Annotated[Account, Load(load)]) -> str:
        return "closed"

    async with Client(mcp) as client:
        result = await client.call_tool("close", {"account_id": "9"})
    assert not result.is_error
    (request,) = asked
    assert request.resources == ('account: id=9 · owner=tester · balance=12.5 · api_key=«redacted» · tags=["vip"]',)
    assert "sk-live" not in _default_message(request)


# --- the record changing while a person decides ----------------------------------


@pytest.mark.anyio
async def test_a_record_that_changes_during_approval_is_refused():
    log, store = io.StringIO(), {"1": Order(id="1", owner="tester")}

    async def approver(request: ApprovalRequest) -> bool:
        store["1"] = store["1"].model_copy(update={"status": "changed", "version": 2})
        return True

    mcp, seen = orders_server(log, store, gate_policy=Policy(require_approval=frozenset({AccessTier.WRITE}), approver=approver))
    async with Client(mcp) as client:
        result = await client.call_tool("close_order", {"order_id": "1"})
    assert result.is_error and "changed while the approval was pending" in text(result)
    assert ("tool", store["1"]) not in seen
    assert reasons(log) == [("denied", "resource changed while awaiting approval")]


@pytest.mark.anyio
async def test_an_amount_that_changes_during_approval_is_refused():
    """Found running examples/orders_postgres.py: a Decimal total was opaque to
    the fingerprint, so an approval for $812 carried over to $99,999. No
    describe= here: the default line shows the total, but only the fingerprint
    can refuse the change."""
    from decimal import Decimal

    class Invoice(BaseModel):
        id: str
        owner: str
        total: Decimal

    log, ran = io.StringIO(), []
    store = {"1": Invoice(id="1", owner="tester", total=Decimal("812"))}

    async def approver(request: ApprovalRequest) -> bool:
        store["1"] = store["1"].model_copy(update={"total": Decimal("99999")})
        return True

    mcp, gk = gated(Policy(approver=approver), log=log)

    def load(invoice_id: str) -> Invoice | None:
        return store.get(invoice_id)

    def owners(request: AuthorizationRequest):
        return Allow() if request.resources["invoice"].owner == request.caller.subject else Deny("not the owner")

    @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=owners, consistency=AcceptRace("test"))
    def pay(invoice_id: str, invoice: Annotated[Invoice, Load(load)]) -> str:
        ran.append(invoice.total)
        return "paid"

    async with Client(mcp) as client:
        result = await client.call_tool("pay", {"invoice_id": "1"})
    assert result.is_error and ran == []
    assert reasons(log) == [("denied", "resource changed while awaiting approval")]


@pytest.mark.anyio
async def test_a_record_that_becomes_forbidden_during_approval_is_refused():
    log, store = io.StringIO(), {"1": Order(id="1", owner="tester")}

    async def approver(request: ApprovalRequest) -> bool:
        store["1"] = store["1"].model_copy(update={"owner": "someone-else"})
        return True

    mcp, _ = orders_server(log, store, gate_policy=Policy(require_approval=frozenset({AccessTier.WRITE}), approver=approver))
    async with Client(mcp) as client:
        result = await client.call_tool("close_order", {"order_id": "1"})
    assert result.is_error
    assert reasons(log) == [("denied", "policy after approval: not the owner")]


async def _approve(context: Any, params: Any) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True})


@pytest.mark.anyio
async def test_a_round_trip_answer_given_for_an_old_state_is_asked_again():
    log, store = io.StringIO(), {"1": Order(id="1", owner="tester")}
    policy = Policy(require_approval=frozenset({AccessTier.WRITE}), approver=ElicitationApprover())
    mcp, seen = orders_server(log, store, gate_policy=policy)
    arguments = {"order_id": "1"}
    async with Client(mcp, elicitation_callback=_approve) as client:
        question = await client.session.call_tool("close_order", arguments, allow_input_required=True)
        assert isinstance(question, InputRequiredResult)
        (key,) = question.input_requests
        answer = {key: ElicitResult(action="accept", content={"approve": True})}

        store["1"] = store["1"].model_copy(update={"status": "edited", "version": 2})
        again = await client.session.call_tool(
            "close_order", arguments, input_responses=answer, request_state=question.request_state,
            allow_input_required=True,
        )
        assert isinstance(again, InputRequiredResult)  # the old answer doesn't carry over

        (key,) = again.input_requests
        fresh = {key: ElicitResult(action="accept", content={"approve": True})}
        done = await client.session.call_tool(
            "close_order", arguments, input_responses=fresh, request_state=again.request_state,
        )
    assert not done.is_error
    assert [who for who, _ in seen].count("tool") == 1
    assert [o for o, _ in reasons(log)] == ["pending", "pending", "ok"]


# --- consistency: the window between check and write -----------------------------


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "orders.db"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.executescript(
            "CREATE TABLE orders (id TEXT PRIMARY KEY, owner TEXT, status TEXT, version INTEGER);"
            "CREATE TABLE reads (id TEXT);"
            "INSERT INTO orders VALUES ('1', 'tester', 'open', 1);"
        )
        conn.commit()
    return path


def sqlite_server(db_path, log: io.StringIO, *, boom: bool = False, slow: float = 0.0, threads: list | None = None):
    threads = threads if threads is not None else []

    @contextlib.contextmanager
    def transaction(caller: Caller):
        # check_same_thread (sqlite3's default) would raise if any step ran
        # on another thread: the test for "one thread" is built in.
        conn = sqlite3.connect(db_path, isolation_level=None, timeout=10)
        try:
            conn.execute("BEGIN IMMEDIATE")
            threads.append(("transaction", threading.get_ident()))
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def load_order(order_id: str) -> Order | None:
        conn = current_transaction()
        threads.append(("loader", threading.get_ident()))
        conn.execute("INSERT INTO reads VALUES (?)", (order_id,))
        row = conn.execute("SELECT id, owner, status, version FROM orders WHERE id = ?", (order_id,)).fetchone()
        return None if row is None else Order(id=row[0], owner=row[1], status=row[2], version=row[3])

    def can_cancel(request: AuthorizationRequest):
        threads.append(("policy", threading.get_ident()))
        order = request.resources["order"]
        if order.owner != request.caller.subject:
            return Deny("not the owner")
        if order.status == "cancelled":
            return Deny("already cancelled")
        return Allow()

    mcp, gk = gated(log=log, consistency=Transaction(transaction))

    @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel)
    def cancel(order_id: str, order: Annotated[Order, Load(load_order)]) -> str:
        threads.append(("tool", threading.get_ident()))
        current_transaction().execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order.id,))
        if slow:
            time.sleep(slow)
        if boom:
            raise RuntimeError("after the write")
        return f"cancelled {order.id}"

    return mcp


def row(db_path, table: str = "orders") -> list[tuple]:
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(f"SELECT * FROM {table}").fetchall()


@pytest.mark.anyio
async def test_a_sync_transaction_commits_and_runs_in_one_thread(db):
    log, threads = io.StringIO(), []
    mcp = sqlite_server(db, log, threads=threads)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert text(result) == "cancelled 1"
    assert row(db) == [("1", "tester", "cancelled", 1)]
    assert [step for step, _ in threads] == ["transaction", "loader", "policy", "tool"]
    assert len({ident for _, ident in threads}) == 1
    assert events(log)[-1]["consistency"] == "transaction"


@pytest.mark.anyio
async def test_a_denial_rolls_the_transaction_back(db):
    log = io.StringIO()
    mcp = sqlite_server(db, log)
    async with Client(mcp) as client:
        await client.call_tool("cancel", {"order_id": "1"})
        again = await client.call_tool("cancel", {"order_id": "1"})
    assert again.is_error
    assert reasons(log)[-1] == ("denied", "policy: already cancelled")
    # The loader wrote a row in each transaction; the denied one rolled back.
    assert row(db, "reads") == [("1",)]


@pytest.mark.anyio
async def test_a_tool_error_rolls_the_transaction_back(db):
    log = io.StringIO()
    mcp = sqlite_server(db, log, boom=True)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert result.is_error
    assert row(db) == [("1", "tester", "open", 1)]
    assert reasons(log) == [("error", "RuntimeError")]


@pytest.mark.anyio
async def test_two_racing_cancels_run_once(db):
    """Check and write share a transaction, so the second cancel loads the
    first one's result and the policy refuses it."""
    log = io.StringIO()
    mcp = sqlite_server(db, log, slow=0.2)
    results = []

    async with Client(mcp) as client:
        async def cancel() -> None:
            results.append(await client.call_tool("cancel", {"order_id": "1"}))

        async with anyio.create_task_group() as tg:
            tg.start_soon(cancel)
            tg.start_soon(cancel)
    assert sorted(r.is_error for r in results) == [False, True]
    assert sorted(reasons(log)) == [("denied", "policy: already cancelled"), ("ok", None)]


@pytest.mark.anyio
async def test_no_transaction_is_open_while_a_person_decides(db):
    open_now = []

    @contextlib.asynccontextmanager
    async def transaction(caller: Caller):
        open_now.append(1)
        try:
            yield "handle"
        finally:
            open_now.pop()

    async def load(order_id: str) -> Order:
        assert current_transaction() == "handle"
        return Order(id=order_id, owner="tester")

    async def approver(request: ApprovalRequest) -> bool:
        assert open_now == [], "a transaction was held open during approval"
        return True

    log = io.StringIO()
    mcp, gk = gated(Policy(approver=approver), log=log, consistency=Transaction(transaction))

    @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=owners_only)
    async def cancel(order_id: str, order: Annotated[Order, Load(load)]) -> str:
        assert open_now == [1]
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert text(result) == "cancelled"
    assert reasons(log) == [("ok", None)]


def test_transaction_mode_must_fit_the_tool():
    @contextlib.contextmanager
    def sync_tx(caller):
        yield None

    @contextlib.asynccontextmanager
    async def async_tx(caller):
        yield None

    async def async_load(order_id: str) -> Order:
        return Order(id=order_id, owner="x")

    _, gk = gated()
    with pytest.raises(TypeError, match="these are async: loader for 'order', the tool"):
        @gk.tool(authorize=any_caller, consistency=Transaction(sync_tx))
        async def a(order_id: str, order: Annotated[Order, Load(async_load)]) -> str:
            return "x"
    with pytest.raises(TypeError, match="these are sync: loader for 'order', the tool"):
        @gk.tool(authorize=any_caller, consistency=Transaction(async_tx))
        def b(order_id: str, order: Annotated[Order, Load(_loader)]) -> str:
            return "x"
    with pytest.raises(TypeError, match="sync or async"):
        Transaction(lambda caller: None)


@pytest.mark.anyio
async def test_a_conditional_write_that_misses_is_a_conflict():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(tier=AccessTier.WRITE, authorize=any_caller, consistency=ConditionalWrite())
    def edit(order_id: str, order: Annotated[Order, Load(_loader)]) -> str:
        raise Conflict()

    async with Client(mcp) as client:
        result = await client.call_tool("edit", {"order_id": "1"})
    assert result.is_error and "the record changed" in text(result)
    (line,) = events(log)
    assert (line["outcome"], line["consistency"]) == ("conflict", "conditional")


@pytest.mark.anyio
async def test_accepting_the_race_is_logged_with_its_reason():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(tier=AccessTier.WRITE, authorize=any_caller, consistency=AcceptRace("append-only"))
    def note(order_id: str, order: Annotated[Order, Load(_loader)]) -> str:
        return "noted"

    async with Client(mcp) as client:
        await client.call_tool("note", {"order_id": "1"})
    (line,) = events(log)
    assert (line["consistency"], line["consistency_reason"]) == ("accept-race", "append-only")


# --- lists: what the caller may see ----------------------------------------------


ORDERS = [Order(id="1", owner="tester"), Order(id="2", owner="someone-else"), Order(id="3", owner="tester")]


@pytest.mark.anyio
async def test_the_gate_withholds_items_the_caller_may_not_see():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(authorize=any_caller, authorize_items=owners_only)
    def list_orders() -> list[Order]:
        return list(ORDERS)

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert [o["id"] for o in result.structured_content["result"]] == ["1", "3"]
    (line,) = events(log)
    assert line["withheld"] == 1 and "scope_mismatch" not in line


@pytest.mark.anyio
async def test_a_scope_the_query_ignored_is_flagged():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    def mine(request: AuthorizationRequest) -> str:
        return request.caller.subject or ""

    @gk.tool(authorize=any_caller, authorize_items=owners_only)
    def honest(owner: Annotated[str, Scope(mine)]) -> list[Order]:
        return [o for o in ORDERS if o.owner == owner]

    @gk.tool(authorize=any_caller, authorize_items=owners_only)
    def careless(owner: Annotated[str, Scope(mine)]) -> list[Order]:
        return list(ORDERS)

    async with Client(mcp) as client:
        (tool, _) = (await client.list_tools()).tools
        assert tool.input_schema.get("properties", {}) == {}
        good = await client.call_tool("honest", {})
        bad = await client.call_tool("careless", {})
    assert len(good.structured_content["result"]) == len(bad.structured_content["result"]) == 2
    first, second = events(log)
    assert first["withheld"] == 0 and "scope_mismatch" not in first
    assert second["withheld"] == 1 and second["scope_mismatch"] is True


@pytest.mark.anyio
async def test_item_policy_errors_withhold_and_are_counted():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    async def picky(request: AuthorizationRequest):
        if request.resource.id == "3":
            raise RuntimeError("lookup failed")
        return Allow()

    @gk.tool(authorize=any_caller, authorize_items=picky)
    async def list_orders() -> list[Order]:
        return list(ORDERS)

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert [o["id"] for o in result.structured_content["result"]] == ["1", "2"]
    (line,) = events(log)
    assert (line["withheld"], line["filter_errors"]) == (1, 1)


@pytest.mark.anyio
async def test_any_item_is_the_marked_opt_out():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(authorize=any_caller, authorize_items=any_item)
    def list_orders() -> list[Order]:
        return list(ORDERS)

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert len(result.structured_content["result"]) == 3
    (line,) = events(log)
    assert line["items"] == "open" and "withheld" not in line


@pytest.mark.anyio
async def test_a_result_the_gate_cant_filter_is_never_returned():
    log = io.StringIO()
    mcp, gk = gated(log=log)

    @gk.tool(authorize=any_caller, authorize_items=owners_only)
    def list_orders() -> list[Order]:
        return "1, 2, 3"  # type: ignore[return-value]

    async with Client(mcp) as client:
        result = await client.call_tool("list_orders", {})
    assert result.is_error and "2" not in text(result).split("returned")[0]
    assert reasons(log) == [("error", "unfilterable result: str")]


# --- over real HTTP, with real bearer tokens ------------------------------------------


@pytest.mark.anyio
@pytest.mark.filterwarnings("ignore:.*validate_token_resource")
async def test_over_http_each_caller_gets_their_own_decision():
    """Streamable HTTP with a token verifier: alice can cancel her order and
    not bob's, and a token without the scope is refused before anything
    loads. With no token at all, the SDK's auth turns the request away
    before it reaches the server (on a server without auth, the gate does:
    test_anonymous_http_is_never_the_local_caller)."""
    from mcp.server.auth.settings import AuthSettings

    from _support import ISSUER, bearer

    log, loaded = io.StringIO(), []
    store = {"1": Order(id="1", owner="alice"), "2": Order(id="2", owner="bob")}

    def app(url: str):
        tokens = {
            "alice": token("alice", ("orders:cancel",), resource=url),
            "alice-read-only": token("alice", ("orders:read",), resource=url),
        }

        class Verifier:
            async def verify_token(self, presented: str):
                return tokens.get(presented)

        mcp = MCPServer("authz-http", token_verifier=Verifier(),
                        auth=AuthSettings(issuer_url=ISSUER, resource_server_url=url))
        gk = Gatehouse(mcp, policy=NO_TIER_APPROVAL, audit=AuditLog(stream=log), local_caller=LOCAL)

        def load(order_id: str) -> Order | None:
            loaded.append(order_id)
            return store.get(order_id)

        @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=owners_only, scopes={"orders:cancel"},
                 consistency=AcceptRace("test"))
        async def cancel(order_id: str, order: Annotated[Order, Load(load)]) -> str:
            return f"cancelled {order.id}"

        return mcp.streamable_http_app()

    async def calls(url: str, presented: str | None, *order_ids: str) -> list[Any]:
        http = bearer(presented) if presented else None
        results: list[Any] = []
        try:
            await session_calls(url, http, results, order_ids)
        except Exception as exc:  # the connection itself refused
            results.append(exc)
        return results

    async def session_calls(url: str, http: Any, results: list[Any], order_ids: tuple[str, ...]) -> None:
        async with contextlib.AsyncExitStack() as stack:
            if http is not None:
                await stack.enter_async_context(http)
            read, write, *_ = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            for order_id in order_ids:
                results.append(await session.call_tool("cancel", {"order_id": order_id}))

    async with http_server(app) as url:
        mine, theirs = await calls(url, "alice", "1", "2")
        (read_only,) = await calls(url, "alice-read-only", "1")
        (anonymous,) = await calls(url, None, "1")

    assert text(mine) == "cancelled 1"
    assert theirs.is_error and NOT_PERMITTED in text(theirs)
    assert read_only.is_error and "orders:cancel" in text(read_only)
    assert isinstance(anonymous, Exception)  # 401 from the SDK's auth, before any tool
    assert loaded == ["1", "2"]  # the read-only token never reached the loader
    assert [(e["outcome"], e.get("reason"), e["caller"]["subject"]) for e in events(log)] == [
        ("ok", None, "alice"),
        ("denied", "policy: not the owner", "alice"),
        ("denied", "missing scope: orders:cancel", "alice"),
    ]
    assert "secret-token" not in log.getvalue()
