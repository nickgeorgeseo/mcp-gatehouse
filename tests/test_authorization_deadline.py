"""The authorization deadline: loaders, policy and scopes share
``authorization_timeout`` seconds, and running out is a denial the model can
retry, or a question for the approver when the tool says so."""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import time
from typing import Annotated

import anyio
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import (
    AcceptRace,
    AccessTier,
    Allow,
    Ask,
    AuditLog,
    Deny,
    Load,
    Policy,
    Scope,
    Transaction,
    current_transaction,
)

from _support import OpenGatehouse as Gatehouse

SHORT = 0.2  # the deadline in these tests
HANG = 2.0  # how long a slow step takes: well past SHORT


def gate(**policy):
    log = io.StringIO()
    mcp = MCPServer("t")
    return mcp, Gatehouse(mcp, policy=Policy(**policy), audit=AuditLog(stream=log)), log


def lines(log: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in log.getvalue().splitlines()]


def slow_sync(seconds=HANG, answer=None):
    def policy(request):
        time.sleep(seconds)
        return answer if answer is not None else Allow()

    return policy


def slow_async(seconds=HANG, answer=None):
    async def policy(request):
        await anyio.sleep(seconds)
        return answer if answer is not None else Allow()

    return policy


async def call(mcp, tool="t", args=None):
    async with Client(mcp) as client:
        began = time.monotonic()
        result = await client.call_tool(tool, args or {})
        return result, time.monotonic() - began


# --- the default ---------------------------------------------------------------


def test_the_default_deadline_is_five_seconds_and_denies():
    assert Policy().authorization_timeout == 5.0
    assert Policy().on_authorization_timeout is Deny


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "5"])
def test_a_deadline_must_be_a_positive_number_of_seconds(bad):
    with pytest.raises(ValueError, match="authorization_timeout"):
        Policy(authorization_timeout=bad)
    _, gk, _ = gate()
    with pytest.raises(ValueError, match="authorization_timeout"):
        gk.tool(authorization_timeout=bad)


@pytest.mark.parametrize("bad", [Ask("x"), Allow, "ask", object()])
def test_on_timeout_is_the_deny_or_ask_class(bad):
    with pytest.raises(ValueError, match="on_authorization_timeout"):
        Policy(on_authorization_timeout=bad)
    _, gk, _ = gate()
    with pytest.raises(ValueError, match="on_authorization_timeout"):
        gk.tool(on_authorization_timeout=bad)


# --- running out ---------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("policy", [slow_sync(), slow_async()], ids=["sync", "async"])
async def test_a_slow_policy_is_denied_at_the_deadline_and_the_tool_never_runs(policy):
    mcp, gk, log = gate(authorization_timeout=SHORT)
    ran = []

    @gk.tool(authorize=policy)
    def t() -> str:
        ran.append(1)
        return "ran"

    result, took = await call(mcp)
    assert result.is_error and ran == []
    assert took < HANG / 2  # ended at the deadline, not when the policy did
    text = result.content[0].text
    assert "couldn't be authorized in time" in text and "can be retried" in text
    (line,) = lines(log)
    assert (line["outcome"], line["reason"]) == ("denied", "authorization timed out: policy")


@pytest.mark.anyio
async def test_a_slow_loader_is_denied_and_named():
    mcp, gk, log = gate(authorization_timeout=SHORT)

    def load(order_id: str) -> dict:
        time.sleep(HANG)
        return {"id": order_id}

    @gk.tool(authorize=lambda r: Allow())
    def t(order_id: str, order: Annotated[dict, Load(load)]) -> str:
        return "ran"

    result, took = await call(mcp, args={"order_id": "1"})
    assert result.is_error and took < HANG / 2
    assert lines(log)[-1]["reason"] == "authorization timed out: loading order"


@pytest.mark.anyio
async def test_a_slow_scope_is_denied_and_named():
    mcp, gk, log = gate(authorization_timeout=SHORT)

    async def mine(request):
        await anyio.sleep(HANG)
        return request.caller.subject

    @gk.tool(authorize=lambda r: Allow(), authorize_items=lambda r: Allow())
    def t(owner: Annotated[str, Scope(mine)]) -> list[dict]:
        return []

    result, took = await call(mcp)
    assert result.is_error and took < HANG / 2
    assert lines(log)[-1]["reason"] == "authorization timed out: scope owner"


@pytest.mark.anyio
async def test_loader_and_policy_share_one_budget():
    """Each step fits on its own; together they don't."""
    mcp, gk, log = gate(authorization_timeout=0.3)

    async def load(order_id: str) -> dict:
        await anyio.sleep(0.2)
        return {"id": order_id}

    @gk.tool(authorize=slow_async(0.2))
    def t(order_id: str, order: Annotated[dict, Load(load)]) -> str:
        return "ran"

    result, _ = await call(mcp, args={"order_id": "1"})
    assert result.is_error
    assert lines(log)[-1]["reason"] == "authorization timed out: policy"


@pytest.mark.anyio
async def test_a_fast_policy_is_untouched():
    mcp, gk, log = gate(authorization_timeout=SHORT)

    @gk.tool(authorize=lambda r: Allow())
    def t() -> str:
        return "ran"

    result, _ = await call(mcp)
    assert not result.is_error
    (line,) = lines(log)
    assert line["outcome"] == "ok" and "authorization_deadline" not in line


# --- overriding it -------------------------------------------------------------


@pytest.mark.anyio
async def test_a_tool_can_give_itself_longer():
    mcp, gk, log = gate(authorization_timeout=0.1)

    @gk.tool(authorize=slow_async(0.3), authorization_timeout=2)
    def t() -> str:
        return "ran"

    result, _ = await call(mcp)
    assert not result.is_error


@pytest.mark.anyio
async def test_a_tool_can_be_shorter_than_the_policy():
    mcp, gk, log = gate(authorization_timeout=5)

    @gk.tool(authorize=slow_async(), authorization_timeout=SHORT)
    def t() -> str:
        return "ran"

    result, took = await call(mcp)
    assert result.is_error and took < HANG / 2


@pytest.mark.anyio
@pytest.mark.parametrize("where", ["policy", "tool"])
async def test_turning_the_deadline_off_is_on_every_line(where):
    """An opt-out, so it shows: on the ok line and on a denial alike."""
    mcp, gk, log = gate(authorization_timeout=None if where == "policy" else 0.1, deny=frozenset({"blocked"}))
    off = {} if where == "policy" else {"authorization_timeout": None}

    @gk.tool(authorize=slow_async(0.3), **off)
    def t() -> str:
        return "ran"

    @gk.tool(authorize=lambda r: Allow(), **off)
    def blocked() -> str:
        return "ran"

    result, _ = await call(mcp)
    assert not result.is_error  # 0.3s, and no deadline to run out
    await call(mcp, "blocked")
    ok, denied = lines(log)
    assert ok["outcome"] == "ok" and denied["reason"] == "denylist"
    assert ok["authorization_deadline"] == denied["authorization_deadline"] == "off"


# --- asking instead ------------------------------------------------------------


def asking_gate(answer: bool, **tool):
    seen = []

    def approver(request):
        seen.append(request.reason)
        return answer

    mcp, gk, log = gate(
        authorization_timeout=SHORT, approver=approver, require_approval=frozenset(),
        on_authorization_timeout=tool.pop("policy_on_timeout", None),
    )
    return mcp, gk, log, seen


@pytest.mark.anyio
@pytest.mark.parametrize("where", ["policy", "tool"])
async def test_on_timeout_ask_puts_the_call_to_the_approver(where):
    mcp, gk, log, seen = asking_gate(True, policy_on_timeout=Ask if where == "policy" else None)
    ran = []
    on = {} if where == "policy" else {"on_authorization_timeout": Ask}

    @gk.tool(tier=AccessTier.WRITE, authorize=slow_async(), **on)
    def refund() -> str:
        ran.append(1)
        return "refunded"

    result, _ = await call(mcp, "refund")
    assert not result.is_error and ran == [1]
    assert seen == ["authorization timed out"]
    assert lines(log)[-1]["outcome"] == "ok" and lines(log)[-1]["authz"] == "ask"


@pytest.mark.anyio
async def test_on_timeout_ask_and_the_approver_says_no():
    mcp, gk, log, seen = asking_gate(False)

    @gk.tool(tier=AccessTier.WRITE, authorize=slow_async(), on_authorization_timeout=Ask)
    def refund() -> str:
        return "refunded"

    result, _ = await call(mcp, "refund")
    assert result.is_error and seen == ["authorization timed out"]
    assert lines(log)[-1]["outcome"] == "denied"


@pytest.mark.anyio
async def test_on_timeout_ask_still_denies_a_slow_loader():
    """No record yet, so nothing to put to a person."""
    mcp, gk, log, seen = asking_gate(True)

    async def load(order_id: str) -> dict:
        await anyio.sleep(HANG)
        return {"id": order_id}

    @gk.tool(tier=AccessTier.WRITE, authorize=lambda r: Allow(), on_authorization_timeout=Ask,
             consistency=AcceptRace("test: nothing is written"))
    def refund(order_id: str, order: Annotated[dict, Load(load)]) -> str:
        return "refunded"

    result, _ = await call(mcp, "refund", {"order_id": "1"})
    assert result.is_error and seen == []
    assert lines(log)[-1]["reason"] == "authorization timed out: loading order"


@pytest.mark.anyio
async def test_a_policy_that_denies_in_time_is_still_a_denial_with_ask_on_timeout():
    mcp, gk, log, seen = asking_gate(True)

    @gk.tool(tier=AccessTier.WRITE, authorize=lambda r: Deny("not the owner"), on_authorization_timeout=Ask)
    def refund() -> str:
        return "refunded"

    result, _ = await call(mcp, "refund")
    assert result.is_error and seen == []
    assert lines(log)[-1]["reason"] == "policy: not the owner"


# --- inside a sync transaction -------------------------------------------------


@pytest.mark.anyio
async def test_a_sync_transaction_checks_the_deadline_between_steps(tmp_path):
    """A thread can't be cut off, so the slow policy runs to the end; the
    gate then counts it as late, denies, and the transaction rolls back."""
    path = tmp_path / "t.db"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE touched (what TEXT)")
        conn.commit()

    @contextlib.contextmanager
    def transaction(caller):
        conn = sqlite3.connect(path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def load(order_id: str) -> dict:
        current_transaction().execute("INSERT INTO touched VALUES ('loader')")
        return {"id": order_id}

    mcp, gk, log = gate(authorization_timeout=SHORT)
    ran = []

    @gk.tool(tier=AccessTier.WRITE, authorize=slow_sync(0.4), consistency=Transaction(transaction))
    def write(order_id: str, order: Annotated[dict, Load(load)]) -> str:
        ran.append(1)
        return "written"

    result, took = await call(mcp, "write", {"order_id": "1"})
    assert result.is_error and ran == []
    assert took >= 0.35  # waited for the policy: the thread can't be cut off
    assert lines(log)[-1]["reason"] == "authorization timed out: policy"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT * FROM touched").fetchall() == []
