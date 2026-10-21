"""Cancelled calls are audited too. When the client gives up or the server
shuts down, a call waiting on its approver or inside its tool still leaves
one line in the log, and the cancellation carries on unchanged."""

from __future__ import annotations

import contextlib
import io
import json
import threading
import time

import anyio
import pytest
from mcp import Client, MCPError
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy

ARGUMENTS = {"order_id": "4417", "api_key": "sk-live-not-for-the-log"}
LOGGED_ARGUMENTS = {"order_id": "4417", "api_key": "«redacted»"}


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


async def until(started: threading.Event) -> None:
    with anyio.fail_after(5):
        while not started.is_set():
            await anyio.sleep(0.01)


# --- the ways a call gets cancelled ---------------------------------------


async def client_gives_up(mcp: MCPServer, started: threading.Event) -> None:
    """In process, the client's cancellation reaches the tool directly."""
    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "refund", ARGUMENTS)
            await until(started)
            tg.cancel_scope.cancel()


async def client_gives_up_over_json_rpc(mcp: MCPServer, started: threading.Event) -> None:
    """Over the wire, the client sends notifications/cancelled and the
    server cancels the handler."""
    async with Client(mcp, mode="legacy") as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "refund", ARGUMENTS)
            await until(started)
            tg.cancel_scope.cancel()


async def server_shuts_down(mcp: MCPServer, started: threading.Event) -> None:
    """The connection closes mid-call and the server cancels what is in
    flight on its way out."""

    async def call(client: Client) -> None:
        with contextlib.suppress(MCPError):  # "Connection closed"
            await client.call_tool("refund", ARGUMENTS)

    async with anyio.create_task_group() as tg:
        async with Client(mcp, mode="legacy") as client:
            tg.start_soon(call, client)
            await until(started)


interruptions = pytest.mark.parametrize(
    "interrupt", [client_gives_up, client_gives_up_over_json_rpc, server_shuts_down]
)


# --- what the log says -----------------------------------------------------


@pytest.mark.anyio
@interruptions
async def test_cancelled_while_awaiting_approval(interrupt):
    started = threading.Event()
    ran = []

    async def slow_human(request) -> bool:
        started.set()
        await anyio.sleep_forever()

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=slow_human), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def refund(order_id: str, api_key: str) -> str:
        ran.append(order_id)
        return "refunded"

    await interrupt(mcp, started)

    assert ran == []
    (event,) = events(log)
    del event["ts"]
    assert event == {
        "tool": "refund", "tier": "destructive", "outcome": "cancelled",
        "reason": "awaiting approval", "arguments": LOGGED_ARGUMENTS,
    }


@pytest.mark.anyio
@interruptions
async def test_cancelled_inside_an_async_tool(interrupt):
    started = threading.Event()

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=lambda request: True), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    async def refund(order_id: str, api_key: str) -> str:
        started.set()
        await anyio.sleep_forever()

    await interrupt(mcp, started)

    (event,) = events(log)
    del event["ts"]
    assert event.pop("duration_ms") >= 0
    assert event == {
        "tool": "refund", "tier": "destructive", "outcome": "cancelled",
        "reason": "tool running", "arguments": LOGGED_ARGUMENTS,
    }


@pytest.mark.anyio
@interruptions
async def test_sync_tool_finishes_before_the_cancellation_lands(interrupt):
    """A worker thread can't be interrupted, so anyio holds the cancellation
    until the sync tool returns. The tool did all its work, so its line says
    ``ok``, and no ``cancelled`` line follows it."""
    started = threading.Event()
    ran = []

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=lambda request: True), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def refund(order_id: str, api_key: str) -> str:
        started.set()
        time.sleep(0.3)
        ran.append(order_id)
        return "refunded"

    await interrupt(mcp, started)

    assert ran == ["4417"]
    (event,) = events(log)
    assert event["outcome"] == "ok"
    assert event["arguments"] == LOGGED_ARGUMENTS


# --- the cancellation itself is left alone ---------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["approval", "tool"])
async def test_cancellation_reaches_the_caller_unchanged(phase):
    """The guard logs the cancellation and re-raises the very exception it
    caught: not swallowed, not wrapped, not turned into a tool error."""
    started = threading.Event()
    seen = []

    async def hang() -> None:
        started.set()
        try:
            await anyio.sleep_forever()
        except BaseException as exc:
            seen.append(exc)
            raise

    async def slow_human(request) -> bool:
        await hang()
        return True

    async def refund(order_id: str) -> str:
        await hang()
        return "refunded"

    log = io.StringIO()
    approver = slow_human if phase == "approval" else (lambda request: True)
    gk = Gatehouse(MCPServer("t"), policy=Policy(approver=approver), audit=AuditLog(stream=log))
    guarded = gk._guard(refund, "refund", AccessTier.DESTRUCTIVE)
    raised = []

    async def call() -> None:
        try:
            await guarded(order_id="4417")
        except BaseException as exc:
            raised.append(exc)
            raise

    async with anyio.create_task_group() as tg:
        tg.start_soon(call)
        await until(started)
        tg.cancel_scope.cancel()

    (exc,) = raised
    assert isinstance(exc, anyio.get_cancelled_exc_class())
    (inside,) = seen
    assert exc is inside
    (event,) = events(log)
    assert event["outcome"] == "cancelled"
