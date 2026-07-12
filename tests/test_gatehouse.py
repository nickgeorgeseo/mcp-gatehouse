"""End-to-end tests: tools registered through the Gatehouse, called
through a real MCP client session over the SDK's in-memory transport."""

from __future__ import annotations

import io
import json

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy


def build_server(policy: Policy, log_stream: io.StringIO) -> FastMCP:
    mcp = FastMCP("test-server")
    gk = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=log_stream))

    @gk.tool(tier=AccessTier.READ)
    def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}: 3 items, packed"

    @gk.tool(tier=AccessTier.WRITE)
    def update_note(order_id: str, note: str, api_key: str = "") -> str:
        """Attach a note to an order."""
        return f"note added to {order_id}"

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        """Cancel an order."""
        return f"order {order_id} cancelled"

    @gk.tool(tier=AccessTier.READ)
    def broken() -> str:
        """Always fails."""
        raise RuntimeError("downstream exploded")

    return mcp


def events(stream: io.StringIO) -> list[dict]:
    # split("\n"), not splitlines(): the log guarantees one \n per record,
    # and splitlines() would treat U+2028-style separators as record breaks.
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


@pytest.mark.anyio
async def test_read_tool_runs_and_audits():
    log = io.StringIO()
    server = build_server(Policy(), log)
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("lookup", {"order_id": "4417"})
    assert result.isError is False
    assert "order 4417" in result.content[0].text
    (event,) = events(log)
    assert event["tool"] == "lookup"
    assert event["outcome"] == "ok"
    assert event["tier"] == "read"
    assert event["arguments"] == {"order_id": "4417"}
    assert "ts" in event and "duration_ms" in event


@pytest.mark.anyio
async def test_destructive_fails_closed_without_approver():
    log = io.StringIO()
    server = build_server(Policy(), log)  # default: DESTRUCTIVE needs approval
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("cancel", {"order_id": "4417"})
    assert result.isError is True
    assert "fails closed" in result.content[0].text
    (event,) = events(log)
    assert event["outcome"] == "denied"
    assert "no approver" in event["reason"]


@pytest.mark.anyio
async def test_approver_allows_and_refuses():
    log = io.StringIO()
    seen: list[str] = []

    def approver(request) -> bool:
        seen.append(request.tool)
        return request.arguments["order_id"] == "yes-please"

    policy = Policy(approver=approver)
    server = build_server(policy, log)
    async with create_connected_server_and_client_session(server) as session:
        ok = await session.call_tool("cancel", {"order_id": "yes-please"})
        refused = await session.call_tool("cancel", {"order_id": "no-thanks"})
    assert ok.isError is False
    assert refused.isError is True
    assert "refused" in refused.content[0].text
    assert seen == ["cancel", "cancel"]
    outcomes = [e["outcome"] for e in events(log)]
    assert outcomes == ["ok", "denied"]


@pytest.mark.anyio
async def test_async_approver_supported():
    log = io.StringIO()

    async def approver(request) -> bool:
        return True

    server = build_server(Policy(approver=approver), log)
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("cancel", {"order_id": "4417"})
    assert result.isError is False


@pytest.mark.anyio
async def test_denylist_blocks_any_tier():
    log = io.StringIO()
    server = build_server(Policy(deny=frozenset({"lookup"})), log)
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("lookup", {"order_id": "4417"})
    assert result.isError is True
    assert "blocked by policy" in result.content[0].text
    (event,) = events(log)
    assert event["reason"] == "denylist"


@pytest.mark.anyio
async def test_secrets_never_reach_the_log():
    log = io.StringIO()
    server = build_server(Policy(), log)
    async with create_connected_server_and_client_session(server) as session:
        await session.call_tool(
            "update_note",
            {"order_id": "4417", "note": "call back", "api_key": "sk-live-hunter2"},
        )
    (event,) = events(log)
    assert event["arguments"]["api_key"] == "«redacted»"
    assert "hunter2" not in log.getvalue()


@pytest.mark.anyio
async def test_tool_errors_are_audited_and_surfaced():
    log = io.StringIO()
    server = build_server(Policy(), log)
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("broken", {})
    assert result.isError is True
    (event,) = events(log)
    assert event["outcome"] == "error"
    # only the exception TYPE is logged — messages can embed secrets
    assert event["reason"] == "RuntimeError"
    assert "downstream exploded" not in log.getvalue()


@pytest.mark.anyio
async def test_annotations_reflect_tiers():
    log = io.StringIO()
    server = build_server(Policy(), log)
    async with create_connected_server_and_client_session(server) as session:
        tools = {t.name: t for t in (await session.list_tools()).tools}
    assert tools["lookup"].annotations.readOnlyHint is True
    assert tools["lookup"].annotations.destructiveHint is False
    assert tools["cancel"].annotations.destructiveHint is True
    assert tools["update_note"].annotations.readOnlyHint is False
    assert tools["update_note"].annotations.destructiveHint is False


@pytest.mark.anyio
async def test_input_schema_survives_the_wrapper():
    """FastMCP must still see the real signature through the guard."""
    log = io.StringIO()
    server = build_server(Policy(), log)
    async with create_connected_server_and_client_session(server) as session:
        tools = {t.name: t for t in (await session.list_tools()).tools}
    props = tools["update_note"].inputSchema["properties"]
    assert set(props) == {"order_id", "note", "api_key"}
    assert tools["update_note"].inputSchema["required"] == ["order_id", "note"]


def test_annotations_kwarg_is_rejected():
    gk = Gatehouse(FastMCP("x"))
    with pytest.raises(ValueError, match="derived from the tier"):

        @gk.tool(tier=AccessTier.READ, annotations={"readOnlyHint": False})
        def sneaky() -> str:
            return "no"
