"""What the default policy gates, and the one switch that opens it."""

from __future__ import annotations

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, Gatehouse, MemoryAuditLog, Policy


def test_default_policy_gates_destructive_only():
    p = Policy()
    assert p.needs_approval(AccessTier.DESTRUCTIVE)
    assert not p.needs_approval(AccessTier.WRITE)
    assert not p.needs_approval(AccessTier.READ)


def test_write_gating_opt_in():
    p = Policy(require_approval=frozenset({AccessTier.WRITE, AccessTier.DESTRUCTIVE}))
    assert p.needs_approval(AccessTier.WRITE)


@pytest.mark.anyio
async def test_fail_closed_false_lets_an_unapproved_call_run_and_logs_it():
    """The one documented way to open the gate: it must do exactly that,
    and still leave the line in the trail."""
    audit, ran = MemoryAuditLog(), []
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp, policy=Policy(fail_closed=False), audit=audit)

    @gatehouse.destructive
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert not result.is_error and ran == ["1"]
    assert audit.outcomes() == [("ok", None)]
