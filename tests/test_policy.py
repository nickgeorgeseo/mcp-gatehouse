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


# --- max_tier: a read-only switch ---------------------------------------------


def server_with_every_tier(policy: Policy, audit: MemoryAuditLog, ran: list[str]) -> tuple[MCPServer, Gatehouse]:
    mcp = MCPServer("tiers")
    gatehouse = Gatehouse(mcp, policy=policy, audit=audit)

    @gatehouse.read
    def lookup() -> str:
        ran.append("lookup")
        return "found"

    @gatehouse.write
    def note() -> str:
        ran.append("note")
        return "noted"

    @gatehouse.destructive
    def wipe() -> str:
        ran.append("wipe")
        return "wiped"

    return mcp, gatehouse


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("max_tier", "allowed"),
    [("read", ["lookup"]), ("write", ["lookup", "note"]), (AccessTier.DESTRUCTIVE, ["lookup", "note", "wipe"])],
)
async def test_max_tier_denies_everything_above_it(max_tier, allowed):
    """Whatever the approver would say: an approver that approves
    everything is configured, and still nothing above max_tier runs."""
    audit, ran = MemoryAuditLog(), []
    mcp, _ = server_with_every_tier(Policy(max_tier=max_tier, approver=lambda r: True), audit, ran)
    async with Client(mcp) as client:
        results = {name: await client.call_tool(name, {}) for name in ("lookup", "note", "wipe")}
    assert ran == allowed
    for name, result in results.items():
        if name in allowed:
            assert not result.is_error
        else:
            assert result.is_error
            assert "is not allowed: this server is limited to" in result.content[0].text
    denied = [e["tool"] for e in audit.events if e["outcome"] == "denied"]
    assert denied == [n for n in ("lookup", "note", "wipe") if n not in allowed]
    assert all(e["reason"] == "tier above max_tier" for e in audit.events if e["outcome"] == "denied")


@pytest.mark.anyio
async def test_a_running_server_switches_to_read_only_and_back():
    audit, ran = MemoryAuditLog(), []
    mcp, gatehouse = server_with_every_tier(Policy(), audit, ran)
    async with Client(mcp) as client:
        assert not (await client.call_tool("note", {})).is_error
        gatehouse.policy = Policy(max_tier="read")  # an incident: stop all changes
        assert (await client.call_tool("note", {})).is_error
        assert not (await client.call_tool("lookup", {})).is_error
        gatehouse.policy = Policy()
        assert not (await client.call_tool("note", {})).is_error
    assert ran == ["note", "lookup", "note"]


@pytest.mark.anyio
async def test_the_denylist_is_checked_before_max_tier():
    audit = MemoryAuditLog()
    mcp, _ = server_with_every_tier(Policy(max_tier="read", deny={"wipe"}), audit, [])
    async with Client(mcp) as client:
        await client.call_tool("wipe", {})
    assert audit.outcomes() == [("denied", "denylist")]


def test_max_tier_is_read_like_any_tier():
    assert Policy(max_tier="READ").max_tier is AccessTier.READ
    assert Policy().max_tier is None
    assert Policy(max_tier="write").allows("read") and not Policy(max_tier="write").allows(AccessTier.DESTRUCTIVE)
    assert Policy().allows("destructive")
    with pytest.raises(ValueError, match="unknown access tier"):
        Policy(max_tier="readonly")


def test_replace_switches_max_tier_and_keeps_the_rest():
    """The README's mid-incident switch: dataclasses.replace on a Policy."""
    from dataclasses import replace

    def approver(request):
        return True

    policy = Policy(approver=approver, deny={"drop_db"}, require_approval={"write"}, approval_timeout=5)
    switched = replace(policy, max_tier="read")
    assert switched.max_tier is AccessTier.READ
    assert switched.approver is approver and switched.deny == {"drop_db"}
    assert switched.require_approval == {AccessTier.WRITE} and switched.approval_timeout == 5
