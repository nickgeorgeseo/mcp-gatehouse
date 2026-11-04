"""Configuration the gate can't read is refused where it is written, never
guessed at, and never treated as some other setting.

Each of these used to fail open or crash on the first call: a tier spelled
as a string matched nothing and the call ran ungated; a single string where
a collection belongs iterated into its characters."""

from __future__ import annotations

import io
import json

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, AuditLog, Gatehouse, Policy, redact_arguments


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def server(policy: Policy, log: io.StringIO, ran: list[str], tier: object = AccessTier.DESTRUCTIVE) -> MCPServer:
    mcp = MCPServer("inputs")
    gatehouse = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=log))

    @gatehouse.tool(tier=tier)  # type: ignore[arg-type]
    def wipe() -> str:
        ran.append("wipe")
        return "wiped"

    return mcp


# --- Policy: tiers -----------------------------------------------------------


@pytest.mark.parametrize("given", [{"destructive"}, ["DESTRUCTIVE"], ("destructive",), {AccessTier.DESTRUCTIVE}])
def test_require_approval_accepts_tier_names_and_any_collection(given):
    policy = Policy(require_approval=given)
    assert policy.require_approval == frozenset({AccessTier.DESTRUCTIVE})
    assert policy.needs_approval(AccessTier.DESTRUCTIVE)
    assert policy.needs_approval("destructive")
    assert not policy.needs_approval(AccessTier.WRITE)


@pytest.mark.anyio
async def test_tier_names_in_require_approval_still_gate():
    """{"destructive"} used to match no enum member, so the call ran."""
    log, ran = io.StringIO(), []
    mcp = server(Policy(require_approval={"write", "destructive"}), log, ran)
    async with Client(mcp) as client:
        result = await client.call_tool("wipe", {})
    assert result.is_error and "fails closed" in result.content[0].text
    assert ran == []
    assert [e["outcome"] for e in events(log)] == ["denied"]


def test_unknown_tier_name_is_refused_with_the_choices():
    with pytest.raises(ValueError, match="'read', 'write', 'destructive'"):
        Policy(require_approval={"destructve"})


def test_a_single_tier_is_refused_with_the_fix():
    """It used to raise TypeError on every call, with no audit line."""
    with pytest.raises(TypeError, match=r"require_approval=\{AccessTier.DESTRUCTIVE\}"):
        Policy(require_approval=AccessTier.DESTRUCTIVE)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="not a single string"):
        Policy(require_approval="destructive")


def test_non_tiers_are_refused():
    with pytest.raises(TypeError, match="not int"):
        Policy(require_approval={3})  # type: ignore[arg-type]


# --- Policy: names and keys --------------------------------------------------


def test_deny_as_a_bare_string_is_refused():
    """A bare string blocked every tool whose name was a substring of it."""
    with pytest.raises(TypeError, match=r"deny=\{'cancel_order'\}"):
        Policy(deny="cancel_order")


def test_redact_as_a_bare_string_is_refused():
    """A bare string masked one-letter keys and logged the real one in clear."""
    with pytest.raises(TypeError, match=r"redact=\{'api_key'\}"):
        Policy(redact="api_key")


@pytest.mark.parametrize("field", ["deny", "redact"])
def test_names_must_be_strings(field):
    with pytest.raises(TypeError, match="takes strings; got int"):
        Policy(**{field: {"ok", 7}})


def test_lists_and_sets_become_frozensets():
    policy = Policy(deny=["drop_db", "drop_db"], redact={"card_pin"})
    assert policy.deny == frozenset({"drop_db"})
    assert policy.redact == frozenset({"card_pin"})
    assert redact_arguments({"card_pin": "1234"}, policy.redact) == {"card_pin": "«redacted»"}
    hash(policy)  # still a frozen, hashable value


def test_non_collection_is_refused():
    with pytest.raises(TypeError, match="not int"):
        Policy(deny=5)  # type: ignore[arg-type]


def test_approver_must_be_callable():
    with pytest.raises(TypeError, match="callable"):
        Policy(approver=True)  # type: ignore[arg-type]
