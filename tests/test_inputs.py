"""Configuration the gate can't read is refused where it is written, never
guessed at, and never treated as some other setting.

Each of these used to fail open or crash on the first call: a tier spelled
as a string matched nothing and the call ran ungated; a single string where
a collection belongs iterated into its characters."""

from __future__ import annotations

import io
import warnings

import pytest
from audit_helpers import events
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from mcp_gatehouse import (
    AccessTier,
    AuditLog,
    Gatehouse,
    Policy,
    redact_arguments,
)


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


# --- registration: tiers -----------------------------------------------------


async def listed(mcp: MCPServer) -> dict:
    async with Client(mcp) as client:
        return {t.name: t for t in (await client.list_tools()).tools}


@pytest.mark.anyio
async def test_tier_given_as_a_string_is_gated():
    """tier="destructive" used to run with no approval, then crash writing
    the audit line: no record, and an error that invites a retry."""
    log, ran = io.StringIO(), []
    mcp = server(Policy(), log, ran, tier="destructive")
    async with Client(mcp) as client:
        result = await client.call_tool("wipe", {})
    assert result.is_error and "fails closed" in result.content[0].text
    assert ran == []
    (event,) = events(log)
    assert (event["outcome"], event["tier"]) == ("denied", "destructive")


@pytest.mark.anyio
async def test_tier_names_are_case_insensitive():
    mcp = server(Policy(), io.StringIO(), [], tier="Write")
    hints = (await listed(mcp))["wipe"].annotations
    assert (hints.read_only_hint, hints.destructive_hint) == (False, False)


@pytest.mark.parametrize(("tier", "error"), [("destroy", ValueError), (3, TypeError), (None, TypeError)])
def test_unreadable_tier_fails_at_registration(tier, error):
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(error):
        gatehouse.tool(tier=tier)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_no_tier_warns_and_stays_read():
    """Unchanged behaviour, no longer silent: the warning names the tool
    and points at the line that registered it."""
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp)
    with pytest.warns(FutureWarning, match="'delete_everything' has no tier") as caught:

        @gatehouse.tool()
        def delete_everything() -> str:
            return "deleted"

    assert caught[0].filename == __file__
    hints = (await listed(mcp))["delete_everything"].annotations
    assert hints.read_only_hint is True


def test_explicit_tier_does_not_warn():
    gatehouse = Gatehouse(MCPServer("t"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")

        @gatehouse.tool(tier=AccessTier.READ)
        def lookup() -> str:
            return "x"

        @gatehouse.read
        def lookup2() -> str:
            return "x"


# --- registration: the tier decorators and add_tool -------------------------


@pytest.mark.anyio
async def test_tier_decorators_with_and_without_parentheses():
    log, ran = io.StringIO(), []
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp, audit=AuditLog(stream=log))

    @gatehouse.read
    def lookup(order_id: str) -> str:
        return f"order {order_id}"

    @gatehouse.write(name="annotate", title="Add a note")
    def add_note(order_id: str, note: str) -> str:
        return "noted"

    @gatehouse.destructive
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    assert lookup("1") == "order 1"  # the function comes back unwrapped
    tools = await listed(mcp)
    assert set(tools) == {"lookup", "annotate", "cancel"}
    hints = {n: (t.annotations.read_only_hint, t.annotations.destructive_hint) for n, t in tools.items()}
    assert hints == {"lookup": (True, False), "annotate": (False, False), "cancel": (False, True)}
    assert tools["annotate"].title == "Add a note"
    async with Client(mcp) as client:
        assert not (await client.call_tool("lookup", {"order_id": "1"})).is_error
        assert (await client.call_tool("cancel", {"order_id": "1"})).is_error  # default policy, no approver
    assert ran == []
    assert [e["outcome"] for e in events(log)] == ["ok", "denied"]


def test_tier_decorators_refuse_a_positional_name_or_a_tier():
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError, match="keyword arguments only"):
        gatehouse.read("lookup")  # type: ignore[call-overload]
    with pytest.raises(TypeError, match="sets the tier itself"):
        gatehouse.write(tier=AccessTier.DESTRUCTIVE)


@pytest.mark.anyio
async def test_add_tool_registers_a_gated_tool():
    log, ran = io.StringIO(), []
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp, policy=Policy(approver=lambda request: True), audit=AuditLog(stream=log))

    def purge(order_id: str) -> str:
        ran.append(order_id)
        return "purged"

    gatehouse.add_tool(purge, tier="destructive", name="purge_order", description="Purge an order.")
    tools = await listed(mcp)
    assert tools["purge_order"].annotations.destructive_hint is True
    assert tools["purge_order"].description == "Purge an order."
    async with Client(mcp) as client:
        assert not (await client.call_tool("purge_order", {"order_id": "7"})).is_error
    assert ran == ["7"]
    assert events(log)[-1]["tool"] == "purge_order"


def test_add_tool_requires_a_tier():
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError):
        gatehouse.add_tool(lambda: "x")  # type: ignore[call-arg]


# --- registration: annotations -----------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "given",
    [
        {"openWorldHint": False, "idempotentHint": True},
        {"open_world_hint": False, "idempotent_hint": True},
        ToolAnnotations(open_world_hint=False, idempotent_hint=True),
    ],
    ids=["camelCase", "snake_case", "model"],
)
async def test_annotations_add_the_hints_the_tier_does_not_decide(given):
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp)

    @gatehouse.write(annotations=given)
    def upsert(key: str) -> str:
        return "ok"

    hints = (await listed(mcp))["upsert"].annotations
    assert (hints.open_world_hint, hints.idempotent_hint) == (False, True)
    assert (hints.read_only_hint, hints.destructive_hint) == (False, False)


def test_annotations_may_agree_with_the_tier_but_not_contradict_it():
    gatehouse = Gatehouse(MCPServer("t"))
    gatehouse.tool(tier="destructive", annotations={"destructiveHint": True, "readOnlyHint": False})
    with pytest.raises(ValueError, match="destructiveHint=False contradicts tier 'destructive'"):
        gatehouse.destructive(annotations={"destructiveHint": False})
    with pytest.raises(ValueError, match="readOnlyHint=True contradicts tier 'write'"):
        gatehouse.write(annotations=ToolAnnotations(read_only_hint=True))


def test_misspelled_annotation_is_refused():
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(ValueError, match="unknown tool annotation"):
        gatehouse.read(annotations={"openworldHint": False})


@pytest.mark.anyio
async def test_title_comes_from_the_annotations_unless_given():
    mcp = MCPServer("t")
    gatehouse = Gatehouse(mcp)

    @gatehouse.read(annotations={"title": "From annotations"})
    def a() -> str:
        return "a"

    @gatehouse.read(title="From title", annotations={"title": "From annotations"})
    def b() -> str:
        return "b"

    tools = await listed(mcp)
    assert tools["a"].annotations.title == "From annotations"
    assert tools["b"].annotations.title == "From title"


def test_annotations_of_the_wrong_type_are_refused():
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError, match="ToolAnnotations or a mapping"):
        gatehouse.read(annotations=["readOnlyHint"])  # type: ignore[arg-type]
