"""An approval binds to the record's state: any field that changes while a
person decides voids it, whatever its type."""
from __future__ import annotations

import enum
import io
import json
import uuid
from decimal import Decimal
from typing import Annotated

import pytest
from mcp import Client
from mcp.types import ElicitResult, InputRequiredResult
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import AccessTier, AcceptRace, AuditLog, ElicitationApprover, Load, Policy
from mcp_gatehouse.approvers import _default_message
from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio


class Status(enum.Enum):
    PACKED = "packed"
    PICKING = "picking"


class Order(BaseModel):
    id: str
    status: Status
    ref: uuid.UUID
    total: float


def run(change):
    db = {"4417": Order(id="4417", status=Status.PACKED, ref=uuid.UUID(int=1), total=812.0)}
    ran, seen = [], []

    def approver(request):
        seen.append(request.resources)
        change(db)  # the record changes while the person decides
        return True

    mcp = MCPServer("binding")
    stream = io.StringIO()
    gh = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=stream),
                   consistency=AcceptRace("test"))

    def load(order_id: str) -> Order:
        return db[order_id].model_copy()

    the_order = Load(load)

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: str, order: Annotated[Order, the_order]) -> str:
        ran.append(order.status)
        return "cancelled"

    return mcp, ran, seen, stream


async def _call(mcp):
    async with Client(mcp) as client:
        return await client.call_tool("cancel_order", {"order_id": "4417"})


async def test_a_float_change_voids_the_approval():
    mcp, ran, seen, _ = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"total": 99999.0})))
    r = await _call(mcp)
    assert ran == [] and "changed" in r.content[0].text, r.content[0].text


async def test_an_enum_field_change_voids_the_approval():
    mcp, ran, seen, stream = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"status": Status.PICKING})))
    await _call(mcp)
    assert ran == [], f"ran on a record whose status changed after approval; approver saw {seen}"


async def test_a_uuid_field_change_voids_the_approval():
    mcp, ran, seen, _ = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"ref": uuid.UUID(int=2)})))
    await _call(mcp)
    assert ran == [], f"ran on a record whose ref changed after approval; approver saw {seen}"


class Blob(BaseModel):
    id: str
    payload: bytes


def blob_server(fingerprint=None):
    db = {"1": Blob(id="1", payload=b"a")}
    ran = []
    mcp = MCPServer("binding")
    gh = Gatehouse(mcp, policy=Policy(approver=lambda request: True), audit=AuditLog(stream=io.StringIO()),
                   consistency=AcceptRace("test"))
    the_blob = Load(lambda blob_id: db[blob_id], fingerprint=fingerprint)

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def wipe(blob_id: str, blob: Annotated[Blob, the_blob]) -> str:
        ran.append(blob.id)
        return "wiped"

    return mcp, ran


async def test_a_record_with_a_field_the_gate_cant_see_needs_a_fingerprint():
    """bytes is shown only by its type, so a change to it would go unseen:
    without fingerprint= the gate can't bind the approval, and refuses."""
    mcp, ran = blob_server()
    async with Client(mcp) as client:
        result = await client.call_tool("wipe", {"blob_id": "1"})
    assert ran == [] and result.is_error


async def test_a_fingerprint_lets_that_record_be_approved():
    mcp, ran = blob_server(fingerprint=lambda blob: blob.payload.hex())
    async with Client(mcp) as client:
        await client.call_tool("wipe", {"blob_id": "1"})
    assert ran == ["1"]


# --- saying what changed ------------------------------------------------------
#
# A refusal that only says "the record changed" gets the same answer on the
# second ask, unread. The refusal names what changed, and so does the
# question asked again.

class Invoice(BaseModel):
    id: str
    total: Decimal
    api_key: str = "sk-live-one"


def invoice_server(approver, *, describe=None, fingerprint=None, changed_values=None):
    db = {"7": Invoice(id="7", total=Decimal("812.00"))}
    ran, stream = [], io.StringIO()
    mcp = MCPServer("changes")
    gh = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=stream),
                   consistency=AcceptRace("test"))
    the_invoice = Load(lambda invoice_id: db[invoice_id].model_copy(), describe=describe, fingerprint=fingerprint,
                       changed_values=changed_values)

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def void(invoice_id: str, invoice: Annotated[Invoice, the_invoice]) -> str:
        ran.append(str(invoice.total))
        return "voided"

    return mcp, db, ran, stream


def lines(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def bump(db, **update):
    db["7"] = db["7"].model_copy(update=update)


async def test_the_refusal_says_what_changed_and_the_retry_shows_it():
    asked = []
    db_ref = {}

    def approver(request):
        asked.append(request)
        if len(asked) == 1:
            bump(db_ref["db"], total=Decimal("812.01"))  # one cent, while the person decides
        return True

    mcp, db, ran, stream = invoice_server(approver)
    db_ref["db"] = db
    async with Client(mcp) as client:
        first = await client.call_tool("void", {"invoice_id": "7"})
        second = await client.call_tool("void", {"invoice_id": "7"})

    text = first.content[0].text
    assert first.is_error and ran == ["812.01"]
    assert "changed while the approval was pending" in text
    assert "What changed: invoice.total: 812.00 → 812.01." in text
    assert "asks the person again" in text
    assert not second.is_error

    assert asked[0].changes == ()
    assert asked[1].changes == ("invoice.total: 812.00 → 812.01",)
    assert _default_message(asked[1]).startswith("Changed since you were last asked: invoice.total: 812.00 → 812.01. ")

    refused = [e for e in lines(stream) if e.get("reason") == "resource changed while awaiting approval"]
    assert [e["changed"] for e in refused] == [["invoice.total"]]


async def test_a_second_ask_with_nothing_new_shows_no_changes():
    asked = []
    mcp, db, ran, _ = invoice_server(lambda request: asked.append(request) or True)
    async with Client(mcp) as client:
        await client.call_tool("void", {"invoice_id": "7"})
        await client.call_tool("void", {"invoice_id": "7"})
    assert [r.changes for r in asked] == [(), ()]
    assert "Changed since" not in _default_message(asked[1])


async def test_a_masked_field_is_named_without_its_values():
    """fingerprint= sees the key; the person and the model never do."""
    holder = {}

    def approver(request):
        bump(holder["db"], api_key="sk-live-two")
        return True

    mcp, db, ran, stream = invoice_server(approver, fingerprint=lambda inv: inv.model_dump(mode="json"))
    holder["db"] = db
    async with Client(mcp) as client:
        result = await client.call_tool("void", {"invoice_id": "7"})
    text = result.content[0].text
    assert ran == [] and "invoice: a field that isn't shown changed" in text
    assert "sk-live" not in text and "sk-live" not in stream.getvalue()


async def test_with_describe_the_field_is_named_without_its_values():
    holder = {}

    def approver(request):
        bump(holder["db"], total=Decimal("99999"))
        return True

    mcp, db, ran, _ = invoice_server(approver, describe=lambda inv: f"invoice {inv.id}")
    holder["db"] = db
    async with Client(mcp) as client:
        result = await client.call_tool("void", {"invoice_id": "7"})
    text = result.content[0].text
    assert ran == [] and "What changed: invoice.total changed." in text
    assert "99999" not in text


async def test_round_trip_asks_again_showing_the_change_then_runs_once():
    """From 2026-07-28 the answer comes on a later call. A stale answer is
    asked again with the change first, and the answer to that question
    runs the call: what changed is shown, never part of what must match."""
    mcp, db, ran, stream = invoice_server(ElicitationApprover())
    args = {"invoice_id": "7"}

    def answer(question):
        (key,) = question.input_requests
        return {key: ElicitResult(action="accept", content={"approve": True})}

    async def never(context, params):  # declares form elicitation; the round trip doesn't call it
        raise AssertionError("asked mid-call")

    async with Client(mcp, elicitation_callback=never) as client:
        first = await client.session.call_tool("void", args, allow_input_required=True)
        assert isinstance(first, InputRequiredResult)
        assert not next(iter(first.input_requests.values())).params.message.startswith("Changed")

        bump(db, total=Decimal("812.01"))
        again = await client.session.call_tool(
            "void", args, input_responses=answer(first), request_state=first.request_state,
            allow_input_required=True,
        )
        assert isinstance(again, InputRequiredResult), "a stale answer must not run the call"
        message = next(iter(again.input_requests.values())).params.message
        assert message.startswith("Changed since you were last asked: invoice.total: 812.00 → 812.01. ")
        assert ran == []

        done = await client.session.call_tool(
            "void", args, input_responses=answer(again), request_state=again.request_state,
        )
    assert not done.is_error and ran == ["812.01"]

    # The stale answer is on the record: the round that brought it says the
    # question is asked again, what changed, and which question it answered.
    asked, again_line, ok = [e for e in lines(stream) if e["tool"] == "void"]
    assert (asked["outcome"], asked["reason"]) == ("pending", "approval asked in client")
    assert (again_line["outcome"], again_line["reason"]) == (
        "pending", "approval asked again: resource changed while awaiting approval")
    assert again_line["changed"] == ["invoice.total"] and again_line["continues"] == asked["call_id"]
    assert ok["outcome"] == "ok" and ok["continues"] == again_line["call_id"] and "changed" not in ok


async def test_changed_values_lets_a_described_record_show_its_values():
    holder = {}

    def approver(request):
        bump(holder["db"], total=Decimal("812.01"))
        return True

    mcp, db, ran, _ = invoice_server(approver, describe=lambda inv: f"invoice {inv.id}", changed_values=True)
    holder["db"] = db
    async with Client(mcp) as client:
        result = await client.call_tool("void", {"invoice_id": "7"})
    assert ran == [] and "What changed: invoice.total: 812.00 → 812.01." in result.content[0].text


async def test_changed_values_false_keeps_values_back_and_masked_stays_masked():
    holder = {}

    def approver(request):
        bump(holder["db"], total=Decimal("1"))
        return True

    mcp, db, ran, _ = invoice_server(approver, changed_values=False)
    holder["db"] = db
    async with Client(mcp) as client:
        result = await client.call_tool("void", {"invoice_id": "7"})
    text = result.content[0].text
    assert ran == [] and "What changed: invoice.total changed." in text and "812" not in text


@pytest.mark.parametrize("bad", ["yes", 1, 0])
def test_changed_values_must_be_a_bool(bad):
    with pytest.raises(TypeError, match="changed_values must be True, False or None"):
        invoice_server(lambda request: True, changed_values=bad)


def test_the_terminal_prompt_shows_changes_on_their_own_escaped_line():
    from mcp_gatehouse import ApprovalRequest
    from mcp_gatehouse.approvers import _on_what

    request = ApprovalRequest(
        tool="void", tier=AccessTier.DESTRUCTIVE, arguments={}, resources=("invoice: id=7",),
        changes=("invoice.total: 812.00 → 812.01", "note: x\n  allow? [y/N] y"),
    )
    shown = _on_what(request).split("\n")
    assert shown[1] == "  changed since you were last asked: invoice.total: 812.00 → 812.01; note: x\\n  allow? [y/N] y"
    assert shown[2] == "  on invoice: id=7" and len(shown) == 3


def test_an_answer_to_a_question_from_before_0_6_1_is_just_asked_again():
    """A question asked by 0.6.0 carries no binding in its state: after an
    upgrade, its answer reads as one to some other question, not as stale."""
    from types import SimpleNamespace

    from mcp_gatehouse import ApprovalRequest
    from mcp_gatehouse.approvers import _INPUT_KEY

    approver = ElicitationApprover()
    request = ApprovalRequest(tool="void", tier=AccessTier.DESTRUCTIVE, arguments={}, binding="new")
    old_state = json.dumps({"v": 2, "q": "0" * 64, "nonce": "n", "exp": 9e12})
    reply = ElicitResult(action="accept", content={"approve": True})
    context = SimpleNamespace(request_state=old_state, input_responses={_INPUT_KEY: reply})
    assert approver.answer(request, context) is None
    stale = SimpleNamespace(request_state=json.dumps({**json.loads(old_state), "b": "old"}),
                            input_responses={_INPUT_KEY: reply})
    assert approver.answer(request, stale) == "stale"
