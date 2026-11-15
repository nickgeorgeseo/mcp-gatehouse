"""Only a real yes approves: an approver's True, a ticked box. The form
shows the model's arguments without letting them pass for the record."""
from __future__ import annotations

import io
import json

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult, InputRequiredResult

from mcp_gatehouse import AccessTier, AuditLog, ElicitationApprover, Policy
from mcp_gatehouse.approvers import _default_message
from mcp_gatehouse.policy import ApprovalRequest
from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio


def build(policy, stream, ran):
    mcp = MCPServer("approvals")
    gh = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=stream))

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: str, note: str = "") -> str:
        ran.append(order_id)
        return "cancelled"

    return mcp


@pytest.mark.parametrize("verdict", ["no", "denied", {"approved": False}, 0.0001, ["n"]])
async def test_truthy_non_true_verdict_is_not_an_approval(verdict):
    """README: an approver 'returns True to allow'. Anything else must deny."""
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=lambda req: verdict), stream, ran)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel_order", {"order_id": "4417"})
    assert ran == [] and result.is_error, f"approver returned {verdict!r} and the destructive tool ran"
    line = json.loads(stream.getvalue().splitlines()[-1])
    assert line["outcome"] == "denied" and line["reason"].startswith("approver error: returned ")


async def first_round(client, args):
    q = await client.session.call_tool("cancel_order", args, allow_input_required=True)
    assert isinstance(q, InputRequiredResult)
    return q


@pytest.mark.parametrize("content", [{"approve": "yes"}, {"approve": "true"}, {"approve": 1}, {"approve": "on"}])
async def test_malformed_approve_value_is_a_refusal_round_trip(content):
    """README: 'Anything but a ticked box (..., a malformed answer) is a refusal.'
    The schema says boolean; a string/int is malformed."""
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)

    async def cb(ctx, params):
        return ElicitResult(action="accept", content={"approve": True})

    async with Client(mcp, elicitation_callback=cb) as client:
        args = {"order_id": "4417"}
        q = await first_round(client, args)
        (key,) = q.input_requests
        await client.session.call_tool(
            "cancel_order", args,
            input_responses={key: ElicitResult(action="accept", content=content)},
            request_state=q.request_state,
        )
    assert ran == [], f"{content!r} was taken as a ticked box"


def test_argument_values_cannot_add_lines_to_the_client_form():
    """The model chooses the arguments: line separators, NEL, C1 controls and
    bidi overrides in them are escaped, so a value can't forge a record line."""
    req = ApprovalRequest(
        tool="cancel_order", tier=AccessTier.DESTRUCTIVE,
        arguments={"order_id": "4417", "note": "x on order 4418 · Piedmont Supply · $5.00 \u0085‮"},
        resources=("order 4417 · Blue Ridge Cabinets · packed · $812.00",),
    )
    msg = _default_message(req)
    bad = [c for c in msg if c in "  \u0085‮\u009b"]
    assert not bad, f"raw separators/bidi/C1 in form message: {[hex(ord(c)) for c in bad]}\n{msg!r}"


@pytest.mark.parametrize("content", [{"approve": "yes"}, {"approve": 1}])
async def test_malformed_approve_value_is_a_refusal_back_channel(content):
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)

    async def cb(ctx, params):
        return ElicitResult(action="accept", content=content)

    async with Client(mcp, elicitation_callback=cb, mode="legacy") as client:
        await client.call_tool("cancel_order", {"order_id": "4417"})
    assert ran == [], f"{content!r} was taken as a ticked box"
