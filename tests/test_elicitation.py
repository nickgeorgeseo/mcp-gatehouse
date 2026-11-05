"""ElicitationApprover: approval asked in the client's own UI.

Two transports, picked by the negotiated protocol. Up to 2025-11-25 the
form goes over the back-channel mid-call; from 2026-07-28 the call returns
the question and runs when the client calls again with the answer. Both
fail closed, and a client that can't be asked hands over to the fallback.
"""

from __future__ import annotations

import io
import json
import time
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from audit_helpers import events, outcomes
from mcp import Client, MCPError
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ElicitResult, InputRequiredResult

from mcp_gatehouse import (
    AccessTier,
    ApprovalRequest,
    AuditLog,
    ElicitationApprover,
    Gatehouse,
    Policy,
)
from mcp_gatehouse.approvers import _INPUT_KEY, _default_message, _digest

ARGUMENTS = {"order_id": "4417", "api_key": "sk-live-not-for-the-form"}
LOGGED = {"order_id": "4417", "api_key": "«redacted»"}

pytestmark = pytest.mark.anyio


def build(policy: Policy, stream: io.StringIO, ran: list[str]) -> MCPServer:
    mcp = MCPServer("elicit-test")
    gatehouse = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=stream))

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: str, api_key: str = "") -> str:
        ran.append(order_id)
        return f"{order_id} cancelled"

    return mcp


def answering(action: str, content: dict[str, Any] | None = None, asked: list | None = None):
    async def callback(context: Any, params: Any) -> ElicitResult:
        if asked is not None:
            asked.append(params)
        return ElicitResult(action=action, content=content)

    return callback


APPROVE = ("accept", {"approve": True})
UNTICKED = ("accept", {"approve": False})


# --- both transports --------------------------------------------------------

ROUND_TRIP = {}  # in process, the client adopts the newest revision
BACK_CHANNEL = {"mode": "legacy"}  # the initialize handshake, 2025-11-25


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_approved_in_client_runs_once(connect):
    stream, ran, asked = io.StringIO(), [], []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE, asked=asked), **connect) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)

    assert not result.is_error
    assert ran == ["4417"]
    # The person sees what the model asked for, secrets masked.
    (form,) = asked
    assert "cancel_order (destructive)" in form.message
    assert "«redacted»" in form.message and "sk-live" not in form.message
    assert form.requested_schema["required"] == ["approve"]

    trail = events(stream)
    assert trail[-1]["outcome"] == "ok" and trail[-1]["arguments"] == LOGGED
    if connect is ROUND_TRIP:
        # The first round ends the call for now; its line records the asking.
        assert outcomes(stream) == [("pending", "approval asked in client"), ("ok", None)]
    else:
        assert outcomes(stream) == [("ok", None)]


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
@pytest.mark.parametrize(
    "answer", [("decline", None), ("cancel", None), UNTICKED], ids=["decline", "cancel", "unticked"]
)
async def test_anything_but_a_ticked_box_refuses(connect, answer):
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*answer), **connect) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)

    assert result.is_error
    assert "refused by the approver" in result.content[0].text
    assert ran == []
    assert outcomes(stream)[-1] == ("denied", "approver refused")


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_malformed_form_fails_closed(connect):
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering("accept", {"approve": "maybe"}), **connect) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)

    assert result.is_error
    assert ran == []
    outcome, reason = outcomes(stream)[-1]
    assert outcome == "denied" and reason.startswith("approver error")


# --- a client that can't be asked ------------------------------------------


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_no_elicitation_and_no_fallback_denies(connect):
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, **connect) as client:  # no elicitation_callback: no capability
        result = await client.call_tool("cancel_order", ARGUMENTS)

    assert result.is_error
    assert "can't be asked" in result.content[0].text
    assert ran == []
    assert outcomes(stream) == [("denied", "approval required, client cannot be asked")]


@pytest.mark.parametrize("verdict", [True, False])
async def test_no_elicitation_hands_over_to_the_fallback(verdict):
    stream, ran, seen = io.StringIO(), [], []

    def fallback(request):
        seen.append(request.arguments)
        return verdict

    mcp = build(Policy(approver=ElicitationApprover(fallback=fallback)), stream, ran)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)

    assert seen == [LOGGED]
    assert result.is_error is (not verdict)
    assert ran == (["4417"] if verdict else [])


async def test_async_fallback_is_awaited():
    stream, ran = io.StringIO(), []

    async def fallback(request):
        return True

    mcp = build(Policy(approver=ElicitationApprover(fallback=fallback)), stream, ran)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)
    assert not result.is_error and ran == ["4417"]


async def test_tool_with_its_own_rounds_uses_the_fallback():
    """A tool that returns its own InputRequiredResult owns the call's one
    multi-round channel; the gate's question would overwrite its state."""
    stream, seen = io.StringIO(), []
    mcp = MCPServer("own-rounds")
    gatehouse = Gatehouse(
        mcp,
        policy=Policy(approver=ElicitationApprover(fallback=lambda r: seen.append(r.tool) or True)),
        audit=AuditLog(stream=stream),
    )

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
    def purge(order_id: str) -> str | InputRequiredResult:
        return f"{order_id} purged"

    async with Client(mcp, elicitation_callback=answering(*APPROVE)) as client:
        result = await client.call_tool("purge", {"order_id": "1"})

    assert not result.is_error
    assert seen == ["purge"]


# --- the round trip's checks ------------------------------------------------


async def first_round(client: Client, arguments: dict = ARGUMENTS) -> InputRequiredResult:
    question = await client.session.call_tool("cancel_order", arguments, allow_input_required=True)
    assert isinstance(question, InputRequiredResult)
    return question


def approval(question: InputRequiredResult, action: str = "accept", content: dict | None = None):
    (key,) = question.input_requests
    return {key: ElicitResult(action=action, content=content or {"approve": True})}


async def test_an_approval_runs_its_call_once():
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE)) as client:
        question = await first_round(client)
        answer = approval(question)
        first = await client.session.call_tool(
            "cancel_order", ARGUMENTS, input_responses=answer, request_state=question.request_state
        )
        replay = await client.session.call_tool(
            "cancel_order", ARGUMENTS, input_responses=answer, request_state=question.request_state
        )

    assert not first.is_error
    assert replay.is_error and "already used" in replay.content[0].text
    assert ran == ["4417"]
    assert outcomes(stream)[-1] == ("denied", "approval already used")


async def test_an_approval_cant_be_moved_to_other_arguments():
    """The SDK binds the sealed state to the tool and its exact arguments."""
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE)) as client:
        question = await first_round(client)
        with pytest.raises(MCPError):
            await client.session.call_tool(
                "cancel_order",
                {**ARGUMENTS, "order_id": "4418"},
                input_responses=approval(question),
                request_state=question.request_state,
            )
    assert ran == []


async def test_an_answer_without_its_state_is_asked_again():
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE)) as client:
        question = await first_round(client)
        again = await client.session.call_tool(
            "cancel_order", ARGUMENTS, input_responses=approval(question), allow_input_required=True
        )
    assert isinstance(again, InputRequiredResult)
    assert ran == []


async def test_a_late_approval_is_denied():
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover(), approval_timeout=0.2), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE)) as client:
        question = await first_round(client)
        await anyio.sleep(0.3)
        late = await client.session.call_tool(
            "cancel_order", ARGUMENTS, input_responses=approval(question), request_state=question.request_state
        )
    assert late.is_error and "not approved within 0.2s" in late.content[0].text
    assert ran == []
    assert outcomes(stream)[-1] == ("denied", "approval timed out")


async def test_back_channel_respects_the_approval_timeout():
    stream, ran = io.StringIO(), []

    async def slow(context, params):
        await anyio.sleep(5)
        return ElicitResult(action="accept", content={"approve": True})

    mcp = build(Policy(approver=ElicitationApprover(), approval_timeout=0.2), stream, ran)
    async with Client(mcp, elicitation_callback=slow, mode="legacy") as client:
        with anyio.fail_after(3):
            result = await client.call_tool("cancel_order", ARGUMENTS)
    assert result.is_error
    assert ran == []
    assert outcomes(stream)[-1] == ("denied", "approval timed out")


# --- the guard's Context plumbing -------------------------------------------


async def test_hidden_context_stays_out_of_the_schema():
    mcp = build(Policy(approver=ElicitationApprover()), io.StringIO(), [])
    async with Client(mcp) as client:
        (tool,) = (await client.list_tools()).tools
    assert set(tool.input_schema["properties"]) == {"order_id", "api_key"}


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_tool_that_takes_a_context_still_gets_it(connect):
    stream, got = io.StringIO(), []
    mcp = MCPServer("ctx-tool")
    gatehouse = Gatehouse(mcp, policy=Policy(approver=ElicitationApprover()), audit=AuditLog(stream=stream))

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
    async def wipe(order_id: str, ctx: Context) -> str:
        got.append(isinstance(ctx, Context))
        return "wiped"

    async with Client(mcp, elicitation_callback=answering(*APPROVE), **connect) as client:
        (tool,) = (await client.list_tools()).tools
        result = await client.call_tool("wipe", {"order_id": "1"})

    assert set(tool.input_schema["properties"]) == {"order_id"}
    assert not result.is_error and got == [True]
    assert events(stream)[-1]["arguments"] == {"order_id": "1"}


# Written as source and compiled without this file's `from __future__ import
# annotations`, so each hint is the real object as well as its string form.
OPTIONAL_CONTEXT_HINTS = [
    "Optional[Context]",
    "Union[Context, None]",
    "Context | None",
    "Annotated[Context, 'injected']",
    "Context[Any, Any] | None",
]


def _tool_with_hint(hint: str, as_string: bool, ran: list):
    quoted = repr(hint) if as_string else hint
    source = (
        "from typing import Annotated, Any, Optional, Union\n"
        "from mcp.server.mcpserver import Context\n"
        f"def purge(order_id: str, ctx: {quoted} = None) -> str:\n"
        "    ran.append(type(ctx).__name__)\n"
        "    return 'purged'\n"
    )
    namespace: dict[str, Any] = {"ran": ran}
    exec(compile(source, "<purge>", "exec", dont_inherit=True), namespace)
    return namespace["purge"]


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
@pytest.mark.parametrize("as_string", [False, True], ids=["hint", "string-hint"])
@pytest.mark.parametrize("hint", OPTIONAL_CONTEXT_HINTS)
async def test_optional_context_is_found_like_the_sdk_finds_it(hint, as_string, connect):
    """The gate used to miss these, while the SDK injected into them. Its
    hidden parameter then reached the model-visible schema, ctx reached
    the audit log, and approval in the client was always denied."""
    stream, ran = io.StringIO(), []
    mcp = MCPServer("optional-ctx")
    gatehouse = Gatehouse(mcp, policy=Policy(approver=ElicitationApprover()), audit=AuditLog(stream=stream))
    gatehouse.add_tool(_tool_with_hint(hint, as_string, ran), tier=AccessTier.DESTRUCTIVE)

    async with Client(mcp, elicitation_callback=answering(*APPROVE), **connect) as client:
        (tool,) = (await client.list_tools()).tools
        result = await client.call_tool("purge", {"order_id": "1"})

    assert set(tool.input_schema["properties"]) == {"order_id"}
    assert not result.is_error, result.content[0].text
    assert ran == ["Context"]
    assert all(e["arguments"] == {"order_id": "1"} for e in events(stream))


@pytest.mark.parametrize("hint", [*OPTIONAL_CONTEXT_HINTS, "Context", "int", "Optional[int]"])
def test_fallback_detection_agrees_with_the_sdk(hint):
    """Used only if the SDK's helper moves; it must give the SDK's answer."""
    from mcp.server.mcpserver.utilities.context_injection import find_context_parameter

    from mcp_gatehouse.gatehouse import _sdk_find_context_parameter

    for as_string in (False, True):
        fn = _tool_with_hint(hint, as_string, [])
        assert _sdk_find_context_parameter(fn) == find_context_parameter(fn)


def test_reserved_parameter_name_is_refused():
    gatehouse = Gatehouse(MCPServer("reserved"))
    with pytest.raises(ValueError, match="reserves"):

        @gatehouse.tool(tier=AccessTier.READ)
        def clash(gatehouse_context: str) -> str:
            return gatehouse_context


def test_called_directly_it_defers_to_the_fallback():
    from mcp_gatehouse import ApprovalRequest

    request = ApprovalRequest(tool="t", tier=AccessTier.DESTRUCTIVE, arguments={})
    assert ElicitationApprover()(request) is False
    assert ElicitationApprover(fallback=lambda r: True)(request) is True


# --- the round trip's answer checks, one at a time ---------------------------

REQUEST = ApprovalRequest(tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={"order_id": "1"})


def answer_context(state: dict | str | None, reply: object = None) -> SimpleNamespace:
    raw = state if isinstance(state, str) or state is None else json.dumps(state)
    return SimpleNamespace(request_state=raw, input_responses=None if reply is None else {_INPUT_KEY: reply})


def sealed_state(**overrides: object) -> dict:
    base = {"v": 1, "q": _digest(_default_message(REQUEST)), "nonce": "n-1", "exp": time.time() + 60}
    return {**base, **overrides}


APPROVED = ElicitResult(action="accept", content={"approve": True})


@pytest.mark.parametrize(
    "ctx",
    [
        answer_context(None, APPROVED),
        answer_context("not json", APPROVED),
        answer_context(sealed_state(v=2), APPROVED),
        answer_context(sealed_state(nonce=5), APPROVED),
        answer_context({"v": 1}, APPROVED),
        answer_context(sealed_state(), None),
        answer_context(sealed_state(q=_digest("some other question")), APPROVED),
    ],
    ids=["no-state", "garbage", "other-version", "bad-nonce", "missing-fields", "no-answer", "other-question"],
)
def test_anything_but_an_answer_to_this_question_is_asked_again(ctx):
    """None means 'ask (again)'; nothing here may approve."""
    assert ElicitationApprover().answer(REQUEST, ctx) is None


def test_an_answer_that_is_not_an_elicitation_result_is_an_error():
    assert ElicitationApprover().answer(REQUEST, answer_context(sealed_state(), {"action": "accept"})) == (
        False,
        "approver error: not an elicitation answer",
    )


def test_spent_approvals_are_forgotten_once_expired():
    """Single use is tracked in memory; expired entries must not pile up
    for the life of the process."""
    approver = ElicitationApprover()
    now = time.time()
    assert approver._spend("old", now - 1)
    assert approver._spend("live", now + 60)
    assert not approver._spend("live", now + 60)
    assert approver._spend("new", now + 60)
    assert set(approver._used) == {"live", "new"}


# --- no live request: nobody to ask -------------------------------------------


@pytest.mark.parametrize("fallback", [None, True, False], ids=["no-fallback", "fallback-yes", "fallback-no"])
async def test_direct_call_tool_has_no_client_to_ask(fallback):
    """MCPServer.call_tool() from server code (a test, a job) has no
    request behind it, so there's no client to ask: the fallback decides,
    and with none the call is denied."""
    stream, ran = io.StringIO(), []
    approver = ElicitationApprover(fallback=None if fallback is None else (lambda r: fallback))
    mcp = build(Policy(approver=approver), stream, ran)
    if fallback:
        await mcp.call_tool("cancel_order", ARGUMENTS)
        assert ran == ["4417"]
    else:
        with pytest.raises(Exception, match="fails closed|refused"):
            await mcp.call_tool("cancel_order", ARGUMENTS)
        assert ran == []
        assert events(stream)[-1]["outcome"] == "denied"


# --- what the person is shown --------------------------------------------------


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_the_form_shows_invisible_characters_as_escapes(connect):
    """The arguments come from the model, and the person approving reads
    them. Bidi overrides and zero-width characters would let a crafted
    value display as something other than what is being approved: escape
    them. Readable text, accents and all, stays as it is."""
    stream, ran, asked = io.StringIO(), [], []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    tricky = {"order_id": "4417‮0001", "api_key": "", "note": "café​"}
    async with Client(mcp, elicitation_callback=answering(*APPROVE, asked=asked), **connect) as client:
        mcp_tool = (await client.list_tools()).tools[0].name
        await client.call_tool(mcp_tool, {"order_id": tricky["order_id"]})
    (form,) = asked
    assert "‮" not in form.message and "\\u202e" in form.message
    assert "4417" in form.message


def test_the_default_message_keeps_readable_text_and_escapes_the_rest():
    from mcp_gatehouse.approvers import _default_message

    request = ApprovalRequest(
        tool="t", tier=AccessTier.WRITE, arguments={"note": "café ünïcode 中文 ​⁦x⁩   tab\there"}
    )
    message = _default_message(request)
    assert "café ünïcode 中文" in message
    for hidden in ("​", "⁦", "⁩", " ", "\t"):
        assert hidden not in message
    assert "\\u200b" in message and "\\u2066" in message and "\\t" in message


# --- the approver's own machinery failing ---------------------------------------


@pytest.mark.parametrize("connect", [ROUND_TRIP, BACK_CHANNEL], ids=["round-trip", "back-channel"])
async def test_a_message_function_that_raises_is_an_audited_denial(connect):
    """A custom message= that raises is the approver failing: a denial on
    the record, not a crash that leaves no line."""
    stream, ran = io.StringIO(), []

    def broken_message(request):
        raise KeyError("customer_name")

    mcp = build(Policy(approver=ElicitationApprover(message=broken_message)), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE), **connect) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)
    assert result.is_error and "the approver failed" in result.content[0].text
    assert ran == []
    assert outcomes(stream) == [("denied", "approver error: KeyError")]


# --- one call_id across the round trip; who was asked ---------------------------


@pytest.mark.parametrize("answer", [APPROVE, ("decline", None)], ids=["approved", "declined"])
async def test_the_pending_line_and_its_verdict_share_a_call_id(answer):
    """Two tools/call requests, one call: the line written when the
    question goes out, and the one written when the answer comes back,
    can be matched exactly, not by guessing from arguments and time."""
    stream, ran = io.StringIO(), []
    mcp = build(Policy(approver=ElicitationApprover()), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*answer)) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
        await client.call_tool("cancel_order", ARGUMENTS)  # a second call: its own id
    first, verdict, again, again_verdict = events(stream)
    assert first["outcome"] == "pending" and verdict["outcome"] in ("ok", "denied")
    assert first["call_id"] == verdict["call_id"]
    assert again["call_id"] == again_verdict["call_id"] != first["call_id"]
    assert {e["approver"] for e in events(stream)} == {"client"}


async def test_the_back_channel_names_the_client_and_a_fallback_its_own_name():
    stream, ran = io.StringIO(), []

    def front_desk(request):
        return True

    mcp = build(Policy(approver=ElicitationApprover(fallback=front_desk)), stream, ran)
    async with Client(mcp, elicitation_callback=answering(*APPROVE), mode="legacy") as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    async with Client(mcp) as client:  # no elicitation: the fallback decides
        await client.call_tool("cancel_order", ARGUMENTS)
    assert [(e["outcome"], e["approver"]) for e in events(stream)] == [("ok", "client"), ("ok", "front_desk")]


@pytest.mark.parametrize(
    "request_state",
    [None, "not json", json.dumps({"cid": "../../etc"}), json.dumps({"cid": 7}), json.dumps({"other": 1}),
     json.dumps({"cid": "0123456789abcdef"})],
    ids=["none", "garbage", "path-like", "not-a-string", "no-cid", "valid"],
)
def test_only_a_well_formed_call_id_is_resumed(request_state):
    from types import SimpleNamespace

    resumed = ElicitationApprover().resumed_call_id(SimpleNamespace(request_state=request_state))
    assert resumed == ("0123456789abcdef" if request_state and "0123456789abcdef" in request_state else None)
