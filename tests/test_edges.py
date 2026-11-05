"""Branches no test reached, found by coverage and by mutation testing
(breaking one safety check at a time and seeing whether the suite noticed)."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult
from pydantic import BaseModel

from mcp_gatehouse import (
    DEFAULT_REDACT,
    AccessTier,
    ApprovalRequest,
    AuditLog,
    ElicitationApprover,
    Gatehouse,
    MemoryAuditLog,
    Policy,
    redact_arguments,
)
from mcp_gatehouse.approvers import _INPUT_KEY, _digest, _default_message

REQUEST = ApprovalRequest(tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={"order_id": "1"})


def build(policy: Policy, audit: MemoryAuditLog, ran: list[str]) -> MCPServer:
    mcp = MCPServer("edges")
    gatehouse = Gatehouse(mcp, policy=policy, audit=audit)

    @gatehouse.destructive
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return f"{order_id} cancelled"

    return mcp


# --- policy branches ---------------------------------------------------------


@pytest.mark.anyio
async def test_fail_closed_false_lets_an_unapproved_call_run_and_logs_it():
    """The one documented way to open the gate: it must do exactly that,
    and still leave the line in the trail."""
    audit, ran = MemoryAuditLog(), []
    async with Client(build(Policy(fail_closed=False), audit, ran)) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert not result.is_error and ran == ["1"]
    assert audit.outcomes() == [("ok", None)]


@pytest.mark.anyio
@pytest.mark.parametrize("verdict", [True, False])
async def test_sync_approver_returning_a_coroutine_is_awaited(verdict):
    """`lambda r: check(r)` where check is async: a sync callable that
    hands back an awaitable. Its answer is the awaited value, not the
    coroutine object (which is truthy, and would approve everything)."""

    async def check(request: ApprovalRequest) -> bool:
        return verdict

    audit, ran = MemoryAuditLog(), []
    async with Client(build(Policy(approver=lambda r: check(r)), audit, ran)) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert result.is_error is (not verdict)
    assert ran == (["1"] if verdict else [])


# --- ElicitationApprover with no live client --------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("fallback", [None, True, False], ids=["no-fallback", "fallback-yes", "fallback-no"])
async def test_direct_call_tool_has_no_client_to_ask(fallback):
    """MCPServer.call_tool() from server code (a test, a job) has no
    request behind it, so there's no client to ask: the fallback decides,
    and with none the call is denied."""
    approver = ElicitationApprover(fallback=None if fallback is None else (lambda r: fallback))
    audit, ran = MemoryAuditLog(), []
    mcp = build(Policy(approver=approver), audit, ran)
    if fallback:
        await mcp.call_tool("cancel", {"order_id": "1"})
        assert ran == ["1"]
    else:
        with pytest.raises(Exception, match="fails closed|refused"):
            await mcp.call_tool("cancel", {"order_id": "1"})
        assert ran == []
        assert audit.events[-1]["outcome"] == "denied"


# --- the round trip's answer checks, unit-level ------------------------------


def context(state: dict | str | None, reply: object = None) -> SimpleNamespace:
    raw = state if isinstance(state, str) or state is None else json.dumps(state)
    return SimpleNamespace(request_state=raw, input_responses=None if reply is None else {_INPUT_KEY: reply})


def state(**overrides: object) -> dict:
    base = {"v": 1, "q": _digest(_default_message(REQUEST)), "nonce": "n-1", "exp": time.time() + 60}
    return {**base, **overrides}


APPROVED = ElicitResult(action="accept", content={"approve": True})


@pytest.mark.parametrize(
    "ctx",
    [
        context(None, APPROVED),
        context("not json", APPROVED),
        context(state(v=2), APPROVED),
        context(state(nonce=5), APPROVED),
        context({"v": 1}, APPROVED),
        context(state(), None),
        context(state(q=_digest("some other question")), APPROVED),
    ],
    ids=["no-state", "garbage", "other-version", "bad-nonce", "missing-fields", "no-answer", "other-question"],
)
def test_anything_but_an_answer_to_this_question_is_asked_again(ctx):
    """None means 'ask (again)'; nothing here may approve."""
    assert ElicitationApprover().answer(REQUEST, ctx) is None


def test_an_answer_that_is_not_an_elicitation_result_is_an_error():
    assert ElicitationApprover().answer(REQUEST, context(state(), {"action": "accept"})) == (
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


# --- registration and redaction branches -------------------------------------


def test_annotations_of_the_wrong_type_are_refused():
    gatehouse = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError, match="ToolAnnotations or a mapping"):
        gatehouse.read(annotations=["readOnlyHint"])  # type: ignore[arg-type]


def test_a_model_whose_dump_fails_is_opaque():
    class Fragile(BaseModel):
        secret: str

        def model_dump(self, *args: object, **kwargs: object) -> dict:  # type: ignore[override]
            raise RuntimeError(f"cannot dump {self.secret}")

    safe = redact_arguments({"thing": Fragile(secret="sk-live")}, DEFAULT_REDACT)
    assert safe == {"thing": "«opaque:Fragile»"}


# --- the audit file ----------------------------------------------------------


def test_each_record_is_on_disk_before_the_next_call(tmp_path):
    """Flushed per record, while the log stays open: a crash after a call
    must not take that call's line with it."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path)
    try:
        log.record(tool="refund", outcome="ok")
        with open(path, encoding="utf-8") as reader:  # a second handle, as a tail -f would
            assert json.loads(reader.read())["tool"] == "refund"
    finally:
        log.close()
