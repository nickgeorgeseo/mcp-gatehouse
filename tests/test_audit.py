"""The audit log: the JSONL file, other sinks, and what happens when a
sink can't record.

A sink that fails must not change a call's outcome: most records are
written after the tool ran, and an error then told the model a call that
had done its work had failed, inviting it to run it again."""

from __future__ import annotations

import functools
import io
import json
import logging

import pytest
from audit_helpers import CALL_ID
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult

from mcp_gatehouse import (
    AccessTier,
    ApprovalRequest,
    AuditLog,
    AuditSink,
    ElicitationApprover,
    Gatehouse,
    MemoryAuditLog,
    Policy,
)

pytestmark = pytest.mark.anyio


class BrokenSink:
    """A sink whose storage is gone: every record raises."""

    def __init__(self) -> None:
        self.attempts = 0

    def record(self, **event: object) -> None:
        self.attempts += 1
        raise OSError("No space left on device")


def build(audit: object, policy: Policy | None = None, ran: list | None = None) -> tuple[MCPServer, Gatehouse]:
    ran = ran if ran is not None else []
    mcp = MCPServer("sinks")
    gatehouse = Gatehouse(mcp, policy=policy, audit=audit)  # type: ignore[arg-type]

    @gatehouse.read
    def lookup(order_id: str) -> str:
        return f"order {order_id}"

    @gatehouse.destructive
    def refund(order_id: str, api_key: str = "") -> str:
        ran.append(order_id)
        return f"{order_id} refunded"

    @gatehouse.read
    def broken() -> str:
        raise RuntimeError("downstream exploded")

    return mcp, gatehouse


# --- MemoryAuditLog ----------------------------------------------------------


async def test_memory_log_holds_what_the_file_would(tmp_path):
    memory, path = MemoryAuditLog(), tmp_path / "audit.jsonl"
    with AuditLog(path=path) as file_log:
        for audit in (memory, file_log):
            mcp, _ = build(audit, Policy(approver=lambda request: False))
            async with Client(mcp) as client:
                await client.call_tool("lookup", {"order_id": "1"})
                await client.call_tool("refund", {"order_id": "1", "api_key": "sk-live-x"})
    from_file = [json.loads(line) for line in path.read_text().split("\n") if line]

    def strip(events: list[dict]) -> list[dict]:
        # ts, duration and call_id differ between the two runs by nature.
        return [{k: v for k, v in e.items() if k not in ("ts", "duration_ms", "call_id")} for e in events]

    assert strip(memory.events) == strip(from_file)
    assert all("ts" in e for e in memory.events)
    assert memory.outcomes() == [("ok", None), ("denied", "approver refused")]
    assert memory.events[1]["arguments"]["api_key"] == "«redacted»"
    memory.clear()
    assert memory.events == []


def test_sinks_are_recognised_by_shape():
    class Mine:
        def record(self, **event: object) -> None: ...

    assert isinstance(MemoryAuditLog(), AuditSink)
    assert isinstance(Mine(), AuditSink)
    assert not isinstance(object(), AuditSink)


async def test_any_object_with_record_is_a_sink():
    seen: list[dict] = []

    class ListSink:
        def record(self, **event: object) -> None:
            seen.append(event)

    mcp, _ = build(ListSink())
    async with Client(mcp) as client:
        await client.call_tool("lookup", {"order_id": "2"})
    assert [(e["tool"], e["outcome"]) for e in seen] == [("lookup", "ok")]


def test_something_without_record_is_refused():
    with pytest.raises(TypeError, match="record"):
        Gatehouse(MCPServer("t"), audit=io.StringIO())  # type: ignore[arg-type]


@pytest.mark.parametrize("as_str", [True, False], ids=["str", "Path"])
async def test_a_path_opens_an_audit_log(tmp_path, as_str):
    path = tmp_path / "logs" / "audit.jsonl"
    mcp, gatehouse = build(str(path) if as_str else path)
    assert isinstance(gatehouse.audit, AuditLog) and gatehouse.audit.path == path
    async with Client(mcp) as client:
        await client.call_tool("lookup", {"order_id": "3"})
    gatehouse.audit.close()
    assert json.loads(path.read_text())["tool"] == "lookup"


# --- a sink that fails -------------------------------------------------------


async def test_a_call_that_ran_is_not_reported_as_failed(caplog):
    sink, ran = BrokenSink(), []
    mcp, _ = build(sink, Policy(approver=lambda request: True), ran)
    with caplog.at_level(logging.ERROR, logger="mcp_gatehouse"):
        async with Client(mcp) as client:
            result = await client.call_tool("refund", {"order_id": "9"})
    assert not result.is_error and result.content[0].text == "9 refunded"
    assert ran == ["9"] and sink.attempts == 1
    (logged,) = [r for r in caplog.records if r.name == "mcp_gatehouse"]
    assert "'refund'" in logged.getMessage() and "'ok'" in logged.getMessage()
    assert logged.exc_info is not None


async def test_a_denial_keeps_its_reason():
    mcp, _ = build(BrokenSink())  # default policy, no approver
    async with Client(mcp) as client:
        result = await client.call_tool("refund", {"order_id": "9"})
    assert result.is_error and "fails closed" in result.content[0].text


async def test_a_tool_error_stays_the_tools_error():
    """Whatever the SDK makes of the tool's own exception, a failing sink
    doesn't replace it."""
    texts = []
    for sink in (MemoryAuditLog(), BrokenSink()):
        mcp, _ = build(sink)
        async with Client(mcp) as client:
            result = await client.call_tool("broken", {})
        assert result.is_error
        texts.append(result.content[0].text)
    assert texts[0] == texts[1]


async def test_approval_in_the_client_still_completes():
    """The round trip writes a `pending` line before asking; losing it
    must not lose the question."""
    sink, ran = BrokenSink(), []

    async def approve(context, params):
        return ElicitResult(action="accept", content={"approve": True})

    mcp, _ = build(sink, Policy(approver=ElicitationApprover()), ran)
    async with Client(mcp, elicitation_callback=approve) as client:
        result = await client.call_tool("refund", {"order_id": "5"})
    assert not result.is_error and ran == ["5"]
    assert sink.attempts == 2  # pending, then ok


# --- policy and audit are read per call --------------------------------------


async def test_a_new_policy_applies_to_tools_already_registered():
    audit = MemoryAuditLog()
    mcp, gatehouse = build(audit)
    async with Client(mcp) as client:
        assert not (await client.call_tool("lookup", {"order_id": "1"})).is_error
        gatehouse.policy = Policy(deny={"lookup"})
        blocked = await client.call_tool("lookup", {"order_id": "1"})
        gatehouse.policy = Policy()
        assert not (await client.call_tool("lookup", {"order_id": "1"})).is_error
    assert blocked.is_error and "blocked by policy" in blocked.content[0].text
    assert audit.outcomes() == [("ok", None), ("denied", "denylist"), ("ok", None)]


async def test_a_new_audit_sink_gets_the_next_records():
    first, second = MemoryAuditLog(), MemoryAuditLog()
    mcp, gatehouse = build(first)
    async with Client(mcp) as client:
        await client.call_tool("lookup", {"order_id": "1"})
        gatehouse.audit = second
        await client.call_tool("lookup", {"order_id": "2"})
    assert [e["arguments"]["order_id"] for e in first.events] == ["1"]
    assert [e["arguments"]["order_id"] for e in second.events] == ["2"]


def test_policy_applies_to_both_tiers_and_is_typed():
    gatehouse = Gatehouse(MCPServer("t"))
    assert isinstance(gatehouse.policy, Policy)
    assert gatehouse.policy.needs_approval(AccessTier.DESTRUCTIVE)


# --- the JSONL file -----------------------------------------------------------


def test_audit_log_exposes_its_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with AuditLog(path="sub/audit.jsonl") as log:
        assert log.path == tmp_path / "sub" / "audit.jsonl"
    assert AuditLog(stream=io.StringIO()).path is None


def test_audit_log_writes_jsonl_with_timestamp(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    with AuditLog(path=path) as log:
        log.record(tool="x", outcome="ok")
        log.record(tool="y", outcome="denied")
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "x"
    assert first["ts"].endswith("+00:00")


def test_audit_log_requires_exactly_one_sink():
    import pytest

    with pytest.raises(ValueError):
        AuditLog()
    with pytest.raises(ValueError):
        AuditLog(path="x.jsonl", stream=io.StringIO())


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


# --- call_id and approver: tying lines together --------------------------------


async def test_every_line_has_a_call_id_and_each_call_its_own():
    audit = MemoryAuditLog()
    mcp, _ = build(audit, Policy(approver=lambda request: True))
    async with Client(mcp) as client:
        for order_id in ("1", "2", "3"):
            await client.call_tool("lookup", {"order_id": order_id})
    ids = [e["call_id"] for e in audit.events]
    assert len(set(ids)) == 3 and all(CALL_ID.fullmatch(i) for i in ids)
    assert list(audit.events[0])[:3] == ["ts", "call_id", "tool"]  # read first when scanning a line


async def test_the_approver_gets_the_call_id_its_line_will_carry():
    """So a Slack message or a ticket can name the call, and be matched to
    the audit line later."""
    seen, audit = [], MemoryAuditLog()

    def approver(request):
        seen.append(request.call_id)
        return True

    mcp, _ = build(audit, Policy(approver=approver))
    async with Client(mcp) as client:
        await client.call_tool("refund", {"order_id": "9"})
    assert seen == [audit.events[-1]["call_id"]]


class SlackApprovals:
    def ask(self, request: ApprovalRequest) -> bool:
        return True

    def __call__(self, request: ApprovalRequest) -> bool:
        return True


def approve_with_reason(request: ApprovalRequest, reason: str) -> bool:
    return True


def outer():
    def nested_approver(request: ApprovalRequest) -> bool:
        return True

    return nested_approver


@pytest.mark.parametrize(
    ("approver", "name"),
    [
        (functools.partial(approve_with_reason, reason="x"), "approve_with_reason"),
        (SlackApprovals().ask, "SlackApprovals.ask"),
        (SlackApprovals(), "SlackApprovals"),
        (outer(), "nested_approver"),
        (lambda request: True, "<lambda>"),
    ],
    ids=["partial", "method", "callable-object", "nested-function", "lambda"],
)
async def test_lines_name_the_approver_that_was_asked(approver, name):
    audit = MemoryAuditLog()
    mcp, _ = build(audit, Policy(approver=approver))
    async with Client(mcp) as client:
        await client.call_tool("refund", {"order_id": "9"})
    (line,) = audit.events
    assert (line["outcome"], line["approver"]) == ("ok", name)


async def test_a_refusal_names_the_approver_too():
    audit = MemoryAuditLog()

    def finance_team(request: ApprovalRequest) -> bool:
        return False

    mcp, _ = build(audit, Policy(approver=finance_team))
    async with Client(mcp) as client:
        await client.call_tool("refund", {"order_id": "9"})
    assert [(e["outcome"], e["approver"]) for e in audit.events] == [("denied", "finance_team")]


async def test_no_approver_field_when_nobody_was_asked():
    audit = MemoryAuditLog()
    mcp, _ = build(audit, Policy(deny={"broken"}))  # no approver configured
    async with Client(mcp) as client:
        await client.call_tool("lookup", {"order_id": "1"})  # needs no approval
        await client.call_tool("refund", {"order_id": "1"})  # nobody to ask
        await client.call_tool("broken", {})  # denylisted
    assert [e["outcome"] for e in audit.events] == ["ok", "denied", "denied"]
    assert all("approver" not in e for e in audit.events)
