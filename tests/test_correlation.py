"""Correlation and timing in the audit trail.

Every line carries the call's ``call_id``; lines written inside a live
request carry its JSON-RPC ``request_id`` and, when there is one, the
OpenTelemetry trace; the round that answers a round-trip approval points
back to the round that asked (``continues``); and ``timings_ms`` says
where the time went, stage by stage.
"""

from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult
from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from mcp_gatehouse import (
    AccessTier,
    ApprovalRequest,
    AuditLog,
    Conflict,
    ElicitationApprover,
    Gatehouse,
    Policy,
    Transaction,
    any_caller,
)
from mcp_gatehouse.approvers import asking_call

from _support import OpenGatehouse

pytestmark = pytest.mark.anyio

ARGUMENTS = {"order_id": "4417"}


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


async def approve(context, params) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True})


def gated(policy: Policy | None = None, **tool_kwargs):
    stream = io.StringIO()
    mcp = MCPServer("correlation-test")
    gk = OpenGatehouse(mcp, policy=policy, audit=AuditLog(stream=stream))

    @gk.tool(tier=AccessTier.DESTRUCTIVE if policy else AccessTier.READ, **tool_kwargs)
    def cancel_order(order_id: str) -> str:
        return f"{order_id} cancelled"

    return mcp, stream


# --- call_id ---------------------------------------------------------------


async def test_each_call_has_its_own_id_on_every_line():
    mcp, stream = gated()
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
        await client.call_tool("cancel_order", ARGUMENTS)
    first, second = events(stream)
    assert len(first["call_id"]) == 32 and len(second["call_id"]) == 32
    assert first["call_id"] != second["call_id"]


async def test_the_approver_sees_the_call_id_the_trail_carries():
    seen: list[ApprovalRequest] = []

    def approver(request: ApprovalRequest) -> bool:
        seen.append(request)
        return True

    mcp, stream = gated(Policy(approver=approver))
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    (request,) = seen
    assert request.call_id == line["call_id"]


async def test_denials_before_the_gate_have_an_id_too():
    """A request with no verified caller is refused in call_tool, before the
    tool's own gate: it has an id and the request's, but no timings."""
    stream = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, audit=AuditLog(stream=stream))  # no local caller

    @gk.tool(authorize=any_caller)
    def read_order(order_id: str) -> str:
        return order_id

    async with Client(mcp) as client:
        result = await client.call_tool("read_order", ARGUMENTS)
    assert result.is_error
    (line,) = events(stream)
    assert line["reason"] == "no verified caller"
    assert len(line["call_id"]) == 32
    assert "request_id" in line
    assert "timings_ms" not in line


# --- request and trace -----------------------------------------------------


async def test_the_request_id_is_the_json_rpc_id():
    mcp, stream = gated()
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
        await client.call_tool("cancel_order", ARGUMENTS)
    ids = [line["request_id"] for line in events(stream)]
    assert all(isinstance(i, str) and i for i in ids)
    assert ids[0] != ids[1]


async def test_no_trace_means_no_trace_fields():
    mcp, stream = gated()
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    assert "trace_id" not in line and "span_id" not in line


async def test_the_clients_trace_reaches_the_line():
    """The client's span travels as traceparent in _meta; the SDK parents
    its server span on it, and the line names that trace."""
    client_span = SpanContext(
        trace_id=0x0AF7651916CD43DD8448EB211C80319C,
        span_id=0xB7AD6B7169203331,
        is_remote=False,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    mcp, stream = gated()
    async with Client(mcp) as client:
        with trace.use_span(NonRecordingSpan(client_span)):
            await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    assert line["trace_id"] == "0af7651916cd43dd8448eb211c80319c"
    assert len(line["span_id"]) == 16


# --- round-trip approvals --------------------------------------------------


async def test_the_answering_round_points_back_to_the_asking_round():
    mcp, stream = gated(Policy(approver=ElicitationApprover()))
    async with Client(mcp, elicitation_callback=approve) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    pending, done = events(stream)
    assert pending["outcome"] == "pending" and "continues" not in pending
    assert done["outcome"] == "ok"
    assert done["continues"] == pending["call_id"]
    assert done["call_id"] != pending["call_id"]  # each round is its own call


@pytest.mark.parametrize(
    "state",
    [None, "", "not json", "[]", '{"call": 7}', '{"call": "../../etc"}', '{"call": "' + "A" * 32 + '"}'],
)
def test_asking_call_ignores_anything_but_a_call_id(state):
    assert asking_call(SimpleNamespace(request_state=state)) is None


def test_asking_call_reads_a_call_id():
    call = "0123456789abcdef0123456789abcdef"
    assert asking_call(SimpleNamespace(request_state=json.dumps({"call": call}))) == call


# --- timings ---------------------------------------------------------------


async def test_timings_split_the_call_into_its_stages():
    mcp, stream = gated(Policy(approver=lambda request: True))
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    timings = line["timings_ms"]
    assert list(timings) == ["authorize", "approval", "tool", "total"]
    assert timings["tool"] == line["duration_ms"]
    parts = sum(v for k, v in timings.items() if k != "total")
    assert timings["total"] >= parts - 0.05  # rounding


async def test_a_transaction_reports_its_commit():
    @contextlib.contextmanager
    def transaction(caller):
        yield None

    mcp, stream = gated(consistency=Transaction(transaction))
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    assert "commit" in line["timings_ms"]


async def test_without_a_transaction_there_is_no_commit():
    mcp, stream = gated()
    async with Client(mcp) as client:
        await client.call_tool("cancel_order", ARGUMENTS)
    (line,) = events(stream)
    assert list(line["timings_ms"]) == ["authorize", "tool", "total"]


class _TickingClock:
    """``time`` for the gate, with a ``perf_counter`` that moves 1 ms on
    every read, so two reads of it never agree."""

    def __init__(self) -> None:
        import time as real

        self._real, self._now = real, real.perf_counter()

    def perf_counter(self) -> float:
        # Never behind the real clock: the call's start is read from it.
        self._now = max(self._now, self._real.perf_counter()) + 0.001
        return self._now

    def __getattr__(self, name: str):
        return getattr(self._real, name)


@pytest.fixture
def ticking_clock(monkeypatch):
    import mcp_gatehouse.gatehouse as gatehouse_module

    monkeypatch.setattr(gatehouse_module, "time", _TickingClock())


def _failing(raise_: type[Exception]):
    stream = io.StringIO()
    mcp = MCPServer("correlation-test")
    gk = OpenGatehouse(mcp, audit=AuditLog(stream=stream))

    @gk.tool(tier=AccessTier.READ)
    def cancel_order(order_id: str) -> str:
        raise raise_()

    return mcp, stream


@pytest.mark.parametrize("raise_, outcome", [(ValueError, "error"), (Conflict, "conflict")])
async def test_duration_is_the_tools_timing_on_every_outcome(ticking_clock, raise_, outcome):
    # duration_ms and timings_ms.tool are one clock read, not two: on an
    # error or a conflict they used to differ by the time between reads.
    mcp, stream = _failing(raise_)
    async with Client(mcp) as client:
        result = await client.call_tool("cancel_order", ARGUMENTS)
    assert result.is_error
    (line,) = events(stream)
    assert line["outcome"] == outcome
    assert line["duration_ms"] == line["timings_ms"]["tool"]


async def test_duration_is_the_tools_timing_when_cancelled(ticking_clock):
    started = anyio.Event()
    stream = io.StringIO()
    mcp = MCPServer("correlation-test")
    gk = OpenGatehouse(mcp, audit=AuditLog(stream=stream))

    @gk.tool(tier=AccessTier.READ)
    async def cancel_order(order_id: str) -> str:
        started.set()
        await anyio.sleep_forever()

    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "cancel_order", ARGUMENTS)
            with anyio.fail_after(5):
                await started.wait()
            tg.cancel_scope.cancel()
    (line,) = events(stream)
    assert (line["outcome"], line["reason"]) == ("cancelled", "tool running")
    assert line["duration_ms"] == line["timings_ms"]["tool"]
