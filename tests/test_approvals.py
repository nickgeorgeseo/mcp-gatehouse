"""Approvals: a deadline that fails closed, approvers that fail or answer
oddly, their own thread pool; and a call path that never blocks the event
loop and does each job once.

The terminal prompt has its own file, test_terminal_approver.py."""

from __future__ import annotations

import io
import logging
import threading
import time

import anyio
import anyio.to_thread
import pytest
from audit_helpers import events, outcomes
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import (
    AccessTier,
    ApprovalRequest,
    AuditLog,
    Gatehouse,
    Policy,
)
from mcp_gatehouse import gatehouse as gatehouse_module

# --- pending approvals can't starve the reads -----------------------------


@pytest.mark.anyio
async def test_pending_approvals_cannot_starve_sync_reads():
    """Park as many approvals as anyio has default worker threads, all
    waiting on a human. When approvers shared that pool, a sync read then
    had no thread to run on and hung until someone answered."""
    pool = anyio.to_thread.current_default_thread_limiter().total_tokens
    released = threading.Event()
    waiting = 0
    count_lock = threading.Lock()

    def slow_human(request) -> bool:
        nonlocal waiting
        with count_lock:
            waiting += 1
        return released.wait(timeout=10)

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=slow_human))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    @gk.tool(tier=AccessTier.READ)
    def lookup(order_id: str) -> str:
        return f"order {order_id}"

    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            for i in range(pool):
                tg.start_soon(client.call_tool, "cancel", {"order_id": str(i)})
            try:
                with anyio.fail_after(5):
                    while waiting < pool:
                        await anyio.sleep(0.01)
                with anyio.fail_after(2):
                    result = await client.call_tool("lookup", {"order_id": "4417"})
            finally:
                released.set()
    assert result.content[0].text == "order 4417"


# --- an approval that takes too long is a denial --------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [False, True])
async def test_approval_timeout_is_an_audited_denial(is_async):
    released = threading.Event()

    def slow_human(request) -> bool:
        return released.wait(timeout=10)

    async def aslow_human(request) -> bool:
        await anyio.sleep(10)
        return True

    log = io.StringIO()
    mcp = MCPServer("t")
    policy = Policy(approver=aslow_human if is_async else slow_human, approval_timeout=0.2)
    gk = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=log))
    ran = []

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    try:
        async with Client(mcp) as client:
            start = time.monotonic()
            result = await client.call_tool("cancel", {"order_id": "4417"})
            elapsed = time.monotonic() - start
    finally:
        released.set()

    assert elapsed < 2
    assert ran == []
    assert result.is_error is True
    assert "not approved within 0.2s" in result.content[0].text
    (event,) = events(log)
    assert event["outcome"] == "denied"
    assert event["reason"] == "approval timed out"


@pytest.mark.anyio
async def test_timed_out_approvals_give_back_their_thread():
    """More approvals than the approver pool has threads, every one ignored
    until it times out. The pool must be free again afterwards, or one
    absent human would lock out every later approval."""
    released = threading.Event()

    def approver(request) -> bool:
        if request.arguments["order_id"] == "quick":
            return True
        return released.wait(timeout=10)

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=approver, approval_timeout=0.2))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    results = []
    try:
        async with Client(mcp) as client:

            async def call(order_id):
                results.append(await client.call_tool("cancel", {"order_id": order_id}))

            async with anyio.create_task_group() as tg:
                for i in range(gatehouse_module._APPROVER_THREADS + 1):
                    tg.start_soon(call, str(i))
            with anyio.fail_after(2):
                quick = await client.call_tool("cancel", {"order_id": "quick"})
    finally:
        released.set()

    assert all(r.is_error for r in results)
    assert quick.is_error is False
    assert quick.content[0].text == "cancelled"


@pytest.mark.anyio
async def test_approver_answering_in_time_is_unaffected():
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=lambda request: True, approval_timeout=5))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "4417"})
    assert result.is_error is False
    assert result.content[0].text == "cancelled"


@pytest.mark.anyio
async def test_approver_raising_timeout_error_is_not_the_gates_deadline():
    """The approver's own TimeoutError (a Slack call timing out) is an
    approver failure, and must be recorded as one."""

    def flaky(request) -> bool:
        raise TimeoutError("slack took too long")

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=flaky, approval_timeout=5), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "4417"})
    assert result.is_error is True
    (event,) = events(log)
    assert event["reason"] == "approver error: TimeoutError"


@pytest.mark.anyio
@pytest.mark.parametrize("timeout", [None, 30])
async def test_approver_is_told_its_deadline(timeout):
    seen = []

    def approver(request) -> bool:
        seen.append((request, time.monotonic()))
        return True

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=approver, approval_timeout=timeout))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    async with Client(mcp) as client:
        await client.call_tool("cancel", {"order_id": "4417"})
    ((request, asked_at),) = seen
    if timeout is None:
        assert request.deadline is None
    else:
        assert timeout - 1 < request.deadline - asked_at <= timeout


@pytest.mark.parametrize("bad", [0, -1, float("nan")])
def test_approval_timeout_must_be_positive(bad):
    with pytest.raises(ValueError, match="approval_timeout"):
        Policy(approval_timeout=bad)


def test_approval_request_deadline_is_optional():
    request = ApprovalRequest(tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={})
    assert request.deadline is None


# --- the call path does each job once -------------------------------------


@pytest.mark.anyio
async def test_arguments_are_redacted_once_per_call(monkeypatch):
    calls = []
    real = gatehouse_module.redact_arguments

    def counting(arguments, keys):
        calls.append(arguments)
        return real(arguments, keys)

    monkeypatch.setattr(gatehouse_module, "redact_arguments", counting)
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=lambda request: True))

    @gk.tool(tier=AccessTier.READ)
    def lookup(order_id: str) -> str:
        return "ok"

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return "cancelled"

    async with Client(mcp) as client:
        await client.call_tool("lookup", {"order_id": "1"})
        assert len(calls) == 1
        await client.call_tool("cancel", {"order_id": "2"})
        assert len(calls) == 2


@pytest.mark.anyio
async def test_signature_is_not_recomputed_per_call(monkeypatch):
    gk = Gatehouse(MCPServer("t"))

    def lookup(order_id: str, verbose: bool = False) -> str:
        return f"order {order_id}"

    guarded = gk._guard(lookup, "lookup", AccessTier.READ)

    def no_signature(*args, **kwargs):
        raise AssertionError("inspect.signature called on the call path")

    monkeypatch.setattr(gatehouse_module.inspect, "signature", no_signature)
    assert await guarded(order_id="1") == "order 1"


@pytest.mark.anyio
async def test_approver_cannot_rewrite_the_audit_record():
    """The approver and the log share one redaction pass now, so the
    approver must get its own copy of the arguments."""

    def meddling(request) -> bool:
        request.arguments["order_id"] = "something-else"
        return True

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=meddling), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        return f"cancelled {order_id}"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "4417"})
    assert result.content[0].text == "cancelled 4417"
    (event,) = events(log)
    assert event["arguments"] == {"order_id": "4417"}


# --- whoever finishes first, a no at the deadline is a timeout ----------------


@pytest.mark.anyio
@pytest.mark.parametrize("run", range(5))
async def test_an_approver_that_gives_up_at_the_deadline_is_a_timeout(run):
    """An approver that honours request.deadline, as the README asks,
    returns False right as the gate's own timer fires. Whichever won the
    race decided the record: on an idle machine the approver did, and an
    unanswered prompt was logged, and reported, as a person refusing."""

    def patient(request: ApprovalRequest) -> bool:
        time.sleep(max(0.0, request.deadline - time.monotonic()))
        return False

    log, ran = io.StringIO(), []
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=patient, approval_timeout=0.3), audit=AuditLog(stream=log))

    @gk.destructive
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert result.is_error and "not approved within 0.3s" in result.content[0].text
    assert ran == []
    assert [(e["outcome"], e["reason"]) for e in events(log)] == [("denied", "approval timed out")]


# --- blocking work stays off the event loop --------------------------------


@pytest.mark.anyio
async def test_sync_tool_does_not_block_other_calls():
    """A sync tool waits for a signal only a *second* call can send. If the
    first call held the event loop, the second could never run."""
    released = threading.Event()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp)

    @gk.tool(tier=AccessTier.READ)
    def wait_for_release() -> str:
        return "released" if released.wait(timeout=3) else "loop was blocked"

    @gk.tool(tier=AccessTier.READ)
    def release() -> str:
        released.set()
        return "ok"

    results = {}
    async with Client(mcp) as client:

        async def call(name):
            results[name] = (await client.call_tool(name, {})).content[0].text

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "wait_for_release")
            await anyio.sleep(0.05)
            tg.start_soon(call, "release")
    assert results["wait_for_release"] == "released"


@pytest.mark.anyio
async def test_sync_approver_does_not_block_other_calls():
    """While a human mulls over a destructive call, reads keep flowing."""
    released = threading.Event()

    def slow_human(request) -> bool:
        return released.wait(timeout=3)

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=slow_human))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel() -> str:
        return "cancelled"

    @gk.tool(tier=AccessTier.READ)
    def release() -> str:
        released.set()
        return "ok"

    results = {}
    async with Client(mcp) as client:

        async def call(name):
            results[name] = await client.call_tool(name, {})

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "cancel")
            await anyio.sleep(0.05)
            tg.start_soon(call, "release")
    assert results["cancel"].is_error is False
    assert results["cancel"].content[0].text == "cancelled"


@pytest.mark.anyio
async def test_async_tools_and_partials_still_work():
    import functools

    mcp = MCPServer("t")
    gk = Gatehouse(mcp)

    @gk.tool(tier=AccessTier.READ)
    async def ping() -> str:
        await anyio.sleep(0)
        return "pong"

    async def greet(greeting: str, name: str) -> str:
        return f"{greeting}, {name}"

    hello = functools.partial(greet, "hello")
    hello.__name__ = "hello"
    gk.tool(tier=AccessTier.READ)(hello)

    async with Client(mcp) as client:
        assert (await client.call_tool("ping", {})).content[0].text == "pong"
        assert (await client.call_tool("hello", {"name": "nick"})).content[0].text == "hello, nick"


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [False, True])
async def test_approver_exception_is_an_audited_denial(is_async, caplog):
    def boom(request):
        raise ConnectionError("slack is down, token=xoxb-secret")

    async def aboom(request):
        boom(request)

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=aboom if is_async else boom), audit=AuditLog(stream=log))
    ran = []

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    with caplog.at_level(logging.DEBUG):
        async with Client(mcp) as client:
            result = await client.call_tool("cancel", {"order_id": "4417"})

    assert ran == []
    assert result.is_error is True
    assert "approver failed" in result.content[0].text
    (event,) = events(log)
    assert event["outcome"] == "denied"
    assert event["reason"] == "approver error: ConnectionError"
    assert "xoxb-secret" not in log.getvalue()
    # an anticipated refusal, not a server crash
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.anyio
@pytest.mark.parametrize("verdict", [True, False])
async def test_sync_approver_returning_a_coroutine_is_awaited(verdict):
    """`lambda r: check(r)` where check is async: a sync callable that
    hands back an awaitable. Its answer is the awaited value, not the
    coroutine object (which is truthy, and would approve everything)."""

    async def check(request: ApprovalRequest) -> bool:
        return verdict

    ran: list[str] = []
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=lambda r: check(r)))

    @gk.destructive
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert result.is_error is (not verdict)
    assert ran == (["1"] if verdict else [])


# --- only True approves --------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (True, None),
        (False, "approver refused"),
        ({"ok": False, "error": "channel_not_found"}, "approver error: returned dict, not True or False"),
        ("no", "approver error: returned str, not True or False"),
        (1, "approver error: returned int, not True or False"),
        (None, "approver error: returned NoneType, not True or False"),
    ],
    ids=["True", "False", "a-response-dict", "the-string-no", "one", "None"],
)
async def test_only_true_approves(answer, reason, is_async):
    """An approver that returned a Slack API response, a string or a 1
    approved the call: they're truthy. Only True approves, and anything
    else but False is the approver's bug, said plainly in the log."""

    def sync(request):
        return answer

    async def async_(request):
        return answer

    log, ran = io.StringIO(), []
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=async_ if is_async else sync), audit=AuditLog(stream=log))

    @gk.destructive
    def refund(order_id: str) -> str:
        ran.append(order_id)
        return "refunded"

    async with Client(mcp) as client:
        result = await client.call_tool("refund", {"order_id": "1"})
    assert ran == (["1"] if answer is True else [])
    assert result.is_error is (answer is not True)
    assert outcomes(log) == [("ok", None) if answer is True else ("denied", reason)]
