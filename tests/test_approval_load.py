"""Approvals under load: their own thread pool, a deadline that fails
closed, and a call path that does no more work than it has to."""

from __future__ import annotations

import io
import json
import os
import select
import sys
import threading
import time

import anyio
import anyio.to_thread
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, ApprovalRequest, AuditLog, Gatehouse, Policy, terminal_approver
from mcp_gatehouse import approvers
from mcp_gatehouse import gatehouse as gatehouse_module


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


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


# --- terminal_approver keeps to the deadline ------------------------------

needs_pty = pytest.mark.skipif(sys.platform == "win32", reason="needs a pseudo-terminal")


@pytest.fixture
def pty_pair(monkeypatch):
    """A real pseudo-terminal standing in for /dev/tty. Yields
    ``(operator, terminal)``: the operator's end writes answers and reads
    prompts; the terminal end is what the approver opens.

    Only the path is swapped; the approver's own open() call runs for real.
    A pty refuses to seek just as /dev/tty does, which is what caught the
    approver opening its terminal in a mode that needs seeking."""
    operator_fd, terminal_fd = os.openpty()
    terminal_path = os.ttyname(terminal_fd)
    monkeypatch.setattr(
        approvers, "open", lambda _path, *args, **kwargs: open(terminal_path, *args, **kwargs), raising=False
    )
    yield operator_fd, terminal_fd
    os.close(operator_fd)
    os.close(terminal_fd)


@pytest.fixture
def operator(pty_pair):
    return pty_pair[0]


def screen(fd: int) -> str:
    shown = b""
    try:
        while select.select([fd], [], [], 0.1)[0]:
            shown += os.read(fd, 4096)
    except OSError:
        pass
    return shown.decode()


def request(deadline: float | None) -> ApprovalRequest:
    return ApprovalRequest(
        tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={"order_id": "4417"}, deadline=deadline
    )


@needs_pty
def test_terminal_prompt_withdraws_at_its_deadline(operator):
    start = time.monotonic()
    assert terminal_approver(request(time.monotonic() + 0.2)) is False
    assert time.monotonic() - start < 2
    shown = screen(operator)
    assert "approval needed" in shown
    assert "timed out, denied" in shown


@needs_pty
@pytest.mark.parametrize("timeout", [None, 5])
def test_terminal_prompt_takes_an_answer(operator, timeout):
    os.write(operator, b"y\n")
    deadline = None if timeout is None else time.monotonic() + timeout
    assert terminal_approver(request(deadline)) is True


@needs_pty
def test_terminal_prompt_stays_off_a_full_screen_programs_terminal(pty_pair, capsys):
    """An MCP client's terminal UI keeps the terminal in raw mode, and a
    server it launched can still open that terminal. Prompting there drew
    over the client's screen, then hung past the deadline: Enter arrives as
    \\r, so the answer never completed a line. Deny without touching it."""
    import tty  # Unix only

    operator, terminal = pty_pair
    tty.setraw(terminal)
    os.write(operator, b"y\r")
    start = time.monotonic()
    assert terminal_approver(request(time.monotonic() + 5)) is False
    assert time.monotonic() - start < 1
    assert screen(operator) == ""
    assert "full-screen program" in capsys.readouterr().err


@needs_pty
def test_terminal_prompt_stops_waiting_for_a_busy_terminal(operator):
    """Another prompt holds the terminal past this one's deadline: deny
    without ever showing a prompt that can no longer be answered."""
    with approvers._tty_lock:
        assert terminal_approver(request(time.monotonic() + 0.1)) is False
    assert screen(operator) == ""
