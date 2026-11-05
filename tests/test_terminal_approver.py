"""terminal_approver: the prompt on the controlling terminal, never stdio.

Real pseudo-terminals throughout: a pty refuses to seek just as /dev/tty
does, and full-screen programs and session boundaries behave as they do
for a real MCP client."""

from __future__ import annotations

import io
import os
import select
import subprocess
import sys
import threading
import time

import pytest
from audit_helpers import events
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import (
    AccessTier,
    ApprovalRequest,
    AuditLog,
    Gatehouse,
    Policy,
    approvers,
    terminal_approver,
)

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


def within(seconds: float, fn, *args):
    """Run fn in a thread and fail, rather than hang the suite, if it
    doesn't return in time: a terminal read that never completes would
    otherwise stall CI until the job times out."""
    result: list = []
    worker = threading.Thread(target=lambda: result.append(fn(*args)), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"{fn.__name__} did not return within {seconds}s"
    return result[0]


@needs_pty
@pytest.mark.parametrize("timeout", [None, 5])
def test_terminal_prompt_takes_an_answer(operator, timeout):
    os.write(operator, b"y\n")
    deadline = None if timeout is None else time.monotonic() + timeout
    assert within(10, terminal_approver, request(deadline)) is True


@needs_pty
@pytest.mark.parametrize(
    ("typed", "allowed"),
    [
        (b"y\n", True), (b"Y\n", True), (b"yes\n", True), (b"YES\n", True), (b"  y  \n", True),
        (b"\n", False), (b"n\n", False), (b"no\n", False), (b"yep\n", False), (b"y please\n", False),
        (b"ok\n", False), (b"1\n", False),
    ],
)
def test_terminal_prompt_only_a_yes_approves(operator, typed, allowed):
    """[y/N]: the default is no, so Enter refuses, and so does anything
    that isn't plainly y or yes."""
    os.write(operator, typed)
    assert within(10, terminal_approver, request(time.monotonic() + 5)) is allowed


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
    # Guarded: prompting in raw mode blocks in readline for good.
    assert within(10, terminal_approver, request(time.monotonic() + 5)) is False
    assert time.monotonic() - start < 1
    assert screen(operator) == ""
    assert "full-screen program" in capsys.readouterr().err


@needs_pty
@pytest.mark.anyio
async def test_an_unanswered_terminal_prompt_is_logged_as_a_timeout(operator):
    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=terminal_approver, approval_timeout=0.3), audit=AuditLog(stream=log))

    @gk.destructive
    def cancel(order_id: str) -> str:
        return "cancelled"

    async with Client(mcp) as client:
        result = await client.call_tool("cancel", {"order_id": "1"})
    assert "approval needed" in screen(operator)
    assert result.is_error and "not approved within" in result.content[0].text
    assert [(e["outcome"], e["reason"]) for e in events(log)] == [("denied", "approval timed out")]


@needs_pty
def test_terminal_prompt_stops_waiting_for_a_busy_terminal(operator):
    """Another prompt holds the terminal past this one's deadline: deny
    without ever showing a prompt that can no longer be answered."""
    with approvers._tty_lock:
        assert terminal_approver(request(time.monotonic() + 0.1)) is False
    assert screen(operator) == ""


# A client on a real terminal starts the approver's server, the way the MCP
# Python SDK's stdio client does (start_new_session=True) or not. Run from a
# helper process so pytest itself never forks.
_SESSION_HARNESS = r'''
import os, pty, sys, time

SERVER = """
import time
from mcp_gatehouse import AccessTier, ApprovalRequest, terminal_approver
request = ApprovalRequest(tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={}, deadline=time.monotonic() + 0.5)
print("allowed:", terminal_approver(request), flush=True)
"""
CLIENT = "import subprocess, sys; subprocess.run([sys.executable, '-c', %r], start_new_session=%s, timeout=20)"

pid, fd = pty.fork()  # the child gets the pty as its controlling terminal
if pid == 0:
    os.execv(sys.executable, [sys.executable, "-c", CLIENT % (SERVER, sys.argv[1])])
shown, end = b"", time.monotonic() + 20
while time.monotonic() < end:
    try:
        chunk = os.read(fd, 4096)
    except OSError:  # EIO once the client and server have both exited
        break
    if not chunk:
        break
    shown += chunk
os.waitpid(pid, 0)
sys.stdout.write(shown.decode())
'''


@needs_pty
@pytest.mark.parametrize("own_session", [False, True])
def test_terminal_prompt_needs_the_clients_session(own_session):
    """Started in the client's session, the server prompts on the client's
    terminal. Started in a session of its own, it has no controlling
    terminal although its stderr is that terminal, so it denies, and says
    why: the README once promised a prompt here."""
    src = os.path.dirname(os.path.dirname(approvers.__file__))
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [src, os.environ.get("PYTHONPATH")]))}
    shown = subprocess.run(
        [sys.executable, "-c", _SESSION_HARNESS, str(own_session)],
        env=env, capture_output=True, text=True, timeout=60, check=True,
    ).stdout
    assert "allowed: False" in shown
    if own_session:
        assert "approval needed" not in shown
        assert "no controlling terminal" in shown
    else:
        assert "approval needed" in shown
        assert "timed out, denied" in shown
