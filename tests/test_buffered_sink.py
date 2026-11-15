"""BufferedSink: audit writes off the request path, a bounded queue that
never blocks a call, and a close that drains."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time

import anyio
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, AuditLog, BufferedSink, CallableSink

from conftest import AUDIT_LINE
from _support import OpenGatehouse as Gatehouse


class Blocking:
    """A sink whose write waits until released, recording what it got."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.released = threading.Event()
        self.records: list[dict] = []
        self.closed = False

    def write(self, record: dict) -> None:
        self.entered.set()
        self.released.wait(timeout=10)
        self.records.append(record)

    def close(self) -> None:
        self.closed = True


def line(tool: str) -> dict:
    return {"call_id": "0" * 32, "tool": tool, "tier": "read", "outcome": "ok", "arguments": {}}


def stderr_lines(capsys) -> list[dict]:
    return [json.loads(raw) for raw in capsys.readouterr().err.splitlines()]


@pytest.mark.anyio
async def test_a_sink_that_blocks_does_not_slow_the_call():
    inner = Blocking()
    log = AuditLog(sink=BufferedSink(inner))
    mcp = MCPServer("buffered")
    gatehouse = Gatehouse(mcp, audit=log)

    @gatehouse.tool(tier=AccessTier.READ)
    def ping() -> str:
        return "pong"

    try:
        async with Client(mcp) as client:
            began = time.monotonic()
            with anyio.fail_after(2):
                first = await client.call_tool("ping", {})
                second = await client.call_tool("ping", {})
            took = time.monotonic() - began
        assert not first.is_error and not second.is_error
        assert took < 1.0  # the sink is still blocked in its first write
        # The drain thread picks the first line up on its own schedule; on a
        # busy runner that can be just after the calls return.
        assert inner.entered.wait(timeout=2) and inner.records == []
    finally:
        inner.released.set()
        log.close()
    assert [r["tool"] for r in inner.records] == ["ping", "ping"]
    assert inner.closed


def test_a_full_queue_sends_the_line_to_stderr_and_never_blocks(capsys):
    inner = Blocking()
    sink = BufferedSink(inner, maxsize=1)
    try:
        sink.write(line("taken"))  # the thread takes it and blocks in inner.write
        assert inner.entered.wait(timeout=5)
        sink.write(line("queued"))  # fills the one slot
        began = time.monotonic()
        sink.write(line("overflow"))  # no room: stderr, at once
        assert time.monotonic() - began < 0.5
    finally:
        inner.released.set()
        sink.close()

    (spilled,) = stderr_lines(capsys)
    assert spilled["tool"] == "overflow" and spilled["sink_error"] == "queue full"
    assert AUDIT_LINE.is_valid({"ts": "2026-01-01T00:00:00+00:00", **spilled})
    assert [r["tool"] for r in inner.records] == ["taken", "queued"]


def test_close_drains_everything_written_before_it():
    got: list[str] = []

    def slow(record: dict) -> None:
        time.sleep(0.002)
        got.append(record["tool"])

    sink = BufferedSink(CallableSink(slow), maxsize=500)
    for i in range(200):
        sink.write(line(f"t{i}"))
    sink.close()
    assert got == [f"t{i}" for i in range(200)]  # all of them, in order


def test_close_waits_out_a_full_queue_rather_than_dropping_it(capsys):
    inner = Blocking()
    sink = BufferedSink(inner, maxsize=2)
    sink.write(line("a"))
    assert inner.entered.wait(timeout=5)
    sink.write(line("b"))
    sink.write(line("c"))  # the queue is full now
    threading.Timer(0.2, inner.released.set).start()
    sink.close()
    assert [r["tool"] for r in inner.records] == ["a", "b", "c"]
    assert capsys.readouterr().err == ""


def test_an_inner_sink_that_raises_goes_to_stderr_from_the_thread(capsys):
    def down(record: dict) -> None:
        raise ConnectionError("collector down: secret-value-here")

    sink = BufferedSink(CallableSink(down))
    sink.write(line("x"))
    sink.close()
    err = capsys.readouterr().err
    (spilled,) = [json.loads(raw) for raw in err.splitlines()]
    assert spilled["tool"] == "x" and spilled["sink_error"] == "ConnectionError"
    assert "secret-value-here" not in err


def test_a_write_after_close_goes_to_stderr(capsys):
    got: list[dict] = []
    sink = BufferedSink(CallableSink(got.append))
    sink.close()
    sink.close()  # twice is fine
    sink.write(line("late"))
    (spilled,) = stderr_lines(capsys)
    assert spilled["tool"] == "late" and spilled["sink_error"] == "sink closed"
    assert got == []


def test_concurrent_writers_lose_nothing():
    got: list[str] = []
    sink = BufferedSink(CallableSink(lambda r: got.append(r["tool"])), maxsize=10_000)

    def writer(n: int) -> None:
        for i in range(500):
            sink.write(line(f"{n}-{i}"))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sink.close()
    assert sorted(got) == sorted(f"{n}-{i}" for n in range(8) for i in range(500))


@pytest.mark.parametrize("maxsize", [0, -1, 1.5, True, None])
def test_maxsize_must_be_a_positive_int(maxsize):
    with pytest.raises(ValueError, match="maxsize"):
        BufferedSink(CallableSink(print), maxsize=maxsize)


def test_inner_must_be_a_sink():
    with pytest.raises(TypeError, match="write"):
        BufferedSink(print)


def test_an_unclosed_buffer_is_drained_at_exit(tmp_path):
    """The thread is a daemon, so without the exit hook a process that
    forgets close() would lose the queue's tail."""
    out = tmp_path / "audit.jsonl"
    script = (
        "import sys, time\n"
        "from mcp_gatehouse import AuditLog, BufferedSink, JsonlSink, CallableSink\n"
        "inner = JsonlSink(path=sys.argv[1])\n"
        "def slow(r):\n"
        "    time.sleep(0.005); inner.write(r)\n"
        "log = AuditLog(sink=BufferedSink(CallableSink(slow)))\n"
        "for i in range(50):\n"
        "    log.record(call_id='0' * 32, tool=f't{i}', tier='read', outcome='ok', arguments={})\n"
    )
    done = subprocess.run([sys.executable, "-c", script, str(out)], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert [json.loads(raw)["tool"] for raw in out.read_text().splitlines()] == [f"t{i}" for i in range(50)]


def test_an_inner_sink_that_raises_a_base_exception_loses_nothing(capsys):
    """A CancelledError from a sink posting through a loop that is shutting
    down: that record goes to stderr, and the thread goes on with the rest."""
    import asyncio

    got: list[dict] = []

    def inner(record):
        if record["n"] == 0:
            raise asyncio.CancelledError()
        got.append(record)

    sink = BufferedSink(CallableSink(inner), maxsize=10)
    for n in range(4):
        sink.write({"n": n})
    sink.close()
    assert got == [{"n": 1}, {"n": 2}, {"n": 3}]
    (line,) = capsys.readouterr().err.splitlines()
    assert json.loads(line) == {"n": 0, "sink_error": "CancelledError"}


def test_close_does_not_hang_when_the_thread_is_gone():
    """With the drain thread gone and the queue full, nothing would ever make
    room for close()'s stop marker: it must not wait for one."""
    from mcp_gatehouse.audit import _STOP

    sink = BufferedSink(CallableSink(lambda record: None), maxsize=1)
    sink._queue.put(_STOP)  # end the thread the way close() would
    sink._thread.join(timeout=5)
    assert not sink._thread.is_alive()
    sink._queue.put_nowait({"n": 1})  # full, and no thread to empty it
    finished = threading.Event()
    threading.Thread(target=lambda: (sink.close(), finished.set()), daemon=True).start()
    assert finished.wait(5), "close() blocked on a queue nobody drains"


# --- SIGTERM ------------------------------------------------------------------

_KILLED = r"""
import json, os, signal, sys, threading, time
from mcp_gatehouse import BufferedSink, CallableSink

path = sys.argv[1]
mode = sys.argv[2]
if mode == "own-handler":
    signal.signal(signal.SIGTERM, lambda *a: (print("own handler", flush=True), os._exit(3)))

def slow(record):
    time.sleep(0.2)
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")

if mode == "off-main-thread":
    made = []
    t = threading.Thread(target=lambda: made.append(BufferedSink(CallableSink(slow))))
    t.start(); t.join()
    sink = made[0]
else:
    sink = BufferedSink(CallableSink(slow))
print(signal.getsignal(signal.SIGTERM) is signal.SIG_DFL, flush=True)
for n in range(10):
    sink.write({"n": n})
print("ready", flush=True)
time.sleep(30)
"""


def _kill_with_records_queued(tmp_path, mode: str = "plain"):
    path = tmp_path / "inner.jsonl"
    proc = subprocess.Popen(
        [sys.executable, "-c", _KILLED, str(path), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    default_after = proc.stdout.readline().strip()
    assert proc.stdout.readline().strip() == "ready"
    time.sleep(0.3)  # one record written, one being written, the rest queued
    proc.send_signal(__import__("signal").SIGTERM)
    out, err = proc.communicate(timeout=10)
    written = [json.loads(line)["n"] for line in path.read_text().splitlines()] if path.exists() else []
    spilled = [json.loads(line) for line in err.splitlines() if line.startswith("{")]
    return proc.returncode, default_after, out, written, spilled


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_spills_the_queue_to_stderr_rather_than_losing_it(tmp_path):
    """Python's default SIGTERM skips atexit, so a buffer nobody closed lost
    its queue without a word. Now every record not yet written goes to
    stderr marked ``sink_error: "terminated"``, and the process still dies
    of SIGTERM."""
    code, _, _, written, spilled = _kill_with_records_queued(tmp_path)
    assert code == -15
    assert {r["sink_error"] for r in spilled} == {"terminated"}
    on_stderr = [r["n"] for r in spilled]
    # The record being written when the signal came may land in both.
    assert set(written) | set(on_stderr) == set(range(10))
    assert len(set(written) & set(on_stderr)) <= 1
    assert len(written) < 10  # the test did kill it mid-drain


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_sigterm_handler_of_your_own_is_left_alone(tmp_path):
    code, default_after, out, _, spilled = _kill_with_records_queued(tmp_path, "own-handler")
    assert code == 3 and "own handler" in out
    assert spilled == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_buffer_made_off_the_main_thread_installs_nothing(tmp_path):
    # signal.signal only works on the main thread; the buffer still works.
    code, default_after, _, _, _ = _kill_with_records_queued(tmp_path, "off-main-thread")
    assert default_after == "True"
    assert code == -15


def test_a_buffer_on_the_main_thread_installs_the_handler():
    import signal

    before = signal.signal(signal.SIGTERM, signal.SIG_DFL)  # as a fresh process has it
    try:
        sink = BufferedSink(CallableSink(lambda record: None))
        sink.close()
        assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    finally:
        signal.signal(signal.SIGTERM, before)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_while_close_drains_spills_the_rest(tmp_path):
    """The MCP Python SDK's stdio client closes stdin, waits 2 s, then sends
    SIGTERM: the exit hook may still be draining. What it hadn't written
    goes to stderr, not nowhere."""
    path = tmp_path / "inner.jsonl"
    script = (
        "import json, sys, time\n"
        "from mcp_gatehouse import BufferedSink, CallableSink\n"
        "def slow(r):\n"
        "    time.sleep(0.2)\n"
        "    open(sys.argv[1], 'a').write(json.dumps(r) + '\\n')\n"
        "sink = BufferedSink(CallableSink(slow))\n"
        "for n in range(10):\n"
        "    sink.write({'n': n})\n"
        "print('closing', flush=True)\n"
        "sink.close()\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", script, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    assert proc.stdout.readline().strip() == "closing"
    time.sleep(0.5)
    proc.send_signal(__import__("signal").SIGTERM)
    _, err = proc.communicate(timeout=10)
    assert proc.returncode == -15
    written = [json.loads(line)["n"] for line in path.read_text().splitlines()]
    spilled = [json.loads(line)["n"] for line in err.splitlines() if line.startswith("{")]
    assert set(written) | set(spilled) == set(range(10))
    assert len(written) < 10


def test_a_record_the_thread_takes_during_the_spill_is_spilled_not_lost(monkeypatch):
    """The drain thread keeps running while SIGTERM spills. If the record it
    was writing finishes meanwhile, the thread must not start writing the
    next one: the process ends straight after the spill, mid-write, and
    that record would be in neither place. Everything not fully written to
    ``inner`` when the spill returns must be on stderr.

    Forced with events: record 0's write ends only once the spill has
    begun, and the spill's first line (stderr blocking) takes until the
    thread has gone on to record 1, or half a second."""
    from mcp_gatehouse import audit as audit_module

    done: list[int] = []
    spilled: list[int] = []
    spill_began, took_next, end = threading.Event(), threading.Event(), threading.Event()

    def inner(record):
        if record["n"] == 0:
            spill_began.wait(5)
        else:
            took_next.set()
            end.wait(5)  # still writing when the process would end
        done.append(record["n"])

    def slow_spill(record):
        spilled.append(record["n"])
        spill_began.set()
        if record["n"] == 0:
            took_next.wait(0.5)

    monkeypatch.setattr(audit_module, "_spill_line", slow_spill)
    sink = BufferedSink(CallableSink(inner))
    try:
        for n in range(6):
            sink.write({"n": n})
        deadline = time.monotonic() + 5
        while sink._writing is None and time.monotonic() < deadline:
            time.sleep(0.005)  # record 0 is being written
        sink._spill()  # what the SIGTERM handler does
        written = list(done)  # the process ends here
        missing = set(range(6)) - set(written) - set(spilled)
        assert not missing, f"in neither inner nor stderr: {sorted(missing)}"
        assert len(spilled) == len(set(spilled))  # each spilled once
    finally:
        end.set()
        audit_module._OPEN_BUFFERS.discard(sink)
