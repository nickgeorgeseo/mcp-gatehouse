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
    return {"tool": tool, "tier": "read", "outcome": "ok", "arguments": {}}


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
        assert inner.entered.is_set() and inner.records == []
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
        "    log.record(tool=f't{i}', tier='read', outcome='ok', arguments={})\n"
    )
    done = subprocess.run([sys.executable, "-c", script, str(out)], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert [json.loads(raw)["tool"] for raw in out.read_text().splitlines()] == [f"t{i}" for i in range(50)]
