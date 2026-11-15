"""The audit log's sinks, and the schema its lines are documented by."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from typing import Annotated

import jsonschema
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import (
    AcceptRace, AccessTier, AuditLog, AuditSink, CallableSink, JsonlSink, Load, Policy, any_item,
)

from conftest import AUDIT_LINE, SCHEMA_PATH
from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio


# --- sinks -------------------------------------------------------------------


_DISK_FILLS = r"""
import json, resource, signal, sys
from mcp_gatehouse import JsonlSink

path = sys.argv[1]
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)  # a write past the limit fails with EFBIG instead
sink = JsonlSink(path=path)
failed = []

def record(n):
    try:
        sink.write({"n": n, "padding": "x" * 300})
    except OSError:
        failed.append(n)

resource.setrlimit(resource.RLIMIT_FSIZE, (1000, resource.RLIM_INFINITY))  # the disk fills
for n in range(5):
    record(n)
resource.setrlimit(resource.RLIMIT_FSIZE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))  # space returns
for n in range(5, 8):
    record(n)
sink.close()
print(json.dumps(failed))
"""


@pytest.mark.skipif(sys.platform == "win32", reason="needs RLIMIT_FSIZE")
def test_a_full_disk_leaves_only_whole_lines(tmp_path):
    """While the disk is full a record's write fails part way. The file keeps
    whole lines only (no torn record), and a record that failed, and so went
    to stderr, never turns up in the file later as well."""
    path = tmp_path / "audit.jsonl"
    run = subprocess.run([sys.executable, "-c", _DISK_FILLS, str(path)], capture_output=True, text=True, check=True)
    failed = json.loads(run.stdout)
    assert failed, "the disk never filled"
    raw = path.read_text()
    assert raw.endswith("\n")
    written = [json.loads(line)["n"] for line in raw.splitlines()]  # every line parses
    assert not set(written) & set(failed)
    assert sorted(written + failed) == list(range(8))


def test_writes_after_close_raise_rather_than_reach_another_file(tmp_path):
    sink = JsonlSink(path=tmp_path / "audit.jsonl")
    sink.write({"n": 1})
    sink.close()
    with pytest.raises(ValueError):
        sink.write({"n": 2})
    sink.close()  # twice is fine
    assert [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()] == [{"n": 1}]


def test_exactly_one_destination():
    with pytest.raises(ValueError):
        AuditLog()
    with pytest.raises(ValueError):
        AuditLog(path="x.jsonl", stream=io.StringIO())
    with pytest.raises(ValueError):
        AuditLog(stream=io.StringIO(), sink=CallableSink(print))
    with pytest.raises(TypeError, match="write"):
        AuditLog(sink=lambda record: None)  # a bare function isn't a sink


def test_jsonl_file_is_the_default_sink(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    with AuditLog(path=path) as log:
        assert isinstance(log.sink, JsonlSink)
        assert log.path == path.absolute()
        log.record(call_id="0123456789abcdef0123456789abcdef", tool="x", tier="read", outcome="ok", arguments={})
    (line,) = path.read_text().splitlines()
    assert json.loads(line)["tool"] == "x"


def test_callable_sink_gets_the_record_as_a_dict():
    seen: list[dict] = []
    log = AuditLog(sink=CallableSink(seen.append))
    log.record(call_id="0123456789abcdef0123456789abcdef", tool="x", tier="read", outcome="ok", arguments={"a": 1})
    (record,) = seen
    assert record["tool"] == "x" and record["arguments"] == {"a": 1}
    assert record["ts"].endswith("+00:00")
    assert log.path is None


def test_any_object_with_write_is_a_sink():
    class Collector:
        def __init__(self) -> None:
            self.records: list[dict] = []
            self.closed = False

        def write(self, record: dict) -> None:
            self.records.append(record)

        def close(self) -> None:
            self.closed = True

    collector = Collector()
    assert isinstance(collector, AuditSink)
    with AuditLog(sink=collector) as log:
        log.record(call_id="0123456789abcdef0123456789abcdef", tool="x", tier="read", outcome="ok", arguments={})
    assert [r["tool"] for r in collector.records] == ["x"]
    assert collector.closed


def test_a_sink_that_raises_sends_the_line_to_stderr_and_goes_on(capsys):
    calls = 0

    def flaky(record: dict) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("collector down: secret-value-here")

    log = AuditLog(sink=CallableSink(flaky))
    log.record(call_id="0123456789abcdef0123456789abcdef", tool="x", tier="read", outcome="ok", arguments={})  # the sink fails
    log.record(call_id="0123456789abcdef0123456789abcdef", tool="y", tier="read", outcome="ok", arguments={})  # the sink works
    (line,) = capsys.readouterr().err.splitlines()
    fallen_back = json.loads(line)
    assert fallen_back["tool"] == "x"
    assert fallen_back["sink_error"] == "ConnectionError"
    assert "secret-value-here" not in line  # the type only, never the message
    assert calls == 2
    assert not AUDIT_LINE.is_valid({**fallen_back, "sink_error": 1})  # and the field is in the schema
    assert AUDIT_LINE.is_valid(fallen_back)


async def test_a_failing_sink_never_fails_the_call(capsys):
    def down(record: dict) -> None:
        raise OSError("disk full")

    mcp = MCPServer("audit-down")
    gatehouse = Gatehouse(mcp, audit=AuditLog(sink=CallableSink(down)))

    @gatehouse.tool(tier=AccessTier.READ)
    def ping() -> str:
        return "pong"

    async with Client(mcp) as client:
        result = await client.call_tool("ping", {})
    assert not result.is_error and result.content[0].text == "pong"
    (line,) = capsys.readouterr().err.splitlines()
    assert json.loads(line)["sink_error"] == "OSError"


# --- the documented schema ---------------------------------------------------


def test_the_schema_file_is_a_valid_schema():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False  # an undocumented field fails the suite


@pytest.mark.parametrize(
    "bad",
    [
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "read", "outcome": "ok", "arguments": {}, "extra": 1},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "read", "outcome": "denied", "arguments": {}},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "read", "outcome": "ok", "arguments": {}, "reason": "?"},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "admin", "outcome": "ok", "arguments": {}},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "read", "outcome": "ok", "arguments": {}, "authz": "maybe"},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "read", "outcome": "ok", "arguments": {},
         "caller": {"client_id": "c", "subject": None, "issuer": None, "scopes": [], "token": "secret"}},
        {"ts": "2026-01-01T00:00:00+00:00", "call_id": "0" * 32, "tool": "x", "tier": "write", "outcome": "ok", "arguments": {},
         "consistency": "conditional", "consistency_reason": "why"},
    ],
    ids=["unknown field", "denied without reason", "ok with reason", "unknown tier", "unknown authz",
         "token in caller", "reason without accept-race"],
)
def test_the_schema_rejects_what_the_gate_never_writes(bad):
    assert not AUDIT_LINE.is_valid(bad)


async def test_every_kind_of_line_the_gate_writes_fits_the_schema():
    """A tour through the outcomes, so the schema is exercised on real lines
    (the autouse fixture checks each one), and the fields the README table
    lists are the fields that appear."""
    seen: list[dict] = []
    mcp = MCPServer("audit-tour")
    gatehouse = Gatehouse(
        mcp, policy=Policy(deny=frozenset({"blocked"})), audit=AuditLog(sink=CallableSink(seen.append)),
    )

    class Order(BaseModel):
        id: str

    def load(order_id: str) -> Order | None:
        return Order(id=order_id) if order_id != "missing" else None

    @gatehouse.tool(tier=AccessTier.WRITE, consistency=AcceptRace("demo"))
    def note(order_id: str, order: Annotated[Order, Load(load)]) -> str:
        return "noted"

    @gatehouse.tool(tier=AccessTier.READ, authorize_items=any_item)
    def listing() -> list[Order]:
        return [Order(id="1")]

    @gatehouse.tool(tier=AccessTier.READ)
    def blocked() -> str:
        return "never"

    @gatehouse.tool(tier=AccessTier.READ)
    def broken() -> str:
        raise RuntimeError("boom with a secret in it")

    async with Client(mcp) as client:
        await client.call_tool("note", {"order_id": "4417"})
        await client.call_tool("note", {"order_id": "missing"})
        await client.call_tool("listing", {})
        await client.call_tool("blocked", {})
        await client.call_tool("broken", {})

    by_tool = {r["tool"]: r for r in seen}
    noted, missing = [r for r in seen if r["tool"] == "note"]
    assert noted["consistency"] == "accept-race" and noted["consistency_reason"] == "demo"
    assert noted["resources"] == {"order": {"order_id": "4417"}} and noted["authz"] == "open"
    assert missing["outcome"] == "denied" and missing["reason"] == "not found: order"
    assert "authz" not in missing  # the policy never ran
    assert by_tool["listing"]["items"] == "open" and by_tool["listing"]["authz"] == "open"
    assert by_tool["blocked"] == {**by_tool["blocked"], "outcome": "denied", "reason": "denylist"}
    assert by_tool["broken"]["outcome"] == "error" and by_tool["broken"]["reason"] == "RuntimeError"
    for record in seen:
        assert record["caller"]["source"] == "local"
        AUDIT_LINE.validate(json.loads(json.dumps(record, default=str)))


async def test_an_infinite_argument_is_still_strict_json():
    """Wire JSON can carry 1e999 (the SDK parses it to inf). The line must
    stay readable to jq and JSON.parse, which reject Infinity."""
    from _support import signed_in, token

    stream = io.StringIO()
    gate = Gatehouse(MCPServer("audit"), policy=Policy(), audit=AuditLog(stream=stream))

    def refund(amount: float) -> str:
        return "ok"

    guarded = gate.guard(refund, "refund", AccessTier.READ)
    with signed_in(token("alice")):
        await guarded(amount=float("inf"))

    def no_constants(name):
        raise ValueError(name)

    line = json.loads(stream.getvalue().splitlines()[-1], parse_constant=no_constants)
    assert line["arguments"] == {"amount": "inf"}
