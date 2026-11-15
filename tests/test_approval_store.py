"""ApprovalStore: where used round-trip approvals are remembered.

The default remembers per process. The SQLite example shares one file
between processes, and the single-use guarantee is checked across two of
them, and across two servers that share the SDK's request-state key.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.server.request_state import RequestStateSecurity
from mcp.types import ElicitResult, InputRequiredResult

from mcp_gatehouse import AccessTier, ApprovalStore, AuditLog, ElicitationApprover, MemoryApprovalStore, Policy

from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "approval_store_sqlite.py"


def load_example():
    spec = importlib.util.spec_from_file_location("approval_store_sqlite", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def build(approver: ElicitationApprover, stream: io.StringIO, ran: list[str], **server) -> MCPServer:
    mcp = MCPServer("store-test", **server)
    gatehouse = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=stream))

    @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: str) -> str:
        ran.append(order_id)
        return f"{order_id} cancelled"

    return mcp


async def approve_in_client(context, params) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True})


async def ask(client: Client) -> InputRequiredResult:
    question = await client.session.call_tool("cancel_order", {"order_id": "4417"}, allow_input_required=True)
    assert isinstance(question, InputRequiredResult)
    return question


async def answer(client: Client, question: InputRequiredResult):
    (key,) = question.input_requests
    return await client.session.call_tool(
        "cancel_order", {"order_id": "4417"},
        input_responses={key: ElicitResult(action="accept", content={"approve": True})},
        request_state=question.request_state,
    )


# --- the protocol -------------------------------------------------------------


def test_memory_store_spends_each_nonce_once():
    store = MemoryApprovalStore()
    later = time.time() + 60
    assert store.spend("a", later) is True
    assert store.spend("a", later) is False
    assert store.spend("b", later) is True
    assert isinstance(store, ApprovalStore)


def test_memory_store_forgets_expired_nonces_after_a_grace():
    store = MemoryApprovalStore()
    assert store.spend("old", time.time() - 301) is True
    assert store.spend("recent", time.time() - 1) is True
    assert store.spend("new", time.time() + 60) is True  # sweeps "old" only
    assert sorted(store._used) == ["new", "recent"]


def test_memory_store_refuses_a_replay_after_the_clock_steps_back(monkeypatch):
    """Swept at expiry, an approval could be spent again once an NTP step
    puts the clock back before its expiry; the grace keeps it remembered."""
    store = MemoryApprovalStore()
    now = time.time()
    assert store.spend("n", now + 10) is True
    monkeypatch.setattr(time, "time", lambda: now + 20)
    assert store.spend("other", now + 80) is True  # a sweep, past n's expiry
    monkeypatch.setattr(time, "time", lambda: now)
    assert store.spend("n", now + 10) is False


def test_the_approver_needs_a_real_store():
    with pytest.raises(TypeError, match="spend"):
        ElicitationApprover(store=object())  # type: ignore[arg-type]
    assert isinstance(ElicitationApprover().store, MemoryApprovalStore)


async def test_a_custom_store_is_asked_once_per_answer():
    seen: list[tuple[str, float]] = []

    class Recording:
        def spend(self, nonce: str, expires: float) -> bool:
            seen.append((nonce, expires))
            return nonce not in {n for n, _ in seen[:-1]}

    stream, ran = io.StringIO(), []
    mcp = build(ElicitationApprover(store=Recording()), stream, ran)
    async with Client(mcp, elicitation_callback=approve_in_client) as client:
        question = await ask(client)
        first = await answer(client, question)
        replay = await answer(client, question)

    assert not first.is_error and ran == ["4417"]
    assert replay.is_error and "already used" in replay.content[0].text
    (nonce, expires), (again, _) = seen
    assert nonce == again and expires > time.time()
    assert nonce not in question.request_state  # sealed by the SDK: the client never sees it


async def test_a_store_that_fails_denies_the_call():
    class Down:
        def spend(self, nonce: str, expires: float) -> bool:
            raise ConnectionError("db unreachable: dsn=postgres://secret@host")

    stream, ran = io.StringIO(), []
    mcp = build(ElicitationApprover(store=Down()), stream, ran)
    async with Client(mcp, elicitation_callback=approve_in_client) as client:
        question = await ask(client)
        result = await answer(client, question)

    assert result.is_error and "approval store failed" in result.content[0].text
    assert ran == []
    last = events(stream)[-1]
    assert (last["outcome"], last["reason"]) == ("denied", "approval store error: ConnectionError")
    assert "secret" not in stream.getvalue()


async def test_a_store_that_answers_something_else_denies_too():
    class Vague:
        def spend(self, nonce: str, expires: float):
            return "yes"  # not True: the gate takes nothing but True as "first use"

    stream, ran = io.StringIO(), []
    mcp = build(ElicitationApprover(store=Vague()), stream, ran)
    async with Client(mcp, elicitation_callback=approve_in_client) as client:
        result = await answer(client, await ask(client))
    assert result.is_error and ran == []
    assert events(stream)[-1]["reason"] == "approval already used"


# --- the SQLite example -------------------------------------------------------


def test_sqlite_store_spends_once_within_a_process(tmp_path):
    store = load_example().SqliteApprovalStore(tmp_path / "approvals.db")
    later = time.time() + 60
    assert store.spend("n1", later) is True
    assert store.spend("n1", later) is False
    assert store.spend("n2", later) is True
    assert isinstance(store, ApprovalStore)


def test_sqlite_store_sweeps_expired_nonces_after_a_grace(tmp_path):
    store = load_example().SqliteApprovalStore(tmp_path / "approvals.db")
    assert store.spend("old", time.time() - 301) is True
    assert store.spend("recent", time.time() - 1) is True
    assert store.spend("new", time.time() + 60) is True
    import sqlite3

    rows = sqlite3.connect(store.path).execute("SELECT nonce FROM used_approvals ORDER BY nonce").fetchall()
    assert rows == [("new",), ("recent",)]


def test_sqlite_store_survives_a_restart(tmp_path):
    """A new process (here: a new store object) still sees the spent nonce,
    which is the restart-within-approval_timeout case."""
    make = load_example().SqliteApprovalStore
    assert make(tmp_path / "approvals.db").spend("n", time.time() + 60) is True
    assert make(tmp_path / "approvals.db").spend("n", time.time() + 60) is False


def test_sqlite_store_is_single_use_across_two_processes(tmp_path):
    """Two processes race to spend the same 40 nonces; each nonce is spent
    by exactly one of them."""
    db = tmp_path / "approvals.db"
    load_example().SqliteApprovalStore(db)  # create the table before the race
    nonces = [f"nonce-{i}" for i in range(40)]
    command = [sys.executable, "-I", str(EXAMPLE), str(db), *nonces]  # the example is standard library only
    procs = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outputs = [p.communicate(timeout=60) for p in procs]
    for (out, err), p in zip(outputs, procs):
        assert p.returncode == 0, err

    spent_by: dict[str, list[int]] = {n: [] for n in nonces}
    for i, (out, _) in enumerate(outputs):
        for line in out.splitlines():
            nonce, verdict = line.split()
            if verdict == "spent":
                spent_by[nonce].append(i)
    assert all(len(who) == 1 for who in spent_by.values()), spent_by


async def test_two_servers_sharing_the_state_key_share_the_store(tmp_path):
    """Two replicas: the same request-state key (so either accepts the
    other's sealed question) and the same SQLite store. An approval
    answered on one replica can't run again on the other."""
    key = os.urandom(32)
    store = load_example().SqliteApprovalStore(tmp_path / "approvals.db")
    stream, ran = io.StringIO(), []
    replicas = [
        build(ElicitationApprover(store=store), stream, ran, request_state_security=RequestStateSecurity(keys=[key]))
        for _ in range(2)
    ]
    async with (
        Client(replicas[0], elicitation_callback=approve_in_client) as a,
        Client(replicas[1], elicitation_callback=approve_in_client) as b,
    ):
        question = await ask(a)
        on_b = await answer(b, question)  # the other replica runs it
        replay_on_a = await answer(a, question)

    assert not on_b.is_error
    assert replay_on_a.is_error and "already used" in replay_on_a.content[0].text
    assert ran == ["4417"]


async def test_without_a_shared_store_each_replica_runs_the_approval(tmp_path):
    """The failure the shared store prevents, shown: same key, separate
    in-memory stores, and one approval runs the call twice."""
    key = os.urandom(32)
    stream, ran = io.StringIO(), []
    replicas = [
        build(ElicitationApprover(), stream, ran, request_state_security=RequestStateSecurity(keys=[key]))
        for _ in range(2)
    ]
    async with (
        Client(replicas[0], elicitation_callback=approve_in_client) as a,
        Client(replicas[1], elicitation_callback=approve_in_client) as b,
    ):
        question = await ask(a)
        await answer(a, question)
        await answer(b, question)
    assert ran == ["4417", "4417"]
