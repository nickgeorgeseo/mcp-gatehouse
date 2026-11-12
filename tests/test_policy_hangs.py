"""How far a policy that doesn't return reaches. tests/test_authorization_deadline.py
covers the deadline itself; these cover what is left around it.

- Sync loaders, policies and scopes run on the gate's own worker threads,
  not anyio's default pool, so a hung one never leaves a sync tool
  elsewhere on the server without a thread.
- With the deadline on (the default), a call whose client gives up ends
  at once: the policy's thread is abandoned and finishes in the
  background. With ``authorization_timeout=None`` the call waits for the
  policy, however long that is, as it always did.
- An async policy runs on the event loop. One that awaits forever blocks
  only its own call. One that blocks without awaiting (a sync HTTP call
  inside ``async def``) stalls the whole server; no deadline the gate sets
  can interrupt that.
- Inside a sync ``Transaction`` every step, the policy included, runs in
  the transaction's one worker thread, so a hung policy also holds the
  transaction open. A client that gives up meanwhile gets its
  cancellation once the policy returns, before the tool: the transaction
  rolls back and the tool never runs.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import threading
import time
from typing import Annotated

import anyio
import anyio.to_thread
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, Allow, AuditLog, Load, Policy, Transaction, current_transaction

from _support import OpenGatehouse as Gatehouse


async def until(event: threading.Event) -> None:
    with anyio.fail_after(5):
        while not event.is_set():
            await anyio.sleep(0.01)


def server(policy, ran=None, *, deadline=None):
    """``deadline=None`` turns the authorization deadline off, so these
    tests see a hung policy for as long as it hangs."""
    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(authorization_timeout=deadline), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.READ, authorize=policy)
    def stuck() -> str:
        if ran is not None:
            ran.append("stuck")
        return "ran"

    @gk.tool(tier=AccessTier.READ)
    def other() -> str:
        return "other ran"

    return mcp, log


@pytest.mark.anyio
async def test_a_hung_sync_policy_blocks_only_its_own_call():
    started, released = threading.Event(), threading.Event()

    def policy(request):
        started.set()
        released.wait(timeout=10)
        return Allow()

    mcp, _ = server(policy)
    try:
        async with Client(mcp) as client:
            async with anyio.create_task_group() as tg:
                tg.start_soon(client.call_tool, "stuck", {})
                await until(started)
                with anyio.fail_after(2):
                    result = await client.call_tool("other", {})
                assert not result.is_error
                released.set()
    finally:
        released.set()


async def cancel_during_a_sync_policy(release_after: float, deadline=None):
    """The client gives up while a sync policy is still running; the policy
    returns ``release_after`` seconds later. Returns the elapsed time, the
    last audit line and what ran."""
    started, released, ran = threading.Event(), threading.Event(), []

    def policy(request):
        started.set()
        released.wait(timeout=10)
        return Allow()

    mcp, log = server(policy, ran, deadline=deadline)
    threading.Timer(release_after, released.set).start()
    began = time.monotonic()
    try:
        async with Client(mcp) as client:
            async with anyio.create_task_group() as tg:
                tg.start_soon(client.call_tool, "stuck", {})
                await until(started)
                tg.cancel_scope.cancel()
    finally:
        released.set()
    return time.monotonic() - began, json.loads(log.getvalue().splitlines()[-1]), ran


@pytest.mark.anyio
async def test_without_a_deadline_a_cancelled_call_waits_for_its_sync_policy():
    """``authorization_timeout=None``: the policy's thread isn't abandoned,
    so the call stays until the policy returns. The tool still doesn't run."""
    elapsed, line, ran = await cancel_during_a_sync_policy(0.5)
    assert elapsed >= 0.45  # waited for the policy, not for the client
    assert line["outcome"] == "cancelled" and ran == []
    assert line["authorization_deadline"] == "off"


@pytest.mark.anyio
async def test_with_a_deadline_a_cancelled_call_ends_when_the_client_gives_up():
    """The deadline is on, so the policy's thread may be abandoned: the call
    ends with the client, not with the policy."""
    elapsed, line, ran = await cancel_during_a_sync_policy(1.0, deadline=5.0)
    assert elapsed < 0.8
    assert (line["outcome"], line["reason"]) == ("cancelled", "authorizing") and ran == []
    assert "authorization_deadline" not in line


@pytest.mark.anyio
async def test_a_call_cancelled_during_a_sync_policy_is_logged_as_authorizing():
    """The cancellation is taken as soon as the policy's thread returns, so
    the line says where the call was, and the tool never starts."""
    _, line, ran = await cancel_during_a_sync_policy(0.2)
    assert ran == []
    assert line["reason"] == "authorizing" and "duration_ms" not in line


@pytest.mark.anyio
async def test_hung_sync_policies_leave_sync_tools_their_threads():
    """Policies run on the gate's own threads. With the default pool cut to
    two threads and two policies hung, with no deadline to end them, a
    sync tool elsewhere still gets a thread."""
    limiter = anyio.to_thread.current_default_thread_limiter()
    tokens = limiter.total_tokens
    limiter.total_tokens = 2
    started, released = threading.Semaphore(0), threading.Event()

    def policy(request):
        started.release()
        released.wait(timeout=10)
        return Allow()

    mcp, _ = server(policy)
    try:
        async with Client(mcp) as client:
            async with anyio.create_task_group() as tg:
                tg.start_soon(client.call_tool, "stuck", {})
                tg.start_soon(client.call_tool, "stuck", {})
                for _ in range(2):
                    with anyio.fail_after(5):
                        while not started.acquire(blocking=False):
                            await anyio.sleep(0.01)
                with anyio.fail_after(2):
                    result = await client.call_tool("other", {})
                assert not result.is_error
                released.set()
    finally:
        released.set()
        limiter.total_tokens = tokens


@pytest.mark.anyio
async def test_a_hung_async_policy_blocks_only_its_call_and_goes_when_the_client_does():
    started = threading.Event()

    async def policy(request):
        started.set()
        await anyio.sleep_forever()

    mcp, log = server(policy)
    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "stuck", {})
            await until(started)
            with anyio.fail_after(2):
                assert not (await client.call_tool("other", {})).is_error
            with anyio.fail_after(2):
                tg.cancel_scope.cancel()
    line = json.loads(log.getvalue().splitlines()[-1])
    assert (line["tool"], line["outcome"], line["reason"]) == ("stuck", "cancelled", "authorizing")


@pytest.mark.anyio
async def test_a_call_cancelled_while_its_items_are_filtered_says_the_tool_ran():
    """The tool returned; the client gave up while an async item policy ran.
    The line says the tool was running, with its duration, not "authorizing"."""
    started = anyio.Event()

    async def items(request):
        started.set()
        await anyio.sleep(10)
        return Allow()

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.READ, authorize_items=items)
    def listing() -> list[dict]:
        return [{"id": "a"}]

    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "listing", {})
            with anyio.fail_after(5):
                await started.wait()
            tg.cancel_scope.cancel()
    line = json.loads(log.getvalue().splitlines()[-1])
    assert (line["outcome"], line["reason"]) == ("cancelled", "tool running")
    assert "duration_ms" in line


# --- inside a sync Transaction ------------------------------------------------


def transactional_server(db_path, policy, tool_started=None, tool_takes=0.0):
    """A write tool in a sync SQLite transaction. The loader writes a row,
    so a rollback is visible afterwards."""
    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=log))

    @contextlib.contextmanager
    def transaction(caller):
        conn = sqlite3.connect(db_path)
        try:
            with conn:  # commits on success, rolls back on any exception
                yield conn
        finally:
            conn.close()

    def load(order_id: str) -> dict:
        current_transaction().execute("INSERT INTO touched VALUES ('loader')")
        return {"id": order_id}

    @gk.tool(tier=AccessTier.WRITE, authorize=policy, consistency=Transaction(transaction))
    def write(order_id: str, order: Annotated[dict, Load(load)]) -> str:
        current_transaction().execute("INSERT INTO touched VALUES ('tool')")
        if tool_started is not None:
            tool_started.set()
        time.sleep(tool_takes)
        return "written"

    return mcp, log


def touched(db_path) -> list[str]:
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        return [r[0] for r in conn.execute("SELECT what FROM touched")]


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE touched (what TEXT)")
        conn.commit()
    return path


async def cancel_when(event: threading.Event, mcp) -> None:
    async with Client(mcp) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.call_tool, "write", {"order_id": "1"})
            await until(event)
            tg.cancel_scope.cancel()


@pytest.mark.anyio
async def test_a_transaction_cancelled_while_authorizing_rolls_back_before_the_tool(db):
    """The client gives up while a sync policy runs inside the transaction.
    The policy finishes in its thread, the gate takes the cancellation
    before the tool, and the transaction rolls back: the loader's write is
    gone and the tool never ran."""
    started, released = threading.Event(), threading.Event()

    def policy(request):
        started.set()
        released.wait(timeout=10)
        return Allow()

    mcp, log = transactional_server(db, policy)
    threading.Timer(0.2, released.set).start()
    try:
        await cancel_when(started, mcp)
    finally:
        released.set()
    await anyio.sleep(0.3)  # let the worker thread finish its rollback
    assert touched(db) == []
    line = json.loads(log.getvalue().splitlines()[-1])
    assert (line["outcome"], line["reason"]) == ("cancelled", "authorizing")
    assert "duration_ms" not in line


@pytest.mark.anyio
async def test_a_transaction_whose_tool_already_started_still_commits(db):
    """Once the tool is running, the gate doesn't stop it: the tool's
    thread finishes, the transaction commits, and the line says ok."""
    tool_started = threading.Event()
    mcp, log = transactional_server(db, lambda request: Allow(), tool_started, tool_takes=0.3)
    await cancel_when(tool_started, mcp)
    await anyio.sleep(0.5)
    assert touched(db) == ["loader", "tool"]
    line = json.loads(log.getvalue().splitlines()[-1])
    assert line["outcome"] == "ok"
