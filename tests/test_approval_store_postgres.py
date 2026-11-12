"""The Postgres approval store: single use under concurrent spenders,
expired rows swept, and two replicas sharing it behind the gate.

Runs only against a real Postgres: set GATEHOUSE_TEST_POSTGRES_DSN to a
database the tests may create tables in, and install psycopg. Skipped
otherwise. Each test uses a table of its own and drops it afterwards.
"""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

DSN = os.environ.get("GATEHOUSE_TEST_POSTGRES_DSN")
if not DSN:
    pytest.skip("set GATEHOUSE_TEST_POSTGRES_DSN to run the Postgres store tests", allow_module_level=True)
psycopg = pytest.importorskip("psycopg")

from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.request_state import RequestStateSecurity  # noqa: E402
from mcp.types import ElicitResult, InputRequiredResult  # noqa: E402

from mcp_gatehouse import AccessTier, ApprovalStore, AuditLog, ElicitationApprover, Policy  # noqa: E402

from _support import OpenGatehouse as Gatehouse  # noqa: E402

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "approval_store_postgres.py"


def load_example():
    spec = importlib.util.spec_from_file_location("approval_store_postgres", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def table():
    name = "gatehouse_test_" + uuid.uuid4().hex[:12]
    yield name
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f'DROP TABLE IF EXISTS "{name}"')


def rows(table: str) -> list[str]:
    with psycopg.connect(DSN) as conn:
        return sorted(r[0] for r in conn.execute(f'SELECT nonce FROM "{table}"'))


def test_spends_each_nonce_once(table):
    store = load_example().PostgresApprovalStore(DSN, table=table)
    later = time.time() + 60
    assert store.spend("n1", later) is True
    assert store.spend("n1", later) is False
    assert store.spend("n2", later) is True
    assert isinstance(store, ApprovalStore)


def test_a_new_store_object_still_sees_spent_nonces(table):
    """The restart case: another process, the same table."""
    make = load_example().PostgresApprovalStore
    assert make(DSN, table=table).spend("n", time.time() + 60) is True
    assert make(DSN, table=table).spend("n", time.time() + 60) is False


def test_expired_rows_are_swept_after_the_grace(table):
    store = load_example().PostgresApprovalStore(DSN, table=table, sweep_grace=30)
    now = time.time()
    assert store.spend("long-gone", now - 31) is True
    assert store.spend("just-expired", now - 5) is True  # inside the grace: kept
    assert store.spend("live", now + 60) is True
    assert rows(table) == ["just-expired", "live"]


def test_single_use_under_concurrent_spenders_in_one_process(table):
    """Eight threads, each on its own connection, race for the same 50
    nonces at once. Each nonce is spent exactly once."""
    store = load_example().PostgresApprovalStore(DSN, table=table)
    nonces = [f"nonce-{i}" for i in range(50)]
    start = threading.Barrier(8)
    spent: list[str] = []
    lock = threading.Lock()
    errors: list[BaseException] = []

    def spender() -> None:
        try:
            start.wait()
            for nonce in nonces:
                if store.spend(nonce, time.time() + 60):
                    with lock:
                        spent.append(nonce)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=spender) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert sorted(spent) == sorted(nonces)


def test_single_use_across_two_processes(table):
    load_example().PostgresApprovalStore(DSN, table=table)  # the table exists before the race
    nonces = [f"nonce-{i}" for i in range(40)]
    script = (
        "import sys, time; sys.path.insert(0, sys.argv[1]);"
        "from approval_store_postgres import PostgresApprovalStore as S;"
        "s = S(sys.argv[2], table=sys.argv[3]);"
        "[print(n, 'spent' if s.spend(n, time.time() + 60) else 'refused', flush=True) for n in sys.argv[4:]]"
    )
    command = [sys.executable, "-I", "-c", script, str(EXAMPLE.parent), DSN, table, *nonces]
    procs = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outputs = [p.communicate(timeout=60) for p in procs]
    for (_, err), p in zip(outputs, procs):
        assert p.returncode == 0, err
    spent_by: dict[str, int] = {n: 0 for n in nonces}
    for out, _ in outputs:
        for line in out.splitlines():
            nonce, verdict = line.split()
            spent_by[nonce] += verdict == "spent"
    assert set(spent_by.values()) == {1}, spent_by


def test_postgres_down_raises_so_the_gate_denies():
    make = load_example().PostgresApprovalStore
    with pytest.raises(psycopg.OperationalError):
        make("postgresql://nobody@127.0.0.1:1/none", connect_timeout=1)


async def approve_in_client(context, params) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True})


@pytest.mark.anyio
async def test_two_replicas_sharing_the_key_and_the_store_run_an_approval_once(table):
    key = os.urandom(32)
    store = load_example().PostgresApprovalStore(DSN, table=table)
    stream, ran = io.StringIO(), []

    def replica() -> MCPServer:
        mcp = MCPServer("order-desk", request_state_security=RequestStateSecurity(keys=[key]))
        gatehouse = Gatehouse(
            mcp, policy=Policy(approver=ElicitationApprover(store=store)), audit=AuditLog(stream=stream)
        )

        @gatehouse.tool(tier=AccessTier.DESTRUCTIVE)
        def cancel_order(order_id: str) -> str:
            ran.append(order_id)
            return f"{order_id} cancelled"

        return mcp

    async def answer(client: Client, question: InputRequiredResult):
        (k,) = question.input_requests
        return await client.session.call_tool(
            "cancel_order", {"order_id": "4417"},
            input_responses={k: ElicitResult(action="accept", content={"approve": True})},
            request_state=question.request_state,
        )

    async with (
        Client(replica(), elicitation_callback=approve_in_client) as a,
        Client(replica(), elicitation_callback=approve_in_client) as b,
    ):
        question = await a.session.call_tool("cancel_order", {"order_id": "4417"}, allow_input_required=True)
        assert isinstance(question, InputRequiredResult)
        on_b = await answer(b, question)
        replay_on_a = await answer(a, question)

    assert not on_b.is_error
    assert replay_on_a.is_error and "already used" in replay_on_a.content[0].text
    assert ran == ["4417"]
