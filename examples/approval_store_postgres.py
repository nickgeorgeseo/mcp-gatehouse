"""Used approvals remembered in Postgres, shared by replicas on any host.

The round-trip approval (protocol 2026-07-28) hands the client a sealed
question and runs the call when the client comes back with the answer.
Each answer runs its call once: the gate spends the approval's nonce in an
`ApprovalStore`. `examples/approval_store_sqlite.py` shares one file
between the replicas on one host. This store is the same contract on
Postgres, for replicas on several hosts.

You need it once the replicas share the SDK's request-state key, so any
replica accepts a question another one asked:

    KEY = os.environ["MCP_REQUEST_STATE_KEY"]  # 32+ random bytes, the same on every replica
    mcp = MCPServer("order-desk", request_state_security=RequestStateSecurity(keys=[KEY]))
    store = PostgresApprovalStore(os.environ["APPROVALS_DSN"])
    gatehouse = Gatehouse(mcp, policy=Policy(approver=ElicitationApprover(store=store)), ...)

Needs `pip install "psycopg[binary]"`. The library doesn't import this
file; copy it.

How it holds:

- A nonce is the primary key, and `INSERT ... ON CONFLICT DO NOTHING`
  is one atomic statement. Two replicas spending the same nonce at the
  same moment: Postgres makes the second wait for the first to commit,
  then inserts nothing. Exactly one of them gets `True`.
- Autocommit, so a spent nonce is durable before `spend` returns.
- Expired rows are swept on each call, skipping rows another replica is
  sweeping at the same moment, so sweeps never wait on each other.
  `expires` is a `time.time()` from the replica that asked, and replica
  clocks drift, so a row is only swept `sweep_grace` seconds (default
  300) after its expiry. A replica whose clock runs ahead can't forget a
  nonce another replica still honours, unless the clocks are further
  apart than that.
- Postgres unreachable, or any error: `spend` raises, and the gate denies
  the call (`approval store error: OperationalError`). It can't tell a
  first use from a replay, so it fails closed.

Each call opens and closes its own connection. Approvals are rare next
to tool calls, so that is usually fine; put a connection pool behind
`_connect` if it isn't.

Run this file to spend nonces from the command line:

    python examples/approval_store_postgres.py postgresql:///approvals nonce-1 nonce-2
"""

from __future__ import annotations

import sys
import time
import psycopg
from psycopg import sql


class PostgresApprovalStore:
    """An `mcp_gatehouse.ApprovalStore` on one Postgres table."""

    def __init__(
        self,
        conninfo: str,
        *,
        table: str = "gatehouse_used_approvals",
        sweep_grace: float = 300.0,
        connect_timeout: int = 5,
    ) -> None:
        if not sweep_grace >= 0:
            raise ValueError("sweep_grace must be zero or more seconds")
        self.conninfo = conninfo
        self.sweep_grace = sweep_grace
        self.connect_timeout = connect_timeout
        self._table = sql.Identifier(table)
        with self._connect() as conn:
            conn.execute(
                sql.SQL(
                    "CREATE TABLE IF NOT EXISTS {} (nonce text PRIMARY KEY, expires double precision NOT NULL)"
                ).format(self._table)
            )
            conn.execute(
                sql.SQL("CREATE INDEX IF NOT EXISTS {} ON {} (expires)").format(
                    sql.Identifier(table + "_expires"), self._table
                )
            )

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.conninfo, autocommit=True, connect_timeout=self.connect_timeout)

    def spend(self, nonce: str, expires: float) -> bool:
        with self._connect() as conn:
            conn.execute(
                sql.SQL(
                    "DELETE FROM {t} WHERE nonce IN "
                    "(SELECT nonce FROM {t} WHERE expires < %s FOR UPDATE SKIP LOCKED LIMIT 1000)"
                ).format(t=self._table),
                (time.time() - self.sweep_grace,),
            )
            inserted = conn.execute(
                sql.SQL("INSERT INTO {} (nonce, expires) VALUES (%s, %s) ON CONFLICT (nonce) DO NOTHING").format(
                    self._table
                ),
                (nonce, expires),
            ).rowcount
            return inserted == 1


if __name__ == "__main__":
    dsn, *nonces = sys.argv[1:]
    store = PostgresApprovalStore(dsn)
    expires = time.time() + 3600
    for nonce in nonces:
        print(nonce, "spent" if store.spend(nonce, expires) else "refused", flush=True)
