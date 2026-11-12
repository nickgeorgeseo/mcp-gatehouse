"""Used approvals remembered in SQLite, shared by every replica.

The round-trip approval (protocol 2026-07-28) hands the client a sealed
question and runs the call when the client comes back with the answer.
Each answer runs its call once: the gate spends the approval's nonce in an
`ApprovalStore`. The default store is a dict in the server process. That
is enough while the SDK's request-state key is per process too, which it
is by default: an approval minted before a restart, or by another
replica, fails the SDK's own seal check before the gate sees it.

You need a shared store the moment you share that key. A server started
with

    MCPServer("order-desk", request_state_security=RequestStateSecurity(keys=[KEY]))

so approvals survive a restart or work behind a load balancer accepts an
approval on any replica, and after a restart within `approval_timeout`.
Then an in-memory store would let one approval run its call once per
replica, and once more after each restart. This store puts the nonces in
one SQLite file every replica on the host can see. For replicas on
different hosts, the same `INSERT ... ON CONFLICT DO NOTHING` works on
any SQL database; `examples/approval_store_postgres.py` is that on Postgres.

Standard library only. The single-use guarantee is tested across two
processes in `tests/test_approval_store.py`. Wire it in with:

    ElicitationApprover(store=SqliteApprovalStore("/var/lib/order-desk/approvals.db"))

Run this file to spend nonces from the command line, which is what the
two-process test does:

    python examples/approval_store_sqlite.py approvals.db nonce-1 nonce-2
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time



class SqliteApprovalStore:
    """An `mcp_gatehouse.ApprovalStore` on one SQLite file.

    One short connection per call: SQLite's own file lock then serializes
    writers across threads and processes, and nothing is tied to a thread.
    A nonce is a primary key, so the first insert wins and every later one
    changes no row. Expired nonces are swept on each call; the gate never
    asks about one past its expiry anyway.

    An unreadable or locked-for-too-long database raises, and the gate
    then denies the call (`approval store error: OperationalError`): it
    can't tell a first use from a replay, so it fails closed.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 5.0) -> None:
        self.path = os.fspath(path)
        self.timeout = timeout
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS used_approvals (nonce TEXT PRIMARY KEY, expires REAL NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")  # readers never block the writer
        db.execute("PRAGMA synchronous=FULL")  # a spent nonce survives a crash
        return db

    def spend(self, nonce: str, expires: float) -> bool:
        with self._connect() as db:
            db.execute("DELETE FROM used_approvals WHERE expires <= ?", (time.time(),))
            inserted = db.execute(
                "INSERT INTO used_approvals (nonce, expires) VALUES (?, ?) ON CONFLICT (nonce) DO NOTHING",
                (nonce, expires),
            ).rowcount
            return inserted == 1



if __name__ == "__main__":
    path, *nonces = sys.argv[1:]
    store = SqliteApprovalStore(path)
    expires = time.time() + 3600
    for nonce in nonces:
        print(nonce, "spent" if store.spend(nonce, expires) else "refused", flush=True)
