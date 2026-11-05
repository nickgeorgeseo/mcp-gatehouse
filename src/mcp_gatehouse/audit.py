"""Append-only JSONL audit log.

One line per tool call — allowed, denied, failed, or cancelled — with UTC
timestamps and redacted arguments. The point is a trail you can grep six
months later when someone asks "what did the AI actually do?"
"""

from __future__ import annotations

import datetime as _dt
import enum
import io
import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol, TextIO, runtime_checkable


class Outcome(str, enum.Enum):
    """The ``outcome`` field of an audit line: what happened to the call.

    A ``str`` enum, so ``event["outcome"] == Outcome.DENIED`` works on a
    line read back from the file.
    """

    OK = "ok"
    """It ran and returned."""

    DENIED = "denied"
    """The gate refused it; ``reason`` says why."""

    ERROR = "error"
    """It ran and raised; ``reason`` is the exception's type."""

    PENDING = "pending"
    """Approval was asked in the client; the verdict follows on a line of
    its own when the client calls again."""

    CANCELLED = "cancelled"
    """The client gave up, or the server stopped, before it finished;
    ``reason`` says at which step."""


class Reason:
    """The fixed values of an audit line's ``reason`` field.

    An ``error`` line's reason is the exception's type name instead, and an
    approver error carries a detail after the colon.
    """

    DENYLIST = "denylist"
    NO_APPROVER = "approval required, no approver configured"
    CLIENT_CANNOT_BE_ASKED = "approval required, client cannot be asked"
    REFUSED = "approver refused"
    TIMED_OUT = "approval timed out"
    ALREADY_USED = "approval already used"
    APPROVER_ERROR = "approver error"
    ASKED_IN_CLIENT = "approval asked in client"
    AWAITING_APPROVAL = "awaiting approval"
    TOOL_RUNNING = "tool running"

    @staticmethod
    def approver_error(detail: str) -> str:
        """``approver error: <detail>``, such as the exception's type."""
        return f"{Reason.APPROVER_ERROR}: {detail}"


@runtime_checkable
class AuditSink(Protocol):
    """Anything the gate can hand its audit events to.

    One method: ``record(**event)``, called once per outcome with ``tool``,
    ``tier``, ``outcome`` (see :class:`Outcome`) and the redacted
    ``arguments``, plus ``reason`` (see :class:`Reason`) and
    ``duration_ms`` where they apply. Send them to a database, a SIEM or
    your logging stack by writing a class with that method.

    A sink that raises doesn't change the call: the failure is logged (at
    ERROR, on the ``mcp_gatehouse`` logger) and the call's result stands.
    By the time most records are written the tool has already run, and
    telling the model it failed would invite it to run it again.
    """

    def record(self, **event: Any) -> None: ...


class AuditLog:
    """Writes one JSON object per line to a file or stream.

    Thread-safe for concurrent tool calls within one process. Events are
    flushed on every write — an audit log that loses its tail in a crash
    is not an audit log.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        stream: TextIO | None = None,
    ) -> None:
        if (path is None) == (stream is None):
            raise ValueError("provide exactly one of `path` or `stream`")
        self._lock = threading.Lock()
        self.path: Path | None = None
        """Absolute path of the log file, or ``None`` when writing to a stream."""
        if path is not None:
            p = Path(path).expanduser().absolute()
            p.parent.mkdir(parents=True, exist_ok=True)
            self._stream: TextIO = p.open("a", encoding="utf-8")
            self._owns_stream = True
            self.path = p
        else:
            assert stream is not None
            self._stream = stream
            self._owns_stream = False

    def record(self, **event: Any) -> None:
        """Append one event. A ``ts`` field (UTC, ISO-8601) is added.

        ``ensure_ascii=True`` on purpose: it escapes U+2028/U+2029/NEL and
        friends, so a crafted argument value can never split one record
        into two for line-aware readers. One ``\\n`` per record, always.
        """
        line = _line(event)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()

    def close(self) -> None:
        if self._owns_stream:
            self._stream.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _line(event: dict[str, Any]) -> str:
    """One record as the file holds it: a ``ts`` first, then the event."""
    stamped = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), **event}
    return json.dumps(stamped, ensure_ascii=True, default=str)


class NullAuditLog(AuditLog):
    """An audit log that swallows everything. For tests and dry runs."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())

    def record(self, **event: Any) -> None:
        pass


class MemoryAuditLog(AuditLog):
    """Keeps every record in memory, in :attr:`events`. For tests::

        audit = MemoryAuditLog()
        gatehouse = Gatehouse(mcp, audit=audit)
        ...
        assert audit.outcomes() == [("denied", "approver refused")]

    Each event is exactly what a line of the JSONL file would parse back
    to, ``ts`` included, so a test written against it holds for the file.
    """

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())
        self.events: list[dict[str, Any]] = []
        """Every record so far, oldest first."""

    def record(self, **event: Any) -> None:
        parsed = json.loads(_line(event))
        with self._lock:
            self.events.append(parsed)

    def outcomes(self) -> list[tuple[str, str | None]]:
        """``(outcome, reason)`` for each record, oldest first."""
        return [(e["outcome"], e.get("reason")) for e in self.events]

    def clear(self) -> None:
        with self._lock:
            self.events.clear()
