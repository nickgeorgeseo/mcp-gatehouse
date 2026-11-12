"""The audit log: one record per tool call, handed to a sink.

One record per tool call — allowed, denied, failed, pending or cancelled —
with a UTC timestamp and redacted arguments. The point is a trail you can
grep six months later when someone asks "what did the AI actually do?"

The default sink is an append-only JSONL file. A sink is anything with a
``write(record)`` method (:class:`AuditSink`), so the same records can go
to a logging pipeline, OpenTelemetry, or an HTTP collector instead. The
record's fields are documented in the README and in
``docs/audit-line.schema.json``.
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TextIO, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """Where audit records go. One method: it takes the record as a dict.

    :class:`AuditLog` serializes its calls, so a sink needn't be
    thread-safe. A sink that raises doesn't lose the record: the log
    writes it to stderr with a ``sink_error`` field and goes on. A sink
    may also define ``close()``, which :meth:`AuditLog.close` calls.
    """

    def write(self, record: dict[str, Any]) -> None: ...


def _line(record: dict[str, Any]) -> str:
    """One record as one line of JSON.

    ``ensure_ascii=True`` on purpose: it escapes U+2028/U+2029/NEL and
    friends, so a crafted argument value can never split one record into
    two for line-aware readers. One ``\\n`` per record, always.
    """
    return json.dumps(record, ensure_ascii=True, default=str) + "\n"


class JsonlSink:
    """Append one JSON object per line to a file or a text stream.

    Flushed on every write — an audit log that loses its tail in a crash
    is not an audit log. A file opened here is closed by :meth:`close`; a
    stream passed in is left to its owner.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        stream: TextIO | None = None,
    ) -> None:
        if (path is None) == (stream is None):
            raise ValueError("provide exactly one of `path` or `stream`")
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

    def write(self, record: dict[str, Any]) -> None:
        self._stream.write(_line(record))
        self._stream.flush()

    def close(self) -> None:
        if self._owns_stream:
            self._stream.close()


class CallableSink:
    """Hand each record to a function of yours: ``CallableSink(queue.put)``,
    ``CallableSink(lambda r: logger.info("audit", extra=r))``, an HTTP
    post. The function gets the record dict; its return value is ignored.
    """

    def __init__(self, fn: Callable[[dict[str, Any]], Any]) -> None:
        if not callable(fn):
            raise TypeError("CallableSink needs a callable")
        self.fn = fn

    def write(self, record: dict[str, Any]) -> None:
        self.fn(record)


class AuditLog:
    """Writes one record per call to a sink: a JSONL file (``path=``), a
    text stream (``stream=``), or any :class:`AuditSink` (``sink=``).

    Thread-safe for concurrent tool calls within one process: records
    reach the sink one at a time. If the sink raises, the record is
    written to stderr as one JSON line with a ``sink_error`` field naming
    the exception type, and the call goes on; the gate never drops a line
    silently, and never fails a call because its log did.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        stream: TextIO | None = None,
        sink: AuditSink | None = None,
    ) -> None:
        given = sum(x is not None for x in (path, stream, sink))
        if given != 1:
            raise ValueError("provide exactly one of `path`, `stream` or `sink`")
        if sink is not None and not callable(getattr(sink, "write", None)):
            raise TypeError("sink must have a write(record) method; wrap a function in CallableSink")
        self._lock = threading.Lock()
        self.sink: AuditSink = sink if sink is not None else JsonlSink(path=path, stream=stream)
        """Where the records go."""
        self.path: Path | None = getattr(self.sink, "path", None) if sink is None else None
        """Absolute path of the log file, or ``None`` when not writing to one."""

    def record(self, **event: Any) -> None:
        """Append one event. A ``ts`` field (UTC, ISO-8601) is added first."""
        record = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), **event}
        with self._lock:
            try:
                self.sink.write(record)
            except Exception as exc:
                _to_stderr(record, exc)

    def close(self) -> None:
        close = getattr(self.sink, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _to_stderr(record: dict[str, Any], exc: BaseException) -> None:
    """The sink failed: the record goes to stderr, saying so. Only the
    exception type, as everywhere else: error text loves to embed the
    values the record redacted."""
    try:
        sys.stderr.write(_line({**record, "sink_error": type(exc).__name__}))
        sys.stderr.flush()
    except Exception:
        pass  # nowhere left to write; nothing can be done about that here


class NullAuditLog(AuditLog):
    """An audit log that swallows everything. For tests and dry runs."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())

    def record(self, **event: Any) -> None:  # noqa: D102 — intentionally inert
        pass
