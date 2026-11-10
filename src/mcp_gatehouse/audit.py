"""The audit log: one record per tool call, handed to a sink.

One record per tool call — allowed, denied, failed, pending or cancelled —
with a UTC timestamp and redacted arguments. The point is a trail you can
grep six months later when someone asks "what did the AI actually do?"

The default sink is an append-only JSONL file. A sink is anything with a
``write(record)`` method (:class:`AuditSink`), so the same records can go
to a logging pipeline, OpenTelemetry, or an HTTP collector instead. Wrap
a slow one in :class:`BufferedSink` to write it off the request path. The
record's fields are documented in the README and in
``docs/audit-line.schema.json``.
"""

from __future__ import annotations

import atexit
import datetime as _dt
import io
import json
import os
import queue
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


_STOP = object()


class BufferedSink:
    """Hands records to ``inner`` from one background thread, so a slow
    sink never slows a call.

    ``write`` puts the record on a bounded queue and returns at once. One
    thread takes records off in order and writes them to ``inner``. When
    the queue is full, the record doesn't wait for room: it goes to stderr
    as one JSON line with ``sink_error: "queue full"``, and the call goes
    on. Nothing is dropped silently, but stderr is then the only copy of
    that line, so size ``maxsize`` for the bursts you expect and watch
    stderr for ``sink_error``.

    If ``inner`` raises, the record goes to stderr with ``sink_error``
    naming the exception type, as with any sink. :meth:`close` drains the
    queue, waiting for every record written before it, then closes
    ``inner`` if it has a ``close()``. It also runs at interpreter exit for
    a sink nobody closed. A record written after close goes to stderr with
    ``sink_error: "sink closed"``.

    Standard library only: one ``queue.Queue`` and one daemon thread.
    """

    def __init__(self, inner: AuditSink, *, maxsize: int = 10_000) -> None:
        if not callable(getattr(inner, "write", None)):
            raise TypeError("inner must have a write(record) method; wrap a function in CallableSink")
        if isinstance(maxsize, bool) or not isinstance(maxsize, int) or maxsize < 1:
            raise ValueError("maxsize must be a positive int: an unbounded queue can grow without limit")
        self.inner = inner
        """Where the records go, one at a time, from the background thread."""
        self.maxsize = maxsize
        self._queue: queue.Queue[Any] = queue.Queue(maxsize)
        self._state = threading.Lock()  # write's check-and-put against close's flag
        self._closing = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._drain, name="mcp-gatehouse-audit", daemon=True)
        self._thread.start()
        _OPEN_BUFFERS.add(self)

    def write(self, record: dict[str, Any]) -> None:
        with self._state:
            if not self._closed:
                try:
                    self._queue.put_nowait(record)
                    return
                except queue.Full:
                    why = "queue full"
            else:
                why = "sink closed"
        _to_stderr(record, why)

    def _drain(self) -> None:
        while True:
            record = self._queue.get()
            if record is _STOP:
                return
            try:
                self.inner.write(record)
            except Exception as exc:
                _to_stderr(record, exc)

    def close(self) -> None:
        """Write everything queued so far, stop the thread, close ``inner``."""
        with self._closing:
            with self._state:
                if self._closed:
                    return
                self._closed = True
            _OPEN_BUFFERS.discard(self)
            # Nothing is queued after the flag. This put blocks while the
            # queue is full: the thread is emptying it, and every record
            # already accepted is written before the stop.
            self._queue.put(_STOP)
            self._thread.join()
            close = getattr(self.inner, "close", None)
            if callable(close):
                close()


# Buffers not yet closed. A plain set: the running thread holds its
# buffer anyway, so a weak reference would keep nothing shorter.
_OPEN_BUFFERS: "set[BufferedSink]" = set()


@atexit.register
def _close_at_exit() -> None:
    """Drain every buffer nobody closed, so the tail of the trail isn't lost
    with the daemon thread."""
    for sink in list(_OPEN_BUFFERS):
        try:
            sink.close()
        except Exception:
            pass  # a failing inner close() must not stop the others draining


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


def _to_stderr(record: dict[str, Any], error: BaseException | str) -> None:
    """The sink failed: the record goes to stderr, saying so. For an
    exception, only its type, as everywhere else: error text loves to
    embed the values the record redacted. A string is the gate's own
    reason (``"queue full"``)."""
    why = error if isinstance(error, str) else type(error).__name__
    try:
        sys.stderr.write(_line({**record, "sink_error": why}))
        sys.stderr.flush()
    except Exception:
        pass  # nowhere left to write; nothing can be done about that here


class NullAuditLog(AuditLog):
    """An audit log that swallows everything. For tests and dry runs."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())

    def record(self, **event: Any) -> None:  # noqa: D102 — intentionally inert
        pass
