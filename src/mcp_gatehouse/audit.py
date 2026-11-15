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
import signal
import sys
import threading
import time
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

    A file opened here (``path=``) gets each record as one unbuffered
    ``os.write`` of the whole line, in append mode, so the file only ever
    holds whole lines. When a write fails part way (the disk is full), what
    it wrote is cut off again before the error is raised: the record goes
    to stderr with ``sink_error`` as with any failing sink, and never turns
    up in the file later as well. Nothing is held back in a buffer, so a
    crash loses no line already written. The file is closed by
    :meth:`close`.

    A stream passed in (``stream=``) is written and flushed on every
    record, and left to its owner; a failure part way through is that
    stream's to handle.
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
        self._stream: TextIO | None = None
        self._fd: int | None = None
        self._lock = threading.Lock()
        if path is not None:
            p = Path(path).expanduser().absolute()
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o666)
            self.path = p
        else:
            assert stream is not None
            self._stream = stream

    def write(self, record: dict[str, Any]) -> None:
        if self._stream is not None:
            self._stream.write(_line(record))
            self._stream.flush()
            return
        data = _line(record).encode("utf-8")
        with self._lock:
            if self._fd is None:
                raise ValueError("I/O operation on closed file")
            _append_whole(self._fd, data)

    def close(self) -> None:
        with self._lock:
            fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)


def _append_whole(fd: int, data: bytes) -> None:
    """Append ``data`` to the file, all of it or none of it.

    ``os.write`` may write part of it and then fail (a full disk, a file
    size limit). The bytes it did write would be a torn line, so they are
    cut off again: the file goes back to its size before this record,
    unless something else has appended since, in which case it is left
    alone rather than cut into someone else's line."""
    before = os.fstat(fd).st_size
    written = 0
    try:
        while written < len(data):
            written += os.write(fd, data[written:])
    except OSError:
        if written:
            try:
                if os.fstat(fd).st_size == before + written:
                    os.ftruncate(fd, before)
            except OSError:
                pass  # the write's own error is the one to report
        raise


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

    Python's default SIGTERM ends the process without running exit hooks,
    so a buffer created on the main thread installs a SIGTERM handler,
    unless one is already set (yours is never replaced). On SIGTERM it
    writes every record still queued to stderr with ``sink_error:
    "terminated"``, then lets the default SIGTERM end the process. The
    record being written at that moment goes to stderr too, so it may also
    be in ``inner``. To drain into ``inner`` instead, handle SIGTERM
    yourself and call :meth:`AuditLog.close` from it.

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
        self._writing: Any = None  # the record the thread is handing to inner
        self._terminating = False  # SIGTERM: the thread must hand nothing more to inner
        self._thread = threading.Thread(target=self._drain, name="mcp-gatehouse-audit", daemon=True)
        self._thread.start()
        _OPEN_BUFFERS.add(self)
        _handle_sigterm()

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
            self._writing = record
            if self._terminating:
                # The process is being terminated and would end in the
                # middle of this write. _spill sees the record here and
                # puts it on stderr instead.
                return
            try:
                self.inner.write(record)
            except BaseException as exc:
                # BaseException too: a CancelledError from a sink posting
                # through a loop that is shutting down would otherwise end
                # this thread, and every later record would queue unread.
                _to_stderr(record, exc)
            finally:
                self._writing = None

    def _spill(self) -> None:
        """The process is being terminated: every record not yet written
        goes to stderr, the one being written included.

        Runs in a signal handler, which may have interrupted the main
        thread anywhere, even inside this buffer's locks or a write to
        stderr, so it takes no lock: flag assignments, items popped
        straight off the queue's deque, and raw writes to file descriptor 2.

        The thread keeps running meanwhile. Once it sees the flag it takes
        at most one more record and stops before writing it, leaving it in
        ``_writing``; so the queue and ``_writing`` are read again until a
        pass finds nothing new, with a short pause between passes that
        lets the thread get there."""
        self._terminating = True
        self._closed = True
        spilled: dict[int, Any] = {}  # by identity; holding each keeps its id unique

        def out(record: Any) -> None:
            if record is not None and record is not _STOP and id(record) not in spilled:
                spilled[id(record)] = record
                _spill_line(record)

        quiet = 0
        while quiet < 2:
            before = len(spilled)
            out(self._writing)
            while True:
                try:
                    out(self._queue.queue.popleft())
                except IndexError:
                    break
            quiet = quiet + 1 if len(spilled) == before else 0
            if quiet < 2:
                time.sleep(0.01)

    def close(self) -> None:
        """Write everything queued so far, stop the thread, close ``inner``."""
        with self._closing:
            with self._state:
                if self._closed:
                    return
                self._closed = True
            # Nothing is queued after the flag. While the queue is full this
            # waits for the thread to empty it, and every record already
            # accepted is written before the stop; a thread that is gone
            # can't, so then it doesn't wait.
            while self._thread.is_alive():
                try:
                    self._queue.put(_STOP, timeout=0.1)
                    break
                except queue.Full:
                    continue
            self._thread.join()
            # Only now: a SIGTERM while this drains (at exit, say) must
            # still find what is left of the queue.
            _OPEN_BUFFERS.discard(self)
            close = getattr(self.inner, "close", None)
            if callable(close):
                close()


# Buffers not yet closed. A plain set: the running thread holds its
# buffer anyway, so a weak reference would keep nothing shorter.
_OPEN_BUFFERS: "set[BufferedSink]" = set()


def _handle_sigterm() -> None:
    """Install the SIGTERM handler, if this is the main thread and nothing
    else handles SIGTERM. A handler already there, the user's or a web
    server's, is left alone."""
    if not hasattr(signal, "SIGTERM") or threading.current_thread() is not threading.main_thread():
        return
    try:
        if signal.getsignal(signal.SIGTERM) is signal.SIG_DFL:
            signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):
        pass  # not allowed here (an embedded interpreter); exit hooks still run on a clean exit


def _on_sigterm(signum: int, frame: Any) -> None:
    """Records still queued go to stderr, then the default SIGTERM."""
    for sink in list(_OPEN_BUFFERS):
        try:
            sink._spill()
        except Exception:
            pass
    _OPEN_BUFFERS.clear()
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTERM)


def _spill_line(record: dict[str, Any]) -> None:
    try:
        data = _line({**record, "sink_error": "terminated"}).encode("utf-8")
        while data:
            data = data[os.write(2, data):]
    except Exception:
        pass  # nowhere left to write


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
        self.path: Path | None = self.sink.path if isinstance(self.sink, JsonlSink) else None
        """Absolute path of the log file, or ``None`` when not writing to one
        (a stream, or a sink other than a ``JsonlSink`` on a file)."""

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
