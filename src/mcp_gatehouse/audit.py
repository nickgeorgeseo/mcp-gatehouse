"""Append-only JSONL audit log.

One line per tool call — allowed, denied, or failed — with UTC timestamps
and redacted arguments. The point is a trail you can grep six months later
when someone asks "what did the AI actually do?"
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import threading
from pathlib import Path
from typing import Any, TextIO


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
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._stream: TextIO = p.open("a", encoding="utf-8")
            self._owns_stream = True
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
        event = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), **event}
        line = json.dumps(event, ensure_ascii=True, default=str)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()

    def close(self) -> None:
        if self._owns_stream:
            self._stream.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class NullAuditLog(AuditLog):
    """An audit log that swallows everything. For tests and dry runs."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())

    def record(self, **event: Any) -> None:  # noqa: D102 — intentionally inert
        pass
