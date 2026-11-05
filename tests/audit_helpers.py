"""Reading an AuditLog's lines back, for tests that log to a StringIO."""

from __future__ import annotations

import io
import json
from typing import Any


def events(stream: io.StringIO) -> list[dict[str, Any]]:
    """The records written to ``stream``, oldest first.

    Split on ``\\n`` only, never ``splitlines()``: the log promises exactly
    one ``\\n`` per record, and ``splitlines()`` would also break a line at
    U+2028 and its kin, which an argument value may contain.
    """
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def outcomes(stream: io.StringIO) -> list[tuple[str, str | None]]:
    """``(outcome, reason)`` for each record in ``stream``, oldest first."""
    return [(event["outcome"], event.get("reason")) for event in events(stream)]
