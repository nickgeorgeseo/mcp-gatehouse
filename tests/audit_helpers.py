"""Reading an AuditLog's lines back, for tests that log to a StringIO."""

from __future__ import annotations

import io
import json
import re
from typing import Any

CALL_ID = re.compile(r"[0-9a-f]{16}")


def events(stream: io.StringIO) -> list[dict[str, Any]]:
    """The records written to ``stream``, oldest first.

    Split on ``\\n`` only, never ``splitlines()``: the log promises exactly
    one ``\\n`` per record, and ``splitlines()`` would also break a line at
    U+2028 and its kin, which an argument value may contain.
    """
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def without_call_id(event: dict[str, Any]) -> dict[str, Any]:
    """``event`` without its ``call_id``, once that's checked to be one.
    For comparing a whole line: the id is random."""
    event = dict(event)
    assert CALL_ID.fullmatch(event.pop("call_id"))
    return event


def outcomes(stream: io.StringIO) -> list[tuple[str, str | None]]:
    """``(outcome, reason)`` for each record in ``stream``, oldest first."""
    return [(event["outcome"], event.get("reason")) for event in events(stream)]
