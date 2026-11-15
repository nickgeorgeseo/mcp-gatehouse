import json
from pathlib import Path

import jsonschema
import pytest

from mcp_gatehouse import AuditLog

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "audit-line.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
jsonschema.Draft202012Validator.check_schema(SCHEMA)
AUDIT_LINE = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def every_audit_line_matches_the_schema(monkeypatch):
    """Every record any test's gate writes is checked against the documented
    schema, as a JSON reader would see it: the README's table and
    docs/audit-line.schema.json can't drift from the code unnoticed."""
    original = AuditLog.record
    problems: list[str] = []

    def record(self, **event):
        original(self, **event)
        try:
            # allow_nan=False: strict JSON readers (jq, JSON.parse) reject
            # NaN and Infinity, so a line carrying them isn't a valid line.
            text = json.dumps(
                {"ts": "2026-01-01T00:00:00+00:00", **event}, ensure_ascii=True, default=str, allow_nan=False
            )
        except ValueError as exc:
            problems.append(f"not strict JSON ({exc}) in {event}")
            return
        as_read = json.loads(text)
        for error in AUDIT_LINE.iter_errors(as_read):
            problems.append(f"{error.json_path}: {error.message} in {as_read}")

    monkeypatch.setattr(AuditLog, "record", record)
    yield
    assert not problems, "audit lines off the documented schema:\n" + "\n".join(problems)
