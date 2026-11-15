"""Redaction reaches every shape an argument or record can take, and shows
values the approval must see change as what they are."""

from __future__ import annotations

import enum
import io
import json
import uuid
from typing import NamedTuple

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import DEFAULT_REDACT, AccessTier, AuditLog, Policy, redact_arguments
from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio


class Creds(NamedTuple):
    user: str
    password: str


def test_namedtuple_field_names_are_redacted():
    """'Matching is by whole key name at any nesting depth'. A NamedTuple
    has named fields, but is recursed as a bare list, so the name is lost."""
    out = redact_arguments({"creds": Creds("bob", "hunter2")}, DEFAULT_REDACT)
    assert "hunter2" not in json.dumps(out), out


async def test_namedtuple_secret_reaches_audit_end_to_end():
    stream = io.StringIO()
    mcp = MCPServer("redaction")
    gate = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=stream))

    @gate.tool(tier=AccessTier.READ)
    def login(creds: Creds) -> str:
        return "ok"

    async with Client(mcp) as client:
        await client.call_tool("login", {"creds": ["bob", "hunter2"]})
    assert "hunter2" not in stream.getvalue(), stream.getvalue()



@pytest.mark.parametrize("value", [b"hi", bytearray(b"hi"), memoryview(b"hi")])
def test_byte_buffers_are_opaque(value):
    out = redact_arguments({"blob": value}, DEFAULT_REDACT)
    assert out == {"blob": f"«opaque:{type(value).__name__}»"}


class Status(enum.Enum):
    PACKED = "packed"


def test_enums_uuids_and_infinities_read_as_values():
    out = redact_arguments(
        {"status": Status.PACKED, "ref": uuid.UUID(int=1), "amount": float("inf"), "nan": float("nan")},
        DEFAULT_REDACT,
    )
    assert out == {"status": "packed", "ref": str(uuid.UUID(int=1)), "amount": "inf", "nan": "nan"}
    json.dumps(out, allow_nan=False)  # strict JSON
