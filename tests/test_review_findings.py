"""Regression tests for the pre-publication security review findings.

Each test pins one reviewed hole shut. If any of these break, a finding
has been reintroduced — do not release.
"""

from __future__ import annotations

import dataclasses
import io
import json
import logging

import pytest
from mcp import Client
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

from mcp_gatehouse import AccessTier, AuditLog, GateDenied, Gatehouse, Policy
from mcp_gatehouse.policy import DEFAULT_REDACT, REDACTED, redact_arguments


def events(stream: io.StringIO) -> list[dict]:
    # split("\n"), not splitlines(): U+2028 etc. must not create records.
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


class Creds(BaseModel):
    username: str
    password: str


@dataclasses.dataclass
class DcCreds:
    username: str
    token: str


# --- Finding 1: redaction must reach inside structured argument values ---

def test_pydantic_model_secrets_are_redacted():
    safe = redact_arguments(
        {"creds": Creds(username="u", password="hunter2")}, DEFAULT_REDACT
    )
    assert safe["creds"]["password"] == REDACTED
    assert safe["creds"]["username"] == "u"


def test_dataclass_secrets_are_redacted():
    safe = redact_arguments(
        {"creds": DcCreds(username="u", token="t-tok")}, DEFAULT_REDACT
    )
    assert safe["creds"]["token"] == REDACTED


def test_opaque_objects_never_pass_through():
    class Mystery:
        def __repr__(self) -> str:
            return "Mystery(password='leaky')"

    safe = redact_arguments({"thing": Mystery(), "blob": b"raw"}, DEFAULT_REDACT)
    assert "leaky" not in json.dumps(safe)
    assert safe["thing"] == "«opaque:Mystery»"
    assert safe["blob"] == "«opaque:bytes»"


def test_tuples_and_sets_are_recursed():
    safe = redact_arguments({"batch": ({"api_key": "k"},)}, DEFAULT_REDACT)
    assert safe["batch"][0]["api_key"] == REDACTED


@pytest.mark.anyio
async def test_model_argument_secret_never_reaches_log_end_to_end():
    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.WRITE)
    def connect(creds: Creds) -> str:
        """Connect somewhere."""
        return "ok"

    async with Client(mcp) as session:
        result = await session.call_tool(
            "connect", {"creds": {"username": "u", "password": "hunter2"}}
        )
    assert result.is_error is False
    assert "hunter2" not in log.getvalue()


# --- Finding 2: exception messages must not leak argument values ---

@pytest.mark.anyio
async def test_exception_text_stays_out_of_the_audit_log():
    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.READ)
    def check(api_key: str) -> str:
        """Validate a key."""
        raise ValueError(f"invalid api key: {api_key!r}")

    async with Client(mcp) as session:
        await session.call_tool("check", {"api_key": "sk-live-SECRET"})
    (event,) = events(log)
    assert event["outcome"] == "error"
    assert event["reason"] == "ValueError"
    assert "SECRET" not in log.getvalue()


# --- Finding 4: line-separator characters must not split audit records ---

def test_unicode_line_separators_cannot_forge_records():
    log = io.StringIO()
    audit = AuditLog(stream=log)
    evil = 'x {"ts":"0","tool":"forged","outcome":"ok"}'
    audit.record(tool="real", outcome="ok", arguments={"note": evil})
    raw = log.getvalue()
    assert raw.count("\n") == 1
    assert len(raw.splitlines()) == 1  # even line-aware readers see ONE record
    (event,) = events(log)
    assert event["tool"] == "real"


# --- Finding 5: MCPServer's injected Context stays out of the audit trail ---

@pytest.mark.anyio
async def test_injected_context_not_recorded_or_shown_to_approver():
    log = io.StringIO()
    seen: list[dict] = []

    def approver(request) -> bool:
        seen.append(request.arguments)
        return True

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def wipe(target: str, ctx: Context) -> str:
        """Wipe a target."""
        return f"wiped {target}"

    async with Client(mcp) as session:
        result = await session.call_tool("wipe", {"target": "db"})
    assert result.is_error is False
    (event,) = events(log)
    assert event["arguments"] == {"target": "db"}
    assert seen == [{"target": "db"}]


# --- Finding 6: @tool without parentheses must fail loudly ---

def test_bare_decorator_raises():
    gk = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError, match="parentheses"):

        @gk.tool
        def oops() -> str:
            return "silently unregistered"


# --- Finding 7: a denial reaches the model as its reason, not as a crash ---
#
# SDK v2 splits tool exceptions into anticipated failures (`ToolError`: the
# message reaches the model, logged at INFO) and crashes (everything else:
# the model gets a generic "Error executing tool <name>" and the server logs
# a traceback at ERROR). A GateDenied that is not a ToolError silently lands
# in the crash bucket, which withholds the reason the gate exists to give
# and floods the log with ERRORs on every routine refusal.

def test_gate_denied_is_both_permission_error_and_tool_error():
    """Both bases are load-bearing; neither may be dropped."""
    denial = GateDenied("nope")
    # The SDK reads this to classify the failure as anticipated.
    assert isinstance(denial, ToolError)
    # The documented public type. Existing `except PermissionError` must hold.
    assert isinstance(denial, PermissionError)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("policy", "tool_name", "expected"),
    [
        (Policy(deny=frozenset({"wipe"})), "wipe", "blocked by policy"),
        (Policy(), "wipe", "requires approval"),
        (Policy(approver=lambda r: False), "wipe", "refused by the approver"),
    ],
    ids=["denylist", "fails-closed", "approver-refused"],
)
async def test_denial_reason_reaches_the_client(policy, tool_name, expected):
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=io.StringIO()))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def wipe(target: str) -> str:
        """Wipe a target."""
        return f"wiped {target}"

    async with Client(mcp) as session:
        result = await session.call_tool(tool_name, {"target": "db"})

    assert result.is_error is True
    text = result.content[0].text
    assert expected in text, f"denial reason withheld from the model: {text!r}"
    # The generic crash message means the SDK classified this as a crash.
    assert text != f"Error executing tool {tool_name}"


@pytest.mark.anyio
async def test_denial_is_not_logged_as_a_server_crash(caplog):
    """A gate refusing on purpose is not an ERROR."""
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=io.StringIO()))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def wipe(target: str) -> str:
        """Wipe a target."""
        return f"wiped {target}"

    with caplog.at_level(logging.ERROR, logger="mcp.server.mcpserver.server"):
        async with Client(mcp) as session:
            result = await session.call_tool("wipe", {"target": "db"})

    assert result.is_error is True
    assert caplog.records == [], (
        "denial logged as a server error: " f"{[r.getMessage() for r in caplog.records]}"
    )
