"""The caller: who a call is for, from the request's verified access token.

Most tests sign in by setting the SDK's auth context directly, as its auth
middleware does for each HTTP request. The last one runs a real
streamable-HTTP server with a token verifier, so the whole path is covered:
bearer header, verification, the tool call, the audit line.
"""

from __future__ import annotations

import contextlib
import io
import json
import socket

import anyio
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer

from mcp_gatehouse import AccessTier, ApprovalRequest, AuditLog, Caller, Gatehouse, Policy
from mcp_gatehouse.approvers import _for_whom

ISSUER = "https://idp.example"


def token(user: str, scopes: tuple[str, ...] = ("orders:read",), *, named: bool = True,
          resource: str | None = None) -> AccessToken:
    """A verified token for `user`; `named=False` is a verifier that sets no subject."""
    return AccessToken(
        token=f"secret-token-{user}",
        client_id="support-agent",
        scopes=list(scopes),
        subject=user if named else None,
        claims={"iss": ISSUER} if named else None,
        resource=resource,
    )


@contextlib.contextmanager
def signed_in(access_token: AccessToken):
    """What the SDK's AuthContextMiddleware does around each HTTP request."""
    reset = auth_context_var.set(AuthenticatedUser(access_token))
    try:
        yield
    finally:
        auth_context_var.reset(reset)


def build(policy: Policy, log: io.StringIO, name: str = "caller-test") -> MCPServer:
    mcp = MCPServer(name)
    gk = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.READ)
    def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}"

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    async def cancel(order_id: str) -> str:
        """Cancel an order."""
        return f"order {order_id} cancelled"

    @gk.tool(tier=AccessTier.READ)
    def broken() -> str:
        """Always fails."""
        raise RuntimeError("downstream exploded")

    return mcp


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


def alice_only(seen: list[Caller | None]):
    async def approver(request: ApprovalRequest) -> bool:
        seen.append(request.caller)
        return request.caller is not None and request.caller.subject == "alice"

    return approver


@pytest.mark.anyio
async def test_no_caller_without_authentication():
    log, seen = io.StringIO(), []
    server = build(Policy(approver=alice_only(seen)), log)
    async with Client(server) as session:
        await session.call_tool("lookup", {"order_id": "4417"})
        await session.call_tool("cancel", {"order_id": "4417"})
    assert seen == [None]
    # Lines stay exactly as they were before callers existed.
    assert all("caller" not in event for event in events(log))


@pytest.mark.anyio
async def test_caller_is_on_every_line_and_in_the_approval_request():
    log, seen = io.StringIO(), []
    server = build(Policy(approver=alice_only(seen)), log)
    with signed_in(token("alice")):
        async with Client(server) as session:
            await session.call_tool("lookup", {"order_id": "4417"})
            await session.call_tool("cancel", {"order_id": "4417"})
            await session.call_tool("broken", {})

    alice = Caller(client_id="support-agent", subject="alice", issuer=ISSUER, scopes=("orders:read",))
    assert seen == [alice]
    lines = events(log)
    assert [e["outcome"] for e in lines] == ["ok", "ok", "error"]
    for line in lines:
        assert line["caller"] == {
            "client_id": "support-agent", "subject": "alice", "issuer": ISSUER, "scopes": ["orders:read"],
        }
    # Who, never the credential.
    assert "secret-token" not in log.getvalue()


@pytest.mark.anyio
async def test_denials_name_the_caller_too():
    log = io.StringIO()
    refused = build(Policy(approver=alice_only([])), log)
    no_approver = build(Policy(), log, name="no-approver")
    with signed_in(token("bob")):
        async with Client(refused) as session:
            await session.call_tool("cancel", {"order_id": "4417"})
        async with Client(no_approver) as session:
            await session.call_tool("cancel", {"order_id": "4418"})
    first, second = events(log)
    assert (first["outcome"], first["reason"]) == ("denied", "approver refused")
    assert second["outcome"] == "denied" and "no approver" in second["reason"]
    assert first["caller"]["subject"] == second["caller"]["subject"] == "bob"


@pytest.mark.anyio
async def test_a_token_without_a_subject_names_only_the_client():
    log = io.StringIO()
    server = build(Policy(), log)
    with signed_in(token("ignored", named=False)):
        async with Client(server) as session:
            await session.call_tool("lookup", {"order_id": "4417"})
    (line,) = events(log)
    assert line["caller"] == {
        "client_id": "support-agent", "subject": None, "issuer": None, "scopes": ["orders:read"],
    }


def test_approval_requests_built_without_a_caller_still_work():
    request = ApprovalRequest(tool="cancel", tier=AccessTier.DESTRUCTIVE, arguments={})
    assert request.caller is None


def test_terminal_prompt_says_who_the_call_is_for():
    assert _for_whom(None) == ""
    alice = Caller(client_id="support-agent", subject="alice")
    assert _for_whom(alice) == "\n  for 'alice' via client 'support-agent'"
    nameless = Caller(client_id="support-agent")
    assert "a user the token doesn't name" in _for_whom(nameless)


def test_terminal_prompt_escapes_control_characters_in_names():
    # A subject that tries to clear the line and redraw the prompt.
    sneaky = Caller(client_id="app\x1b[2K", subject="mallory\r\x1b[1A‮")
    line = _for_whom(sneaky)
    assert "\x1b" not in line and "\r" not in line and "‮" not in line
    assert "\\x1b" in line


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.anyio
# Newer SDKs nag about AuthSettings.validate_token_resource, which 2.0 doesn't have.
@pytest.mark.filterwarnings("ignore:.*validate_token_resource")
async def test_each_http_request_is_logged_for_its_own_caller():
    """Real bearer auth over streamable HTTP: two users, one token refresh."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    tokens = {
        "alice-1": token("alice", resource=url),
        "alice-2": token("alice", ("orders:read", "orders:write"), resource=url),
        "bob-1": token("bob", resource=url),
    }

    class Verifier:
        async def verify_token(self, presented: str) -> AccessToken | None:
            return tokens.get(presented)

    log, seen = io.StringIO(), []
    mcp = MCPServer(
        "caller-http",
        token_verifier=Verifier(),
        auth=AuthSettings(issuer_url=ISSUER, resource_server_url=url),
    )
    gk = Gatehouse(mcp, policy=Policy(approver=alice_only(seen)), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.READ)
    def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}"

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    async def cancel(order_id: str) -> str:
        """Cancel an order."""
        return f"order {order_id} cancelled"

    server = uvicorn.Server(
        uvicorn.Config(mcp.streamable_http_app(), host="127.0.0.1", port=port, log_level="warning")
    )

    async def call(http: httpx2.AsyncClient, *calls: tuple[str, str]) -> None:
        async with streamable_http_client(url, http_client=http) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for tool, order_id in calls:
                    await session.call_tool(tool, {"order_id": order_id})
                    if http.headers["Authorization"] == "Bearer alice-1":
                        # The client refreshes its token mid-session.
                        http.headers["Authorization"] = "Bearer alice-2"

    with anyio.fail_after(30):
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            while not server.started:
                await anyio.sleep(0.02)
            try:
                async with httpx2.AsyncClient(headers={"Authorization": "Bearer alice-1"}) as alice:
                    await call(alice, ("lookup", "1"), ("cancel", "1"))
                async with httpx2.AsyncClient(headers={"Authorization": "Bearer bob-1"}) as bob:
                    await call(bob, ("cancel", "2"))
            finally:
                server.should_exit = True

    lines = events(log)
    assert [(e["tool"], e["outcome"], e["caller"]["subject"], e["caller"]["scopes"]) for e in lines] == [
        ("lookup", "ok", "alice", ["orders:read"]),
        ("cancel", "ok", "alice", ["orders:read", "orders:write"]),
        ("cancel", "denied", "bob", ["orders:read"]),
    ]
    assert [c.subject for c in seen] == ["alice", "bob"]
    assert "secret-token" not in log.getvalue()
