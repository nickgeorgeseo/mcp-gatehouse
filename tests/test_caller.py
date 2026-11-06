"""The caller: who a call is for, from the request's verified access token.

Most tests sign in by setting the SDK's auth context directly, as its auth
middleware does for each HTTP request. The last ones run a real
streamable-HTTP server with a token verifier, so the whole path is covered:
bearer header, verification, the tool call, the audit line.
"""

from __future__ import annotations

import io
import json
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client, MCPError
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult, InputRequiredResult

from mcp_gatehouse import (
    AccessTier, ApprovalRequest, AuditLog, Caller, ElicitationApprover, Policy,
)
from mcp_gatehouse.approvers import _for_whom

from _support import ISSUER, LOCAL, LOCAL_ENTRY, bearer, http_server, signed_in, token
from _support import OpenGatehouse as Gatehouse


def build(policy: Policy, log: io.StringIO, name: str = "caller-test", **gate: Any) -> MCPServer:
    mcp = MCPServer(name)
    gk = Gatehouse(mcp, policy=policy, audit=AuditLog(stream=log), **gate)

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


async def approve_in_client(context: Any, params: Any) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True})


ALICE = {"client_id": "support-agent", "subject": "alice", "issuer": ISSUER, "scopes": ["orders:read"]}


@pytest.mark.anyio
async def test_no_caller_is_denied_before_anything_runs():
    """Nobody signed in and no local caller declared: every call fails closed,
    and neither the approver nor the tool is reached."""
    log, seen = io.StringIO(), []
    server = build(Policy(approver=alice_only(seen)), log, local_caller=None)
    async with Client(server) as session:
        for name in ("lookup", "cancel"):
            result = await session.call_tool(name, {"order_id": "4417"})
            assert result.is_error
            assert "needs a verified caller" in result.content[0].text
    assert seen == []
    assert [(e["tool"], e["outcome"], e["reason"]) for e in events(log)] == [
        ("lookup", "denied", "no verified caller"),
        ("cancel", "denied", "no verified caller"),
    ]
    assert all("caller" not in event for event in events(log))


@pytest.mark.anyio
async def test_the_declared_local_caller_is_named_on_every_line():
    """Over stdio or in memory, the server's declared local caller is who
    the call is for: the approver gets it, and the log marks it local."""
    log, seen = io.StringIO(), []
    server = build(Policy(approver=alice_only(seen)), log)
    async with Client(server) as session:
        await session.call_tool("lookup", {"order_id": "4417"})
        await session.call_tool("cancel", {"order_id": "4417"})
    assert seen == [LOCAL]
    assert [event["caller"] for event in events(log)] == [LOCAL_ENTRY, LOCAL_ENTRY]


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
    assert all(line["caller"] == ALICE for line in lines)
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
async def test_an_approval_asked_in_the_client_names_the_caller_both_times():
    """The 2026-07-28 round trip writes two lines: `pending`, then the verdict."""
    log = io.StringIO()
    server = build(Policy(approver=ElicitationApprover()), log)
    with signed_in(token("alice")):
        async with Client(server, elicitation_callback=approve_in_client) as session:
            result = await session.call_tool("cancel", {"order_id": "4417"})
    assert not result.is_error
    lines = events(log)
    assert [line["outcome"] for line in lines] == ["pending", "ok"]
    assert all(line["caller"] == ALICE for line in lines)


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["awaiting approval", "tool running"])
async def test_cancelled_calls_name_the_caller(phase):
    started = anyio.Event()

    async def slow_human(request: ApprovalRequest) -> bool:
        started.set()
        await anyio.sleep_forever()

    async def instant_yes(request: ApprovalRequest) -> bool:
        return True

    log = io.StringIO()
    mcp = MCPServer("cancel-test")
    approver = slow_human if phase == "awaiting approval" else instant_yes
    gk = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=log))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    async def cancel(order_id: str) -> str:
        """Cancel an order, slowly."""
        started.set()
        await anyio.sleep_forever()

    with signed_in(token("alice")):
        async with Client(mcp) as client:
            async with anyio.create_task_group() as tg:
                tg.start_soon(client.call_tool, "cancel", {"order_id": "4417"})
                with anyio.fail_after(5):
                    await started.wait()
                tg.cancel_scope.cancel()

    (line,) = events(log)
    assert (line["outcome"], line["reason"]) == ("cancelled", phase)
    assert line["caller"] == ALICE


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


# --- the line terminal_approver adds to its prompt -----------------------------


def test_terminal_prompt_says_who_the_call_is_for():
    assert _for_whom(None) == ""
    alice = Caller(client_id="support-agent", subject="alice")
    assert _for_whom(alice) == '\n  for "alice" via client "support-agent"'
    nameless = Caller(client_id="support-agent")
    assert "a user the token doesn't name" in _for_whom(nameless)


def test_terminal_prompt_escapes_control_characters_in_names():
    # A subject that tries to clear the line and redraw the prompt.
    sneaky = Caller(client_id="app\x1b[2K\x7f", subject="mallory\r\x1b[1A‮\x9b")
    line = _for_whom(sneaky)
    for raw in ("\x1b", "\r", "‮", "\x9b", "\x7f"):
        assert raw not in line
    assert "\\u001b" in line and "\\u007f" in line


def test_a_quote_in_a_name_cant_fake_the_rest_of_the_line():
    forged = Caller(client_id="evil", subject='alice" via client "support-agent')
    line = _for_whom(forged)
    # The whole name stays inside one pair of quotes, and the real client follows.
    assert line == '\n  for "alice\\" via client \\"support-agent" via client "evil"'


def test_look_alike_and_blank_characters_show_as_escapes():
    # Cyrillic "а" for Latin "a", and a Hangul filler that renders blank.
    line = _for_whom(Caller(client_id="support-agent", subject="аliceㅤ"))
    assert line.startswith('\n  for "\\u0430lice\\u3164"')


def test_long_names_are_cut():
    line = _for_whom(Caller(client_id="support-agent", subject="a" * 500))
    assert len(line) < 150 and '"…' in line


# --- over real HTTP ------------------------------------------------------------


def signed_in_server(url: str, tokens: dict[str, AccessToken], name: str) -> MCPServer:
    class Verifier:
        async def verify_token(self, presented: str) -> AccessToken | None:
            return tokens.get(presented)

    return MCPServer(
        name, token_verifier=Verifier(), auth=AuthSettings(issuer_url=ISSUER, resource_server_url=url)
    )


@pytest.mark.anyio
# Newer SDKs nag about AuthSettings.validate_token_resource, which 2.0 doesn't have.
@pytest.mark.filterwarnings("ignore:.*validate_token_resource")
async def test_each_http_request_is_logged_for_its_own_caller():
    """Real bearer auth over streamable HTTP: two users, one token refresh."""
    log, seen = io.StringIO(), []

    def app(url: str):
        tokens = {
            "alice-1": token("alice", resource=url),
            "alice-2": token("alice", ("orders:read", "orders:write"), resource=url),
            "bob-1": token("bob", resource=url),
        }
        mcp = signed_in_server(url, tokens, "caller-http")
        gk = Gatehouse(mcp, policy=Policy(approver=alice_only(seen)), audit=AuditLog(stream=log))

        @gk.tool(tier=AccessTier.READ)
        def lookup(order_id: str) -> str:
            """Look up an order."""
            return f"order {order_id}"

        @gk.tool(tier=AccessTier.DESTRUCTIVE)
        async def cancel(order_id: str) -> str:
            """Cancel an order."""
            return f"order {order_id} cancelled"

        return mcp.streamable_http_app()

    async def call(url: str, http: httpx2.AsyncClient, *calls: tuple[str, str]) -> None:
        async with streamable_http_client(url, http_client=http) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for tool, order_id in calls:
                    await session.call_tool(tool, {"order_id": order_id})
                    if http.headers["Authorization"] == "Bearer alice-1":
                        # The client refreshes its token mid-session.
                        http.headers["Authorization"] = "Bearer alice-2"

    async with http_server(app) as url:
        async with bearer("alice-1") as alice:
            await call(url, alice, ("lookup", "1"), ("cancel", "1"))
        async with bearer("bob-1") as bob:
            await call(url, bob, ("cancel", "2"))

    lines = events(log)
    assert [(e["tool"], e["outcome"], e["caller"]["subject"], e["caller"]["scopes"]) for e in lines] == [
        ("lookup", "ok", "alice", ["orders:read"]),
        ("cancel", "ok", "alice", ["orders:read", "orders:write"]),
        ("cancel", "denied", "bob", ["orders:read"]),
    ]
    assert [c.subject for c in seen] == ["alice", "bob"]
    assert "secret-token" not in log.getvalue()


@pytest.mark.anyio
@pytest.mark.filterwarnings("ignore:.*validate_token_resource")
async def test_an_approval_asked_over_http_stays_with_its_caller():
    """The round trip over HTTP: the question goes out in one request and the
    answer comes back in another. Both lines name alice, and bob can't spend
    her approval by replaying it."""
    log, ran = io.StringIO(), []

    def app(url: str):
        tokens = {"alice-1": token("alice", resource=url), "bob-1": token("bob", resource=url)}
        mcp = signed_in_server(url, tokens, "caller-round-trip")
        gk = Gatehouse(mcp, policy=Policy(approver=ElicitationApprover()), audit=AuditLog(stream=log))

        @gk.tool(tier=AccessTier.DESTRUCTIVE)
        async def cancel(order_id: str) -> str:
            """Cancel an order."""
            ran.append(order_id)
            return f"order {order_id} cancelled"

        return mcp.streamable_http_app()

    arguments = {"order_id": "4417"}
    async with http_server(app) as url:
        async with bearer("alice-1") as alice_http, bearer("bob-1") as bob_http:
            # The callback declares that these clients can show a form; this
            # test answers the question itself, so it is never called.
            async with Client(
                streamable_http_client(url, http_client=alice_http), elicitation_callback=approve_in_client
            ) as alice, Client(
                streamable_http_client(url, http_client=bob_http), elicitation_callback=approve_in_client
            ) as bob:
                question = await alice.session.call_tool("cancel", arguments, allow_input_required=True)
                assert isinstance(question, InputRequiredResult)
                (key,) = question.input_requests
                answer = {key: ElicitResult(action="accept", content={"approve": True})}

                with pytest.raises(MCPError):
                    await bob.session.call_tool(
                        "cancel", arguments, input_responses=answer,
                        request_state=question.request_state, allow_input_required=True,
                    )
                assert ran == []

                result = await alice.session.call_tool(
                    "cancel", arguments, input_responses=answer, request_state=question.request_state,
                )
    assert not result.is_error and ran == ["4417"]
    lines = events(log)
    assert [(line["outcome"], line["caller"]["subject"]) for line in lines] == [
        ("pending", "alice"), ("ok", "alice"),
    ]
