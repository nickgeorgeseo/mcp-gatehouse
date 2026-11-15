"""The OPA and Cerbos examples: what they send, how they read the answer,
and that an engine that can't be reached is a denial."""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import AccessTier, Allow, Ask, AuditLog, Caller, ConditionalWrite, Deny, Load, Policy
from mcp_gatehouse.authz import AuthorizationRequest

from _support import OpenGatehouse as Gatehouse

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def load(name: str):
    if str(EXAMPLES) not in sys.path:
        sys.path.insert(0, str(EXAMPLES))  # the examples import their shared _engine_http
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Order(BaseModel):
    id: str
    owner: str
    status: str
    total: float


ALICE = Caller(client_id="support-agent", subject="alice", issuer="https://idp.example", scopes=("orders:read",))
ORDER = Order(id="4417", owner="alice", status="packed", total=812.0)


def request(record: Any = ORDER, action: str = "call", tool: str = "cancel_order") -> AuthorizationRequest:
    return AuthorizationRequest(
        caller=ALICE, tool=tool, tier=AccessTier.DESTRUCTIVE, action=action, arguments={},
        resources={"order": record} if action == "call" else {}, resource=record if action == "read" else None,
    )


class FakeEngine:
    """An HTTP server answering every POST with whatever the test set."""

    def __init__(self) -> None:
        self.answer: Any = {}
        self.status = 200
        self.raw: bytes | None = None
        self.requests: list[tuple[str, dict]] = []
        engine = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                engine.requests.append((self.path, json.loads(body)))
                payload = engine.raw if engine.raw is not None else json.dumps(engine.answer).encode()
                self.send_response(engine.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def engine():
    fake = FakeEngine()
    yield fake
    fake.close()


def unused_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


# --- OPA -----------------------------------------------------------------------


def test_opa_sends_caller_tool_action_and_record(engine):
    engine.answer = {"result": {"effect": "allow"}}
    policy = load("policy_opa").opa_policy(engine.url)
    assert policy(request()) == Allow()
    (path, body), = engine.requests
    assert path == "/v1/data/gatehouse/decision"
    assert body == {
        "input": {
            "caller": {"client_id": "support-agent", "subject": "alice", "issuer": "https://idp.example", "scopes": ["orders:read"]},
            "tool": "cancel_order",
            "tier": "destructive",
            "action": "call",
            "record": {"id": "4417", "owner": "alice", "status": "packed", "total": 812.0},
        }
    }


def test_opa_item_checks_send_the_item(engine):
    engine.answer = {"result": {"effect": "allow"}}
    policy = load("policy_opa").opa_policy(engine.url)
    assert policy(request(action="read", tool="list_orders")) == Allow()
    (_, body), = engine.requests
    assert body["input"]["action"] == "read" and body["input"]["record"]["id"] == "4417"


@pytest.mark.parametrize(
    "result, decision",
    [
        ({"effect": "allow"}, Allow()),
        ({"effect": "deny", "reason": "someone else's order"}, Deny("someone else's order")),
        ({"effect": "ask", "reason": "order over $500"}, Ask("order over $500")),
        ({"effect": "maybe"}, Deny("policy engine returned an unknown effect: 'maybe'")),
        ({}, Deny("policy engine returned no decision")),
        (None, Deny("policy engine returned no decision")),
    ],
)
def test_opa_maps_the_answer(engine, result, decision):
    engine.answer = {"result": result} if result is not None else {}
    assert load("policy_opa").opa_policy(engine.url)(request()) == decision


RETRY = (
    "The authorization service did not answer, so this call was not run. "
    "Nothing was changed. The call can be retried."
)


def test_opa_unreachable_is_a_denial_the_model_may_retry():
    policy = load("policy_opa").opa_policy(unused_port_url(), timeout=0.5)
    assert policy(request()) == Deny("policy engine unavailable", message=RETRY)


def test_opa_unreachable_can_ask_instead():
    opa = load("policy_opa")
    policy = opa.opa_policy(unused_port_url(), timeout=0.5, on_unavailable=Ask)
    assert policy(request()) == Ask("policy engine unavailable")


@pytest.mark.parametrize("factory", ["opa", "cerbos"])
@pytest.mark.parametrize("bad", [Allow, Deny("x"), Ask("x"), "ask", None])
def test_on_unavailable_takes_deny_or_ask_only(factory, bad):
    with pytest.raises(ValueError, match="on_unavailable must be Deny or Ask"):
        if factory == "opa":
            load("policy_opa").opa_policy("http://127.0.0.1:1", on_unavailable=bad)
        else:
            load("policy_cerbos").cerbos_policy("http://127.0.0.1:1", kind="order", on_unavailable=bad)


def test_an_engine_that_answers_badly_denies_even_with_ask(engine):
    """on_unavailable is about an engine that didn't answer, nothing else."""
    policy = load("policy_opa").opa_policy(engine.url, on_unavailable=Ask)
    engine.status = 503
    assert policy(request()) == Deny("policy engine error: HTTP 503")


def test_opa_http_error_and_garbage_are_denials(engine):
    policy = load("policy_opa").opa_policy(engine.url)
    engine.status = 500
    assert policy(request()) == Deny("policy engine error: HTTP 500")
    engine.status, engine.raw = 200, b"not json"
    assert policy(request()) == Deny("policy engine returned an unreadable answer")


# --- Cerbos --------------------------------------------------------------------


def cerbos_answer(**effects: str) -> dict:
    return {"results": [{"resource": {"kind": "order", "id": "4417"}, "actions": effects}]}


def test_cerbos_sends_principal_resource_and_both_actions(engine):
    engine.answer = cerbos_answer(**{"cancel_order": "EFFECT_ALLOW", "cancel_order:unattended": "EFFECT_ALLOW"})
    policy = load("policy_cerbos").cerbos_policy(engine.url, kind="order")
    assert policy(request()) == Allow()
    (path, body), = engine.requests
    assert path == "/api/check/resources"
    assert body["principal"] == {
        "id": "alice", "roles": ["user"],
        "attr": {"client_id": "support-agent", "issuer": "https://idp.example", "scopes": ["orders:read"]},
    }
    (resource,) = body["resources"]
    assert resource["actions"] == ["cancel_order", "cancel_order:unattended"]
    assert resource["resource"] == {
        "kind": "order", "id": "4417", "attr": {"id": "4417", "owner": "alice", "status": "packed", "total": 812.0},
    }


def test_cerbos_item_checks_ask_about_read_only(engine):
    engine.answer = cerbos_answer(read="EFFECT_ALLOW")
    policy = load("policy_cerbos").cerbos_policy(engine.url, kind="order")
    assert policy(request(action="read", tool="list_orders")) == Allow()
    (_, body), = engine.requests
    assert body["resources"][0]["actions"] == ["read"]


@pytest.mark.parametrize(
    "effects, decision",
    [
        ({"cancel_order": "EFFECT_ALLOW", "cancel_order:unattended": "EFFECT_ALLOW"}, Allow()),
        ({"cancel_order": "EFFECT_ALLOW", "cancel_order:unattended": "EFFECT_DENY"}, Ask("policy engine requires approval")),
        ({"cancel_order": "EFFECT_DENY", "cancel_order:unattended": "EFFECT_DENY"}, Deny("policy engine: EFFECT_DENY")),
        ({"cancel_order:unattended": "EFFECT_ALLOW"}, Deny("policy engine returned no decision for 'cancel_order'")),
        # Skipping the approval check isn't an allow: it was asked about.
        (
            {"cancel_order": "EFFECT_ALLOW"},
            Deny("policy engine returned no decision for 'cancel_order:unattended'"),
        ),
    ],
)
def test_cerbos_maps_the_effects(engine, effects, decision):
    engine.answer = cerbos_answer(**effects)
    assert load("policy_cerbos").cerbos_policy(engine.url, kind="order")(request()) == decision


def test_cerbos_without_results_denies(engine):
    engine.answer = {"results": []}
    assert load("policy_cerbos").cerbos_policy(engine.url, kind="order")(request()) == Deny(
        "policy engine returned no decision"
    )


def test_cerbos_unreachable_is_a_denial_the_model_may_retry():
    policy = load("policy_cerbos").cerbos_policy(unused_port_url(), kind="order", timeout=0.5)
    assert policy(request()) == Deny("policy engine unavailable", message=RETRY)


def test_cerbos_unreachable_can_ask_instead():
    policy = load("policy_cerbos").cerbos_policy(unused_port_url(), kind="order", timeout=0.5, on_unavailable=Ask)
    assert policy(request()) == Ask("policy engine unavailable")


# --- behind the gate -----------------------------------------------------------


def gated_add_note(policy, approver=None):
    """A server with one WRITE tool behind ``policy``; returns it, its log
    and the list of calls that ran."""
    stream, ran = io.StringIO(), []
    mcp = MCPServer("engine-gate")
    gatehouse = Gatehouse(
        mcp, policy=Policy(approver=approver), audit=AuditLog(stream=stream), local_caller=ALICE
    )

    def load_order(order_id: str) -> Order | None:
        return ORDER if order_id == ORDER.id else None

    @gatehouse.tool(tier=AccessTier.WRITE, authorize=policy, consistency=ConditionalWrite())
    def add_note(order_id: str, note: str, order: Annotated[Order, Load(load_order)]) -> str:
        ran.append(order_id)
        return "noted"

    return mcp, stream, ran


def last_line(stream: io.StringIO) -> dict:
    return json.loads(stream.getvalue().splitlines()[-1])


@pytest.mark.anyio
@pytest.mark.parametrize("engine_name", ["opa", "cerbos"])
async def test_an_unreachable_engine_denies_the_call_and_tells_the_model_it_can_retry(engine_name):
    url = unused_port_url()
    if engine_name == "opa":
        policy = load("policy_opa").opa_policy(url, timeout=0.5)
    else:
        policy = load("policy_cerbos").cerbos_policy(url, kind="order", timeout=0.5)
    mcp, stream, ran = gated_add_note(policy)

    async with Client(mcp) as client:
        result = await client.call_tool("add_note", {"order_id": "4417", "note": "hi"})

    assert result.is_error and result.content[0].text == "Error executing tool add_note: " + RETRY
    assert "not permitted" not in result.content[0].text
    assert ran == []
    line = last_line(stream)
    assert (line["outcome"], line["reason"], line["authz"]) == ("denied", "policy: policy engine unavailable", "deny")


@pytest.mark.anyio
async def test_a_refusal_on_the_merits_still_reads_not_permitted(engine):
    engine.answer = {"result": {"effect": "deny", "reason": "someone else's order"}}
    mcp, stream, ran = gated_add_note(load("policy_opa").opa_policy(engine.url))

    async with Client(mcp) as client:
        result = await client.call_tool("add_note", {"order_id": "4417", "note": "hi"})

    assert result.is_error and "not permitted" in result.content[0].text
    assert "retried" not in result.content[0].text
    assert last_line(stream)["reason"] == "policy: someone else's order"


@pytest.mark.anyio
@pytest.mark.parametrize("engine_name", ["opa", "cerbos"])
@pytest.mark.parametrize("approve", [True, False])
async def test_an_unreachable_engine_can_go_to_the_approver(engine_name, approve):
    url = unused_port_url()
    if engine_name == "opa":
        policy = load("policy_opa").opa_policy(url, timeout=0.5, on_unavailable=Ask)
    else:
        policy = load("policy_cerbos").cerbos_policy(url, kind="order", timeout=0.5, on_unavailable=Ask)
    asked = []

    def approver(req):
        asked.append(req.reason)
        return approve

    mcp, stream, ran = gated_add_note(policy, approver=approver)

    async with Client(mcp) as client:
        result = await client.call_tool("add_note", {"order_id": "4417", "note": "hi"})

    assert asked == ["policy engine unavailable"]
    line = last_line(stream)
    assert line["authz"] == "ask"
    if approve:
        # Asked again after the approval: still unreachable, so the same
        # question, and the approval given for it applies.
        assert not result.is_error and ran == ["4417"]
        assert line["outcome"] == "ok" and "reason" not in line
    else:
        assert result.is_error and result.content[0].text.endswith("'add_note' was refused by the approver.")
        assert ran == []
        assert (line["outcome"], line["reason"]) == ("denied", "approver refused")


@pytest.mark.anyio
async def test_ask_on_unavailable_without_an_approver_is_still_denied():
    policy = load("policy_opa").opa_policy(unused_port_url(), timeout=0.5, on_unavailable=Ask)
    mcp, stream, ran = gated_add_note(policy)

    async with Client(mcp) as client:
        result = await client.call_tool("add_note", {"order_id": "4417", "note": "hi"})

    assert result.is_error and ran == []
    line = last_line(stream)
    assert (line["outcome"], line["reason"], line["authz"]) == (
        "denied", "approval required, no approver configured", "ask"
    )
