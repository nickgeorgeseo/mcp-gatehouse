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

from mcp_gatehouse import AccessTier, Allow, Ask, AuditLog, Caller, ConditionalWrite, Deny, Load, Policy, any_caller
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


def test_opa_unreachable_is_a_denial():
    policy = load("policy_opa").opa_policy(unused_port_url(), timeout=0.5)
    assert policy(request()) == Deny("policy engine unavailable")


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


def test_cerbos_unreachable_is_a_denial():
    policy = load("policy_cerbos").cerbos_policy(unused_port_url(), kind="order", timeout=0.5)
    assert policy(request()) == Deny("policy engine unavailable")


# --- behind the gate -----------------------------------------------------------


@pytest.mark.anyio
async def test_an_unreachable_engine_denies_the_call_and_the_log_says_so():
    policy = load("policy_opa").opa_policy(unused_port_url(), timeout=0.5)
    stream, ran = io.StringIO(), []
    mcp = MCPServer("opa-gate")
    gatehouse = Gatehouse(mcp, policy=Policy(), audit=AuditLog(stream=stream), local_caller=ALICE)

    def load_order(order_id: str) -> Order | None:
        return ORDER if order_id == ORDER.id else None

    @gatehouse.tool(tier=AccessTier.WRITE, authorize=policy, consistency=ConditionalWrite())
    def add_note(order_id: str, note: str, order: Annotated[Order, Load(load_order)]) -> str:
        ran.append(order_id)
        return "noted"

    async with Client(mcp) as client:
        result = await client.call_tool("add_note", {"order_id": "4417", "note": "hi"})

    assert result.is_error and "not permitted" in result.content[0].text
    assert ran == []
    line = json.loads(stream.getvalue().splitlines()[-1])
    assert (line["outcome"], line["reason"], line["authz"]) == ("denied", "policy: policy engine unavailable", "deny")
