"""0.3.0: sync code off the event loop, approver failures audited, looser
redaction key matching, and a demo that starts anywhere."""

from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

import anyio
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

import mcp_gatehouse
from mcp_gatehouse import DEFAULT_REDACT, AccessTier, AuditLog, Gatehouse, Policy, redact_arguments
from mcp_gatehouse import demo

REPO = Path(__file__).resolve().parent.parent


def events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().split("\n") if line]


# --- blocking work stays off the event loop -------------------------------


@pytest.mark.anyio
async def test_sync_tool_does_not_block_other_calls():
    """A sync tool waits for a signal only a *second* call can send. If the
    first call held the event loop, the second could never run."""
    released = threading.Event()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp)

    @gk.tool(tier=AccessTier.READ)
    def wait_for_release() -> str:
        return "released" if released.wait(timeout=3) else "loop was blocked"

    @gk.tool(tier=AccessTier.READ)
    def release() -> str:
        released.set()
        return "ok"

    results = {}
    async with Client(mcp) as client:

        async def call(name):
            results[name] = (await client.call_tool(name, {})).content[0].text

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "wait_for_release")
            await anyio.sleep(0.05)
            tg.start_soon(call, "release")
    assert results["wait_for_release"] == "released"


@pytest.mark.anyio
async def test_sync_approver_does_not_block_other_calls():
    """While a human mulls over a destructive call, reads keep flowing."""
    released = threading.Event()

    def slow_human(request) -> bool:
        return released.wait(timeout=3)

    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=slow_human))

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel() -> str:
        return "cancelled"

    @gk.tool(tier=AccessTier.READ)
    def release() -> str:
        released.set()
        return "ok"

    results = {}
    async with Client(mcp) as client:

        async def call(name):
            results[name] = await client.call_tool(name, {})

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "cancel")
            await anyio.sleep(0.05)
            tg.start_soon(call, "release")
    assert results["cancel"].is_error is False
    assert results["cancel"].content[0].text == "cancelled"


@pytest.mark.anyio
async def test_async_tools_and_partials_still_work():
    import functools

    mcp = MCPServer("t")
    gk = Gatehouse(mcp)

    @gk.tool(tier=AccessTier.READ)
    async def ping() -> str:
        await anyio.sleep(0)
        return "pong"

    async def greet(greeting: str, name: str) -> str:
        return f"{greeting}, {name}"

    hello = functools.partial(greet, "hello")
    hello.__name__ = "hello"
    gk.tool(tier=AccessTier.READ)(hello)

    async with Client(mcp) as client:
        assert (await client.call_tool("ping", {})).content[0].text == "pong"
        assert (await client.call_tool("hello", {"name": "nick"})).content[0].text == "hello, nick"


# --- an approver that crashes is a denial, and it's on the record ---------


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [False, True])
async def test_approver_exception_is_an_audited_denial(is_async, caplog):
    def boom(request):
        raise ConnectionError("slack is down, token=xoxb-secret")

    async def aboom(request):
        boom(request)

    log = io.StringIO()
    mcp = MCPServer("t")
    gk = Gatehouse(mcp, policy=Policy(approver=aboom if is_async else boom), audit=AuditLog(stream=log))
    ran = []

    @gk.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel(order_id: str) -> str:
        ran.append(order_id)
        return "cancelled"

    with caplog.at_level(logging.DEBUG):
        async with Client(mcp) as client:
            result = await client.call_tool("cancel", {"order_id": "4417"})

    assert ran == []
    assert result.is_error is True
    assert "approver failed" in result.content[0].text
    (event,) = events(log)
    assert event["outcome"] == "denied"
    assert event["reason"] == "approver error: ConnectionError"
    assert "xoxb-secret" not in log.getvalue()
    # an anticipated refusal, not a server crash
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


# --- redaction matches the way people actually spell keys -----------------


@pytest.mark.parametrize(
    "key", ["api_key", "apiKey", "API-Key", "x-api-key", "accessToken", "client_secret", "Set-Cookie", "PRIVATE_KEY"]
)
def test_default_redaction_ignores_case_and_separators(key):
    assert redact_arguments({key: "hunter2"}, DEFAULT_REDACT) == {key: "«redacted»"}


def test_custom_keys_normalize_too_and_defaults_extend():
    keys = DEFAULT_REDACT | {"card_pin"}
    out = redact_arguments({"cardPin": "1234", "password": "x", "note": "fine"}, keys)
    assert out == {"cardPin": "«redacted»", "password": "«redacted»", "note": "fine"}


def test_redaction_is_still_whole_key_not_substring():
    assert redact_arguments({"token_count": 12, "secretary": "Ann"}, DEFAULT_REDACT) == {
        "token_count": 12,
        "secretary": "Ann",
    }


# --- packaging ------------------------------------------------------------


def test_version_has_one_source_of_truth():
    tomllib = pytest.importorskip("tomllib")  # 3.11+
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
    server = json.loads((REPO / "server.json").read_text())
    expected = pyproject["project"]["version"]
    assert mcp_gatehouse.__version__ == expected
    assert server["version"] == expected
    assert all(p["version"] == expected for p in server["packages"])


def test_package_ships_type_information():
    assert (Path(mcp_gatehouse.__file__).parent / "py.typed").exists()


def test_audit_log_exposes_its_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with AuditLog(path="sub/audit.jsonl") as log:
        assert log.path == tmp_path / "sub" / "audit.jsonl"
    assert AuditLog(stream=io.StringIO()).path is None


# --- the demo -------------------------------------------------------------


def test_importing_the_demo_has_no_side_effects(tmp_path):
    subprocess.run(
        [sys.executable, "-c", "import mcp_gatehouse.demo; from mcp_gatehouse.demo import terminal_approver"],
        cwd=tmp_path,
        check=True,
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs POSIX permissions, non-root")
def test_demo_falls_back_when_cwd_is_read_only(tmp_path, monkeypatch):
    readonly = tmp_path / "ro"
    readonly.mkdir()
    readonly.chmod(0o500)
    fallback = tmp_path / "home" / "audit.jsonl"
    monkeypatch.chdir(readonly)
    monkeypatch.delenv(demo.AUDIT_ENV_VAR, raising=False)
    monkeypatch.setattr(demo, "FALLBACK_AUDIT_PATH", fallback)
    try:
        with demo.open_audit_log() as log:
            assert log.path == fallback
    finally:
        readonly.chmod(0o700)


def test_demo_explicit_audit_path_wins_and_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv(demo.AUDIT_ENV_VAR, str(tmp_path / "env.jsonl"))
    with demo.open_audit_log() as log:
        assert log.path == tmp_path / "env.jsonl"
    with demo.open_audit_log(str(tmp_path / "flag.jsonl")) as log:
        assert log.path == tmp_path / "flag.jsonl"
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(OSError):
        demo.open_audit_log(str(blocker / "audit.jsonl"))


def test_demo_cli_version():
    out = subprocess.run(
        [sys.executable, "-m", "mcp_gatehouse.demo", "--version"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == f"mcp-gatehouse-demo {mcp_gatehouse.__version__}"


@pytest.mark.anyio
async def test_demo_tools_are_documented_and_work_end_to_end():
    log = io.StringIO()
    server = demo.build_server(AuditLog(stream=log), approver=lambda request: True)
    async with Client(server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == {"list_orders", "lookup_order", "add_note", "cancel_order"}
        for tool in tools.values():
            assert len(tool.description) > 60, tool.name
            for name, prop in tool.input_schema.get("properties", {}).items():
                assert prop.get("description"), f"{tool.name}.{name} has no description"

        listing = (await client.call_tool("list_orders", {})).content[0].text
        assert "4417" in listing and "4418" in listing
        await client.call_tool("add_note", {"order_id": "4418", "note": "rush", "api_key": "sk-live-1"})
        assert "rush" in (await client.call_tool("lookup_order", {"order_id": "4418"})).content[0].text

    assert "sk-live-1" not in log.getvalue()
    assert [e["tool"] for e in events(log)] == ["list_orders", "add_note", "lookup_order"]
