"""The demo server, and how the package is built: one version number,
type information, and a demo that starts from any directory."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from audit_helpers import events
from mcp import Client

import mcp_gatehouse
from mcp_gatehouse import (
    AuditLog,
    demo,
)

REPO = Path(__file__).resolve().parent.parent


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
