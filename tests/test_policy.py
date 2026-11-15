"""Unit tests for redaction and policy semantics."""

from __future__ import annotations

import json

import pytest

from mcp_gatehouse import AccessTier, AuditLog, Policy, redact_arguments
from mcp_gatehouse.policy import DEFAULT_REDACT, REDACTED


def test_redaction_is_case_insensitive_and_recursive():
    args = {
        "order_id": "4417",
        "API_KEY": "sk-live",
        "customer": {"name": "Pat", "Password": "pw"},
        "batch": [{"token": "t1"}, {"note": "fine"}],
    }
    safe = redact_arguments(args, DEFAULT_REDACT)
    assert safe["order_id"] == "4417"
    assert safe["API_KEY"] == REDACTED
    assert safe["customer"]["Password"] == REDACTED
    assert safe["customer"]["name"] == "Pat"
    assert safe["batch"][0]["token"] == REDACTED
    assert safe["batch"][1]["note"] == "fine"
    # the original is untouched
    assert args["API_KEY"] == "sk-live"


def test_default_policy_gates_destructive_only():
    p = Policy()
    assert p.needs_approval(AccessTier.DESTRUCTIVE)
    assert not p.needs_approval(AccessTier.WRITE)
    assert not p.needs_approval(AccessTier.READ)


def test_write_gating_opt_in():
    p = Policy(require_approval=frozenset({AccessTier.WRITE, AccessTier.DESTRUCTIVE}))
    assert p.needs_approval(AccessTier.WRITE)


def test_audit_log_writes_jsonl_with_timestamp(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    with AuditLog(path=path) as log:
        log.record(call_id="0123456789abcdef0123456789abcdef", tool="x", tier="read", outcome="ok", arguments={})
        log.record(call_id="0123456789abcdef0123456789abcdef", tool="y", tier="read", outcome="denied", reason="denylist", arguments={})
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "x"
    assert first["ts"].endswith("+00:00")




@pytest.mark.parametrize("bad", [True, 0, -1, float("nan"), "5"])
def test_approval_timeout_is_a_positive_number_of_seconds(bad):
    with pytest.raises(ValueError, match="approval_timeout"):
        Policy(approval_timeout=bad)
    Policy(approval_timeout=float("inf"))  # a person may take as long as they take
