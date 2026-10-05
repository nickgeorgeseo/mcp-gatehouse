"""mcp-gatehouse — permission tiers, approval gates, and audit logging
for MCP servers built with the official Python SDK.

The server is the gatekeeper: you decide what an AI can read, what it can
write, and what's off-limits — and every action gets logged.
"""

from importlib.metadata import PackageNotFoundError, version

from .approvers import terminal_approver
from .audit import AuditLog, NullAuditLog
from .gatehouse import GateDenied, Gatehouse
from .policy import (
    DEFAULT_REDACT,
    AccessTier,
    ApprovalRequest,
    Approver,
    Policy,
    redact_arguments,
)

__all__ = [
    "DEFAULT_REDACT",
    "AccessTier",
    "ApprovalRequest",
    "Approver",
    "AuditLog",
    "GateDenied",
    "Gatehouse",
    "NullAuditLog",
    "Policy",
    "redact_arguments",
    "terminal_approver",
]

# Single source of truth is pyproject.toml; a hand-kept copy here drifts.
try:
    __version__ = version("mcp-gatehouse")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0+unknown"
