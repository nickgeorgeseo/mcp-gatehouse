"""mcp-gatehouse — permission tiers, approval gates, and audit logging
for MCP servers built with the official Python SDK.

The server is the gatekeeper: you decide what an AI can read, what it can
write, and what's off-limits — and every action gets logged.
"""

from .audit import AuditLog, NullAuditLog
from .gatehouse import GateDenied, Gatehouse
from .policy import (
    AccessTier,
    ApprovalRequest,
    Approver,
    Policy,
    redact_arguments,
)

__all__ = [
    "AccessTier",
    "ApprovalRequest",
    "Approver",
    "AuditLog",
    "GateDenied",
    "Gatehouse",
    "NullAuditLog",
    "Policy",
    "redact_arguments",
]

__version__ = "0.1.0"
