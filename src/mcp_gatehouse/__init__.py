"""mcp-gatehouse — authorization as a runtime invariant for MCP servers
built with the official Python SDK.

Every tool call needs a verified caller, an explicit policy, and a decision
on the record it acts on, made server-side before the tool runs. Anything
missing, and the call fails closed. Around that: permission tiers, approval
gates, and an audit log of every call.
"""

from importlib.metadata import PackageNotFoundError, version

from .approvers import ApprovalStore, ElicitationApprover, MemoryApprovalStore, terminal_approver
from .audit import AuditLog, AuditSink, CallableSink, JsonlSink, NullAuditLog
from .authz import (
    AcceptRace,
    Allow,
    Ask,
    AuthorizationRequest,
    Authorizer,
    ConditionalWrite,
    Conflict,
    Consistency,
    Decision,
    Deny,
    Load,
    Scope,
    Transaction,
    any_caller,
    any_item,
    current_transaction,
)
from .gatehouse import GateDenied, Gatehouse
from .policy import (
    DEFAULT_REDACT,
    AccessTier,
    ApprovalRequest,
    Approver,
    Caller,
    Policy,
    redact_arguments,
)

__all__ = [
    "DEFAULT_REDACT",
    "AcceptRace",
    "AccessTier",
    "Allow",
    "ApprovalRequest",
    "ApprovalStore",
    "Approver",
    "Ask",
    "AuditLog",
    "AuditSink",
    "AuthorizationRequest",
    "Authorizer",
    "CallableSink",
    "Caller",
    "ConditionalWrite",
    "Conflict",
    "Consistency",
    "Decision",
    "Deny",
    "ElicitationApprover",
    "GateDenied",
    "Gatehouse",
    "JsonlSink",
    "Load",
    "MemoryApprovalStore",
    "NullAuditLog",
    "Policy",
    "Scope",
    "Transaction",
    "any_caller",
    "any_item",
    "current_transaction",
    "redact_arguments",
    "terminal_approver",
]

# Single source of truth is pyproject.toml; a hand-kept copy here drifts.
try:
    __version__ = version("mcp-gatehouse")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0+unknown"
