"""Access tiers and the policy that governs them.

The model: every tool is classified by what it can do to your systems
(read, write, destructive). The policy decides which tiers need a human
sign-off, which tools are blocked outright, and which argument keys never
reach the audit log.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Union


class AccessTier(enum.Enum):
    """What a tool is allowed to do to the system behind it."""

    READ = "read"
    """Looks things up. Never changes state."""

    WRITE = "write"
    """Creates or updates records. Reversible with effort."""

    DESTRUCTIVE = "destructive"
    """Deletes, sends, or pays. Hard or impossible to take back."""


@dataclass(frozen=True)
class ApprovalRequest:
    """What an approver sees before a gated tool runs.

    ``arguments`` is the redacted copy — secrets configured in
    ``Policy.redact`` are already masked by the time this is built.
    """

    tool: str
    tier: AccessTier
    arguments: dict[str, Any]


Approver = Callable[[ApprovalRequest], Union[bool, Awaitable[bool]]]

#: Argument keys that are masked in audit logs and approval requests by
#: default. Matched against whole key names, ignoring case, ``_`` and ``-``
#: — so ``api_key`` also covers ``apiKey``, ``API-Key`` and ``apikey``.
DEFAULT_REDACT: frozenset[str] = frozenset(
    {
        "password", "passwd", "passphrase",
        "token", "access_token", "refresh_token", "id_token",
        "secret", "client_secret",
        "api_key", "x_api_key", "private_key",
        "authorization", "cookie", "set_cookie",
        "ssn",
    }
)


def _normalize_key(key: str) -> str:
    """``API-Key``, ``api_key`` and ``apiKey`` all name the same secret."""
    return key.lower().replace("_", "").replace("-", "")


@dataclass(frozen=True)
class Policy:
    """The rules a :class:`~mcp_gatehouse.Gatehouse` enforces.

    The default policy is deliberately conservative: destructive tools
    require approval, and if no approver is configured the call is denied
    (fail closed) rather than waved through.
    """

    require_approval: frozenset[AccessTier] = frozenset({AccessTier.DESTRUCTIVE})
    """Tiers that need the approver's sign-off before the tool runs."""

    deny: frozenset[str] = frozenset()
    """Tool names that are blocked outright, whatever their tier."""

    approver: Approver | None = None
    """Callable (sync or async) that decides gated calls. Receives an
    :class:`ApprovalRequest`, returns ``True`` to allow."""

    redact: frozenset[str] = field(default_factory=lambda: DEFAULT_REDACT)
    """Argument keys masked in logs and approvals. Whole-name matches,
    ignoring case, ``_`` and ``-``. To extend rather than replace the
    defaults: ``redact=DEFAULT_REDACT | {"pin"}``."""

    fail_closed: bool = True
    """If a tier requires approval and no approver is set: ``True`` denies
    the call, ``False`` lets it through. Leave this alone unless you have
    a very good reason."""

    def needs_approval(self, tier: AccessTier) -> bool:
        return tier in self.require_approval


REDACTED = "«redacted»"


def redact_arguments(arguments: dict[str, Any], keys: frozenset[str]) -> dict[str, Any]:
    """Return a deep copy of ``arguments`` with sensitive values masked.

    Matching is by whole key name at any nesting depth, ignoring case,
    ``_`` and ``-`` (``apiKey`` matches ``api_key``).
    Structured values are unwrapped so nested keys are reachable: mappings
    and sequences are recursed, dataclasses and Pydantic models are
    converted to dicts first. Anything else that isn't a plain JSON
    primitive is replaced with an opaque placeholder — a repr can carry a
    secret, so unknown objects never pass through verbatim. The gate fails
    closed here too.
    """
    import dataclasses as _dc
    from collections.abc import Mapping, Sequence

    lowered = {_normalize_key(k) for k in keys}

    def scrub(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return {
                str(k): (REDACTED if _normalize_key(str(k)) in lowered else scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)) or (
            isinstance(value, Sequence) and not isinstance(value, bytes)
        ):
            return [scrub(v) for v in value]
        if _dc.is_dataclass(value) and not isinstance(value, type):
            return scrub(_dc.asdict(value))
        model_dump = getattr(value, "model_dump", None)  # pydantic v2
        if callable(model_dump):
            try:
                return scrub(model_dump())
            except Exception:
                return f"«opaque:{type(value).__name__}»"
        return f"«opaque:{type(value).__name__}»"

    return scrub(dict(arguments))
