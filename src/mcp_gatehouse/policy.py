"""Access tiers and the policy that governs them.

The model: every tool is classified by what it can do to your systems
(read, write, destructive). The policy decides which tiers need a human
sign-off, which tools are blocked outright, and which argument keys never
reach the audit log.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable, Callable, Mapping
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
class Caller:
    """Who a call was made for.

    Over streamable HTTP or SSE with a ``token_verifier``, it is the identity
    in the access token the MCP SDK verified for this request. Over stdio
    nobody signs in, so it is the ``local_caller`` the server declared to
    its :class:`~mcp_gatehouse.Gatehouse`; a server that declares none
    denies every call. An HTTP request without a verified token is nobody,
    never the local caller.

    It is only as specific as your token verifier makes it. ``subject`` is
    the user the token speaks for; a verifier that doesn't fill in
    ``AccessToken.subject`` leaves it ``None``, and then all you know is
    the client application. The token itself is never kept.
    """

    client_id: str
    """The OAuth client (the application) the token was issued to."""

    subject: str | None = None
    """The token's ``sub``: the user it acts for. Unique only per issuer."""

    issuer: str | None = None
    """The token's ``iss`` claim, when the verifier supplies claims."""

    scopes: tuple[str, ...] = ()
    """The scopes the token was granted."""


@dataclass(frozen=True)
class ApprovalRequest:
    """What an approver sees before a gated tool runs.

    ``arguments`` is the redacted copy — secrets configured in
    ``Policy.redact`` are already masked by the time this is built.
    """

    tool: str
    tier: AccessTier
    arguments: dict[str, Any]
    deadline: float | None = None
    """``time.monotonic()`` value at which the gate stops waiting and denies
    the call, or ``None`` for no limit. An approver that blocks — a prompt,
    a poll — should give up by then: past it, its answer is ignored."""

    caller: Caller | None = None
    """Who the call is for: the request's verified access token, or the
    server's declared ``local_caller`` on stdio."""

    reason: str | None = None
    """Why the policy asked, when it answered ``Ask(reason)``; ``None`` when
    the approval is required by the tool's tier alone."""

    resources: tuple[str, ...] = ()
    """One line per record the call acts on: what ``Load(describe=...)``
    returns, or by default the record's redacted fields, so the approver
    sees what will change, not only the model's arguments."""

    binding: str | None = None
    """A fingerprint of the caller, the records' state and the reason. Not
    for showing: an approval given for one binding never runs a call with
    another, so a record that changed while a person decided is refused."""


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

    approval_timeout: float | None = None
    """Seconds to wait for the approver before denying the call. ``None``
    waits as long as the approver takes. Running out of time is a denial,
    so the gate still fails closed."""

    def __post_init__(self) -> None:
        # `not > 0` rather than `<= 0`, so NaN is rejected too.
        if self.approval_timeout is not None and not self.approval_timeout > 0:
            raise ValueError("approval_timeout must be a positive number of seconds, or None")

    def needs_approval(self, tier: AccessTier) -> bool:
        return tier in self.require_approval


REDACTED = "«redacted»"


def redact_arguments(arguments: Mapping[str, Any], keys: frozenset[str]) -> dict[str, Any]:
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
    import datetime as _dt
    from collections.abc import Sequence
    from decimal import Decimal

    lowered = {_normalize_key(k) for k in keys}

    def scrub(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Decimal):
            # Numbers and dates are shown as what they are: they can't carry
            # text, and an approval's fingerprint must see an amount change.
            return str(value)
        if isinstance(value, (_dt.date, _dt.time)):  # datetime is a date
            return value.isoformat()
        if isinstance(value, Mapping):
            return {
                str(k): (REDACTED if _normalize_key(str(k)) in lowered else scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, (set, frozenset)):
            # Sorted: a set's order depends on PYTHONHASHSEED, and approvals
            # bind to a fingerprint of the redacted record, which must read
            # the same in every worker process.
            return sorted((scrub(v) for v in value), key=_canonical)
        if isinstance(value, (list, tuple)) or (
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


def _canonical(value: Any) -> str:
    """One stable text for a JSON-shaped value, for sorting and fingerprints."""
    import json

    return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
