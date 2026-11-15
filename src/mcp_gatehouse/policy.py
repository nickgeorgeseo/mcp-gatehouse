"""Access tiers and the policy that governs them.

The model: every tool is classified by what it can do to your systems
(read, write, destructive). The policy decides which tiers need a human
sign-off, which tools are blocked outright, and which argument keys never
reach the audit log.
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
import ipaddress
import json
import math
import pathlib
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
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

    call_id: str | None = None
    """The ``call_id`` this call's audit lines carry, so an approval kept
    elsewhere (a Slack thread, a ticket) can be matched to the trail. It is
    new on every round of a round-trip approval: keep it out of an
    ``ElicitationApprover(message=...)``, or the answer never matches the
    question."""


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

    authorization_timeout: float | None = 5.0
    """Seconds a call gets to load its records and reach a decision: the
    loaders, the policy and any ``Scope``, together. Past it the call is
    denied as "authorization timed out" and the model is told it can retry.
    ``None`` turns the deadline off, and every audit line for the tool then
    says ``"authorization_deadline": "off"``. A tool can set its own."""

    on_authorization_timeout: Any = None
    """What a policy that runs out of time counts as: ``Deny`` (the default)
    or ``Ask``, which puts the call to the approver with the reason
    "authorization timed out". A loader or ``Scope`` that runs out of time
    always denies: there is no record yet to ask about."""

    def __post_init__(self) -> None:
        # An approver may take as long as a person does: no upper bound.
        _check_seconds("approval_timeout", self.approval_timeout, finite=False)
        _check_authorization_timeout(self.authorization_timeout)
        object.__setattr__(
            self, "on_authorization_timeout", _check_on_authorization_timeout(self.on_authorization_timeout)
        )

    def needs_approval(self, tier: AccessTier) -> bool:
        return tier in self.require_approval


def _check_seconds(name: str, value: Any, *, finite: bool) -> None:
    """A positive number of seconds (finite, if asked), or ``None``. Not a
    bool, and not NaN: ``0 < nan`` is false, so the range check refuses it."""
    if value is None:
        return
    is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
    if not is_number or not value > 0 or (finite and not math.isfinite(value)):
        raise ValueError(f"{name} must be a positive number of seconds, or None")


def _check_authorization_timeout(value: Any) -> None:
    """A positive, finite number of seconds, or ``None`` for no deadline."""
    _check_seconds("authorization_timeout", value, finite=True)


def _check_on_authorization_timeout(value: Any) -> Any:
    """``Deny`` or ``Ask`` (the classes); ``None`` means ``Deny``."""
    from .authz import Ask, Deny  # authz imports this module

    if value is None:
        return Deny
    if value is Deny or value is Ask:
        return value
    raise ValueError("on_authorization_timeout must be Deny or Ask (the class, not an instance)")


REDACTED = "«redacted»"


_OPAQUE_PREFIX = "«opaque:"
"""How a redacted value that is shown only by its type starts."""


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
    lowered = {_normalize_key(k) for k in keys}

    def scrub(value: Any) -> Any:
        if isinstance(value, float) and not math.isfinite(value):
            # JSON has no inf or nan: written raw, they'd make the audit
            # line unreadable to strict parsers.
            return str(value)
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, enum.Enum):
            # Its value, which the code defines: an approval's fingerprint
            # must see a status go from "packed" to "picking".
            return scrub(value.value)
        if isinstance(value, Decimal):
            # Numbers, dates and identifiers are shown as what they are:
            # they can't carry text, and an approval's fingerprint must see
            # an amount change.
            return str(value)
        if isinstance(value, (datetime.date, datetime.time)):  # datetime is a date
            return value.isoformat()
        if isinstance(value, (uuid.UUID, ipaddress.IPv4Address, ipaddress.IPv6Address, pathlib.PurePath)):
            return str(value)
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
        if isinstance(value, tuple) and callable(getattr(value, "_asdict", None)):
            # A NamedTuple: by field name, so a ``password`` field is masked.
            return scrub(value._asdict())  # type: ignore[attr-defined]
        if isinstance(value, (bytes, bytearray, memoryview)):
            return f"{_OPAQUE_PREFIX}{type(value).__name__}»"
        if isinstance(value, (list, tuple, Sequence)):
            return [scrub(v) for v in value]
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return scrub(dataclasses.asdict(value))
        model_dump = getattr(value, "model_dump", None)  # pydantic v2
        if callable(model_dump):
            try:
                return scrub(model_dump())
            except Exception:
                return f"{_OPAQUE_PREFIX}{type(value).__name__}»"
        return f"{_OPAQUE_PREFIX}{type(value).__name__}»"

    return scrub(dict(arguments))


def _holds_opaque(value: Any) -> bool:
    """Whether a redacted value has an opaque placeholder anywhere in it:
    something the gate can show only by its type, and can't see change."""
    if isinstance(value, str):
        return value.startswith(_OPAQUE_PREFIX)
    if isinstance(value, Mapping):
        return any(_holds_opaque(v) for v in value.values())
    if isinstance(value, list):
        return any(_holds_opaque(v) for v in value)
    return False


def _canonical(value: Any) -> str:
    """One stable text for a JSON-shaped value, for sorting and fingerprints."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
