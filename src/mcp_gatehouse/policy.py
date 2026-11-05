"""Access tiers and the policy that governs them.

The model: every tool is classified by what it can do to your systems
(read, write, destructive). The policy decides which tiers need a human
sign-off, which tools are blocked outright, and which argument keys never
reach the audit log.
"""

from __future__ import annotations

import enum
import functools
import re
from collections.abc import Awaitable, Callable, Collection
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


def _as_tier(value: object) -> AccessTier:
    """An :class:`AccessTier` from the enum itself or its value (``"write"``).

    Anything else is an error, raised where the tier is written down. A
    tier the gate can't read must never be treated as some other tier: a
    string that matched no member used to slip past the approval check.
    """
    if isinstance(value, AccessTier):
        return value
    if isinstance(value, str):
        try:
            return AccessTier(value.strip().lower())
        except ValueError:
            pass
        raise ValueError(
            f"unknown access tier {value!r}; use one of "
            + ", ".join(repr(t.value) for t in AccessTier)
            + " (or AccessTier.READ / .WRITE / .DESTRUCTIVE)"
        )
    raise TypeError(f"an access tier is an AccessTier or its name as a string, not {type(value).__name__}")


def _as_collection(name: str, value: object) -> frozenset[Any]:
    """A frozenset from any collection, refusing the single values that
    iterate into nonsense: ``"api_key"`` would mean the keys ``a``, ``p``,
    ``i``… and ``"cancel_order"`` would block every tool whose name is a
    substring of it. Refused rather than guessed at, with the fix."""
    if isinstance(value, (str, bytes)):
        raise TypeError(f"Policy({name}=...) takes a collection, not a single string: use {name}={{{value!r}}}")
    if isinstance(value, AccessTier):
        raise TypeError(
            f"Policy({name}=...) takes a collection of tiers, not a single tier: "
            f"use {name}={{AccessTier.{value.name}}}"
        )
    try:
        return frozenset(value)  # type: ignore[call-overload]
    except TypeError:
        raise TypeError(
            f"Policy({name}=...) takes a collection (a set, list or tuple), not {type(value).__name__}"
        ) from None


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


Approver = Callable[[ApprovalRequest], Union[bool, Awaitable[bool]]]

#: Argument keys that are masked in audit logs and approval requests by
#: default. A key covers every spelling of itself (``api_key`` covers
#: ``apiKey``, ``API-Key`` and ``apikey``) and any name it ends, word for
#: word (``token`` covers ``github_token`` and ``authToken``, not
#: ``token_count``). See :func:`redact_arguments`.
DEFAULT_REDACT: frozenset[str] = frozenset(
    {
        "password", "passwd", "passphrase",
        "token", "access_token", "refresh_token", "id_token",
        "secret", "client_secret", "secret_key", "secret_access_key",
        "api_key", "x_api_key", "private_key",
        "credential", "credentials",
        "authorization", "cookie", "set_cookie",
        "ssn",
    }
)


def _normalize_key(key: str) -> str:
    """``API-Key``, ``api_key`` and ``apiKey`` all name the same secret."""
    return key.lower().replace("_", "").replace("-", "")


_SEPARATORS = re.compile(r"[\W_]+")
# Before a capital that follows a lower-case letter or digit (apiKey), and
# between an acronym and the word after it (APIKey, openAIApiKey).
_CAMEL_BREAK = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _words(key: str) -> tuple[str, ...]:
    """``openAIApiKey`` and ``OPENAI_API_KEY`` → words ending ``api``, ``key``."""
    words: list[str] = []
    for part in _SEPARATORS.split(key):
        words.extend(w.lower() for w in _CAMEL_BREAK.sub(" ", part).split())
    return tuple(words)


@functools.lru_cache(maxsize=64)
def _secret_matcher(keys: frozenset[str]) -> Callable[[str], bool]:
    """Whether an argument name is one of ``keys``, built once per key set.

    Two ways to match, and either masks:

    - the whole name, ignoring case, ``_`` and ``-`` (``apikey`` is
      ``api_key``), as it always has;
    - the name's last words (``github_token`` ends in ``token``,
      ``openAIApiKey`` in ``api key``). Words, not letters: ``pin`` masks
      ``card_pin`` but not ``spin``, and ``token`` leaves ``token_count``
      and ``max_tokens`` alone.
    """
    whole = {_normalize_key(k) for k in keys}
    tails = {w for w in map(_words, keys) if w}
    # Payloads repeat a few names many times (a list of rows), so each
    # name's answer is kept. Only short names, and only so many, so hostile
    # input can't grow it.
    seen: dict[str, bool] = {}
    # Only a name's last words can match a tail, and every tail fits well
    # inside this many characters, so splitting a long name into words
    # need only look at its end. A word cut at the window's edge can only
    # make the name mask more, never less.
    window = max(_SCAN_LIMIT, 2 * max((len(k) for k in keys), default=0) + 8)

    def match(name: str) -> bool:
        # Always the whole name, however long: separators vanish when it is
        # normalised, so `api____…____key` is still `api_key`.
        if _normalize_key(name) in whole:
            return True
        words = _words(name[-window:])
        return any(words[-len(tail):] == tail for tail in tails if len(tail) <= len(words))

    def is_secret(name: str) -> bool:
        known = seen.get(name)
        if known is None:
            known = match(name)
            if len(name) <= _SCAN_LIMIT and len(seen) < _SEEN_LIMIT:
                seen[name] = known
        return known

    return is_secret


# How much of the end of a long argument name is split into words (at
# least; more if a key is long), and the longest name whose verdict is kept.
_SCAN_LIMIT = 256
# Distinct names whose verdict a matcher remembers.
_SEEN_LIMIT = 4096


@dataclass(frozen=True)
class Policy:
    """The rules a :class:`~mcp_gatehouse.Gatehouse` enforces.

    The default policy is deliberately conservative: destructive tools
    require approval, and if no approver is configured the call is denied
    (fail closed) rather than waved through.
    """

    require_approval: Collection[AccessTier | str] = frozenset({AccessTier.DESTRUCTIVE})
    """Tiers that need the approver's sign-off before the tool runs. Any
    collection of tiers, as ``AccessTier`` members or their names:
    ``{"write", "destructive"}``. Stored as a ``frozenset[AccessTier]``."""

    deny: Collection[str] = frozenset()
    """Tool names that are blocked outright, whatever their tier. Any
    collection of names; stored as a ``frozenset``."""

    approver: Approver | None = None
    """Callable (sync or async) that decides gated calls. Receives an
    :class:`ApprovalRequest`, returns ``True`` to allow."""

    redact: Collection[str] = field(default_factory=lambda: DEFAULT_REDACT)
    """Argument keys masked in logs and approvals, ignoring case, ``_`` and
    ``-``. See :func:`redact_arguments` for how keys match. To extend
    rather than replace the defaults: ``redact=DEFAULT_REDACT | {"pin"}``."""

    fail_closed: bool = True
    """If a tier requires approval and no approver is set: ``True`` denies
    the call, ``False`` lets it through. Leave this alone unless you have
    a very good reason."""

    approval_timeout: float | None = None
    """Seconds to wait for the approver before denying the call. ``None``
    waits as long as the approver takes. Running out of time is a denial,
    so the gate still fails closed."""

    def __post_init__(self) -> None:
        # Normalised here, once, so every check downstream compares like with
        # like. A tier written as "destructive" against a set of enum members
        # matched nothing, and the gate waved the call through.
        tiers = frozenset(_as_tier(t) for t in _as_collection("require_approval", self.require_approval))
        object.__setattr__(self, "require_approval", tiers)
        for name in ("deny", "redact"):
            names = _as_collection(name, getattr(self, name))
            wrong = sorted({type(n).__name__ for n in names if not isinstance(n, str)})
            if wrong:
                raise TypeError(f"Policy({name}=...) takes strings; got {', '.join(wrong)}")
            object.__setattr__(self, name, names)
        if self.approver is not None and not callable(self.approver):
            raise TypeError(
                f"Policy(approver=...) takes a callable (sync or async), not {type(self.approver).__name__}"
            )
        # `not > 0` rather than `<= 0`, so NaN is rejected too.
        if self.approval_timeout is not None and not self.approval_timeout > 0:
            raise ValueError("approval_timeout must be a positive number of seconds, or None")

    def needs_approval(self, tier: AccessTier | str) -> bool:
        return _as_tier(tier) in self.require_approval


REDACTED = "«redacted»"


def redact_arguments(arguments: dict[str, Any], keys: Collection[str]) -> dict[str, Any]:
    """Return a deep copy of ``arguments`` with sensitive values masked.

    A key in ``keys`` masks an argument, at any nesting depth, when it
    names it whole, ignoring case, ``_`` and ``-`` (``api_key`` masks
    ``apiKey``), or when the argument's name ends in its words
    (``token`` masks ``github_token`` and ``authToken``, but not
    ``token_count``; ``pin`` masks ``card_pin``, not ``spin``).

    Structured values are unwrapped so nested keys are reachable: mappings
    and sequences are recursed, dataclasses and Pydantic models are
    converted to dicts first. Anything else that isn't a plain JSON
    primitive, bytes included, is replaced with an opaque placeholder — a
    repr can carry a secret, so unknown objects never pass through
    verbatim. The gate fails closed here too.
    """
    import dataclasses as _dc
    from collections.abc import Mapping, Sequence

    is_secret = _secret_matcher(frozenset(keys))

    def scrub(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, (bytes, bytearray, memoryview)):
            # Before the Sequence check: bytearray and memoryview are
            # sequences, and were logged as their contents, byte by byte.
            return f"«opaque:{type(value).__name__}»"
        if isinstance(value, Mapping):
            return {
                str(k): (REDACTED if is_secret(str(k)) else scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset, Sequence)):
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
