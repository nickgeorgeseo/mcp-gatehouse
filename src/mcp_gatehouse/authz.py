"""Authorization: your rules, decided on the record itself, before the tool runs.

The gate doesn't know your business rules. It guarantees where and when
they run: server-side, at the tool boundary, on the record the tool then
acts on, for a caller the transport verified. Every tool names a policy;
a tool that needs none says so with ``any_caller``.

The pieces:

- A **policy** is any callable, sync or async, that takes an
  :class:`AuthorizationRequest` and returns :class:`Allow`,
  :class:`Deny` or :class:`Ask`. Anything else it returns, or raises, is a
  denial.
- :class:`Load` marks a tool parameter the gate fills: it loads the record
  from the model's arguments, hands it to the policy, and passes that same
  object to the tool. The model never supplies it.
- :class:`Scope` marks a parameter the gate fills with a query filter your
  code computes from the caller, so a list tool asks the database only for
  what the caller may see.
- ``consistency=`` says how the window between the check and the write is
  closed: one :class:`Transaction` around both, a :class:`ConditionalWrite`
  whose query carries the condition, or :class:`AcceptRace` on purpose.
"""

from __future__ import annotations

import contextvars
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Union

from mcp.server.mcpserver.exceptions import ToolError

from .policy import AccessTier, Caller

# --- decisions ---------------------------------------------------------------


@dataclass(frozen=True)
class Allow:
    """The policy allows the call (or, for a list item, lets the caller see it)."""


@dataclass(frozen=True)
class Deny:
    """The policy refuses.

    ``reason`` goes to the audit log, not to the model: every refusal on
    authorization reads the same to the model ("not permitted"), so it can't
    tell a record it may not touch from one that doesn't exist. Set
    ``message`` to tell the model more, when that's safe to say.
    """

    reason: str
    message: str | None = None


@dataclass(frozen=True)
class Ask:
    """The policy wants a person to decide: the configured approver is asked.

    The approver sees ``reason``. Keep it stable for the same record and
    caller: the approval is bound to it, so a reason that changes on every
    call never matches its own answer.
    """

    reason: str


Decision = Union[Allow, Deny, Ask]


@dataclass(frozen=True)
class AuthorizationRequest:
    """What a policy decides on."""

    caller: Caller
    """Who the call is for: the verified token's identity, or the server's
    declared ``local_caller`` on stdio."""

    tool: str
    tier: AccessTier

    action: Literal["call", "read"]
    """``"call"`` for the call itself; ``"read"`` when the gate asks, item by
    item, whether the caller may see what a list tool returned."""

    arguments: Mapping[str, Any]
    """The validated arguments the model sent, unredacted and read-only.
    Facts about a record come from ``resources``, which the server loaded;
    these are only what the model asked for."""

    resources: Mapping[str, Any]
    """Each ``Load`` parameter's name mapped to the record the gate loaded."""

    resource: Any = None
    """For ``action="read"``: the item being checked."""

    claims: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    """The verified token's claims (``act``, ``authorization_details``, …), as
    the token verifier supplied them. For policies only: never logged. Empty
    for the local caller."""


Authorizer = Callable[[AuthorizationRequest], Union[Decision, Awaitable[Decision]]]


def any_caller(request: AuthorizationRequest) -> Decision:
    """The deliberate opt-out: any verified caller may call this tool.

    Identity is still required. The audit log marks these calls
    ``authz: "open"``, so every tool that opted out is one grep away.
    """
    return Allow()


def any_item(request: AuthorizationRequest) -> Decision:
    """The deliberate opt-out for list tools: the caller may see every item.

    Logged as ``items: "open"``.
    """
    return Allow()


# --- parameters the gate fills -----------------------------------------------


@dataclass(frozen=True)
class Load:
    """Mark a tool parameter as a record the gate loads, checks and hands over::

        def load_order(order_id: str) -> Order | None: ...

        @gatehouse.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel, ...)
        def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]): ...

    The loader's parameters name the tool's own arguments; the model sees
    ``order_id`` only. A loader that returns ``None`` means "not found",
    and the call is refused.

    ``fingerprint`` returns what identifies the record's state for an
    approval (a version number, an updated-at stamp). By default it is the
    record itself, redacted, which needs a Pydantic model, a dataclass or
    a mapping. An approval binds to that state: if it changes while a
    person decides, the call is refused rather than run on something they
    never saw.

    ``describe`` returns the line a person reads when asked to approve
    ("4417 · Blue Ridge Cabinets · $812"), so they see what the call will
    act on, not just the arguments the model chose. Without it the approver
    sees the record's fields as the audit log would show them, secrets
    masked (``order: id=4417 · customer=Blue Ridge Cabinets · ...``).
    """

    loader: Callable[..., Any]
    fingerprint: Callable[[Any], Any] | None = None
    describe: Callable[[Any], str] | None = None


@dataclass(frozen=True)
class Scope:
    """Mark a tool parameter as a query filter the gate computes for the caller::

        def orders_visible_to(request: AuthorizationRequest) -> OrderScope:
            return OrderScope(owner=request.caller.subject)

        @gatehouse.tool(tier=AccessTier.READ, authorize=any_caller, authorize_items=can_see)
        def list_orders(scope: Annotated[OrderScope, Scope(orders_visible_to)]) -> list[Order]: ...

    ``fn`` takes the call's :class:`AuthorizationRequest` and returns
    whatever your query needs: an owner, a tenant, the IDs a
    relationship-based engine lists. The gate can't see your query use it;
    ``authorize_items`` is what checks the result, and the audit log flags
    ``scope_mismatch`` when it had to withhold anything.
    """

    fn: Callable[[AuthorizationRequest], Any]


# --- the window between check and write -------------------------------------


@dataclass(frozen=True)
class Transaction:
    """Load, check, run and commit inside one transaction of yours.

    ``factory(caller)`` returns a context manager, sync or async, that
    begins a transaction and commits on a clean exit or rolls back on an
    exception. The gate enters it, loads the records (lock them:
    ``SELECT … FOR UPDATE``), runs the policy, runs the tool and exits. A
    refusal or an error inside rolls it back. The caller is passed in so
    the factory can tell the database who is asking (``SET LOCAL
    app.subject``) for row-level security. Loaders and the tool reach what
    the context manager yielded through :func:`current_transaction`.

    The gate never holds the transaction open while a person decides on
    an approval: it asks first, then opens the transaction, reloads and
    checks again.

    With a sync context manager, the whole of it runs in one worker
    thread, so a driver tied to its thread stays safe; the loaders, the
    policies and the tool must then be sync. With an async one, the
    loaders and the tool must be async. ``asynchronous`` is inferred from
    ``@contextmanager`` / ``@asynccontextmanager`` and from classes; pass
    it when the factory is something else.
    """

    factory: Callable[[Caller], Any]
    asynchronous: bool | None = None

    def __post_init__(self) -> None:
        if not callable(self.factory):
            raise TypeError("Transaction(factory): factory must be callable")
        if self.asynchronous is None:
            inferred = _infer_async_cm(self.factory)
            if inferred is None:
                raise TypeError(
                    "can't tell whether this transaction factory is sync or async; "
                    "say Transaction(factory, asynchronous=True or False)"
                )
            object.__setattr__(self, "asynchronous", inferred)


@dataclass(frozen=True)
class ConditionalWrite:
    """The tool's write carries the checked state in its own condition.

    ``UPDATE orders SET status = 'cancelled' WHERE id = ? AND version = ?``:
    if the record changed after the check, the write matches nothing, and
    the tool raises :class:`Conflict`. The gate can't see the query, so
    this is your promise; the audit log records it as
    ``consistency: "conditional"``.
    """


@dataclass(frozen=True)
class AcceptRace:
    """The deliberate opt-out: the record may change between check and write.

    Say why. The reason is in the audit line of every call.
    """

    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("AcceptRace needs a reason")


Consistency = Union[Transaction, ConditionalWrite, AcceptRace]


class Conflict(ToolError):
    """Raise from a tool when its conditional write matched nothing.

    The record changed after the gate checked it, so nothing was written.
    The audit log records ``outcome: "conflict"``, and the model is told the
    record changed.
    """

    def __init__(self, message: str = "the record changed before it could be written; nothing was done") -> None:
        super().__init__(message)


_TRANSACTION: contextvars.ContextVar[Any] = contextvars.ContextVar("mcp_gatehouse_transaction")
_NO_TRANSACTION = object()


def current_transaction() -> Any:
    """What the tool's :class:`Transaction` context manager yielded.

    Call it from a loader, a policy, a scope or the tool. Raises
    ``LookupError`` outside a transaction.
    """
    value = _TRANSACTION.get(_NO_TRANSACTION)
    if value is _NO_TRANSACTION:
        raise LookupError("no gatehouse transaction is open here")
    return value


def _infer_async_cm(factory: Callable[..., Any]) -> bool | None:
    """Is ``factory``'s context manager async? ``None`` if it can't be told."""
    if inspect.isclass(factory):
        if hasattr(factory, "__aenter__"):
            return True
        if hasattr(factory, "__enter__"):
            return False
        return None
    target = inspect.unwrap(factory)
    if inspect.isasyncgenfunction(target):
        return True
    if inspect.isgeneratorfunction(target):
        return False
    return None


__all__ = [
    "AcceptRace",
    "Allow",
    "Ask",
    "AuthorizationRequest",
    "Authorizer",
    "ConditionalWrite",
    "Conflict",
    "Consistency",
    "Decision",
    "Deny",
    "Load",
    "Scope",
    "Transaction",
    "any_caller",
    "any_item",
    "current_transaction",
]
