"""The Gatehouse: the one enforcement point around every tool on a server.

Wrap an ``MCPServer`` and register tools through the gate. From then on the
server runs no tool the gate didn't register, and every call it does run
needs, in order:

1. a **verified caller**: the identity in the access token the SDK verified
   for the request, or, over stdio where nobody signs in, the
   ``local_caller`` the server declared;
2. an **explicit policy** for the tool (``authorize=``; ``any_caller`` is the
   deliberate opt-out);
3. a **decision on the record itself**: the gate loads each ``Load``
   parameter from the model's arguments, gives the records to the policy,
   and hands the tool those same objects.

Anything missing, and the call fails closed. Around that, as before:
denylist, approval gates on the tiers you choose (and on ``Ask``), redacted
audit logging naming the caller, and honest ``ToolAnnotations`` from the
tier.
"""

from __future__ import annotations

import asyncio
import collections.abc
import contextvars
import copy
import dataclasses
import functools
import hashlib
import inspect
import json
import math
import sys
import threading
import time
import types
import typing
import uuid
from collections.abc import Generator, Mapping
from types import MappingProxyType
from typing import Annotated, Any, Callable, Literal, TypeVar, get_args, get_origin

import anyio
import anyio.from_thread
import anyio.lowlevel
import anyio.to_thread
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import principal_components
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_REQUEST
from mcp.types import InputRequiredResult, ToolAnnotations
from opentelemetry import trace as _otel_trace
from pydantic import BaseModel

from .approvers import ElicitationApprover, asking_call
from .audit import AuditLog, NullAuditLog
from .authz import (
    _TRANSACTION,
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
)
from .policy import (
    AccessTier,
    ApprovalRequest,
    Caller,
    Policy,
    _canonical,
    _holds_opaque,
    _OPAQUE_PREFIX,
    _check_authorization_timeout,
    _check_on_authorization_timeout,
    redact_arguments,
)

F = TypeVar("F", bound=Callable[..., Any])

# Worker threads for sync approvers, per tool, kept apart from anyio's
# default pool. Sync tools draw on that pool; approvers wait on people. If
# they shared it, a stack of pending sign-offs would leave no thread for a
# plain read. Per tool, and held until the thread returns, as for the
# authorization threads below: an approver still blocked when the approval
# times out can't make another tool's approvals wait, or start more threads.
_APPROVER_THREADS = 40

# Worker threads for sync loaders, policies and scopes, per tool, kept apart
# from the default pool for the same reason: a hung policy must not leave a
# sync tool elsewhere on the server waiting for a thread. Per tool, so a
# policy that hangs on one tool can't make another tool's authorization wait,
# and a thread abandoned at the deadline keeps its place until it returns,
# so one that never does can't start more than this many.
_AUTHORIZE_THREADS = 40

# Worker threads for whole sync transactions, per tool. A sync transaction
# runs its loader, policy and tool in one thread that can't be abandoned
# (the connection is tied to it), so it is kept off the default pool too: a
# policy hung inside one holds only its own tool's threads, never the ones
# plain sync tools run on.
_TRANSACTION_THREADS = 40

# A tool that leaves the authorization deadline to the Policy.
_INHERIT: Any = object()

# The parameter the guard adds, out of the tool's schema, so MCPServer hands
# it the call's Context when the tool takes none itself. Asking the client
# for approval, and telling stdio from HTTP, need one. No leading
# underscore: MCPServer rejects those.
_CONTEXT_PARAM = "gatehouse_context"

# Set while the gate itself registers a tool. The server's own add_tool
# refuses everyone else.
_REGISTERING: contextvars.ContextVar[Any] = contextvars.ContextVar("mcp_gatehouse_registering")

# Set by the call_tool guard for the call it admitted, so the tool's guard
# reads the same caller without resolving it a second time.
_ADMITTED: contextvars.ContextVar[tuple[str, _Who | None]] = contextvars.ContextVar("mcp_gatehouse_admitted")

_UNSET = object()


class GateDenied(PermissionError, ToolError):
    """Raised when the gate blocks a call, so the model sees that it was
    refused.

    Subclassing the SDK's ``ToolError`` is what makes that true. v2 sorts
    tool exceptions into two buckets: a ``ToolError`` is an *anticipated*
    failure, so its message reaches the model and the server logs it at
    INFO; anything else is a crash, and the model gets only "Error
    executing tool <name>" while the server logs a traceback at ERROR.

    A denial is the most anticipated failure a gate has. Without this, a
    policy working exactly as designed would withhold its reason from the
    model and log an ERROR traceback on every refusal — noise that would
    bury the real failures. ``PermissionError`` stays first in the bases so
    existing ``except PermissionError`` handlers keep working.
    """


def _annotations_for(tier: AccessTier, title: str | None) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        read_only_hint=tier is AccessTier.READ,
        destructive_hint=tier is AccessTier.DESTRUCTIVE,
    )


# --- what registration works out about a tool --------------------------------


@dataclasses.dataclass(frozen=True)
class _LoadSpec:
    name: str
    marker: Load
    argnames: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class _ScopeSpec:
    name: str
    marker: Scope


@dataclasses.dataclass(frozen=True)
class _ToolSpec:
    name: str
    tier: AccessTier
    fn: Callable[..., Any]
    authorize: Authorizer
    authorize_items: Authorizer | None
    consistency: Consistency | None
    scopes: frozenset[str]
    loads: tuple[_LoadSpec, ...]
    scope_params: tuple[_ScopeSpec, ...]
    ctx_param: str | None
    bind_signature: inspect.Signature
    exposed_signature: inspect.Signature
    exposed_annotations: dict[str, Any]
    round_trip: bool
    authorization_timeout: float | None
    on_authorization_timeout: Any

    @property
    def open(self) -> bool:
        return self.authorize is any_caller

    @property
    def items_open(self) -> bool:
        return self.authorize_items is any_item

    @property
    def hidden(self) -> frozenset[str]:
        names = {s.name for s in self.loads} | {s.name for s in self.scope_params}
        if self.ctx_param is None:
            names.add(_CONTEXT_PARAM)
        return frozenset(names)


@dataclasses.dataclass(frozen=True)
class _Entry:
    guarded: Callable[..., Any]
    tier: AccessTier


@dataclasses.dataclass(frozen=True)
class _Who:
    """The verified caller of one request."""

    caller: Caller
    claims: Mapping[str, Any]
    local: bool


_Stage = Literal["authorizing", "awaiting approval", "tool running", "filtering", "committing"]

# Each stage's name in the audit line's ``timings_ms``.
_TIMING_KEYS: dict[str, str] = {
    "authorizing": "authorize",
    "awaiting approval": "approval",
    "tool running": "tool",
    "filtering": "filter",
    "committing": "commit",
}


@dataclasses.dataclass
class _CallState:
    """What one call has got to, for the audit lines it writes."""

    stage: _Stage = "authorizing"
    authz: str | None = None
    withheld: int | None = None
    filter_errors: int = 0
    scope_mismatch: bool = False
    continues: str | None = None
    """The ``call_id`` of the round that asked for the approval this round
    answers, on the second round of a round-trip approval."""
    began: float = dataclasses.field(default_factory=time.perf_counter)
    stage_began: float | None = None
    spent: dict[str, float] = dataclasses.field(default_factory=dict)

    def enter(self, stage: _Stage) -> None:
        """Move to ``stage``, adding the time spent in the last one to its total.
        A stage entered twice (authorizing, before and after an approval) adds up."""
        now = time.perf_counter()
        if self.stage_began is not None:
            key = _TIMING_KEYS[self.stage]
            self.spent[key] = self.spent.get(key, 0.0) + (now - self.stage_began)
        self.stage, self.stage_began = stage, now

    def timings_ms(self) -> dict[str, float]:
        """Milliseconds per stage so far, the current one included, and the total."""
        now = time.perf_counter()
        spent = dict(self.spent)
        if self.stage_began is not None:
            key = _TIMING_KEYS[self.stage]
            spent[key] = spent.get(key, 0.0) + (now - self.stage_began)
        timings = {key: round(seconds * 1000, 2) for key, seconds in spent.items()}
        timings["total"] = round((now - self.began) * 1000, 2)
        return timings


@dataclasses.dataclass(frozen=True)
class _Call:
    """One call's inputs, as the gate's steps need them."""

    spec: _ToolSpec
    who: _Who
    call_id: str
    arguments: dict[str, Any]
    view: Mapping[str, Any]
    safe_args: dict[str, Any]
    args: tuple
    kwargs: dict[str, Any]
    context: Any


class _Refused(Exception):
    """A step refused the call. Raised inside a transaction so it rolls back."""

    def __init__(self, reason: str, message: str | None = None, *, outcome: str = "denied") -> None:
        super().__init__(reason)
        self.reason = reason
        self.message = message
        self.outcome = outcome


class _DeadlinePassed(Exception):
    """A step before the tool ran past the authorization deadline. The
    driver throws it into the steps at the yield that ran out."""


# The reason an approver sees when a policy ran out of time and the tool
# asks instead of denying. Stable, so the approval binds to it.
_TIMEOUT_ASK_REASON = "authorization timed out"


def _timed_out_message(tool_name: str) -> str:
    """What the model is told: not a refusal on the merits, and nothing ran."""
    return (
        f"'{tool_name}' couldn't be authorized in time, so nothing ran. "
        "This isn't a refusal; the call can be retried."
    )


class _NeedsApproval(Exception):
    """A person has to decide before the call can go on.

    Raised inside a transaction so it rolls back: nothing holds a lock while
    someone makes up their mind. ``via`` says how to ask.
    """

    def __init__(self, request: ApprovalRequest, via: str) -> None:
        super().__init__(via)
        self.request = request
        self.via = via


class Gatehouse:
    """The enforcement point around every tool on an :class:`MCPServer`.

    Usage::

        mcp = MCPServer("orders")
        gk = Gatehouse(mcp, policy=Policy(...), audit=AuditLog(path="audit.jsonl"))

        @gk.tool(tier=AccessTier.READ, authorize=any_caller)
        def lookup_order(order_id: str) -> str: ...

        @gk.tool(tier=AccessTier.DESTRUCTIVE, authorize=can_cancel, consistency=...)
        def cancel_order(order_id: str, order: Annotated[Order, Load(load_order)]) -> str: ...

    Create it before registering any tool: it refuses a server that already
    has tools, and from then on the server refuses tools registered around
    it. Resources, prompts and completions too: they have no policy, so
    they are refused unless registered with :meth:`open_resource` or
    :meth:`open_prompt`, for content any verified caller may read.

    ``local_caller`` is who a call is for when nobody signed in: stdio, and
    in-memory clients. It never applies to an HTTP request; an HTTP call
    without a verified token is denied. ``consistency`` is the default for
    tools that don't set their own.
    """

    def __init__(
        self,
        server: MCPServer,
        policy: Policy | None = None,
        audit: AuditLog | None = None,
        *,
        local_caller: Caller | None = None,
        consistency: Consistency | None = None,
    ) -> None:
        if local_caller is not None and not isinstance(local_caller, Caller):
            raise TypeError("local_caller must be a Caller")
        _check_consistency(consistency)
        self.server = server
        self.policy = policy or Policy()
        self.audit = audit or NullAuditLog()
        self.local_caller = local_caller
        self.consistency = consistency
        # The pool the authorization and approver threads come from never
        # makes a step wait: the per-tool places below are the limit.
        self._authorize_pool = anyio.CapacityLimiter(math.inf)
        self._authorize_places: dict[str, _Places] = {}
        self._approver_places: dict[str, _Places] = {}
        self._transaction_threads: dict[str, anyio.CapacityLimiter] = {}
        self._registry: dict[str, _Entry] = {}
        self._lock_down()

    # --- the server, locked down ---------------------------------------------

    def _lock_down(self) -> None:
        """Make the gate the only way a tool gets onto, and runs on, the server."""
        server = self.server
        manager = getattr(server, "_tool_manager", None)
        if manager is None or not all(
            callable(getattr(manager, attr, None)) for attr in ("get_tool", "list_tools", "add_tool", "call_tool")
        ) or not all(callable(getattr(server, attr, None)) for attr in ("add_tool", "call_tool", "list_tools")):
            raise RuntimeError(
                "mcp-gatehouse can't enforce its gate on this version of the mcp SDK: "
                "the tool registry it guards isn't there. The gate fails closed."
            )
        if getattr(server, "_mcp_gatehouse", None) is not None:
            raise ValueError("this server already has a Gatehouse")
        existing = sorted(tool.name for tool in manager.list_tools())
        if existing:
            raise ValueError(
                "the server already has tools registered outside the gate: "
                + ", ".join(existing)
                + ". Create the Gatehouse first and register every tool through it."
            )
        resources, prompts = self._other_registries()
        self._check_extensions()
        self._manager: Any = manager
        server._mcp_gatehouse = self  # type: ignore[attr-defined]
        gate = self

        def refuse_unless_gate(original: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(original)
            def add_tool(*args: Any, **kwargs: Any) -> Any:
                if _REGISTERING.get(None) is not gate:
                    raise TypeError(
                        "this server is gated: register tools with @gatehouse.tool(...), "
                        "not directly on the MCPServer"
                    )
                return original(*args, **kwargs)

            return add_tool

        server.add_tool = refuse_unless_gate(server.add_tool)  # type: ignore[method-assign]
        manager.add_tool = refuse_unless_gate(manager.add_tool)  # type: ignore[method-assign]
        self._lock_down_others(resources, prompts)

        server_call = server.call_tool
        manager_call = manager.call_tool
        server_list = server.list_tools

        @functools.wraps(server_call)
        async def call_tool(name: str, arguments: dict[str, Any], context: Any = None, *args: Any, **kwargs: Any) -> Any:
            who = gate._admit(name, arguments, context)
            admitted = _ADMITTED.set((name, who))
            try:
                return await server_call(name, arguments, context, *args, **kwargs)
            finally:
                _ADMITTED.reset(admitted)

        @functools.wraps(manager_call)
        async def manager_call_tool(name: str, arguments: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            gate._admit(name, arguments, None, check_caller=False)
            return await manager_call(name, arguments, *args, **kwargs)

        @functools.wraps(server_list)
        async def list_tools(*args: Any, **kwargs: Any) -> Any:
            tools = await server_list(*args, **kwargs)
            return [tool for tool in tools if gate._gated(tool.name) is True]

        server.call_tool = call_tool  # type: ignore[method-assign]
        manager.call_tool = manager_call_tool  # type: ignore[method-assign]
        server.list_tools = list_tools  # type: ignore[method-assign]

    def _check_extensions(self) -> None:
        """Refuse SDK extensions that serve around the gate.

        Their tools and resources are refused with the rest of the registry.
        Two more contributions reach data with no policy and no audit line:
        a request method of the extension's own (``Extension.methods()``),
        and a ``tools/call`` interceptor (an overridden
        ``Extension.intercept_tool_call``), which runs before the gate and
        can answer a call itself. Extensions are fixed when the server is
        made, so checking here covers them.
        """
        try:
            from mcp.server.extension import Extension
        except ImportError:  # pragma: no cover - an SDK without extensions
            return
        extensions = getattr(self.server, "_extensions", None)
        if not isinstance(extensions, list):
            raise RuntimeError(
                "mcp-gatehouse can't enforce its gate on this version of the mcp SDK: "
                "the server's extensions aren't where it checks them. The gate fails closed."
            )
        around: list[str] = []
        for extension in extensions:
            name = getattr(extension, "identifier", type(extension).__name__)
            around += [f"method {binding.method} (from {name})" for binding in extension.methods()]
            if type(extension).intercept_tool_call is not Extension.intercept_tool_call:
                around.append(f"intercept_tool_call (from {name})")
        if around:
            raise ValueError(
                "the server has extensions that serve around the gate: "
                + ", ".join(around)
                + ". An extension's own request methods and a tools/call interceptor run with no "
                "policy and no audit line; put what they serve behind a tool registered with "
                "@gatehouse.tool(...)."
            )

    def _other_registries(self) -> tuple[Any, Any]:
        """The server's resource and prompt registries, checked before the
        gate touches the server: they must be there, and empty.

        Resources and prompts are other ways to the same data. A resource
        template ``orders://{id}`` reads the record a tool would, with no
        policy and no caller check. Completions suggest argument values
        (order ids, customer names) and never see who is asking.
        """
        server = self.server
        resources = getattr(server, "_resource_manager", None)
        prompts = getattr(server, "_prompt_manager", None)
        lowlevel = getattr(server, "_lowlevel_server", None)
        if (
            not all(callable(getattr(resources, a, None)) for a in ("add_resource", "add_template", "list_resources", "list_templates"))
            or not all(callable(getattr(prompts, a, None)) for a in ("add_prompt", "list_prompts"))
            or not all(callable(getattr(server, a, None)) for a in ("add_resource", "add_prompt", "read_resource", "get_prompt", "completion"))
            or not isinstance(getattr(lowlevel, "_request_handlers", None), dict)
        ):
            raise RuntimeError(
                "mcp-gatehouse can't enforce its gate on this version of the mcp SDK: "
                "the resource and prompt registries it guards aren't there. The gate fails closed."
            )
        existing = [str(r.uri) for r in resources.list_resources()]
        existing += [str(t.uri_template) for t in resources.list_templates()]
        existing += [f"prompt {p.name}" for p in prompts.list_prompts()]
        if "completion/complete" in lowlevel._request_handlers:
            existing.append("a completion handler")
        if existing:
            raise ValueError(
                "the server already has resources, prompts or completions registered outside the gate: "
                + ", ".join(sorted(existing))
                + ". Create the Gatehouse first; use gatehouse.open_resource(...) and "
                "gatehouse.open_prompt(...) for content any verified caller may read, "
                "and a READ tool for anything per caller."
            )
        return resources, prompts

    def _lock_down_others(self, resources: Any, prompts: Any) -> None:
        """Refuse resources, prompts and completions added around the gate,
        and deny reads of the open ones without a verified caller."""
        server, gate = self.server, self

        def refuse_unless_gate(original: Callable[..., Any], what: str) -> Callable[..., Any]:
            @functools.wraps(original)
            def add(*args: Any, **kwargs: Any) -> Any:
                if _REGISTERING.get(None) is not gate:
                    raise TypeError(
                        f"this server is gated: {what} have no policy, so they can't be registered "
                        f"directly on the MCPServer. Use gatehouse.open_{what[:-1]}(...) for content "
                        "any verified caller may read, or a READ tool with a policy for anything "
                        "that depends on who is asking"
                    )
                return original(*args, **kwargs)

            return add

        server.add_resource = refuse_unless_gate(server.add_resource, "resources")  # type: ignore[method-assign]
        resources.add_resource = refuse_unless_gate(resources.add_resource, "resources")
        resources.add_template = refuse_unless_gate(resources.add_template, "resources")
        server.add_prompt = refuse_unless_gate(server.add_prompt, "prompts")  # type: ignore[method-assign]
        prompts.add_prompt = refuse_unless_gate(prompts.add_prompt, "prompts")

        def completion(*args: Any, **kwargs: Any) -> Any:
            raise TypeError(
                "this server is gated: a completion handler never sees who is asking, "
                "so it could suggest values (ids, names) the caller may not see. "
                "Completions can't be registered on a gated server."
            )

        server.completion = completion  # type: ignore[method-assign]

        server_read = server.read_resource
        server_prompt = server.get_prompt

        @functools.wraps(server_read)
        async def read_resource(uri: Any, context: Any = None, *args: Any, **kwargs: Any) -> Any:
            if gate._resolve(context) is None:
                raise MCPError(INVALID_REQUEST, f"reading {uri} needs a verified caller, and this request has none.")
            return await server_read(uri, context, *args, **kwargs)

        @functools.wraps(server_prompt)
        async def get_prompt(name: str, arguments: Any = None, context: Any = None, *args: Any, **kwargs: Any) -> Any:
            if gate._resolve(context) is None:
                raise MCPError(INVALID_REQUEST, f"prompt '{name}' needs a verified caller, and this request has none.")
            return await server_prompt(name, arguments, context, *args, **kwargs)

        server.read_resource = read_resource  # type: ignore[method-assign]
        server.get_prompt = get_prompt  # type: ignore[method-assign]

    def open_resource(self, uri: str, **resource_kwargs: Any) -> Callable[[F], F]:
        """Register a resource any verified caller may read: the same for
        everyone, such as docs, a schema or a price list.

        It has no policy and writes no audit line; a read without a verified
        caller is refused. Takes what ``MCPServer.resource`` takes. Anything
        that depends on who is asking (a customer's order, a user's file),
        including a template whose parameters pick a record, belongs in a
        READ tool with a policy instead.
        """
        if not isinstance(uri, str):
            raise TypeError("use @gatehouse.open_resource(\"scheme://...\"), with the URI")
        return self._register_open(lambda: self.server.resource(uri, **resource_kwargs))

    def open_prompt(self, **prompt_kwargs: Any) -> Callable[[F], F]:
        """Register a prompt any verified caller may get. The same terms as
        :meth:`open_resource`; takes what ``MCPServer.prompt`` takes."""
        return self._register_open(lambda: self.server.prompt(**prompt_kwargs))

    def _register_open(self, make: Callable[[], Callable[[F], F]]) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            registering = _REGISTERING.set(self)
            try:
                return make()(fn)
            finally:
                _REGISTERING.reset(registering)

        return decorator

    def _gated(self, name: str) -> bool | None:
        """``True`` if the gate's own guard is what would run for ``name``;
        ``None`` if there's no such tool; ``False`` otherwise, including when
        the gate can't tell."""
        try:
            registry: Any = getattr(self.server, "_tool_manager", None)
            if registry is not self._manager:
                return False  # the registry was swapped out from under the gate
            tool = self._manager.get_tool(name)
            if tool is None:
                return None
            entry = self._registry.get(name)
            return entry is not None and getattr(tool, "fn", None) is entry.guarded
        except Exception:
            return False

    def _admit(self, name: str, arguments: Any, context: Any, *, check_caller: bool = True) -> _Who | None:
        """Refuse a call before the SDK touches it: a tool the gate didn't
        register, or (when ``check_caller``) a request with no verified caller.

        Returns the caller it resolved, so the guard needn't resolve it again;
        the guard still denies a call that reaches it with none.
        """
        gated = self._gated(name)
        if gated is None:
            return None  # no such tool: the SDK says so

        def safe() -> dict[str, Any]:
            return redact_arguments(arguments if isinstance(arguments, Mapping) else {}, self.policy.redact)

        if gated is False:
            self.audit.record(
                call_id=_new_call_id(), tool=name, tier=None, outcome="denied", reason="ungated tool",
                arguments=safe(), **_correlation(context),
            )
            raise GateDenied(f"'{name}' was not registered through the gate, so it can't run.")
        if not check_caller:
            return None
        who = self._resolve(context)
        if who is None:
            self.audit.record(
                call_id=_new_call_id(), tool=name, tier=self._registry[name].tier.value, outcome="denied",
                reason="no verified caller", arguments=safe(), **_correlation(context),
            )
            raise GateDenied(_no_caller_message(name))
        return who

    # --- identity ------------------------------------------------------------

    def _resolve(self, context: Any) -> _Who | None:
        """Who this request is for, or ``None`` if nobody verifiable.

        A verified access token wins: the SDK's auth middleware puts each
        HTTP request's token in a context variable tool calls inherit, so
        this is the current request's, also after a refresh. Without one,
        the declared ``local_caller`` applies only when the call came in
        with no HTTP request behind it (stdio, in-memory): an anonymous HTTP
        request is nobody, never the local user. A call with no live
        request at all (``MCPServer.call_tool`` from code) is nobody too.
        """
        token = get_access_token()
        if token is not None:
            client_id, issuer, subject = principal_components(token)
            caller = Caller(client_id=client_id, subject=subject, issuer=issuer, scopes=tuple(token.scopes))
            return _Who(caller, _read_only(token.claims or {}), local=False)
        if self.local_caller is None:
            return None
        try:
            request_context = context.request_context
        except Exception:
            return None
        if getattr(request_context, "request", None) is not None:
            return None
        return _Who(self.local_caller, MappingProxyType({}), local=True)

    # --- registration --------------------------------------------------------

    def tool(
        self,
        tier: AccessTier = AccessTier.READ,
        *,
        authorize: Authorizer | None = None,
        authorize_items: Authorizer | None = None,
        consistency: Consistency | None = None,
        scopes: collections.abc.Iterable[str] = (),
        authorization_timeout: float | None = _INHERIT,
        on_authorization_timeout: Any = _INHERIT,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        **tool_kwargs: Any,
    ) -> Callable[[F], F]:
        """Register a tool on the wrapped server, with enforcement.

        ``authorize`` is required: the policy that decides each call, or
        ``any_caller`` to let any verified caller in on purpose.
        ``authorize_items`` is required when the tool returns a list of
        records, and decides item by item what the caller may see
        (``any_item`` opts out). ``consistency`` is required for WRITE and
        DESTRUCTIVE tools that ``Load`` a record, unless the Gatehouse sets
        a default. ``scopes`` are token scopes the caller must hold.
        ``authorization_timeout`` and ``on_authorization_timeout`` override
        the Policy's for this tool; ``authorization_timeout=None`` turns the
        deadline off, and the tool's audit lines say so.

        Accepts any extra keyword arguments ``MCPServer.tool`` understands
        and forwards them untouched. ``annotations`` is derived from the
        tier and cannot be overridden — the hints must stay honest.
        """
        if callable(tier):
            raise TypeError(
                "use @gatehouse.tool(...) with parentheses, not @gatehouse.tool"
            )
        if "annotations" in tool_kwargs:
            raise ValueError(
                "annotations are derived from the tier; set tier=... instead"
            )
        if authorize is None:
            raise TypeError(
                "every gated tool needs a policy: authorize=<your policy>, "
                "or authorize=any_caller to let any verified caller in on purpose"
            )
        if not callable(authorize):
            raise TypeError("authorize must be a callable policy")
        if authorize_items is not None and not callable(authorize_items):
            raise TypeError("authorize_items must be a callable policy")
        _check_consistency(consistency)
        required_scopes = frozenset({scopes} if isinstance(scopes, str) else scopes)
        if authorization_timeout is not _INHERIT:
            _check_authorization_timeout(authorization_timeout)
        if on_authorization_timeout is not _INHERIT:
            on_authorization_timeout = _check_on_authorization_timeout(on_authorization_timeout)

        def decorator(fn: F) -> F:
            tool_name = name or fn.__name__
            if self._manager.get_tool(tool_name) is not None:
                raise ValueError(f"a tool named {tool_name!r} is already registered")
            # The scope the tool is defined in, so a string annotation naming
            # a local (a Load(...) bound to a database handle, a model class
            # defined in a function) still evaluates.
            frame = inspect.currentframe()
            scope = frame.f_back if frame is not None else None
            try:
                defined_in = dict(scope.f_locals) if scope is not None else {}
            finally:
                del frame, scope
            # The tool's own settings, else the gate's defaults.
            spec = _build_spec(
                fn,
                tool_name,
                tier=tier,
                authorize=authorize,
                authorize_items=authorize_items,
                consistency=consistency if consistency is not None else self.consistency,
                scopes=required_scopes,
                policy=self.policy,
                localns=defined_in,
                authorization_timeout=(
                    self.policy.authorization_timeout
                    if authorization_timeout is _INHERIT
                    else authorization_timeout
                ),
                on_authorization_timeout=(
                    self.policy.on_authorization_timeout
                    if on_authorization_timeout is _INHERIT
                    else on_authorization_timeout
                ),
            )
            guarded = self._guard(spec)
            registering = _REGISTERING.set(self)
            try:
                self.server.tool(
                    name=tool_name,
                    title=title,
                    description=description,
                    annotations=_annotations_for(tier, title),
                    **tool_kwargs,
                )(guarded)
            finally:
                _REGISTERING.reset(registering)
            self._registry[tool_name] = _Entry(guarded, tier)
            self._verify_registration(spec, guarded)
            return fn

        return decorator

    def _verify_registration(self, spec: _ToolSpec, guarded: Callable[..., Any]) -> None:
        """Read the tool back from the server and check the gate is what runs,
        and that nothing the gate fills is something the model can send.

        A future SDK that put a ``Load`` parameter into the input schema
        would let the model hand the tool its own "loaded" record. That must
        stop the server, not slip through.
        """
        problems: list[str] = []
        try:
            tool = self._manager.get_tool(spec.name)
            if tool is None or tool.fn is not guarded:
                problems.append("the server kept a different function for this name")
            else:
                visible = set((tool.parameters or {}).get("properties", {}))
                model = tool.fn_metadata.arg_model
                visible |= set(model.model_fields)
                visible |= {f.alias for f in model.model_fields.values() if f.alias}
                leaked = sorted(spec.hidden & visible)
                if leaked:
                    problems.append(f"parameters the gate fills are in the input schema: {', '.join(leaked)}")
                # The other way round too: everything the model can send is
                # a parameter the gate knows it leaves to the model.
                expected_args = {p for p in spec.bind_signature.parameters if p != spec.ctx_param}
                sent = {f.alias or name for name, f in model.model_fields.items()}
                sent |= set((tool.parameters or {}).get("properties", {}))
                unknown = sorted(sent - expected_args)
                if unknown:
                    problems.append(f"the input schema has parameters the gate didn't expect: {', '.join(unknown)}")
                if getattr(tool, "resolved_params", None):
                    problems.append("the SDK resolves some of its parameters before the gate")
                expected = spec.ctx_param or _CONTEXT_PARAM
                if tool.context_kwarg != expected:
                    problems.append(f"the SDK injects its Context into {tool.context_kwarg!r}, not {expected!r}")
        except Exception as exc:  # pragma: no cover - only on an SDK the gate doesn't know
            problems.append(f"the registered tool couldn't be read back ({type(exc).__name__})")
        if problems:
            self._registry.pop(spec.name, None)
            try:
                self.server.remove_tool(spec.name)
            except Exception:
                pass
            raise RuntimeError(f"{spec.name}: refusing to register: " + "; ".join(problems))

    # --- the guard -----------------------------------------------------------

    def _guard(self, spec: _ToolSpec) -> Callable[..., Any]:
        gate, policy, audit = self, self.policy, self.audit
        fn = spec.fn

        tool_fields = _static_audit_fields(spec)

        async def run(arguments: dict[str, Any], args: tuple, kwargs: dict[str, Any], context: Any) -> Any:
            safe_args = redact_arguments(arguments, policy.redact)
            # Read once, so every line this call writes names the same caller:
            # what the call_tool guard resolved when it admitted this call,
            # else (a call that came in another way) resolved here.
            admitted = _ADMITTED.get(None)
            who = admitted[1] if admitted is not None and admitted[0] == spec.name else gate._resolve(context)
            state = _CallState()
            call_id = _new_call_id()
            fixed: dict[str, Any] = _correlation(context)
            if spec.loads:
                fixed["resources"] = {
                    load.name: {arg: safe_args.get(arg) for arg in load.argnames} for load in spec.loads
                }
            if spec.items_open:
                fixed["items"] = "open"
            fixed.update(tool_fields)

            def record(**event: Any) -> None:
                """One audit line for this call."""
                if who is not None:
                    event["caller"] = _caller_entry(who)
                if state.authz is not None:
                    event["authz"] = state.authz
                if state.continues is not None:
                    event["continues"] = state.continues
                event.update(fixed)
                timings = state.timings_ms()
                # Stages with nothing to do take ~0 and would only be noise.
                if spec.authorize_items is None or spec.items_open:
                    timings.pop("filter", None)
                if not isinstance(spec.consistency, Transaction):
                    timings.pop("commit", None)
                event["timings_ms"] = timings
                if "duration_ms" in event:
                    # The same number as timings_ms.tool, from the same
                    # clock read; None when the tool never started.
                    event["duration_ms"] = timings.get("tool")
                audit.record(call_id=call_id, tool=spec.name, tier=spec.tier.value, **event)

            def denied(reason: str, message: str, outcome: str = "denied") -> GateDenied:
                record(outcome=outcome, reason=reason, arguments=safe_args)
                return GateDenied(message)

            if spec.name in policy.deny:
                raise denied("denylist", f"'{spec.name}' is blocked by policy.")
            if who is None:
                raise denied("no verified caller", _no_caller_message(spec.name))
            missing = sorted(spec.scopes - set(who.caller.scopes))
            if missing:
                raise denied(
                    "missing scope: " + ", ".join(missing),
                    f"'{spec.name}' needs the token scope {', '.join(missing)}, "
                    "which this caller's token doesn't carry.",
                )

            call = _Call(
                spec=spec, who=who, call_id=call_id, arguments=arguments, view=_read_only(arguments),
                safe_args=safe_args, args=args, kwargs=kwargs, context=context,
            )
            approved: str | None = None
            while True:
                state.enter("authorizing")
                try:
                    result = await gate._authorize_and_run(call, approved, state)
                except _Refused as refusal:
                    raise denied(
                        refusal.reason, refusal.message or _not_permitted_message(spec.name), refusal.outcome
                    ) from None
                except _NeedsApproval as need:
                    if approved is not None:  # pragma: no cover - the phase compares bindings
                        raise denied("approval did not apply", _not_permitted_message(spec.name)) from None
                    state.enter("awaiting approval")
                    question = await gate._obtain_approval(need, call, record, denied)
                    if question is not None:
                        return question
                    approved = need.request.binding
                    continue
                except Conflict:
                    record(
                        outcome="conflict", reason="the record changed before the write",
                        arguments=safe_args, duration_ms=None,
                    )
                    raise
                except Exception as exc:
                    # Only the exception TYPE goes in the log. Exception
                    # messages routinely embed argument values ("invalid api
                    # key: sk-…"), which would defeat redaction. The client
                    # still receives the full message through the normal
                    # tool-error path.
                    if state.stage == "tool running":
                        record(
                            outcome="error", reason=type(exc).__name__, arguments=safe_args,
                            duration_ms=None,
                        )
                    else:
                        # Outside the tool, only the transaction's own code
                        # (factory, enter, commit) raises past the gate's
                        # steps, which turn their errors into refusals.
                        where = "transaction" if isinstance(spec.consistency, Transaction) else "gate"
                        record(
                            outcome="error", reason=f"{where} error: {type(exc).__name__}",
                            arguments=safe_args,
                        )
                    raise
                except anyio.get_cancelled_exc_class():
                    # The client gave up, or the server is shutting down. Log
                    # it, then let it carry on as is: swallowing it would keep
                    # a cancelled task running. A tool cut off mid-run may
                    # have done part of its work, which is what the trail is
                    # for; inside a transaction, that work rolls back.
                    # Filtering and committing come after the tool ran.
                    if state.stage != "authorizing":
                        record(
                            outcome="cancelled", reason="tool running", arguments=safe_args,
                            duration_ms=None,
                        )
                    else:
                        record(outcome="cancelled", reason="authorizing", arguments=safe_args)
                    raise
                event: dict[str, Any] = {"outcome": "ok", "arguments": safe_args, "duration_ms": None}
                if state.withheld is not None:
                    event["withheld"] = state.withheld
                    if state.filter_errors:
                        event["filter_errors"] = state.filter_errors
                    if state.scope_mismatch:
                        event["scope_mismatch"] = True
                record(**event)
                return result

        # functools.wraps preserves the name and docstring. The signature the
        # SDK builds the schema from is __signature__, set below: the tool's
        # own, minus what the gate fills, plus the hidden Context. It is
        # computed once, at registration, not on every call.
        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            context = kwargs.pop(_CONTEXT_PARAM, None) if spec.ctx_param is None else None
            bound = spec.bind_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            if spec.ctx_param is not None:
                # MCPServer injects its Context as a regular parameter. It is
                # not a model-supplied argument, so it stays out of the audit
                # trail, the policy and what the approver sees.
                context = arguments.pop(spec.ctx_param, None)
            return await run(arguments, args, kwargs, context)

        guarded.__signature__ = spec.exposed_signature  # type: ignore[attr-defined]
        # A fresh dict: wraps() shares fn's own, which must stay untouched.
        guarded.__annotations__ = dict(spec.exposed_annotations)
        return guarded

    async def _authorize_and_run(self, call: _Call, approved: str | None, state: _CallState) -> Any:
        """Load, authorize and run, inside the tool's transaction if it has one."""
        steps = self._steps(call, approved, state)
        transaction = call.spec.consistency if isinstance(call.spec.consistency, Transaction) else None
        timeout, limiter = call.spec.authorization_timeout, self._places(call.spec.name)
        if transaction is None:
            return await _drive_async(steps, timeout, limiter)
        if transaction.asynchronous:
            return await _run_async_transaction(transaction, call.who.caller, steps, timeout, limiter)
        # One worker thread for the whole transaction: sync database drivers
        # are often tied to the thread that opened the connection.
        threads = self._transaction_threads.get(call.spec.name)
        if threads is None:
            threads = self._transaction_threads[call.spec.name] = anyio.CapacityLimiter(_TRANSACTION_THREADS)
        return await anyio.to_thread.run_sync(
            functools.partial(_run_sync_transaction, transaction, call.who.caller, steps, timeout),
            limiter=threads,
        )

    def _places(self, tool: str) -> _Places:
        places = self._authorize_places.get(tool)
        if places is None:
            places = self._authorize_places[tool] = _Places(tool, _AUTHORIZE_THREADS, self._authorize_pool)
        return places

    def _approver_places_for(self, tool: str) -> _Places:
        places = self._approver_places.get(tool)
        if places is None:
            places = self._approver_places[tool] = _Places(
                tool, _APPROVER_THREADS, self._authorize_pool,
                what="sync approver", deadline="approval timeout",
            )
        return places

    def _steps(self, call: _Call, approved: str | None, state: _CallState) -> Generator[Callable[[], Any], Any, Any]:
        """The call, step by step. Each ``yield`` hands the driver a callable
        to run (the user's loader, policy, tool, …) and gets its result back.

        Written once, driven two ways: on the event loop, or all in one
        worker thread inside a sync transaction. Raises ``_Refused`` or
        ``_NeedsApproval`` to stop; inside a transaction, both roll it back.
        Each stage below is a generator of its own, joined with
        ``yield from``, which passes the driver's ``_DeadlinePassed`` through to
        the step that ran out.
        """
        spec = call.spec
        loaded = yield from self._load_records(call)
        request = AuthorizationRequest(
            caller=call.who.caller, tool=spec.name, tier=spec.tier, action="call",
            arguments=call.view, resources=MappingProxyType(dict(loaded)), claims=call.who.claims,
        )
        decision = yield from self._decide(call, request)
        state.authz = _authz_label(spec, decision)
        if isinstance(decision, Deny):
            prefix = "policy after approval: " if approved is not None else "policy: "
            raise _Refused(prefix + decision.reason, decision.message)

        # Every Ask goes to the gate, whatever the tier: an Ask that ran
        # without asking anyone would be an Allow by another name.
        if isinstance(decision, Ask) or self.policy.needs_approval(spec.tier):
            reason = decision.reason if isinstance(decision, Ask) else None
            self._settle_approval(call, reason, loaded, approved, state)

        scoped = yield from self._compute_scopes(call, request)

        yield _BEFORE_TOOL
        state.enter("tool running")
        result = yield functools.partial(spec.fn, *call.args, **call.kwargs, **loaded, **scoped)
        state.enter("filtering")
        result = yield from self._filter_result(call, request, result, state)
        state.enter("committing")
        return result

    def _load_records(self, call: _Call) -> Generator[Callable[[], Any], Any, dict[str, Any]]:
        """Each ``Load`` parameter's record, from the model's arguments."""
        spec = call.spec
        loaded: dict[str, Any] = {}
        for load in spec.loads:
            step = functools.partial(load.marker.loader, **{arg: call.arguments[arg] for arg in load.argnames})
            try:
                found = yield step
            except _DeadlinePassed:
                raise _Refused(f"{_TIMEOUT_ASK_REASON}: loading {load.name}", _timed_out_message(spec.name)) from None
            except Exception as exc:
                raise _Refused(f"loader error: {type(exc).__name__}") from exc
            if found is None:
                raise _Refused(f"not found: {load.name}")
            loaded[load.name] = found
        return loaded

    def _decide(self, call: _Call, request: AuthorizationRequest) -> Generator[Callable[[], Any], Any, Decision]:
        """The policy's decision. Anything but an ``Allow``, ``Deny`` or
        ``Ask`` is a refusal; so is running out of time, unless the tool
        says to ask a person instead."""
        spec = call.spec
        if spec.open:
            return Allow()
        try:
            decision = yield functools.partial(spec.authorize, request)
        except _DeadlinePassed:
            if spec.on_authorization_timeout is not Ask:
                raise _Refused(f"{_TIMEOUT_ASK_REASON}: policy", _timed_out_message(spec.name)) from None
            return Ask(_TIMEOUT_ASK_REASON)
        except Exception as exc:
            raise _Refused(f"policy error: {type(exc).__name__}") from exc
        if not isinstance(decision, (Allow, Deny, Ask)):
            raise _Refused(f"policy returned {type(decision).__name__}")
        return decision

    def _compute_scopes(
        self, call: _Call, request: AuthorizationRequest
    ) -> Generator[Callable[[], Any], Any, dict[str, Any]]:
        """Each ``Scope`` parameter's value, computed from the request."""
        spec = call.spec
        scoped: dict[str, Any] = {}
        for scope in spec.scope_params:
            try:
                scoped[scope.name] = yield functools.partial(scope.marker.fn, request)
            except _DeadlinePassed:
                raise _Refused(f"{_TIMEOUT_ASK_REASON}: scope {scope.name}", _timed_out_message(spec.name)) from None
            except Exception as exc:
                raise _Refused(f"scope error: {type(exc).__name__}") from exc
        return scoped

    def _filter_result(
        self, call: _Call, request: AuthorizationRequest, result: Any, state: _CallState
    ) -> Generator[Callable[[], Any], Any, Any]:
        """The tool's result with the items the caller may not see taken
        out, when the tool has an item policy."""
        spec = call.spec
        if (
            spec.authorize_items is None
            or spec.items_open
            or result is None
            or isinstance(result, InputRequiredResult)
        ):
            return result
        if not isinstance(result, collections.abc.Sequence) or isinstance(result, (str, bytes, bytearray)):
            raise _Refused(
                f"unfilterable result: {type(result).__name__}",
                f"'{spec.name}' returned something the gate can't filter item by item, "
                "so it isn't returned.",
                outcome="error",
            )

        def item_request(item: Any) -> AuthorizationRequest:
            return dataclasses.replace(request, action="read", resource=item)

        if _is_async_callable(spec.authorize_items):
            kept, errors = yield from _filter_each(spec.authorize_items, result, item_request)
        else:
            try:
                # A sync item policy: the whole list in one step, one
                # thread hop rather than one per item.
                kept, errors = yield functools.partial(_filter_items, spec.authorize_items, result, item_request)
            except _AwaitableVerdict:
                # Sync on the outside, async inside (a decorator that
                # hides the coroutine): each verdict gets awaited.
                kept, errors = yield from _filter_each(spec.authorize_items, result, item_request)
        state.withheld = len(result) - len(kept)
        state.filter_errors = errors
        state.scope_mismatch = bool(spec.scope_params) and state.withheld > 0
        return tuple(kept) if isinstance(result, tuple) else kept

    def _settle_approval(
        self, call: _Call, reason: str | None, loaded: dict[str, Any], approved: str | None, state: _CallState
    ) -> None:
        """Settle what can be settled now; raise ``_NeedsApproval`` for the rest.

        Returns when the call may go on: no approver needed after all, an
        approval already given for exactly this state, or an answer the
        client sent back with this round.
        """
        spec, policy = call.spec, self.policy
        approver = policy.approver
        if approver is None:
            if reason is None and not policy.fail_closed:
                return
            raise _Refused(
                "approval required, no approver configured",
                f"'{spec.name}' ({spec.tier.value}) requires approval and no approver "
                "is configured. The gate fails closed.",
            )
        request = self._approval_request(call, reason, loaded)
        if approved is not None:
            if approved != request.binding:
                raise _Refused(
                    "resource changed while awaiting approval",
                    f"'{spec.name}': the record changed while the approval was pending, so "
                    "the approval no longer applies. Nothing was done.",
                )
            return
        if isinstance(approver, ElicitationApprover):
            transport = approver.transport(call.context, round_trip=spec.round_trip)
            if transport == "round-trip":
                try:
                    # A custom message= runs in here, and can raise.
                    verdict = approver.answer(request, call.context)
                except Exception as exc:
                    why = f"approver error: {type(exc).__name__}"
                    raise _Refused(why, _approval_refused_message(spec.name, why)) from exc
                if verdict is None:
                    raise _NeedsApproval(request, "round-trip")
                # An answer to a question this gate asked: the line says
                # which call asked it, so the two rounds read as one.
                state.continues = asking_call(call.context)
                allowed, why = verdict
                if not allowed:
                    raise _Refused(why, _approval_refused_message(spec.name, why))
                return
            if transport == "back-channel":
                raise _NeedsApproval(request, "back-channel")
            if approver.fallback is None:
                raise _Refused(
                    "approval required, client cannot be asked",
                    f"'{spec.name}' ({spec.tier.value}) requires approval, and this "
                    "client can't be asked for it (no form elicitation). "
                    "The gate fails closed.",
                )
            raise _NeedsApproval(request, "fallback")
        raise _NeedsApproval(request, "approver")

    def _approval_request(self, call: _Call, reason: str | None, loaded: dict[str, Any]) -> ApprovalRequest:
        """What the approver sees, and the binding that ties its answer to
        this caller, this reason and these records in this state."""
        spec, policy = call.spec, self.policy
        lines: list[str] = []
        fingerprints: dict[str, Any] = {}
        for load in spec.loads:
            found = loaded[load.name]
            # The record as the audit log would show it: fields, secrets masked.
            snapshot = redact_arguments({"r": found}, policy.redact)["r"]
            opaque = isinstance(snapshot, str) and snapshot.startswith(_OPAQUE_PREFIX)
            if load.marker.describe is not None:
                try:
                    lines.append(str(load.marker.describe(found)))
                except Exception as exc:
                    raise _Refused(f"describe error: {type(exc).__name__}") from exc
            else:
                lines.append(_describe_record(load.name, found if opaque else snapshot, opaque))
            if load.marker.fingerprint is not None:
                try:
                    fingerprints[load.name] = load.marker.fingerprint(found)
                except Exception as exc:
                    raise _Refused(f"fingerprint error: {type(exc).__name__}") from exc
            else:
                # Opaque anywhere, not just at the top: a field the gate
                # sees only by its type could change unnoticed while a
                # person decides.
                if _holds_opaque(snapshot):
                    raise _Refused(
                        f"record can't be fingerprinted for approval: {load.name}",
                        f"'{spec.name}' needs approval, but the gate can't tell whether "
                        "its record changes while it waits. The gate fails closed.",
                    )
                fingerprints[load.name] = snapshot
        binding = hashlib.sha256(
            _canonical(
                {
                    "tool": spec.name,
                    "caller": _caller_entry(call.who),
                    "reason": reason,
                    "resources": fingerprints,
                }
            ).encode("utf-8", "surrogatepass")
        ).hexdigest()
        timeout = policy.approval_timeout
        return ApprovalRequest(
            tool=spec.name,
            tier=spec.tier,
            # Its own copy: nothing the approver does to these can change
            # what the audit log records.
            arguments=copy.deepcopy(call.safe_args),
            deadline=None if timeout is None else time.monotonic() + timeout,
            caller=call.who.caller,
            reason=reason,
            resources=tuple(lines),
            binding=binding,
            call_id=call.call_id,
        )

    async def _obtain_approval(
        self,
        need: _NeedsApproval,
        call: _Call,
        record: Callable[..., None],
        denied: Callable[..., GateDenied],
    ) -> InputRequiredResult | None:
        """Ask, outside any transaction. ``None`` means approved; a question
        means the client must answer it and call again."""
        request, spec = need.request, call.spec
        approver = self.policy.approver
        timeout = self.policy.approval_timeout
        if need.via == "round-trip":
            assert isinstance(approver, ElicitationApprover)
            try:
                question = approver.question(request, timeout)
            except Exception as exc:
                why = f"approver error: {type(exc).__name__}"
                raise denied(why, _approval_refused_message(spec.name, why)) from exc
            # The call ends here for now, and the client calls again with the
            # answer. If it never does, this line is the record that it was
            # asked.
            record(outcome="pending", reason="approval asked in client", arguments=call.safe_args)
            return question
        if need.via == "back-channel":
            assert isinstance(approver, ElicitationApprover)
            ask: Callable[[], Any] = functools.partial(approver.ask, request, call.context)
        elif need.via == "fallback":
            assert isinstance(approver, ElicitationApprover) and approver.fallback is not None
            ask = functools.partial(approver.fallback, request)
        else:
            assert approver is not None
            ask = functools.partial(approver, request)
        try:
            # move_on_after, not fail_after: an approver that raises
            # TimeoutError itself (a Slack call timing out) is an approver
            # error, not the gate's deadline.
            with anyio.move_on_after(timeout) as waiting:
                if _is_async_callable(ask):
                    approved = await _invoke(ask)
                else:
                    places = self._approver_places_for(spec.name)
                    approved = await places.run(ask, abandon_on_cancel=True)
        except Exception as exc:
            # An approver that can't answer (Slack down, ticket API timing
            # out) is a refusal, not a crash — and it belongs in the trail.
            # Type only, as with tool errors.
            why = f"approver error: {type(exc).__name__}"
            raise denied(why, _approval_refused_message(spec.name, why)) from exc
        except anyio.get_cancelled_exc_class():
            # Cancellation is a BaseException, so the clause above never sees
            # it, and the gate's own timeout never gets this far:
            # move_on_after catches that one.
            record(outcome="cancelled", reason="awaiting approval", arguments=call.safe_args)
            raise
        if waiting.cancelled_caught:
            raise denied(
                "approval timed out",
                f"'{spec.name}' was not approved within {timeout:g}s. "
                "The gate fails closed.",
            )
        if approved is True:
            return None
        if approved is False or approved is None:
            raise denied("approver refused", _approval_refused_message(spec.name, "approver refused"))
        # Only True approves. A Slack helper that returns its response
        # object, or a "no", would otherwise wave every call through.
        reason = f"approver error: returned {type(approved).__name__}"
        raise denied(reason, _approval_refused_message(spec.name, reason))


# --- driving the steps --------------------------------------------------------


def _before_tool() -> None:
    """Marks the point between the gate's steps and the tool. Never called."""


# The last step the gate yields before the tool runs. Both drivers take a
# pending cancellation there: the event-loop driver at a checkpoint, the
# sync-transaction driver from its worker thread.
_BEFORE_TOOL: Callable[[], Any] = _before_tool


async def _drive_async(
    steps: Generator[Callable[[], Any], Any, Any],
    timeout: float | None,
    limiter: _Places,
) -> Any:
    """Run each step on the event loop, sync ones in a worker thread.

    The steps before the tool (loaders, policy, scopes) share ``timeout``
    seconds and run sync ones in the tool's places (``limiter``). A step still running
    at the deadline is abandoned: the generator gets ``_DeadlinePassed`` at the
    step that ran out, and a sync step's thread finishes in the background
    with its result dropped.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    authorizing = True
    value: Any = None
    error: BaseException | None = None
    while True:
        try:
            step = steps.throw(error) if error is not None else steps.send(value)
        except StopIteration as done:
            return done.value
        value, error = None, None
        if step is _BEFORE_TOOL:
            # A sync step's thread isn't abandoned on cancellation: a policy
            # or loader finishes, and the cancellation waits for the next
            # checkpoint. Take it here, before the gate moves to the tool, so
            # a call cancelled while it was authorized stops at
            # "authorizing" and its tool never starts.
            await anyio.lowlevel.checkpoint_if_cancelled()
            authorizing = False
            continue
        try:
            if authorizing:
                value = await _authorizing_step(step, deadline, limiter)
            else:
                value = await _invoke(step)
        except Exception as exc:
            error = exc


async def _authorizing_step(step: Callable[[], Any], deadline: float | None, places: _Places) -> Any:
    """One step before the tool, within what is left of the deadline. A
    sync step waits for a place among the tool's threads within it too."""
    async def run(abandon_on_cancel: bool) -> Any:
        if _is_async_callable(step):
            return await _invoke(step)
        return await places.run(step, abandon_on_cancel=abandon_on_cancel)

    if deadline is None:
        return await run(abandon_on_cancel=False)
    left = deadline - time.monotonic()
    if left <= 0:
        raise _DeadlinePassed()
    with anyio.move_on_after(left):
        return await run(abandon_on_cancel=True)
    raise _DeadlinePassed()


class _Places:
    """One tool's worker threads for its sync loaders, policies and scopes,
    or for its sync approvers.

    A step takes a place before its thread starts and gives it back when
    the thread returns. A step abandoned at the deadline keeps its place
    until its thread really returns, however long that is: Python can't
    stop the thread, and counting it as gone would let a policy that never
    returns start a new thread on every call. So a tool whose places are
    all held by hung steps denies its own calls at the deadline, and
    starts no more threads, while every other tool keeps its own places.

    An abandoned thread that returns never calls into the event loop and
    never waits on it: it puts its place on ``_returned`` and, if it can,
    wakes the loop without waiting. The loop gives the place back then, or
    at the latest when the tool's next step starts, on whatever loop that
    is. So a loop that has stopped or closed meanwhile neither loses the
    place nor leaves the thread blocked at interpreter exit.
    """

    def __init__(
        self,
        tool: str,
        total: int,
        pool: anyio.CapacityLimiter,
        *,
        what: str = "sync loader, policy or scope",
        deadline: str = "authorization deadline",
    ) -> None:
        self.tool = tool
        self.total = total
        self.what = what
        self.deadline = deadline
        self._places = anyio.CapacityLimiter(total)
        self._pool = pool
        self._returned: list[object] = []  # holders whose abandoned thread has returned
        self._returned_lock = threading.Lock()

    def _reclaim(self) -> None:
        """Give back the places of abandoned threads that have returned.
        On the event loop only."""
        with self._returned_lock:
            holders, self._returned = self._returned, []
        for holder in holders:
            self._places.release_on_behalf_of(holder)

    async def run(self, step: Callable[[], Any], *, abandon_on_cancel: bool) -> Any:
        self._reclaim()
        holder = object()
        await self._places.acquire_on_behalf_of(holder)
        wake = _loop_waker()
        guard = threading.Lock()
        phase = ["waiting"]  # → running → done, or → abandoned → done, or → dropped

        def give_back() -> None:
            self._places.release_on_behalf_of(holder)

        def in_thread() -> Any:
            with guard:
                if phase[0] == "dropped":
                    return None
                phase[0] = "running"
            try:
                return step()
            finally:
                with guard:
                    abandoned = phase[0] == "abandoned"
                    phase[0] = "done"
                if abandoned:
                    with self._returned_lock:
                        self._returned.append(holder)
                    if wake is not None:
                        try:
                            wake(self._reclaim)
                        except Exception:
                            pass  # the loop is gone: the next step's _reclaim gives it back

        try:
            result = await anyio.to_thread.run_sync(in_thread, limiter=self._pool, abandon_on_cancel=abandon_on_cancel)
        except BaseException:
            with guard:
                was = phase[0]
                if was == "running":
                    phase[0] = "abandoned"
                elif was == "waiting":
                    phase[0] = "dropped"
            if was == "running":
                _warn_abandoned(self)
            else:
                give_back()
            raise
        give_back()
        if inspect.isawaitable(result):
            result = await result
        return result


def _loop_waker() -> Callable[[Callable[[], None]], object] | None:
    """A way for a worker thread to have the running event loop call a
    function soon, without waiting for it, or ``None``."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        return loop.call_soon_threadsafe
    try:
        import trio

        return trio.lowlevel.current_trio_token().run_sync_soon
    except Exception:
        return None


def _warn_abandoned(places: _Places) -> None:
    held = places._places.borrowed_tokens
    try:
        sys.stderr.write(
            f"mcp-gatehouse: a {places.what} for {places.tool!r} was abandoned and is still "
            f"running (its {places.deadline} passed, or the call was cancelled); its thread "
            f"keeps one of the tool's "
            f"{places.total} places until it returns ({held} in use)\n"
        )
        sys.stderr.flush()
    except Exception:
        pass


def _drive_sync(steps: Generator[Callable[[], Any], Any, Any], timeout: float | None) -> Any:
    """Run every step right here, in this thread.

    A thread can't be interrupted, so the deadline is checked between steps:
    a step that started in time runs to the end, and if the deadline passed
    meanwhile the generator gets ``_DeadlinePassed`` as if it had been cut off.
    Inside a sync transaction, the database's own statement timeout is what
    stops a query that hangs.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    authorizing = True
    value: Any = None
    error: BaseException | None = None
    while True:
        try:
            step = steps.throw(error) if error is not None else steps.send(value)
        except StopIteration as done:
            return done.value
        value, error = None, None
        if step is _BEFORE_TOOL:
            # Same point, from inside the transaction's worker thread: a
            # client that gave up while the gate was authorizing gets its
            # cancellation here, the transaction rolls back, and the tool
            # never starts.
            anyio.from_thread.check_cancelled()
            authorizing = False
            continue
        try:
            if authorizing and deadline is not None and time.monotonic() >= deadline:
                raise _DeadlinePassed()
            value = step()
            if inspect.isawaitable(value):
                close = getattr(value, "close", None)
                if callable(close):
                    close()
                raise TypeError("an async callable can't run inside a sync transaction")
            if authorizing and deadline is not None and time.monotonic() > deadline and not isinstance(value, Deny):
                # It answered, but too late to count. A late Deny still
                # counts: turning a no into a timeout could, with
                # on_authorization_timeout=Ask, put it to a person.
                raise _DeadlinePassed()
        except Exception as exc:
            error = exc


def _run_sync_transaction(
    transaction: Transaction,
    caller: Caller,
    steps: Generator[Callable[[], Any], Any, Any],
    timeout: float | None,
) -> Any:
    """The whole transaction, in the one worker thread this runs in."""
    manager = transaction.factory(caller)
    if not hasattr(manager, "__enter__"):
        raise TypeError("the transaction factory didn't return a context manager")
    result: Any = _UNSET
    raised: BaseException | None = None
    with manager as handle:
        # This thread runs in a copy of the caller's context, so the value
        # set here is seen by every step and nowhere else.
        _TRANSACTION.set(handle)
        try:
            result = _drive_sync(steps, timeout)
        except BaseException as exc:
            raised = exc
            raise
    return _unless_swallowed(result, raised)


async def _run_async_transaction(
    transaction: Transaction,
    caller: Caller,
    steps: Generator[Callable[[], Any], Any, Any],
    timeout: float | None,
    limiter: _Places,
) -> Any:
    """The whole transaction on the event loop: load, policy, tool, commit."""
    manager = transaction.factory(caller)
    if not hasattr(manager, "__aenter__"):
        raise TypeError("the transaction factory didn't return an async context manager")
    result: Any = _UNSET
    raised: BaseException | None = None
    async with manager as handle:
        token = _TRANSACTION.set(handle)
        try:
            result = await _drive_async(steps, timeout, limiter)
        except BaseException as exc:
            raised = exc
            raise
        finally:
            _TRANSACTION.reset(token)
    return _unless_swallowed(result, raised)


def _unless_swallowed(result: Any, raised: BaseException | None) -> Any:
    """The transaction's result, or, when its context manager swallowed the
    exception that ended it, that exception: the call still failed."""
    if result is _UNSET:
        raise raised if raised is not None else RuntimeError("transaction swallowed the call")
    return result


def _filter_items(
    authorize_items: Authorizer, items: Any, item_request: Callable[[Any], AuthorizationRequest]
) -> tuple[list[Any], int]:
    """A sync item policy over a whole result, in one go. Only ``Allow`` keeps
    an item; anything else, or an exception, withholds it."""
    kept: list[Any] = []
    errors = 0
    for item in items:
        try:
            verdict = authorize_items(item_request(item))
        except Exception:
            errors += 1
            continue
        if inspect.isawaitable(verdict):
            close = getattr(verdict, "close", None)
            if callable(close):
                close()
            raise _AwaitableVerdict()
        if isinstance(verdict, Allow):
            kept.append(item)
    return kept, errors


class _AwaitableVerdict(Exception):
    """A sync-looking item policy returned something to await."""


def _filter_each(
    authorize_items: Authorizer, items: Any, item_request: Callable[[Any], AuthorizationRequest]
) -> Generator[Callable[[], Any], Any, tuple[list[Any], int]]:
    """An item policy one step per item, so the driver can await each
    verdict. Only ``Allow`` keeps an item."""
    kept: list[Any] = []
    errors = 0
    for item in items:
        try:
            verdict = yield functools.partial(authorize_items, item_request(item))
        except Exception:
            errors += 1
            continue
        if isinstance(verdict, Allow):
            kept.append(item)
    return kept, errors


# --- registration-time inspection ---------------------------------------------


def _build_spec(
    fn: Callable[..., Any],
    tool_name: str,
    *,
    tier: AccessTier,
    authorize: Authorizer,
    authorize_items: Authorizer | None,
    consistency: Consistency | None,
    scopes: frozenset[str],
    policy: Policy,
    localns: Mapping[str, Any] | None,
    authorization_timeout: float | None,
    on_authorization_timeout: Any,
) -> _ToolSpec:
    """Work out, once, everything the guard needs, and refuse a tool the gate
    can't enforce on.

    The annotations must evaluate: a ``Load`` marker the gate can't see is a
    parameter it can't fill, and one it can't keep out of the schema.
    """
    try:
        signature = inspect.signature(fn, eval_str=True, locals=dict(localns or {}))
    except Exception as exc:
        raise TypeError(
            f"{tool_name}: can't evaluate the tool's type annotations "
            f"({type(exc).__name__}: {exc}). Define what they name before the tool, "
            "at module level or in the function that registers it."
        ) from exc

    ctx_param: str | None = None
    loads: list[tuple[inspect.Parameter, Load]] = []
    scope_params: list[tuple[inspect.Parameter, Scope]] = []
    plain: set[str] = set()
    for param in signature.parameters.values():
        annotation = param.annotation
        markers = _check_markers(tool_name, param.name, annotation)
        if _is_context(annotation):
            if markers:
                raise TypeError(f"{tool_name}: parameter {param.name!r} is a Context; it can't be Load or Scope")
            if ctx_param is None:
                ctx_param = param.name
            continue
        if not markers:
            plain.add(param.name)
            continue
        if len(markers) > 1:
            raise TypeError(f"{tool_name}: parameter {param.name!r} has more than one Load/Scope marker")
        if param.kind not in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
            raise TypeError(f"{tool_name}: parameter {param.name!r} can't be positional-only or variadic")
        if param.default is not inspect.Parameter.empty:
            raise TypeError(f"{tool_name}: parameter {param.name!r} is filled by the gate; it can't have a default")
        if param.name == _CONTEXT_PARAM:
            raise ValueError(f"'{_CONTEXT_PARAM}' is a parameter name mcp-gatehouse reserves; rename the parameter")
        marker = markers[0]
        if isinstance(marker, Load):
            loads.append((param, marker))
        else:
            scope_params.append((param, marker))

    if ctx_param is None and _CONTEXT_PARAM in signature.parameters:
        raise ValueError(
            f"'{_CONTEXT_PARAM}' is a parameter name mcp-gatehouse reserves; "
            "rename the tool's parameter"
        )

    load_names = {param.name for param, _ in loads}
    scope_names = {param.name for param, _ in scope_params}
    load_specs: list[_LoadSpec] = []
    for param, marker in loads:
        if not callable(marker.loader):
            raise TypeError(f"{tool_name}: Load({marker.loader!r}) needs a callable loader")
        try:
            loader_params = inspect.signature(marker.loader).parameters.values()
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{tool_name}: can't read the signature of {param.name!r}'s loader") from exc
        argnames: list[str] = []
        for lp in loader_params:
            if lp.kind not in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
                raise TypeError(f"{tool_name}: {param.name!r}'s loader can't take *args, **kwargs or positional-only parameters")
            if lp.name in load_names:
                raise TypeError(f"{tool_name}: {param.name!r}'s loader can't take another loaded record ({lp.name!r})")
            if lp.name in scope_names:
                raise TypeError(f"{tool_name}: {param.name!r}'s loader can't take a Scope ({lp.name!r})")
            if lp.name == ctx_param or lp.name == _CONTEXT_PARAM:
                raise TypeError(f"{tool_name}: {param.name!r}'s loader can't take the Context")
            if lp.name not in plain:
                raise TypeError(
                    f"{tool_name}: {param.name!r}'s loader takes {lp.name!r}, which isn't one of "
                    "the tool's arguments. A loader's parameters name the arguments it loads from."
                )
            argnames.append(lp.name)
        load_specs.append(_LoadSpec(param.name, marker, tuple(argnames)))
        if marker.fingerprint is None and policy.needs_approval(tier):
            base = _unannotated(param.annotation)
            if not _is_record_type(base):
                raise TypeError(
                    f"{tool_name}: {param.name!r} needs approval on this tier, and the gate can't "
                    "fingerprint its type to bind the approval to the record's state. Make it a "
                    "Pydantic model, a dataclass or a mapping, or pass Load(..., fingerprint=...)."
                )
    for param, marker in scope_params:
        if not callable(marker.fn):
            raise TypeError(f"{tool_name}: Scope({marker.fn!r}) needs a callable")

    if tier in (AccessTier.WRITE, AccessTier.DESTRUCTIVE) and load_specs and consistency is None:
        raise TypeError(
            f"{tool_name}: a {tier.value} tool that loads a record must say how the window between "
            "the check and the write is closed: consistency=Transaction(...), ConditionalWrite(), "
            "or AcceptRace('why') on purpose (here or as the Gatehouse default)."
        )

    # get_type_hints also evaluates names nested in the return type
    # (list["Order"]), which the signature leaves as strings.
    try:
        returns = typing.get_type_hints(fn, localns=dict(localns or {}), include_extras=True).get(
            "return", signature.return_annotation
        )
    except Exception:
        returns = signature.return_annotation
    try:
        item_type = _record_item_type(returns)
    except TypeError as exc:
        raise TypeError(f"{tool_name}: {exc}. Define it before the tool.") from None
    if item_type is not None and authorize_items is None:
        raise TypeError(
            f"{tool_name}: it returns a list of records, so say who may see each one: "
            "authorize_items=<policy>, or authorize_items=any_item on purpose."
        )
    if authorize_items is not None and item_type is None:
        raise TypeError(
            f"{tool_name}: authorize_items needs the tool to return a list of records "
            "(list[T], tuple[T, ...] or Sequence[T] of Pydantic models, dataclasses, "
            "TypedDicts or mappings) so the gate can check each one."
        )

    if isinstance(consistency, Transaction):
        _check_transaction_fit(tool_name, consistency, fn, authorize, authorize_items, load_specs, scope_params)

    bind_signature, exposed_signature, exposed_annotations = _exposed_signature(
        signature, load_names | scope_names, ctx_param
    )
    return _ToolSpec(
        authorization_timeout=authorization_timeout,
        on_authorization_timeout=on_authorization_timeout,
        name=tool_name,
        tier=tier,
        fn=fn,
        authorize=authorize,
        authorize_items=authorize_items,
        consistency=consistency,
        scopes=scopes,
        loads=tuple(load_specs),
        scope_params=tuple(_ScopeSpec(param.name, marker) for param, marker in scope_params),
        ctx_param=ctx_param,
        bind_signature=bind_signature,
        exposed_signature=exposed_signature,
        exposed_annotations=exposed_annotations,
        # A tool that resolves or returns its own InputRequiredResult owns
        # the call's one multi-round channel, so the gate can't ask over it.
        round_trip=not _runs_own_rounds(fn),
    )


def _exposed_signature(
    signature: inspect.Signature, filled: set[str], ctx_param: str | None
) -> tuple[inspect.Signature, inspect.Signature, dict[str, Any]]:
    """What the SDK sees of the tool, and what the guard binds calls to.

    Both leave out the parameters the gate fills. The exposed signature,
    which the SDK builds the schema from, adds a hidden Context when the
    tool takes none, so the guard still gets one.
    """
    params = [p for p in signature.parameters.values() if p.name not in filled]
    bind_signature = signature.replace(parameters=params)
    if ctx_param is None:
        # The tool takes no Context, so the guard asks for one under a name
        # of its own. Its Context annotation keeps it out of the schema.
        hidden = inspect.Parameter(
            _CONTEXT_PARAM, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context
        )
        at = len(params) - (bool(params) and params[-1].kind is inspect.Parameter.VAR_KEYWORD)
        params = [*params[:at], hidden, *params[at:]]
    exposed_signature = signature.replace(parameters=params)
    annotations = {p.name: p.annotation for p in params if p.annotation is not inspect.Parameter.empty}
    if signature.return_annotation is not inspect.Signature.empty:
        annotations["return"] = signature.return_annotation
    return bind_signature, exposed_signature, annotations


def _check_transaction_fit(
    tool_name: str,
    transaction: Transaction,
    fn: Callable[..., Any],
    authorize: Authorizer,
    authorize_items: Authorizer | None,
    loads: list[_LoadSpec],
    scope_params: list[tuple[inspect.Parameter, Scope]],
) -> None:
    """Everything inside a sync transaction is sync (it all runs in one
    thread); inside an async one, the loaders and the tool are async."""
    if transaction.asynchronous:
        sync = [f"loader for {load.name!r}" for load in loads if not _is_async_callable(load.marker.loader)]
        if not _is_async_callable(fn):
            sync.append("the tool")
        if sync:
            raise TypeError(
                f"{tool_name}: an async transaction needs async loaders and an async tool; "
                f"these are sync: {', '.join(sync)}"
            )
        return
    asynchronous = [f"loader for {load.name!r}" for load in loads if _is_async_callable(load.marker.loader)]
    asynchronous += [f"scope {param.name!r}" for param, marker in scope_params if _is_async_callable(marker.fn)]
    if _is_async_callable(authorize):
        asynchronous.append("the policy")
    if authorize_items is not None and _is_async_callable(authorize_items):
        asynchronous.append("the item policy")
    if _is_async_callable(fn):
        asynchronous.append("the tool")
    if asynchronous:
        raise TypeError(
            f"{tool_name}: a sync transaction runs in one worker thread, so everything inside it "
            f"must be sync; these are async: {', '.join(asynchronous)}"
        )


def _check_markers(tool_name: str, param: str, annotation: Any) -> list[Load | Scope]:
    """The parameter's top-level Load/Scope markers. Refuses one nested
    anywhere else, and the SDK's Resolve anywhere: it runs before the gate."""
    from mcp.server.mcpserver import Resolve

    top: list[Load | Scope] = []
    for item, is_top in _metadata(annotation):
        if isinstance(item, Resolve):
            raise TypeError(
                f"{tool_name}: parameter {param!r} uses Resolve(...), which the SDK runs before "
                "the gate checks the call. On a gated server, load records with Load(...)."
            )
        if isinstance(item, type) and issubclass(item, (Load, Scope)):
            raise TypeError(
                f"{tool_name}: parameter {param!r} names the {item.__name__} class; "
                f"give it an instance: {item.__name__}(...)"
            )
        if isinstance(item, (Load, Scope)):
            if not is_top:
                raise TypeError(
                    f"{tool_name}: parameter {param!r}: Load/Scope must be the parameter's own "
                    "Annotated[...] marker, not nested inside another type"
                )
            top.append(item)
    return top


def _metadata(annotation: Any, top: bool = True) -> Generator[tuple[Any, bool], None, None]:
    """Every Annotated metadata item in ``annotation``, at any depth, and
    whether it is the parameter's own (top-level) marker."""
    annotation = _resolve_alias(annotation)
    if get_origin(annotation) is Annotated:
        for item in annotation.__metadata__:
            yield item, top
        yield from _metadata(get_args(annotation)[0], False)
        return
    for arg in get_args(annotation):
        if isinstance(arg, (list, tuple)):
            for inner in arg:
                yield from _metadata(inner, False)
        else:
            yield from _metadata(arg, False)


def _alias_types() -> tuple[type, ...]:
    """``typing.TypeAliasType`` (3.12+) and its backport, where present."""
    found = [getattr(typing, "TypeAliasType", None)]
    try:
        import typing_extensions  # pydantic's dependency; not one of ours

        found.append(getattr(typing_extensions, "TypeAliasType", None))
    except ImportError:  # pragma: no cover
        pass
    return tuple(t for t in found if isinstance(t, type))


_ALIAS_TYPES = _alias_types()


def _resolve_alias(annotation: Any) -> Any:
    """What a ``type X = ...`` alias stands for (``X[int]`` too). The gate
    must see a marker behind an alias, or the model could fill it."""
    while True:
        if isinstance(annotation, _ALIAS_TYPES):
            annotation = getattr(annotation, "__value__")
        elif isinstance(origin := get_origin(annotation), _ALIAS_TYPES):
            annotation = getattr(origin, "__value__")
        else:
            return annotation


def _unannotated(annotation: Any) -> Any:
    annotation = _resolve_alias(annotation)
    if get_origin(annotation) is Annotated:
        annotation = _resolve_alias(get_args(annotation)[0])
    return annotation


def _is_context(annotation: Any) -> bool:
    """Would MCPServer inject its Context here? Mirrors the SDK: a Context
    class, or any generic (``Context | None``) with one among its arguments."""
    base = _unannotated(annotation)
    if inspect.isclass(base) and issubclass(base, Context):
        return True
    if get_origin(base) is not None:
        return any(inspect.isclass(arg) and issubclass(arg, Context) for arg in get_args(base))
    return False


def _is_record_type(annotation: Any) -> bool:
    """A type the gate can snapshot: a Pydantic model, a dataclass, a
    TypedDict or a mapping."""
    base = _unannotated(annotation)
    origin = get_origin(base)
    if origin is not None:
        return inspect.isclass(origin) and issubclass(origin, collections.abc.Mapping)
    if not inspect.isclass(base):
        return False
    return (
        issubclass(base, BaseModel)
        or dataclasses.is_dataclass(base)
        or typing.is_typeddict(base)
        or issubclass(base, collections.abc.Mapping)
    )


def _record_item_type(annotation: Any) -> Any | None:
    """The item type when ``annotation`` is, or may be, a list of records,
    else ``None``. Any arm of a union counts (``list[Order] | None``,
    ``list[Order] | tuple[Order, ...]``), and so does an item that may be a
    record (``list[Order | None]``): what may reach the model unfiltered
    needs an item policy."""
    if annotation is inspect.Signature.empty:
        return None
    base = _unannotated(annotation)
    arms = [_unannotated(arm) for arm in get_args(base)] if _is_union(base) else [base]
    for arm in arms:
        if arm is InputRequiredResult or arm is type(None):
            continue
        item = _sequence_item(arm)
        if item is not None and _may_be_record(item):
            return item
    return None


def _sequence_item(annotation: Any) -> Any | None:
    """T for ``list[T]``, ``Sequence[T]`` or ``tuple[T, ...]``."""
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (list, collections.abc.Sequence) and len(args) == 1:
        return args[0]
    if origin is tuple and len(args) == 2 and args[1] is Ellipsis:
        return args[0]
    return None


def _may_be_record(item: Any) -> bool:
    item = _unannotated(item)
    if isinstance(item, (str, typing.ForwardRef)):
        name = item if isinstance(item, str) else item.__forward_arg__
        raise TypeError(f"the return type names {name!r}, which doesn't evaluate here")
    if _is_union(item):
        return any(_may_be_record(arm) for arm in get_args(item) if arm is not type(None))
    return _is_record_type(item)


def _is_union(annotation: Any) -> bool:
    origin = get_origin(annotation)
    return origin is typing.Union or origin is types.UnionType


def _check_consistency(consistency: Any) -> None:
    if consistency is not None and not isinstance(consistency, (Transaction, ConditionalWrite, AcceptRace)):
        raise TypeError("consistency must be Transaction(...), ConditionalWrite() or AcceptRace('why')")


# --- small helpers ------------------------------------------------------------


def _static_audit_fields(spec: _ToolSpec) -> dict[str, Any]:
    """The fields every audit line for this tool carries, whatever the call
    does: how its check and write are kept together, and a deadline turned
    off. Both are opt-outs the trail should show."""
    fields: dict[str, Any] = {}
    if isinstance(spec.consistency, Transaction):
        fields["consistency"] = "transaction"
    elif isinstance(spec.consistency, ConditionalWrite):
        fields["consistency"] = "conditional"
    elif isinstance(spec.consistency, AcceptRace):
        fields["consistency"] = "accept-race"
        fields["consistency_reason"] = spec.consistency.reason
    if spec.authorization_timeout is None:
        fields["authorization_deadline"] = "off"
    return fields


def _authz_label(spec: _ToolSpec, decision: Decision) -> str:
    """The audit line's ``authz``: what the policy decided."""
    if spec.open:
        return "open"
    if isinstance(decision, Allow):
        return "allow"
    return "ask" if isinstance(decision, Ask) else "deny"


def _read_only(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    """A read-only copy for a policy, so nothing it does reaches the tool.
    An argument that can't be deep-copied is shared with the tool as is."""
    try:
        return MappingProxyType(copy.deepcopy(dict(mapping)))
    except Exception:
        return MappingProxyType(dict(mapping))


def _describe_record(name: str, snapshot: Any, opaque: bool) -> str:
    """The approver's line for a record whose ``Load`` has no ``describe``:
    its fields as the audit log shows them (``order: id=4417 · customer=Blue
    Ridge Cabinets · total=812.0``). Nested values are shown as compact
    JSON. An opaque record (not a model, dataclass or mapping) is named by
    type only: a repr can carry a secret."""
    if opaque:
        return f"{name}: a {type(snapshot).__name__}"
    if isinstance(snapshot, Mapping):
        parts = []
        for key, value in snapshot.items():
            shown = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            parts.append(f"{key}={shown}")
        return f"{name}: " + " · ".join(parts)
    return f"{name}: {json.dumps(snapshot, ensure_ascii=False, default=str)}"


def _new_call_id() -> str:
    """The audit trail's id for one call: every line the call writes carries it."""
    return uuid.uuid4().hex


# A JSON-RPC id is the client's choice: kept in the trail, but never long.
_MAX_REQUEST_ID = 128


def _correlation(context: Any) -> dict[str, Any]:
    """What ties a call's lines to the rest of the system: the MCP request's
    JSON-RPC id, and the OpenTelemetry trace the call runs in.

    The trace is the MCP SDK's own: it opens a span for every request,
    parented on the ``traceparent`` the client sent in ``_meta``. With an
    OpenTelemetry SDK configured, ``span_id`` is that server span; without
    one, the client's trace still comes through, and ``span_id`` is the
    client's span. No trace in the request and none configured: no fields.
    """
    fields: dict[str, Any] = {}
    try:
        request_id = context.request_context.request_id
    except Exception:
        request_id = None  # no live request (a direct call_tool from code)
    if request_id is not None:
        fields["request_id"] = str(request_id)[:_MAX_REQUEST_ID]
    span = _otel_trace.get_current_span().get_span_context()
    if span.is_valid:
        fields["trace_id"] = _otel_trace.format_trace_id(span.trace_id)
        fields["span_id"] = _otel_trace.format_span_id(span.span_id)
    return fields


def _caller_entry(who: _Who) -> dict[str, Any]:
    entry = dataclasses.asdict(who.caller)
    if who.local:
        entry["source"] = "local"
    return entry


def _not_permitted_message(tool_name: str) -> str:
    """What the model is told for every refusal on authorization, so it can't
    tell a record it may not touch from one that doesn't exist."""
    return f"'{tool_name}' is not permitted for this caller."


def _no_caller_message(tool_name: str) -> str:
    return (
        f"'{tool_name}' needs a verified caller, and this request has none. "
        "The gate fails closed."
    )


def _approval_refused_message(tool_name: str, reason: str) -> str:
    """What the model is told when an approval comes back no."""
    if reason == "approval timed out":
        return f"'{tool_name}' was not approved in time. The gate fails closed."
    if reason == "approval already used":
        return f"'{tool_name}': that approval was already used. Each approval runs one call."
    if reason.startswith("approval store error"):
        return f"'{tool_name}' could not be approved: the approval store failed. The gate fails closed."
    if reason.startswith("approver error"):
        return f"'{tool_name}' could not be approved: the approver failed. The gate fails closed."
    return f"'{tool_name}' was refused by the approver."


def _runs_own_rounds(fn: Callable[..., Any]) -> bool:
    """Does the tool drive the call's multi-round input flow itself?"""
    try:
        from mcp.server.mcpserver.resolve import find_resolved_parameters, returns_input_required

        return bool(find_resolved_parameters(fn)) or returns_input_required(fn)
    except Exception:
        return True  # can't tell, so stay off the channel: the fallback decides


async def _invoke(
    fn: Callable[[], Any],
    *,
    limiter: anyio.CapacityLimiter | None = None,
    abandon_on_cancel: bool = False,
) -> Any:
    """Await an async callable; run a sync one in a worker thread.

    MCPServer offloads sync tools to a thread itself, but all it sees is the
    guard, which is async — so the offload has to happen here. Otherwise a
    blocking tool, or an approver waiting on a human, stalls every other
    request on the server until it returns.

    ``fn`` takes no arguments (bind them with ``functools.partial``), so
    these options can't collide with a tool's own parameter names.
    ``limiter`` picks the thread pool (anyio's default when ``None``).
    ``abandon_on_cancel`` lets a timeout stop waiting on a thread that is
    still blocked; Python can't stop the thread, so it finishes in the
    background and its result is dropped.
    """
    if _is_async_callable(fn):
        return await fn()
    result = await anyio.to_thread.run_sync(
        fn, limiter=limiter, abandon_on_cancel=abandon_on_cancel
    )
    if inspect.isawaitable(result):
        result = await result
    return result


def _is_async_callable(fn: Any) -> bool:
    while isinstance(fn, functools.partial):
        fn = fn.func
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(
        getattr(fn, "__call__", None)
    )
