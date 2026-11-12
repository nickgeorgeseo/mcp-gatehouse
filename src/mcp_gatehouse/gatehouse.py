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

import collections.abc
import contextvars
import copy
import dataclasses
import functools
import hashlib
import inspect
import json
import time
import typing
from collections.abc import Generator, Mapping
from types import MappingProxyType
from typing import Annotated, Any, Callable, Literal, TypeVar, get_args, get_origin

import anyio
import anyio.lowlevel
import anyio.to_thread
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import principal_components
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import InputRequiredResult, ToolAnnotations
from pydantic import BaseModel

from .approvers import ElicitationApprover
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
    Deny,
    Load,
    Scope,
    Transaction,
    any_caller,
    any_item,
)
from .policy import AccessTier, ApprovalRequest, Caller, Policy, _canonical, redact_arguments

F = TypeVar("F", bound=Callable[..., Any])

# Worker threads for sync approvers, kept apart from anyio's default pool.
# Sync tools draw on that pool; approvers wait on people. If they shared it,
# a stack of pending sign-offs would leave no thread for a plain read.
_APPROVER_THREADS = 40

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


@dataclasses.dataclass
class _CallState:
    """What one call has got to, for the audit lines it writes."""

    stage: Literal["authorizing", "tool running", "filtering", "committing"] = "authorizing"
    authz: str | None = None
    start: float | None = None
    duration_ms: float | None = None
    withheld: int | None = None
    filter_errors: int = 0
    scope_mismatch: bool = False
    signal: BaseException | None = None

    def elapsed_ms(self) -> float | None:
        if self.duration_ms is not None:
            return self.duration_ms
        if self.start is None:
            return None
        return round((time.perf_counter() - self.start) * 1000, 2)


@dataclasses.dataclass(frozen=True)
class _Call:
    """One call's inputs, as the gate's steps need them."""

    spec: _ToolSpec
    who: _Who
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
    it.

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
        self._approver_limiter = anyio.CapacityLimiter(_APPROVER_THREADS)
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
            self.audit.record(tool=name, tier=None, outcome="denied", reason="ungated tool", arguments=safe())
            raise GateDenied(f"'{name}' was not registered through the gate, so it can't run.")
        if not check_caller:
            return None
        who = self._resolve(context)
        if who is None:
            self.audit.record(
                tool=name, tier=self._registry[name].tier.value, outcome="denied",
                reason="no verified caller", arguments=safe(),
            )
            raise GateDenied(_no_caller(name))
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
            spec = _build_spec(
                fn, tool_name, tier, authorize, authorize_items,
                consistency if consistency is not None else self.consistency,
                required_scopes, self.policy, defined_in,
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

        consistency_fields: dict[str, Any] = {}
        if isinstance(spec.consistency, Transaction):
            consistency_fields["consistency"] = "transaction"
        elif isinstance(spec.consistency, ConditionalWrite):
            consistency_fields["consistency"] = "conditional"
        elif isinstance(spec.consistency, AcceptRace):
            consistency_fields["consistency"] = "accept-race"
            consistency_fields["consistency_reason"] = spec.consistency.reason

        async def run(arguments: dict[str, Any], args: tuple, kwargs: dict[str, Any], context: Any) -> Any:
            safe_args = redact_arguments(arguments, policy.redact)
            # Read once, so every line this call writes names the same caller:
            # what the call_tool guard resolved when it admitted this call,
            # else (a call that came in another way) resolved here.
            admitted = _ADMITTED.get(None)
            who = admitted[1] if admitted is not None and admitted[0] == spec.name else gate._resolve(context)
            state = _CallState()
            fixed: dict[str, Any] = {}
            if spec.loads:
                fixed["resources"] = {
                    load.name: {arg: safe_args.get(arg) for arg in load.argnames} for load in spec.loads
                }
            if spec.items_open:
                fixed["items"] = "open"
            fixed.update(consistency_fields)

            def record(**event: Any) -> None:
                """One audit line for this call."""
                if who is not None:
                    event["caller"] = _caller_entry(who)
                if state.authz is not None:
                    event["authz"] = state.authz
                event.update(fixed)
                audit.record(tool=spec.name, tier=spec.tier.value, **event)

            def denied(reason: str, message: str, outcome: str = "denied") -> GateDenied:
                record(outcome=outcome, reason=reason, arguments=safe_args)
                return GateDenied(message)

            if spec.name in policy.deny:
                raise denied("denylist", f"'{spec.name}' is blocked by policy.")
            if who is None:
                raise denied("no verified caller", _no_caller(spec.name))
            missing = sorted(spec.scopes - set(who.caller.scopes))
            if missing:
                raise denied(
                    "missing scope: " + ", ".join(missing),
                    f"'{spec.name}' needs the token scope {', '.join(missing)}, "
                    "which this caller's token doesn't carry.",
                )

            call = _Call(
                spec=spec, who=who, arguments=arguments, view=_read_only(arguments),
                safe_args=safe_args, args=args, kwargs=kwargs, context=context,
            )
            approved: str | None = None
            while True:
                state.stage = "authorizing"
                try:
                    result = await gate._phase(call, approved, state)
                except _Refused as refusal:
                    raise denied(
                        refusal.reason, refusal.message or _not_permitted(spec.name), refusal.outcome
                    ) from None
                except _NeedsApproval as need:
                    if approved is not None:  # pragma: no cover - the phase compares bindings
                        raise denied("approval did not apply", _not_permitted(spec.name)) from None
                    question = await gate._obtain_approval(need, call, record, denied)
                    if question is not None:
                        return question
                    approved = need.request.binding
                    continue
                except Conflict:
                    record(
                        outcome="conflict", reason="the record changed before the write",
                        arguments=safe_args, duration_ms=state.elapsed_ms(),
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
                            duration_ms=state.elapsed_ms(),
                        )
                    else:
                        record(
                            outcome="error", reason=f"transaction error: {type(exc).__name__}",
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
                            duration_ms=state.elapsed_ms(),
                        )
                    else:
                        record(outcome="cancelled", reason="authorizing", arguments=safe_args)
                    raise
                event: dict[str, Any] = {"outcome": "ok", "arguments": safe_args, "duration_ms": state.elapsed_ms()}
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

    async def _phase(self, call: _Call, approved: str | None, state: _CallState) -> Any:
        """Load, authorize and run, inside the tool's transaction if it has one."""
        steps = self._steps(call, approved, state)
        transaction = call.spec.consistency if isinstance(call.spec.consistency, Transaction) else None
        if transaction is None:
            return await _drive_async(steps)
        if transaction.asynchronous:
            return await _run_async_transaction(transaction, call.who.caller, steps, state)
        # One worker thread for the whole transaction: sync database drivers
        # are often tied to the thread that opened the connection.
        return await anyio.to_thread.run_sync(
            functools.partial(_run_sync_transaction, transaction, call.who.caller, steps, state)
        )

    def _steps(self, call: _Call, approved: str | None, state: _CallState) -> Generator[Callable[[], Any], Any, Any]:
        """The call, step by step. Each ``yield`` hands the driver a callable
        to run (the user's loader, policy, tool, …) and gets its result back.

        Written once, driven two ways: on the event loop, or all in one
        worker thread inside a sync transaction. Raises ``_Refused`` or
        ``_NeedsApproval`` to stop; inside a transaction, both roll it back.
        """
        spec, who = call.spec, call.who

        loaded: dict[str, Any] = {}
        for load in spec.loads:
            step = functools.partial(load.marker.loader, **{arg: call.arguments[arg] for arg in load.argnames})
            try:
                found = yield step
            except Exception as exc:
                raise _Refused(f"loader error: {type(exc).__name__}") from exc
            if found is None:
                raise _Refused(f"not found: {load.name}")
            loaded[load.name] = found

        request = AuthorizationRequest(
            caller=who.caller, tool=spec.name, tier=spec.tier, action="call",
            arguments=call.view, resources=MappingProxyType(dict(loaded)), claims=who.claims,
        )
        if spec.open:
            decision: Any = Allow()
        else:
            try:
                decision = yield functools.partial(spec.authorize, request)
            except Exception as exc:
                raise _Refused(f"policy error: {type(exc).__name__}") from exc
            if not isinstance(decision, (Allow, Deny, Ask)):
                raise _Refused(f"policy returned {type(decision).__name__}")
        state.authz = (
            "open" if spec.open else "allow" if isinstance(decision, Allow) else "ask" if isinstance(decision, Ask) else "deny"
        )
        if isinstance(decision, Deny):
            prefix = "policy after approval: " if approved is not None else "policy: "
            raise _Refused(prefix + decision.reason, decision.message)

        reason = decision.reason if isinstance(decision, Ask) else None
        if reason is not None or self.policy.needs_approval(spec.tier):
            self._approval_gate(call, reason, loaded, approved)

        scoped: dict[str, Any] = {}
        for scope in spec.scope_params:
            try:
                scoped[scope.name] = yield functools.partial(scope.marker.fn, request)
            except Exception as exc:
                raise _Refused(f"scope error: {type(exc).__name__}") from exc

        yield _BEFORE_TOOL
        state.stage = "tool running"
        state.start = time.perf_counter()
        result = yield functools.partial(spec.fn, *call.args, **call.kwargs, **loaded, **scoped)
        state.duration_ms = round((time.perf_counter() - state.start) * 1000, 2)
        state.stage = "filtering"

        if (
            spec.authorize_items is not None
            and not spec.items_open
            and result is not None
            and not isinstance(result, InputRequiredResult)
        ):
            if not isinstance(result, (list, tuple)):
                raise _Refused(
                    f"unfilterable result: {type(result).__name__}",
                    f"'{spec.name}' returned something the gate can't filter item by item, "
                    "so it isn't returned.",
                    outcome="error",
                )

            def item_request(item: Any) -> AuthorizationRequest:
                return dataclasses.replace(request, action="read", resource=item)

            if _is_async_callable(spec.authorize_items):
                kept: list[Any] = []
                errors = 0
                for item in result:
                    try:
                        verdict = yield functools.partial(spec.authorize_items, item_request(item))
                    except Exception:
                        errors += 1
                        continue
                    if isinstance(verdict, Allow):
                        kept.append(item)
            else:
                kept, errors = yield functools.partial(_filter_items, spec.authorize_items, result, item_request)
            state.withheld = len(result) - len(kept)
            state.filter_errors = errors
            state.scope_mismatch = bool(spec.scope_params) and state.withheld > 0
            result = kept if isinstance(result, list) else tuple(kept)

        state.stage = "committing"
        return result

    def _approval_gate(self, call: _Call, reason: str | None, loaded: dict[str, Any], approved: str | None) -> None:
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
                verdict = approver.answer(request, call.context)
                if verdict is None:
                    raise _NeedsApproval(request, "round-trip")
                allowed, why = verdict
                if not allowed:
                    raise _Refused(why, _refusal(spec.name, why))
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
            opaque = isinstance(snapshot, str) and snapshot.startswith("«opaque:")
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
                if opaque:
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
            # The call ends here for now, and the client calls again with the
            # answer. If it never does, this line is the record that it was
            # asked.
            record(outcome="pending", reason="approval asked in client", arguments=call.safe_args)
            return approver.question(request, timeout)
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
                approved = await _call(ask, limiter=self._approver_limiter, abandon_on_cancel=True)
        except Exception as exc:
            # An approver that can't answer (Slack down, ticket API timing
            # out) is a refusal, not a crash — and it belongs in the trail.
            # Type only, as with tool errors.
            raise denied(
                f"approver error: {type(exc).__name__}",
                f"'{spec.name}' could not be approved: the approver "
                "failed. The gate fails closed.",
            ) from exc
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
        if not approved:
            raise denied("approver refused", _refusal(spec.name, "approver refused"))
        return None


# --- driving the steps --------------------------------------------------------


def _before_tool() -> None:
    """Marks the point between the gate's steps and the tool. Never called."""


# The last step the gate yields before the tool runs. The event-loop driver
# takes a pending cancellation there; the sync driver passes through.
_BEFORE_TOOL: Callable[[], Any] = _before_tool


async def _drive_async(steps: Generator[Callable[[], Any], Any, Any]) -> Any:
    """Run each step on the event loop, sync ones in a worker thread."""
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
            continue
        try:
            value = await _call(step)
        except Exception as exc:
            error = exc


def _drive_sync(steps: Generator[Callable[[], Any], Any, Any]) -> Any:
    """Run every step right here, in this thread."""
    value: Any = None
    error: BaseException | None = None
    while True:
        try:
            step = steps.throw(error) if error is not None else steps.send(value)
        except StopIteration as done:
            return done.value
        value, error = None, None
        if step is _BEFORE_TOOL:
            continue
        try:
            value = step()
            if inspect.isawaitable(value):
                close = getattr(value, "close", None)
                if callable(close):
                    close()
                raise TypeError("an async callable can't run inside a sync transaction")
        except Exception as exc:
            error = exc


def _run_sync_transaction(
    transaction: Transaction, caller: Caller, steps: Generator[Callable[[], Any], Any, Any], state: _CallState
) -> Any:
    """The whole transaction, in the one worker thread this runs in."""
    manager = transaction.factory(caller)
    if not hasattr(manager, "__enter__"):
        raise TypeError("the transaction factory didn't return a context manager")
    result: Any = _UNSET
    with manager as handle:
        # This thread runs in a copy of the caller's context, so the value
        # set here is seen by every step and nowhere else.
        _TRANSACTION.set(handle)
        try:
            result = _drive_sync(steps)
        except BaseException as exc:
            state.signal = exc
            raise
    if result is _UNSET:
        # The context manager swallowed the exception. The call still failed.
        raise state.signal if state.signal is not None else RuntimeError("transaction swallowed the call")
    return result


async def _run_async_transaction(
    transaction: Transaction, caller: Caller, steps: Generator[Callable[[], Any], Any, Any], state: _CallState
) -> Any:
    manager = transaction.factory(caller)
    if not hasattr(manager, "__aenter__"):
        raise TypeError("the transaction factory didn't return an async context manager")
    result: Any = _UNSET
    async with manager as handle:
        token = _TRANSACTION.set(handle)
        try:
            result = await _drive_async(steps)
        except BaseException as exc:
            state.signal = exc
            raise
        finally:
            _TRANSACTION.reset(token)
    if result is _UNSET:
        raise state.signal if state.signal is not None else RuntimeError("transaction swallowed the call")
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
        if isinstance(verdict, Allow):
            kept.append(item)
    return kept, errors


# --- registration-time inspection ---------------------------------------------


def _build_spec(
    fn: Callable[..., Any],
    tool_name: str,
    tier: AccessTier,
    authorize: Authorizer,
    authorize_items: Authorizer | None,
    consistency: Consistency | None,
    scopes: frozenset[str],
    policy: Policy,
    localns: Mapping[str, Any] | None = None,
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
    plain: list[str] = []
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
            plain.append(param.name)
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

    item_type = _record_item_type(signature.return_annotation)
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

    exposed_params = [
        p for p in signature.parameters.values() if p.name not in load_names and p.name not in scope_names
    ]
    bind_signature = signature.replace(parameters=exposed_params)
    if ctx_param is None:
        # The tool takes no Context, so the guard asks for one under a name
        # of its own. Its Context annotation keeps it out of the schema.
        hidden = inspect.Parameter(
            _CONTEXT_PARAM, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context
        )
        at = len(exposed_params) - (
            bool(exposed_params) and exposed_params[-1].kind is inspect.Parameter.VAR_KEYWORD
        )
        exposed_params = [*exposed_params[:at], hidden, *exposed_params[at:]]
    exposed_signature = signature.replace(parameters=exposed_params)
    exposed_annotations = {
        p.name: p.annotation for p in exposed_params if p.annotation is not inspect.Parameter.empty
    }
    if signature.return_annotation is not inspect.Signature.empty:
        exposed_annotations["return"] = signature.return_annotation

    return _ToolSpec(
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


def _unannotated(annotation: Any) -> Any:
    return get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation


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
    """The item type when ``annotation`` is a list of records, else ``None``."""
    if annotation is inspect.Signature.empty:
        return None
    base = _unannotated(annotation)
    if _is_union(base):
        arms = [arm for arm in get_args(base) if arm is not InputRequiredResult and arm is not type(None)]
        if len(arms) != 1:
            return None
        base = _unannotated(arms[0])
    origin = get_origin(base)
    args = get_args(base)
    if origin in (list, collections.abc.Sequence) and len(args) == 1:
        item = args[0]
    elif origin is tuple and len(args) == 2 and args[1] is Ellipsis:
        item = args[0]
    else:
        return None
    return item if _is_record_type(item) else None


def _is_union(annotation: Any) -> bool:
    import types

    origin = get_origin(annotation)
    return origin is typing.Union or origin is getattr(types, "UnionType", None)


def _check_consistency(consistency: Any) -> None:
    if consistency is not None and not isinstance(consistency, (Transaction, ConditionalWrite, AcceptRace)):
        raise TypeError("consistency must be Transaction(...), ConditionalWrite() or AcceptRace('why')")


# --- small helpers ------------------------------------------------------------


def _read_only(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    """A read-only copy for a policy: nothing it does reaches the tool."""
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


def _caller_entry(who: _Who) -> dict[str, Any]:
    entry = dataclasses.asdict(who.caller)
    if who.local:
        entry["source"] = "local"
    return entry


def _not_permitted(tool_name: str) -> str:
    """What the model is told for every refusal on authorization, so it can't
    tell a record it may not touch from one that doesn't exist."""
    return f"'{tool_name}' is not permitted for this caller."


def _no_caller(tool_name: str) -> str:
    return (
        f"'{tool_name}' needs a verified caller, and this request has none. "
        "The gate fails closed."
    )


def _refusal(tool_name: str, reason: str) -> str:
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


async def _call(
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
