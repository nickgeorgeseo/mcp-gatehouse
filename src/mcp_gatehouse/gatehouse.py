"""The Gatehouse: policy enforcement and audit logging around MCPServer tools.

Register tools through a :class:`Gatehouse` instead of the ``MCPServer``.
Each tool keeps its own name, docs and input schema, and gains:

- honest spec hints (``readOnlyHint`` / ``destructiveHint``) from its tier;
- the policy, checked on every call: the denylist first, then, for the
  tiers that need it, approval from the policy's approver;
- one audit line per outcome, with the arguments redacted first.

Where to read: :class:`Gatehouse` is registration. :class:`_ToolGate` is
everything that happens when the model calls a tool, in order, starting
at :meth:`_ToolGate.__call__`. :class:`_Call` writes the audit lines.
"""

from __future__ import annotations

import copy
import functools
import inspect
import logging
import os
import time
import typing
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar, overload

import anyio
import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import InputRequiredResult, ToolAnnotations

from .approvers import ElicitationApprover
from .audit import AuditLog, AuditSink, NullAuditLog, Outcome, Reason
from .policy import AccessTier, ApprovalRequest, Policy, _as_tier, redact_arguments

F = TypeVar("F", bound=Callable[..., Any])

_log = logging.getLogger("mcp_gatehouse")

# Worker threads for sync approvers, apart from anyio's default pool. Sync
# tools run in that pool, and approvers wait on people: sharing it, a stack
# of pending sign-offs would leave no thread for a plain read.
_APPROVER_THREADS = 40

# The parameter the gate adds, kept out of the tool's schema, so MCPServer
# hands it the call's Context when the tool takes none itself. Asking the
# client for approval needs one. No leading underscore: MCPServer refuses those.
_CONTEXT_PARAM = "gatehouse_context"

# A sleep or select can wake a hair before the instant it was given, so a
# "no" this close to the deadline counts as the deadline.
_DEADLINE_SLACK = 0.05

# Tells "no tier given" apart from every real tier, so the gate can warn.
_NO_TIER: Any = object()


class GateDenied(PermissionError, ToolError):
    """Raised when the policy blocks a call; its message tells the model why.

    It's a ``ToolError`` because the SDK treats those as anticipated
    failures: the message reaches the model, and the server logs it at
    INFO. Anything else counts as a crash: the model gets only "Error
    executing tool <name>", and the server logs a traceback at ERROR, which
    on every refusal would bury the real failures. ``PermissionError``
    comes first, so ``except PermissionError`` catches it too.
    """


# --- registration -----------------------------------------------------------


class Gatehouse:
    """Policy-enforcing façade over an :class:`MCPServer`.

    Usage::

        mcp = MCPServer("orders")
        gk = Gatehouse(mcp, policy=Policy(...), audit="audit.jsonl")

        @gk.read
        def lookup_order(order_id: str) -> str: ...

        @gk.destructive
        def cancel_order(order_id: str) -> str: ...

    ``@gk.tool(tier=...)`` is the long form, and ``gk.add_tool(fn, tier=...)``
    registers without a decorator. Each returns (or keeps) your function
    unwrapped: calling it directly, in a unit test say, skips the gate.
    """

    def __init__(
        self,
        server: MCPServer,
        policy: Policy | None = None,
        audit: AuditSink | str | os.PathLike[str] | None = None,
    ) -> None:
        """``audit`` is an :class:`AuditLog`, any :class:`AuditSink`, or a
        path, which opens an ``AuditLog`` there. ``None`` keeps no log.

        ``policy`` and ``audit`` are read on every call, so assigning a new
        one to ``gatehouse.policy`` or ``gatehouse.audit`` takes effect on
        the next call to any tool, registered before or after.
        """
        self.server = server
        self.policy: Policy = policy or Policy()
        if isinstance(audit, (str, os.PathLike)):
            audit = AuditLog(path=audit)
        elif audit is not None and not callable(getattr(audit, "record", None)):
            raise TypeError(
                f"audit must be an AuditLog, a path, or an object with a record(**event) method; "
                f"got {type(audit).__name__}"
            )
        self.audit: AuditSink = audit if audit is not None else NullAuditLog()
        self._approver_limiter = anyio.CapacityLimiter(_APPROVER_THREADS)

    def tool(
        self,
        tier: AccessTier | str = _NO_TIER,
        *,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | Mapping[str, Any] | None = None,
        **tool_kwargs: Any,
    ) -> Callable[[F], F]:
        """Register a tool on the wrapped server, with enforcement.

        ``tier`` is an :class:`AccessTier` or its name (``"write"``). Leaving
        it out still registers the tool as ``READ``, with a ``FutureWarning``:
        that's ungated, and tells clients the tool is read-only, whatever it
        does. A future release will require it.

        Accepts any extra keyword arguments ``MCPServer.tool`` understands
        and forwards them untouched. ``annotations`` may set the hints the
        tier doesn't decide (``idempotentHint``, ``openWorldHint``); the
        tier sets ``readOnlyHint`` and ``destructiveHint``, and an
        ``annotations`` value contradicting them is refused, so the hints
        stay honest.
        """
        if callable(tier):
            raise TypeError(
                "use @gatehouse.tool(...) with parentheses, not @gatehouse.tool "
                "(or @gatehouse.read / .write / .destructive, which take either)"
            )
        unclassified = tier is _NO_TIER
        resolved = AccessTier.READ if unclassified else _as_tier(tier)
        # Checked now, not on the first call: a mistake here should stop the
        # server starting, not surface as a crash mid-conversation.
        tool_annotations = _annotations_for(resolved, title, annotations)

        def decorator(fn: F) -> F:
            tool_name = name or fn.__name__
            if unclassified:
                warnings.warn(
                    f"mcp-gatehouse: tool {tool_name!r} has no tier, so it is registered as READ: "
                    "it runs without approval and clients are told it is read-only. Pass tier=... "
                    "(or use @gatehouse.read / .write / .destructive). A future release will require it.",
                    FutureWarning,
                    stacklevel=2,
                )
            self.server.tool(
                name=tool_name,
                title=title,
                description=description,
                annotations=tool_annotations,
                **tool_kwargs,
            )(self._guard(fn, tool_name, resolved))
            return fn

        return decorator

    def add_tool(self, fn: Callable[..., Any], tier: AccessTier | str, **tool_kwargs: Any) -> None:
        """Register ``fn`` as a gated tool without a decorator, the way
        ``MCPServer.add_tool`` does: in a loop, or for a function defined
        elsewhere. Takes the same keyword arguments as :meth:`tool`."""
        self.tool(tier, **tool_kwargs)(fn)

    @overload
    def read(self, fn: F, /) -> F: ...
    @overload
    def read(self, fn: None = None, /, **tool_kwargs: Any) -> Callable[[F], F]: ...
    def read(self, fn: F | None = None, /, **tool_kwargs: Any) -> F | Callable[[F], F]:
        """Register a ``READ`` tool: looks things up, never changes state.
        Use as ``@gatehouse.read`` or ``@gatehouse.read(name=..., ...)``."""
        return self._tier_decorator(AccessTier.READ, fn, tool_kwargs)

    @overload
    def write(self, fn: F, /) -> F: ...
    @overload
    def write(self, fn: None = None, /, **tool_kwargs: Any) -> Callable[[F], F]: ...
    def write(self, fn: F | None = None, /, **tool_kwargs: Any) -> F | Callable[[F], F]:
        """Register a ``WRITE`` tool: creates or updates, reversible with
        effort. Use as ``@gatehouse.write`` or ``@gatehouse.write(...)``."""
        return self._tier_decorator(AccessTier.WRITE, fn, tool_kwargs)

    @overload
    def destructive(self, fn: F, /) -> F: ...
    @overload
    def destructive(self, fn: None = None, /, **tool_kwargs: Any) -> Callable[[F], F]: ...
    def destructive(self, fn: F | None = None, /, **tool_kwargs: Any) -> F | Callable[[F], F]:
        """Register a ``DESTRUCTIVE`` tool: deletes, sends or pays. Gated
        under the default policy. Use as ``@gatehouse.destructive`` or
        ``@gatehouse.destructive(...)``."""
        return self._tier_decorator(AccessTier.DESTRUCTIVE, fn, tool_kwargs)

    def _tier_decorator(
        self, tier: AccessTier, fn: F | None, tool_kwargs: dict[str, Any]
    ) -> F | Callable[[F], F]:
        if "tier" in tool_kwargs:
            raise TypeError(f"@gatehouse.{tier.value} sets the tier itself; use @gatehouse.tool(tier=...) to pass one")
        decorator: Callable[[F], F] = self.tool(tier, **tool_kwargs)
        if fn is None:
            return decorator
        if not callable(fn):
            raise TypeError(
                f"@gatehouse.{tier.value}(...) takes keyword arguments only "
                f"(name=..., title=...), not {type(fn).__name__}"
            )
        return decorator(fn)

    def _guard(self, fn: Callable[..., Any], tool_name: str, tier: AccessTier) -> Callable[..., Any]:
        """The function MCPServer registers in ``fn``'s place."""
        return _ToolGate(self, fn, tool_name, tier).entry_point()


def _annotations_for(
    tier: AccessTier, title: str | None, given: ToolAnnotations | Mapping[str, Any] | None = None
) -> ToolAnnotations:
    """The tool's spec hints: ``readOnlyHint`` / ``destructiveHint`` from the
    tier, anything else (``idempotentHint``, ``openWorldHint``) from ``given``.

    The tier's two hints aren't up for negotiation. ``given`` may repeat
    them, but one that contradicts the tier is refused: a client trusts
    those hints, so they must say what the gate enforces.
    """
    derived = {"read_only_hint": tier is AccessTier.READ, "destructive_hint": tier is AccessTier.DESTRUCTIVE}
    if given is None:
        base = ToolAnnotations()
    elif isinstance(given, ToolAnnotations):
        base = given
    elif isinstance(given, Mapping):
        fields = ToolAnnotations.model_fields
        known = set(fields) | {f.alias for f in fields.values() if f.alias}
        unknown = sorted(set(map(str, given)) - known)
        if unknown:
            # Pydantic would drop these without a word; a misspelled hint
            # should not quietly vanish.
            raise ValueError(f"unknown tool annotation(s) {unknown}; known: {sorted(known)}")
        base = ToolAnnotations.model_validate(dict(given))
    else:
        raise TypeError(f"annotations must be a ToolAnnotations or a mapping, not {type(given).__name__}")
    for hint, value in derived.items():
        claimed = getattr(base, hint)
        if claimed is not None and claimed != value:
            alias = ToolAnnotations.model_fields[hint].alias or hint
            raise ValueError(
                f"annotations {alias}={claimed} contradicts tier {tier.value!r}, which sets it to {value}; "
                "change the tier instead"
            )
    return base.model_copy(update={**derived, "title": title if title is not None else base.title})


# --- enforcement: what happens on each call ----------------------------------


class _ToolGate:
    """Everything that happens when the model calls one gated tool.

    Built once, at registration. What can be worked out from the function
    alone (its signature, where its Context goes) is worked out here, not
    on every call. MCPServer calls the function :meth:`entry_point` returns,
    which hands each call to :meth:`__call__`.
    """

    def __init__(self, gatehouse: Gatehouse, fn: Callable[..., Any], name: str, tier: AccessTier) -> None:
        self.gatehouse = gatehouse
        self.fn = fn
        self.name = name
        self.tier = tier
        self.signature = inspect.signature(fn)
        # MCPServer injects its Context as an ordinary parameter. The model
        # didn't send it, so it stays out of the log and away from approvers.
        self.context_param = _find_context_parameter(fn)
        if self.context_param is None and _CONTEXT_PARAM in self.signature.parameters:
            raise ValueError(
                f"'{_CONTEXT_PARAM}' is a parameter name mcp-gatehouse reserves; rename the tool's parameter"
            )
        # A tool that resolves its own parameters, or returns its own
        # InputRequiredResult, owns the call's one multi-round channel, so
        # the gate can't ask the client over it.
        self.can_round_trip = not _runs_own_rounds(fn)

    def entry_point(self) -> Callable[..., Any]:
        """``fn`` as MCPServer should see it: same name, docs and schema.

        ``functools.wraps`` keeps ``fn``'s signature (through
        ``__wrapped__``), so MCPServer builds the input schema from ``fn``
        itself. When ``fn`` takes no Context, the signature gains a hidden
        one (see :func:`_add_hidden_context`).
        """
        gate = self

        @functools.wraps(self.fn)
        async def gated(*args: Any, **kwargs: Any) -> Any:
            return await gate(args, kwargs)

        if self.context_param is None:
            _add_hidden_context(gated, self.fn, self.signature)
        return gated

    async def __call__(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        """One call: redact, check the policy, run. Every way out of here
        writes its own audit line."""
        context, arguments = self._take_context(args, kwargs)
        # Read once per call: a policy or sink assigned to the Gatehouse
        # applies from the next call, and one call never sees two.
        policy, audit = self.gatehouse.policy, self.gatehouse.audit
        call = _Call(
            tool=self.name,
            tier=self.tier,
            # Only this redacted copy reaches the log or an approver.
            arguments=redact_arguments(arguments, policy.redact),
            audit=audit,
            timeout=policy.approval_timeout,
        )
        question = await self._check(call, policy, context)
        if question is not None:
            return question  # the client answers it, then calls again
        return await self._run(call, args, kwargs)

    def _take_context(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[Context | None, dict[str, Any]]:
        """Split the call's Context off the arguments the model sent.

        The hidden parameter comes out of ``kwargs`` itself, so ``fn``
        never receives it. A Context parameter ``fn`` declares stays in
        ``kwargs``, for ``fn``.
        """
        context: Context | None = None
        if self.context_param is None:
            context = kwargs.pop(_CONTEXT_PARAM, None)
        bound = self.signature.bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        if self.context_param is not None:
            context = arguments.pop(self.context_param, None)
        return context, arguments

    async def _check(self, call: _Call, policy: Policy, context: Context | None) -> InputRequiredResult | None:
        """Raise :class:`GateDenied` unless the policy lets this call run.

        Returns a question for the client instead when the approval is
        being asked in the client and the call has to wait for the answer.
        """
        if self.name in policy.deny:
            raise call.deny(Reason.DENYLIST)
        if not policy.needs_approval(self.tier):
            return None
        approver = policy.approver
        if approver is None:
            if policy.fail_closed:
                raise call.deny(Reason.NO_APPROVER)
            return None
        request = ApprovalRequest(
            tool=self.name,
            tier=self.tier,
            # Its own copy: nothing an approver does to it can change what
            # the log records.
            arguments=copy.deepcopy(call.arguments),
            deadline=None if call.timeout is None else time.monotonic() + call.timeout,
        )
        if isinstance(approver, ElicitationApprover):
            return await self._ask_in_client(call, approver, request, context)
        await self._wait_for_approval(call, request, functools.partial(approver, request))
        return None

    async def _ask_in_client(
        self, call: _Call, approver: ElicitationApprover, request: ApprovalRequest, context: Context | None
    ) -> InputRequiredResult | None:
        """Approval from the person at the client: MCP elicitation.

        Up to protocol 2025-11-25 the form goes to the client mid-call, and
        the gate waits for it like any approver. From 2026-07-28 the call
        ends with the question, and the client's next call brings the
        answer. A client that can't be asked leaves it to the fallback.
        """
        transport = approver.transport(context, round_trip=self.can_round_trip)
        if transport == "round-trip":
            answer = approver.answer(request, context)
            if answer is None:
                # The first round. If the client never comes back, this line
                # is the record that it was asked.
                call.record(Outcome.PENDING, Reason.ASKED_IN_CLIENT)
                return approver.question(request, call.timeout)
            allowed, reason = answer
            if not allowed:
                raise call.deny(reason)
            return None
        ask: Callable[[], Any]
        if transport == "back-channel":
            ask = functools.partial(approver.ask, request, context)
        elif approver.fallback is not None:
            ask = functools.partial(approver.fallback, request)
        else:
            raise call.deny(Reason.CLIENT_CANNOT_BE_ASKED)
        await self._wait_for_approval(call, request, ask)
        return None

    async def _wait_for_approval(self, call: _Call, request: ApprovalRequest, ask: Callable[[], Any]) -> None:
        """Run the approver under the policy's deadline. Return if it said
        yes; otherwise raise :class:`GateDenied`, saying why."""
        try:
            # move_on_after, not fail_after: an approver that raises
            # TimeoutError itself (a Slack call timing out) has failed, which
            # isn't the same as the gate's deadline passing.
            with anyio.move_on_after(call.timeout) as waiting:
                approved = await _call(ask, limiter=self.gatehouse._approver_limiter, abandon_on_cancel=True)
        except Exception as exc:
            # An approver that can't answer (Slack down, a bug) is a refusal,
            # not a crash. Type only, as with tool errors.
            raise call.deny(Reason.approver_error(type(exc).__name__)) from exc
        except anyio.get_cancelled_exc_class():
            # The client gave up, or the server is stopping. (The gate's own
            # deadline never gets here: move_on_after catches that.) Record
            # it and let it carry on: swallowing it would keep a cancelled
            # task running.
            call.record(Outcome.CANCELLED, Reason.AWAITING_APPROVAL)
            raise
        # An approver that honours request.deadline gives up just as the
        # gate's own timer fires, and either can finish first. A "no" at
        # the deadline is the deadline, not a person refusing.
        if waiting.cancelled_caught or (not approved and _past(request.deadline)):
            raise call.deny(Reason.TIMED_OUT)
        if not approved:
            raise call.deny(Reason.REFUSED)

    async def _run(self, call: _Call, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        """Run the tool and record how it went."""
        start = time.perf_counter()

        def took() -> float:
            return round((time.perf_counter() - start) * 1000, 2)

        try:
            result = await _call(functools.partial(self.fn, *args, **kwargs))
        except Exception as exc:
            # Only the exception's type goes in the log: messages routinely
            # embed argument values ("invalid api key: sk-…"), which would
            # defeat redaction. The client gets what the SDK gives it either
            # way: a ToolError's message, or else "Error executing tool <name>".
            call.record(Outcome.ERROR, type(exc).__name__, duration_ms=took())
            raise
        except anyio.get_cancelled_exc_class():
            # Cancelled mid-run. The tool may have done part of its work,
            # which is exactly what the trail is for.
            call.record(Outcome.CANCELLED, Reason.TOOL_RUNNING, duration_ms=took())
            raise
        call.record(Outcome.OK, duration_ms=took())
        return result


@dataclass
class _Call:
    """One call to a gated tool, as its audit lines describe it."""

    tool: str
    tier: AccessTier
    arguments: dict[str, Any]
    """The redacted arguments."""
    audit: AuditSink
    timeout: float | None
    """The policy's ``approval_timeout`` when the call started."""

    def record(self, outcome: Outcome, reason: str | None = None, **extra: Any) -> None:
        """Write one audit line: tool, tier, outcome, reason, arguments, then ``extra``."""
        event: dict[str, Any] = {"tool": self.tool, "tier": self.tier.value, "outcome": outcome.value}
        if reason is not None:
            event["reason"] = reason
        event["arguments"] = self.arguments
        event.update(extra)
        _record(self.audit, event)

    def deny(self, reason: str) -> GateDenied:
        """Record a denial; return the error that tells the model why."""
        self.record(Outcome.DENIED, reason)
        return GateDenied(_denial_message(self, reason))


def _denial_message(call: _Call, reason: str) -> str:
    """What the model is told when the gate refuses a call."""
    tool = f"'{call.tool}'"
    if reason == Reason.DENYLIST:
        return f"{tool} is blocked by policy."
    if reason == Reason.NO_APPROVER:
        return f"{tool} ({call.tier.value}) requires approval and no approver is configured. The gate fails closed."
    if reason == Reason.CLIENT_CANNOT_BE_ASKED:
        return (
            f"{tool} ({call.tier.value}) requires approval, and this client can't be asked for it "
            "(no form elicitation). The gate fails closed."
        )
    if reason == Reason.TIMED_OUT:
        within = "in time" if call.timeout is None else f"within {call.timeout:g}s"
        return f"{tool} was not approved {within}. The gate fails closed."
    if reason == Reason.ALREADY_USED:
        return f"{tool}: that approval was already used. Each approval runs one call."
    if reason.startswith(Reason.APPROVER_ERROR):
        return f"{tool} could not be approved: the approver failed. The gate fails closed."
    return f"{tool} was refused by the approver."


def _record(audit: AuditSink, event: dict[str, Any]) -> None:
    """Hand one event to the sink. A sink that fails is logged, loudly, and
    the call goes on: most lines are written after the tool ran, and turning
    its result into an error would tell the model that a call which did its
    work had failed, so it might well run it again."""
    try:
        audit.record(**event)
    except Exception:
        _log.error(
            "mcp-gatehouse: the audit sink failed to record %r (outcome %r); this record is lost",
            event.get("tool"), event.get("outcome"), exc_info=True,
        )


def _past(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline - _DEADLINE_SLACK


# --- helpers ------------------------------------------------------------------


async def _call(
    fn: Callable[[], Any],
    *,
    limiter: anyio.CapacityLimiter | None = None,
    abandon_on_cancel: bool = False,
) -> Any:
    """Await an async callable; run a sync one in a worker thread.

    MCPServer runs sync tools in a thread itself, but all it sees is the
    gate's async wrapper, so the offload has to happen here. Otherwise a
    blocking tool, or an approver waiting on a person, would stall every
    other request on the server.

    ``fn`` takes no arguments (bind them with ``functools.partial``), so
    these options can't collide with a tool's own parameter names.
    ``limiter`` picks the thread pool (anyio's default when ``None``).
    ``abandon_on_cancel`` lets a timeout stop waiting on a thread that is
    still blocked; Python can't stop the thread, so it finishes in the
    background and its result is dropped. A sync callable that returns an
    awaitable (``lambda r: check(r)`` with ``check`` async) is awaited.
    """
    if _is_async_callable(fn):
        return await fn()
    result = await anyio.to_thread.run_sync(fn, limiter=limiter, abandon_on_cancel=abandon_on_cancel)
    if inspect.isawaitable(result):
        result = await result
    return result


def _is_async_callable(fn: Any) -> bool:
    while isinstance(fn, functools.partial):
        fn = fn.func
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None))


def _runs_own_rounds(fn: Callable[..., Any]) -> bool:
    """Does the tool drive the call's multi-round input flow itself?"""
    try:
        from mcp.server.mcpserver.resolve import find_resolved_parameters, returns_input_required

        return bool(find_resolved_parameters(fn)) or returns_input_required(fn)
    except Exception:
        return True  # can't tell, so stay off the channel: the fallback decides


def _find_context_parameter(fn: Callable[..., Any]) -> str | None:
    """Name of the parameter MCPServer will inject its ``Context`` into.

    Asks the SDK, so the gate and the SDK can't disagree. If they did, a
    tool taking ``ctx: Context | None = None`` would get the gate's hidden
    parameter too, the SDK would treat that one as an ordinary argument
    (in the schema, for the model to fill), and approval in the client
    would never see the Context it needs.
    """
    try:
        from mcp.server.mcpserver.utilities.context_injection import find_context_parameter
    except ImportError:  # moved in some later SDK: mirror what it did
        find_context_parameter = _sdk_find_context_parameter
    try:
        return find_context_parameter(fn)
    except Exception:
        return None


def _sdk_find_context_parameter(fn: Callable[..., Any]) -> str | None:
    """The SDK's rule (mcp 2.0-2.3): the first parameter whose resolved
    hint is a ``Context`` subclass, directly or inside a union such as
    ``Optional[Context]``. ``Annotated`` is unwrapped by get_type_hints."""
    try:
        hints = typing.get_type_hints(fn)
    except Exception:
        return None
    for param_name, annotation in hints.items():
        candidates = (annotation, *typing.get_args(annotation)) if typing.get_origin(annotation) else (annotation,)
        if any(inspect.isclass(c) and issubclass(c, Context) for c in candidates):
            return param_name
    return None


def _add_hidden_context(gated: Callable[..., Any], fn: Callable[..., Any], signature: inspect.Signature) -> None:
    """Give ``gated`` a keyword-only ``gatehouse_context`` parameter, which
    MCPServer fills with the call's Context, without it entering the schema.

    ``__signature__`` wins over ``__wrapped__``, and the parameter's
    Context annotation is what keeps MCPServer from treating it as an
    argument. String annotations are resolved here, in ``fn``'s own
    globals: MCPServer takes a ``__signature__`` as it is.
    """
    try:
        exposed = inspect.signature(fn, eval_str=True)
    except Exception:
        exposed = signature
    params = list(exposed.parameters.values())
    hidden = inspect.Parameter(_CONTEXT_PARAM, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context)
    # Before a **kwargs, which has to stay last.
    at = len(params) - (bool(params) and params[-1].kind is inspect.Parameter.VAR_KEYWORD)
    gated.__signature__ = exposed.replace(  # type: ignore[attr-defined]  # read by inspect.signature
        parameters=[*params[:at], hidden, *params[at:]]
    )
    # wraps() handed gated fn's own annotations dict, which must stay
    # untouched: give gated a copy with the hidden parameter added.
    gated.__annotations__ = {**getattr(fn, "__annotations__", {}), _CONTEXT_PARAM: Context}
