"""The Gatehouse: policy enforcement + audit logging around MCPServer tools.

Wrap an ``MCPServer``, register tools through the gatekeeper instead of
directly, and every call gets: denylist enforcement, approval gates on the
tiers you choose, redacted audit logging, and spec ``ToolAnnotations``
(``readOnlyHint`` / ``destructiveHint``) derived from the tier — so MCP
clients see honest hints without you hand-writing them.
"""

from __future__ import annotations

import copy
import functools
import inspect
import time
import warnings
from collections.abc import Callable, Mapping
from typing import Any, TypeVar, overload

import anyio
import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import InputRequiredResult, ToolAnnotations

from .approvers import ElicitationApprover
from .audit import AuditLog, NullAuditLog
from .policy import AccessTier, ApprovalRequest, Policy, _as_tier, redact_arguments

F = TypeVar("F", bound=Callable[..., Any])

# Tells "no tier given" apart from any tier, so the gate can say so.
_NO_TIER: Any = object()

# Worker threads for sync approvers, kept apart from anyio's default pool.
# Sync tools draw on that pool; approvers wait on people. If they shared it,
# a stack of pending sign-offs would leave no thread for a plain read.
_APPROVER_THREADS = 40

# The parameter the guard adds, out of the tool's schema, so MCPServer hands
# it the call's Context when the tool takes none itself. Asking the client
# for approval needs one. No leading underscore: MCPServer rejects those.
_CONTEXT_PARAM = "gatehouse_context"


class GateDenied(PermissionError, ToolError):
    """Raised when the policy blocks a call, so the model sees *why* it was
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


class Gatehouse:
    """Policy-enforcing façade over an :class:`MCPServer`.

    Usage::

        mcp = MCPServer("orders")
        gk = Gatehouse(mcp, policy=Policy(...), audit=AuditLog(path="audit.jsonl"))

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
        audit: AuditLog | None = None,
    ) -> None:
        self.server = server
        self.policy = policy or Policy()
        self.audit = audit or NullAuditLog()
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
            guarded = self._guard(fn, tool_name, resolved)
            self.server.tool(
                name=tool_name,
                title=title,
                description=description,
                annotations=tool_annotations,
                **tool_kwargs,
            )(guarded)
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
        policy, audit, approver_limiter = self.policy, self.audit, self._approver_limiter
        signature = inspect.signature(fn)
        # A tool that resolves or returns its own InputRequiredResult owns the
        # call's one multi-round channel, so the gate can't ask over it.
        round_trip = not _runs_own_rounds(fn)

        async def enforce(safe_args: dict[str, Any], context: Context | None) -> InputRequiredResult | None:
            """Raise GateDenied unless the policy allows this call.

            Returns an ``InputRequiredResult`` instead when the approval is
            being asked in the client and the call must wait for its answer.

            Gets the redacted arguments only: the raw ones never reach the
            log or the approver.
            """

            def denied(reason: str, message: str) -> GateDenied:
                """Record the denial; return the error that tells the model why."""
                audit.record(
                    tool=tool_name, tier=tier.value, outcome="denied",
                    reason=reason, arguments=safe_args,
                )
                return GateDenied(message)

            if tool_name in policy.deny:
                raise denied("denylist", f"'{tool_name}' is blocked by policy.")

            if not policy.needs_approval(tier):
                return

            if policy.approver is None:
                if not policy.fail_closed:
                    return
                raise denied(
                    "approval required, no approver configured",
                    f"'{tool_name}' ({tier.value}) requires approval and "
                    "no approver is configured. The gate fails closed.",
                )

            timeout = policy.approval_timeout
            request = ApprovalRequest(
                tool=tool_name,
                tier=tier,
                # Its own copy: nothing the approver does to these can change
                # what the audit log records.
                arguments=copy.deepcopy(safe_args),
                deadline=None if timeout is None else time.monotonic() + timeout,
            )
            ask = functools.partial(policy.approver, request)
            if isinstance(policy.approver, ElicitationApprover):
                elicitor = policy.approver
                transport = elicitor.transport(context, round_trip=round_trip)
                if transport == "round-trip":
                    verdict = elicitor.answer(request, context)
                    if verdict is None:
                        # The call ends here for now, and the client calls
                        # again with the answer. If it never does, this line
                        # is the record that it was asked.
                        audit.record(
                            tool=tool_name, tier=tier.value, outcome="pending",
                            reason="approval asked in client", arguments=safe_args,
                        )
                        return elicitor.question(request, timeout)
                    allowed, reason = verdict
                    if not allowed:
                        raise denied(reason, _refusal(tool_name, reason))
                    return None
                if transport == "back-channel":
                    ask = functools.partial(elicitor.ask, request, context)
                elif elicitor.fallback is not None:
                    ask = functools.partial(elicitor.fallback, request)
                else:
                    raise denied(
                        "approval required, client cannot be asked",
                        f"'{tool_name}' ({tier.value}) requires approval, and this "
                        "client can't be asked for it (no form elicitation). "
                        "The gate fails closed.",
                    )
            try:
                # move_on_after, not fail_after: an approver that raises
                # TimeoutError itself (a Slack call timing out) is an approver
                # error, not the gate's deadline.
                with anyio.move_on_after(timeout) as waiting:
                    approved = await _call(
                        ask, limiter=approver_limiter, abandon_on_cancel=True
                    )
            except Exception as exc:
                # An approver that can't answer (Slack down, ticket API timing
                # out) is a refusal, not a crash — and it belongs in the trail.
                # Type only, as with tool errors.
                raise denied(
                    f"approver error: {type(exc).__name__}",
                    f"'{tool_name}' could not be approved: the approver "
                    "failed. The gate fails closed.",
                ) from exc
            except anyio.get_cancelled_exc_class():
                # The client gave up, or the server is shutting down.
                # Cancellation is a BaseException, so the clause above never
                # sees it, and the gate's own timeout never gets this far:
                # move_on_after catches that one. Log it, then let it carry
                # on as is: swallowing it would keep a cancelled task running.
                audit.record(
                    tool=tool_name, tier=tier.value, outcome="cancelled",
                    reason="awaiting approval", arguments=safe_args,
                )
                raise
            if waiting.cancelled_caught:
                raise denied(
                    "approval timed out",
                    f"'{tool_name}' was not approved within {timeout:g}s. "
                    "The gate fails closed.",
                )
            if not approved:
                raise denied("approver refused", _refusal(tool_name, "approver refused"))
            return None

        async def run(
            arguments: dict[str, Any], args: tuple, kwargs: dict[str, Any], context: Context | None
        ) -> Any:
            safe_args = redact_arguments(arguments, policy.redact)
            question = await enforce(safe_args, context)
            if question is not None:
                return question
            start = time.perf_counter()
            try:
                result = await _call(functools.partial(fn, *args, **kwargs))
            except Exception as exc:
                # Only the exception TYPE goes in the log. Exception messages
                # routinely embed argument values ("invalid api key: sk-…"),
                # which would defeat redaction. The client still receives the
                # full message through the normal tool-error path.
                audit.record(
                    tool=tool_name, tier=tier.value, outcome="error",
                    reason=type(exc).__name__, arguments=safe_args,
                    duration_ms=round((time.perf_counter() - start) * 1000, 2),
                )
                raise
            except anyio.get_cancelled_exc_class():
                # Cancelled mid-run, as in enforce. The tool may have done
                # part of its work, which is exactly what the trail is for.
                audit.record(
                    tool=tool_name, tier=tier.value, outcome="cancelled",
                    reason="tool running", arguments=safe_args,
                    duration_ms=round((time.perf_counter() - start) * 1000, 2),
                )
                raise
            audit.record(
                tool=tool_name, tier=tier.value, outcome="ok", arguments=safe_args,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )
            return result

        # MCPServer injects its Context object as a regular parameter. It is
        # not a model-supplied argument, so it stays out of the audit trail
        # and out of what the approver sees.
        ctx_param = _find_context_parameter(fn)

        # functools.wraps preserves the signature (via __wrapped__), so
        # MCPServer still generates the tool's input schema from the real
        # function — the guard is invisible to schema generation. The
        # signature is computed once, above, not on every call.
        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            context = kwargs.pop(_CONTEXT_PARAM, None) if ctx_param is None else None
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            if ctx_param is not None:
                context = arguments.pop(ctx_param, None)
            return await run(arguments, args, kwargs, context)

        if ctx_param is None:
            # The tool takes no Context, so the guard asks for one under a
            # name of its own. __signature__ wins over __wrapped__, and its
            # Context annotation keeps the parameter out of the schema.
            if _CONTEXT_PARAM in signature.parameters:
                raise ValueError(
                    f"'{_CONTEXT_PARAM}' is a parameter name mcp-gatehouse reserves; "
                    "rename the tool's parameter"
                )
            # Evaluated here, where fn's own globals resolve string annotations:
            # MCPServer takes a __signature__ as it is and evaluates nothing.
            try:
                exposed = inspect.signature(fn, eval_str=True)
            except Exception:
                exposed = signature
            params = list(exposed.parameters.values())
            hidden = inspect.Parameter(
                _CONTEXT_PARAM, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context
            )
            at = len(params) - (bool(params) and params[-1].kind is inspect.Parameter.VAR_KEYWORD)
            guarded.__signature__ = exposed.replace(parameters=[*params[:at], hidden, *params[at:]])
            # A copy: wraps() shares fn's own dict, which must stay untouched.
            guarded.__annotations__ = {**getattr(fn, "__annotations__", {}), _CONTEXT_PARAM: Context}

        return guarded


def _refusal(tool_name: str, reason: str) -> str:
    """What the model is told when an approval comes back no."""
    if reason == "approval timed out":
        return f"'{tool_name}' was not approved in time. The gate fails closed."
    if reason == "approval already used":
        return f"'{tool_name}': that approval was already used. Each approval runs one call."
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


def _find_context_parameter(fn: Callable[..., Any]) -> str | None:
    """Name of the parameter MCPServer will inject its ``Context`` into.

    Asks the SDK itself, so the two can't disagree. They used to: the gate
    missed ``ctx: Context | None = None``, which the SDK injects into, so
    the gate added its own hidden parameter. The SDK, seeing ``ctx``
    first, then treated that one as an ordinary argument: it showed up in
    the tool's schema for the model to fill, ``ctx`` went into the audit
    log, and approval in the client was always denied, because the gate
    never got the Context.
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
    import typing

    try:
        hints = typing.get_type_hints(fn)
    except Exception:
        return None
    for param_name, annotation in hints.items():
        candidates = (annotation, *typing.get_args(annotation)) if typing.get_origin(annotation) else (annotation,)
        if any(inspect.isclass(c) and issubclass(c, Context) for c in candidates):
            return param_name
    return None
