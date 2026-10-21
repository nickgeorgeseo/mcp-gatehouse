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
from typing import Any, Callable, TypeVar

import anyio
import anyio.to_thread
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .audit import AuditLog, NullAuditLog
from .policy import AccessTier, ApprovalRequest, Policy, redact_arguments

F = TypeVar("F", bound=Callable[..., Any])

# Worker threads for sync approvers, kept apart from anyio's default pool.
# Sync tools draw on that pool; approvers wait on people. If they shared it,
# a stack of pending sign-offs would leave no thread for a plain read.
_APPROVER_THREADS = 40


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


def _annotations_for(tier: AccessTier, title: str | None) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=tier is AccessTier.READ,
        destructiveHint=tier is AccessTier.DESTRUCTIVE,
    )


class Gatehouse:
    """Policy-enforcing façade over an :class:`MCPServer`.

    Usage::

        mcp = MCPServer("orders")
        gk = Gatehouse(mcp, policy=Policy(...), audit=AuditLog(path="audit.jsonl"))

        @gk.tool(tier=AccessTier.READ)
        def lookup_order(order_id: str) -> str: ...

        @gk.tool(tier=AccessTier.DESTRUCTIVE)
        def cancel_order(order_id: str) -> str: ...
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
        tier: AccessTier = AccessTier.READ,
        *,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        **tool_kwargs: Any,
    ) -> Callable[[F], F]:
        """Register a tool on the wrapped server, with enforcement.

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

        def decorator(fn: F) -> F:
            tool_name = name or fn.__name__
            guarded = self._guard(fn, tool_name, tier)
            self.server.tool(
                name=tool_name,
                title=title,
                description=description,
                annotations=_annotations_for(tier, title),
                **tool_kwargs,
            )(guarded)
            return fn

        return decorator

    def _guard(self, fn: Callable[..., Any], tool_name: str, tier: AccessTier) -> Callable[..., Any]:
        policy, audit, approver_limiter = self.policy, self.audit, self._approver_limiter
        signature = inspect.signature(fn)

        async def enforce(safe_args: dict[str, Any]) -> None:
            """Raise GateDenied unless the policy allows this call.

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
            try:
                # move_on_after, not fail_after: an approver that raises
                # TimeoutError itself (a Slack call timing out) is an approver
                # error, not the gate's deadline.
                with anyio.move_on_after(timeout) as waiting:
                    approved = await _call(
                        functools.partial(policy.approver, request),
                        limiter=approver_limiter,
                        abandon_on_cancel=True,
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
            if waiting.cancelled_caught:
                raise denied(
                    "approval timed out",
                    f"'{tool_name}' was not approved within {timeout:g}s. "
                    "The gate fails closed.",
                )
            if not approved:
                raise denied("approver refused", f"'{tool_name}' was refused by the approver.")

        async def run(arguments: dict[str, Any], args: tuple, kwargs: dict[str, Any]) -> Any:
            safe_args = redact_arguments(arguments, policy.redact)
            await enforce(safe_args)
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
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            if ctx_param is not None:
                arguments.pop(ctx_param, None)
            return await run(arguments, args, kwargs)

        return guarded


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
    """Name of the parameter MCPServer will inject its ``Context`` into."""
    try:
        from mcp.server.mcpserver import Context

        hints = inspect.get_annotations(fn, eval_str=True)
    except Exception:
        return None
    for param_name, annotation in hints.items():
        if param_name == "return":
            continue
        if annotation is Context or (
            inspect.isclass(annotation) and issubclass(annotation, Context)
        ):
            return param_name
    return None
