"""The Gatehouse: policy enforcement + audit logging around FastMCP tools.

Wrap a ``FastMCP`` server, register tools through the gatekeeper instead of
directly, and every call gets: denylist enforcement, approval gates on the
tiers you choose, redacted audit logging, and spec ``ToolAnnotations``
(``readOnlyHint`` / ``destructiveHint``) derived from the tier — so MCP
clients see honest hints without you hand-writing them.
"""

from __future__ import annotations

import functools
import inspect
import time
from typing import Any, Callable, TypeVar

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .audit import AuditLog, NullAuditLog
from .policy import AccessTier, ApprovalRequest, Policy, redact_arguments

F = TypeVar("F", bound=Callable[..., Any])


class GateDenied(PermissionError):
    """Raised when the policy blocks a call. FastMCP surfaces it to the
    client as a tool error, so the model sees *why* it was refused."""


def _annotations_for(tier: AccessTier, title: str | None) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=tier is AccessTier.READ,
        destructiveHint=tier is AccessTier.DESTRUCTIVE,
    )


class Gatehouse:
    """Policy-enforcing façade over a :class:`FastMCP` server.

    Usage::

        mcp = FastMCP("orders")
        gk = Gatehouse(mcp, policy=Policy(...), audit=AuditLog(path="audit.jsonl"))

        @gk.tool(tier=AccessTier.READ)
        def lookup_order(order_id: str) -> str: ...

        @gk.tool(tier=AccessTier.DESTRUCTIVE)
        def cancel_order(order_id: str) -> str: ...
    """

    def __init__(
        self,
        server: FastMCP,
        policy: Policy | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.server = server
        self.policy = policy or Policy()
        self.audit = audit or NullAuditLog()

    def tool(
        self,
        tier: AccessTier = AccessTier.READ,
        *,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        **fastmcp_kwargs: Any,
    ) -> Callable[[F], F]:
        """Register a tool on the wrapped server, with enforcement.

        Accepts any extra keyword arguments ``FastMCP.tool`` understands
        and forwards them untouched. ``annotations`` is derived from the
        tier and cannot be overridden — the hints must stay honest.
        """
        if callable(tier):
            raise TypeError(
                "use @gatehouse.tool(...) with parentheses, not @gatehouse.tool"
            )
        if "annotations" in fastmcp_kwargs:
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
                **fastmcp_kwargs,
            )(guarded)
            return fn

        return decorator

    def _guard(self, fn: Callable[..., Any], tool_name: str, tier: AccessTier) -> Callable[..., Any]:
        policy, audit = self.policy, self.audit

        async def enforce(arguments: dict[str, Any]) -> None:
            """Raise GateDenied unless the policy allows this call."""
            safe_args = redact_arguments(arguments, policy.redact)

            if tool_name in policy.deny:
                audit.record(
                    tool=tool_name, tier=tier.value, outcome="denied",
                    reason="denylist", arguments=safe_args,
                )
                raise GateDenied(f"'{tool_name}' is blocked by policy.")

            if policy.needs_approval(tier):
                if policy.approver is None:
                    if policy.fail_closed:
                        audit.record(
                            tool=tool_name, tier=tier.value, outcome="denied",
                            reason="approval required, no approver configured",
                            arguments=safe_args,
                        )
                        raise GateDenied(
                            f"'{tool_name}' ({tier.value}) requires approval and "
                            "no approver is configured. The gate fails closed."
                        )
                else:
                    request = ApprovalRequest(tool=tool_name, tier=tier, arguments=safe_args)
                    verdict = policy.approver(request)
                    if inspect.isawaitable(verdict):
                        verdict = await verdict
                    if not verdict:
                        audit.record(
                            tool=tool_name, tier=tier.value, outcome="denied",
                            reason="approver refused", arguments=safe_args,
                        )
                        raise GateDenied(f"'{tool_name}' was refused by the approver.")

        async def run(arguments: dict[str, Any], call: Callable[[], Any]) -> Any:
            await enforce(arguments)
            safe_args = redact_arguments(arguments, policy.redact)
            start = time.perf_counter()
            try:
                result = call()
                if inspect.isawaitable(result):
                    result = await result
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

        # FastMCP injects its Context object as a regular parameter. It is
        # not a model-supplied argument, so it stays out of the audit trail
        # and out of what the approver sees.
        ctx_param = _find_context_parameter(fn)

        # functools.wraps preserves the signature (via __wrapped__), so
        # FastMCP still generates the tool's input schema from the real
        # function — the guard is invisible to schema generation.
        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            bound = inspect.signature(fn).bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            if ctx_param is not None:
                arguments.pop(ctx_param, None)
            return await run(arguments, lambda: fn(*args, **kwargs))

        return guarded


def _find_context_parameter(fn: Callable[..., Any]) -> str | None:
    """Name of the parameter FastMCP will inject its ``Context`` into."""
    try:
        from mcp.server.fastmcp import Context

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
