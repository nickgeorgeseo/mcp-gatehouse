"""Ready-made approvers.

An approver is any callable that takes an :class:`ApprovalRequest` and
returns ``True`` to allow — these are the ones worth not rewriting.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import select
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal, TextIO

from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
)
from mcp.server.elicitation import render_elicitation_schema
from mcp_types.version import is_version_at_least
from pydantic import BaseModel, Field, ValidationError

from .policy import ApprovalRequest, Approver, Caller

# Approvers run in worker threads, so two gated calls can ask at once.
# One prompt at a time, or the questions and answers interleave.
_tty_lock = threading.Lock()


def terminal_approver(request: ApprovalRequest) -> bool:
    """Ask whoever ran the server — on the controlling terminal, never stdio.

    Over the stdio transport, stdout/stdin ARE the JSON-RPC pipe; printing
    a prompt there would corrupt the protocol (which is why a plain
    ``input()`` approver is a trap). So the prompt goes to ``/dev/tty``.

    When it can't ask properly, the gate fails closed. That covers no
    terminal (Windows, a container, a client that launched the server
    detached, as the MCP Python SDK's stdio client does even when it runs
    in a terminal); a terminal held in raw mode by a full-screen program, such
    as an MCP client's own UI, where a prompt would garble the screen and
    fight it for keystrokes; and no answer by ``request.deadline``, which
    ``Policy.approval_timeout`` sets.
    """
    left = _seconds_left(request)
    if not _tty_lock.acquire(timeout=-1 if left is None else left):
        return False  # another prompt held the terminal past our deadline
    try:
        # Unbuffered, as getpass does it. Text-mode "r+" wraps the file in
        # BufferedRandom, which insists on a seekable file; a terminal isn't
        # one, so that open always raised.
        with io.TextIOWrapper(open("/dev/tty", "r+b", buffering=0)) as tty:
            if not _in_line_mode(tty):
                _report_denial(request, "the terminal is in use by a full-screen program")
                return False
            tty.write(
                f"\n⚠ approval needed → {request.tool} ({request.tier.value}) "
                f"{request.arguments}{_for_whom(request.caller)}\nallow? [y/N] "
            )
            tty.flush()
            left = _seconds_left(request)
            if left is not None:
                # In line mode the terminal only reads as ready once a whole
                # line is in, so a half-typed answer doesn't end the wait.
                answered, _, _ = select.select([tty], [], [], left)
                if not answered:
                    tty.write("\n(timed out, denied)\n")
                    tty.flush()
                    return False
            return tty.readline().strip().lower() == "y"
    except OSError:
        _report_denial(request, _no_terminal_reason())
        return False
    finally:
        _tty_lock.release()


def _for_whom(caller: Caller | None) -> str:
    """The prompt's "for whom" line, or nothing when no one signed in (stdio)."""
    if caller is None:
        return ""
    # repr, as the arguments get: these strings come from a token, and a
    # control character in one must not get to redraw the prompt.
    user = "a user the token doesn't name" if caller.subject is None else repr(caller.subject)
    return f"\n  for {user} via client {caller.client_id!r}"


def _seconds_left(request: ApprovalRequest) -> float | None:
    if request.deadline is None:
        return None
    return max(0.0, request.deadline - time.monotonic())


def _in_line_mode(tty: TextIO) -> bool:
    """Is the terminal in ordinary line-by-line (canonical) mode?

    Full-screen programs, including MCP clients with a terminal UI, switch
    it to raw mode and read every keystroke themselves. A server they
    launched can still open their terminal, but a prompt there would draw
    over their screen and race them for input. And in raw mode Enter sends
    ``\\r``, not ``\\n``, so the answer would never complete a line.
    """
    import termios  # Unix only; /dev/tty never opens on Windows, so never reached there

    try:
        return bool(termios.tcgetattr(tty.fileno())[3] & termios.ICANON)
    except termios.error:
        return False


def _no_terminal_reason() -> str:
    """Why /dev/tty wouldn't open, as far as the server can tell.

    The surprising case: stderr is a terminal, so the client runs in one,
    but the server has no controlling terminal. The client started it in a
    session of its own, which is what the MCP Python SDK's stdio client
    does (``start_new_session=True``). A process outside the terminal's
    session can't open /dev/tty, so there is nowhere to ask.
    """
    if sys.platform != "win32" and os.isatty(2):
        return (
            "no controlling terminal (the client likely started the server in a session "
            "of its own, as the MCP Python SDK's stdio client does)"
        )
    return "no terminal for approval"


def _report_denial(request: ApprovalRequest, why: str) -> None:
    sys.stderr.write(f"mcp-gatehouse: {why}; denying {request.tool} (fail closed)\n")


# --- approval in the client's own UI ---------------------------------------

# The first protocol revision with no server-to-client back-channel: from it
# on, a question to the user travels in the tool's result instead.
_ROUND_TRIP_VERSION = "2026-07-28"

# The key the gate's question is filed under in `input_requests`.
_INPUT_KEY = "mcp-gatehouse/approval"

# How long an asked-for approval stays answerable when the policy sets no
# timeout. The SDK's own request-state lifetime (ten minutes unless
# configured) usually ends it sooner.
_MAX_APPROVAL_AGE = 3600.0

Transport = Literal["back-channel", "round-trip"]


class _ApprovalForm(BaseModel):
    """The form the client shows. One required box, nothing pre-ticked, so
    a client that accepts forms unseen still can't approve by accident."""

    approve: bool = Field(
        title="Approve",
        description="Tick to let this call run. Leave it unticked, decline, or cancel to refuse.",
    )


def _default_message(request: ApprovalRequest) -> str:
    # Two lines, arguments on the second. Clients show only the start of a
    # long message (Claude Code folds it after three lines), and what is
    # being approved must never be in the folded part.
    arguments = json.dumps(request.arguments, ensure_ascii=False, default=str)
    return f"The AI wants to run {request.tool} ({request.tier.value}) with:\n{arguments}"


class ElicitationApprover:
    """Ask the person using the MCP client, in the client's own UI.

    MCP calls this elicitation: the server sends the client a small form
    and the client shows it to its user. The model can't answer it. Claude
    Code, Cursor and VS Code support it, and it needs no terminal, Slack or
    anything else running beside the server::

        Policy(approver=ElicitationApprover(fallback=terminal_approver))

    The gate picks the transport from the negotiated protocol. Up to
    2025-11-25 it sends the form mid-call and waits, under
    ``Policy.approval_timeout`` like any approver. From 2026-07-28 there
    is no channel for that, so the call returns the question to the client
    and runs when the client calls again with the answer. That second
    round is checked before anything runs: the SDK seals the gate's state
    and binds it to the tool and its exact arguments, the answer must be
    to the question asked, within ``approval_timeout`` (an hour when none
    is set), and each approval runs its call once. Single use is tracked
    per process.

    When the client can't be asked (it declares no form elicitation, or
    the tool runs its own multi-round flow), ``fallback`` decides. With no
    fallback, the call is denied: the gate fails closed.

    Elicitation trusts the client to put the form in front of a person.
    A client set to accept forms on its own, or a hook that does, can
    approve too. When the approver must sit outside the client, use an
    out-of-band one (Slack, a ticket) instead.
    """

    def __init__(
        self,
        fallback: Approver | None = None,
        *,
        message: Callable[[ApprovalRequest], str] | None = None,
    ) -> None:
        self.fallback = fallback
        """Decides when the client can't be asked; ``None`` denies."""
        self._message = message or _default_message
        self._used_lock = threading.Lock()
        self._used: dict[str, float] = {}  # nonce → when its approval expires

    def __call__(self, request: ApprovalRequest) -> bool | Awaitable[bool]:
        """Decide with no client to ask: the fallback's answer, or a refusal.

        The gate asks the client itself and calls this only when it can't.
        """
        return False if self.fallback is None else self.fallback(request)

    def transport(self, context: Any, *, round_trip: bool) -> Transport | None:
        """How this call's client can be asked, or ``None`` if it can't.

        ``round_trip`` is whether the tool leaves the multi-round channel
        free for the gate; one that resolves or returns its own
        ``InputRequiredResult`` doesn't.
        """
        try:
            capabilities = context.client_capabilities
            version = context.protocol_version
            can_send = context.session.can_send_request
        except Exception:
            # No live request behind this Context (a direct MCPServer.call_tool).
            return None
        elicitation = capabilities.elicitation if capabilities is not None else None
        # A bare `elicitation: {}` predates modes and means form; url-only doesn't.
        if elicitation is None or (elicitation.form is None and elicitation.url is not None):
            return None
        if version is None:
            return None
        if is_version_at_least(version, _ROUND_TRIP_VERSION):
            return "round-trip" if round_trip else None
        return "back-channel" if can_send else None

    async def ask(self, request: ApprovalRequest, context: Any) -> bool:
        """Back-channel: send the form mid-call and wait for the answer."""
        result = await context.elicit(self._message(request), _ApprovalForm)
        return result.action == "accept" and result.data.approve

    def question(self, request: ApprovalRequest, timeout: float | None) -> InputRequiredResult:
        """Round trip, first round: hand the question back to the client."""
        message = self._message(request)
        age = _MAX_APPROVAL_AGE if timeout is None else timeout
        state = {
            "v": 1,
            "q": _digest(message),
            "nonce": secrets.token_urlsafe(16),
            "exp": time.time() + age,
        }
        form = ElicitRequest(
            params=ElicitRequestFormParams(
                message=message,
                requested_schema=render_elicitation_schema(_ApprovalForm),
            )
        )
        return InputRequiredResult(
            input_requests={_INPUT_KEY: form}, request_state=json.dumps(state)
        )

    def answer(self, request: ApprovalRequest, context: Any) -> tuple[bool, str] | None:
        """Round trip, later round: read the client's answer.

        Returns ``None`` when there is nothing to read — first round, or an
        answer to some other question — so the gate asks (again). Otherwise
        ``(allowed, reason)``, the reason saying why not.
        """
        try:
            state = json.loads(context.request_state or "")
            nonce, expires, asked = state["nonce"], float(state["exp"]), state["q"]
            if state["v"] != 1 or not isinstance(nonce, str):
                return None
        except (ValueError, TypeError, KeyError):
            return None
        reply = (context.input_responses or {}).get(_INPUT_KEY)
        if reply is None or asked != _digest(self._message(request)):
            return None
        if not time.time() < expires:
            return False, "approval timed out"
        if not self._spend(nonce, expires):
            return False, "approval already used"
        if not isinstance(reply, ElicitResult):
            return False, "approver error: not an elicitation answer"
        if reply.action != "accept":
            return False, "approver refused"
        try:
            form = _ApprovalForm.model_validate(reply.content or {})
        except ValidationError:
            return False, "approver error: invalid approval form"
        return (True, "") if form.approve else (False, "approver refused")

    def _spend(self, nonce: str, expires: float) -> bool:
        """Mark one approval used. ``False`` if it already was."""
        now = time.time()
        with self._used_lock:
            # Past its expiry a nonce is refused before it gets here, so the
            # record of it can go.
            for old in [n for n, exp in self._used.items() if exp <= now]:
                del self._used[old]
            if nonce in self._used:
                return False
            self._used[nonce] = expires
            return True


def _digest(message: str) -> str:
    return hashlib.sha256(message.encode("utf-8", "surrogatepass")).hexdigest()
