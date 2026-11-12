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
from typing import Any, Literal, Protocol, TextIO, runtime_checkable

from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
)
from mcp.server.elicitation import render_elicitation_schema
from mcp_types.version import is_version_at_least
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
                f"{request.arguments}{_on_what(request)}{_for_whom(request.caller)}\nallow? [y/N] "
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


def _on_what(request: ApprovalRequest) -> str:
    """The prompt's lines for the records the call acts on and why it was
    asked, or nothing. Shown as single lines, so a record can't redraw the
    prompt."""
    lines = ""
    if request.resources:
        lines += "\n  on " + " | ".join(_one_line(line) for line in request.resources)
    if request.reason:
        lines += "\n  asked because: " + _one_line(request.reason)
    return lines


def _one_line(text: str, limit: int = 200) -> str:
    """``text`` on one line: line breaks, control and format characters
    (bidi overrides among them) escaped, cut at ``limit``."""
    shown = "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in str(text))
    return shown[:limit] + "…" if len(shown) > limit else shown


def _for_whom(caller: Caller | None) -> str:
    """The prompt's "for whom" line, or nothing when no one signed in (stdio)."""
    if caller is None:
        return ""
    user = "a user the token doesn't name" if caller.subject is None else _shown(caller.subject)
    return f"\n  for {user} via client {_shown(caller.client_id)}"


# Long enough for an email address or a URL-shaped client ID; a name past
# it is cut rather than allowed to push the rest of the prompt off screen.
_NAME_LIMIT = 80


def _shown(name: str) -> str:
    """A name from a token, quoted so it can only ever read as itself.

    JSON-quoted with everything outside printable ASCII escaped: no control
    sequence can redraw the prompt, a quote in the name can't close the
    quoting early and fake the rest of the line, and a look-alike or blank
    Unicode character shows up as an escape instead of passing for a letter.
    """
    quoted = json.dumps(name[:_NAME_LIMIT], ensure_ascii=True).replace("\x7f", "\\u007f")
    return quoted + "…" if len(name) > _NAME_LIMIT else quoted


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


@runtime_checkable
class ApprovalStore(Protocol):
    """Where used approvals are remembered, so each one runs its call once.

    ``spend(nonce, expires)`` marks the approval ``nonce`` used and returns
    ``True``, or returns ``False`` if it already was. ``expires`` is the
    ``time.time()`` after which the nonce can be forgotten: past it, the
    gate refuses the approval before asking the store. A store that raises
    denies the call, logged as ``approval store error: <ExceptionType>``.

    :class:`MemoryApprovalStore` is the default and remembers per process.
    That is enough while the server's request-state key is per process
    too, which is the MCP SDK's default: an approval minted before a
    restart or by another replica fails the SDK's own check first. A
    server that shares that key (``MCPServer(request_state_security=
    RequestStateSecurity(keys=[...]))``) so approvals survive a restart
    or work across replicas needs a store they all share, such as the
    SQLite one in ``examples/approval_store_sqlite.py``.
    """

    def spend(self, nonce: str, expires: float) -> bool: ...


class MemoryApprovalStore:
    """Used approvals, remembered in this process. The default."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: dict[str, float] = {}  # nonce → when its approval expires

    def spend(self, nonce: str, expires: float) -> bool:
        now = time.time()
        with self._lock:
            # Past its expiry a nonce is refused before it gets here, so the
            # record of it can go.
            for old in [n for n, exp in self._used.items() if exp <= now]:
                del self._used[old]
            if nonce in self._used:
                return False
            self._used[nonce] = expires
            return True


# One required box, nothing pre-ticked, so a client that accepts forms unseen
# still can't approve by accident. The docstring is the schema's description
# and the title its name: both reach the person, so they read as the form.
class _ApprovalForm(BaseModel):
    """Tick Approve to let this call run. Leave it, decline or cancel to refuse."""

    model_config = ConfigDict(title="Approval")

    approve: bool = Field(
        title="Approve",
        description="Tick to let this call run. Leave it unticked, decline, or cancel to refuse.",
    )


def _default_message(request: ApprovalRequest) -> str:
    # The tool (and why it was asked, and for whom), its arguments, and the
    # records it acts on, one per line. Clients show only the start of a
    # long message (Claude Code folds it after three lines), so what is
    # being approved comes first: the first three lines carry the tool, the
    # arguments and the first record.
    arguments = json.dumps(request.arguments, ensure_ascii=False, default=str)
    head = f"The AI wants to run {request.tool} ({request.tier.value}){_who(request.caller)} with:"
    if request.reason:
        head = f"Approval needed ({_one_line(request.reason, 120)}). {head}"
    lines = [head, arguments]
    lines.extend("on " + _one_line(line) for line in request.resources)
    return "\n".join(lines)


def _who(caller: Caller | None) -> str:
    """" for whom" in the form's first line, or nothing when no one signed in."""
    if caller is None:
        return ""
    user = "a user the token doesn't name" if caller.subject is None else _shown(caller.subject)
    return f" for {user} via client {_shown(caller.client_id)}"


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
    is set), and each approval runs its call once. Used approvals are
    remembered in ``store``, per process by default; see
    :class:`ApprovalStore` for when replicas need to share one.

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
        store: ApprovalStore | None = None,
    ) -> None:
        self.fallback = fallback
        """Decides when the client can't be asked; ``None`` denies."""
        self._message = message or _default_message
        if store is not None and not callable(getattr(store, "spend", None)):
            raise TypeError("store must have a spend(nonce, expires) method")
        self.store: ApprovalStore = store if store is not None else MemoryApprovalStore()
        """Where used approvals are remembered."""

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
            "v": 2,
            "q": _digest(message, request.binding),
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
            if state["v"] != 2 or not isinstance(nonce, str):
                return None
        except (ValueError, TypeError, KeyError):
            return None
        reply = (context.input_responses or {}).get(_INPUT_KEY)
        if reply is None or asked != _digest(self._message(request), request.binding):
            return None
        if not time.time() < expires:
            return False, "approval timed out"
        try:
            spent = self.store.spend(nonce, expires)
        except Exception as exc:
            # The store is the single-use guarantee. Without its answer the
            # gate can't tell a first use from a replay, so it refuses. Type
            # only, as with every other error in the trail.
            return False, f"approval store error: {type(exc).__name__}"
        if spent is not True:
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


def _digest(message: str, binding: str | None) -> str:
    """The question asked, bound to the state it was asked about.

    The binding (caller, reason, a fingerprint of each record) is part of
    the digest whatever the message says, so a custom ``message=`` that
    leaves the record out still can't carry an answer over to a record
    that changed."""
    text = message + "\0" + (binding or "")
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
