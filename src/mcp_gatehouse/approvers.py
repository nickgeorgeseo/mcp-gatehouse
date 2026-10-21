"""Ready-made approvers.

An approver is any callable that takes an :class:`ApprovalRequest` and
returns ``True`` to allow — these are the ones worth not rewriting.
"""

from __future__ import annotations

import io
import select
import sys
import threading
import time
from typing import TextIO

from .policy import ApprovalRequest

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
    detached); a terminal held in raw mode by a full-screen program, such
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
                f"{request.arguments}\nallow? [y/N] "
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
        _report_denial(request, "no terminal for approval")
        return False
    finally:
        _tty_lock.release()


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


def _report_denial(request: ApprovalRequest, why: str) -> None:
    sys.stderr.write(f"mcp-gatehouse: {why}; denying {request.tool} (fail closed)\n")
