"""Ready-made approvers.

An approver is any callable that takes an :class:`ApprovalRequest` and
returns ``True`` to allow — these are the ones worth not rewriting.
"""

from __future__ import annotations

import sys
import threading

from .policy import ApprovalRequest

# Approvers run in worker threads, so two gated calls can ask at once.
# One prompt at a time, or the questions and answers interleave.
_tty_lock = threading.Lock()


def terminal_approver(request: ApprovalRequest) -> bool:
    """Ask whoever ran the server — on the controlling terminal, never stdio.

    Over the stdio transport, stdout/stdin ARE the JSON-RPC pipe; printing
    a prompt there would corrupt the protocol (which is why a plain
    ``input()`` approver is a trap). So the prompt goes to ``/dev/tty``.
    No terminal available (Windows, a container, a client that launched
    the server detached)? The gate fails closed.
    """
    try:
        with _tty_lock, open("/dev/tty", "r+") as tty:
            tty.write(
                f"\n⚠ approval needed → {request.tool} ({request.tier.value}) "
                f"{request.arguments}\nallow? [y/N] "
            )
            tty.flush()
            return tty.readline().strip().lower() == "y"
    except OSError:
        sys.stderr.write(
            f"mcp-gatehouse: no terminal for approval; "
            f"denying {request.tool} (fail closed)\n"
        )
        return False
