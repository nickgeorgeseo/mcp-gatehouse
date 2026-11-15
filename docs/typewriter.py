"""Type a Python file onto the terminal, section by section, for a recording.

Comment lines are the narration: they appear fast, in their own colour, right
before the code they explain. Lines starting with ``# ---`` begin a new
section: the screen is cleared and the rest of the line becomes its heading.
Lines starting with ``#>`` are callouts (a requirement being shown): drawn
bold with a marker, and left out of the file that is written at the end.
Code is typed character by character, syntax-highlighted. At the end the
file, minus the callouts, is written to the working directory so it can run.

    python docs/typewriter.py examples/gated_tool.py
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

from pygments import highlight
from pygments.formatters import TerminalTrueColorFormatter
from pygments.lexers import PythonLexer

BOLD, DIM, YELLOW, RESET = "\033[1m", "\033[2m", "\033[38;2;249;226;175m", "\033[0m"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
LEXER = PythonLexer(ensurenl=False)
FORMATTER = TerminalTrueColorFormatter(style="dracula")


def typed(text: str, delay: float) -> None:
    """Write ``text`` one visible character at a time; escape codes go at once."""
    pos = 0
    for match in ANSI.finditer(text):
        for ch in text[pos : match.start()]:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(delay)
        sys.stdout.write(match.group())
        pos = match.end()
    for ch in text[pos:]:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--code-delay", type=float, default=0.028)
    parser.add_argument("--comment-delay", type=float, default=0.011)
    parser.add_argument("--pause", type=float, default=3.0, help="seconds to hold each finished section")
    parser.add_argument("--copy-to", default=".", help="where to put the finished file")
    args = parser.parse_args()

    lines = Path(args.source).read_text().splitlines()
    sections = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# ---"):
            if sections:
                time.sleep(args.pause)
            sections += 1
            sys.stdout.write("\033[2J\033[H")
            typed(f"{BOLD}{stripped.lstrip('# -')}{RESET}\n\n", args.comment_delay)
            time.sleep(0.6)
        elif stripped.startswith("#>"):
            indent = line[: len(line) - len(line.lstrip())]
            typed(f"{indent}{BOLD}{YELLOW}▶ {stripped[2:].strip()}{RESET}\n", args.comment_delay)
            time.sleep(1.4)
        elif stripped.startswith("#"):
            indent = line[: len(line) - len(line.lstrip())]
            typed(f"{indent}{YELLOW}{stripped}{RESET}\n", args.comment_delay)
            time.sleep(0.9)
        elif not stripped:
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            typed(highlight(line, LEXER, FORMATTER) + "\n", args.code_delay)
            time.sleep(0.25)
    time.sleep(args.pause)
    target = Path(args.copy_to) / Path(args.source).name
    kept = [line for line in lines if not line.strip().startswith("#>")]
    target.write_text("\n".join(kept) + "\n")
    sys.stdout.write(f"\n{DIM}written to {target.name}{RESET}\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
