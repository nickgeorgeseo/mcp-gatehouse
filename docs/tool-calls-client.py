"""A tiny interactive MCP client for the demo video.

It starts ``mcp-gatehouse-demo`` over stdio, lists its tools, and lets you
type tool calls one per line::

    gatehouse> lookup_order order_id=4417

Approvals arrive as MCP elicitation, the same form Claude Code, Cursor and
VS Code show; this client prints it and asks for y/N. Run it with the
package installed: ``python docs/tool-calls-client.py [--audit-log PATH]``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import shlex
import shutil
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import ElicitRequestParams, ElicitResult, TextContent

DIM, BOLD, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[2m", "\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m",
)
PROMPT = "gatehouse> "


def callout(line: str) -> None:
    """Redraw a typed comment as a highlighted note. ``#>`` marks a requirement
    being demonstrated; a plain ``#`` is narration."""
    rows = math.ceil((len(PROMPT) + len(line)) / max(shutil.get_terminal_size().columns, 20))
    sys.stdout.write(f"\033[{rows}A\033[J")  # back over the echoed line, clear it
    if line.startswith("#>"):
        print(f"{BOLD}{YELLOW}▶ {line[2:].strip()}{RESET}")
    else:
        print(f"{YELLOW}{line[1:].strip()}{RESET}")


def tier_of(tool) -> str:
    a = tool.annotations
    if a is None:
        return "?"
    if a.destructive_hint:
        return f"{RED}destructive{RESET}"
    if a.read_only_hint:
        return f"{GREEN}read{RESET}"
    return f"{YELLOW}write{RESET}"


def parse(line: str) -> tuple[str, dict[str, str]]:
    name, *rest = shlex.split(line)
    args: dict[str, str] = {}
    for item in rest:
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"expected key=value, got {item!r}")
        args[key] = value
    return name, args


def show(result) -> None:
    mark = f"{RED}✗{RESET}" if result.is_error else f"{GREEN}✓{RESET}"
    for block in result.content:
        if isinstance(block, TextContent):
            text = block.text
            try:
                text = json.dumps(json.loads(text))  # one record per line
            except ValueError:
                pass
            print(f"{mark} {text}")


async def approve_in_terminal(context, params: ElicitRequestParams) -> ElicitResult:
    """The approval form, shown here instead of in a GUI. Only a 'y' ticks the box."""
    message = getattr(params, "message", "")
    print(f"\n{YELLOW}⚠ approval form from the server{RESET}")
    for line in message.splitlines():
        print(f"{YELLOW}│{RESET} {line}")
    loop = asyncio.get_running_loop()
    answer = await loop.run_in_executor(None, input, f"{YELLOW}└ Approve? [y/N]{RESET} ")
    if answer.strip().lower() == "y":
        return ElicitResult(action="accept", content={"approve": True})
    return ElicitResult(action="decline")


async def repl(audit_log: str, command: list[str]) -> None:
    if command == ["mcp-gatehouse-demo"]:
        command = [*command, "--audit-log", audit_log]
    server = StdioServerParameters(command=command[0], args=command[1:])
    # The server's own stderr (SDK logging) stays out of the way; approvals go
    # to /dev/tty, so they still show up here.
    quiet = open(os.devnull, "w")
    async with stdio_client(server, errlog=quiet) as (read, write), ClientSession(
        read, write, elicitation_callback=approve_in_terminal
    ) as session:
        init = await session.initialize()
        info = init.server_info
        print(f"{BOLD}connected to {info.name} {info.version}{RESET} (stdio) · audit log → {audit_log}")
        tools = (await session.list_tools()).tools
        print(f"{DIM}tools the gate exposes:{RESET}")
        for tool in tools:
            first = " ".join((tool.description or "").split(".")[0].split())
            if len(first) > 64:
                first = first[:63].rstrip(",: ") + "…"
            print(f"  {CYAN}{tool.name:<14}{RESET} {tier_of(tool):<22} {DIM}{first}{RESET}")
        print()
        loop = asyncio.get_running_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, input, f"{BOLD}{PROMPT.strip()}{RESET} ")
            except EOFError:
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                callout(line)
                continue
            if line in {"quit", "exit"}:
                break
            if line == "clear":
                print("\033[2J\033[H", end="", flush=True)
                continue
            try:
                name, args = parse(line)
            except ValueError as exc:
                print(f"{RED}✗ {exc}{RESET}")
                continue
            result = await session.call_tool(name, args)
            show(result)
            print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--audit-log", default="audit.jsonl", help="passed to the demo server")
    parser.add_argument(
        "--server", default="mcp-gatehouse-demo", help="command that starts the server over stdio"
    )
    args = parser.parse_args()
    try:
        asyncio.run(repl(args.audit_log, shlex.split(args.server)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
