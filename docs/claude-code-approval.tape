# Renders docs/claude-code-approval.gif with VHS: the demo server's approval
# form in Claude Code's own UI, a cancel on someone else's order refused by
# policy, then the audit log. Needs the `claude` CLI signed in, and spends
# two short turns on your account. Run from the repo root with the package
# installed in .venv:
#   vhs docs/claude-code-approval.tape
# The demo server is loaded from $GATEHOUSE_REPO (else the current
# directory) and Claude Code starts in $GATEHOUSE_CWD (else the current
# directory), which must be a folder it already trusts. Variables from a
# parent Claude Code session are unset so the recording is a plain one.
# VHS stops rendering if output scrolls past the last row, so the terminal
# is tall enough for the whole session and the log screen starts cleared.

Output docs/claude-code-approval.gif

Set Shell bash
Set FontSize 20
Set Width 1320
Set Height 900
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type `REPO=${GATEHOUSE_REPO:-$PWD}; CFG=$(mktemp -d)/mcp.json; printf '{"mcpServers":{"order-desk":{"command":"%s/.venv/bin/python","args":["-m","mcp_gatehouse.demo","--audit-log","/tmp/audit.jsonl"]}}}' "$REPO" > "$CFG"; rm -f /tmp/audit.jsonl; unset $(compgen -v | grep "^CLAUDE"); cd "${GATEHOUSE_CWD:-$PWD}"; claude() { command claude --mcp-config "$CFG" --strict-mcp-config --permission-mode auto --allowedTools mcp__order-desk "$@"; }; clear`
Enter
Sleep 500ms
Show

Type "claude"
Enter
Wait+Screen@90s /for agents|Try "/
Sleep 1.5s
Type "Cancel order 4418 on the order desk."
Enter

# The gate's form: who the call is for, the arguments, and the order as the
# server loaded it. Space ticks the box, Enter moves to Accept, Enter accepts.
Wait+Screen@180s /requests your input/
Sleep 5s
Space
Sleep 1.5s
Enter
Sleep 1s
Enter
Wait+Screen@180s /[Cc]ancelled/
Sleep 3s

# Order 4420 belongs to someone else: the policy denies it, and no form appears.
Type "Now cancel order 4420."
Enter
Wait+Screen@180s /not permitted|someone else|belongs to/
Sleep 5s

Type "/exit"
Enter
Sleep 3s
Type "clear"
Enter
Sleep 500ms
Type "jq -c '{tool, who: .caller.subject, outcome, why: .reason}' /tmp/audit.jsonl"
Enter
Wait+Screen /"ok"/
Sleep 6s
