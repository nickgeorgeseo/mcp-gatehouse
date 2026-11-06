# Renders docs/gated-tool-demo.mp4 with VHS: a gated tool written out line by
# line with its explanation, then run.
#   vhs docs/gated-tool-demo.tape
# Run from the repo root with the package installed in .venv. The screen is
# cleared between sections: VHS's terminal stalls once output scrolls.

Output docs/gated-tool-demo.mp4

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 1000
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `note() { printf '\033[1A\033[2K\033[1;33m\xe2\x96\xb6 %s\033[0m\n' "$*"; }; REPO=$PWD; cd "$(mktemp -d)"; cp "$REPO/docs/tool-calls-client.py" "$REPO/docs/typewriter.py" "$REPO/examples/gated_tool.py" .; source "$REPO/.venv/bin/activate"; clear`
Enter
Sleep 500ms
Show

# --- write the server, section by section ------------------------------
Type "# mcp-gatehouse: one gated tool, written out line by line"
Enter
Sleep 2s
Type "python typewriter.py gated_tool.py"
Enter
Wait+Screen@400s /written to gated_tool.py/
Sleep 2s

# --- run it --------------------------------------------------------------
Type "clear"
Enter
Sleep 500ms
Type "# now run it, and call the two tools"
Enter
Sleep 1.5s
Type `python tool-calls-client.py --server "python gated_tool.py"`
Enter
Wait+Screen /gatehouse>/
Sleep 3s

Type "lookup_order order_id=4417"
Sleep 600ms
Enter
Wait+Screen /is packed/
Sleep 2s

Type "lookup_order order_id=4420"
Sleep 600ms
Enter
Wait+Screen /not permitted/
Sleep 1s
Type "#> Resource-level: dana's order. The gate loaded it, owner_only said Deny, the tool never ran."
Enter
Sleep 3.5s

Type "cancel_order order_id=4417"
Sleep 600ms
Enter
Wait+Screen /Approve\?/
Sleep 3.5s
Type "y"
Sleep 800ms
Enter
Wait+Screen /4417 cancelled/
Sleep 1s
Type "#> Approval by default: the server sent the client a form, and a person saw the record before it ran."
Enter
Sleep 3.5s

Type "lookup_order order_id=4417"
Sleep 600ms
Enter
Wait+Screen /is cancelled/
Sleep 2.5s

Type "quit"
Enter
Sleep 1s

# --- the audit log ------------------------------------------------------
Type "clear"
Enter
Sleep 500ms
Type "# and what the log says about it"
Enter
Sleep 1s
Type "jq -c '{tool, outcome, reason, authz, consistency, caller: .caller.subject}' audit.jsonl"
Enter
Wait+Screen /conditional/
Sleep 2s
Type `note "Audit: every call, the policy's decision, the real reason, and who it was for."`
Enter
Sleep 6s
