# Renders docs/tool-calls-demo.mp4 with VHS (https://github.com/charmbracelet/vhs):
#   vhs docs/tool-calls-demo.tape
# Run from the repo root with the package installed in .venv. The demo runs
# in a fresh temp dir so the audit log starts empty. The screen is cleared
# between sections: VHS's terminal stalls once output scrolls. Lines typed
# as "#> ..." are drawn by the client as highlighted callouts; at the shell
# prompt the hidden `note` function does the same.

Output docs/tool-calls-demo.mp4

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 1000
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `note() { printf '\033[1A\033[2K\033[1;33m\xe2\x96\xb6 %s\033[0m\n' "$*"; }; REPO=$PWD; cd "$(mktemp -d)"; cp "$REPO/docs/tool-calls-client.py" .; source "$REPO/.venv/bin/activate"; clear`
Enter
Sleep 500ms
Show

# --- screen 1: reads ---------------------------------------------------
Type "# mcp-gatehouse: an order desk where every tool call passes through the gate"
Enter
Sleep 1.5s
Type "python tool-calls-client.py"
Enter
Wait+Screen /gatehouse>/
Sleep 2s
Type "#> Tiers and honest annotations: read, write, destructive. The client is told the truth about each tool."
Enter
Sleep 3s
Type "#> Any agent framework: this is a plain MCP client over stdio. The gate lives in the server."
Enter
Sleep 3.5s

Type "list_orders"
Sleep 600ms
Enter
Wait+Screen /Tidewater Mill/
Sleep 1s
Type "#> Lists are filtered per item: the desk holds four orders. 4420 is someone else's, so the gate withheld it."
Enter
Sleep 4s

Type "lookup_order order_id=4417"
Sleep 600ms
Enter
Wait+Screen /notes: none/
Sleep 2s

Type "lookup_order order_id=4420"
Sleep 600ms
Enter
Wait+Screen /not permitted/
Sleep 1s
Type "#> Resource-level authorization: the gate loaded order 4420, the policy saw it isn't mine, the tool never ran."
Enter
Sleep 3.5s
Type "#> Listing isn't authorizing: lookup_order was in the tool list, and the call was still checked on the record."
Enter
Sleep 3.5s
Type "# not-found and forbidden read the same to the model; the audit log keeps the real reason."
Enter
Sleep 3.5s

# --- screen 2: writes and the approval ---------------------------------
Type "clear"
Enter
Sleep 800ms
Type `add_note order_id=4417 note="customer asked for a callback" api_key=sk-live-9f3a`
Sleep 600ms
Enter
Wait+Screen /note added/
Sleep 1s
Type "#> Defense in depth: a WRITE, conditional on the order's version. The api_key is masked before it reaches the log."
Enter
Sleep 4s

Type "cancel_order order_id=4419"
Sleep 600ms
Enter
Wait+Screen /has shipped/
Sleep 1s
Type "#> Enforced at the tool level, not in the prompt: the policy refused on the order itself. No instruction can change that."
Enter
Sleep 4s

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
Type "#> Approval gates, right by default: DESTRUCTIVE always asks a person. With nobody to ask, it is denied."
Enter
Sleep 3.5s
Type "#> Not the agent's instructions: the server sent the form, a person saw the record and the reason. The model can't answer it."
Enter
Sleep 3.5s
Type "#> Allowed isn't wanted: that person is the chance to spot an action nobody asked for."
Enter
Sleep 3.5s

Type "quit"
Enter
Sleep 1s

# --- screen 3: the audit log -------------------------------------------
Type "clear"
Enter
Sleep 500ms
Type "# every call, allowed or not, is on the record"
Enter
Sleep 1s
Type "jq -c '{tool, outcome, reason, authz, withheld, caller: .caller.subject, arguments}' audit.jsonl"
Enter
Wait+Screen /redacted/
Sleep 2s
Type `note "Audit: what did the AI do, and for whom. The real reason for every refusal, the caller on every line."`
Enter
Sleep 3s
Type `note "Delegated identity: over stdio the server declared the caller. Over HTTP it comes from the verified token."`
Enter
Sleep 7s
