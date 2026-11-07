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
Type `note() { local msg="$*"; local cols; cols=$(stty size 2>/dev/null | cut -d" " -f2); cols=${cols:-${COLUMNS:-143}}; local rows=$(( (${#msg} + 18 + cols - 1) / cols )); printf '\033[%dA\033[J\033[1;33m\xe2\x96\xb6 %s\033[0m\n' "$rows" "$msg"; }; REPO=$PWD; cd "$(mktemp -d)"; cp "$REPO/docs/tool-calls-client.py" "$REPO/docs/audit-line.schema.json" .; source "$REPO/.venv/bin/activate"; clear`
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
Sleep 4s

# --- screen 4: the record's shape, and where it goes --------------------
Type "clear"
Enter
Sleep 500ms
Type "# the trail has a documented shape, so a SIEM can rely on it"
Enter
Sleep 1s
Type `python -c 'import json, jsonschema; schema = json.load(open("audit-line.schema.json")); lines = [json.loads(l) for l in open("audit.jsonl")]; [jsonschema.validate(line, schema) for line in lines]; print(len(lines), "audit lines, every one matches docs/audit-line.schema.json")'`
Enter
Wait+Screen /every one matches/
Sleep 1s
Type `note "Audit sinks: AuditLog(sink=...) hands the same record to OpenTelemetry or your log pipeline. examples/audit_otel.py"`
Enter
Sleep 4s
Type `note "Approvals across replicas: ElicitationApprover(store=...) shares used approvals. examples/approval_store_sqlite.py"`
Enter
Sleep 4s

# --- screen 5: where it sits -------------------------------------------
Type "clear"
Enter
Sleep 500ms
Type "# where the gate sits"
Enter
Sleep 1s
Type `note "Agent-framework approvals live beside the model. They see the tool name and the arguments the model proposed."`
Enter
Sleep 3.5s
Type `note "Gateways and policy services sit in front of the server. They see the token, the tool name and the arguments."`
Enter
Sleep 3.5s
Type `note "The gate is the check inside the server, on the loaded record, for the verified caller. The one layer that makes the check mandatory."`
Enter
Sleep 4s
Type `note "A central policy engine? examples/policy_opa.py and policy_cerbos.py send it the caller and the record. Unreachable is a Deny."`
Enter
Sleep 4s
Type `note "What it trusts: the token verifier, and the client showing the form to a person. If that isn't acceptable, an out-of-band approver."`
Enter
Sleep 8s
