# Using the MCP server

The toolkit has two shells over one core: a CLI (`ozpb`) and an MCP server
(`ozpb-mcp-server`). `docs/DEVELOPERS.md` covers the CLI and
`scripts/demo-tranche1.sh` runs the whole pipeline against testnet. This is about the **MCP**
shell: how you actually use it, and — at the back, for when you need it — how to speak to it
directly.

Nothing here holds a key or deploys anything.

---

## 1. Use the server and skill with Claude Code

```bash
cargo build -r -p ozpb-mcp-server
```

For the guided flow, run `claude --plugin-dir .` from this checkout and invoke
`/oz-policy-builder:policy-builder`. The plugin bundles the skill and an MCP server entry.
For direct tool use, the repository's `.mcp.json` also points at
`scripts/mcp-server-dev.sh`. The wrapper refreshes plugin builds in Claude's persistent
plugin data directory and starts the server with development registry trust configured;
without trust roots, `synthesize_policy` refuses. It also configures one RPC source, named
`testnet`, for the tools that read through an operator source: SDF's public testnet RPC, or
another `https://` endpoint named in `OZPB_DEV_TESTNET_RPC_URL`. The network is fixed to
testnet, and any `OZPB_RPC_SOURCES_JSON` already in the environment is replaced. Those tools
therefore read live testnet state by default, and what a request carries reaches that endpoint.

**The trust that wrapper installs is the committed development pair, and it is not a production
configuration.** `docs/examples/registry-roots.json` is a key this repository publishes, so
anything it admits is signed by a key anyone can sign with. That is the right trade for a local
session and for the demo, and the wrong one for a deployment: a hosted server sets
`OZPB_REGISTRY_ROOTS_JSON` and `OZPB_REGISTRY_MIN_VERSION` to roots it controls, which is what
makes a request unable to bring its own. See `docs/DEVELOPERS.md`.

**You never start the server yourself, and there is no daemon to connect to.** A stdio MCP
server is launched *by the client*, as a child process, once per session, and it exits when
the session ends. That is the design: one process inside your own trust domain, no port, no
listener, nothing left running. If you are looking for something to `curl`, see §5 — and
that is the hosted shape, not the local one.

So the demo is a conversation. Ask for what you want:

> Record what authorization a transfer from `C…` to `G…` would need on testnet, then
> synthesize a minimum-permission policy for it and generate the crate.

The agent composes the tool calls and you watch it work — while it still holds no key and
deploys nothing. That is the point of shipping an MCP server rather than only a CLI: the
person who needs a scoped policy does not have to know the pipeline exists.

### The one command to show it works

If all you want is to demonstrate that the server is live and doing real work, this is
enough — one sentence, no tool names, no file paths:

> Record Stellar testnet transaction `<hash>` for me and tell me what authorization it
> required.

The agent picks `record_transaction`, which reads through the server's configured RPC source
(`testnet` under `scripts/mcp-server-dev.sh`), and you get back the authorization tree, the observed
code hash of every contract involved, and the evidence trust level. That is the recording
layer — RFP requirement #1 — answering from a hash you can paste from an explorer.

The hash has to be recent: RPC retention drops transactions after a few days, and an expired
one comes back as `E_RETENTION_EXPIRED` rather than a guess. If you have no hash to hand, run
`bash scripts/demo-tranche1.sh` and use the account it prints, or ask for the *simulated*
path instead — "what would a transfer of 1 XLM from `C…` to `G…` require?" — which needs no
hash and no signature.

**Going further than one command is better done with the skill.** The flow needs decisions
only you can make — how long the grant lives, a call cap, a spend limit, which signer.
The skill asks for them and guides the available record, synthesize, reference, generate,
and verify tools, with optional exact-envelope preflight, then shows a confirmation card and
stops. When policies are already deployed it can also run the advisory authority check,
install intent and dry-run preparation; otherwise the authority check comes in the handoff,
before assembly. It never deploys, signs or installs (§4.7).

### Confirm, then hand off

Before anything leaves the conversation, the skill shows a **Confirm before deploy** card built
from tool outputs: what the grant permits and what it leaves unconstrained, every high-blast-
radius choice (an `any_value` argument, including one an adapter derives for a caller-chosen
deadline, a `high` widening, no expiry, no cap), the signer, expiry, cap and policies, the build
verdict and target code identity, all four dry-run layers with their status, and the authority
list or why it has not been read. It then waits for a reply that is just `confirm`. A later
synthesis or a new authority or dry-run result needs a new card and a new confirmation.

The handoff is a separate skill, `/oz-policy-builder:policy-builder-install`, which only the
user can start: its `disable-model-invocation: true` keeps the agent from invoking it. It
checks that the current grant was confirmed and then prints one of two things:

- **An `ozpb-grant-proposal/v1` document**, for a grant of the shape the wallet integration
  supports (recorded from the wallet account's confirmed testnet transaction; one rule, one
  delegated signer, an expiry and a call cap; exact arguments; the generated policy only). It
  carries the network ID, that transaction's hash, the wallet-supported decisions (`grant_name`,
  `delegate`, `valid_until_ledger`, `max_calls`, `unlimited_calls_acknowledged`),
  `expected_grant` and the agent's `spec_hash`. `expected_grant` is the spec's grant projection:
  the account and, per rule, the context type, contract and target code hash (`null` for a
  Stellar Asset contract, so an upgraded target is refused), each allowed call's function and
  argument constraints, the authorization, the expiry ledger, the call cap and the policy kinds.
  It leaves out when the target code was observed, its role and drift policy, and constraint
  provenance, which an honest re-acquisition can observe differently. The wallet import
  treats it as untrusted: record the transaction again by hash through its own RPC,
  synthesize again with its own toolchain from its own decisions document, refuse any projection
  difference, widening or spending limit, and show the delegate, expiry and cap for approval.
  Spec hashes are shown, not required to match. The skill's text is the exact field-by-field
  definition, and `scripts/check-agent-transcript.py` checks a printed proposal against the tool
  calls it came from. The local wallet accepts the supported native-XLM transfer subset through
  [Import a grant proposal](POLLYWALLET-INTEGRATION.md#importing-an-agent-proposal).
  Its execution checks require the delegate held by that backend session.
- **A user-run path** for every other grant: generate and verify the policy locally, upload it
  and deploy it by its verified Wasm hash with the user's own key, bind it, rerun the authority
  check, confirm a new card that includes the authority list, then
  `assemble_install_transaction` for an unsigned draft. That draft still needs a wallet that
  validates it, builds the owner authorization and enforce-simulates before signing
  ([`docs/INSTALL-ASSEMBLY.md`](INSTALL-ASSEMBLY.md)).

**Do not pre-approve `prepare_install_intent`, `assemble_install_transaction` or
`capture_target`** — not with a Claude Code permission rule, `--allowedTools`, or a skill's
`allowed-tools`. Neither the plugin nor the skills do, and a test keeps it that way. Each call
should prompt, so a person sees every request that reads the account for an install or carries
a confidential envelope.

`scripts/check-agent-transcript.py` reads a session's JSON lines: `claude -p --output-format
stream-json --verbose` output (with `--input-format stream-json --replay-user-messages` for a
multi-turn run, so the user's turns are in it) or a session log. It works on the structured
sequence of user turns, tool calls and results, and exits 1 on a synthesis whose decisions were
not restated to the user and plainly accepted, a delegate the user never wrote, a handoff
without a complete card and confirmation, the agent invoking the install skill, a command naming
the Stellar CLI with a signing, submitting, deploying or key verb (a search for them included),
a tool touching the CLI's key store, a secret seed, an affirmative "safe" about the account or
grant, or a proposal whose values are not the tools' latest. "Not safe" passes. Its card,
confirmation and safety checks read English, as the skill asks. A pass says the session kept
these rules, not that the grant is what the user wanted.

### Two more things worth trying

Because they are what a reviewer will ask:

- **Ask it what tools it has.** The answer comes from the server, not from this page: the
  served set is what this milestone ships, and a list written here would go stale the moment
  it changes.
- **Give it something impossible** — a spec that is not a spec, a transaction hash that never
  existed. The refusals are the interesting half, and §4 says what shape they take.

## 2. What each tool needs

`evaluate_spec`, `reference_suite`, `synthesize_policy`, and `import_recording` run offline;
network recording, exact-envelope preflight and target capture read RPC, while generation and
verification build Wasm. The account and install tools, `capture_target`, and the recording tools
unless a request gives its own `rpc_url`, read through an RPC source the server was started with
(`OZPB_RPC_SOURCES_JSON`); the account and install tools
may rebuild generated policies, and `prepare_dry_run` builds but reads nothing. Knowing which is
which saves a confusing failure.

| Tool | Needs |
|---|---|
| `evaluate_spec` | nothing — pure and offline. The one to try first |
| `import_recording` | nothing, but anything arriving this way is labelled `self_supplied`: a `trust` field in caller JSON is a claim, not a receipt |
| `record_transaction` | a transaction hash still inside RPC retention — a few days. It reads through the server's configured source (the only one, or `rpc_source`), or through `rpc_url` with its `network_passphrase` |
| `record_simulation` | the same source, but no signature and no custody: record mode asks what an *unsigned* envelope would require. This is the path the demo script uses |
| `preflight_transaction` | the network and an exact envelope carrying its intended authorization entries; enforcement mode returns the endpoint-reported simulation outcome and ledger, names each declared footprint list that is not exactly the simulated one and each disk-read or write limit below the use, and lists declared instructions or fee below the endpoint's padded estimate as advice that never changes the outcome. It does not prove that a particular installed policy was selected, and writes are discarded. Discarded writes do not make it harmless: signed authorization entries are live authorizations that anyone who sees the envelope — the RPC endpoint, this transcript — can submit until their `signatureExpirationLedger`, and simulation does not consume their nonce. Use testnet or a short expiration, a trusted endpoint, and the stdio server; a hosted server refuses signed envelopes |
| `capture_target` | an RPC source the operator configured in `OZPB_RPC_SOURCES_JSON` (the request names it and its network, never a URL; `scripts/mcp-server-dev.sh` configures one, `testnet`), and an unsigned envelope whose only call is a native Stellar Asset Contract `transfer` from the contract account to an existing G recipient. Returns the `rpc_reported` target capture the native worker's captured-target layer reads; its record-mode simulation is acquisition only, not evidence that a policy permits the call. Any other call is refused with `E_UNSUPPORTED_ENVELOPE`; a failed simulation of the call returns `E_TARGET_REFUSED`, archived call state `E_TARGET_ARCHIVED`. The envelope is confidential input: no result or error echoes it, but it reaches the endpoint and this transcript, and the capture repeats its call (account, recipient, amount), so prefer the CLI or a local stdio server. It does not run the captured-target layer |
| `synthesize_policy` | a recording and the decisions — the signer set, the lifetime, the call cap (or an explicit `unlimited_calls_acknowledged: true` instead of one). Everything else it can work out: the account comes from the recording, and the registry snapshot from what the server was started with (`scripts/mcp-server-dev.sh` supplies the committed development pair). What it will not work out is the decisions, because those are the grant |
| `reference_suite` | a validated spec; returns layer-1 permit/deny evidence and coverage, not a complete dry run |
| `generate_code` | the pinned `stellar contract build` installed, and a warm dependency cache. The first call is slow |
| `verify` | the spec, selected rule, and either the `build_manifest_hash` of an artifact `generate_code` built in this session (as `generated_artifact`) or the complete generated non-lock files, claimed Wasm and BuildManifest; reports reproduction and evidence limits separately. A reference is replaced by the bytes before anything is checked, and only the session that generated the artifact can resolve it |
| `prepare_dry_run` | the authority-check request below, the artifact `verify` takes, a proposed context-rule ID and a fresh run nonce. It reproduces the artifact and derives the reference suite, then reports the account-Wasm, captured-target and live layers as unavailable: not a complete dry run ([`docs/DRY-RUN-PREPARATION.md`](DRY-RUN-PREPARATION.md)) |
| `check_policy_call_surface` | the spec and rule index, the exact policy bindings, a signed registry snapshot, the account, the network, and the *name* of a configured RPC source, never a URL. Returns who can change the account or reset the bound policies, with refusals and gaps; advisory, never "safe" |
| `prepare_install_intent` | the same request. It runs that check itself and returns the exact `add_context_rule` arguments only when nothing is refused or unresolved; it never signs |
| `assemble_install_transaction` | that request plus a fee-payer address, a fee ceiling and a validity window of at most 120 ledgers. Returns unsigned XDR the wallet must validate, recheck and enforce-simulate before signing ([`docs/INSTALL-ASSEMBLY.md`](INSTALL-ASSEMBLY.md)) |
| `check_against_policy` | an installed rule's on-chain ID with its spec, bindings and signed snapshot, the account, an RPC source name, candidate signers and the proposed invocation. Predicts permit, deny or `unsupported` at one ledger, recognition-scoped and without verifying signatures ([`docs/LIVE-POLICY-CHECK.md`](LIVE-POLICY-CHECK.md)) |

To see recording and synthesis in sequence without an agent, run
`bash scripts/demo-tranche1.sh`: it drives those operations through the CLI and keeps every
input and output as a file.

## 3. Synthesizing a policy, in one request

The tool that turns a recording into a policy is the one worth exercising, so here it is end to
end. It needs two things: a recording, and what you decided about the grant.

```bash
RUN="$(ls -1dt demo-runs/*/ | head -1)"      # any completed `demo-tranche1.sh` run
python3 - "$RUN" <<'EOF' > /tmp/mcp-synthesize.jsonl
import json, sys
run = sys.argv[1].rstrip("/")
load = lambda p: json.load(open(p))
line = lambda o: print(json.dumps(o))
line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {},
    "clientInfo": {"name": "manual", "version": "0"}}})
line({"jsonrpc": "2.0", "method": "notifications/initialized"})
line({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
    "name": "synthesize_policy", "arguments": {
        # `03-recording.json` is the envelope the CLI writes; the tool takes the bundle inside
        # it, which is also exactly what `record_transaction` hands back over MCP.
        "bundles": [load(f"{run}/03-recording.json")["bundle"]],
        "decisions": load(f"{run}/04-decisions.json"),
        "spending_limit_capability": "pinned"}}})
EOF

./scripts/mcp-server-dev.sh < /tmp/mcp-synthesize.jsonl 2>/dev/null | tail -1 \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["result"]["structuredContent"]["spec_hash"])'
```

That prints the spec's canonical hash, and it is the same hash the CLI produces from the same
inputs — `jq -r .spec_hash "$RUN/04-synthesis.json"` to check. Two surfaces onto one
implementation is the claim; equal hashes are what makes it checkable.

`bash scripts/demo/mcp-synthesize.sh` is that whole comparison in one command: the same request,
against the most recent run or one named as its argument, and a non-zero exit if the two hashes
differ. The request above is worth reading once for the shape; the script is what to run.

Three of those arguments are worth a word each:

- **`bundles`** is a recording, not a path. Over MCP you rarely paste one: `record_transaction`
  and `record_simulation` return exactly this shape, so an agent that just recorded something
  already holds it.
- **`decisions`** stays required. The signer set, the lifetime and the call cap are what the
  grant *is*; a default would mean the toolkit decided how much authority to hand out. That
  includes leaving a cap out: since v0.2.0, `max_calls: null` alone is refused with an
  `E_NEEDS_DECISION` finding, and an uncapped grant also needs
  `unlimited_calls_acknowledged: true`, as a grant that never expires needs
  `no_expiry_acknowledged: true`. An absent acknowledgement reads as `false`; a cap together
  with it, or an expiry ledger together with `no_expiry_acknowledged: true`, is refused as
  contradictory with an `E_INVALID_DECISION` finding. The findings are in the error's
  `details`; the top-level code is the first one's. This is a breaking change for decisions
  documents that relied on a null cap ([release notes](release-notes/v0.2.0.md)).
- **`spending_limit_capability: "pinned"`** opts in to composing OpenZeppelin's reviewed
  spending-limit policy without transcribing its hash. It is an opt-in rather than a default:
  composing a reviewed third-party contract into a grant is a decision too. Omit it and a
  `decisions` file that asks for a spending limit gets `E_UNREGISTERED_POLICY` rather than a
  policy quietly composed for you.

You can also pass `selected_authorizer` and `account` explicitly, and the CLI always does. The
derivation only answers when the recording leaves nothing to choose: two authorizing accounts is
a decision about whose authority is being constrained, and that comes back as an error naming
both rather than a pick.

## 4. Two answers that look like bugs

Worth knowing before showing this to anyone, because both invite the wrong conclusion.

**`evaluate_spec` answers `indeterminate` on a call that looks like it should pass.**

```json
{"verdict": "indeterminate", "deny_reason": "ReviewedPoliciesUnmodeled"}
```

The invocation matches the generated scope policy, so a naive evaluator would say `permit`.
But the spec also composes OpenZeppelin's reviewed spending-limit policy, whose rolling state
this evaluator does not model — so a whole-spec `permit` would be a claim it cannot support.
An evaluator that answered `permit` there would be more useful and less honest. Deny is still
definite where it can be: a recipient outside the allowed tuple gives
`{"verdict": "deny", "deny_reason": "NoTupleMatched"}`.

**A bad input comes back as a result, not as a crash.**

```json
{"isError": true, "structuredContent": {"code": "E_SPEC_INVALID",
 "message": "malformed input JSON: missing field `name`"}}
```

`isError: true` on a *tool result*, not a JSON-RPC protocol error — so a model can read it,
fix its arguments and retry, which it cannot do with a transport-level failure. The `code` is
stable; the prose after it is for humans and may change.

## 5. If you want a listener instead

`--http <addr>` serves the same handler at `/v1/mcp`. It will not start bare:

```console
$ ./target/release/ozpb-mcp-server --http 127.0.0.1:8080
Error: OZPB_HTTP_BEARER_TOKEN is required for HTTP mode
```

That refusal is the feature. HTTP mode also requires `OZPB_RPC_ALLOWLIST`, binds localhost
only, and applies bearer auth, a request quota, a request-size bound and a limit on concurrent
builds. `docs/DEVELOPERS.md` has the full set, and what is still owed before anything
resembling multi-tenant hosting.
This is the shape a hosted deployment would take. [`docs/SELF-HOSTING.md`](SELF-HOSTING.md)
packages it behind a TLS proxy for one operator, and
[`docs/ISOLATED-BUILDS.md`](ISOLATED-BUILDS.md) adds disposable build workers. No hosted
endpoint is deployed, and this is not how to run it locally.

---

## Appendix: speaking to it directly

You do not need this to use the toolkit. It is here for two cases: seeing the actual wire
format, and debugging the server without a client in the way.

The server speaks newline-delimited JSON-RPC on stdin/stdout and exits when stdin closes, so
a whole session is one pipe. Every session opens with the same two lines — an `initialize`
request and an `initialized` notification. Skip them and tool calls are refused, which is the
protocol working rather than a bug.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
| ./target/release/ozpb-mcp-server 2>/dev/null \
| python3 -c 'import sys,json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]'
```

(`json.tool --json-lines` would be shorter, but that flag only exists in recent Python 3.x
and this page is meant to be pasted, not adapted.)

A real tool call, using the committed examples as its three inputs:

```bash
python3 - > /tmp/mcp-session.jsonl <<'EOF'
import json
def line(o): print(json.dumps(o))
line({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
      "capabilities":{},"clientInfo":{"name":"manual","version":"0"}}})
line({"jsonrpc":"2.0","method":"notifications/initialized"})
line({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evaluate_spec","arguments":{
    "spec":       json.load(open("docs/examples/subscription-spec.json")),
    "context":    json.load(open("docs/examples/eval-context.json")),
    "invocation": json.load(open("docs/examples/invocation-permit.json"))}}})
EOF

./target/release/ozpb-mcp-server < /tmp/mcp-session.jsonl 2>/dev/null
```

That returns the `indeterminate` verdict from §4. Swap `invocation-permit.json` for
`invocation-deny.json` to get the definite one, and send a spec that is not one to see the
error shape — handshake included, since a bare `tools/call` is refused:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evaluate_spec","arguments":{"spec":{"schema":"nope"},"context":{},"invocation":{}}}}' \
| ./target/release/ozpb-mcp-server 2>/dev/null | tail -1
```

Every command on this page was run to write it, and the outputs are pasted from those runs.

---

## What this does not show

No policy is installed and nothing is signed here. The complete permit/deny dry-run report,
wallet install flow, and a deployed hosted endpoint are scheduled work; self-hosting is
covered in [`docs/SELF-HOSTING.md`](SELF-HOSTING.md). `evaluate_spec` is the reference
evaluator answering about a spec —
not a smart account executing a policy, which is a different and stronger claim that belongs
with the harness.

The `policy-builder` skill guides the available tools through an artifact and evidence
summary and, once the policies are deployed, the advisory authority check, install intent and
dry-run preparation, then asks for confirmation; the install skill hands the confirmed grant
off. Neither signs or installs. Its layer-1 reference suite is not the full contract/live dry
run. The complete dry-run report, wallet install flow and proposal import, and a deployed
hosted endpoint remain scheduled work.
