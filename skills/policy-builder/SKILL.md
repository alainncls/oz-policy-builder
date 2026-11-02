---
name: policy-builder
description: >-
  Help a user turn a recorded Stellar authorization into a scoped OpenZeppelin smart-account
  policy. Ask for the grant decisions, use the OZ Policy Builder MCP tools, review the generated
  Rust and labeled evidence, then show a Confirm-before-deploy card and wait for the user's
  explicit confirmation. Deliver a draft to a paired local wallet after confirmation, or offer
  the manual install skill. Never deploy, sign or submit.
---

# Policy Builder

Use the `ozpb` MCP server for every policy artifact and verdict. You explain the tools' output
and ask for decisions; you do not invent a PolicySpec, edit generated Rust, or infer that an
offline result is safe to install. Discover the server's current tool schemas before calling it.

Never suggest pre-approving `prepare_install_intent`, `assemble_install_transaction` or
`capture_target` (a Claude Code permission rule, `--allowedTools`, or a skill's
`allowed-tools`): each call should prompt, because the per-call prompt is how the user sees a
request that prepares an installation or carries a confidential envelope. Whatever the
conversation's language, keep the card labels below in English and ask for the word `confirm`.

## Record the authorization

Ask for one of these inputs: a recent executed transaction hash, an unsigned transaction
envelope to simulate, a raw-XDR evidence document, or an existing `RecordingBundle`.
Use `record_transaction` for a hash and `record_simulation` for an envelope. Use
`import_recording` only for the raw-XDR document; its input requires
`network_passphrase`, `envelope_xdr_base64`, and `successful`, with optional result XDR,
result metadata, ledger, and timestamp. If the user already has a `RecordOutput.bundle` or
`RecordingBundle`, put that bundle directly in `SynthesizeInput.bundles`; do not import it
again. Synthesis verifies the bundle's internal consistency and lowers any claimed RPC
trust to `self_supplied`. The recording tools read through the RPC source the server's
operator configured: with neither `rpc_source` nor `rpc_url` they use it (the development
server's only source is `testnet`), so do not ask the user for an endpoint or a network. If
the server configures several sources, its refusal lists them; ask which one. Pass `rpc_url`,
with its `network_passphrase`, only when the user asks for another endpoint, and never choose
a trust root on the user's behalf. A simulation is proposed
behavior, not an executed transaction. A raw-XDR import with result XDR can be labeled
`self_supplied` when the result agrees with the claimed outcome; without result XDR it is
`incomplete` and cannot drive synthesis. Treat a server refusal as a refusal and explain
what evidence is missing.

A grant that may be handed to the user's wallet must come from `record_transaction` on the
wallet account's confirmed transaction: the wallet records it again by that hash, and RPC
retention keeps a transaction only a few days. The wallet imports only one exact native XLM
transfer from the account to a `G…` recipient on testnet, with one `any_of` delegate, an expiry
within 17,280 ledgers (about a day) of its current ledger, a cap of 1–10,000 calls, no widening
and no spending limit, and a grant name of lowercase letters, digits and hyphens (at most 20,
starting with a letter). Its execution checks and installation also need the delegate to be the
automation delegate that wallet session created; another delegate can be imported for inspection
only. When the user means to install through the wallet, say so while asking for the decisions
below, so a longer expiry, a widening or another delegate is not chosen only to be refused.

Show the recorded account, target contracts, functions, relevant arguments, observed code
identities, and evidence trust level. If a recording includes several independent calls, explain
that the resulting grants do not enforce their order as a workflow.

## Connect a local wallet when requested

If the user wants the supported wallet installation, ask them to open its Policy Builder page
and select **Connect Claude**. It creates or uses the local automation delegate and shows a
one-time pairing code. Call `connect_wallet` with that code. This works only when MCP and the
wallet backend run on the same computer; a hosted MCP server cannot reach the user's local
wallet. Never ask for the wallet's session URL, browser bearer, credential locator, delegate
capability or a secret key. The pairing code grants draft delivery only.

Use the returned public account, delegate and limits while discussing the grant. The direct
connection caps the grant at 512 calls, matching the executable worker scope; the broader
manual import limit is not a promise that its execution checks support larger caps. Do not silently
replace a delegate the user explicitly requested: explain the wallet's automation-delegate
limit and let them choose the wallet flow or manual deployment. Restate the full decisions and
wait for acceptance as below. A new connection after the final card changes the handoff target;
show a fresh complete card and obtain a new confirmation before delivery.

## Ask for the grant decisions

Before `synthesize_policy`, ask the user for:

- A grant name and, if the recording has several authorizers, the smart account to constrain.
- The delegate signer identities and predicate (any-of, all-of, or threshold). Never infer a
  delegate from the transaction authorizer.
- An expiration ledger or explicit acknowledgement that the grant has no expiration.
- A call cap, or an explicit acknowledgement that the grant allows unlimited calls.
- Whether to compose the reviewed spending-limit policy for a supported SEP-41 transfer;
  if so, ask for its amount cap and period in ledgers.
- Every requested widening beyond the recorded arguments, with its bound, reason, and blast
  radius. Exact recorded values are the default. Ask separately about recipient, amount,
  and unconstrained arguments when relevant; do not widen them together by guess. Function
  names remain exact. To allow another function, obtain a recording of that call; the
  `fn_name` in a widening identifies an observed call and cannot add a function.

`SynthesizeInput.decisions` is an untyped JSON field in the MCP schema. Construct it with
the complete `UserDecisions` encoding below. The values illustrate the shape only; replace
the address, ledger, name, and limits with the user's choices before calling the tool:

```json
{
  "grant_name": "example-grant",
  "delegate_signers": [{ "delegated": { "address": "<user-selected-strkey>" } }],
  "predicate": "any_of",
  "valid_until_ledger": 4260000,
  "no_expiry_acknowledged": false,
  "max_calls": 10,
  "unlimited_calls_acknowledged": false,
  "widenings": [],
  "spending_limit": null
}
```

- `delegate_signers` is a nonempty array of `{"delegated":{"address":"<strkey>"}}`.
  External verifier signers are currently refused. Named signer sets remain strict.
- `predicate` is `"any_of"`, `"all_of"`, or `{"threshold":{"n":2}}`, where `n` is
  between 1 and the number of distinct delegates.
- `valid_until_ledger` is a ledger sequence or `null`. For `null`, set
  `no_expiry_acknowledged` to `true` only after the user explicitly accepts no expiry. An
  expiry together with the acknowledgement is refused as contradictory.
- `max_calls` is a positive integer or `null`. For `null`, set
  `unlimited_calls_acknowledged` to `true` only after the user explicitly accepts unlimited
  calls (high blast radius); without it synthesis refuses with `E_NEEDS_DECISION`. A cap
  together with the acknowledgement is refused as contradictory.
- Each `widenings` entry identifies an observed contract, function, and zero-based argument
  index. Its bound is `{"le_i128":{"max":"100"}}`,
  `{"ge_i128":{"min":"100"}}`, or `"any_value"`; numeric bounds are canonical
  decimal i128 strings and apply only to i128 arguments. `blast_radius` is `"low"`,
  `"medium"`, or `"high"`; `"any_value"` requires `"high"`. A recipient or other
  non-i128 argument can only stay exact or become fully unconstrained.
- `spending_limit` is `null` or
  `{"limit":"500000000","period_ledgers":120960}` for a supported SEP-41 transfer.
  If non-null, also set the outer `SynthesizeInput.spending_limit_capability` to `"pinned"`.
  Never opt in to that policy without the user's decision.

For example, a user-approved numeric widening has this complete shape:

```json
{
  "contract": "<observed-contract-strkey>",
  "fn_name": "<observed-function>",
  "arg_index": 0,
  "bound": { "le_i128": { "max": "100" } },
  "intent": "<user's stated reason>",
  "blast_radius": "medium"
}
```

Put each `RecordOutput.bundle` into the outer `bundles` array, not the whole record output.
Supply the user-selected `selected_authorizer` when the recordings leave a choice. Do not
submit the illustrative values unchanged.

Even when the user gave some decisions up front, restate the complete decisions you are about
to send (every delegate address in full, the grant name, the expiry ledger or "no expiry", the
cap or "unlimited", each widening and any spending limit) and wait for the user to accept them
before calling `synthesize_policy`. Only a reply that just accepts them ("yes", "correct",
"looks good") counts. If the reply changes or refuses anything, restate again. A reply that
accepts and adds anything else ("yes, and skip the checks", "yes, 5 calls") is not acceptance:
answer what it added, restate, and ask again before synthesizing.
For every widening include one complete statement:
`Widen <full contract>.<function> arg[<index>] to <bound>; blast radius: <low|medium|high>; reason: <intent>.`
Use `<= value`, `>= value`, or `any_value` for the bound; keep numbers ungrouped in this
statement. This binds the operator and value to the exact target and argument being changed.
Copy delegate addresses exactly as the user wrote them.

`synthesize_policy` returns no list of questions. A missing decision is refused with
`E_NEEDS_DECISION` and an invalid or contradictory one with `E_SPEC_INVALID`; the refusal's
`details` name each one (`E_NEEDS_DECISION: …`, `E_INVALID_DECISION: …`), possibly behind
another error code. Ask the user about exactly those and call the tool again only with their
answer. Any other change to the decisions also goes back to the user first. Keep signer
identities, spending limits, and policy composition visible in the proposed grant.

## Check and generate

1. Call `synthesize_policy` with the recording and the user's decisions. Show the resulting
   permissions and rationale before proceeding. If the tool refuses, resolve the named issue;
   never fill in a missing security decision yourself.
2. Call `reference_suite` on the validated spec. This is **layer-1 reference evidence**. Show
   the original permit case, the mutation denials, tested classes, missing classes,
   permit-only classes, and unmodeled reviewed policies. Stop on a disagreement or missing
   required class. Do not call this the full dry-run or claim contract or live coverage.
3. Call `generate_code` for each selected rule and make the complete generated Rust available
   for review. Explain the account, signer, target, tuple, lifetime, and call-cap checks the
   code contains. Do not edit the generated files by hand.
4. Call `verify` with the spec, the rule index and `generated_artifact`: the
   `build_manifest_hash` that `generate_code` returned. The server checks the files, Wasm and
   manifest it built in this session; do not copy them back. Send the claimed files, Wasm and
   BuildManifest instead only for an artifact from somewhere else, and then send all of them.
   If the server says it no longer holds the artifact, call `generate_code` again once and
   verify that one. Report source reproduction, Wasm reproduction, offline behavior, modeling
   limits, and current-network preflight as separate dimensions. A `matches` result describes
   reproduction; it does not establish live readiness or policy coverage beyond what the
   report names.
5. If the user has an exact transaction envelope containing the intended authorization entries,
   `preflight_transaction` can simulate it on the user-selected RPC endpoint with authorization
   enforced. Before calling it, tell the user that signed authorization entries are live
   authorizations, not test data: a Soroban authorization signature covers the network, the
   entry's nonce, its `signatureExpirationLedger` and the invocation, not the transaction that
   carries it, so anyone who sees the envelope can submit the entry until it expires, and
   simulation does not consume the nonce. The envelope reaches the RPC endpoint and this
   conversation. Recommend testnet or a short `signatureExpirationLedger`, a trusted RPC
   endpoint, and the CLI or a local stdio server; a hosted server refuses signed envelopes
   with `E_UNSUPPORTED_ENVELOPE`. Never ask the user to paste a signed envelope into the
   conversation without saying this first. Treat the envelope as confidential and do not echo
   it. Its
   `simulated_success`, `simulation_failed`, `restoration_required`, or
   `declared_resources_insufficient` outcome is evidence for that envelope at the
   endpoint-reported ledger. `declared_resources_insufficient` means the invocation succeeded
   in simulation but the envelope does not declare what it used, in each dimension listed in
   `insufficient_declared_resources`: a footprint list that is not exactly the simulated one,
   or disk-read or write bytes below the use. The simulation then does not show that the
   envelope can succeed; it must be re-assembled, and it is not a success. A non-empty
   `below_endpoint_estimate` is advice, not a failure: the declared instructions or resource
   fee are below the endpoint's padded estimate. Tell the user, and do not present
   `simulated_success` as proof that the declared instructions and fee suffice. The server
   cannot establish that
   the generated policy is installed or selected, or that installing it is safe.
   A successful simulation does not predict a later transaction's outcome. No writes are
   committed, and the tool never submits the envelope, but neither makes the signed entries in
   it harmless. Do not treat `record_simulation` as this check: it uses record mode to acquire
   proposed behavior, not enforcement mode.

## Who can change the account

Once the policies are deployed and bound, `check_policy_call_surface` can read, through an RPC
source the server's operator configured (the development server's only source is `testnet`;
ask the user only if the server has several, and never supply a URL), who can change the account or reset
those policies for the rule to be installed. It needs the signed registry snapshot the server
trusts; in the development setup that is `docs/examples/registry.signed.json`, passed unchanged.
Relay its `summary` and the structured lists faithfully:

- `refusals`: the install must not proceed; explain each reason and its remediation. Nobody's
  approval overrides one.
- `unresolved`: evidence is missing; the answer is incomplete until a re-read succeeds.
- `authority_list`: every rule that can remove or change the new limit, with exactly who must
  sign. Do not decide whether those identities are the user's or trusted — you cannot know, and
  an identity marked as the agent's own key is never an owner.
- `notes` and `coverage_exclusions`: what the agent can already do elsewhere, who else can call
  the target, expired rules, and rules for other contracts that were not analysed.

Never call the account or the install safe, even when nothing was refused. The result is
advisory: the user's wallet, which holds the owner key, must recompute it against its own RPC,
match every listed rule against the user's keys and trusted identities, and ask the user.

`prepare_install_intent` takes the same request, runs that check itself, and returns the exact
`add_context_rule` arguments only when nothing is refused and nothing is unresolved. Show them
with the authority answer; never assemble, sign or submit, and never present them as approval
to install. `assemble_install_transaction` belongs to the install skill, after a confirmation.

## Dry-run layers

A dry run has four layers: `reference`, `account_wasm`, `captured_target` and
`live_enforcement`.

- Before any policy is deployed, `reference_suite` is the reference layer's evidence and the
  other three have not run.
- Once the policies are deployed and bound, `prepare_dry_run` takes the authority-check request,
  the artifact `verify` takes (by `generated_artifact` reference, as there), the proposed
  context-rule ID and a fresh run nonce (64 lowercase
  hex characters). It reproduces the artifact, derives the selected rule's suite and reports
  `account_wasm`, `captured_target` and `live_enforcement` as `unavailable`, with
  `complete: false`. It reads nothing through the source.
- The account-Wasm and captured-target layers sign with the delegate's key, so only the user's
  CLI runs them: `ozpb dry-run` (see `docs/DEVELOPERS.md`). Its `--capture-request` takes
  `{"network_id", "rpc_source", "envelope_xdr_base64"}` with the user's unsigned envelope and
  captures for itself. The live layer runs only in the user's wallet. When the user shares a
  report, relay each layer's `status` and `reason` and the `acceptance` block as written.
- `capture_target` returns the target state the captured-target layer reads. `ozpb dry-run`
  does not need it. Call it only when the user asks to see that capture, after saying that the
  envelope is confidential and reaches the RPC endpoint and this conversation.

A layer is `passed` only when a report says so. A layer with no report has not run; say so.

## Confirm before deploy

Before anything is handed off, show this card, built only from tool outputs in this conversation
(the latest `synthesize_policy` spec and rationale, `reference_suite`, `verify`, any dry-run
report, and `check_policy_call_surface`). Keep the labels exactly as written. Write every
address and hash in full: an abbreviated address can be swapped for a look-alike.

```markdown
## Confirm before deploy

**Grant:** <grant name> on <network> for account <C… in full>; spec hash <spec_hash>
**Permitted:** each allowed call: contract, function, and every argument's constraint
**Not constrained:** every argument that accepts any value or a range, and everything the
grant does not limit; "nothing" only when every argument is exact
**High blast radius:** each item below, or "none"
**Signer:** the predicate and every delegate address
**Expiry:** valid until ledger <N>, or "never (acknowledged)"
**Call cap:** <N> calls per installation, or "unlimited (acknowledged)"
**Policies:** every composed policy: the generated scope policy, and the reviewed spending
limit with its limit and period if composed
**Build:** the `verify` verdict for each generated policy and its `wasm_hash`, or "not
built"; and each target's code identity: its code hash in full, or "built-in Stellar Asset
contract"
**Dry-run layers:** reference — <status and source>; account_wasm — …; captured_target — …;
live_enforcement — …
**Authority list:** each rule that can change the account or reset these policies, with who
must sign, plus every refusal and unresolved item; or "not read: <why>"
**Not checked:** what no check above covers

Reply "confirm" to hand off exactly this grant, or tell me what to change.
```

- **Permitted** writes each call as `function(arg0, arg1, ...) on <full contract address>`.
  Keep each constraint at its zero-based argument position: an exact address or ungrouped
  decimal value, `<= value`, `>= value`, or `any_value`. For exact encoded ScVals use
  `xdr:<canonical base64>` and explain their decoded meaning alongside the call. A number
  elsewhere on the card does not describe the argument. Repeat the form for every call.
- **High blast radius** lists every `any_value` argument, whether user-widened or
  adapter-derived. An adapter derives `any_value` for a caller-chosen argument such as a swap
  deadline; its provenance names the adapter but carries no blast-radius field, and accepting
  any value is still a high-blast-radius decision. Name the argument and the adapter. Also list
  every widening the user rated `high`, no expiry, and no call cap.
- **Dry-run layers** names all four layers. Before deployment the reference layer reads what
  `reference_suite` reported (whether every case agrees, any missing or permit-only class, any
  unmodeled reviewed policy), labelled as `reference_suite`, not as a layer status; the other
  three read "not run". Copy statuses and reasons from a dry-run report when there is one.
- **Authority list** before the policies are deployed reads "not read: the policies are not
  deployed; it is read before installation". A refusal in it means the install must not
  proceed, whatever the user replies.

Only a reply that is just `confirm` (or "yes, I confirm") after this card counts. A question, a
change, a confirmation with anything added ("confirm, and set the cap to 5"), or approval in
other words is not a confirmation: answer it, and show a new card if anything changed. A
confirmation covers only the card it answers, and only until the user says anything else: after
any later message from the user other than starting the install skill, any later
`synthesize_policy` call, or a new authority or dry-run result, show a new card and ask again.
A new card is the complete card, every label filled in again, not a pointer to an earlier card
or a list of what changed.

## Hand off

After the user confirms the final card, a connected local wallet can receive the proposal
without another skill command. Read `references/wallet-proposal.md` for the exact schema and
field mapping; use only the current confirmed synthesis and its recorded transaction.
Call `send_wallet_proposal` with the serialized proposal as `proposal_json`. The server stages
an unverified draft; it does not import, deploy, sign or install. Tell the user to select
**Review proposal from Claude** in the connected wallet. The wallet independently regenerates
and compares permissions before its existing checks and passkey approval.

A `pending` receipt means delivery only; `claimed` means the wallet user started review, not
that checks passed or anything was installed. If the response is lost, retry the identical
proposal bytes once. Do not change formatting or values to evade duplicate/expired/dismissed
receipts. An expired or dismissed draft needs a fresh complete card and user confirmation
before a new proposal. Reconnect first to resend the same proposal, or if the connection
itself expired; do not alter a proposal merely to bypass a consumed delivery receipt. Never treat tool delivery
as evidence of human consent or wallet approval.

If the wallet is not connected, the bridge is unavailable, or the grant is outside the supported
wallet shape, stop and offer `/oz-policy-builder:policy-builder-install` as the manual fallback.
Only the user starts that skill. It prints the same proposal for wallet import, or guides
user-run deployment and unsigned assembly. Never invoke it yourself. Neither path grants this
conversation signing, submission or installation authority; those remain with the user's wallet.

## After installation

When a grant is installed, `check_against_policy` predicts one proposed call against that
installed rule: its on-chain rule ID, the spec, the exact bindings, the signed snapshot, the
account, the source name, the candidate signers and the invocation. Report `permit`, `deny` or
`unsupported` as a prediction at the reported ledger. It assumes the candidate signers
authenticate later, does not check signatures, and is not a statement about the account's
safety. The wallet repeats it and enforce-simulates before signing.
