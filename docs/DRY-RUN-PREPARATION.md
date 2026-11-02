# Preparing candidate-bound evidence

`ozpb prepare-dry-run` and MCP `prepare_dry_run` bind one candidate grant to its
deterministic reference cases and reproduced artifact. They return the four named evidence
layers and state exactly which have not executed. This is preparation for a layered dry run,
not the complete `dry_run` operation; `complete` is always `false`.

```sh
ozpb prepare-dry-run \
  --request dry-run-request.json \
  --registry-roots registry-roots.json \
  --registry-min-version 4 \
  --rpc-sources rpc-sources.json
```

The typed `DryRunInput` contains:

- `candidate`: the existing `CheckPolicyCallSurfaceInput`, including the exact spec, rule,
  policy bindings, signed registry, account, network and operator RPC-source name.
- `artifact`: `VerifyInput` for exactly the same spec and rule, with source, Wasm and
  BuildManifest claims. Over MCP it may instead carry `generated_artifact`, the
  `build_manifest_hash` of an artifact `generate_code` built earlier in the same session; that
  server substitutes the stored source, Wasm and manifest before anything is checked, so the
  run hash covers those bytes exactly as if the client had sent them. The CLI and toolkit refuse
  a reference. A hosted session forgets its artifacts when it ends.
- `candidate_context_rule_id`: the proposed chain ID, independently of the spec index.
  No live read has established that this is the next ID.
- `run_nonce`: a canonical lowercase 32-byte hex nonce distinguishing this run.

The shells resolve the source through operator configuration; the hosted shell also checks
its endpoint allowlist and reserves shared work capacity. Preparation does not contact that
source. Registry recognition, generated binding reproduction and artifact verification use
the configured build limits. Registry validity is checked again when preparation finishes.
No request field selects a command, builder, endpoint URL, signing key or execution report.

The result includes the complete-request hash, selected-rule suite hash, exact spec/binding/
registry/account/network identities and every bound policy's recognized or reproduced code
hash. These are candidate identities, not live code observations. A changed artifact claim,
nonce, rule ID or RPC-source name changes the run hash. The signed registry and operator
configuration must still be current when later execution starts.

The `reference` layer passes only when its selected-rule cases exist, agree with their
expectations, cover every required boundary class and model every composed policy. A reviewed
policy outside that model yields `unsupported`, even if every generated scope/count case
agrees. Source/Wasm reproduction is reported separately and cannot turn missing runtime
evidence into success.

`account_wasm`, `captured_target` and `live_enforcement` are explicitly `unavailable`.
Preparation runs no full account authorization, target-contract execution or live enforce
simulation. It commits no local or network state, signs nothing and submits nothing.
The absence of those layers cannot be overridden by supplying a caller-written report.

Completing those layers needs an actual execution backend, captured target dependencies and
wallet-owned authorization. An owner passkey is not a delegate signing capability. A wallet
must not substitute its owner key for an arbitrary delegate or present virtual authentication
as human approval. Live authorization must be approved in the wallet before it is exposed to
an RPC: authorization signatures can be replayed until their expiration, independently of an
unsigned fee-payer envelope. Installation preflight alone is not evidence of the candidate
policy's behavior.

The [canonical hashing specification](CANONICAL-HASHING.md) defines both new hash domains.
This preparation package adds no complete acceptance claim.

The separately configured [native execution worker](NATIVE-EXECUTION.md) can produce
local account-Wasm evidence after this preparation; `ozpb dry-run` runs this preparation and
then that worker ([running the layers from the CLI](NATIVE-EXECUTION.md#running-the-layers-from-the-cli)).
Neither changes this operation's meaning or completes the live-enforcement layer. The worker's separate
[captured-target mode](CAPTURED-TARGET-EXECUTION.md) does not either: this operation still
reports `captured_target` as unavailable. The [atomic live-enforcement helper](ATOMIC-LIVE-HELPER.md)
is the contract the wallet's [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check)
simulates after the owner's consent, limited to generated policies with a call cap; this operation's
`live_enforcement` stays `unavailable`.

## Executed layers and acceptance

A coordinator that runs the runtime layers returns the same report type with two additions that
a preparation never carries: an `execution` block on each layer it executed, and an
`acceptance` block. The pure assembler in `ozpb_toolkit::dry_run_report` builds that report from
the preparation, the worker's raw reports and exit statuses, and identities it derives itself.

- **Bindings.** Before any case is read, the worker's offline binding (run, job, suite and
  initialization hashes, source network and ledger, account, delegate), its execution network,
  account and policy code identities and proposed rule ID must equal the preparation's and the
  locally derived ones. The account-Wasm job and initialization hashes and the execution network
  ID are derived without the worker. A report from another run is `failed` with
  `worker_binding_mismatch`, and none of its cases is accepted. The native suite hash must also
  be the preparation's.
- **Signatures.** The coordinator reports which case IDs its signer answered. They must be
  exactly the ones a correct run asks for: every derived case the delegate authenticates, every
  control and, for a capped rule, every call of the cap sequence (both signing cases for the
  captured layer). A report from a run that skipped or added a signature is `failed` with
  `signatures_differ_from_expectation`, and none of its cases is accepted.
- **Agreement.** Each case's expectation is the preparation's reference expectation, not the
  worker's. A permitted case agrees only when the expectation is permit, nothing was attributed
  as a refusal and any counter advanced by exactly one. A denial agrees only when the refusal is
  the error its class predicts, raised by the contract that owns that error (`account` or
  `policy`), with local state and counter unchanged. The worker's own `agree` and `passed` are
  necessary, never sufficient. Controls and, for a capped rule, the call-cap sequence must pass.
- **Exit status.** A nonzero worker exit or a signal fails the layer even with a passing report.
  A run the coordinator stopped (deadline, output bound, refused frame or signature request) is
  `failed` with that reason and no evidence.
- **Missing layers stay missing.** A layer that did not run keeps `unavailable` or
  `unsupported`; what a preparation says about the runtime layers is ignored. Outside the
  wallet, `live_enforcement` is always `unavailable` with reason
  `wallet_owner_consent_required`, and `complete` stays `false`.

`ozpb dry-run` is the CLI coordinator that fills these fields. It reports the live layer as
above and `captured_target` as `unavailable` with `captured_target_not_requested` unless given a
capture request. A requested capture that does not complete is `failed` with
`target_capture_failed`, so it blocks acceptance. A selected rule outside the native worker's
scope, including its size bounds (64 KiB of specification, eight calls per rule, sixteen
arguments per call, 256 derived cases, a call cap of 512), is `unsupported` with
`selected_rule_outside_native_scope`, and the key is not read.

`acceptance` counts only executed layers that passed. For each executed layer it records whether
the original call was permitted and how many derived denials reverted: refused with the
predicted error from the predicted contract, with state unchanged. `meets_minimum` holds when
the reference layer passed, at least one layer executed, every executed layer passed and
permitted the original, and one executed layer reverted at least `required_reverted_denials`
(five) derived denials. The captured-target layer has two denials, so it never meets the bar
alone. `meets_minimum` is a statement about the executed cases only, never about untested inputs,
live behavior or installation safety.
