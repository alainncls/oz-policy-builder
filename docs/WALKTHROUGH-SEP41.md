# SEP-41 subscription walkthrough

This executable W2 harness records one native-XLM SAC transfer from a fresh smart account to
a fixed merchant address. It synthesizes an exact transfer scope and a two-call lifetime cap,
composed with the reviewed OpenZeppelin spending-limit policy. One exact charge fills its
rolling window. The native SAC is a SEP-41 implementation; this mode exercises the actual
token and the composed policies, rather than substituting a call counter for cadence.

The short test window is explicitly chosen by the operator, between 12 and 120 ledgers. It is
not a production billing interval. Successful completion requires two separate charge
transactions and a second window wait to isolate the lifetime count cap from the spending cap.

## Run

Use the prerequisites and full authority-check configuration in the
[harness README](../testnet-harness/README.md#the-wallet-decision-on-the-authority-check), then add:

```bash
OZPB_HARNESS_WALKTHROUGH=subscription \
OZPB_HARNESS_AUTHORITY_CHECK=cli \
OZPB_SUBSCRIPTION_PERIOD_LEDGERS=12 \
OZPB_SUBSCRIPTION_POLICY=deploy \
bash testnet-harness/run.sh
```

`OZPB_SUBSCRIPTION_POLICY=deploy` creates an isolated instance of the exact reviewed Wasm
named by the committed signed development registry. That Wasm must be on the configured
testnet; absent code requires an explicit operator upload first. On 30 October 2026 the code
entry was archived, and the instance creation restored it under the default one-XLM fee
ceiling with a 1.2% margin; the restored entry stays live until about 6 November 2026
([testnet evidence, section 18](TESTNET-EVIDENCE-TRANCHE-2.md#18-controlled-sep-41-run-30-october-2026)).
A costlier restore stops the run before signing. An
existing instance can instead be supplied as a contract address; its exact code is read and
checked before use. No unknown policy implementation is accepted.

The setup creates a fresh merchant smart account under the run's same throwaway owner,
before recording the transfer. Both SACs can credit that contract merchant without requiring
a classic trustline, so the wrong-token control keeps the exact same recipient.

It also creates a disposable `W2TEST` SAC issued by the run's fresh payer and mints
only the fixed charge amount to the run's controlled account. This gives the wrong-token
control a real funded token, so a missing contract or insufficient balance cannot count as a
scope denial. Setup transaction identities are saved as each submission is confirmed.

The installer binds both deployed policy instances, including the reviewed policy's code and
exact limit/period. The account owner approves the complete intent, the authority commitment
is rechecked, and the signed call must equal that intent and the synthesized spec. The harness
then checks the generated policy's installation and the spending policy's stored configuration.

## Required observations

| Control | Required evidence |
| --- | --- |
| Larger amount | Attributed generated tuple refusal or reviewed spending-cap refusal. |
| Smaller split charge | Generated tuple refusal; several smaller charges are not allowed. |
| Other merchant | Generated tuple refusal. |
| Other funded token | The account's `UnvalidatedContext` error for the selected rule. |
| Wrong signer | The account's `UnauthorizedSigner` error. |
| Empty signer set | Generated `ZeroSigners` or reviewed `NotAllowed`, depending on policy execution order. |
| First exact charge | Confirmed transaction and ledger. |
| Immediate exact repeat | Spending-policy `SpendingLimitExceeded` at a simulation ledger strictly before first-charge ledger plus the period. |
| Next-window exact charge | Confirmed transaction at or after first-charge ledger plus the period. |
| Lifetime count cap | Generated `CallCountExceeded` after waiting another full period so the spending cap cannot mask it. |
| Removal | Confirmed owner removal, pinned event, absent rule, and separate cleanup observations for both policies. |
| Post-removal call | The account's `ContextRuleNotFound`; an exhausted policy is insufficient. |

Before those controls, `derived-denials.mjs` replays this spec's own layer-1 suite against the
installed rule ([Derived denials](../testnet-harness/README.md#derived-denials)). The recorded
transfer must be permitted in simulation, and every live-realizable deny case must be refused
by the enforcer its class predicts, read from the live rule's policy order. That is the
generated policy's `#6` or `#1`, the spending policy's `3221` or `3223` where it runs first and
refuses first, or the account's `3002`/`3016`. For this spec that is ten cases: another token (the funded
control token stands in for the suite's undeployed address), another merchant, five amounts and
three signer sets. The spending policy must still be unexercised, so the replay runs before any
charge.

**Passing.** The W2 report passes when the recorded transfer is permitted (a confirmed delegated
charge, and the suite's original permitted in simulation) and at least five derived denials from
that spec's suite, identified by its suite hash, are refused with the predicted enforcer. Those
denials are enforcing simulations after installation, observed at their reported ledgers; nothing
is submitted. Time, call-count, missing-state and strict-signer-set cases and mutations the target
rejects before authorization (arity, type confusion) stay offline layer-1 evidence, and the
report lists them by class and reason. The unrecognized-signer case and the
delegate-plus-unrecognized case stop at the same account check, so they count as two suite cases
but only one live check. **Status:** the [22 October run](TESTNET-EVIDENCE-TRANCHE-2.md#11-controlled-sep-41-run-with-derived-denials-22-october-2026)
permitted the original and refused all ten derived denials as predicted, and the
[30 October run](TESTNET-EVIDENCE-TRANCHE-2.md#18-controlled-sep-41-run-30-october-2026) at
revision `60e1da70` repeated that result, as did the
[1 November run](TESTNET-EVIDENCE-TRANCHE-2.md#22-controlled-sep-41-run-1-november-2026) at
revision `86854cee`. The 20 October run (§8) predates the step.

Wrong-tuple and signer controls run before the first charge. Every W2 negative control is an
enforcing simulation, with no fee-transaction signing or submission even if unexpectedly
permitted. A late immediate-repeat observation is marked inconclusive and fails the run;
retry with a fresh isolated grant. Ledger waits have a finite deadline. Neither wall-clock
elapsed time nor a missing readback is converted into a successful observation.

On failure after installation, the wrapper makes one bounded owner-removal attempt before
discarding its temporary keys. A pending or already confirmed removal is not resubmitted. A
pending one is reconciled from its hash after the network check: one that landed is verified and
marked `reconciled`, and only one that failed, or that the endpoint has not seen although its
latest ledger closed after the validity window, may be followed by one fresh removal, never a
third. The cleanup child's output is kept in a new private `cleanup-child.log`.
The failure-cleanup journal distinguishes verified removal from an unresolved live grant,
and the run retains its original nonzero exit status. An unresolved grant may remain until
its configured ledger expiry; disposal of the throwaway keys is not evidence of revocation.

## Evidence boundaries

The real CLI chain is record → synthesize → reference-suite → generate/build → verify. It
checks the exact recorded tuple, selected account and code, explicit delegate/count/expiry,
resolved registry root, source, Wasm and manifest. Supplied recording JSON remains
`self_supplied` at synthesis, even when acquisition came from RPC.

The independent reference evaluator models generated scope/count. It does not model the
reviewed spending policy's rolling state. This mode permits only that exact named gap, still
requires zero disagreements and no missing reference classes, and writes
`models_all_policies: false` plus `rule[0]: oz:spending_limit` into the pipeline evidence.
Unknown gaps or claims of complete modeled coverage are refused. Live cadence observations
remain separate from artifact reproduction.

The run journal and allowlisted summary preserve charge transaction IDs, simulation ledgers,
window cutoffs, actual refusal contracts/codes, partial outcomes and independent cleanup
results. These are editable local RPC observations, not authenticated ledger proofs. Monitoring
reads are non-atomic and do not cover the account's entire authority surface.

The harness uses throwaway test keys or an exportable virtual passkey. Its operator trust and
approval flow do not establish Pollywallet's protected human approval. The [20 October live evidence](TESTNET-EVIDENCE-TRANCHE-2.md#8-controlled-sep-41-subscription-run-20-october-2026)
records both charges, attributed controls and complete removal for a fresh controlled account.
Adopted wallet evidence remains separate from this harness execution.
