# Atomic live-enforcement helper

The `live_enforcement` layer has to show the candidate policy deciding a real call, through the
pinned account, against current network state. Simulating installation does not show that, and
a policy cannot be exercised by a simulation before it is installed. The helper contract in
[`contracts/atomic-live-helper`](../contracts/atomic-live-helper/src/lib.rs) closes that gap:
one invocation installs the candidate rule through the account's own `add_context_rule` and then
makes one native-asset transfer under it. An enforce-mode simulation of that invocation runs the
generated policy on live state, and nothing is installed because nothing is submitted.

This package is the helper contract, its real-Wasm host tests, a testnet deployment probed by
the harness, the wallet's validators of a live case, and the wallet's consented live check that
produces the `live_enforcement` layer. The helper is deployed on testnet and the harness has
simulated one permit and one denial through it with automation keys
([Testnet deployment](#testnet-deployment)). The validators decide what such a simulation must
show to count ([How live use is meant to work](#how-live-use-is-meant-to-work)). The wallet
prepares the two cases, gets the owner's consent and passkey signature, signs the delegate's part
and validates both enforce-mode simulations
([live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check)). Its
[22 October 2026 automation run](evidence/wallet-live-enforcement-testnet-2026-10-22.json) passed
against the deployed helper with a passkey owner on a fresh account. The result is state-dependent
simulation evidence for one grant shape. The wallet's
[installation](POLLYWALLET-INTEGRATION.md#installation) requires this layer to have passed on recent
evidence and the replay check to report the account unchanged.

## What the helper does

`install_and_transfer(candidate)` takes the account, the generated policy and its expected Wasm
hash, one delegate, the expected rule ID, the grant name and validity, a recipient and an
amount. In order, it:

1. refuses an amount outside `1..=1,000,001` stroops — the sample permit of 1,000,000 and its
   one-stroop adjacent denial case. This bounds only the transfer the helper executes, not what
   any signature authorizes (see [Signatures](#signatures-are-real-and-usable-without-the-helper));
2. derives the native asset contract of the executing network itself; there is no token or
   function argument;
3. refuses any two of helper, account, policy, delegate, recipient and asset sharing an address;
4. refuses a delegate that is not an existing classic account, an account not running the
   pinned `stellar-accounts` 0.7.2 Wasm, and a policy not running the expected candidate Wasm;
   the candidate must be a generated policy with a call cap (see step 6);
5. calls the account's `add_context_rule` with exactly one `CallContract(native asset)` rule,
   one `Delegated` signer and one policy, and refuses unless the account allocated the expected
   rule ID and returned exactly that rule (registry IDs are checked for count, not value);
6. reads the candidate policy's remaining call count for the installed rule, calls the asset's
   `transfer(account, recipient, amount)`, reads the count again, and returns the installed rule
   only if the transfer succeeded **and** the count dropped by exactly one.

Step 6 narrows, but does not close, how success can be reached without the candidate. The
transfer's own authorization names the rule it is checked against, and the owner's Default rule
needs no policy: an owner-signed transfer
under rule 0 moves even the adjacent 1,000,001 stroops without the candidate policy ever running.
That was reproduced against the previous helper, which then succeeded with the policy's counter
untouched; the host test `atomic_helper_refuses_a_transfer_not_authorized_by_the_candidate_rule`
now requires the refusal. The generated policy's `enforce` requires the account's own
authorization and counts only while the account checks some context under the rule the policy is
installed on, so a drop of exactly one shows that the candidate policy ran once for a context of
the transfer's authorization. It does not show that this context was the executed transfer. The
host hands every context of the signed authorization tree to `__check_auth`, executed or not, and
the account checks each under its own rule: an entry whose root is the executed 1,000,001-stroop
transfer, checked under rule 0, with a never-executed 1,000,000-stroop transfer as a
sub-invocation checked under the candidate rule, satisfies the guard while the candidate never
checks what moves. The host test `counter_guard_is_satisfied_by_an_unexecuted_candidate_context`
pins that limit. The helper cannot see authorization entries, so only the orchestrator can close
it (see below). A generated policy without a cap exports no counter; the helper then cannot
observe its execution and refuses rather than report success.

It has no storage, constructor, administrator, upgrade path, relay or arbitrary call surface; its
only export is `install_and_transfer`. It cannot authorize anything: installation needs the
account owner's authorization of `add_context_rule` and the transfer needs the delegate's
authorization under the new rule, exactly as without the helper. A denial is never caught, so it
aborts the invocation and the installation with it.

Refusals are contract errors 7001–7009: `AmountOutOfScope`, `AliasedIdentity`,
`UnsupportedDelegate`, `UnrecognizedAccount`, `PolicyCodeMismatch`, `UnexpectedRuleId`,
`InstalledRuleMismatch`, `UnobservablePolicy` (no readable counter) and
`CandidateRuleNotExercised` (the counter did not drop by exactly one). `InstalledRuleMismatch`
cannot be reached with the pinned account, which returns the rule it was given; the check stays
so that the helper never relies on that. The range keeps
clear of the asset contract's and the policies' small codes. An error a called contract raises
directly keeps its code — an already expired grant surfaces as the account's `PastValidUntil`
(3005) from `add_context_rule`, a failing transfer as the asset's own error. Any recoverable
failure inside an account's `__check_auth`, a policy denial included, is converted by the host
into `Error(Auth, InvalidAction)`. The helper calls the account and asset without `try_call`, so
that error propagates as is: a transaction or simulation invoking the helper fails with
`Error(Auth, InvalidAction)`. Only a caller using `try_call` — as the host tests do — sees it
narrowed to `Error(Context, InvalidAction)`. A refusal is therefore attributed by the contract ID
of its diagnostic `error` events, never by its code alone.

The helper declares its own copies of the account's `Signer`, `ContextRuleType` and
`ContextRule` wire types so that its contract spec describes its return value. Their encoding is
checked against the [shared ABI vector](examples/native-runtime-abi.json) by
`cargo test -p ozpb-atomic-live-helper` in the CI contracts job, and against the real account
Wasm in the host tests.

## What the host tests establish

`bash scripts/test-atomic-live-helper.sh` generates the candidate policy, builds the helper from
source, checks its export set, and runs `execution-runtime/tests/atomic_helper.rs` on a
protocol-29 host with the pinned account Wasm, the generated policy Wasm, the reviewed helper
Wasm (its hash is asserted) and the real native asset contract. Every authorization is a real
Ed25519 signature over its address-bound (`AddressV2`) preimage, by distinct synthetic owner and
delegate keys; no authorization is mocked. These are automated keys, not wallet or human
approval. The tests require:

- the permitted 1,000,000-stroop transfer installs rule 1, moves exactly that amount, advances
  the policy's call counter, returns the rule the account now stores, and leaves the helper with
  no state;
- the adjacent 1,000,001-stroop transfer fails (as `Error(Context, InvalidAction)` at the tests'
  `try_call`), carries the generated policy's `NoTupleMatched` (code 6) as a diagnostic error
  attributed to the policy contract, and leaves every ledger entry — installation, balances,
  nonces, counters — unchanged;
- a missing owner or delegate authorization, a delegate signing the installation, the owner
  signing the transfer, an altered signature preimage and an expired signature are refused with
  no state change and the same error a policy denial returns. What distinguishes them from a
  denial is that the policy raises no error. Where the cause is specific it is also asserted:
  the delegate signing the installation raises the account's `UnvalidatedContext` (3002), the
  owner signing the transfer its `UnauthorizedSigner` (3016), and the expired signature the
  signer's `Error(Auth, InvalidInput)` ("signature has expired"), all attributed to the account.
  For the missing and altered entries only the host's generic `Error(Auth, InvalidAction)` is
  available, which a policy denial also emits. An already expired grant returns the account's
  `PastValidUntil` (3005), attributed to the account;
- each reachable helper guard (errors 7001–7006) refuses with its own code and no state change,
  including an unexpected rule ID after a valid installation;
- a transfer authorized by the owner under the Default rule 0 instead of the candidate rule is
  refused with `CandidateRuleNotExercised` and no state change, for both the permit and the
  adjacent amount, and the policy raises no error;
- a candidate policy generated without a call cap is refused with `UnobservablePolicy`.

The tests are `#[ignore]`d in the ordinary `cargo test` run because they need freshly built Wasm.
The scheduled source-build job runs the script through
`scripts/test-pinned-account-authorization.sh`, on the aarch64-apple-darwin host the account pin
needs; the helper hash was recorded on the same host and toolchain.

## How live use is meant to work

Each live case is one atomic simulation from unchanged network state: the captured permit
(`target:original:0`), and separately the amount plus one stroop (`target:argument-denial:0`),
expected to fail with `NoTupleMatched`. This is two named cases, not the derived deny suite; it
cannot stand in for anything the reference, account-Wasm or captured-target layers must cover.

Preconditions, which the wallet's [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check)
establishes before anything is signed: the helper and candidate policy are already deployed and
their code is read back and matched to reviewed hashes; the delegate is a funded classic account
whose signer settings are checked; the wallet shows the owner both exact calls, the expiry and the
replay warning and gets explicit consent before any signature exists. Only `simulateTransaction` in
enforce mode is used, never `sendTransaction`. The wallet builds every authorization itself; a
recording-mode simulation is never used for them and is never evidence.

Helper success is evidence only together with what the orchestrator checks itself.
`validateLiveCase` in [`wallet/shared/live-enforcement.mjs`](../wallet/shared/live-enforcement.mjs)
makes these checks from the approved case, the exact transaction that was simulated and the RPC's
raw enforce-mode simulation result, its XDR still base64. It returns `permit`, `deny` or `failed`
with a reason. Only `permit` and `deny` are evidence:

- the simulated transaction is one call of the helper for exactly the approved case, on the
  testnet native asset, which the validator derives rather than accepts;
- the account's authorization entry for the transfer has the exact transfer as its root and no
  sub-invocations, its `context_rule_ids` are exactly `[expected_rule_id]`, and its signers are
  exactly `{Delegated(delegate)}`;
- the owner's entries cover only the installation, with the approved arguments and under the
  owner's rule. Each delegated signer's own entry authorizes exactly the digest of its account
  entry, and there is no other entry. Every entry expires at the approved ledger;
- a permit's ledger changes are exactly these and nothing else: the account's and the recipient's
  balances, by the amount; the installed rule with the account's bookkeeping for it (next rule ID,
  rule count, and the delegate's and policy's registry entries); the candidate policy's
  installation marker and its call counter for that rule and account, used once; and the nonce of
  every entry, consumed once. The helper must return the rule the account stored. A simulation
  that would restore archived entries is refused.

A denial requires a top-level `Auth/InvalidAction` failure and rejects conflicting account
errors in the printed log or transfer authorization events. It needs the `NoTupleMatched` error
attributed to the candidate policy inside the asset's failed authentication of the account, with
no ledger changes. It is read twice: from the printed
event log as the harness reads it, matched only where the log starts an event so that a value it
prints verbatim, such as the rule name, cannot pass for one, and from the structured diagnostic
events. A helper refusal such as `CandidateRuleNotExercised` is not a policy denial and settles
nothing about the policy, and neither is an account error.

A failed simulation reports no ledger changes, and a permit's nonces tie it only to the entries'
address and nonce pairs, so the response is bound to the envelope through its diagnostic events,
which the RPC returns for a failed simulation too. In the order the host records them, they must
show one top-level helper call with exactly the approved candidate, then the account's `__check_auth` for the
installation and then for the transfer, once each, with that entry's signature payload (which
covers its nonce and expiry), its signature and its contexts. Only the host's diagnostic events
count; a contract can emit any topics as a contract event. For a permit every event comes from a
successful call, and the result must echo exactly the envelope's four entries, which is what binds
the classic signers' own entries. For a denial every event comes from a failed call, the helper
never returns, and the policy's error follows the transfer's check and precedes any return of it. A
failed response echoes nothing, so a denial vouches for the helper call and the account's two
entries but not for the classic signers' entries, although `envelope_xdr_sha256` covers their
bytes. The validator does not verify signatures, which the simulation's host did, and it neither
signs nor simulates anything. Its tests use the addresses, amounts, rule and ledgers of the
[testnet probe](#testnet-deployment) with entries, ledger changes, errors and events constructed in
the shapes the probe and the host use. They also run it over real responses: a second,
simulation-only probe the same day reused the deployed helper with a fresh throwaway account,
automation keys and a new candidate, `CDTRH2NIFBKASKAF3FA2NCEYJ65O4XXI6NUPWDW6J4T3JYBHOLEYCHKF`,
and kept the RPC's raw responses as
[`wallet/tests/live-enforcement-testnet.json`](../wallet/tests/live-enforcement-testnet.json), with
the two classic signer entries' Ed25519 signatures zeroed. On them the permit validates as
`permit`, the adjacent amount as `deny`, and each case with the other's response as `failed`. The
real responses matched the shapes the validator expects: the permit result echoes the four supplied
entries, the fresh account's permit writes fourteen entries including the four nonces, and the
denial's events, all from failed calls, are returned alongside its error. The owner must never be
asked to sign the transfer: an owner-signed transfer under rule 0 is a real transfer that no policy
checks, should the signatures ever be submitted.

## Signatures are real and usable without the helper

None of the four authorization entries a case needs names the helper. The owner's account entry
is rooted at the account's `add_context_rule` and its signer entry at the account's
`__check_auth`; the delegate's account entry is rooted at the asset's `transfer` and its signer
entry likewise at `__check_auth`. Each is valid on its own, so the set signed for the permit case
is a real, submittable installation of the candidate rule followed by a real 1,000,000-stroop
transfer. The host test `permit_case_authorizations_install_and_transfer_without_the_helper`
submits the first two entries to `add_context_rule` and the other two to the asset's `transfer`
directly, and both succeed. Simulating the set as a helper invocation does not change what was
signed.

The entries cannot be bound to the helper with the pinned account. A single helper-rooted
account authorization would be checked by the account once, at installation, before the rule it
needs for the transfer exists; and the host does not start a second, independent root for the
same address while a helper-rooted one is active.

So the helper's amount bound and identity checks constrain only what the helper executes. The
wallet must enforce the amount, recipient and a short expiry before it signs, and treat consent
to a live case as consent to that installation and that transfer actually happening, for as long
as the signatures are valid. The consent screen has to say so.

## Testnet deployment

[`testnet-harness/scripts/deploy-live-helper.mjs`](../testnet-harness/scripts/deploy-live-helper.mjs)
deploys the helper on testnet and probes it once each way. It pins the testnet passphrase and
refuses an RPC serving any other network before it builds, funds or signs anything. It:

1. builds the helper with `stellar contract build --locked` and refuses unless the Wasm's SHA-256
   is `EXPECTED_HELPER_HASH` from the host tests. Reproducing it needs the pinned rustc and
   stellar-cli on the aarch64-apple-darwin host the hash was recorded on;
2. runs the harness's own steps, as `run.sh` does: setup with Friendbot keys and an ed25519 owner,
   a real owner transfer of 1,000,000 stroops under rule 0, and record → synthesize → generate →
   verify. The candidate is a generated policy capped at one call, for exactly that transfer by
   a separate delegate;
3. uploads and deploys the candidate policy and the helper, refusing unless the network stores
   the reviewed bytes and each instance reads back with that code hash;
4. builds the four authorization entries itself, never from a recording simulation, with
   signatures that expire 12 ledgers later, and runs one enforce-mode simulation of
   `install_and_transfer` per case. Nothing is submitted for either case. The owner's and the
   delegate's `__check_auth` entries carry classic (V1) address credentials, as elsewhere in the
   harness, where the host tests sign all four entries as `AddressV2`;
5. requires the permit case to return rule 1, to have the account store that rule, to change no
   balance except the account's (down exactly 1,000,000 stroops) and the recipient's (up by the
   same), and to create the candidate's installation with its call counter used once. The denial
   case must fail with `NoTupleMatched` (6) raised by the candidate policy's contract ID inside the
   account's failed authentication. A helper refusal (7001–7009) or an account error fails the
   case; neither counts as a denial;
6. waits until every case signature has expired, then reads back that the account's balance is
   unchanged and that the candidate reports no installation;
7. only then writes public addresses, hashes, ledgers and outcomes, never keys or signed entries,
   to `docs/evidence/atomic-live-helper-testnet-<date>.json`. It deletes the throwaway keys on
   success, on failure and on SIGINT, SIGTERM or SIGHUP. A signal stops the active harness
   subprocess and its process group, waits for the child to close, and then deletes the keys;
   no later harness step runs. Repeated signals cannot bypass that cleanup.

### Current SDK 28 helper deployment

The [28 October 2026 receipt](evidence/atomic-live-helper-testnet-2026-10-28.json) records the
current helper at `CBFSOXRVL4KTZJD6JAIBB7EHRQKOFYKMXQX6YMCLONAS45RQ77MKNOOA`, read back at
ledger 5435087 with the current `EXPECTED_HELPER_HASH` / wallet helper pin. Configure new
wallet live checks with that address, subject to their fresh code/liveness checks. Its instance
was live until ledger 5556046 and code until 5556045 when observed, before the extension
[below](#keeping-the-helper-live); these are observations, not a promise that the contract
remains live.

The original 1,000,000-stroop simulation permitted and the adjacent amount was denied by the
candidate policy's `NoTupleMatched` (6). After signature expiry at ledger 5435099, readback at
5435100 showed unchanged balance and no installed candidate. The receipt retains code revision
`5c7ec41a9d84e07ce1131dc5c018f3ef76ce806c`, script/tool identities and `checkout_dirty: true`.
It is automated, state-dependent simulation evidence, not human approval or a clean-clone
release attestation. The throwaway keys were deleted.

### Historical SDK 26 deployment

The [21 October 2026 run](evidence/atomic-live-helper-testnet-2026-10-21.json) deployed the
older SDK 26 helper as `CC4KNOAXRNRQNQKZ4ZOH65W6TTK4DN7FYJIB6VI7KQ6ZOCKFQFVS556V`.
Its historical receipt carries that build's hash; it does not match the current helper pin
and must not be used for the updated wallet configuration. Both cases were simulated at
ledger 5316206 against the candidate
`CD6RHN5HQ6ZRZ3DTFCNPLDJWPDZXOSWX7TDOYHIWDDUTA6Y5IOVKZQWS`, on the throwaway account
`CDQLZKNQHQGHZPIS4GATWI2XTLQVEVF47IETQQMWNV3QRGKBA6KD2L24`:

- the permit case returned rule 1, moved exactly 1,000,000 stroops from the account to the
  recipient, and used the candidate's one call;
- the adjacent case failed with `Error(Auth, InvalidAction)`. The candidate policy's own contract
  ID raised `NoTupleMatched` (6), inside the account's failed authentication. The policy runs
  below the helper (helper → asset `transfer` → account `__check_auth` → policy `enforce`), and
  attribution by contract ID survives that nesting, as it does at top level.

After the last case signature expired at ledger 5316218, the account's balance was unchanged and
the candidate reported no installation. When deployed, the helper's instance entry was live until
ledger 5437165 and its code entry until ledger 5437164, about a week of testnet ledgers. After
that the helper is archived and the script has to be run again. The evidence's `script_sha256`
is the script as committed with it; the script was later restructured so that its gates and key
handling are unit-tested, without changing what a run checks.

This is a harness probe, not the live layer. The keys are throwaway automation keys held by the
script, and no owner saw or approved anything. Each outcome describes testnet state at its
simulation ledger. The signatures were real until they expired, as described
[above](#signatures-are-real-and-usable-without-the-helper). They went to the testnet RPC endpoint
inside the simulation request, and the script neither prints nor stores them.

### Redeploying after a testnet reset

A testnet reset removes the helper, the candidate, the pinned account code and every account
built on it. To deploy again:

1. Upload the pinned account Wasm, which `setup.mjs` deploys from its hash but never uploads.
   `OZPB_VERIFIED_ACCOUNT_WASM_OUT=<file> bash scripts/verify-pinned-upstream.sh` rebuilds it and
   checks the bytes against the pin; then
   `stellar contract upload --wasm <file> --source <funded testnet key> --network testnet`.
2. Run, from the repository root on the pinned build host:

   ```
   npm ci --prefix testnet-harness/scripts
   OZPB_BIN=<built ozpb> node testnet-harness/scripts/deploy-live-helper.mjs
   ```

   It uploads the helper and a fresh candidate itself and needs nothing else from before the reset.
3. Commit the new evidence file and replace the contract ID above; the old one is gone.

The script always deploys a new instance. It never restores an archived one. Once the helper has
been archived, step 2 deploys a new instance; whether its archived code entry has to be restored
first has not been tried.

### Keeping the helper live

The wallet reads the helper's instance and code entries before every live check and reports the
layer `unavailable` when either is archived or stays live only until the check's signatures would
expire, naming the ledger. Nothing in this repository extends that lifetime automatically. Before
it ends, an operator can extend both entries with the Stellar CLI, from any funded testnet key:

```
stellar contract extend --id <helper contract ID> --ledgers-to-extend <ledgers> \
  --source-account <funded testnet key> --network testnet
stellar contract extend --wasm-hash <EXPECTED_HELPER_HASH> \
  --ledgers-to-extend <ledgers> --source-account <funded testnet key> --network testnet
```

The first extends the instance, the second the code, whose hash is `EXPECTED_HELPER_HASH`. On
3 November 2026 both ran against the current helper
`CBFSOXRVL4KTZJD6JAIBB7EHRQKOFYKMXQX6YMCLONAS45RQ77MKNOOA`, with `--ledgers-to-extend 518400`
and `--network testnet`, from a funded testnet key; testnet was on protocol 29. Transaction
`14bdcc3afa12419e65b6d22b809dce8895057546632b19fd3c7155f912d4b7a3`, at ledger 5536754, moved the
instance from live until ledger 5556046 to 6055154; transaction
`64ab7170d827e1f0af12b374ec8a0b1df255e022fe5de9bdeaa45b6486724aed`, at ledger 5536756, moved the
code from 5556045 to 6055156. That is about 30 days of testnet ledgers, and the values are what
the transactions wrote, not a promise that the entries stay live. An entry that is already
archived would have to be restored first (`stellar contract restore`), which has not been tried;
deploying again ([above](#redeploying-after-a-testnet-reset)) is the tested path. Either way,
update the operator's `liveHelper` if the contract ID changes.

## Outstanding

- A live check with a human owner's passkey; the automation run uses a virtual authenticator.
- Grant shapes beyond one exact native transfer of at most 1,000,000 stroops, and the derived
  deny suite, which the two named cases do not stand in for.
