# Testnet and runtime evidence — Tranche 2

This record separates historical testnet observations from checks a reviewer can run on the
current revision. It does not establish completion of the Phase 2 outcome in
[architecture §10](architecture.md#10-delivery-plan). The first milestone's observations
remain in [TESTNET-EVIDENCE.md](TESTNET-EVIDENCE.md), sections 1–3.

The [testnet harness](../testnet-harness/README.md) is the executable source for the install
flow. Its run records are local observations, not authenticated ledger proofs. The
[scope map](SCOPE.md) names the remaining requirements. The 15 October observations predate
later installer fixes; sections 8 and 9 record the controlled 20 October W2 and W3 runs.

## 4. Pinned account, passkey owner, and generated policy

On 2026-10-15, the harness recorded an accepted testnet run with a passkey-owned account and
the optional authority-check flow. The account was
`CARMB4NCOKFT4NGSWANUIIVHVFPIT4IFQTGCCZQXSDKKWZDHPMLBLH43`; the generated policy was
`CCWIX4Z7WDOTMGLLE3DJ3ZMC57NZAEDNSFRRX72B5VFDMLX3KX6FQ7ZR`.
The earlier run and its limitations are also described in
[the harness change](https://github.com/gateway-fm/oz-policy-builder/pull/58).

| Step | Recorded observation | Limit |
| --- | --- | --- |
| Account and verifier | Setup read back the deployed account and WebAuthn verifier code hashes and compared them with the harness pins. | Recognition is tied to those builds; it does not cover arbitrary wallet accounts. |
| Recording | The owner authorized a transfer, whose transaction was imported from raw XDR. | Imported evidence is `self_supplied`; this was not the live RPC recorder followed by synthesis. |
| Spec and generation | A checked template described that exact transfer, with a separate delegate and a one-call cap; `ozpb generate` built it. | The spec was filled from the recording by the harness, not produced by `ozpb synthesize`. |
| Authority and wallet decision | The wallet accepted the intent, then required a matching commitment on the recheck at ledger 5213154, after the first observation at 5213153. | Trust was operator-supplied test configuration; `--confirm operator` provided no human approval prompt. |
| Installation | The passkey signed `add_context_rule`; the harness recorded successful installation. | The passkey was an exportable software credential in Chrome's virtual authenticator. |
| Delegate permit | The exact transfer was submitted successfully once. | This is one account, policy, and transfer, not the three required protocol walkthroughs. |
| Delegate denials | Wrong amount and recipient returned policy code 6; a second exact transfer returned code 7. | These were enforcing simulations, stopped before transaction submission. They have no failed on-chain transaction hashes. |
| Passkey negative control | A signature over the wrong challenge returned verifier code 3114. | This exercises the verifier path; it is not evidence of hardware-backed key custody. |

The recorded install transaction is
[`89c5c181f108682c4f19e1908f17f8926ceae3e16bfa04ba657107a380cc8da6`](https://stellar.expert/explorer/testnet/tx/89c5c181f108682c4f19e1908f17f8926ceae3e16bfa04ba657107a380cc8da6).
Testnet retention and resets can make a historical identifier unavailable; this document does
not claim a fresh network verification of it.

A separate run added an owner rule for an account the wallet did not trust. The recorded
wallet decision refused that authority. Its saved record contains no install transaction or
installed rule ID. The run used a one-off setup script to add that owner, so it is not a
fully reproduced refusal scenario in this tree. A missing install record alone cannot prove
that nothing was submitted. The older installer also did not persist the policy deployment
before refusal; the current installer does.

Both saved records can be read by the evidence exporter, which reports their provenance as
`unavailable`. They were created before checkout and CLI identity capture existed. The
earlier PR records the authority CLI revision used, but a new export must not fill that
metadata in as though it had been captured by the run. These runs do not test the later
manifest/spec consistency fixes, composed-rule refusal, or deployment-checkpoint changes;
those changes have their own offline regression tests.

The default harness creates the account itself and does not ask for an authority verdict.
The optional path requires an `ozpb` binary containing `check-policy-call-surface` and
`prepare-install-intent`; both commands are included in this checkout. Build the selected
binary from the revision being tested and configure its trust inputs as the harness README
describes. An external CLI digest identifies the selected binary; it does not attest to its
source revision.

## 5. Browser and wallet observations

The [browser harness record](../testnet-harness/browser/README.md) describes two headless
pollywallet runs on 2026-10-15. Its real page registered one resident credential per run and
showed a new wallet address. The committed
[screenshot](../testnet-harness/browser/media/pollywallet-wallet-created.png) is from the
second run. These observations establish wallet creation through that UI, not policy
installation into that wallet.

The account and verifier used by that deployment differ from the toolkit's pinned builds.
The separate pinned-account harness signs and installs with the same kind of passkey owner,
but does not use pollywallet's protected approval screen or backend. Browser registration,
off-chain assertion verification, pinned-account installation, and wallet-product integration
are distinct evidence claims. A successful first three does not establish the fourth.

## 6. Reference evaluation and MCP

The current CLI and MCP expose `reference-suite` / `reference_suite` for layer-1 evaluation,
`verify` for artifact reproduction, and `prepare-dry-run` / `prepare_dry_run`, which binds
candidate evidence and reports the account-Wasm, captured-target and live layers as
unavailable. Both also expose recording, synthesis, generation, exact-envelope preflight,
installed-rule prediction, the authority check, install intents and unsigned install
assembly; [DEVELOPERS.md](DEVELOPERS.md#mcp-server) lists the MCP tools. A reference result
does not establish target execution, live preflight, or successful installation. An older
observation labeled `dry_run` cannot be used as evidence for an operation that the current
server does not expose.

Run the existing MCP verification integration tests with:

```bash
cargo test --locked -p ozpb-mcp-server --test mcp_stdio_verification
```

Those tests cover the `reference_suite`, `verify` and `prepare_dry_run` schemas, reference
responses and structured errors. They do not deploy a hosted endpoint or complete a
successful real-builder `verify` round trip.
The [Phase 2 verification guide](TRANCHE-2-VERIFICATION.md) describes the focused automated
gate included in this tree. The evidence exporter can run independently of that gate.

## 7. Capture and review a new run

The current wrapper uses `ozpb record` for the owner's confirmed transfer, then runs real
synthesis with explicit bounded test decisions, the reference suite, generation and
artifact verification before installation. It refuses incomplete reference coverage,
disagreements and any reproduction mismatch, including a zero-exit `verify` response with
`matches: false`. It preserves the RPC recording bytes and the full synthesis/reproduction
reports locally. This new executable path does not retrospectively change the historical
manual-template observations in section 4. Section 8 records the later subscription run.

The wrapper now also observes the installed grant's configuration, removes it through owner
authorization and requires a post-removal delegate denial from the account's missing-rule
check. It verifies the pinned removal event and records policy cleanup separately, because
the account's uninstall calls are best effort. Section 8 records these lifecycle observations;
they do not demonstrate a delivered wallet's protected revoke screen.

Use the harness README's prerequisites and its explicit testnet commands. Choose an empty
output directory. The harness spends testnet XLM, creates contracts, and uses throwaway keys.
For an authority run, configure the compatible CLI, signed snapshot, roots, RPC sources and
wallet confirmation mode as described there before starting.

`run.sh` writes `provenance.json` at startup and finalizes it on shell exit. It attempts an
evidence export after successful or failed steps, publishing complete `evidence.json` files
by atomic rename. A reporting error changes a zero exit to failure in the provenance too;
an original failure keeps its own code. Malformed records (including JSON `null`) are refused,
and an I/O error can prevent an output file. A hard kill can leave provenance unfinished.
To regenerate a summary without network access or keys:

```bash
node testnet-harness/scripts/evidence.mjs --run-dir /path/to/run --write
```

`--write` uses the same atomic publication as the wrapper: validation happens before the
previous report is replaced, and output symlinks cannot redirect the write to another file.

Review these fields before sharing the summary:

| Evidence | What to check |
| --- | --- |
| `provenance` | Checkout commit and dirty state, start/finish times, exit status, Node version, Cargo mode or the external CLI byte digest. These describe startup; they do not detect later edits or prove the external binary came from the checkout. |
| `run` | Expected testnet account, target, owner kind, delegate, policy hash, rule and expiry. No `run` means setup did not save one; it is not a successful empty run. |
| `run.transactions` | Recorded deploy and install transaction identifiers. An install record requires both its transaction and rule ID. Deployment can precede a refused wallet decision. |
| `run.authority` | `rechecked`, `refused`, or `not_recorded`. The last means no decision was recorded, not that an account is safe. Refusal text and operator identities are omitted from this summary. |
| `run.invocations` | Separate owner controls from delegate calls; inspect arguments, selected rule, result and error attribution. A null denial code is not an attributed policy refusal. Simulation denials have no transaction ID. |
| `pipeline` | A `recorded` completion record describes the new CLI chain. Check the distinct RPC acquisition and `self_supplied` synthesis identities; trust downgrade changes the recording hash. Artifact reproduction remains separate from current-network preflight. Older runs say `not_recorded`. |
| `lifecycle` | Check removal transaction, event, absent-rule and policy-cleanup observations separately. Configuration reads carry distinct RPC ledger numbers and are non-atomic; a match covers the recorded rule and code pins, not the whole authority surface. `post_revocation` invocation controls retain their actual result, including a failure to obtain the expected denial. |
| `derived_denials` | W1, W2 and W3 only. The exporter rebuilds the replay's plan from the retained run, spec and emitted suite, and refuses a journal that names other cases, offline reasons or expected enforcers. Check that `suite.spec_hash` is the pipeline's, that each original is `permitted` and each case's `observed` enforcer and code equal its `expected` ones, and read `offline` for what was not replayed and why. `live_stand_in` marks a case realized by a control's live equivalent (W1's pool `submit`, W2's control token). Labels say post-install, state-dependent, simulation-only, never submitted. |
| `artifacts` | Digests of available run, provenance, spec, recording, import bundle, manifest and Wasm bytes, and the emitted suite (`derived_cases`). Missing artifacts remain missing. JSON file digests are not canonical spec hashes. |

No field makes the summary an acceptance verdict. The exporter checks types and selected
consistency relationships, not the truth of a file supplied by another person. It does not
reproduce a build, fetch transactions, prove account-state freshness, or verify every
historical invocation against the current installed policy. Retain the raw artifacts locally
for deeper review. Do not publish the secrets file or a whole run directory: free-form logs,
raw errors and operator configuration are outside the export's allowlist. The summary still
exposes public account relationships and must be reviewed before publication.

### What a passing permit/deny report is

A walkthrough's permit/deny report passes when both of these hold:

- **The original call is permitted.** The delegated positive is confirmed, and the spec's suite
  original, replayed on the recorded call, is permitted in simulation.
- **At least five denials are refused.** They come from that spec's own layer-1 suite,
  identified by its suite hash and emitted from the installed spec, not from hand-written
  controls. Each is refused in an enforcing simulation against the installed rule by the
  enforcer its class predicts, attributed by contract id. The report names the expected and
  observed enforcer for every replayed case and lists every other case as offline (layer 1).

The scope is narrower than "the suite":

- The denials are simulations after installation, observed at their reported ledgers; nothing is
  submitted.
- Time, call-count, missing-state and strict-signer-set cases need ledger or installation state
  the live grant does not have, so they stay offline (layer 1).
- So do mutations the target rejects before the account is asked to authorize: arity, type
  confusion, or a value of another type.
- So does replacing the argument that asks the account to authorize, which moves the
  authorization off the account.
- The suite's undeployed contract address and absent function name are realized live only where
  a control has already shown a live equivalent.
- An unrecognized signer alone and the delegate plus an unrecognized signer stop at the same
  account check. Both count toward the five, so W1's five suite cases are four distinct checks.
- The report lists every offline case by class and reason. The
  [harness README](../testnet-harness/README.md#derived-denials) gives the selection rule.

## 8. Controlled SEP-41 subscription run, 20 October 2026

The [allowlisted run summary](evidence/testnet-subscription-2026-10-20.json) records a complete
W2 harness execution from 10:21:26 to 10:28:44 UTC, with a clean checkout at
`0fdb55c274d474ef641022502ccfbe25289f9cd3`. The external CLI digest is retained in its provenance;
that digest identifies executable bytes, not a source attestation. The owner was an exportable
virtual passkey, and confirmation used the explicit operator mode without a human prompt.

The selected account was `CDSWQ6MBK6UICYCSYWNTTLP3RQ27BQKCU435LBBHPXQ3XLXPB53OFCVC`.
Its grant composed an exact 1-XLM transfer to one controlled merchant, a two-call lifetime
cap, and the pinned spending policy with a deliberately short 24-ledger test window.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | A confirmed owner transfer went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [Transaction 5fcaab10…d615](https://stellar.expert/explorer/testnet/tx/5fcaab10e09e28a0bad514683962cfd01827d0846ea3f3a2a744aeb123d3d615) installed rule 1 after the authority commitment recheck at ledger 5293646. Both policy configurations matched. |
| Tuple and signer controls | Larger amount, split charge, other merchant, funded other token, wrong signer and empty signer set all produced attributed enforcing-simulation denials before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/2538c174dfbbd730c4ccaa8cdf52fd9ed03156af8b22531836db3bbd55156ec9) confirmed at 5293653. The immediate repeat returned spending-policy code 3221 at 5293653, strictly before cutoff 5293677. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/4a33492fb9ad6d65a73e07e428a8470fb46c085a1f2e3c1d5d510a6f2252c347) confirmed at 5293681. After another full window, generated-policy code 7 was observed at 5293705. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/b924cc544bc958077990718d8c10728f0cd8f4f88a98e748a31020486f3261e6) confirmed at 5293707. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5293707. No negative-control fee transaction was submitted. |

All 12 subscription control steps completed and the wrapper finalized with exit 0. The
reference evaluator still does not model the reviewed spending policy's rolling state;
the summary retains that exact gap. These remain editable local RPC observations, with
non-atomic reads and no ledger proof or protected wallet-approval claim.

A separate earlier failed attempt installed rule 1 on
`CDL6OEBK7K36WJCUPE3UC6AQF3CPNVNGU57SHYIN7SGVYXSEUEMDVEJL` and stopped during a negative
control before charging. No removal was confirmed before its throwaway keys were discarded;
its configured expiry is ledger 5310498. The completed run above does not revoke that earlier
grant. The current wrapper attempts bounded owner removal before discarding keys after a
failure, retaining pending or incomplete removal evidence without automatic resubmission.

## 9. Controlled Soroswap swap runs, 20 October 2026

Two complete [W3 harness executions](WALKTHROUGH-PROTOCOLS.md) ran that day. The second adds
the transfer rule's own denials; the first predates them.

### Earlier attempt

An attempt before both runs, on `CDAPJPE5Y4LL5CSSKAHSRWVRDFEQDGOD7AKHNQBF7T5HF55AGJZU5CYD`,
deployed both policies but installed neither: the harness wallet refused the first rule because
it expected only that rule's policy in an answer covering the whole bundle. The wrapper's cleanup
reported no installed grants. Both runs below include the installer fix.

### First run: router-rule denials only

The [allowlisted run summary](evidence/testnet-soroswap-2026-10-20.json) records a complete
[W3 harness execution](WALKTHROUGH-PROTOCOLS.md) from 12:00:08 to 12:16:14 UTC, with a clean
checkout at `610a196fc7543126a914c20ba583291178d90636`. The external CLI digest is retained in its
provenance. The owner was a throwaway ed25519 key, and both rules were approved in the explicit
operator mode without a human prompt.

The selected account was `CBSCLOU6CGH5DVIFL2K7KZHOPZNSQRKLI4ZIESVAMOG6S3D6XXZ27Z7E`. The grant
was two independent one-call rules from one spec, both valid until ledger 5294992: the router
rule (account rule ID 1) for the swap, and the transfer rule (ID 2) for the native-XLM transfer
to the exact pair. The account's owner rule is ID 0.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/8e075309901d4508b6d12929cd3aa1b93c22b8279a81505029612796760175f7) of 0.1 XLM confirmed at 5294812 with 175656 output units and a matching balance increase. It went through the real RPC recorder, synthesis, the 63-case reference suite, and generation/build with matching source/Wasm/manifest reproduction for both rules. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/d20dabfd95bb1bfcb341749be65d450a7af4c62bfb8e55603b01cb61625e523c) was checked at 5294817, rechecked before signing at 5294818 and read back matched at 5294819. The [transfer rule](https://stellar.expert/explorer/testnet/tx/02bf33a1b07bf699778ff1703c676f638bc9af1054629d1763fe0cbf44a12b61) was checked and rechecked at 5294822 and read back matched at 5294824. Each answer covered both bound policies. |
| Swap controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6. A wrong signer returned the account's 3016; an empty signer set returned the router-rule policy's code 1. |
| Independent transfer authority | A direct transfer to the pair under the transfer rule alone was permitted in simulation at 5294828, as disclosed. It was not submitted. |
| Delegated swap and count cap | [Delegated swap](https://stellar.expert/explorer/testnet/tx/868a99476333c25620f6f1e725a1c55d625eeef7b6386cacdd9ed07d193aa9c7) confirmed at 5294830 with 175656 output units. The repeat returned the router-rule policy's code 7 at 5294833. |
| Expiry | After the wait reached ledger 5294993, the account returned `UnvalidatedContext` (3002) at 5294995. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/ea7ac2b0a21688bc86dd78a5e531d9b53ef7ce0bed715b0c356aeadf869ed1d2) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/26970d5b278688bc82e9aa3ff667a19634234b010c36b89032a565d4c850e800) confirmed at 5294996 and 5294997. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5294997. No negative-control fee transaction was submitted. |

All 12 control steps of that run completed and the wrapper finalized with exit 0. The run
predates the two transfer-rule denials (a direct transfer above the cap, and one after the swap),
so no denial in it is attributed to the transfer rule's own policy; the summary labels its
control set `router_rule_denials_only`. The widenings were fixed by the harness's synthesis inputs,
with no per-run acknowledgment; no reviewed Soroswap adapter was involved. These remain editable
local RPC observations, with non-atomic reads and no ledger proof or protected wallet-approval
claim.

The committed summary was re-exported offline from the retained run directory after the exporter
gained per-rule authority and readback fields; the wrapper's own export at the time omitted them.
The run files, provenance and exit status are unchanged.

### Second run: full control set

The [allowlisted run summary](evidence/testnet-soroswap-transfer-controls-2026-10-20.json) records a
complete W3 harness execution from 13:08:57 to 13:25:34 UTC, with a clean checkout at
`fea559868fa957576993d6112439ec5fd5ac6d98` and control set `transfer_rule_denials_included`. The
owner was again a throwaway ed25519 key, and both rules were approved in the explicit operator
mode without a human prompt. The summary is the wrapper's own export.

The selected account was `CD5KAVYCDHMS4D6QQ2BCF5646J3KMYMAWUDXAGV6SBDFULKGLC4PFL3H`. Both rules
were valid until ledger 5295820: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/05d8fa675d2578346154c4babaf5b24ee81ab95fd83d815f39687951284b3292) of 0.1 XLM confirmed at 5295640 with 175274 output units and a matching balance increase, then the real RPC recorder, synthesis, the 63-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/133442ee26839673fa77a59dd1d976a0d0784ca119116be64cd295c4e7906229) was checked at 5295649, rechecked at 5295650 and read back matched at 5295651. The [transfer rule](https://stellar.expert/explorer/testnet/tx/05799950a7ee894e96f49aec0abadc75efde257c35fa45692d6c0eb82f7e1dea) was checked at 5295651, rechecked at 5295655 and read back matched at 5295656. |
| Router-rule and signer controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6; an empty signer set its code 1. A wrong signer returned the account's 3016. |
| Transfer rule alone | A direct transfer to the pair was permitted in simulation at 5295661, as disclosed, and not submitted. A direct transfer one unit above the cap returned the transfer-rule policy's code 6 at 5295662. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/146cd502db654587d1d62d6f1434e74d79c9d95013d2762390885c7dc1cb1b7e) confirmed at 5295663 with 175274 output units. At 5295663 a repeat swap returned the router-rule policy's code 7, and a direct transfer returned the transfer-rule policy's code 7: the swap had spent both rules' one call. |
| Expiry | After the wait reached ledger 5295823 (target 5295821), the account returned `UnvalidatedContext` (3002) at 5295823. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/41caba90fbcb5c22a3bca6c445ba250d9e0aa39393d886fee78786744d504def) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/a7f56018934690ca6454641d4ebeb69f063241f9d2b8267bb0ff0ce80cc06987) confirmed at 5295825 and 5295829. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5295829. No negative-control fee transaction was submitted. |

All 14 control steps completed and the wrapper finalized with exit 0, deleting the throwaway keys.
The same limits apply as for the first run: fixed harness widenings, no reviewed adapter,
editable local RPC observations, non-atomic reads, no ledger proof and no protected
wallet-approval claim.

## 10. Controlled Blend claim run, 21 October 2026

The [allowlisted run summary](evidence/testnet-blend-claim-2026-10-21.json) records a complete
[W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 18:06:42 to 18:34:33 UTC, with a
clean checkout at `8772eddb83bbf16bcd59fc6b8114a3499c3fa884`. The CLI was an external binary
built from this branch's Rust sources, which are unchanged through that commit; its digest is
retained in the provenance. The owner was a throwaway
ed25519 key, and the single rule was approved in the explicit operator mode without a human
prompt. The summary is the wrapper's own export.

The selected account was `CDFLU7GBCURFJC6RA4XP2ZOZHUTJ6CETXBFSBGBNCWJUKKI56EE4GUDS`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the Blend v2 pool
`CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW`, valid until ledger 5316809. ID 3 is
the bToken (supply) ID of the pool's Circle testnet USDC reserve. The owner rule is ID 0.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary; everything else in the table is in the summary.

| Observation | Recorded result |
| --- | --- |
| Emission and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was live until 26 October 2026, 04:23:27 UTC; the read-only preflight passed at 5316491, with an expected owner claim of 210 BLND base units and a quote of 213647060 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/48475f8d7ff5128e7a23292331f8bd1562e4742d2847c59592c8ae511c34a433) exactly 100000000 USDC base units (10 USDC, request type 0) at 5316494. *(journal)* The swap returned 213647060 USDC base units, and the readback showed one USDC supply position of 99888711 bTokens. |
| Owner recording and artifact chain | After a 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/81954cb3585bd5b26a373d37fa0c9502e3464bc2436b49a74c8421c6099c4fbf) confirmed at 5316509 with 262 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/c0c3c10cccb1f423efffcd1c6c1e32fd4af8b3a05946a7c5ef0f0b626f5ff6d7) was checked and rechecked at 5316515 and read back matched. *(journal)* It was installed at 5316517. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6 (`NoTupleMatched`); another pool function (`submit`) returned its code 5 (`FunctionNotAllowed`). A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. The foreign recipient is a contract address that holds nothing; nothing was sent to it. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/4e987cf5f5d3030afe9d044518c26c18edfdb5aa111a07b19419dfc84a3e504f) confirmed at 5316526 with 298 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5316526. |
| Expiry | After the wait reached ledger 5316810 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5316811. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/ec505ff30a03aef18cf2c91a68f09b371b74641e074891a11d8e1d365c088a24) confirmed at 5316813. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5316816. No negative-control fee transaction was submitted. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/3e7caed05c8793f5411250ce6aebb0b952e33346447ea6bab38a6a2a323c78ce) the supply at 5316817, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

All 12 control steps completed. They are 8 enforcing-simulation denials, 1 confirmed delegated
claim, 2 ledger waits (accrual and expiry) and the cleanup step. Five of the denials came from the
generated policy: #6 for the reserve list, #6 for the recipient, #5 for the other pool function, #1
for the empty signer set and #7 for the repeat. Three came from the account: 3016 for the wrong
signer, 3002 for the expired rule and 3000 after removal. The position was withdrawn, and the
wrapper finalized with exit 0, deleting the throwaway keys. The claimed BLND (560 base units), the swap's surplus USDC and
the withdrawn USDC stay on the throwaway account. No reviewed Blend adapter was involved: the
pool's code hash in the spec is an `evidence_only` observation. These remain editable local RPC
observations, with non-atomic reads and no ledger proof or protected wallet-approval claim.

### Earlier attempts

Four attempts that day, each on its own fresh account, stopped before completing; each led to a
harness fix or was a transient refusal. None left a Blend position or an installed grant, as
far as the checks below show.

1. `CCZPKB2CMQNPTVQ2NV4UKSWTZBNRKYSG6R7PUWTA75FDJ2WCNKA46ZIT`: after the funding swap, the
   supply transaction was refused before it was signed or sent, because its assembled fee
   exceeded the harness's one-XLM ceiling. A later read-only simulation reported a minimum
   resource fee of 1.0147 XLM for it. No position was opened and no rule was installed. Fixed by
   a named three-XLM ceiling for Blend calls.
2. `CC37QB7DXY33UIRUBP67G3GB3BI3WMAEU7H7LYLBDNP4Z6RHHR62FK5Y`: the owner claim returned 280 BLND
   base units, but the authority check refused the install (`E_INCOMPLETE_ACCOUNT_STATE: endpoint
   ledger or account instance changed during inspection`). The policy had been deployed but not
   installed. It was a fail-closed refusal, with no harness change. The wrapper withdrew the position (empty readback) and reported no
   installed grants.
3. `CA4DSK7ASGR5RCWS7BWKCNBITNTNJW4A66LZRGVNLLWL7O66VTBFCRIT`: the rule was installed. The
   foreign-recipient control then failed while recording, because the pool's BLND transfer to the
   payer, a classic account without a BLND trustline, failed with #13 before the policy ran. The
   wrapper withdrew the position and removed the grant, both verified. Fixed by a contract
   recipient.
4. `CBFH3ETF22KJXNZUXZFWJ5LUZ3VWVCHOVJ7LZ3H4HFV6SAXKR3ZBA6ES`: the rule was installed and two
   controls passed. The other-pool-function control was refused with the policy's code 5, where
   the harness expected 6, so it stopped as an unattributed denial. Fixed by expecting 5. The
   wrapper withdrew the position (empty readback), but its grant cleanup ended `incomplete`: the
   cleanup child prepared and sent the removal but did not record its confirmation, and its
   output was not retained then. Cleanup children now write `cleanup-child.log`, and a prepared
   removal is reconciled from its hash on the next cleanup instead of staying pending. A later read-only check found the removal transaction successful at
   ledger 5316457, rule 1 absent (3000), the policy reporting it uninstalled, and no Blend
   position. The keys had already been deleted, as designed; the rule would in any case have
   expired at ledger 5316739.

## 11. Controlled SEP-41 run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-subscription-derived-2026-10-22.json) records a
complete W2 harness execution from 09:04:36 to 09:09:40 UTC. The checkout was clean at
`81ff8b82be007946ede4ae1d70a17b66c5fd2c73`, the commit that added the derived-denial step. The
external CLI's byte digest is retained in its provenance; it identifies the executable, not its
source. The owner was a throwaway ed25519 key, and confirmation used the explicit operator mode
without a human prompt. The keys were deleted when the run ended.

The selected account was `CDXYCLOXDIEB4COCDDQN5RM4LSHOELEJAEWSCYA7KUFOIANGQTXBQOHT`. Its grant
composed:

- an exact 1-XLM transfer to one controlled merchant;
- a two-call lifetime cap;
- a newly deployed instance of the pinned spending policy, with a deliberately short 12-ledger
  test window.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | The confirmed owner transfer went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [Transaction 0c591b7d…8f10](https://stellar.expert/explorer/testnet/tx/0c591b7dace397eb217ca2e48f6d6225446df6cdcc1402aa95c42d046ace8f10) installed rule 1 after the authority commitment recheck at ledger 5327278. Both policy configurations matched. |
| Derived denials | The CLI emitted the installed spec's 30-case suite and the replay verified its suite hash. The recorded transfer (`case-0`) was permitted in simulation at 5327282. All 10 live-realizable deny cases were refused at 5327282–5327283 by the predicted enforcer; the live policy order put the spending policy first. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Tuple and signer controls | Larger amount, split charge, other merchant, funded other token, wrong signer and empty signer set all produced attributed enforcing-simulation denials before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/62220c9aa875a216c0e610750e735406c59470a66dd867d78cfcf6859313cb66) confirmed at 5327286. The immediate repeat returned spending-policy code 3221 at 5327289, before cutoff 5327298. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/b8f75fbad162ffce28eb8fbcd78552b67e88c9236c90ebe54eb9c0d46d3cfc69) confirmed at 5327301. After another full window, generated-policy code 7 was observed at 5327313. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/c7c4308926e9f2f4b49ae7d0dc993d29a2432bc670e344e7fa70808de0146b36) confirmed at 5327318. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5327318. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-1` | another contract: the funded control token stands in for the suite's undeployed address | account `UnvalidatedContext` 3002 |
| `case-5`, `case-8`, `case-10` | stranger recipient; amount − 1; zero amount | generated policy `NoTupleMatched` #6 |
| `case-7`, `case-9`, `case-11` | amount + 1; amount × 10; i128 maximum | spending policy `SpendingLimitExceeded` 3221 |
| `case-15` | empty signer set | spending policy `NotAllowed` 3223 |
| `case-16`, `case-18` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

This is W2's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is):
the original was permitted, and ten derived denials were refused by their predicted enforcers
(`case-16` and `case-18` stop at the same account check). All 12 subscription control steps completed, and the wrapper finalized with
exit 0.

The reference evaluator still does not model the reviewed spending policy's rolling state; the
replay predicts that policy's refusals from its pinned source and its live, unexercised state.
These remain editable local RPC observations, with non-atomic reads and no ledger proof or
protected wallet-approval claim.

## 12. Controlled Blend claim run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-blend-claim-derived-2026-10-22.json) records a
complete [W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 10:50:55 to 11:18:39 UTC.
The checkout was clean at `4feb59ea733dff70db6a8309d6078153ea735fc2`, and the external CLI was
built from it just before the run. Its byte digest is retained in the provenance; it identifies
the executable, not its source. The owner was a throwaway ed25519 key, and the single rule was
approved in the explicit operator mode without a human prompt. The keys were deleted when the run
ended. The summary is the wrapper's own export.

The selected account was `CABC2NCFR3KDIJY44QB3ONK67FAAX22JX2LYT7B4RJ3AMMT3HAX27ROW`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the same Blend v2 pool
as section 10, valid until ledger 5328859.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary.

| Observation | Recorded result |
| --- | --- |
| Emission and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was live until 26 October 2026, 04:23:27 UTC; the preflight passed at 5328541, with an expected owner claim of 210 BLND base units and a quote of 213603475 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/b49f66b81a2abe391ffe22278e6ee1b33b87d639bb3a3541f08d6dc491331c1a) exactly 100000000 USDC base units at 5328544. *(journal)* The swap returned 213603475 USDC base units, and the supply showed 99888705 bTokens. |
| Owner recording and artifact chain | After the 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/34428e7cf5a1bc6f97629d252e3e0f782f0fec14ae5b0d3d02b7454145115824) confirmed at 5328559 with 262 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/eba348c235c510bef6f619f4132f0c4efb60b212bdd944f0c51b3278be58109b) was checked at 5328569, rechecked at 5328573, installed at 5328575 and read back matched at 5328575. |
| Derived denials | The CLI emitted the installed spec's 25-case suite and the replay verified its suite hash. The recorded claim (`case-0`) was permitted in simulation at 5328576. All five live-realizable deny cases were refused at 5328576 by the predicted enforcer. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6; the pool's `submit` returned its code 5. A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. All at 5328580–5328581. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/559d9c5cb053faaf1fe8b055453a6f54e2334b550a70ce634ebc9e4976c12650) confirmed at 5328585 with 455 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5328585. |
| Expiry | After the wait reached ledger 5328860 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5328860. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/2e019c91a1919dd37e634b7ff55cb1b1726f40719c13a5b346f15feb14b2b603) confirmed at 5328861. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5328861. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/3e109c59d6e00d4ebc7e0aaae2139382ebe9c380428c1b961471fcdb4456db72) the supply at 5328866, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-2` | another function: the suite's absent `claim_x`, realized as the pool's `submit` (`live_stand_in`) | generated policy `FunctionNotAllowed` #5 |
| `case-6` | stranger `to` | generated policy `NoTupleMatched` #6 |
| `case-10` | empty signer set | generated policy `ZeroSigners` #1 |
| `case-11`, `case-13` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

Offline, not replayed: the undeployed contract (no live stand-in); the `from` mutation (it
replaces the authorizer); an `i128` in place of `from` or `to`, the changed reserve list and the
two arity cases (the pool rejects them before authorization); two strict-set mutations, three
call-count cases and the missing-state case (installation state); and the time boundary.

This is W1's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is),
and it passes at exactly the minimum. The W1 suite has five live-realizable deny cases and all
five were replayed, so there is no margin: losing any one of them to an offline class would
refuse the run before anything is simulated. The five are four distinct live checks, because
`case-11` and `case-13` stop at the same account 3016 check. `case-2` is a stand-in: the suite's
function does not exist on the pool, so the pool's `submit`, which the `pool_function` control
also observes, carries it. Only `case-2` and `case-6` reach the policy's function or argument
checks. All 12 control steps completed, the
position was withdrawn, and the wrapper finalized with exit 0. The claimed BLND (717 base units),
the swap's surplus USDC and the withdrawn USDC stay on the throwaway account. No reviewed Blend
adapter was involved. These remain editable local RPC observations, with non-atomic reads and no
ledger proof or protected wallet-approval claim.

An earlier W1 run that day, from 09:32 to 10:00 UTC at the same commit with an earlier build of
the CLI, on `CDK2QVDV2TVFIVBAZQU4L7SLF7MR7WH3ZTQXDOT2MBI2VKSF655WFG7N`, also finalized with exit 0.
Its journal records the same five derived denials meeting their enforcers, a verified removal and
an empty withdrawal readback. Its summary is not committed; this record uses the later run, made with
a freshly built CLI.

## 13. Controlled Soroswap swap run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-soroswap-derived-2026-10-22.json) records a
complete [W3 harness execution](WALKTHROUGH-PROTOCOLS.md#w3-soroswap) from 11:34:35 to 11:51:09
UTC. The checkout was clean at `2d16dfe1c9722a3c593d69a71c5de2f7a7016b2e`, the commit that lets a
policy upload name a 15-XLM fee ceiling. The external CLI was the section 12 binary, built from
`4feb59ea733dff70db6a8309d6078153ea735fc2`; no Rust source changed between the two commits. Its
byte digest is retained in the provenance; it identifies the executable, not its source. The owner
was a throwaway ed25519 key, and both rules were approved in the explicit operator mode without a
human prompt. The keys were deleted when the run ended. The summary is the wrapper's own export.

The selected account was `CAYI3PJNRFKCH44YCFLLTMURZURAV44KWMWG2ZD3NS3H7YLMP5HN54K6`. Both rules
were valid until ledger 5329248: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/5ff1093ff365c824d1e6ff2d26cc6b52a86afae38116c5c52bb944d52c471ac6) of 0.1 XLM confirmed at 5329068 with 177477 output units and a matching balance increase, then the real RPC recorder, synthesis, the 63-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Policy uploads | Read back from the network after the run (not part of the summary): the router-rule policy's upload carried a fee of 101,536,121 stroops (10.15 XLM), above the former ten-XLM ceiling and within the new 15-XLM one, and was charged 87,423,577. The transfer-rule policy's carried 99,478,611. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/49c3e2ba804e140042cda37a8d7a625fb61fec590478ed899f1c764af0f54e0d) was checked at 5329079, rechecked at 5329080, installed at 5329081 and read back matched at 5329081. The [transfer rule](https://stellar.expert/explorer/testnet/tx/ff7bd39b8634a50dedf35babdccddfe30841b744a2ed6d9edf4eda4515c5bc42) was checked at 5329084, rechecked at 5329085, installed at 5329086 and read back matched at 5329086. |
| Derived denials | The CLI emitted the installed spec's 63-case suite and the replay verified its suite hash. Both recorded calls (`case-0`, the swap, and `case-34`, the transfer) were permitted in simulation at 5329090. All ten live-realizable deny cases were refused at 5329090–5329091 by the predicted enforcer. The 32 deny cases that stay offline are listed by class and reason, and the 19 other permit cases stay layer-1 only. Nothing was submitted. |
| Router-rule and signer controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6; an empty signer set its code 1. A wrong signer returned the account's 3016. All at 5329092–5329096. |
| Transfer rule alone | A direct transfer to the pair was permitted in simulation at 5329096, as disclosed, and not submitted. A direct transfer one unit above the cap returned the transfer-rule policy's code 6 at 5329096. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/33b4717212eab0b9d46d117e1b9b16c8fab37272c65a9d1733e249903ffc3d28) confirmed at 5329098 with 177477 output units. At 5329101 a repeat swap returned the router-rule policy's code 7, and a direct transfer the transfer-rule policy's code 7. |
| Expiry | After the wait reached ledger 5329249 (the grants' last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5329249. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/cb91fafb2544bd0e58238257ecc6de6d6e04bb0a2d61bcf7e42a285c50fe0df2) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/c16b10fd54019a80caad6c3e2e7bfeba144ab7ef99a6b5258dccbed68a5896ef) confirmed at 5329252 and 5329253. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5329256. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-5`, `case-8` | router rule: input above the cap; output below the floor | router-rule policy `NoTupleMatched` #6 |
| `case-19` | router rule: empty signer set | router-rule policy `ZeroSigners` #1 |
| `case-39`, `case-43` | transfer rule: stranger recipient; amount above the cap | transfer-rule policy `NoTupleMatched` #6 |
| `case-48` | transfer rule: empty signer set | transfer-rule policy `ZeroSigners` #1 |
| `case-20`, `case-22`, `case-49`, `case-51` | each rule: unrecognized signer; delegate plus an unrecognized signer (one account check per rule) | account `UnauthorizedSigner` 3016 |

Offline, not replayed, for each rule: the undeployed contract and the absent function (no live
stand-in); the mutation of the argument that asks the account to authorize (the swap `to`, the
transfer `from`); type confusions, arity and, for the router, the route and deadline value
changes (rejected before authorization); strict-set, call-count and missing-state cases
(installation state); and the time boundary.

This is W3's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is):
both recorded calls were permitted, the delegated swap was confirmed, and ten derived denials,
five per rule, were refused by their predicted enforcers. Counted as section 12 counts W1's, the
ten are five distinct checks: each rule's policy tuple check (#6) and empty-signer check (#1), and
the account's 3016, where all four unrecognized-signer cases stop. All 14 control steps completed,
and the wrapper finalized with exit 0. The same limits apply as in section 9: fixed harness widenings, no reviewed adapter,
editable local RPC observations, non-atomic reads, no ledger proof and no protected
wallet-approval claim.

### Earlier attempts

Two W3 attempts earlier that day stopped before completing.

1. `CD4JERDBPZW3CDCXV2MI54XZVE4SHEQIK5XL6N2533TUZH2E2PFJFVSS`, from 10:00:57 UTC at
   `4feb59ea733dff70db6a8309d6078153ea735fc2` with an earlier build of the CLI. Both rules were
   installed (IDs 1 and 2, valid until ledger 5328121). Its journal records the derived-denial
   step completing, with both originals permitted and ten denials refused as predicted, and the
   controls through the delegated swap and both count caps. The process was then ended during
   the expiry wait, and the wrapper's exit handling did not complete: the provenance was never
   finalized, no summary was exported, and the journal records no removal or cleanup. The
   throwaway keys are no longer available, so **neither rule can be removed**. A read-only check
   at ledger 5329062 found both rules still present with `valid_until` 5328121, so the account's
   expiry check refuses them, and both policies reporting themselves installed with zero
   remaining calls. They remain on that throwaway account as expired, spent rules. This attempt
   is not counted as a report.
2. `CCARUZYNM7LL6NKB27URAVGZ4KVUZSODBPEPXWMY3KCH2HLNWOLCOOKR`, from 11:18:54 to 11:20:03 UTC at
   the same commit with the section 12 CLI. The harness refused to sign the router-rule policy's
   upload because its assembled fee exceeded the ten-XLM upload ceiling then in force; a
   read-only simulation a few ledgers later put it at 101,220,139 stroops. Nothing was uploaded,
   deployed or installed. The cleanup recorded `no_installed_grants`, a read-only check found only
   the owner rule, and the keys were deleted at exit. Fixed by the 15-XLM policy upload ceiling
   ([harness README](../testnet-harness/README.md#keys)).

## 14. Controlled Soroswap adapter run (26 October 2026)

The [allowlisted run summary](evidence/testnet-soroswap-adapter-2026-10-26.json) records a clean checkout at
`5180152e58f6f94765a652aa4c240fded08b4936`, from 15:02:33 to 15:18:49 UTC, with exit 0.
The external CLI was built at `cd3a8df2`; no Rust source or build input changed between that
revision and the run checkout. Its byte digest is retained in the summary. Later provenance
export fixes were merged after the run; this evidence describes the recorded revision.

This run used development registry version 4's `soroswap-router@1` binding and the committed
operator decisions: input/transfer cap 1,000,000 stroops, output floor 100,000 units, and an
explicitly accepted open deadline. Both generated rules had a call cap of one and expiry at
ledger 5400859. The account was
`CAWJ7RA2LLQN5BM2CBD3SSZKHMQDZOYLFFPHXYB2IA4I25NDIPNAQFQX`.

| Observation | Recorded result |
| --- | --- |
| Owner recording | [Owner swap](https://stellar.expert/explorer/testnet/tx/ca3eede4a691b498f653526c701e307d7b2dc98df87f4aca4f7b433a45ea17ac) confirmed at 5400679; 169317 output units and a matching balance increase. RPC recording, synthesis, the 64-case reference suite and artifact reproduction completed for both policies. |
| Install | Router rule ID 1 installed at 5400686, after authority checks at 5400684/5400685; transfer rule ID 2 at 5400689, after checks at 5400686/5400687. Both configurations matched their readbacks. |
| Derived denials | Both originals permitted; all ten live-realizable denials refused by their predicted enforcer/code at 5400690–5400691. The other 31 deny cases stayed offline and 21 other permit cases stayed layer-1 only. |
| Route and function | Reordered, extended and truncated routes returned router-policy code 6. The alternate router function returned code 5. |
| Foreign recipient | Recipient authorization refused at 5400694. No policy enforcer/code is attributed to this result. |
| Disclosed permissions | A different deadline and an independent direct transfer to the pair were permitted in simulations. Neither was submitted; these are permissions the grant allows. |
| Other controls | Larger input, lower output floor and direct transfer above its cap returned policy code 6; zero signers returned policy code 1; a wrong signer returned account code 3016. |
| Delegated swap | [Delegated swap](https://stellar.expert/explorer/testnet/tx/92bfb858f95f768c7fd5ce180845d26d4af02bba7c43d8795999762226cee685) confirmed at 5400698; 169317 output units and a matching balance increase. Subsequent swap and direct-transfer attempts returned their respective policies' count-cap code 7. |
| Expiry | Account code 3002 at 5400861, after the grant's last valid ledger. |
| Removal | [Transfer rule](https://stellar.expert/explorer/testnet/tx/e7a8202fea1042021013194a7765d9e06a8ec63d20317fa5a481e30bae18f55d) removed at 5400864; [router rule](https://stellar.expert/explorer/testnet/tx/bf08c657dd64b9f4b5854cb661c9c5873f341eb072a3ac98b1f4b60c201ebc40) at 5400867. Each removal event matched, each rule read back absent, and both policies reported not installed. |
| Post-removal | Account missing-rule code 3000 at 5400868. All 19 control steps completed. |

The 64-case accounting is two original permits, ten verified denials, 31 offline denials and
21 other permits. The ten verified denials represent five distinct checks under section 13's
counting convention. Independent read-only checks confirmed all twelve recorded transaction
receipts and, at ledger 5400935, both rules absent, both policies uninstalled, and the recorded
account/policy code hashes unchanged. An independent re-export matched the saved summary.

The adapter remains a development-root assertion: the router's deployed Wasm was not
reproduced from source ([binding review](TARGET-ADAPTERS.md#the-testnet-router-binding-development-registry-version-4)).
Recording is RPC-reported; synthesis treats its input as self-supplied. These are editable local
observations with non-atomic reads, not ledger proofs. Approval used operator mode and a
throwaway ed25519 owner, not a protected wallet approval. The successful exit runs key cleanup;
there is no separate forensic deletion attestation.

An earlier adapter attempt on 22 October stopped at the pre-sign authority recheck, before
any grant was installed. Its cleanup reported no installed grants. It is not counted as a
passing report; refusal stage/reason diagnostics were added before this fresh run.

## 15. Wallet installation and revocation, 22 October 2026

One automation run went through the Pollywallet route's
[installation](POLLYWALLET-INTEGRATION.md#installation) and
[revocation](POLLYWALLET-INTEGRATION.md#revocation) on testnet. It used a fresh account
`CAS6KU6W2MO57MVR7BMY4OE7P4STCXDMSSNRABDB2Z3GEZ6OL3QUPXGE` and a one-call grant for the fixed 0.1-XLM
sample transfer. The [evidence file](evidence/wallet-install-revoke-testnet-2026-10-22.json) keeps
public addresses, hashes, ledgers and verdicts only.

| Step | Recorded observation | Limit |
| --- | --- | --- |
| Four layers | Reference, account-Wasm, captured-target (captured at ledger 5331737) and live enforcement (simulated at 5331741, signatures valid until 5331770) all passed; the report was complete. | State-dependent evidence for one grant shape; the native worker was built from another revision (stated in the file). |
| Replay check | `waiting` until ledger 5331770, then `unchanged` at 5331772. | The account's counters, rules and the candidate's marker, as the operator RPC reported them. |
| Installation | The browser showed its own consent (rule ID 1, fee at most 1 testnet XLM). The owner's passkey signed `add_context_rule`, and the fee payer submitted it once: [`9b8bcbaa…`](https://stellar.expert/explorer/testnet/tx/9b8bcbaacbb361f968f27c5e2114f7c1664260c688661aac114ca51da535cf7d), ledger 5331779. The record required exactly one `context_rule_added` for rule 1. The rule read back identical at 5331779, and the policy's marker was set. | The passkey was a Chrome virtual authenticator driven by Playwright: automation, `human_approval_attested: false`. |
| Revocation | The owner's passkey signed `remove_context_rule(1)`: [`a6646c5d…`](https://stellar.expert/explorer/testnet/tx/a6646c5d06f7e17ff3de5b56b4bd01bf114a244cad332e104521515f210148ec), ledger 5331783. One `context_rule_removed` was observed, and `get_context_rule(1)` failed with the account's error 3000 at 5331783. Policy cleanup reported `not_installed`. | Receipts, events and reads are `rpc_reported`, not ledger proofs. |

Read afterwards from the public RPC, outside the wallet, both transactions were `SUCCESS`. The
account's `NextId` was 2 and its `Count` 1 at ledger 5331788. No delegated call was made under the
installed rule: the delegate's key exists only inside the wallet backend, which has no
delegate-call control. Delegated permits and denials under installed generated policies are
exercised by the harness walkthroughs ([#85](https://github.com/gateway-fm/oz-policy-builder/pull/85),
[#88](https://github.com/gateway-fm/oz-policy-builder/pull/88)).

Four attempts the same day stopped earlier:

- The first stopped at deployment, because the policy upload's fee was 101,422,794 stroops, above
  the then 10-XLM upload ceiling, which is now 15 XLM.
- The second stopped at preparing the installation, when the CLI's assembly exited with an error
  the backend does not keep. The same request succeeded when re-run.
- The third and fourth stopped when another local service took the wildcard port 3000 from under
  the browser.

Each earlier account read back with its owner rule only (`NextId` 1): nothing was installed.

## 16. Wallet proposal import, installation and revocation, 26 October 2026

The [allowlisted evidence](evidence/wallet-proposal-import-testnet-2026-10-26.json) records one
successful automated run from 17:44:43 to 17:49:23 UTC on testnet. The current CLI and wallet
were built/applied from the clean tracked revision recorded in the file. The native worker was
a preserved older artifact with unchanged runtime sources, locks and toolchain; its byte digest
and the source-compatibility limit are recorded separately. No reproducible-build attestation
is inferred from the executable name.

A fresh wallet `CCW5UOEUJTSJMH5XIZIRO33ZFCN27PR7OOF5BVQERSYLMWKJNIR6O5XK`
authorized a 0.1-XLM sample transfer. An independent CLI recording and synthesis produced a
bounded `ozpb-grant-proposal/v1` document using that backend session's automation delegate,
a one-call cap and expiry ledger 5403229. Playwright uploaded the JSON file
through the real wallet UI. The wallet recorded the transaction again and regenerated the
artifact. Both recording and specification hashes differed between the two acquisitions, while
the backend and browser accepted equal grant permissions. Generation and artifact reproduction
completed before deployment.

| Step | Recorded observation |
| --- | --- |
| Four verification layers | Reference, account-Wasm, captured-target at ledger 5402635 and live enforcement at 5402636 all passed. The live cases permitted the exact transfer and denied one stroop more with policy error 6. |
| Replay check | The live signatures expired at ledger 5402666; the check reported `unchanged` at 5402667. |
| Installation | Owner-passkey [transaction 5d35dbfd…](https://stellar.expert/explorer/testnet/tx/5d35dbfdd33acfd37cfe10cbc92a616ba85253582482d618c17478460d73e290) installed rule 1 at ledger 5402672. The account emitted the matching addition event; the rule read back identical and the policy marker was installed. |
| Revocation | Owner-passkey [transaction d558c505…](https://stellar.expert/explorer/testnet/tx/d558c505144dadceeefe823c7bd88e0bc22a43d646ff3fbff68c226451495c83) removed rule 1 at ledger 5402675. The removal event was verified, the rule read back absent with account error 3000, and policy cleanup reported `not_installed`. |

This is an automated independent CLI-to-wallet handoff with a Chrome virtual authenticator,
`human_approval_attested: false`. It does not exercise a human clarification or permission-review
session, protected human approval, or a delegated transaction under the installed rule. The
four layers retain their distinct local, captured and live-simulation boundaries. Receipts
and reads are editable local observations of RPC reports, not authenticated ledger proofs.
The backend and browser stopped after verified removal; this run needed no retries or recovery.

A separate read-only review fetched all eight reported transaction receipts from the public RPC:
each was `SUCCESS` and its decoded envelope matched the reported hash. The install and removal
events were independently decoded and checked. A final ledger-entry read at 5402699 found
`NextId` 2, `Count` 1, owner rule 0 present, rule 1 absent and the policy installation marker
absent. This post-run check has the same RPC trust and non-atomic observation limits.

## 17. Controlled Soroswap exact-deadline run, 30 October 2026

The [allowlisted run summary](evidence/testnet-soroswap-exact-deadline-2026-10-30.json) records a
complete [W3 harness execution](WALKTHROUGH-PROTOCOLS.md#w3-soroswap) from 14:05:23 to 14:21:23
UTC, with exit 0. The checkout was clean at `60e1da70c69b921692a2f6af2dcfc44c0b4678cd`. The
external CLI and the native worker were built from it just before the run; the CLI's byte digest
is retained in the provenance and identifies the executable, not its source. The owner was a
throwaway ed25519 key, and both rules were approved in the explicit operator mode without a human
prompt. The keys were deleted when the run ended. The summary is the wrapper's own export.

**This is the first live run through `soroswap-router@2`, the binding of
[development registry version 5](TARGET-ADAPTERS.md#current-binding-development-registry-version-5),
with the exact recorded deadline.** The router rule's input bound is `adapter_derived` from that
binding, and its deadline is the recorded `u64` timestamp 1793372746 (15:05:46 UTC, the
preflight time plus one hour), kept exact. The committed operator decisions supplied an output
floor of 100,000 units and a transfer cap of 1,000,000 stroops. Both the deadline controls and
the suite's two derived deadline denials returned the router-rule policy's code 6.

The selected account was `CDDB3YVFNOOXJOV4BC52P6H44NC4AWMRXWLPPGRCKNSV2ZA33A4CTQV4`. Both rules
were valid until ledger 5469283: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/3193d810e0fc4b13bfef3999be6ea8f84106de211946d28eef5abd3492424ded) of 0.1 XLM confirmed at 5469103 with 165760 output units and a matching balance increase. It went through the real RPC recorder, synthesis, the 65-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Account-Wasm reports | Before installation, the offline `ozpb dry-run` report for each rule permitted its original call and reverted its derived denials in the pinned account and generated policy Wasm: 24 for the router rule (36 cases) and 20 for the transfer rule (29 cases). Synthetic local state and proposed rule IDs; not live observations. |
| Policy uploads | Read back from the network after the run (not part of the summary): the router-rule policy's upload carried a fee of 12,202,044 stroops and was charged 9,742,036; the transfer-rule policy's carried 11,974,255. Both are well within the 15-XLM upload ceiling. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/ce5f0c9bb9e901fe8db5becf6b1d1c0bf4435521bd00e5c5bcb31114e8d80bf6) was checked at 5469110, rechecked at 5469111, installed at 5469112 and read back matched at 5469112. The [transfer rule](https://stellar.expert/explorer/testnet/tx/aa9b323ff88c2e831db9915fbf716b26dea6a1258f3ae353fb073a3b32aa3f47) was checked at 5469113, rechecked at 5469114, installed at 5469115 and read back matched at 5469115. |
| Derived denials | The CLI emitted the installed spec's 65-case suite and the replay verified its suite hash. Both recorded calls (`case-0`, the swap, and `case-36`, the transfer) were permitted in simulation at 5469117. All twelve live-realizable deny cases were refused at 5469117–5469120 by the predicted enforcer. The 32 deny cases that stay offline are listed by class and reason, and the 19 other permit cases stay layer-1 only. Nothing was submitted. |
| Deadline controls | The recorded deadline plus one and the largest `u64` deadline each returned the router-rule policy's code 6 at 5469123. Neither was submitted. |
| Route, recipient and function | Reordered, extended and truncated routes returned the router-rule policy's code 6 at 5469121–5469122. The foreign recipient was refused by the recipient's missing authorization at 5469122, with no policy enforcer attributed. The alternate router function returned code 5 at 5469123. |
| Other controls | A larger input and a lower output floor returned the router-rule policy's code 6 at 5469121; a wrong signer the account's 3016 and an empty signer set the router-rule policy's code 1 at 5469124. A direct transfer to the pair under the transfer rule alone was permitted in simulation at 5469124, as disclosed, and not submitted; one unit above the cap returned the transfer-rule policy's code 6 at 5469125. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/0de358d99ffa1f3eef7d82104b9a16cfdcf9fdb6838e86866238344a5567bd71) confirmed at 5469126 with 165760 output units and a matching balance increase. At 5469126 a repeat swap returned the router-rule policy's code 7, and a direct transfer the transfer-rule policy's code 7. |
| Expiry | After the wait reached ledger 5469284 (the grants' last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5469284. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/e50bcf080e4242eb8d5440bd47693f833510adf56125f0de3325e5fa14992dfc) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/42a873f4ce24529ab7b6b2094e58d1e215224ca2389cb6e926f09ff4184abcdc) confirmed at 5469286 and 5469288. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5469288. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-5`, `case-8` | router rule: input above the cap; output below the floor | router-rule policy `NoTupleMatched` #6 |
| `case-16`, `case-17` | router rule: deadline plus one; maximum `u64` deadline | router-rule policy `NoTupleMatched` #6 |
| `case-21` | router rule: empty signer set | router-rule policy `ZeroSigners` #1 |
| `case-41`, `case-45` | transfer rule: stranger recipient; amount above the cap | transfer-rule policy `NoTupleMatched` #6 |
| `case-50` | transfer rule: empty signer set | transfer-rule policy `ZeroSigners` #1 |
| `case-22`, `case-24`, `case-51`, `case-53` | each rule: unrecognized signer; delegate plus an unrecognized signer (one account check per rule) | account `UnauthorizedSigner` 3016 |

Offline, not replayed, for each rule: the undeployed contract and the absent function (no live
stand-in); the mutation of the argument that asks the account to authorize (the swap `to`, the
transfer `from`); type confusions, arity and, for the router, a route or deadline replaced by a
value of another type (rejected before authorization); strict-set, call-count and missing-state
cases (installation state); and the time boundary.

This W3 report passes under [§7's definition](#what-a-passing-permitdeny-report-is): both
recorded calls were permitted, the delegated swap was confirmed, and twelve derived denials,
seven for the router rule and five for the transfer rule, were refused by their predicted
enforcers. Counted as section 13 counts them, the twelve are five distinct checks: each rule's
policy tuple check (#6) and empty-signer check (#1), and the account's 3016, where all four
unrecognized-signer cases stop. The router rule's tuple check now refuses the deadline cases as
well as the amount and floor cases. All 20 control steps of the
`adapter_exact_deadline_controls` set completed, and the wrapper finalized with exit 0. The run
submitted twelve transactions.

Independent read-only checks after the run found all twelve receipts `SUCCESS`, and at ledger
5469735 the owner rule present, rules 1 and 2 absent (3000) and the account code unchanged. An
offline re-export matched the saved summary. The adapter binding remains a development-registry
assertion, not governance, and the router's deployed Wasm was not reproduced from source
([target adapters](TARGET-ADAPTERS.md#reproduction-attempt)). These remain editable local RPC
observations, with non-atomic reads and no ledger proof or protected wallet-approval claim.

An attempt at 13:40 UTC the same day, with an earlier build of the CLI, on
`CBY7KUOOIYVIN6FTNO2MUH5D72G2W7JRAEKDACXW7RL4HO3GW54A3T6S`, stopped at policy generation: the host's C toolchain refused to link because its Xcode license had
not been accepted. Its owner swap had confirmed; nothing was uploaded, deployed or installed, the
cleanup reported nothing to remove, and the keys were deleted at exit. It is not counted.

## 18. Controlled SEP-41 run, 30 October 2026

The [allowlisted run summary](evidence/testnet-subscription-derived-2026-10-30.json) records a
complete W2 harness execution from 14:21:34 to 14:25:34 UTC, with exit 0. The checkout was clean
at `60e1da70c69b921692a2f6af2dcfc44c0b4678cd`, and the CLI was the section 17 build; its byte
digest is retained in the provenance. The owner was a throwaway ed25519 key, and confirmation
used the explicit operator mode without a human prompt. The keys were deleted when the run ended.
The summary is the wrapper's own export.

The selected account was `CBKNO45CISWRZJ24MOKHZCD3QYH46YVZ743VFK2FGASMXQGDIUIAYJ5I`. Its grant
composed an exact 1-XLM transfer to one controlled merchant, a two-call lifetime cap, and a newly
deployed instance of the pinned spending policy with a deliberately short 12-ledger test window.

| Observation | Recorded result |
| --- | --- |
| Spending-policy Wasm restore | Read from the network, not part of the summary. Before the run, the pinned spending-limit Wasm's code entry had been archived: it was returned without a live TTL, last modified at ledger 5283550. The [policy-instance creation](https://stellar.expert/explorer/testnet/tx/ab9dd23eded68d75ca8b998fd1a3ff586f1d7f131644c91cf0574fadccbdf282) at 5469296 restored it automatically. It carried a fee of 9,880,961 stroops against the harness's default 10,000,000-stroop ceiling, a margin of 1.2%, and was charged 7,720,564. The next creation, of the merchant account from the live pinned account Wasm, carried 1,117,371. After the run the code entry was live until ledger 5590255. |
| Owner recording and artifact chain | The confirmed owner transfer at 5469301 went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [Transaction a7f35a1e…10ab](https://stellar.expert/explorer/testnet/tx/a7f35a1eac86697135bf72482bf4a935a9262057494e9890bec88ea43ecd10ab) installed rule 1 after the authority commitment check and recheck at ledger 5469304. Both policy configurations matched at 5469306. |
| Derived denials | The CLI emitted the installed spec's 30-case suite and the replay verified its suite hash. The recorded transfer (`case-0`) was permitted in simulation at 5469307. All 10 live-realizable deny cases were refused at 5469307 by the predicted enforcer; the live policy order put the spending policy first. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Tuple and signer controls | Larger amount (spending policy 3221), split charge and other merchant (generated policy 6), funded other token (account 3002), wrong signer (account 3016) and empty signer set (spending policy 3223), all at 5469308, before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/dbbeed5f5dbb8e6d04640cb7fcf393ede420fd087fea8fc1dfd8a1b0b0709cff) confirmed at 5469310. The immediate repeat returned spending-policy code 3221 at 5469310, before cutoff 5469322. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/650109acfcc90d9bcc3bce1b97ec84fe737bf6c17fe83377593e11b9649acaea) confirmed at 5469323. After another full window (target 5469335, reached 5469336), generated-policy code 7 was observed at 5469336. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/0d71aee778c5b2c5a0e8e42c6c30d8ef9526642f081180463c9a1d79fe845778) confirmed at 5469338. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5469338. |

The derived denials, by enforcer, are the section 11 cases:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-1` | another contract: the funded control token stands in for the suite's undeployed address | account `UnvalidatedContext` 3002 |
| `case-5`, `case-8`, `case-10` | stranger recipient; amount − 1; zero amount | generated policy `NoTupleMatched` #6 |
| `case-7`, `case-9`, `case-11` | amount + 1; amount × 10; i128 maximum | spending policy `SpendingLimitExceeded` 3221 |
| `case-15` | empty signer set | spending policy `NotAllowed` 3223 |
| `case-16`, `case-18` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

This W2 report passes under [§7's definition](#what-a-passing-permitdeny-report-is): the original
was permitted, and ten derived denials were refused by their predicted enforcers. All 12
subscription control steps completed, and the wrapper finalized with exit 0. The run submitted
thirteen transactions. Independent read-only checks after the run found all thirteen receipts
`SUCCESS`, and at ledger 5469735 the owner rule present and rule 1 absent (3000). An offline
re-export matched the saved summary.

**Limit: the spending-limit Wasm's archival.** The restored code entry stays live until ledger
5590255, about 6 November 2026 at five seconds per ledger. A W2 run after it is archived again
pays the restore inside the policy-instance creation, which uses the default one-XLM ceiling. At
this run's rent that left 1.2%; a small rise would make the harness refuse the creation before
signing, since it never raises a ceiling itself. The reference evaluator still does not model the
reviewed spending policy's rolling state; the replay predicts that policy's refusals from its
pinned source and its live, unexercised state. These remain editable local RPC observations, with
non-atomic reads and no ledger proof or protected wallet-approval claim.

## 19. Controlled Blend claim run, 30 October 2026

The [allowlisted run summary](evidence/testnet-blend-claim-derived-2026-10-30.json) records a
complete [W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 14:25:41 to 14:52:52 UTC,
with exit 0. The checkout was clean at `60e1da70c69b921692a2f6af2dcfc44c0b4678cd`; the CLI and
the native worker were the section 17 builds, and the CLI's byte digest is retained in the
provenance. The owner was a throwaway ed25519 key, and the single rule was approved in the
explicit operator mode without a human prompt. The keys were deleted when the run ended. The
summary is the wrapper's own export.

The selected account was `CCC4X4ISIXO3CUAJ7LJLCPVV7U4ACVAZXYDE26HFETEH3ZEV7ECELGSE`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the same Blend v2 pool
as section 10, valid until ledger 5469661.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary.

| Observation | Recorded result |
| --- | --- |
| Emission window and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was live until 2 November 2026, 04:23:17 UTC; the schedule the 21 and 22 October runs used had ended on 26 October and had since been renewed outside this harness. The preflight passed at 5469345, with an expected owner claim of 210 BLND base units and a quote of 1646516095 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/893ccc3882b4b5c7cf421e0ec3055022915b73dea9124990bf51aa40e015e472) exactly 100000000 USDC base units at 5469348. *(journal)* The swap returned 1646516095 USDC base units, and the supply showed 99888643 bTokens. |
| Owner recording and artifact chain | After the 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/738d1d4dfe8fab4452d42dda9ac4af6d1a62476196a00c3da885552e383c687c) confirmed at 5469361 with 227 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Account-Wasm report | Before installation, the offline `ozpb dry-run` report permitted the original claim and reverted 19 derived denials (25 cases) in the pinned account and generated policy Wasm. Synthetic local state; the pool itself is not executed offline. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/0f2e1bd49bbb992148561881a0e996327133a35218ffc3a1611c0143dc297036) was checked and rechecked at 5469364, installed at 5469366 and read back matched at 5469366. |
| Derived denials | The CLI emitted the installed spec's 25-case suite and the replay verified its suite hash. The recorded claim (`case-0`) was permitted in simulation at 5469367. All five live-realizable deny cases were refused at 5469367–5469368 by the predicted enforcer. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6; the pool's `submit` returned its code 5. A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. All at 5469368–5469370. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/a2e8d6f0cae95f6cd02ef5fd55dc0f6a17d9b61e89735a6cfc1cb977214ba7b4) confirmed at 5469375 with 245 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5469375. |
| Expiry | After the wait reached ledger 5469662 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5469662. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/36cb73c8b116ad351a61cc83d0a3ec9f3fe926e330fd467f535429acc2e85bbd) confirmed at 5469664. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5469664. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/b0bf45a766df6c467187386d642f296a0ff958a84ecd0596641f755659156f9f) the supply at 5469666, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

The derived denials are the section 12 cases with the same enforcers: `case-2` (the suite's
absent `claim_x`, realized as the pool's `submit`, generated policy #5), `case-6` (stranger `to`,
#6), `case-10` (empty signer set, #1), and `case-11` and `case-13` (unrecognized signer; delegate
plus an unrecognized signer; the account's 3016). The same 14 deny cases stay offline as in
section 12.

This W1 report passes under [§7's definition](#what-a-passing-permitdeny-report-is), again at
exactly the minimum of five denials, which are four distinct live checks. All 12 control steps
completed, the position was withdrawn, and the wrapper finalized with exit 0. The run submitted
twelve transactions. Independent read-only checks after the run found all twelve receipts
`SUCCESS`, and at ledger 5469735 the owner rule present and rule 1 absent (3000). An offline
re-export matched the saved summary.

**Limit: the emission window.** The preflight requires the emission on ID 3 to outlive the run by
two hours, so it refuses W1 from about 02:23 UTC on 2 November 2026 unless the schedule is renewed
again; this harness's own `gulp_emissions` refresh was refused in a read-only simulation on
21 October. The claimed BLND (472 base units), the swap's surplus USDC (1546516095 base units at
this quote) and the withdrawn USDC stay on the throwaway account. No reviewed Blend adapter was
involved: the pool's code hash in the spec is an `evidence_only` observation. These remain
editable local RPC observations, with non-atomic reads and no ledger proof or protected
wallet-approval claim.

## 20. Evidence still needed

The [SEP-41 subscription walkthrough](WALKTHROUGH-SEP41.md) and section 8 provide current live
harness observations for composed scope/count plus spending limits, ledger-bounded repeats and
separate cleanup checks; the known reference-model gap remains explicit. Section 9 adds two
two-rule Soroswap swap runs with expiry and per-rule removal; the second includes denials by the
transfer rule's own policy. Section 10 adds one Blend claim run on a supply position the harness
opened and withdrew.

Sections 11, 12 and 13 add a W2, a W1 and a W3 run with the derived-denial step; all three pass
under [§7's definition](#what-a-passing-permitdeny-report-is), W1 at exactly the minimum of five.
The section 8–10 runs predate that step. Two rules from an interrupted W3 attempt remain installed,
expired and spent, on a throwaway account (section 13).

The W3 runs in sections 9 and 13 used widenings the harness wrote itself and `evidence_only`
router hashes. For the section-14 run, the harness took the router's input bound and open deadline from the
development registry's `soroswap-router@1` binding, a development-registry assertion whose Wasm
was not reproduced from source ([target adapters](TARGET-ADAPTERS.md#the-testnet-router-binding-development-registry-version-4)),
and the floor and transfer cap from an operator decisions file. Section 14 records the first
completed live run through that binding, including route, recipient and function controls.
These remain historical v1 results; [registry v5](TARGET-ADAPTERS.md#current-binding-development-registry-version-5)
now preserves the recorded deadline exactly.

Sections 15 and 16 add automated wallet installation and revocation, including an independent
CLI proposal import. Both use a virtual authenticator and do not attest to human approval.

Sections 17, 18 and 19 add a W3, a W2 and a W1 run at revision `60e1da70`, each passing under
[§7's definition](#what-a-passing-permitdeny-report-is). That is not the final delivered
revision; reports at that revision remain needed. Section 17 is the first live run through
`soroswap-router@2` with the exact recorded deadline: the deadline-plus-one and maximum-deadline
controls and derived cases were all refused by the router-rule policy's code 6. Sections 17 and
19 are also the first live W3 and W1 runs whose per-rule offline account-Wasm reports passed
before installation. Their limits are the spending-limit Wasm's archival around 6 November
(section 18) and the Blend emission window ending 2 November (section 19).

Sections 21, 22 and 23, after this one, add a W1, a W2 and a W3 run at revision `86854cee` on
1 November 2026, each passing under [§7's definition](#what-a-passing-permitdeny-report-is) with
the same derived-denial cases, enforcers and codes as sections 17–19, including both deadline
denials with the router-rule policy's code 6. The release still has to be tagged; these are
reports at revision `86854cee`, not a claim about the delivered release. The same two limits
apply: the emission window ends on 2 November and the spending-limit Wasm stays live until
about 6 November.

Phase 2 still needs walkthrough and wallet reports at the final delivered revision, a human
owner's protected approval in the wallet's install and revoke flow,
a reviewed Blend adapter rather than an `evidence_only` code observation, the remaining harness
layers with their actual evidence boundaries, hosted-service deployment
evidence, and the public demonstration/video. The controlled W1, W2 and W3 runs do not close
those requirements. See [SCOPE.md](SCOPE.md) for the implementation map.

Sections 24 to 26 add the Tranche 2 demonstration on 11 November 2026: the three walkthroughs
at revision `e5cc132a`, each passing under §7; a wallet install, use and revoke by a person with
a real passkey, from Claude's proposal; and the hosted reference instance's acceptance check.
They close the walkthrough, wallet, human-approval, hosting and demonstration requirements above.
The reviewed Blend adapter and the remaining harness layers are not closed by them; the
[acceptance crosswalk](TRANCHE-2-VERIFICATION.md#contracted-outcome-and-milestone-boundary)
keeps those as stated limits.

## 21. Controlled Blend claim run, 1 November 2026

The [allowlisted run summary](evidence/testnet-blend-claim-derived-2026-11-01.json) records a
complete [W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 16:08:52 to 16:36:06 UTC,
with exit 0. The checkout was clean at `86854cee322e25ef52db8ad42c7e083cf56a481e`. The external
CLI and the native worker were built from it just before the run; the CLI's byte digest is
retained in the provenance and identifies the executable, not its source. The owner was a
throwaway ed25519 key, and the single rule was approved in the explicit operator mode without a
human prompt. The keys were deleted when the run ended. The summary is the wrapper's own export.

The selected account was `CCNCW23M3KOQ7P3RZB4KAWD3NUKSDNBDXNGTXWUW3BDZ2DZHSO5SSXX3`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the same Blend v2 pool
as section 10, valid until ledger 5505460.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary.

| Observation | Recorded result |
| --- | --- |
| Emission window and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was the section 19 schedule, live until 2 November 2026, 04:23:17 UTC. The preflight passed at 5505143, with an expected owner claim of 210 BLND base units and a quote of 1555296222 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/030e4afcb68c49d76d10280c4dab8b39b0c0ba7d71efa6c504b995ed143b5c7f) exactly 100000000 USDC base units at 5505146. *(journal)* The swap returned 1555296222 USDC base units, and the supply showed 99888627 bTokens. |
| Owner recording and artifact chain | After the 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/a59c0b8369f5a7ee3e2009e5f8c849b8aff29453c90bcc0081abf40011145659) confirmed at 5505160 with 245 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Account-Wasm report | Before installation, the offline `ozpb dry-run` report permitted the original claim and reverted 19 derived denials (25 cases) in the pinned account and generated policy Wasm. Synthetic local state; the pool itself is not executed offline. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/e88c9f0ec4bec0761305445b1e79fdfa7fd86d65b3e9ce1fea0f5e7be174ff76) was checked at 5505164, rechecked at 5505165, installed at 5505166 and read back matched at 5505166. |
| Derived denials | The CLI emitted the installed spec's 25-case suite and the replay verified its suite hash. The recorded claim (`case-0`) was permitted in simulation at 5505166. All five live-realizable deny cases were refused at 5505167 by the predicted enforcer. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6; the pool's `submit` returned its code 5. A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. All at 5505168–5505169. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/c91173f75a00d8145d2ea16f25677aa74118989aa7f7774662990214575d09fd) confirmed at 5505173 with 227 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5505173. |
| Expiry | After the wait reached ledger 5505461 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5505461. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/b5f500e449f8a07c03332d4b4054f0711aaecc45d9e11b87292d92b179abdeb5) confirmed at 5505463. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5505463. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/13bfa08ee028769037cad3ee9afc3630692429d9dd2e87a69a57bee4ca81809a) the supply at 5505465, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

The derived denials are the section 12 and 19 cases with the same enforcers: `case-2` (the
suite's absent `claim_x`, realized as the pool's `submit`, generated policy #5), `case-6`
(stranger `to`, #6), `case-10` (empty signer set, #1), and `case-11` and `case-13`
(unrecognized signer; delegate plus an unrecognized signer; the account's 3016). The same 14
deny cases stay offline as in section 12.

This W1 report passes under [§7's definition](#what-a-passing-permitdeny-report-is), again at
exactly the minimum of five denials, which are four distinct live checks. All 12 control steps
completed, the position was withdrawn, and the wrapper finalized with exit 0. The run submitted
twelve transactions. Independent read-only checks after the run found all twelve receipts
`SUCCESS`, and at ledger 5505481 the owner rule present, rule 1 absent (3000) and the account
code unchanged. An offline re-export matched the saved summary.

**Limit: the emission window.** This run used the same emission schedule as section 19, so the
preflight refuses W1 from about 02:23 UTC on 2 November 2026 unless the schedule is renewed;
this harness's own `gulp_emissions` refresh was refused in a read-only simulation on
21 October. The claimed BLND (472 base units), the swap's surplus USDC (1455296222 base units at
this quote) and the withdrawn USDC stay on the throwaway account. No reviewed Blend adapter was
involved: the pool's code hash in the spec is an `evidence_only` observation. These remain
editable local RPC observations, with non-atomic reads and no ledger proof or protected
wallet-approval claim.

## 22. Controlled SEP-41 run, 1 November 2026

The [allowlisted run summary](evidence/testnet-subscription-derived-2026-11-01.json) records a
complete W2 harness execution from 16:36:17 to 16:40:13 UTC, with exit 0. The checkout was clean
at `86854cee322e25ef52db8ad42c7e083cf56a481e`, and the CLI was the section 21 build; its byte
digest is retained in the provenance. The owner was a throwaway ed25519 key, and confirmation
used the explicit operator mode without a human prompt. The keys were deleted when the run ended.
The summary is the wrapper's own export.

The selected account was `CBLE6SZDAPLCF5LDTQD2SHPH5J4VUA3BJPQ4SXVRVLG66SUV3VLNZYNH`. Its grant
composed an exact 1-XLM transfer to one controlled merchant, a two-call lifetime cap, and a newly
deployed instance of the pinned spending policy with a deliberately short 12-ledger test window.

| Observation | Recorded result |
| --- | --- |
| Spending-policy Wasm | Read from the network, not part of the summary. The code entry section 18 restored was still live, until ledger 5590255, both before and after the run. The [policy-instance creation](https://stellar.expert/explorer/testnet/tx/a6967516a4fdd321498516f9ecd993f61b3fb2a8ba55258b3d207d3308681cea) at 5505472 therefore needed no restore: it carried a fee of 1,021,334 stroops against the default 10,000,000-stroop ceiling and was charged 14,908. |
| Owner recording and artifact chain | The confirmed owner transfer at 5505476 went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [The rule 1 installation](https://stellar.expert/explorer/testnet/tx/a6a1cf4ca90d5f67231dee46f556680bb5761392723df34af1c76ca6d165251b) followed the authority commitment check and recheck at ledger 5505479. Both policy configurations matched at 5505481. |
| Derived denials | The CLI emitted the installed spec's 30-case suite and the replay verified its suite hash. The recorded transfer (`case-0`) was permitted in simulation at 5505482. All 10 live-realizable deny cases were refused at 5505482–5505483 by the predicted enforcer; the live policy order put the spending policy first. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Tuple and signer controls | Larger amount (spending policy 3221), split charge and other merchant (generated policy 6), funded other token (account 3002), wrong signer (account 3016) and empty signer set (spending policy 3223), at 5505483–5505484, before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/84817a2ab18b683603da453bdcb17369d2013941b1800631da9859d898e0e828) confirmed at 5505486. The immediate repeat returned spending-policy code 3221 at 5505486, before cutoff 5505498. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/51208efe67ed81962ef0e7c96fd3f444e9c676d1b5b9fab8a066302e64e54eab) confirmed at 5505499. After another full window (target 5505511, reached 5505511), generated-policy code 7 was observed at 5505512. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/b23c676a68f67687d5ffc8419d3992625fc42561c791f52380d3113864715071) confirmed at 5505514. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5505514. |

The derived denials, by enforcer, are the section 11 and 18 cases:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-1` | another contract: the funded control token stands in for the suite's undeployed address | account `UnvalidatedContext` 3002 |
| `case-5`, `case-8`, `case-10` | stranger recipient; amount − 1; zero amount | generated policy `NoTupleMatched` #6 |
| `case-7`, `case-9`, `case-11` | amount + 1; amount × 10; i128 maximum | spending policy `SpendingLimitExceeded` 3221 |
| `case-15` | empty signer set | spending policy `NotAllowed` 3223 |
| `case-16`, `case-18` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

This W2 report passes under [§7's definition](#what-a-passing-permitdeny-report-is): the original
was permitted, and ten derived denials were refused by their predicted enforcers. All 12
subscription control steps completed, and the wrapper finalized with exit 0. The run submitted
thirteen transactions. Independent read-only checks after the run found all thirteen receipts
`SUCCESS`, and at ledger 5505520 the owner rule present and rule 1 absent (3000). An offline
re-export matched the saved summary.

**Limit: the spending-limit Wasm's archival.** The code entry stays live until ledger 5590255,
about 6 November 2026 at five seconds per ledger. A W2 run after it is archived again pays the
restore inside the policy-instance creation, which section 18 measured at 9,880,961 stroops
against the default one-XLM ceiling; the harness never raises a ceiling itself. The reference
evaluator still does not model the reviewed spending policy's rolling state; the replay predicts
that policy's refusals from its pinned source and its live, unexercised state. These remain
editable local RPC observations, with non-atomic reads and no ledger proof or protected
wallet-approval claim.

## 23. Controlled Soroswap exact-deadline run, 1 November 2026

The [allowlisted run summary](evidence/testnet-soroswap-exact-deadline-2026-11-01.json) records a
complete [W3 harness execution](WALKTHROUGH-PROTOCOLS.md#w3-soroswap) from 16:40:25 to 16:56:23
UTC, with exit 0. The checkout was clean at `86854cee322e25ef52db8ad42c7e083cf56a481e`; the CLI
and the native worker were the section 21 builds, and the CLI's byte digest is retained in the
provenance. The owner was a throwaway ed25519 key, and both rules were approved in the explicit
operator mode without a human prompt. The keys were deleted when the run ended. The summary is
the wrapper's own export.

This repeats section 17 through `soroswap-router@2`, the binding of
[development registry version 5](TARGET-ADAPTERS.md#current-binding-development-registry-version-5).
The router rule's input bound is `adapter_derived` from that binding, and its deadline is the
recorded `u64` timestamp 1793554853 (17:40:53 UTC, the preflight time plus one hour), kept exact.
The committed operator decisions supplied an output floor of 100,000 units and a transfer cap of
1,000,000 stroops. Both the deadline controls and the suite's two derived deadline denials
returned the router-rule policy's code 6.

The selected account was `CCHJKHO2TSFH5LDBREYNMVMCT3EJEZY6XGF6O44RLIP23KBNAJ7HSC54`. Both rules
were valid until ledger 5505704: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/9a0fb239c172dad0af48cfbeca470f4b628bb3ba68bd55c31f60ec8ef6b57930) of 0.1 XLM confirmed at 5505524 with 167357 output units and a matching balance increase. It went through the real RPC recorder, synthesis, the 65-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Account-Wasm reports | Before installation, the offline `ozpb dry-run` report for each rule permitted its original call and reverted its derived denials in the pinned account and generated policy Wasm: 24 for the router rule (36 cases) and 20 for the transfer rule (29 cases). Synthetic local state and proposed rule IDs; not live observations. |
| Policy uploads | Read back from the network after the run (not part of the summary): the router-rule policy's upload carried a fee of 12,202,044 stroops and was charged 9,742,036; the transfer-rule policy's carried 11,974,255. Both are well within the 15-XLM upload ceiling. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/7ba01519b31eb23f1a4162f19aea43d4686f746957acf839f0d363b191d3729b) was checked at 5505531, rechecked at 5505532, installed at 5505533 and read back matched at 5505533. The [transfer rule](https://stellar.expert/explorer/testnet/tx/47afb0b3718448473a035c670f8f31ea3bda6c74afa9a6368ec846f566417c0b) was checked and rechecked at 5505534, installed at 5505536 and read back matched at 5505536. |
| Derived denials | The CLI emitted the installed spec's 65-case suite and the replay verified its suite hash. Both recorded calls (`case-0`, the swap, and `case-36`, the transfer) were permitted in simulation at 5505537. All twelve live-realizable deny cases were refused at 5505537–5505539 by the predicted enforcer. The 32 deny cases that stay offline are listed by class and reason, and the 19 other permit cases stay layer-1 only. Nothing was submitted. |
| Deadline controls | The recorded deadline plus one and the largest `u64` deadline each returned the router-rule policy's code 6 at 5505541. Neither was submitted. |
| Route, recipient and function | Reordered, extended and truncated routes returned the router-rule policy's code 6 at 5505540. The foreign recipient was refused by the recipient's missing authorization at 5505541, with no policy enforcer attributed. The alternate router function returned code 5 at 5505541. |
| Other controls | A larger input and a lower output floor returned the router-rule policy's code 6 at 5505540; a wrong signer the account's 3016 and an empty signer set the router-rule policy's code 1 at 5505542. A direct transfer to the pair under the transfer rule alone was permitted in simulation at 5505542, as disclosed, and not submitted; one unit above the cap returned the transfer-rule policy's code 6 at 5505542. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/8471e2feea4ecf3e355d6bc14b21274dfd1bb7bd89ee3a42a6cf2e7e5263c1f5) confirmed at 5505544 with 167357 output units and a matching balance increase. At 5505544 a repeat swap returned the router-rule policy's code 7, and a direct transfer the transfer-rule policy's code 7. |
| Expiry | After the wait reached ledger 5505705 (the grants' last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5505705. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/6d6ec0ea62c65d3d7ae6ab7ec491e80868256bd846f34f1cda6792124b4e4209) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/e16cd26da8b385f20a56df6aac0978fc80c16b31a473fca8cd8771708a27b933) confirmed at 5505707 and 5505708. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5505708. |

The derived denials are the section 17 cases with the same enforcers: `case-5` and `case-8`
(input above the cap; output below the floor) and `case-16` and `case-17` (deadline plus one;
maximum `u64` deadline), all router-rule policy #6; `case-21` (empty signer set, router-rule
policy #1); `case-41` and `case-45` (stranger recipient; amount above the cap, transfer-rule
policy #6); `case-50` (empty signer set, transfer-rule policy #1); and `case-22`, `case-24`,
`case-51` and `case-53` (unrecognized signer; delegate plus an unrecognized signer, for each
rule; the account's 3016). The same 32 deny cases stay offline as in section 17.

This W3 report passes under [§7's definition](#what-a-passing-permitdeny-report-is): both
recorded calls were permitted, the delegated swap was confirmed, and twelve derived denials,
seven for the router rule and five for the transfer rule, were refused by their predicted
enforcers; as in section 17, they are five distinct checks. All 20 control steps of the
`adapter_exact_deadline_controls` set completed, and the wrapper finalized with exit 0. The run
submitted twelve transactions.

Independent read-only checks after the run found all twelve receipts `SUCCESS`, and at ledger
5505714 the owner rule present, rules 1 and 2 absent (3000) and the account code unchanged. An
offline re-export matched the saved summary. The adapter binding remains a development-registry
assertion, not governance, and the router's deployed Wasm was not reproduced from source
([target adapters](TARGET-ADAPTERS.md#reproduction-attempt)). These remain editable local RPC
observations, with non-atomic reads and no ledger proof or protected wallet-approval claim.

## 24. Demonstration walkthrough runs, 11 November 2026

The three walkthroughs were run side by side during the recorded public demonstration, each
from its own clean checkout at `e5cc132aa52358d65d190633b3fed12baa8178fc`, with the CLI and
native worker built from it (the CLI's byte digest is in each provenance). That revision adds
the `OZPB_HARNESS_GRANT_LEDGERS` setting, which shortens the grant lifetime so the expiry step
fits a live demonstration, and the end-of-run summary. Owners were throwaway ed25519 keys approved in the explicit operator mode,
deleted when each run ended. The allowlisted summaries are the wrappers' own exports:
[W1](evidence/testnet-blend-claim-demo-2026-11-11.json),
[W2](evidence/testnet-subscription-demo-2026-11-11.json) and
[W3](evidence/testnet-soroswap-demo-2026-11-11.json). Each exited 0.

| Run | Window (UTC) | Recorded call, installation and use | Derived denials (live, by predicted enforcer) | Controls and lifecycle |
| --- | --- | --- | --- | --- |
| W1 Blend claim | 16:21:09–16:25:55 | [Owner claim](https://stellar.expert/explorer/testnet/tx/fada40262fda822242d652168a58490786fda5555173a92197fad796d10a5498) at 5678107 (168 BLND base units); [install](https://stellar.expert/explorer/testnet/tx/c6aed83398f64843942506cfe6808b0abc03b46f55943037591f51450d0670e2); [delegated claim](https://stellar.expert/explorer/testnet/tx/dc9718729ee268df4f6e13f2fe9f3fdedd5ee83adad9df88fbe1f60417ea7358) at 5678121. The offline account-Wasm report permitted the original and reverted 19 denials (25 cases). | 5 of the 25-case suite: `case-2`, `case-6`, `case-10` (generated policy #5, #6, #1), `case-11`, `case-13` (account 3016); 14 deny cases stay offline. | All 12 steps: reserve list and recipient (#6), pool `submit` (#5), wrong signer (3016), empty signer set (#1), repeat after the delegated claim (#7), expired rule (3002 at 5678138), [removal](https://stellar.expert/explorer/testnet/tx/0a3343f54ad551b86bf91b039931f8bba0e60b950da3d68e45b901999676540c), missing rule (3000 at 5678140). |
| W2 SEP-41 subscription | 16:21:17–16:25:01 | [Owner transfer](https://stellar.expert/explorer/testnet/tx/ee4b57f68048cfe24eaf42c6aebaa984490d50abec3cf4b70e834ed5575b67ba) through recording, synthesis, the 30-case reference suite and matching artifact reproduction; [install](https://stellar.expert/explorer/testnet/tx/e4bfaf18eaf5851d9ef38f901284793282ffa072c55d0ad1f0efa6b9c2a2471f) composed with a fresh instance of the pinned spending-limit policy; [first charge](https://stellar.expert/explorer/testnet/tx/61d1c0a478a0c3b9c984976ce066b7fe0275e4cff3e7a0850c3806d99177ba86) and [next-window charge](https://stellar.expert/explorer/testnet/tx/5ac1d404b370f272e243f0b4b005ee4ba46ae2819f211563be9fa0414541de77). | 10 of 30: `case-1` (account 3002), `case-5`, `case-7`–`case-11` (generated policy #6), `case-15` (#1), `case-16`, `case-18` (account 3016); 14 stay offline. The generated policy came first in the live policy order this time, so it, not the spending policy, refused the amount cases. | Both configurations matched before and after the charges; [removal](https://stellar.expert/explorer/testnet/tx/65b791448edbe2fec797e96b6f93d6adca1b01d17ca8f419ec663a61fe2d1499) at 5678131 read back absent, both policies uninstalled. |
| W3 Soroswap swap | 16:21:26–16:24:47 | [Owner swap](https://stellar.expert/explorer/testnet/tx/a11cd79b3240a3447c49c2c8185cc99c53348f9721a23e3b2501ab31f7d4b2ad) at 5678094; [router rule](https://stellar.expert/explorer/testnet/tx/3839e95cfba1665f538c73d23218b67ad6258a118e7a12e92cb75884512addb9) and [transfer rule](https://stellar.expert/explorer/testnet/tx/26c10bc8284c7aff6475724f588ae5629aba530788f08bd99e60e6ba1ff2db59) installed through `soroswap-router@2`; [delegated swap](https://stellar.expert/explorer/testnet/tx/b0a485064673dd7b7bd61d08c6b1d9b0323cb20652cee5a3e6a56ea2d2f7a88b) at 5678110. Offline account-Wasm reports: 24 denials reverted for the router rule (36 cases), 20 for the transfer rule (29). | 12 of 65: `case-5`, `case-8`, `case-16`, `case-17` (router-rule policy #6, including both deadline cases), `case-21` (#1), `case-41`, `case-45` (transfer-rule policy #6), `case-50` (#1), `case-22`, `case-24`, `case-51`, `case-53` (account 3016); 32 stay offline. | All 20 steps of `adapter_exact_deadline_controls`, including both deadline controls (#6), route, function and floor controls, the two count caps (#7), expiry (3002 at 5678125), [both](https://stellar.expert/explorer/testnet/tx/4a2a2e745291db2efce56ca3d4bd1564a576640fdc539c1d1cb9761f9570d906) [removals](https://stellar.expert/explorer/testnet/tx/1d8ee6125ceb3bf7c3bf376cc3da79ee6c342ff287e4be216cbb96518b7cfd69) and the missing-rule check (3000 at 5678128). |

Each report passes under [§7's definition](#what-a-passing-permitdeny-report-is): the recorded
calls were permitted and at least five derived denials were refused live by their predicted
enforcers. The Blend emission on reserve 3 runs until 16 November 2026, 04:23:47 UTC
*(journal: the W1 run's local `run.json`)*. The walkthrough limits stated in sections 21–23
still apply: no reviewed Blend adapter, no composed account-Wasm layer for W2, and a
development-registry router binding for W3. These are local RPC observations with non-atomic
reads and operator-mode approval; human approval is section 25.

## 25. Wallet run by a person, with Claude's proposal, 11 November 2026

Recorded in the [demonstration video](https://drive.google.com/file/d/19juUqgGOpdBtLzDIkTCrkJjh9w68aDkk/view)
(16:17–16:37 UTC, alongside the walkthroughs). The Pollywallet page and wallet backend were built from
`6c08046db7b6a9410a057dbb543c222fc6b7f315`; the MCP server Claude used had no Rust change since
`cf8df819`. A person used a platform passkey (Touch ID) as the account's only owner and made
every choice. The person gave Claude Code the payment's hash and asked for it to be repeatable
once, within two hours, for exactly that amount. With the policy-builder skill, Claude read the
payment from testnet without asking for a ledger or RPC URL, restated the grant (delegate,
target, exact amount, one call, expiry about two hours ahead), asked whether it was correct,
showed the "Confirm before deploy" card and sent the proposal to the wallet only after the
person confirmed. The person had stated every limit, so no ambiguous constraint needed a
clarifying question in this session. The wallet regenerated and compared the proposal before
any deployment.

| Step | Ledger | Result |
| --- | --- | --- |
| [Passkey verifier](https://stellar.expert/explorer/testnet/tx/5e4ee80d2cdef0cbf1a17f38f0b50a69e727e30ee03aaca66e69c7d15dbdb077), [account](https://stellar.expert/explorer/testnet/tx/f63730bd84509c65bebcfcf71760d619d699a937889d793b79aad9e50c2caab2) and [funding](https://stellar.expert/explorer/testnet/tx/54a1aea98cb1cdd468e9e5afa39005cdac70df5d971c60467beea063158e20d8) | 5678094–5678096 | Account `CB7JTNGBJ4KHLIKGWLKKQK2VTZO277H4VMTCV56ZR7HW2PRICW2ILSBB`, the passkey its only signer. |
| [Owner's 0.1 XLM payment](https://stellar.expert/explorer/testnet/tx/6282cbcdf40bb76b49f466ca122c4098be85406238570c0d61e2b7e870e191a8) | 5678107 | Signed with the passkey; the transaction Claude recorded. |
| Policy [upload](https://stellar.expert/explorer/testnet/tx/ba907170d68db6d4344e39f5e4ac595045745d094b4d456b562728f72e53126e) and [deployment](https://stellar.expert/explorer/testnet/tx/8124765f41a702716c8e139a00a34b87d5f5f5de834bd01e0496359342ecac85) | 5678202–5678203 | Policy `CCEMMKAOEP3XF3XVPTHDKZNJPBZ52GDTXBFPB7UUVZQNAHBAPRB2OVIF`; no permission yet. |
| Authority review, local checks, live check | 5678216 | The passkey alone controls the rules. The offline layers passed. The live check (signatures expiring at 5678228, simulated, not submitted) was reported on the page as allowing the exact payment and refusing one stroop more; the journal keeps its snapshot, the video its outcome. The wallet waited for those signatures to expire unused. |
| [Installation](https://stellar.expert/explorer/testnet/tx/4fc66cff765dc67ea21b01f3d5fe9ece0ad785c551d244236f554742530884c1) | 5678242 | Signed with the passkey; rule 1 read back as approved ("Check installed grant": unchanged). |
| [Automation key's payment](https://stellar.expert/explorer/testnet/tx/d1a31f68095a1710e8b4604958950b93ac7f7cf9f5df92c15c5f5a8684d197eb) | 5678252 | The delegate alone, no passkey. |
| Same payment again | 5678256 | Refused by the policy, code 7 (call count exceeded), in an enforcing simulation; not submitted. |
| [Revocation](https://stellar.expert/explorer/testnet/tx/371fe2ff8655ff74aa45e1ce54e7ca3360687894e172b3a999ed4ee5a81bd5d6) | 5678262 | Signed with the passkey; the rule was removed. |

This is the first wallet run with a person's own approvals and the first agent session
exercised end to end into the wallet; sections 15 and 16 were automation. The person's choices
are recorded by the video; the backend's journal stays local. One grant shape (an exact native
transfer, one call) was exercised; revoke-first replacement was not.

## 26. Hosted reference instance acceptance check, 11 November 2026

Gateway's infrastructure team runs a reference instance for the review at
`https://policy-builder-mcp.dev.eu-north-3.gateway.fm/v1/mcp`: the API container with
`OZPB_HTTP_LISTEN` and `OZPB_HTTP_ALLOWED_HOSTS` behind their own TLS ingress, testnet only,
with one bearer token handed to the reviewers. Which image digest runs is the operator's record;
from outside, the checks below show this toolkit's server answering. Checked at 19:35 UTC:

| Check | Result |
| --- | --- |
| No token | `401`, the server's own "missing or invalid bearer token" through the ingress. |
| `initialize` with the token | `200`; the server identifies as rmcp 2.2.0 and opens a session. |
| `tools/list` | All 17 tools. |
| A real tool call | `record_transaction` for the section 25 payment, through the instance's configured testnet RPC source, returned its recording in about one second, with the wallet account as the authorizer. |
| A browser `Origin` header | `403`. |

This is one acceptance check from one client. Per-client accounts, billing and production
availability are not offered ([hosted operation](TRANCHE-2-VERIFICATION.md#deviations-and-open-gaps-against-the-phase-2-design)).
