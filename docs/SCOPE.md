# Delivery scope and remaining work

Each entry below is scheduled rather than dropped, and says why it is not here yet. The
distinction matters: a reader deciding whether to depend on this tool should be able to tell
what was left out on purpose from what was overlooked.

Section numbers refer to `docs/architecture.md`.

## Tranche 2 status

Tranche 1's record-and-generate release remains distinct from the Phase 2 acceptance outcome.
The following map describes the integrated implementation in this tree. A
feature or an automated check is not by itself evidence that the whole milestone is complete.
The [acceptance crosswalk](TRANCHE-2-VERIFICATION.md#contracted-outcome-and-milestone-boundary)
separates the contracted outcome, architecture gaps and Tranche 3.

| Area | Available evidence or implementation | Still required |
| --- | --- | --- |
| Agent workflow | The policy-builder skill with its confirm-before-deploy card, the human-invoked install skill and its `ozpb-grant-proposal/v1` handoff, the plugin, the MCP tools, a session-transcript checker and [wallet proposal import](POLLYWALLET-INTEGRATION.md#importing-an-agent-proposal) with independent grant regeneration. An [automated CLI-to-wallet testnet run](evidence/wallet-proposal-import-testnet-2026-10-26.json) imported, verified, installed and revoked one exact-transfer grant. | An exercised human clarification, permission review and confirmation session through the final wallet lifecycle. |
| Reference and contract checks | The reference suite, generated mutation suites, native contract tests, artifact verification, [candidate-bound preparation](DRY-RUN-PREPARATION.md), the CLI `dry-run`, which runs the account-Wasm and supported captured-target layers, and a pinned-account [state-invariant and direct-call suite](#state-invariants-and-direct-calls). | Complete layer-by-layer execution evidence and the cases that section lists as not covered; preparation explicitly reports missing runtime layers, and no report authorizes installation. |
| Account authority | Bounded storage acquisition, authority analysis, live CLI/MCP checks and install intents, alongside transaction preflight and captured-state execution. | Wallet-owned trust/approval and current integration evidence; endpoint observations are not authenticated ledger proofs. |
| Installed-rule prediction | [Live policy check](LIVE-POLICY-CHECK.md) with verified recognition, a bounded ledger/hash capture, exact configuration/state evidence and modeled spending/call limits. | Fresh wallet recheck and enforce simulation of actual authorization; additional policy/authentication models and live integration evidence. |
| Live enforcement | The [atomic live helper](ATOMIC-LIVE-HELPER.md), deployed and probed on testnet, and the wallet's [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check): after the owner consents to the exact calls and expiry, an owner passkey installation and the wallet's automation delegate transfer, simulated in enforce mode for the exact amount and one stroop more and validated case by case. Separate signing capabilities keep the delegate's testnet and offline signatures apart, and a replay check after the signatures expire. One automation run on testnet, [22 October 2026](evidence/wallet-live-enforcement-testnet-2026-10-22.json), passed with a virtual-authenticator owner. State-dependent simulation only, for one grant shape. | A run with a human owner's passkey, other grant shapes, and the derived deny suite live. |
| Wallet installation and revocation | The wallet's [installation](POLLYWALLET-INTEGRATION.md#installation) of a reviewed grant whose four layers all passed, on captured and live evidence at most 360 ledgers old, after the replay check: CLI assembly, independent re-validation in the backend and the browser, a fresh authority recheck, the owner's passkey and one fee-payer submission, recorded only with the account's own `context_rule_added` event, a matching read-back and the policy's marker. Each released entry is a replay obligation until it expires. [Revocation](POLLYWALLET-INTEGRATION.md#revocation) signs `remove_context_rule` and succeeds only with the removal event and the rule reading back absent (#3000); policy cleanup is reported separately. One automation run on testnet, [22 October 2026](evidence/wallet-install-revoke-testnet-2026-10-22.json), installed and revoked a one-call grant with a virtual-authenticator owner. | A run with a human owner's passkey, delegated calls through the wallet, testnet evidence for the implemented session-local revoke-first replacement, monitoring, other grant shapes, and installation that needs a separate restoration. |
| Testnet installation | The default harness installs one generated scope+count policy on a fresh pinned account, with a delegated or software-passkey owner; its optional authority path takes a compatible external CLI. The [subscription mode](WALKTHROUGH-SEP41.md) composes that policy with the pinned reviewed spending-limit policy, and the [Soroswap mode](WALKTHROUGH-PROTOCOLS.md) installs two independent rules separately. Lifecycle scripts observe grant/code configuration, remove each rule and check a post-removal denial. Live W2 and W3 runs record that lifecycle ([testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md), sections 8 and 9), with operator-mode approval and throwaway keys or an exportable virtual passkey. | Current lifecycle evidence, an actual user's decisions when claiming human approval of the [wallet's install and revoke flow](POLLYWALLET-INTEGRATION.md#installation), testnet evidence for the wallet's replacement and on-demand monitoring. The default installer refuses composed rules; the subscription mode refuses any composition but its own. |
| Run evidence | Checkout/CLI provenance and an allowlisted summary of available artifacts, successful transactions and simulation denials. The native-transfer wrapper now runs RPC recording, synthesis, reference checks and artifact reproduction before installation. | Reviewed current runs at the delivered revision. An export does not attest to local files or complete milestone acceptance. |
| Walkthroughs | Blend, subscription and Soroswap example inputs and local fixtures; executable native-SAC, composed SEP-41 subscription, [Soroswap two-rule](WALKTHROUGH-PROTOCOLS.md) and Blend claim harness flows; the Blend flow opens and withdraws its own USDC supply position, with controlled live runs. The Soroswap flow now takes its router bounds from the development registry's adapter binding and its floor and transfer cap from an operator file; a [controlled live run](TESTNET-EVIDENCE-TRANCHE-2.md#14-controlled-soroswap-adapter-run-26-october-2026) completed with the earlier v1 (open-deadline) binding; evidence for the current exact-deadline v2 binding remains to be recorded here. | Reviewed current live walkthrough evidence, including relevant denials, wallet approval and adapter/code-hash evidence. |
| Hosted MCP | Streamable HTTP with bearer authentication, a request quota and per-tool quotas, bounded bodies, shared build slots and separate shared authority-read capacity. A client's cancellation stops the build or RPC read it started ([hosted limits](DEVELOPERS.md)). [Self-hosting](SELF-HOSTING.md) deployment configuration behind a TLS proxy, and a [disposable build-worker mode](ISOLATED-BUILDS.md) that isolates each compilation. | Host provisioning, a published image, and a deployed testnet endpoint with operational evidence. Document the shared-token/trusted-client boundary; per-client customer accounts and billing are not supplied by this package. |
| Verification and demonstration | Phase 1 gates and the [Phase 2 gate and guide](TRANCHE-2-VERIFICATION.md). | The complete acceptance run, public demonstration and video. |

[TESTNET-EVIDENCE-TRANCHE-2.md](TESTNET-EVIDENCE-TRANCHE-2.md) distinguishes historical
observations from current checks and explains how to collect and review a new run. The
[harness README](../testnet-harness/README.md) maps each wallet-flow step to what actually runs.
The default harness now runs synthesis with explicit test decisions and signed development
registry trust; the 15 October runs filled a checked template and do not demonstrate that
chain. The controlled 20 October W2 and W3 runs ran it on live testnet, from RPC recording
through artifact reproduction, with operator-mode approval and an external CLI identified by
digest only; the default native mode has no recorded live run of that chain.
Passkey-owner support there does not change the toolkit's restriction on generated
grants using External signers.

## State invariants and direct calls

This maps the generated-policy state invariants and the adversarial direct-call suite listed
in §8 of `architecture.md` to the tests that exercise them. Tests in
`contracts/differential/tests/account_wasm_invariants.rs` run the exact pinned account Wasm and
one reviewed generated scope+count policy Wasm with real delegated Ed25519 signatures, including
for the owner's rule management; `scripts/test-pinned-account-authorization.sh` builds both
artifacts and runs them. In that suite every transaction runs in a fresh host over the ledger
the previous one committed. The ledger source refuses a persistent entry whose TTL has run out,
as the network refuses a transaction that touches an archived entry without restoring it, and a
restoration brings back the archived value, live for the minimum persistent TTL. TTL settings
are the SDK test defaults, not testnet's or mainnet's.

The policy's `install`, `enforce` and `uninstall` require only the account's authorization and
take the context rule, whose id keys the policy's state, from the caller. The account grants
that authorization under any rule that matches the policy's address: `Default` or
`CallContract(policy)`. A rule that matches the account's own address reaches the policy as
well, by having the account make the call through its `execute` method.

| Invariant | Tests | What they show |
| --- | --- | --- |
| Direct calls without account authorization | `generated_suite.rs` `direct_mutating_calls_require_the_smart_account_authorization` | All three methods fail and leave the installation unchanged (library account, mocked setup). |
| Direct calls under the grant's own rule and rule 0 | `grant_rule_cannot_reach_its_policy_and_rule_zero_is_listed_authority` | The grant's `CallContract(target)` rule cannot reach the policy: the account refuses with `UnvalidatedContext`. The owner's `Default` rule 0 alone can remove, recreate and spend the grant's state. Before installation, the call-surface check lists rule 0 with its signer. |
| Direct calls under a rule scoped to the policy's address | `policy_address_rule_can_uninstall_and_call_surface_refuses_it`, `policy_address_rule_held_by_another_key_is_listed_with_its_signer` | Held by the agent's key, the rule lets the agent alone remove the grant's state, which then denies as `MissingState`. The agent can also recreate it with a fresh cap, and spend a call with no transfer while the policy still publishes its enforced event. The check refuses that rule with `E_DELEGATE_HAS_AUTHORITY`. Held by another key, the rule is listed with that signer and the agent cannot use it. |
| Direct calls under rules scoped to other contracts | `alternate_contract_rule_cannot_reach_policy_methods` | The account refuses all three methods under a rule for an unrelated contract and under an unlimited agent rule for the target. The check lists the first as a coverage exclusion and refuses the second as an overlap. |
| Weak account-management authority | `weak_account_rule_can_create_a_policy_reset_rule`, `weak_account_rule_can_take_over_a_protected_rule_by_adding_its_signer`, `weak_account_rule_cannot_widen_the_grant_signers_but_can_strip_its_policy` | The call-surface check refuses the agent's account-address rule. Each test deliberately bypasses that refusal to show what the agent can then do alone. It can create a policy-address rule, remove exhausted policy state and reinstall a fresh cap. It can add its key to a policy-address rule held by another key, then remove the other key: the rule becomes the agent's alone and locks out its original holder. While both keys are on the rule the account requires both, and the check lists the rule with both signers without refusing it; once only the agent's key is left, the check refuses it. It can also remove the grant's policy, which uninstalls the policy's state and leaves an unlimited agent rule on the target. Adding another key to the grant itself fails closed: the generated policy refuses the changed signer set with `SignerSetDiverged` and the added key with `PredicateUnsatisfied`, and the count continues once the key is removed. The account-address rule itself still cannot directly call the policy. |
| Account methods outside the management trait | `weak_account_rule_reaches_the_policy_and_the_code_through_wrapper_methods` | The pinned account's wrapper exposes `execute`, `upgrade` and `batch_add_signer`, each guarded only by the account's own authorization. Through `execute` the agent's account-address rule alone uninstalls and reinstalls the policy, resetting an exhausted cap without creating any rule: the policy's own authorization request is met by the account as its direct caller. Through `batch_add_signer` it adds a key to the grant, which the generated policy then refuses with `SignerSetDiverged`. Through `upgrade` it replaces the account's code. The grant's own rule cannot reach `execute`. The check needs no separate case for these paths: it refuses the agent's account-address rule with `E_DELEGATE_HAS_AUTHORITY`, and lists one held by another key as `account_calls` authority with that signer, who alone can reset the policy through `execute` the same way. |
| Grant revival through weak management | `weak_management_can_revive_an_expired_rule_without_resetting_its_counter` | The agent can extend an expired target rule through a separately live account-management rule. Authorization resumes before the policy's compiled expiry, preserving the used count. The original management authority is refused by the call-surface check. |
| Expired weak rules | `expired_weak_rules_are_noted_and_revived_only_through_live_management` | Once the agent's policy-address and account-address rules expire, the check passes and lists them as expired, with the owner's rule 0 as the only authority. Expired, the policy-address rule cannot reset the policy, and the management rule can neither reset it through `execute` nor revive either rule, itself included, through `update_context_rule_valid_until`. After the owner revives the management rule, the check refuses it again, and through it the agent alone revives its policy-address rule and resets the cap. |
| Archived management rule restored and used | `archived_management_rule_is_restored_and_used_in_one_transaction` | With the agent's account-address rule entry archived, the account scan stops with `E_INCOMPLETE_ACCOUNT_STATE`, so the check gives no verdict until the entry is restored. A transaction that touches the archived entry without restoring it is refused. One that restores exactly that entry and runs at the same ledger with nothing in between, as Protocol 23 automatic restoration does, lets the agent alone create a policy-address rule, through which it then removes the grant's state. |
| Overlapping real-account grants | `overlapping_real_account_grants_have_independent_caps` | Bypassing the check's overlap refusal installs two rule IDs on the same policy instance. Each has its own cap; exhausting or removing one does not refresh the other. These are signed account authorization tests, not token-transfer executions. |
| Revoke-then-recreate reconfiguration | `revoke_then_recreate_never_overlaps_and_bounds_aggregate_use` | The check refuses adding a replacement while the old grant exists. Removing the old rule removes its policy state, the removed rule cannot be revived, and until the replacement exists the agent has no authority on the target and the check passes. A replacement that fails, here because its validity had passed, installs nothing; the retry installs with a fresh cap, and the check then refuses a further overlap. Exercising both rule IDs afterwards permits exactly one cap in aggregate. Calls already made under the old rule are in addition to that cap, as the wallet's replacement consent states. |
| Missing-state denial | `differential.rs` `missing_state_denies_in_both`; `ttl.rs` `remaining_calls_refuses_an_installation_whose_marker_is_gone`; the policy-address test above | Absent state denies; it never reads as zero. |
| Install-only initialization, double install | `differential.rs` `install_is_the_only_initializer_and_double_install_fails` | A second install is refused with `AlreadyInstalled`. |
| TTL and max-TTL bounds | `ttl.rs` (11 tests) | Conditional extension, the clamp to the compiled expiry and the network maximum, no rent on reads, denials or uninstall. |
| Archival and restoration | `archived_counter_denies_until_restored` | With the marker and counter archived, the grant, a fresh install and an uninstall all fail until the entries are restored. The suite models restoration as keeping the archived value, so the count continues; the host and protocol evidence that the network keeps it is in [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md). |
| Rule-expiration extension | `extended_rule_validity_does_not_outlive_the_compiled_expiry` | Without an extension the account refuses past the rule's expiry. If the owner extends the rule, the policy still refuses with `RuleExpired`, and a fresh install after the expiry is refused too. |
| Reinstall as a new grant | `differential.rs` `uninstall_obeys_upstream_lifecycle_and_reinstall_resets_state`; `stale_policy_state_is_refused_not_adopted` | Removing and re-adding the rule through the account gives a new rule id and a fresh count. |
| Stale-state collisions | `stale_policy_state_is_refused_not_adopted`; `differential.rs` `installation_markers_are_isolated_by_account_and_rule` | The account never reuses a rule id, and the call-surface check reads past the removed id. State created in advance for the next id, here pre-spent through a policy-address rule, makes the owner's `add_context_rule` fail with `AlreadyInstalled`; it is never adopted. Installations are isolated by account and rule. |
| Rollback of failed compositions | `failed_composition_rolls_back_the_permitting_policy`; `generated_suite.rs` `later_policy_denial_rolls_back_an_earlier_policy_counter` | With two generated-policy instances on one rule, the first permits and the second's denial rolls back the first one's increment. |
| N+1 and multi-context rollback | `account_wasm_auth.rs` `pinned_account_wasm_full_authorization`; the native worker's [stateful sequence](NATIVE-EXECUTION.md) | The cap holds across ledger advances; a two-context authorization that exceeds it rolls back entirely. |
| Survival across inactivity | `grant_survives_inactivity_until_its_shortest_ttl` | An idle grant's authorization permits, with its count intact, until the first account or policy entry it reads expires. The target's own entries are not part of this check. After that, a transaction that does not restore the archived entries is refused. A normally simulated submission restores them automatically and pays for it, so archival is not revocation. In this suite the first to expire are the account's own instance and code: nothing on the authorization path extends them, for an active grant as for an idle one. The account extends its rule, signer and policy entries to 30 days when it reads them (stellar-accounts 0.7.2, `smart_account/mod.rs:520-521`), so with real network TTLs one of those may expire first. The policy extends its own entries, instance and code to the compiled expiry. |

Not covered:

- **A reviewed policy in a composition.** The state suites compose two generated instances.
  The reviewed spending-policy Wasm is pinned and used by the live subscription walkthrough;
  that does not establish its offline composed account-Wasm execution here (item 3 below).
- **Other generated policies and accounts.** The state suite runs one generated fixture
  against one account code hash.
- **The live check end to end.** The direct-call tests feed the scan, projection and pure
  call-surface check from the local test ledger and supply the generated policy's recognition
  themselves. They do not exercise the request, the registry, the artifact rebuild or a live
  endpoint, and they scan with the reader's default bounds, not bounds declared by a signed
  registry entry.
- **Network durations.** The TTL values are the SDK test defaults. How long a real deployment
  survives idle depends on the TTLs its entries were deployed or extended with.
- **The rest of the authority-surface tests in §8.** These are not executed through the
  account here:
  - an account wrapper other than the pinned one, with management methods of its own, and the
    check's refusal of account code it does not recognize. The pinned account is the only
    account Wasm in the suite, so there is no other wrapper to run; the core's
    `unrecognized_account_fails_closed` unit test covers the refusal. The pinned wrapper's own
    `execute`, `upgrade` and `batch_add_signer` are covered above;
  - a live rule whose referenced signer or policy registry entry is archived. Of the account's
    rule data, only a rule entry is archived here; the scan's unit tests cover an archived
    signer entry;
  - the wallet's replacement flow and its recovery path. The revoke-then-recreate test makes
    the account's management calls itself.

  The call-surface core's unit tests analyse many of these shapes over constructed states.

## Implementation boundaries

The source-reviewed account method inventory and its limits are described in
[`ACCOUNT-METHOD-INVENTORY.md`](ACCOUNT-METHOD-INVENTORY.md).

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7. The pure
   core is implemented and tested over supplied `bounded_next_id` observations. It never
   says an account is safe, and its claim is scoped to the new rule's target, the account's
   management surface and the bound policies. It lists every live rule that can change the
   account or reset a bound policy, each with exactly who must sign, and refuses
   automatically when the new rule's own key could already do either alone, when another rule
   on the target gets around a stateful limit, when the new rule aims at the account or
   something it trusts, or when an in-scope rule has a shape this version does not support
   (any policy on an account-reaching rule, k-of-n, guarded recovery, contract signers,
   unrecognized external signers, classic multisig, a missing classic account). Whether the
   listed identities are the user's, or trusted by the user, is decided by the wallet that
   holds the owner key, which recomputes the result itself (Decision D7). Rules for other
   contracts are listed as not analysed. The live operation is exposed as
   `ozpb check-policy-call-surface` and the MCP tool `check_policy_call_surface`: it validates
   the request against the pinned registry trust (rebuilding generated bindings) before it
   reads anything, reads through an operator-named RPC source (never a request URL), and
   returns the structured answer with a plain-words `summary`. Over MCP it is advisory. The CLI
   command has run against live testnet accounts in the controlled W2 and W3 harness runs
   ([testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md), sections 8 and 9), through an external
   `ozpb` binary whose byte digest, not source revision, was recorded. The MCP tool has not,
   and this repository's tests use constructed scans, refuse-before-read paths and, in the
   [state-invariant suite](#state-invariants-and-direct-calls), the scan, projection and pure
   check over state the pinned account Wasm wrote in a local test ledger.

   `source-rpc` can read bounded contract-instance Wasm hashes and caller-specified contract-data
   keys. It distinguishes live entries, returned archived entries, and omitted keys. A pure
   decoder understands the pinned account's rule, signer, policy, and instance-counter shapes,
   including the code hash carried by the same instance value as its counters.
   An internal consistency check can compare supplied rule slots, `Count`, and transitive
   reference counts; it does not authenticate those values, handle absent counters on a pristine
   account, or inspect reverse lookup keys.
   A bounded account scanner now derives pinned keys, reads every rule slot through `NextId`,
   follows the signer/policy closure, checks reference counts and `Count`, observes the code at
   every installed policy address and at each contract verifier named by an external signer,
   reads the classic account entry (master weight, thresholds, extra signers) of every `G…`
   signer in the closure and of each classic account the caller names, and re-reads the
   account instance; the classic reads count against the same signed batch budget. It retries
   a changed
   endpoint ledger or instance as a whole. Returned archived or undecodable entries, missing
   referenced entries, and a count mismatch fail closed as incomplete account state; exceeded
   scan bounds, including a fixed 24 MiB ceiling on the entry XDR one scan retains, fail closed
   as a budget error. Its output remains an
   endpoint-reported inspection: equal `latestLedger` values across calls are not an
   authenticated ledger-state proof, and an omitted rule key is treated as a removed hole
   only when the stored count reconciles. The scan does not identify the wallet's intended
   administrator or establish complete reviewed method evidence. The scanner hashes the ordered
   XDR keys and values, TTL metadata, and requested absences, including inspected policy and
   verifier instances and classic account entries (whose balances and sequence numbers move it
   on every payment: it is evidence, not the authority commitment). This digest identifies
   endpoint responses, not an authenticated ledger snapshot. Reading every classic signer in
   the closure, out-of-scope and expired rules included, keeps the read simple and archive-safe
   at the cost of batches: an account with many unrelated classic signers can exhaust the
   signed batch budget and fail closed.
   A structural adapter maps the completed scan into the pure authority model, requires
   observed code for every installed policy, and carries the classic account entries. Its
   output keeps the raw XDR/TTL digest separate from the decoded core-state digest: changing a
   TTL or an unmodeled instance field can change the former without changing the latter. The
   adapter decides nothing about authority.
   The signed version-2 development registry example binds the reviewed method-map digest and
   bounded scan protocol to the exact pinned account Wasm. Version 3 extends it with the key
   scheme and statelessness of the pinned ed25519 verifier and adds OpenZeppelin's WebAuthn
   (passkey) verifier, so a passkey owner can be listed as an identity (its scheme and first
   65 key bytes; a credential id is ignored). A verifier vouches for an owner only when its
   observed code is one whose key handling was reviewed from source (compiled in per exact
   hash, like the method inventory) and its signed entry agrees; older binaries refuse the
   version-3 entry's new fields. Version 4 adds one target-adapter binding: the testnet Soroswap
   router's exact code to `soroswap-router@1`. Version 5 extends v4 and rebinds that router
   to [`soroswap-router@2`](TARGET-ADAPTERS.md#current-binding-development-registry-version-5),
   preserving the recorded deadline exactly. Both bindings are development-registry assertions,
   and the router's Wasm was not reproduced from source
   ([target adapters](TARGET-ADAPTERS.md#the-testnet-router-binding-development-registry-version-4)).
   Its public development signing key
   makes this a reproducible code-capability example, not production governance or live-state
   authority evidence. The operator reader below refuses that root unless its pinned network
   is testnet.
   An internal operator-configured reader now pins an RPC endpoint, network passphrase,
   governance roots, and a persisted registry checkpoint. It verifies a signed snapshot on
   each inspection, takes its scan bounds and reviewed method inventory from that snapshot,
   and compares the account and the selected policy bindings with code hashes observed by the
   bounded scanner. It judges nothing else: an unknown policy, an unrecognized verifier or a
   contract-address signer anywhere on the account is reported as observed, and the pure check
   refuses it where it can change the account, a bound policy or the target. Refusing one
   anywhere would refuse every check on an account that has one on an unrelated rule.
   Recognizing a binding (a reviewed registry entry, or a generated artifact rebuilt from its
   spec) is the toolkit's, from the binding set itself; the reader checks only that the
   address runs the expected code.
   The resulting projection is still `rpc_reported`: matching endpoint ledger metadata across
   calls and re-reading the instance do not authenticate a coherent ledger snapshot. A registry
   signature covers implementation capabilities, not live ledger state, and nothing a client
   sends can say who owns the account: owner matching stays with the key-holding wallet. The
   missing assurances are required before a public authority list.

   The install intent (`ozpb prepare-install-intent`, MCP `prepare_install_intent`) runs that
   live check itself — there is no caller-supplied verdict — and, only when it returns no
   refusal and nothing unresolved, returns the exact `add_context_rule` arguments derived from
   the grant the answer's commitment covers, with the answer attached. A new rule aimed at the
   account or one of its own policies, or one already expired at the read ledger, is refused
   before any read or after it respectively. Freshness is the wallet's: it re-reads and
   compares the commitment immediately before signing.

2. **Containerized build, and the BuildManifest provenance fields that go with it** (§4.4,
   §6.3 — container image digest, source commit and dirty-tree status, template-pack hash,
   canonicalization version, build target). The builder is labelled `local-unattested`, which
   is what it is, in every build mode. Adding manifest fields rehashes every manifest, so those
   fields land at a release gate. The memory, disk and cgroup limits in §4.6 are claimed only
   for the optional [worker mode](ISOLATED-BUILDS.md), which runs each build in a disposable
   rootless container with CPU, memory, PID and tmpfs limits, which its acceptance suite
   checks on the chosen host.
   The default host builder and the [Compose package](SELF-HOSTING.md) do **not** isolate one
   build from another, and no manifest records a container image. §6.3 carries a scope note
   listing the fields the manifest holds against the ones it does not, so the gap is stated
   rather than left for a reader to find by diffing the document against the struct.

3. **Reviewed-policy composition at the account-Wasm layer** (F5d). The spending-limit
   example is already built from the pinned OpenZeppelin source, recognized by its exact
   `OZ_SPENDING_LIMIT_POLICY_WASM` hash and used by the [subscription walkthrough](WALKTHROUGH-SEP41.md).
   This is our source build, not an upstream-published Wasm artifact. The remaining gap is
   execution of that reviewed policy together with the generated policy in the offline
   account-Wasm dry-run and its stateful mutation suite. A hash pin or separate spending-model
   parity check cannot establish that composition. Broader threshold-policy composition is
   also outside the implemented model.

4. **Encoded-literal rendering** — template-pack v2, and one deliberate artifact-hash break.

5. **Complete generated-suite reason agreement.** The golden transfer fixture's generated suite
   (`contracts/differential/tests/generated_suite.rs`) now replays every constraint-derived case
   through the compiled policy and checks permit/deny. For the golden fixture's unambiguous
   function, argument, signer, target, expiry, missing-state, and exhausted-counter mutations,
   it also checks the exact denial reason against a hand-stated expectation, including the
   account's refusals for unknown signers and unvalidated context. Other generated cases remain
   verdict-only. The Soroswap fixture's generated mutations also run
   through a registered account (`contracts/differential/tests/swap_generated_suite.rs`), with
   permit/deny checks over its bounded amounts, exact route, recipient, and caller-chosen deadline;
   cap, floor, route, and recipient denials must return the policy's `NoTupleMatched` reason.
   Both suites mock management setup and delegated-signer authentication. They execute the
   account and policy logic, but do not test the delegate's digest-bound signature.
   The golden fixture also checks that direct `install`, `enforce`, and `uninstall` calls
   without account authorization fail without changing its installed state. This checks
   the generated policy's gate. Alternate account rules are exercised through the pinned
   account in the [state-invariant suite](#state-invariants-and-direct-calls).
   A separate Wasm gate (`scripts/test-pinned-account-authorization.sh`) builds the exact
   recognized account from pinned public source and a generated transfer policy with a fixed
   test signer. The account reproduces byte-for-byte only on an Apple Silicon build host
   ([rust-lang/cargo#8140](https://github.com/rust-lang/cargo/issues/8140)); elsewhere it differs
   only in function order and the gate fails, so the scheduled job runs on macOS arm64. It
   checks real delegated Ed25519 authorization through the account's complete
   `__check_auth` path and rejects a changed payload. Entries that name the requested digest but
   carry a signature over another digest, a flipped signature bit, or another key are refused
   by account authentication, not invocation matching. It also commits counts across ledger
   advances and checks N+1 denial and rollback. The test pins the generated policy's Wasm hash,
   so a change to code generation or its templates, the example spec, pinned build inputs, or
   the account authorization path must rerun the script before merge. The scheduled workflow
   also runs it in its own job and fails when a prerequisite or hash is unavailable, but that is
   a backstop after merge, not the review gate.
   The ordinary contracts suite explicitly ignores this test because it needs source-built Wasm.
   This account-path test covers one fixture and one account code hash. It does not establish
   general layer-2 coverage or live preflight.
   The hand-written `differential.rs` checks both verdict and reason for its own cases. Extending
   exact-reason checks to every generated case remains future work. A local two-rule account test
   demonstrates that overlapping counted grants have independent rule-ID counters and can exceed
   one installation's cap in aggregate. Its rule setup uses mocked management authorization; it
   does not establish a safe reconfiguration flow, disposable target execution, or live preflight.
   An internal reader can check a target instance against fetched Wasm bytes. A separate
   selected-key capture can acquire that instance, its matching code, and caller-specified
   target storage keys in one final `getLedgerEntries` response, rejecting missing, archived,
   or inconsistent entries. Its preliminary discovery reads carry separate endpoint-reported
   ledgers; the final response is endpoint-reported evidence, not a historical snapshot. The
   caller-selected keys do not establish all state an invocation can read. A narrow test runs
   a small target Wasm fixture through `Env::from_ledger_snapshot` with these captured entries
   and SDK test ledger defaults; a strict source rejects an uncaptured storage read. The RPC
   capture does not supply a full ledger header or network configuration. That earlier narrow
   test does not reconstruct the original call or authorize through the account and policy.
   It does not demonstrate a stateful mutation suite. It updates one already captured
   storage key, advances the disposable ledger, and observes the committed value in a fresh
   SDK environment. A separate footprint reader captures every key declared by one original
   Soroban envelope in one bounded `getLedgerEntries` reply, including dependency contract
   keys. It validates all captured Wasm instance-to-code links. Omitted keys are unavailable
   because the endpoint does not identify their absence or archive history. The declared
   footprint is the envelope's own claim; the network enforces it only when the transaction
   executes, and the reader does not compare it with any simulation. The original footprint
   does not prove which additional keys a candidate account, policy, or changed invocation
   could read.
   One exact-footprint fixture derives the original target call from its envelope XDR,
   captures its declared instance, code, and fixed storage key in one fixture RPC reply,
   executes that Wasm from a strict SDK snapshot, and observes a committed known-key write
   after a ledger advance. Missing declared state and a changed call's uncaptured key refuse.
   A second, source-built target fixture calls `require_auth` before writing its one fixed
   balance key. It combines target entries from one checked fixture RPC reply with a freshly
   constructed account and policy snapshot, and executes the captured transfer call with
   locally signed authorization through the pinned account Wasm and generated policy Wasm.
   Only four exact new nonce keys may begin absent, and the run must read each of them. The
   target fixture debits one balance key; it does not credit a recipient.
   A direct signed account check returns the policy's exact denial for an adjacent amount.
   The target call returns only the host's generic context error, which a missing or
   mismatched authorization entry would also produce; the policy's diagnostic error event
   attributes that refusal to the same denial. The target has sufficient balance in both
   cases. The permitted write and call count commit. The committed state differs from the
   combined captured and candidate state in exactly seven keys: the balance and call count
   change value only, the permitted call's two nonces are new, and three account entries
   read by its authorization path change TTL only. Any other committed data or TTL change,
   including a deletion, fails. These tests use
   deterministic fixture RPC data, synthetic candidate account/policy state, and SDK default
   ledger header/configuration apart from the reported sequence and network ID. They
   demonstrate only these fixed-key calls. They do not establish key closure or authorization
   for arbitrary target code, reconstruct actual network account state, or provide a public
   complete dry-run report.
   The native worker's [captured-target mode](CAPTURED-TARGET-EXECUTION.md) runs one supported
   shape end to end: an exact-amount native SAC transfer from the candidate account, captured
   by a record-mode simulation, one `getLedgerEntries` read and a self-consistent `getLedgers`
   header. The real built-in SAC executes through the pinned account and generated policy Wasm
   over a strict snapshot source; the original must move exactly the amount between the two
   captured balances and, for a capped rule, advance the counter, and an amount-plus-one and
   an unsigned call must be refused by the policy with unchanged state. Recorded testnet
   responses for the public Pollywallet sample account replay offline through the same path.
   It is offline and counterfactual and covers no other target. `ozpb capture-target` and the
   MCP `capture_target` tool only produce its captured input through an operator-configured RPC
   source; `ozpb dry-run --capture-request` runs the layer from the CLI, the local Pollywallet
   backend runs it for the grant it generates from its sample transfer, and no MCP command runs
   it.

6. **Complete four-layer dry run** (§4.5). `reference_suite` is deterministic layer-1
   evidence, while the fixture suites above provide partial account-path layer-2 evidence.
   `ozpb dry-run` runs the native worker's account-Wasm layer for the selected rule and, for the
   supported native transfer, its captured-target layer, with the CLI's offline-domain signer,
   and reports whether the original was permitted and at least five derived denials reverted
   ([DRY-RUN-PREPARATION.md](DRY-RUN-PREPARATION.md#executed-layers-and-acceptance)). Its live
   layer is always unavailable, because that needs the wallet owner's consent, so its report is
   never complete; the MCP server has no signing dry run.
   `source-rpc::preflight_transaction` now makes a separate `simulateTransaction` request with
   `authMode=enforce` for one caller-supplied envelope, after refusing locally an envelope the
   endpoint would refuse before simulating, such as one with a memo. It records the endpoint's
   ledger and labels success, a failed simulation, or required archival restoration as
   state-dependent RPC evidence. A failed simulation covers an invocation or authorization
   failure and an error inside the endpoint's simulator alike, because the endpoint's text that
   would distinguish them is withheld; a refusal before the endpoint reads its ledger is an RPC
   error rather than an outcome. Restoration is reported whether the endpoint returns a separate
   restoration preamble or, as current stellar-rpc does for an invocation, restores archived
   entries inside the simulation and lists them in the simulated transaction data; neither is a
   success against the endpoint's current state. The endpoint simulates only the envelope's source
   account, its operation's host function, and its authorization entries. It does not evaluate
   signatures, the transaction fee, the sequence number, or time bounds and other
   preconditions, and for an invocation it ignores the envelope's own Soroban footprint and
   resource limits. The adapter therefore requires each declared footprint list to be exactly
   the simulated one and the declared disk-read and write bytes to cover the simulated use,
   which the endpoint reports unpadded, and reports a separate outcome naming each dimension
   that fails, without naming keys. The endpoint reports instructions and the resource fee
   only as padded estimates, so a declaration below either estimate is reported as advice
   beside the outcome and never changes it. A successful simulation says only that this
   invocation succeeded under the endpoint's state with the envelope's declared footprint and
   at least the simulated disk-read and write bytes: it does not establish that the declared
   instructions and fee suffice, that a particular installed policy was selected, that the
   same transaction will succeed at a later ledger, or that any writes committed. The caller
   must supply signed authorization entries in the envelope where the invocation needs them.
   The source adapter does not return raw RPC error details that could echo confidential
   envelope contents. General disposable execution against complete captured target and
   dependency state with a full ledger context, and a policy-bound live preflight for anything
   beyond the wallet's [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check)
   of one exact native transfer remain scheduled.

   The CLI `preflight-transaction` command and the MCP `preflight_transaction` tool expose this
   observation for one exact envelope, with the failing dimensions in
   `insufficient_declared_resources` and the advice in `below_endpoint_estimate`, apart from
   the outcome. That does not make it a dry run: they identify no
   installed policy, run no mutation suite, and give no authority verdict. Signed authorization
   entries in the envelope stay live authorizations until their expiration ledger, so a hosted
   server refuses an envelope carrying signatures, while the CLI and a stdio server send it to
   the caller's chosen endpoint.
