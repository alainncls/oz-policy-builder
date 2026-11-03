# Tranche 2 verification guide

This guide separates reproducible automated checks from the live integration evidence required
by [architecture §10, Phase 2](architecture.md#10-delivery-plan). A passing command below is
evidence for the checked revision and named fixtures. It does not establish completion of the
four-layer harness, wallet integration, hosted service, or three end-to-end walkthroughs.
Read [SCOPE.md](SCOPE.md) and the [change review plan](CHANGE-REVIEW-PLAN.md) alongside it.

## Contracted outcome and milestone boundary

[Issue #3](https://github.com/gateway-fm/oz-policy-builder/issues/3) records the Tranche 2
requirements. [Architecture Phase 2](architecture.md#10-delivery-plan) gives their technical
design and evidence expectations. Both matter: an implementation limit must be stated against
that design, rather than silently counted as complete or moved to the next milestone.

| Contracted item | Implementation and retained evidence | Closure still needed |
| --- | --- | --- |
| Dry-run: original permits and at least five auto-mutated denials revert | Constraint-derived suites, native differential tests, real account-Wasm execution, narrow captured-target execution and live derived-denial reports exist. | Current delivered-revision reports with executed cases, layer/enforcer attribution and explicit unsupported cases. Counts from the reference evaluator alone do not establish Wasm execution. |
| Claude skill: clarification and confirm-before-deploy | Installed skill, permission-review card, human-invoked install handoff, transcript checker and independently regenerated wallet import exist. | An executed clarification → permission review → explicit confirmation → wallet handoff session. A skill file or scripted CLI import alone does not demonstrate this conversation. |
| W1: Blend yield claim | Supply-position setup, nonzero claim, withdrawal and historical live derived-denial evidence are recorded in the [protocol walkthrough](WALKTHROUGH-PROTOCOLS.md). A passing run at revision `60e1da70` on 30 October 2026 includes the per-rule account-Wasm report ([testnet evidence §19](TESTNET-EVIDENCE-TRANCHE-2.md#19-controlled-blend-claim-run-30-october-2026)), and another passed at revision `86854cee` on 1 November 2026 ([§21](TESTNET-EVIDENCE-TRANCHE-2.md#21-controlled-blend-claim-run-1-november-2026)); that emission schedule ends on 2 November 2026. | Fresh target/emissions preflight and delivered-revision permit/deny/lifecycle reports. A zero-reward claim is not a passing positive case. |
| W2: SEP-41 subscription | The [subscription walkthrough](WALKTHROUGH-SEP41.md) composes the generated scope policy and the exact pinned spending-limit policy, with historical live permit/deny and revocation evidence and passing runs at revision `60e1da70` on 30 October 2026 ([testnet evidence §18](TESTNET-EVIDENCE-TRANCHE-2.md#18-controlled-sep-41-run-30-october-2026)) and at revision `86854cee` on 1 November 2026 ([§22](TESTNET-EVIDENCE-TRANCHE-2.md#22-controlled-sep-41-run-1-november-2026)). | Delivered-revision reports; explicitly retain the unsupported composed account-Wasm layer rather than treating native-transfer coverage as composition coverage. |
| W3: bounded Soroswap | Two independent rules, explicit floor/cap decisions, a code-hash-bound router adapter that keeps the recorded deadline exact (`soroswap-router@2`), route/recipient/function controls and live derived denials exist. A passing run at revision `60e1da70` on 30 October 2026 refused deadline plus one and the maximum deadline with the router-rule policy's code 6 ([testnet evidence §17](TESTNET-EVIDENCE-TRANCHE-2.md#17-controlled-soroswap-exact-deadline-run-30-october-2026)), as did a passing run at revision `86854cee` on 1 November 2026 ([§23](TESTNET-EVIDENCE-TRANCHE-2.md#23-controlled-soroswap-exact-deadline-run-1-november-2026)). | Retain delivered-revision reports, tuple-cross-product applicability/coverage and the development-registry/source-reproduction limit below. |
| Wallet integration | [Pollywallet integration](POLLYWALLET-INTEGRATION.md) imports, checks, deploys, installs, revokes, replaces (revoke-first) and checks on demand a supported native-transfer grant; automated virtual-passkey testnet runs are retained. | Record current installation, replacement and monitoring behavior and refusals at the delivered revision. Distinguish automated signature mechanics from an actual user's permission decisions. |
| Hosted testnet endpoint | Authenticated HTTP, per-tool quotas, request cancellation, TLS packaging and disposable build workers have unit, container or containment tests. | A running reachable testnet service, a published self-hostable image and acceptance checks against that deployed service. A container build is not a deployment. |
| Public demo and video with passing reports | Walkthrough runners and historical records exist. | Assemble the final demonstration, reports and artifact inventory; record and publish the video. This is an explicit deliverable. |

The production versioned release (self-hostable; Gateway operates no service),
security-audit remediation/publication, OpenZeppelin generated-code
sign-off and a mainnet wallet installation belong to
[issue #4 / Tranche 3](https://github.com/gateway-fm/oz-policy-builder/issues/4).
The full documentation/test-suite delivery is also listed there. Tranche 2 still needs the
usage, test coverage, limitations and reproduction instructions for what it actually ships.
Monitoring, revocation, stateful-overlap handling and isolated testnet hosting are already
part of the public Phase 2 design; they are not new mainnet prerequisites added here.

### Deviations and open gaps against the Phase 2 design

These limits describe the supported surface; they are not passing evidence for missing
features. The final acceptance record must resolve or explicitly retain each relevant limit.

| Design area | Actual boundary or remaining gap |
| --- | --- |
| Four-layer harness | All four layers are available together only for the supported one-rule native-SAC transfer shape. W1/W3 account-Wasm checks do not execute their real targets offline. W2's reviewed-policy composition is unsupported by that account-Wasm path. General captured-target execution is not delivered. See [native](NATIVE-EXECUTION.md) and [captured-target](CAPTURED-TARGET-EXECUTION.md) scope. |
| Signing dry-run over MCP | The CLI performs offline-domain signing from a protected key file; MCP prepares evidence and captures supported unsigned target state. It holds no user key and exposes no signing `dry_run`. The wallet owns live consent, signatures and submission. |
| Authority and reconfiguration invariants | The exact-account [state-invariant suite](SCOPE.md#state-invariants-and-direct-calls) covers direct calls, archive/expiry, stale state, inactivity and rollback. Through weak account-management rules it also covers rule creation, adding a signer to a protected rule, removing a grant's policy, the wrapper's `execute`, `upgrade` and `batch_add_signer`, revival of an expired grant or policy-address rule, and an archived management rule restored and used in one transaction. An expired management rule stays unusable until the owner revives it. It covers overlapping grants and the revoke-then-recreate replacement across both rule IDs. Not covered through the account: other account wrappers, archived signer or policy registry entries, and the wallet's replacement flow (that section's "Not covered" list). |
| Blend adapter and conversion | W1 uses an exact recorded claim and explicit decisions; it has no reviewed Blend semantic adapter. The architecture's claim-then-convert permission bundle is not delivered by that single-claim walkthrough. Conversion is an architecture extension beyond issue #3's yield-claim wording, not an implemented ordered workflow. |
| Soroswap binding | The adapter is implemented, but its current router binding is a development-registry assertion. The deployed router Wasm was not reproduced from reviewed source. Version 5's `soroswap-router@2` keeps the recorded router deadline exact; the historical v1 binding left it caller-chosen. The 30 October and 1 November 2026 runs observed the bound live ([testnet evidence §17](TESTNET-EVIDENCE-TRANCHE-2.md#17-controlled-soroswap-exact-deadline-run-30-october-2026) and [§23](TESTNET-EVIDENCE-TRANCHE-2.md#23-controlled-soroswap-exact-deadline-run-1-november-2026)); see [target adapters](TARGET-ADAPTERS.md#current-binding-development-registry-version-5). |
| Custom source | Custom edits do not inherit generated-mode reproduction or execution guarantees. Report unavailable checks explicitly; do not turn an unsupported check into permission to install. |
| Build provenance | The BuildManifest records build inputs and hashes but labels the builder `local-unattested`; disposable worker isolation is a separately tested execution boundary. It is not a signed build-service provenance attestation. |
| Hosted operation | The packaged shared-token configuration serves one operator and trusted clients. Public multi-tenant accounts, billing and production availability are not established by it. State the chosen client boundary and test authentication, quotas, cancellation, isolation, RPC restrictions and privacy on the actual testnet host. |

### Work that can run without the wallet owner

Invariant tests, software/virtual-passkey automation, testnet walkthroughs with throwaway
identities, documentation and deployment preparation can run independently. Label virtual
credentials and scripted approvals as automation. Neither the milestone wording nor signature
mechanics require one named person or physical Touch ID.

An actual user or authorized tester must make the clarification/permission/confirmation
choices when evidence claims that conversation occurred. A real wallet grant additionally
requires its owner's consent and signing capability. These are specific actions, not a
requirement to involve the owner in every test or to invent human approval for automation.

The hosted endpoint is the remote MCP tool service, not a wallet or blockchain node. An
operator can prepare its configuration and tests independently. Provisioning requires an
authorized hosting account, client access policy, hostname/TLS ownership and an approved
budget/stop condition if it incurs cost. The owner need not choose the server technology;
those decisions should be presented as a concrete deployment proposal.

## Run the automated checks

Use the revision being reviewed and record `git rev-parse HEAD` and `git status --short` with
the results. The full command extends the Phase 1 release gate. Install the prerequisites and
check the tool versions listed in the [Tranche 1 guide](TRANCHE-1-VERIFICATION.md#1-run-the-release-gate),
then run from the repository root:

```bash
bash scripts/verify-phase2.sh
```

It runs Phase 1's formatting, lint, test, deterministic-build, and dependency checks; the
focused evidence checks below; and a Stellar CLI build of the committed Soroswap policy.
Missing release tools, failed builds, missing Wasm output, and failed evidence checks stop
the command. Success ends with `AUTOMATED PHASE 2 CHECKS PASSED (release mode)` and a reminder
of the separate live evidence requirements.

For a reduced local check:

```bash
bash scripts/verify-phase2.sh --offline
```

This passes `--offline` to the Phase 1 gate and omits the additional Soroswap Wasm build.
It therefore excludes Phase 1's real-builder tests, CLI compilation, Wasm reproducibility,
license/advisory scan, and unused-dependency check. “Offline” means no live Stellar operations;
Cargo may still fetch dependencies. It is not the release check or a milestone acceptance run.

The focused checks are also available independently, without repeating the Phase 1 gate:

```bash
bash scripts/check-phase2-evidence.sh
# CI divides the same checks between its two workspace jobs:
bash scripts/check-phase2-evidence.sh --host-only
bash scripts/check-phase2-evidence.sh --contracts-only
```

These are a subset of verification. Each selected Rust test uses its full name and must pass
exactly once; Cargo succeeding with zero matching tests is a failure. Python regression tests
exercise the gates with removed tests, failed report producers, malformed reports, and omitted
build evidence. CI runs those regression tests as well as both focused modes. PR CI does not
run the complete release command or the additional Stellar CLI build.

## What the focused checks establish

| Check | Evidence and limits |
| --- | --- |
| Subscription CLI reference suite | Labeled layer-1 outcomes, an original permit and denial controls per declared rule, agreement, and no missing required boundary classes. Summary counts, coverage, and policy gaps must match detailed evidence. Exact acknowledgements preserve repeated policy instances. |
| W1 Blend, W2 subscription, W3 Soroswap harness fixtures | Reference-evaluator agreement on the committed Rust fixtures. W3 includes amount boundaries and a caller-chosen deadline. These tests are not live protocol walkthroughs. |
| Golden generated suite | Partial layer 2: generated mutations through a test account and natively registered Rust policy, plus exact reasons for selected unambiguous denials. |
| Golden stateful cases | Permits commit counters; a later denial rolls back state, including an earlier policy's counter. An overlapping-rule test demonstrates aggregate authority across independent counters, not safe reconfiguration. |
| Soroswap generated suite | Partial layer 2: test-account/native-policy permit and denial behavior for bounds, route, recipient, and deadline mutations. |
| MCP stdio verification tests | Named verification tools have schemas, the reference operation returns evidence, and malformed specs retain structured errors. This does not test a hosted endpoint or successful real-builder verification over MCP. |

The partial layer-2 tests use the SDK 28 / stellar-accounts 0.8 native account library.
That is distinct from the recognized, separately source-built 0.7.2 account Wasm exercised
by the pinned-account authorization gate; native library tests do not substitute for that gate.

The partial layer-2 tests register natively compiled Rust in the local Soroban test host with
test accounts (`HarnessAccount` and `SwapAccount`). They do not execute the generated Wasm
artifact. Management setup and delegated-signer authentication are mocked. These tests do not
demonstrate a delegate's digest-bound signature, execution of captured target contracts,
live preflight, or a complete four-layer dry-run. The separate Soroswap Wasm build establishes
compilation only; its artifact is not executed by these tests.

The subscription acknowledgement names `oz:spending_limit`: layer 1 does not model its
stateful cap or period. An acknowledgement never waives a disagreement or missing boundary
class and never establishes on-chain composition coverage. New gaps, stale entries, and
entries for unchecked specs fail the gate. The focused gate uses one `--run` invocation with
`label=spec-path` pairs, so every declared example must actually run and pass. Repeated policy
kinds require one acknowledgement per instance. Permit-only classes are printed as limitations.
See [scope item 3](SCOPE.md) for the reviewed-policy Wasm boundary.

To retain the complete subscription report, use this inspection helper. It checks report
consistency and acknowledgements but skips the input-spec checks. Run the focused checks
above for the complete gate:

```bash
set -o pipefail
cargo run --locked -q -p ozpb-cli -- reference-suite --spec docs/examples/subscription-spec.json \
  | tee subscription-reference.json \
  | python3 scripts/check-unmodeled-acknowledged.py subscription scripts/layer1-unmodeled-acknowledged.txt
```

Review the outcomes and coverage, not only `all_agree`. The checker validates a locally
generated report's consistency; it does not authenticate a report obtained from another party.

## Evidence still required for milestone acceptance

The [Phase 2 outcome](architecture.md#10-delivery-plan) includes a public demo and video of
recording a testnet transaction, generating a policy, reviewing labeled permit/deny evidence
and the authority check, signing an install with a passkey, and revoking it. Review those
operations at the actual delivered revision; this guide does not assert that they are all
available in the current CLI or MCP surface.

The table highlights review areas; architecture §10 is the authoritative, complete acceptance
scope. Passing the automated subset above does not waive any of its requirements.

| Area | Separate evidence to review |
| --- | --- |
| Full harness | Each executed layer and its omissions; generated Wasm through complete account authentication; state-invariant tests and the adversarial direct-call suite; target execution using captured Wasm and state; current live preflight, with state and ledger anchors. |
| Authority and installation | Complete, fresh account and policy observations; intended wallet owner binding; proposed bindings and intent identities; successful and refused paths. A fixture or caller-supplied verdict cannot establish live authority. |
| Tool deliverables | The `dry_run`, `verify`, `check_against_policy`, `prepare_install_intent`, `assemble_install_transaction`, and `import_recording` operations, with their required evidence and refusal behavior through the supported shells. |
| Wallet | Consent and signature authorization, deploy/install separation, confirmed installation records, reconfiguration and overlap handling, revocation, and post-install monitoring. |
| W1/W2/W3 walkthroughs | The actual Blend, SEP-41, and Soroswap paths with code-hash-bound adapters; positive cases and relevant denials. Local reference fixtures alone do not satisfy this requirement. A permit/deny report passes as defined in [testnet evidence §7](TESTNET-EVIDENCE-TRANCHE-2.md#what-a-passing-permitdeny-report-is): the original permitted and at least five denials from that spec's own suite, identified by suite hash, refused live by their predicted enforcers, with the offline classes listed. |
| Agent workflow | Clarification of ambiguous constraints, exact permission review, and the confirmation step before deployment. The installed skill's text alone is not an executed workflow. |
| Hosted endpoint | Versioned deployment, published self-hostable image, authentication and quotas, isolated builds, RPC restrictions, and privacy controls exercised against the deployed service. |

For each live run retain the reviewed revision, tool versions, network, transaction identifiers,
account/policy/target identities and code hashes, observation ledgers, spec, generated sources,
build manifest, labeled evidence reports, wallet decisions, confirmed results, and refusals.
Distinguish mocked, captured, and live state; identify which writes committed. Preserve a full
run log and an artifact inventory with the walkthrough or video. Exclude signing secrets and
access tokens from shared artifacts. A successful historical run is evidence for that revision
and observation, not a guarantee about current network state.
