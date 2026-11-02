# OZ Accounts Policy Builder

Record a transaction, generate a minimum-permission Stellar smart-contract policy.

A **record-and-generate** toolkit for OpenZeppelin Stellar smart accounts: point at a
transaction you already performed (on-chain by hash, or locally simulated) and the toolkit
synthesizes a context rule plus a small, validated composition of policies that permits
exactly what you approved — and denies everything else it can observe. Output is
human-readable Rust implementing the OpenZeppelin `Policy` trait, produced by a
deterministic, auditable pipeline. **Code-first, deploy-second:** the toolkit itself never
deploys anything. Three components do: `scripts/demo-tranche1.sh`, the Tranche 2
[testnet harness](testnet-harness/README.md), and the local wallet backend of the
[Pollywallet integration](docs/POLLYWALLET-INTEGRATION.md), which creates an account, submits
an owner-signed sample transfer and deploys a generated policy. All three act only on testnet,
with throwaway fee-payer keys, and only when you run them.

The full technical architecture (v0.8) lives in `docs/architecture.md`. The Tranche 1
release surface is the core pipeline — recorder → PolicySpec → synthesizer → codegen —
plus the independent reference evaluator, capability registries, and the MCP operations
needed to record and synthesize. Paths explicitly marked **Tranche 2** describe or contain
ongoing later-milestone work; they are not part of the Tranche 1 delivery and are not a
claim that those milestones are complete.

Stellar/SCF reviewers can reproduce the milestone from the
[Tranche 1 verification guide](docs/TRANCHE-1-VERIFICATION.md), which maps every contracted
item to an executable check and the artifact it produces.

The [Tranche 2 verification guide](docs/TRANCHE-2-VERIFICATION.md) maps the current automated
checks and the separate live integration evidence still required for the second milestone.

## Tranche 2 status

The [contracted testnet milestone](https://github.com/gateway-fm/oz-policy-builder/issues/3)
is not complete. The integrated tree includes dry-run execution, testnet walkthroughs,
agent/wallet handoff, wallet install/revoke, revoke-first replacement and on-demand
monitoring, and self-hosting/worker packages; see the
[acceptance crosswalk](docs/TRANCHE-2-VERIFICATION.md#contracted-outcome-and-milestone-boundary)
for what is implemented and the evidence still required.

A deployed hosted testnet MCP endpoint and its operational checks, final-revision reports,
remaining invariant coverage, the executed agent workflow,
and the public demo/video still
need closure. The production versioned release (self-hostable; Gateway operates no service),
audit remediation, OpenZeppelin sign-off and mainnet wallet integration are
[Tranche 3](https://github.com/gateway-fm/oz-policy-builder/issues/4).

## The pipeline

Every stage is deterministic and fail-closed, and each hands the next a canonical artifact rather
than a call.

```
EvidenceSnapshot ─(recorder-core)→ RecordingBundle ─(synthesizer)→ PolicySpec
   ↑ acquisition adapters            (auth tree, dual hashes)        (exact tuples,
   (source-rpc / source-bundle,       evidence, trust levels)         signer predicate,
    trust derived by path)                                            provenance)
                                                                          │
                                              reference evaluator ◄───────┤ (validate → ValidatedSpec)
                                              (independent; CI-enforced    │
                                               no codegen dep)             ▼
                                                                      codegen → immutable
                                                                      Soroban policy crate
                                                                      (compiles; byte-identical
                                                                       wasm; differential-verified)
```

Read left to right: what the network actually returned becomes evidence, evidence becomes a
minimum-permission specification, and the specification becomes Rust you can read before anything
is deployed. The evaluator hangs off the middle rather than the end on purpose — it answers "what
would this spec permit?" from the spec alone, sharing no code with the generator whose output it
is used to check.

## Design invariants (enforced, not aspirational)

- **Determinism:** same canonical PolicySpec + identical pinned build inputs ⇒
  byte-identical generated source. CI runs codegen twice, cold, and diffs the bytes.
- **Exact-by-default synthesis:** every observed argument becomes a deep exact-equality
  constraint; widening only via explicit, provenance-tagged user decisions.
- **Mandatory signer predicate:** the OZ smart account defers signer validation to policies
  when a rule has policies attached — so every generated policy enforces its signer
  predicate first, and strict signer-set checking is the default for named identities.
- **Independent evaluator:** the reference evaluator shares no code with codegen; a CI
  check on the cargo dependency graph fails if that edge ever appears.
- **Fail-closed:** unknown credentials, unknown policies, ambiguous observations, and
  unregistered account hashes are machine-readable errors, never guesses; external verifiers
  are unsupported in this milestone.

The Phase 1 assurance boundary is intentionally narrow. Serialized/imported recordings
are treated as `self_supplied` when they cross the synthesis boundary; a caller cannot mint
the stronger `rpc_reported` provenance label. External-verifier signers are rejected until
their address can be bound to observed executable code. Account-hash recognition establishes
generation compatibility only: this milestone does not claim that a generated policy is safe
to install on a particular live account. The reference evaluator covers the generated scope
policy; it does not return a whole-composition permit when an attached reviewed policy is not
modelled.

## Workspace

```
crates/
  domain            pure shared vocabulary: hashes, newtypes, trust levels, provenance
  recorder-core     pure: EvidenceSnapshot -> RecordingBundle
  source-bundle     acquisition adapter for imported evidence bundles (pure)
  source-rpc        blocking HTTP acquisition adapter over Stellar RPC
  policy-spec       PolicySpec v1: schema, validation (typestate), canonical hashing
  synthesizer       pure: RecordingBundle(s) + user decisions -> PolicySpec
  evaluator         independent reference evaluator (never depends on codegen)
  harness           dry-run layer 1: constraint-derived permit/deny suite over the evaluator
  codegen           pure: ValidatedSpec -> Rust policy crate source
  build-runner      bounded local or worker builds + BuildManifest attestation of the wasm
  registry          signed registries (policy / account / verifier / template / target adapter)
  call-surface-core pure account authority check over a modeled rule set
  api-types         MCP DTOs + stable machine-readable error codes
  toolkit           the operations both shells call, and the only place they live
  mcp-server        rmcp shell over the library, stdio or streamable HTTP (no domain logic)
  cli               human-oriented shell over the same library
contracts/          separate cargo workspace: golden generated policy + soroban tests
execution-runtime/  separate cargo workspace: native account-Wasm and captured-target worker
scripts/            dependency-rule check, determinism check
testnet-harness/    Tranche 2: install a generated policy into an OZ account on testnet (node)
wallet/             Tranche 2: local wallet backend for the Pollywallet integration (node)
deployment/         Tranche 2: self-hosted MCP image, TLS proxy and disposable build workers
skills/             policy-builder Claude skills; .claude-plugin/ packages them with the server
```

The security-critical cores have unit, property, differential, and real-toolchain
gates. See `scripts/verify-phase1.sh` for the local/release distinction and
`docs/TESTNET-EVIDENCE.md` for the evidence that has actually been run; test counts alone are
not treated as assurance.

The [Tranche 2 evidence record](docs/TESTNET-EVIDENCE-TRANCHE-2.md) separates historical
testnet and browser observations from current automated checks, and explains how to capture
a reviewable harness run. The [scope map](docs/SCOPE.md#tranche-2-status) lists the remaining
wallet, harness, hosting and walkthrough work; it does not claim milestone completion.

## License

Licensed under either of **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE)) or **MIT**
([LICENSE-MIT](LICENSE-MIT)), at your option. This is the Rust ecosystem's convention, and here it
also has a specific purpose: the policy primitives this project expects to upstream live in
OpenZeppelin's MIT-licensed `stellar-accounts`, and a contribution that arrives under both licences
can go there without anyone being asked to relicense it afterwards.

The policy crates this toolkit generates carry the same dual licence, stated in the generated
source. Neither licence is copyleft, so deploying or modifying one triggers no obligation to
publish your own source; both do carry notice conditions when you redistribute the source or the
built artifact, and the dependencies a generated crate links keep their own terms — `NOTICE`
records which.

Contributions are taken under the [Developer Certificate of Origin](https://developercertificate.org/)
— one `Signed-off-by` line per commit, `git commit -s`. See [CONTRIBUTING.md](CONTRIBUTING.md).

Built in the open by [Gateway.fm](https://gateway.fm).
