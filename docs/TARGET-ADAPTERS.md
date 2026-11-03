# Reviewed target adapters

Synthesis resolves optional target adapters from the operator-trusted signed registry. A
binding names an exact observed target Wasm hash, a locally supported adapter implementation,
a digest of its semantics, and a source-review reference. Clients cannot supply an adapter
implementation or override a target hash through the synthesis request.

`RegistrySnapshot.target_adapters` maps lowercase Wasm hashes to records with
`implementation`, `semantics_digest`, and `review_reference`. An empty map is omitted when
serialized: previously published snapshots retain their roots and signatures. Governance must
publish new bindings as a signed successor under its existing version/checkpoint policy.
Revocations use `target_adapter/<wasm hash>` and remain effective if the binding is removed.
An adapter cannot share a code hash with an account, policy or verifier capability.

The current descriptor is `soroswap-router@2`; `soroswap-router@1` remains supported for historical signed registries. Its digest uses the
`ozpb:v1:target-adapter-semantics` domain over the complete descriptor, including implementation
name, function name, exact arity, ordered argument types and roles. Registry tooling can obtain
it from `ozpb_domain::target_adapters::soroswap_router_v2().digest()`. A changed interpretation
requires a new descriptor version and reviewed binding; unknown identities or mismatched
digests are refused.

For `swap_exact_tokens_for_tokens(i128, i128, Vec<Address>, Address, u64)`, the roles are:

| Argument | Default constraint from the adapter |
| --- | --- |
| Input amount | Upper bound at the observed amount |
| Minimum output | Exact observed value; no quote or output floor is invented |
| Token path | Exact observed vector |
| Recipient | Exact observed address, with the usual runtime SELF binding |
| Deadline | Exact recorded `u64` timestamp; the delegate cannot replace the approved cutoff |

The entire argument signature must match before any adapter-derived widening is applied.
Short, extended, differently typed or malformed calls retain exact constraints. No binding,
unknown target code, or missing executable observation also leaves synthesis exact unless the
user explicitly widens it. Explicit user decisions remain separate: for example, a user may
supply an absolute minimum-output floor, carrying `user_widened` provenance and intent. The
adapter does not certify that decision or turn it into a trusted quote.

Adapter-derived constraints retain the adapter identity and target code hash. The resulting
rule requires that hash and marks drift as a refusal. A wallet or live checker must compare
current code before relying on those semantics; the generated policy does not inspect target
code hashes on-chain.

The registry signature authenticates a governance assertion. Its review reference is not a
proof that deployed code implements the declared semantics, and caller-carried recording
observations remain `self_supplied` at the synthesis boundary. Governance must review the
actual implementation before binding its hash. This feature alone does not establish a live
swap walkthrough or effect guarantee.

## Current binding: development registry version 5

Version 5 extends the immutable version-4 root and binds the same router code to v2.
A persisted v3 checkpoint must advance through v4 before v5; checkpoints are not discarded.
It preserves the recorded deadline as `EqScval` with `observed_exact` provenance.
The input cap remains `adapter_derived`, so the router still requires the exact observed
code hash and refuses drift. This is an argument bound; the router checks the cutoff against
its ledger timestamp. It is independent of the grant's ledger expiry and call cap.

The current W3 harness requires decisions schema v2 with
`"adapter_deadline": "keep_recorded_deadline"`. The original approved timestamp stays fixed;
it is never refreshed during synthesis. The harness rejects a widened or changed deadline,
including an explicit user any-value override, even though generic synthesis supports such
high-blast-radius decisions. Deadline-plus-one and `u64::MAX` are simulation-only denials
attributed to the router rule's policy (`#6`). Current evidence uses control set 4; historical
v1/set-3 open-deadline evidence keeps its original permit interpretation. The first live run
through this binding, on 30 October 2026, observed both deadline denials with that code, as
controls and as derived suite cases
([testnet evidence, section 17](TESTNET-EVIDENCE-TRANCHE-2.md#17-controlled-soroswap-exact-deadline-run-30-october-2026)),
and the 1 November 2026 run at `86854cee` did again ([section 23](TESTNET-EVIDENCE-TRANCHE-2.md#23-controlled-soroswap-exact-deadline-run-1-november-2026)).

The call cap remains separately configured. The live demonstration uses one successful call
per rule to keep its spend small; the library's synthetic W3 fixture uses ten. Neither value
is a universal requirement for Soroswap delegation. A larger approved cap permits repeated
calls while the same time, amount, route and recipient restrictions hold. The input cap is
per call, not an aggregate spending budget.

## The testnet router binding (development registry, version 4)

Historical version 4 of the development registry (`registry::dev::soroswap_router_successor`, preserved as
`crates/registry/src/published-v4.signed.json`) binds one hash to `soroswap-router@1`: the code of the
Soroswap router deployed on testnet at `CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD`,
`4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c`. It extends the published
version 3 directly, so a checkpoint persisted at version 3 accepts it.

**Both bindings are development-registry assertions, not governance.** Anyone can sign with the
development root key, and the deployed Wasm was not reproduced from source (below). The binding's
own review reference says both. A production deployment supplies its own governance root and
decides for itself whether to bind this hash.

### What the adapter relies on

Read from the public router source: `soroswap/core`, `contracts/router/src/lib.rs`, at tag
`v1.0`. The router directory, including its `Cargo.lock`, is unchanged from commit `8a35511`
(6 February 2024) to the head of the default branch on 22 October 2026. For
`swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`:

| Argument | What the router does with it | Role |
| --- | --- | --- |
| `amount_in` | Quotes the route for exactly this input and transfers that first amount from `to` to the first pair. A smaller value can only spend less. | Upper bound at the observed amount |
| `amount_out_min` | Refuses the swap (`InsufficientOutputAmount`) when the route's final output is below it. Lowering it weakens the only slippage check. | No automatic widening; a floor is a user decision |
| `path` | The route: input token first, output token last. Each hop's pair is derived from the factory recorded at `initialize`. | Exact |
| `to` | The only address asked to authorize: the router calls `to.require_auth()`, and the input token's transfer is from `to`. The output is paid to `to`. A swap naming another `to` asks that address, never the account. | Exact (`SELF`) |
| `deadline` | Refuses the call (`DeadlineExpired`) once the ledger timestamp reaches it. Nothing else reads it. | v1: caller-chosen; v2: exact recorded timestamp |

The historical v1 binding left `deadline` unconstrained, a **high-blast-radius** choice. A delegate may then name any
deadline, including one that never passes, so the router's own time check no longer limits
when the swap executes. The rule's `valid_until` still bounds when the account authorizes it,
and each signed authorization carries its own expiry ledger. Historical v1 reports flag this argument:
synthesis's rationale calls it unconstrained and high blast radius, and the W3 harness flags it
in its pipeline record and requires the operator to accept it
([protocol walkthroughs](WALKTHROUGH-PROTOCOLS.md#two-independent-rules)).

The role table holds only for this code. The router's Wasm imports no
`update_current_contract_wasm`, there is no upgrade entry point, and `initialize` refuses a
second call, so an instance running this hash keeps both its code and its factory. The adapter
says nothing about the factory, the pair or their prices. The harness re-reads the factory and
pair code before every call.

### Reproduction attempt

Not reproduced. The development binding is therefore a labeled assertion about this exact hash,
not a verified build of the reviewed source.

- **Source.** The hash first appears in `public/testnet.contracts.json` of `soroswap/core` on
  10 December 2024 (commit `06898c9`) and is still listed there (22 December 2025). The router
  source at that commit equals tag `v1.0`.
- **Toolchain named by the Wasm.** Its contract metadata names rustc 1.83.0 and soroban-sdk
  20.2.0 (the `Cargo.lock` version), environment protocol 20.
- **Rebuild.** `cargo build --locked --release --target wasm32-unknown-unknown` in `token`,
  `pair`, `factory` and `router`, as their Makefiles do, with rustc 1.83.0 in
  `rust:1.83.0-slim-bookworm` (linux/amd64, `sha256:540c902e99c3…`). Then the optimizer settings
  of soroban-cli 22.0.1's `contract optimize` (wasm-opt 0.116.1: optimize for size
  aggressively, converge, MVP features plus mutable globals and sign extension).
- **Result.** 34 199 bytes, the deployed size, but hash `c2efe757871b…`. A local structural
  comparison found every section other than the function and code sections byte-identical:
  types, imports, exports, data, contract spec and metadata. The function and code sections hold
  the same function bodies; seven internal, non-exported functions are defined in another
  order, and the calls to them are renumbered to match.
- **Host dependence.** The unoptimized bytes differ between `aarch64-apple-darwin`,
  `x86_64-apple-darwin` and `x86_64-unknown-linux-gnu` builds of the same rustc, and so does
  the internal function order after optimization. The original build environment is not
  published. soroban-cli 21's optimizer (wasm-opt 0.114) gives 34 354 bytes, so it was not
  that one.

A matching build would need the original builder's environment. Until a reviewer reproduces
the hash or governance reviews it, treat the binding as what it says it is.
