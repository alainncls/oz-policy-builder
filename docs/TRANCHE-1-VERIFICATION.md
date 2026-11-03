# Tranche 1 verification guide

This is the acceptance path for a Stellar Community Fund reviewer evaluating Tranche 1 of
the OZ Accounts Policy Builder. It reduces the milestone to claims a reviewer can reproduce
from the public repository; the architecture documents more than this tranche delivers.

The contracted milestone is recorded in [public issue #1][tranche-issue]. Its outcome is:
a recorded testnet transfer becomes a minimum-permission Rust policy that the pinned
`stellar contract build` accepts. Tranche 1 also delivers the recording and synthesis
operations through an MCP server v0.

## Known-good public evidence

The manually dispatched [`nightly live` run #33529227155][passing-run] passed on 2026-09-01
at public `main` revision [`064b76cc`][verified-revision]. It exercised:

- the recorded Rust and Stellar CLI build-input pins;
- a real Stellar-contract build and a byte-identical full clean rebuild;
- the real-toolchain boundary tests; and
- the complete Tranche 1 flow against live Stellar testnet, then its fail-closed check.

That run is evidence for the named revision, not a substitute for reproducing the checks.
The `nightly live` workflow also runs every day and can be dispatched manually from GitHub.

## 1. Run the release gate

Clone the public repository and use the revision being reviewed. To reproduce the known-good
run exactly, check out `064b76cc2a172e798a49e057735f6d692cb4e1b7`.

The repository pins Rust 1.91.1 (including `wasm32v1-none`) in `rust-toolchain.toml`. The full
release gate additionally requires Python 3, network access for the RustSec advisory database,
and these tools. Use the pinned versions below to reproduce CI's verdict:

- `stellar-cli` 27.0.0 — the workflow records its revision and release-asset checksum;
- `cargo-deny` 0.20.2; and
- `cargo-machete` 0.9.2.

The checksum-verified Linux and macOS arm64 installations of `stellar-cli` used by CI are in
`.github/workflows/nightly-live.yml`. Install the two Cargo tools with:

```bash
cargo install cargo-deny --locked --version 0.20.2
cargo install cargo-machete --locked --version 0.9.2
```

Confirm the installed versions separately:

```bash
stellar --version
cargo deny --version
cargo machete --version
```

`stellar` must report version 27.0.0 and revision
`5a7c5fe76530bf4248477ac812fc757146b98cc4`; the Cargo tools must report the versions above.
The release gate checks that the repository's configured Rust and Stellar CLI pins agree with
its recorded build provenance, but it does not reject every installed Cargo-tool version
mismatch. Then run:

```bash
bash scripts/verify-phase1.sh
```

Success ends with:

```text
ALL PHASE 1 RELEASE GATES PASSED
```

This single gate covers both Cargo workspaces and the excluded generated policy crate. It
checks dependency boundaries, publication invariants, formatting, warnings, tests, the
reference-evaluator differential suite, deterministic code generation, clean-build Wasm
reproducibility, real-builder reconciliation, licences, advisories, sources, and unused
dependencies. `--offline` is an explicitly reduced developer check and is not sufficient for
acceptance.

## 2. Reproduce the live Tranche 1 outcome

The live demo needs testnet access. It creates throwaway, Friendbot-funded identities in a
temporary configuration directory and deletes their secrets at exit. It does not use real
value, request a user's signature, or install the generated policy.

```bash
bash scripts/demo-tranche1.sh
```

A successful run exits zero and prints the retained artifact directory. Its final three
assertions are the milestone in executable form:

1. the pinned `stellar contract build` accepts the generated crate without hand edits;
2. the same `PolicySpec` produces matching Rust source files and the same recorded Wasm hash; and
3. changing only the observed account code hash to an unknown value is refused with
   `E_INCOMPATIBLE_ACCOUNT` rather than producing a policy.

Open `MANIFEST.md` in the printed directory first. It inventories every input and output. The
most useful files for independent inspection are:

| Artifact | What to verify |
| --- | --- |
| `03-recording.json` | The RPC observation, authorization call, arguments, signer evidence, and token movement that entered synthesis. |
| `04-spec.json` | The exact-by-default constraints and their provenance. |
| `05-policy/src/contract.rs` | The readable generated policy, including signer checks, limits, and named refusal paths. |
| `05-policy/build-manifest.json` | The spec, source, registry, Wasm, toolchain, and build-argument identities bound together by the build. |
| `07-policy-again/` | A second generation of the same spec; the script compares every Rust source file and the recorded Wasm hash with `05-policy/`. |
| `08-account-tampered.json` and `08-refusal.txt` | The one-field negative case and the required fail-closed result. |

The directory is the review artifact: it can be archived and handed to someone who did not
watch the command run.

## 3. Check each contracted deliverable

In the table below, a "Live demo step" is a numbered stage executed automatically by
`scripts/demo-tranche1.sh`; it does not require a synchronous presentation. A reviewer may
inspect the passing workflow run or execute the script again for fresh evidence.

| Contracted item | Primary check | Supporting evidence |
| --- | --- | --- |
| Recording layer | Live demo steps 1–3 | `crates/recorder-core`, `crates/source-rpc`, and `docs/TESTNET-EVIDENCE.md` §1 |
| Synthesizer v1 | Live demo step 4 and its tampered-input refusal | `crates/synthesizer` and the release-gate test suite |
| OZ `spending_limit` plus minimal custom `Policy` | Read the registry-resolved spec and generated `contract.rs` | `contracts/golden-transfer-policy` and `scripts/verify-pinned-upstream.sh` |
| MCP server v0 (exposes `record` / `synthesize`) | The release-gate stdio test asserts the contracted tool list and output schemas | The toolkit end-to-end recording/synthesis test, `docs/MCP-WALKTHROUGH.md`, and `docs/TESTNET-EVIDENCE.md` §3 |
| Compilable Rust policy | Live demo steps 5–7 | The passing `nightly live` run and release-gate Wasm checks |

For the slowest independent trust-anchor check, run:

```bash
bash scripts/verify-pinned-upstream.sh
```

It clones the pinned OpenZeppelin tag, rebuilds every pinned upstream contract with the
recorded compiler, and compares their Wasm hashes. Two are Phase 1 trust anchors; the
ed25519 and WebAuthn verifier pins were added for the Tranche 2 authority check. The script is intentionally separate from the release
gate because it performs a cold build of another repository.

All pins reproduce from the pinned source with the recorded compiler and CLI, but the
account pin reproduces byte-for-byte only on an Apple Silicon (`aarch64-apple-darwin`) host.
Cargo hashes the build host into the `-C metadata` of proc-macros and build scripts, which
reaches the account's symbol names, and rustc orders functions by symbol name
([rust-lang/cargo#8140](https://github.com/rust-lang/cargo/issues/8140); the remaining case is
addressed by the open [rust-lang/cargo#17522](https://github.com/rust-lang/cargo/pull/17522)).
On other hosts the account Wasm differs only in function order, so the script reports the
account as a mismatch there; it prints the build host first. The scheduled pinned-account job
runs on a macOS arm64 runner for this reason.

## 4. Acceptance boundary

Passing the checks above verifies the Tranche 1 record-and-generate milestone. It does not
claim the Tranche 2 dry-run report, agent skill, wallet install flow, hosted endpoint, or three
integration walkthroughs. It also does not claim the Tranche 3 production versioned release, independent
security audit, audit remediation, OpenZeppelin sign-off, or mainnet wallet integration.

Those boundaries are normative in `README.md`, `SECURITY.md`, and `docs/SCOPE.md`. Historical
live-network observations are in `docs/TESTNET-EVIDENCE.md`; the scheduled workflow is the
freshness check for an external network that can change after evidence is recorded.

## Reviewer checklist

- [ ] The revision under review is identified.
- [ ] `scripts/verify-phase1.sh` finishes with the full release-gate success message.
- [ ] `scripts/demo-tranche1.sh` exits zero against live testnet.
- [ ] The generated policy compiles unmodified and its manifest identities reconcile.
- [ ] Every generated Rust source file and the recorded Wasm hash match on regeneration.
- [ ] The tampered account-code input is refused, not synthesized.
- [ ] The MCP `tools/list` response exposes the contracted recording and synthesis operations with their schemas.
- [ ] Later-tranche exclusions are not counted as missing Tranche 1 work.

[passing-run]: https://github.com/gateway-fm/oz-policy-builder/actions/runs/33529227155
[tranche-issue]: https://github.com/gateway-fm/oz-policy-builder/issues/1
[verified-revision]: https://github.com/gateway-fm/oz-policy-builder/commit/064b76cc2a172e798a49e057735f6d692cb4e1b7
