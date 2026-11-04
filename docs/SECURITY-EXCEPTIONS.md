# Temporary Soroban advisory acceptance

This is explicit risk acceptance for [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
not a fix to crypto-bigint or a claim of constant-time execution. It requires acceptance by
the maintainer approving the change. IvanBelyakoff owns reassessment and removal, tracked
in [issue #94](https://github.com/gateway-fm/oz-policy-builder/issues/94).

The exception expires at **2026-11-10 00:00 UTC**. The required supply-chain gate refuses an
expired exception and refuses changes to the reviewed affected packages or their direct
dependents in any of the three workspace lockfiles. Other advisory, source and license
failures remain failures. The root workspace's reviewed affected-package inventory is empty;
introducing this dependency there also causes refusal. All six cargo-deny audits use
`--locked`, so metadata resolution cannot silently replace a reviewed lockfile after
the inventory check.

## Reviewed scope

The application baseline is public revision `c25aa212e1413f44df9f81c3cbdd42f7e07f98b5`.
Independent source review covered:

| Workspace | Dependency path |
| --- | --- |
| Contracts, native tests (original baseline) | soroban-sdk 26.1.0 → soroban-env-host 26.1.3 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5 |
| Native execution | soroban-sdk / soroban-env-host 29.0.1 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5 |
| Root CLI/MCP | No crypto-bigint dependency in the locked graph |

The affected native arithmetic is reachable. Host production call sites in both versions
parse signatures, verify P256 signatures and recover secp256k1 public keys; no operation
receiving an ECDSA private key was identified. See the respective host crates'
`src/crypto/mod.rs:99–260` and `src/host.rs` verification/recovery entry points. ECDSA
0.16.9 `src/hazmat.rs:270–291` and `src/recovery.rs:281–315` derive verification/recovery
scalars from signatures and digests. Repository signing uses ed25519-dalek instead.

The native runtime dependency is **not test-only**. ECDSA signing features are enabled
transitively even though no project signing call site was found. Offline Wasm normal/build
graphs for the contract workspace and both generated policies contain no crypto-bigint;
that does not remove the native runtime dependency.

## Contracts dependency reassessment (28 October 2026)

| Reassessed workspace | Dependency path on 28 October |
| --- | --- |
| Contracts, native tests | soroban-sdk 28.0.0 → soroban-env-host 28.0.2 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5 |

The original baseline table above remains historical; the current contracts lock inventory
records this reassessment. Root/runtime inventories and the original expiry are unchanged.

The generated policy and native contract-test dependencies move to SDK 28.0.0 /
stellar-accounts 0.8.0. The contracts host resolves to 28.0.2. Its `src/crypto/mod.rs`
is byte-identical to the previously reviewed hosts 26.1.3 and 29.0.1; its curve dependency
requirements still select the same elliptic-curve, ECDSA, P256, K256 and crypto-bigint
implementations. The affected verification/recovery arithmetic therefore remains reachable.
The accounts policy interface is used by generated policies; native mock-account tests now
exercise the 0.8 account implementation. Actual deployed-account compatibility is checked
separately against the unchanged 0.7.2 account Wasm.

The contracts fingerprint is reassessed for this dependency update. Root and runtime
inventories, accepted limitations and the 10 November expiry remain unchanged. This is
continued bounded risk acceptance, not advisory remediation. See
[dependency compatibility](SOROBAN-DEPENDENCIES.md).

## Native runtime reassessment (4 November 2026)

The protocol-30 worker uses soroban-sdk 30.0.0-rc.1 and stable soroban-env-host 30.0.0.
Generated contracts remain on SDK 28. The runtime inventory records this source/dependency
reassessment; the original **10 November 2026 expiry is unchanged**.

Host 30's P256 verification, ECDSA signature parsing and K256 public-key recovery code is
byte-identical to host 29.0.1; `src/crypto/mod.rs` adds only the ML-DSA module declaration.
The verification/recovery host wrappers and elliptic-curve dependency requirements are also
unchanged. The locked affected versions remain crypto-bigint 0.5.5, elliptic-curve 0.13.8,
ECDSA 0.16.9, K256 0.13.4, P256 0.13.2 and primeorder 0.13.6. Affected public-input
verification/recovery arithmetic remains reachable; project signing still uses Ed25519.

The new ML-DSA functions decode verifying keys and signatures and verify them; their dependency
closure contains no crypto-bigint or elliptic-curve. This adds no ECDSA private-key operation.
The locked ML-DSA and ctutils versions are outside their published affected ranges; no
additional advisory exception is introduced. This is static source/dependency review, not a
timing or machine-code proof, and it does not fix RUSTSEC-2026-0387. The existing acceptance
limits and maintainer approval requirement remain in force.

## Limits and removal

This review does not prove constant-time execution, exclude disclosure of confidential
offline inputs, or establish absence of every possible side channel. No timing study,
machine-code analysis or exhaustive dynamic reachability proof was performed. The risk
accepted is continued use of the vulnerable upstream package under the reviewed usage.

The advisory's published fixed range begins at 0.7.6; the pinned elliptic-curve 0.13.8
dependency requires crypto-bigint 0.5.x. A direct lockfile bump cannot satisfy it. An
unreviewed cryptographic backport or a changed Soroban host would require a separate
compatibility and security review.

Remove the exception as soon as a compatible fixed dependency chain is available. Reassess
before any new secret-scalar use, cryptographic signing/ECDH use, dependency change or
expiry extension. The lock inventory guard detects dependency changes; it does not inspect
source semantics or prove that future application changes preserve this review.

`scripts/advisory-exception.json` records the expiry, responsibility and normalized lock
inventories. `scripts/check-advisory-exception.py` enforces those bounds before the required
gate runs cargo-deny. Removing this advisory from `deny.toml` restores its normal failure
behavior; remove the associated metadata when retiring the exception.
