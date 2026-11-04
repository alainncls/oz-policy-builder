# Soroban dependency compatibility

Generated policies and the contracts test workspace pin **soroban-sdk 28.0.0** and
**stellar-accounts 0.8.0**. This is the SDK major required by the published OpenZeppelin
0.8.0 release. The execution runtime separately pins SDK 30.0.0-rc.1 and stable host 30.0.0 because its source
snapshots and admission checks target protocol 30. The root CLI/MCP graph has no Soroban host.

These are distinct compatibility boundaries:

| Component | Version | Meaning |
| --- | --- | --- |
| Newly generated policy source and Wasm | SDK 28.0.0, accounts policy library 0.8.0 | Policy `enforce`, `install`, `uninstall`, signer and context-rule wire types |
| Native contracts differential tests | SDK 28.0.0, accounts library 0.8.0 | Current native account-library implementation; delegated authentication is mocked in the generated-suite fixtures |
| Recognized deployed account and verifier Wasm | OpenZeppelin 0.7.2, existing exact code hashes | Existing storage reader, method inventory, wallet signing and authorization protocol |
| Isolated native execution | SDK 30.0.0-rc.1 / host 30.0.0 | Runs actual account and generated-policy Wasm under protocol 30 |

The policy interface is not the account signing protocol. OpenZeppelin 0.8.0 changes
account authentication: external signatures bind the account-address-bearing
`AuthDigestPreimage`, and delegated signers authorize that preimage struct. Existing
0.7.2 accounts use the prior digest encoding. This dependency update does **not** add
recognition or wallet signing support for a 0.8 account. Unknown account code remains refused.
Do not change the old account/verifier/spending-policy trust anchors or historical run evidence
to make a newly built library appear compatible.

Newly generated artifacts have new dependency metadata, source manifests and Wasm hashes.
Current verification regenerates with the current pins: an SDK 26 artifact must not be
relabeled or accepted as an SDK 28 reproduction. Use its original recorded repository
revision to reproduce historical artifacts; regenerate and review proposals intended for
new installation. Existing installed Wasm is not upgraded by changing these dependencies.

The 0.8 spending-limit helper also changes behavior: it caps history at 815 entries and
permits zero transfers before checking an already exceeded budget. The production prediction
model continues to describe the exact recognized 0.7.2 policy. Its boundary/capacity parity
tests therefore execute that hash-checked Wasm in the pinned-account gate, rather than treating
the new native library as a substitute. Separate native tests pin these intentional differences.

The required cross-version proof is `scripts/test-pinned-account-authorization.sh`: newly
built policy Wasm must run through the exact recognized 0.7.2 account Wasm, including signed
delegate authorization, forged-signature refusal, persistent counters, rollback and the
state-invariant suite. The native 0.8 mock-account tests and shared XDR vectors supplement
that proof. They cannot replace it. The `nightly-live.yml` workflow also runs this gate
on pull requests changing the spending evaluator, policy generator/specification, contract
source/tests, native execution runtime, dependency locks/manifests or recorded gate inputs. The two parity tests must actually run and pass;
scheduled/dispatch checks remain a backstop, not their only execution opportunity. A dependency change also requires reviewing changed
policy, helper and target fixture Wasm hashes, byte reproducibility, and fresh testnet evidence
at the delivered revision. Passing ordinary PR CI alone is insufficient for release.

## Protocol 30 compatibility

The CLI/MCP decoder uses stable stellar-xdr 30.0.0. It accepts acquisition protocols through
30 and refuses future protocols; the acquisition protocol is the endpoint's current protocol,
not an assertion of a historical transaction's execution protocol. The execution/capture worker
accepts only source protocol 30. Protocol-29 captures and jobs remain historical evidence and
are not relabelled for host 30; record fresh captures for current execution.

CAP-88 headers carry millisecond extensions. Both Rust and wallet SDKs decode them while
preserving whole-second close-time semantics; advancing ledgers need not advance whole seconds.
Muxed contract addresses (`W…`, CAP-84) remain unsupported: recording refuses them and exact
plain-address constraints do not normalize them into an allowed address.

The worker's release-candidate SDK is off-chain only. The generated policy/helper SDK 28.0.0,
OpenZeppelin pins, CLI 27.0.0 build pin and recognized account/verifier Wasm are unchanged.
Move the worker to stable SDK 30 when available and repeat its compatibility gates. Current
contracts continue to run on protocol 30; the host migration does not upgrade installed code.
The wallet backend/harness use JavaScript SDK 17.4.0; the applied Pollywallet root is pinned
with its lockfile to SDK 16.4.1, which also decodes protocol-30 headers.

Recording decoder identity is checked. Older RPC recordings made by the XDR-28 build require
fresh acquisition while RPC retains the transaction, or an explicit self-supplied raw-XDR
import. Do not change decoder metadata to make an old acquisition appear current. Reacquisition
can change recording/spec hashes; it does not by itself change generated Wasm permissions.

[Protocol 30 validation](PROTOCOL-30-VALIDATION.md) records the automated gates and fresh
testnet observations separately from the historical Protocol-29 evidence.

Sources: [SDF Bell upgrade guide](https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide),
[SDK 30 release candidate](https://github.com/stellar/rs-soroban-sdk/releases/tag/v30.0.0-rc.1),
[CAP-88](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md).

## Live-helper rollout

The SDK update also changes the helper's built Wasm hash. The wallet's reviewed helper pin
and the native execution test pin move together. Existing historical testnet receipts retain
their original hash; they are not evidence for the new helper build. Deploy the new source-built
helper with `testnet-harness/scripts/deploy-live-helper.mjs`, verify its readback receipt, and
configure the wallet server with that new address before repeating live-layer checks.
The manually dispatched `nightly-live.yml` workflow accepts `helper_probe=true` to run this
probe after the pinned-account gates; its public receipt is retained in the job log. It uses
throwaway automation keys, not wallet consent or human approval. A server
still configured with an old helper address is refused by the new hash check. No installed
account or policy is automatically upgraded by this rollout.

## Security follow-up

This update does **not** resolve [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
As checked on 28 October 2026, the published Soroban hosts through 30.0.0 still require
elliptic-curve 0.13 / crypto-bigint 0.5.5. The advisory's fixed range begins at 0.7.6;
a direct update to that version cannot satisfy the old dependency requirement. No unsupported
cryptographic fork is introduced here.

The [temporary exception](SECURITY-EXCEPTIONS.md) retains its **10 November 2026** expiry.
[Issue #94](https://github.com/gateway-fm/oz-policy-builder/issues/94) remains open until all
affected native/test graphs use a compatible fixed chain, the audits pass without the ignore,
and the exception can be removed. A full account 0.8 migration additionally needs explicitly
versioned signing, registry, storage, wallet and testnet compatibility coverage.

Sources: [OpenZeppelin 0.8 release](https://github.com/OpenZeppelin/stellar-contracts/releases/tag/v0.8.0),
[account migration guide](https://github.com/OpenZeppelin/stellar-contracts/blob/v0.8.0/packages/accounts/README.md),
[Soroban host 30 manifest](https://github.com/stellar/rs-soroban-env/blob/v30.0.0/soroban-env-host/Cargo.toml).
