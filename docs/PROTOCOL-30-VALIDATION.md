# Protocol 30 validation — 4 November 2026

These observations exercise the compatibility changes at implementation revision `bfd6b845`.
The decoder and execution worker target Protocol 30, while generated contracts retain SDK 28,
Stellar CLI 27 and the existing account, verifier and helper Wasm pins.

## Automated checks

The full release-mode `scripts/verify-phase2.sh` gate passed, including workspace and contract
checks, dependency licences and advisories, source determinism and clean Wasm reproducibility.
The pinned-account gate passed with actual account, generated-policy, helper and target Wasm.
The native gate explicitly requires a policy-attributed rejection of a muxed form of an allowed
contract address, alongside a permitting ordinary-address control and unchanged state.

Wallet, harness and browser suites passed. The actual wallet-worker integration ran all eight
cases. Actual Blend and Soroswap account-Wasm runs permitted the originals and rejected the
derived mutations, including both Soroswap deadline boundary cases. Applied Pollywallet passed
frozen dependency installation, its production build, bridge tests, real Protocol-30 header
decoding and browser registration, proposal-import and Claude-pairing checks.

## Fresh testnet observations

| Path | Observation | Retained public summary |
| --- | --- | --- |
| Native transfer harness | Record → synthesize → reference → generate → reproduce → authority check → install → delegated permit → tuple/count denials → revoke → removed-rule denial | [Native transfer](evidence/protocol30/native-transfer.json) |
| CLI with a fresh RPC capture | Reference, account-Wasm and captured-target layers passed; 24 account denials and two captured denials. Live enforcement unavailable, `complete: false`. | [CLI capture](evidence/protocol30/cli-capture.json) |
| Applied wallet, virtual passkey | All four execution layers passed; expired live-check authorizations were checked for replay; installation, unchanged monitoring and verified removal completed. | [Wallet automation](evidence/protocol30/wallet.json) |

The native run's 30 reference cases are local evaluator cases. Its live policy denials are
enforcing simulations: two tuple refusals with code 6 and one exhausted-count refusal with
code 7. After removal, the account refused the absent rule with code 3000. They are not 30
submitted denial transactions. Acquisition remains `rpc_reported`; synthesis through the
supplied-recording boundary remains `self_supplied`. Artifact reproduction is a separate check.

The wallet observation is automation using an exportable virtual authenticator. Its complete
four-layer report does not attest a human permission review, confirmation or hardware passkey.
The public summaries omit session capabilities, signing keys, credential exports and local
paths. They are editable local observations; public transaction IDs allow independent receipt
lookup, but the files themselves are not authenticated ledger proofs.

## Limits and follow-up

Historical Protocol-29 captures remain unchanged and are refused for current execution.
Protocol 31 and muxed contract addresses remain unsupported. The off-chain worker still uses
SDK 30.0.0-rc.1; moving to the stable SDK requires repeating its compatibility gates.

The existing crypto-bigint exception still expires on 10 November 2026. Passing the audited
dependency gate does not mean that dependency has been fixed; see
[the reassessed exception](SECURITY-EXCEPTIONS.md).

These checks do not finish the human clarification/confirmation recording, demo video or
hosted-endpoint evidence described in [Tranche 2 verification](TRANCHE-2-VERIFICATION.md).
