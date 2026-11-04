# Testnet harness (Tranche 2)

Installs a generated policy into an OpenZeppelin smart account on Stellar testnet and shows the
account enforcing it. Signing is done the way a wallet would do it, with no wallet product
involved. Not to be confused with `crates/harness`, the offline dry-run harness. This one talks to
the live network and spends testnet XLM.

```
bash testnet-harness/run.sh                                                       # owner: an ed25519 key
OZPB_HARNESS_OWNER=passkey OZPB_BROWSER_CHANNEL=chrome bash testnet-harness/run.sh   # owner: a passkey
```

The account's owner is the one signer of its rule 0, and it is what authorizes the recorded
transfer and the install. By default it is an ed25519 key held by the script. With
`OZPB_HARNESS_OWNER=passkey` it is a passkey, created and used headless in Chrome's virtual
authenticator, behind the pinned OpenZeppelin WebAuthn verifier: the kind of account a passkey
wallet such as pollywallet creates. Everything else is the same in both runs, the delegate
included.

The default native-transfer run, on fresh throwaway keys:

1. **setup** deploys the pinned OpenZeppelin account example from its wasm hash. It checks that
   the code hash the network reports is the pin in `ozpb_domain::pinned_upstream`, reads rule 0
   back (Default context, exactly the owner, no policy, no expiry), then funds the account. With a
   passkey owner it first deploys the [pinned WebAuthn verifier](#the-pinned-webauthn-verifier)
   from its hash, checks the code hash, and creates the passkey.
2. **owner transfer** has the owner authorize a real 1 XLM transfer through rule 0 and
   retains its raw-XDR import bundle. With a passkey owner, a signature over the wrong challenge
   must be refused by the verifier with `ChallengeInvalid` (#3114).
3. **record → synthesize → reference → generate → verify** runs the selected `ozpb` CLI.
   `record` reads the executed transaction and the account's executable through RPC. The
   harness checks the exact transfer and observed account code, then makes its test decisions
   explicit: a separate delegated signer, one call, a one-day ledger horizon, no widening, and
   no composed spending policy. `synthesize` resolves the signed registry and revalidates the
   supplied recording; crossing that JSON boundary lowers its trust to `self_supplied`.
   The reference suite must have no disagreements, missing boundary classes, or unmodeled
   policies. After generation, `verify` must reproduce the source, Wasm and manifest and pass
   its modeled behavior checks. A zero CLI exit alone is insufficient. All reports remain in
   the run directory; only a fully completed chain writes `pipeline.json`.
4. **install** deploys the verified Wasm, then calls `add_context_rule` with the owner signing.
   The policy's own `install` runs inside that call. The script reads back `is_installed`.
5. **permit/deny**: the delegate makes the account call the native SAC's `transfer`.
   - The exact recorded transfer is permitted once.
   - One stroop more is refused with the policy's `NoTupleMatched` (#6).
   - Another recipient is refused with #6.
   - The exact transfer a second time is refused with `CallCountExceeded` (#7).
6. **observe/revoke** reads the installed grant and its account/policy code pins, then has
   the owner sign removal of exactly that rule. It verifies the pinned account's removal
   event, checks that the rule is absent and separately observes policy cleanup. A final
   delegate attempt must fail with the account's `ContextRuleNotFound` (#3000). The already
   exhausted policy's #7 does not satisfy that control. The earlier installation record is
   retained alongside the removal journal.

Every address, transaction hash and outcome goes into `runs/<timestamp>-<pid>/run.json`, which
is gitignored. The run directory also holds the import bundle, RPC recording, explicit decisions, synthesis
response, spec, reference report, generated crate and reproduction report.

`run.sh` requires an empty output directory. It records the checkout commit, dirty state,
Node version, and start/end timestamps in `provenance.json`. With `OZPB_BIN`, it hashes the
selected executable's bytes; that hash does not prove the binary was built from the checkout.
PATH lookup skips files the current user cannot execute; an explicit unusable executable
path is refused. Executable paths preserve filesystem traversal through symlinks and `..`,
so the digest identifies the file the shell selects. A symlinked checkout or reporting
script still runs the startup checks, finalization and evidence export.
Cargo mode records the checkout and explicitly leaves the executable hash unavailable.
Provenance startup requires only Node's built-in modules and Git, so it can run before npm
dependencies are installed. Evidence validation loads at finalization. If a derived replay
fails while reading live policies, its unfinished journal can report a partial policy order
only while no simulation has started; completed evidence always requires the full order.
These observations describe startup, not changes made to the checkout or executable during
the run. The exit status is process bookkeeping, not an acceptance verdict.

On normal shell exit, including a failed step, it writes `evidence.json`: an allowlisted
summary of recorded addresses, transaction IDs, policy-error codes and available artifact
digests. A hard kill can leave provenance unfinished. An exporter error fails the wrapper
and updates its recorded exit code; an existing failure retains its original code. Successful
summaries are published by atomic rename so an interrupted write cannot leave partial JSON
and an output symlink cannot redirect the write. Malformed records, including explicit JSON
`null`, are refused; only absent files count as missing evidence.
The summary omits seeds, passkey credential data, local paths, RPC URLs, free-form errors and
operator trust files. It still reveals public account relationships, so review it before
sharing. It is never published automatically. Raw run files remain local.

To regenerate the summary for a saved run (including an older run without provenance):

```bash
node testnet-harness/scripts/evidence.mjs --run-dir /path/to/run --write
```

`--write` validates the records before atomically replacing `evidence.json`. A refused export
preserves the previous summary; an output symlink is replaced without writing to its target.
Without `--write`, the command prints the summary to stdout.

Old runs say provenance is unavailable. A missing install record means installation was not
recorded, not that nothing was submitted. Permits carry submitted transaction hashes; denials
are labeled enforcing simulations and have no transaction hash. Artifact digests cover exact
file bytes, including whitespace in JSON; they are not the canonical spec hash or independent
Wasm reproduction. Local records can be edited, and neither a zero exit nor this summary
establishes authenticated ledger state or completion of the milestone.

The export labels the pipeline as `recorded` only when its completion record exists. It keeps
RPC acquisition trust separate from the synthesis boundary's `self_supplied` trust and reports
artifact reproduction separately from current-network preflight. These remain editable local
observations. Older runs say `not_recorded`; they do not acquire results from the new pipeline.

If a protocol bundle's approval or pre-sign recheck refuses, the local journal records the
refusal stage and the terminal log includes the redacted reason. No install is signed after
that refusal. Public evidence reports only the refused status, without diagnostic text.
Lifecycle records likewise distinguish a confirmed removal transaction, its checked event,
the rule readback and best-effort policy cleanup. A later readback failure does not erase the
confirmed transaction. The observations come from the configured RPC; they are not ledger proofs.

A failed run with a confirmed installation attempts owner removal before discarding its
temporary keys. The cleanup binds the saved run bytes and rechecks the exact account, rule and
policy configuration. Its entire child process group has a fixed 600-second deadline and a
five-second termination grace. A requested kill must be followed by the child's close event
before the wrapper reconciles the journal. If termination cannot be confirmed, the separate
`cleanup-termination.json` marker records that uncertainty; the wrapper discards keys but
leaves the child-owned run/provenance files unfinalized. The original failure status is preserved. `failure_cleanup: incomplete` means the live grant may
remain; secret deletion does not revoke it. A `run.json` that exists but cannot be read is
reported the same way (`incomplete (unreadable_journal)` on stderr; nothing is written back),
since it may have been cut short after recording an installation. The journal records a removal hash before send,
so an interrupted or unconfirmed submission remains `pending_removal` and is never sent again.
The next cleanup checks the network first, then reconciles it from its hash. One that landed
is verified and marked `reconciled`. One that failed is kept by hash under `failed_removals`, and
so is one the endpoint has not seen. The second case counts only when the endpoint's latest
ledger closed after the transaction's validity window and it still retains the window's start,
both by close time and by the ledger the submission was simulated at. The close times must be
well-formed and ordered; the local clock never decides it. One fresh removal may then follow, never a third; anything else
stays pending. Polling is bounded, and the cleanup child prepares a removal only while 240
seconds remain before its deadline, so it stops before the kill. Removal readbacks count only
from an endpoint at or after the removal's ledger; a stale read is retried, never recorded.
Journals are replaced atomically (synced temporary file, then rename). The cleanup child's stdout
and stderr go to a new private `cleanup-child.log` in the run directory: transaction hashes and,
on failure, one line with the stage or error and the run's secrets redacted, with no stack.

The [Tranche 2 evidence record](../docs/TESTNET-EVIDENCE-TRANCHE-2.md) describes the historical
runs separately and gives the field-by-field review procedure for a new summary.

For W1/Blend and W3/Soroswap, first build the trusted native worker with
`cargo build --locked --manifest-path execution-runtime/Cargo.toml` and set
`OZPB_NATIVE_WORKER=/absolute/path/to/ozpb-execution-runtime` when invoking `run.sh`.
The precheck requires a regular executable owned by the caller or root and not writable
by group/others; it runs before live setup. The offline report gate applies to `run.sh`;
a manual permission-bundle API invocation is a separate operator-controlled path.

## Prerequisites

- Node ≥ 22.12 (required by `@stellar/stellar-sdk` 17), `stellar` CLI 27.0.0, and the Rust
  toolchain `rust-toolchain.toml` pins, with `wasm32v1-none`. The CLI is used by
  `ozpb generate`.
- Network access to `soroban-testnet.stellar.org` and Friendbot. Override the RPC with
  `OZPB_RPC_URL`. The scripts' own output and `run.json` show only its origin, but an error raised
  inside the RPC client can still print the full URL, so keep credentials out of it. Every script
  that signs first checks that the endpoint serves testnet.
- `run.sh` runs `npm ci` in `scripts/` and `../wallet` every time (the authority decision is the
  wallet's module). Dependencies are pinned exactly and locked.
- `ozpb` comes from `cargo run -p ozpb-cli`, or from `OZPB_BIN`. `ozpb generate` builds with
  cargo offline in its build cache (`OZPB_BUILD_CACHE_DIR`), so `run.sh` first fetches the golden
  crate's locked dependencies.
- Synthesis uses the committed testnet development registry by default. To use operator trust,
  set all three of `OZPB_SIGNED_REGISTRY_SNAPSHOT`, `OZPB_REGISTRY_ROOTS_FILE` and
  `OZPB_REGISTRY_MIN_VERSION`. Partial configuration is refused. The development root is public
  test configuration, not production governance. An authority-check run also requires
  `OZPB_REGISTRY_SNAPSHOT_ROOT`; synthesis must resolve exactly that root.
- Before installing, `ozpb reference-suite` validates and canonically hashes the current spec.
  Its hash must match the adjacent build manifest, alongside the Wasm hash, rule index and
  registry root. This runs on both install paths with the same `OZPB_BIN` (or local Cargo CLI)
  as generation. It catches stale artifacts; it trusts the local generator's manifest rather
  than reproducing the Wasm. The default wrapper also runs `ozpb verify` and requires successful artifact reproduction.
- The default installer accepts exactly one generated scope+count policy. The explicit
  [subscription mode](../docs/WALKTHROUGH-SEP41.md) requires the full authority-check path and
  exactly one generated policy plus the pinned reviewed spending-limit policy, with both
  instances bound to their spec indices. Other compositions are refused before deployment.
  The [Soroswap mode](../docs/WALKTHROUGH-PROTOCOLS.md) does not use this installer: it installs
  each of its two independent scope+count rules separately through `bundle-command.mjs`. Its
  output floor and transfer cap are the operator's, read from `OZPB_SOROSWAP_DECISIONS`
  (example: `soroswap-decisions.json`); the router's input bound comes from [registry adapter v2](../docs/TARGET-ADAPTERS.md#current-binding-development-registry-version-5),
  and the approved recorded deadline stays exact. That binding is a development-registry assertion, and the router's
  Wasm was not reproduced from source
  ([target adapters](../docs/TARGET-ADAPTERS.md#reproduction-attempt)).
  Once deployment succeeds, its address, Wasm hash and transaction hashes are saved before
  asking the wallet to approve. A refused or declined attempt retains those identifiers;
  a rule ID and install transaction are recorded immediately after the install is confirmed,
  before the policy readbacks. A failed readback still fails the installer, but retains those
  identifiers. Their presence records installation, not successful readback verification.
- A passkey owner also needs headless Chromium: `run.sh` runs `npm ci` in `browser/` too, and
  `OZPB_BROWSER_CHANNEL=chrome` uses an installed Google Chrome (otherwise run
  `npx playwright install chromium` there once). `OZPB_HARNESS_VERIFIER=C…` reuses an existing
  verifier instance instead of deploying one; its code hash is checked the same way.

## Keys

Every harness submission uses explicit enforcing simulation and a fixed total fee ceiling,
including Soroban resources. By default it is 10,000,000 stroops (1 testnet XLM). A call known to
cost more names its own ceiling, at most 100,000,000 stroops (10 testnet XLM); the Blend calls
name 3 XLM. A Wasm upload, classified only from the original intended operation, defaults to
10 XLM. It is the only transaction that may name more, at most 200,000,000 stroops (20 testnet
XLM). The W1, W2 and W3 installers name 150,000,000 stroops (15 testnet XLM) for each generated
policy's upload; the default native run shares W2's installer, so its upload names it too.

An upload pays the write fee and rent for a new code entry, and those follow the network's
prices. A read-only estimate on 20 October 2026 for a 21,607-byte generated policy at ledger
5293145 required 89,730,616 total stroops (8.97 XLM). On 22 October 2026 the W3 router rule's
21,814-byte policy assembled at 101,220,139 stroops (10.12 XLM), so the ten-XLM ceiling refused
it before signing; about an hour earlier the same upload had assembled at 99,760,084 stroops.
Fifteen XLM leaves room for that drift on testnet. It is not a promised future fee and is not
meant for mainnet. Before the payer signs, assembly must preserve the exact operation, authorization entries, source, sequence, memo,
time bounds and network. Extra signatures, authorization or operations are refused. A
resource estimate above the ceiling stops the run; the harness never raises it automatically.
For a source-funded setup operation without existing authorization, the harness constructs
one source-account entry locally from that exact host function, with no nested calls.
Contract uploads need none. It does not accept authorization entries supplied by RPC.

`setup.mjs` generates these keys with `Keypair.random()` and funds them from Friendbot:

- payer: pays fees and deploys the contracts
- owner: the account's administrator (ed25519 runs only)
- delegate: the grantee
- recipient

The seeds go to the file `OZPB_HARNESS_SECRETS` names. `run.sh` points it into a `mktemp -d`
directory and deletes that directory on exit. Seeds are never printed and never written to the
run directory. Only the payer, owner and delegate seeds are kept; the recipient's is dropped.

A passkey owner has no seed. Its credential lives in Chrome's virtual authenticator, which dies
with the browser, and the run signs from separate scripts with cargo steps in between. So after
creation the credential, private key included, is exported through the DevTools Protocol into the
same secrets file, and each later signature imports it into a fresh virtual authenticator. That
makes the owner a WebAuthn assertion from Chrome's virtual authenticator over a software key the
harness holds; a real authenticator never lets its key out. Playwright's `pw:protocol` and
`pw:channel` debug logs would print that key, so `browser/passkey.mjs` refuses to start when
`DEBUG` could enable them. The passkey's public key and credential id are public and go into
`run.json`.

## How the account is signed for

Whatever the signer, `__check_auth` in `stellar-accounts` 0.7.2 first binds the rule selection
into the payload: `auth_digest = sha256(signature_payload ‖ xdr(context_rule_ids))`. The signer
then proves it authorized that digest. How depends on its kind.

The delegate, and the owner in an ed25519 run, are `Delegated` Stellar accounts. For such a
signer the account calls `signer.require_auth_for_args((auth_digest,))`, so a call from the
account carries two authorization entries:

- **The account's own entry.** Its signature is an `AuthPayload`. It names the signer with an
  empty proof and selects the rule.
- **The signer's entry.** It is rooted at `account.__check_auth(auth_digest)` and signed with the
  signer's ed25519 key.

`scripts/lib.mjs` builds both. `lib.test.mjs` checks the encodings against bytes written out from
the XDR definitions. It also verifies the signer's signature with node's own ed25519, not the
SDK's.

A passkey owner is an `External` signer: `External(verifier, key_data)`, where `key_data` is the
65-byte uncompressed P-256 public key followed by the credential id. pollywallet lays its key data
out the same way. For such a signer `__check_auth` calls
`verifier.verify(auth_digest, key_data, sig_data)`, and there is no second entry. The proof is in
the account's own `AuthPayload`:

- The passkey signs with WebAuthn `navigator.credentials.get`, challenge = the 32-byte
  `auth_digest`. The verifier requires `clientDataJSON` to be a `webauthn.get` whose challenge is
  `base64url(auth_digest)`, and the user-present and user-verified flags to be set. It does not
  check the origin, the relying party or the sign counter.
- `sig_data` is the XDR of `WebAuthnSigData { authenticator_data, client_data, signature }`. The
  signature is 64-byte r ‖ s with s folded into the lower half of the group order. WebAuthn
  returns DER, and the host refuses a high-s signature.

`browser/passkey.mjs` drives the browser, and checks every assertion with node's crypto
(`browser/assertion.mjs`) before it is used. `scripts/owner.mjs` turns it into `sig_data`.
`lib.test.mjs` checks the External signer, `AuthPayload` and `WebAuthnSigData` bytes the same way
as the Delegated ones. It also checks the DER conversion against node's P-256.

## The pinned WebAuthn verifier

The passkey's verifier is OpenZeppelin's WebAuthn verifier example. It comes from the same tag,
commit and toolchain as the pins in `ozpb_domain::pinned_upstream`:

- Source: `github.com/OpenZeppelin/stellar-contracts` `v0.7.2` (`a9c42169000638da937577f592ebf61a7a3c94ca`),
  `examples/multisig-smart-account/webauthn-verifier`.
- Build: `RUSTUP_TOOLCHAIN=1.91.1 stellar contract build` in that directory, with stellar-cli
  27.0.0. That is the command `scripts/verify-pinned-upstream.sh` uses for the other pins, and the
  same build reproduces the pinned account hash.
- Wasm hash: `e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76`
  (`PINNED_WEBAUTHN_VERIFIER_WASM` in `scripts/rpc.mjs`). `setup.mjs` deploys an instance from
  it, which needs the code already on the ledger: like the pinned account wasm, the harness
  never uploads it. On 2026-10-15 its code entry was live until ledger 7878982. After it is
  archived, or after a testnet reset, the deploy fails until someone uploads (or restores) the
  same bytes, built as above.

The verifier can neither change nor remember anything. Its source has no storage, constructor or
upgrade entry point. The built wasm exports only `verify`, `canonicalize_key` and
`batch_canonicalize_key`, and imports no ledger host functions: none of the contract-data calls,
and not `update_current_contract_wasm`, the only way an instance's code can change. So every
instance of this hash gives the same answer for the same input, and nobody, its deployer
included, can change that.

The version-3 development registry recognizes this exact verifier.
`scripts/verify-pinned-upstream.sh` does not rebuild it. pollywallet's verifier is not this
code: its contract metadata shows a different soroban-sdk and stellar-cli, so it does not
reproduce from our pinned inputs.

## Running the parts

```
cd testnet-harness/scripts && npm ci
npm ci --prefix ../../wallet --ignore-scripts          # the wallet's shared authority decision
npm test                                               # offline installer and wallet tests
export OZPB_HARNESS_SECRETS=$(mktemp -d)/keys.json
node setup.mjs --run-dir R                     # or --owner passkey, after npm ci in ../browser
node invoke.mjs --run-dir R --signer owner --rule 0 --amount 10000000 --to <recipient> \
    --expect permit --bundle R/import-bundle.json
node synthesis-flow.mjs --run-dir R          # real record/synthesis/reference/build/verify
node install.mjs --run-dir R --wasm R/policy/<name>.wasm
node invoke.mjs --run-dir R --amount 10000000 --to <recipient> --expect permit
node monitor.mjs --run-dir R                  # read-only grant/code observation; no signing key
node derived-denials.mjs --run-dir R          # W1/W2/W3 only: this spec's suite, enforcing simulations
node lifecycle.mjs --run-dir R                # owner signs removal; needs the run's keys
node invoke.mjs --run-dir R --amount 10000000 --to <recipient> --expect deny-account:3000
```

`deploy-live-helper.mjs` runs setup, the owner transfer and the synthesis chain itself with its
own throwaway keys, then deploys the [atomic live-enforcement helper](../docs/ATOMIC-LIVE-HELPER.md#testnet-deployment)
and simulates one permit and one denial through it. It runs `ozpb` as the other steps do (`OZPB_BIN`,
or Cargo) and needs `stellar`.

CI runs both this suite and `npm test` in `testnet-harness/browser`, with locked dependencies
and pinned Node. The installer tests run the real local CLI (`OZPB_BIN`, or Cargo) but mock
the RPC and key boundaries; they require the Rust dependencies to be cached for offline use.
The browser suite tests the passkey modules without launching a browser. Neither suite signs
or submits a live transaction.

`monitor.mjs` is a one-shot configuration observation, not a background service. It checks
this rule's target, name, expiry, signer and policy identities and the account/policy code pins.
Each account-code, policy-code and rule read retains its own RPC ledger number. These are
explicitly non-atomic observations, not a common-ledger snapshot or authenticated proof.
It records drift or unavailable observations and fails closed; it does not enumerate the
account's complete authority surface or prevent changes after its reads. The wrapper runs it
after installation and before removal. Full wallet-owned call-surface monitoring remains required.

The removal decoder follows the exact pinned account's embedded event specification, captured
in `scripts/fixtures/context-rule-removed-spec.json`: `context_rule_removed`, a `u32` rule topic,
and an empty map. The release's function comment says `[]`, but the compiled event's
`data_format` is `map`. It checks the successful transaction/envelope identity, the exact
removal call, event contract and rule, and refuses missing or conflicting removal events.
OpenZeppelin's pinned removal implementation attempts policy uninstall on a best-effort basis,
so a removed rule and a policy still reporting installed are distinct outcomes. The journal
retains both. Neither these offline controls nor the executable flow is a new live observation.

`invoke.mjs --expect deny:<code>` passes only if both of these hold:

- the account's authentication failed;
- the policy contract itself raised that code.

The same number from another contract does not count. The native SAC's #6, for example, is
`AccountMissingError`. The passkey's negative control,
`invoke.mjs --signer owner --rule 0 --wrong-challenge yes --expect deny:3114`, counts the code only
when the WebAuthn verifier contract raised it.

## Derived denials

`derived-denials.mjs --run-dir R` runs right after installation in the W1, W2 and W3 modes,
before any delegated call. It replays the spec's own layer-1 suite against the installed rules:

- `ozpb reference-suite --spec R/spec.json --emit-cases` writes `R/derived-cases.json`. The
  script requires three things of the emitted list:
  - its spec hash is the installed artifacts' (`pipeline.json` or `protocol-pipeline.json`);
  - its `suite_hash` recomputes over exactly those cases;
  - its labels, classes and expectations are the ones the pre-install reference report agreed with.

  The suite hash is a checksum, not a signature. What binds the cases to the grant is that the
  script runs the CLI on the installed spec itself. To check a report, re-run that command on
  the retained `spec.json` and compare.
- Each rule's recorded call (the call the grant was synthesized from) must be permitted.
- Every deny case of a live-realizable class is then replayed in suite order, not chosen by name:
  argument mutations applied to the recorded call, the function and contract classes, and the
  signer sets. Fewer than five such cases refuses the run before anything is simulated.
- Each rule must have exactly one allowed tuple, because mutations are applied to the one call
  the run recorded for it. A rule with several tuples is refused. Those are the only rules with
  cross-product cases, so cross-product cases are never replayed live.
- Some cases cannot be carried by a live call. They are listed under `offline` with a reason
  and are not counted:
  - `ledger_time`: time boundaries;
  - `installation_state`: call-count, missing-state and strict-set cases;
  - `host_rejects_before_authorization`: arity, type confusion, or a value of another type;
  - `authorizer_replaced`: a mutation of the argument that asks the account to authorize, i.e.
    the transfer or claim `from` or the swap `to`;
  - `no_live_stand_in`: the suite's undeployed contract or absent function, unless a control has
    already shown a live equivalent. W1 uses the pool's `submit`; W2 uses the funded control
    token. Both are labeled `live_stand_in`.
- Each case must be refused by the enforcer its class predicts, attributed by contract id as for
  `invoke.mjs`:
  - the account's `UnvalidatedContext` (3002) for another contract;
  - the account's `UnauthorizedSigner` (3016) for an unrecognized signer;
  - otherwise the first policy in the live rule's own order that refuses: generated `#1`, `#5`
    or `#6`, or W2's spending policy `3223` or `3221`.
- A permit or any other attribution fails the run, and the failure cleanup removes the grant.

The suite's unrecognized signer sorts before any real delegate, so "authorized set plus an
unrecognized signer" stops at the same account check as "unrecognized signer" alone. That is two
suite cases but one live check.

The account's authorization entries are built from the realized call, with a random nonce. The
delegate signs them, and they are sent only to the RPC simulation. A signed original is a valid
authorization of the real call until it expires, and the endpoint sees it, so it expires five
ledgers after the latest one read. The journal (`run.json` → `derived_denials`, exported as `derived_denials`) records:

- the suite and spec hashes;
- the live policy order;
- each case's id, class, realization, expected and observed enforcer and code, and ledger;
- the offline list.

Its labels say what it is: post-install, state-dependent, simulation-only, never submitted.

## What a run does and does not show

**Shown**, on live testnet:

- The pinned account runs a generated policy as one of its context rules.
- A wallet-style signed `add_context_rule` installs it. Before any signer of the account signs,
  ed25519 or passkey, `install.mjs` and `invoke.mjs` check that the authorization the RPC asks
  for is exactly the call they mean to make. The fee payer's own deploy, fund and upload
  transactions take the simulation's source-account authorization as returned.
- With a passkey owner, the pinned WebAuthn verifier accepts the passkey's signatures for
  the recorded transfer and the install, and refuses one over a different challenge.
- The account then permits the exact recorded call once.
- It refuses the call with a changed amount, with a changed recipient, and past the call cap.
  Each refusal is the policy's own published error code.

The default native wrapper also exercises owner removal and a post-removal denial, but in that
mode those steps still need a reviewed live run at this revision. They are not part of the
historical October 15 observations described below. The
[subscription](../docs/WALKTHROUGH-SEP41.md) and [Soroswap](../docs/WALKTHROUGH-PROTOCOLS.md)
modes ran them live on 20 October 2026, at the commits recorded in
[the testnet evidence](../docs/TESTNET-EVIDENCE-TRANCHE-2.md), sections 8 and 9, and most recently,
with the Blend mode, on 1 November 2026 at `86854cee` (sections 21–23).

**Not shown, or not as you might assume:**

- **The default pipeline now synthesizes the grant.** Protocols through 30 are supported by the RPC
  recorder. Its executable observations are acquired after the transaction, so they describe
  the endpoint's later state, not an authenticated historical state. `synthesize` verifies
  raw/decoded coherence, resolves the registry and treats supplied JSON as `self_supplied`.
  The output records the same exact transfer and the harness's explicit test decisions.
  `write-spec.mjs` and its template remain only for inspecting/reproducing the historical
  manual workflow; the wrapper does not call them.
- **Reproduction is not a complete dry run.** The default wrapper requires matching source,
  Wasm and manifest and complete layer-1 coverage for its single scope+count policy. It does
  not establish arbitrary captured-target execution or a wallet product's consent. The Blend
  and Soroswap paths are [separate modes](../docs/WALKTHROUGH-PROTOCOLS.md); Blend opens and
  withdraws its own USDC supply position. Enforcing network simulations remain a separate later observation.
- **Denials have no transaction hash.** Each one is observed in the enforcing simulation, which
  runs `__check_auth` and the policy exactly as the network would. The authorization entries are
  signed, but the transaction is not, nothing is submitted, and the call count is not spent.
- **By default `run.sh` skips the authority check.** It installs only into the account it
  deployed a moment earlier, whose administrator it knows by construction. That is not evidence
  about anyone else's account. The opt-in wallet decision on the check
  ([`OZPB_HARNESS_AUTHORITY_CHECK=cli`](#the-wallet-decision-on-the-authority-check)) needs an
  `ozpb` built with the authority commands included in this tree and configured trust inputs.
- **No wallet product signs.** With the default owner, a script holding an ed25519 key signs.
  With `OZPB_HARNESS_OWNER=passkey`, the account has a passkey wallet's shape: rule 0 is one
  `External` WebAuthn signer. The passkey signs the recorded transfer and the install, and the
  verifier checks it on chain. But the passkey is Chrome's virtual authenticator over a key the
  harness holds, not a device. And the harness creates the account itself: pollywallet's page,
  relayer and deployer are not involved.
- **The PolicySpec still has no External signers.** The grant's signer is the delegate, an
  ed25519 `Delegated` signer, in both runs. Spec validation refuses External signers on this tree,
  so a passkey can own the account but cannot be the grantee.

## The wallet decision on the authority check

The authority check (`ozpb check-policy-call-surface`) reads who can change the account, or the
policy being installed, and lists them. It refuses what it can rule out on its own. It never says
the install is safe: the wallet that holds the owner key decides. `scripts/wallet-decision.mjs` is
that decision, and `scripts/approve-install.mjs` runs it:

1. Ask `ozpb prepare-install-intent` for the `add_context_rule` arguments. The tool runs the check
   itself and answers only when nothing is refused or unresolved. A refusal or any other error is
   a refusal here too, and its findings are shown.
2. Require the intent's arguments to be exactly the grant the check covered. The answer must be
   about this account, network, target, bound policy, spec rule, spec hash and registry root, and
   its scope must be exactly that target, account and policy.
3. Accept only when all of these hold:
   - the check refused nothing and left nothing unresolved;
   - the grant does not target the account itself or its own policy, and has not expired at the
     ledger the answer was read;
   - every rule that can change the account or the bound policy needs at least one trusted
     signer.
4. Show the confirmation screen and ask.
5. Just before signing, run the check again (a fresh read). Require the same
   `authority_commitment`, a ledger no older than the first read, and the fresh answer accepted
   under step 3. Expiry is outside the commitment, so it is judged again at the fresh ledger.
   As the intent itself instructs, its arguments must also equal the grant the fresh answer
   reports.

Trusted means the run's own owner key plus any identity in `--trust`. Identities are compared by
scheme and key. The verifier address does not count, and an ed25519 key behind a verifier is the
same identity as the classic account with that key. Some identities never count, even when
listed:

- one the check marks as aliasing the restricted key, in any rule;
- one that shares key material with the grant's own signer. The wallet uses the check's test
  (equal bytes, or equal first 32 bytes).

Two choices go beyond the check's contract. An empty authority list is refused, where the
contract would accept it vacuously. Arguments are signed only if they equal, byte for byte, the
rule `install.mjs` builds from the spec.

```
OZPB_HARNESS_AUTHORITY_CHECK=cli OZPB_BIN=<ozpb with the check commands> \
OZPB_REGISTRY_SNAPSHOT_ROOT=<root of the signed snapshot> OZPB_SIGNED_REGISTRY_SNAPSHOT=registry.signed.json \
OZPB_REGISTRY_ROOTS_FILE=registry-roots.json OZPB_REGISTRY_MIN_VERSION=4 OZPB_RPC_SOURCES_FILE=sources.json \
[OZPB_RPC_SOURCE=testnet] [OZPB_HARNESS_CONFIRM=tty|operator] [OZPB_HARNESS_TRUST=trust.json] \
bash testnet-harness/run.sh
```

- **The binary.** `OZPB_BIN` must be an `ozpb` built from a tree that has
  `check-policy-call-surface` and `prepare-install-intent`, both included in this tree. `run.sh` uses
  the same binary for `ozpb generate`, so the check's rebuild of the policy can match.
  `OZPB_RPC_SOURCE` names the entry in the sources file, `testnet` by default. `run.sh` checks all
  of these before setup starts.

- **The registry root.** Synthesis resolves the signed registry and writes its root into the
  spec before generation. The pipeline requires it to match `OZPB_REGISTRY_SNAPSHOT_ROOT`;
  the authority check independently requires the same signed snapshot. For the development
  snapshot, recognition rests on a public development root, which is testnet only.
- **The policy binding.** It carries the policy's build manifest unmodified, and its deploy
  transaction as `resolution_reference`. The signed snapshot goes into the request byte for byte.
  Parsing it in JavaScript would turn its 64-bit integers into different numbers, and the check
  would refuse it. The check rebuilds the policy offline to recognize it.
  Run it with the same stellar-cli and the same warm build cache as `ozpb generate`
  (`OZPB_STELLAR_BINARY`, `OZPB_BUILD_CACHE_DIR`), or the rebuild cannot match.
- **The trust file.** `trust.json` is
  `{"operator": [{"classic_account": "G…"}, {"scheme": "webauthn_p256", "public_key": "04…"}]}`.
- **The error format.** `scripts/check-runner.mjs` reads the error code only from the first line
  of stderr (`Error: E_CODE: …`). Each `  - …` line after it is one finding. Any other non-zero
  exit counts as a refusal: an unreadable file, a usage error, a crash.

**What this does not show.**

- The trust is **operator-supplied test configuration**. `--trust`, the run's own key and
  `--confirm operator` all come from whoever runs the script, and `--confirm operator` is no
  prompt at all. `--confirm tty` is a terminal prompt, and anyone with that terminal can answer it.
  None of this shows that a human approved the install, or that an agent with the same access
  could not approve itself. That claim needs a real wallet's protected approval screen.
  `run.json` records the decision under that label, with the exact operator-trusted identities.
- The refused path ran on testnet once, on 2026-10-15. The accepted path ran that day and
  again in the 20 October W2 and W3 runs (see the testnet evidence, sections 8 and 9) and in
  the later passing W1, W2 and W3 runs, most recently on 1 November 2026 (sections 21–23). Both
  15 October runs used a passkey owner and an `ozpb` built from the authority-check branch
  before those commands were integrated into this tree.
  One run was accepted: the intent, the
  decision, the screen, the re-check and the install all ran, and then the delegate's permit and
  denials. The other was refused: a second owner rule for an account the wallet does not trust,
  and no `--trust`. Nothing was signed in that run. The second owner was added by a one-off
  script that is not in this tree. Neither run used `--confirm tty` or `--trust`, and no tool-side
  refusal happened on testnet. The tests drive the decision with fixtures hand-written from the
  check's output types and contract, not captured from the tool. They drive the CLI seam with a
  fake `ozpb` that prints the documented error format.
- Several cases are the check's to catch, and they reach the wallet only as refusals:
  - a signerless permissive policy on the target;
  - the agent added as a classic account's signer;
  - a missing or zero-weight classic account.

  An owner-only rule scoped to the bound policy is not a refusal. The check lists it, and the
  wallet must trust its owner like any other.
- What the check itself does not cover: the RPC endpoint is trusted, with no ledger proof.
  Classic accounts must be master-key only. Threshold and policy-guarded owner rules and nested
  accounts are refused, not analysed. Rules for other contracts are listed as not analysed.

## Against RFP 7

RFP 7 asks for wallet integration with at least one Stellar smart-account wallet, end to end:
record → generate → simulate → sign → install. For each link: what runs in this directory today,
and what does not.

- **record.** The default wrapper calls `ozpb record` for the owner's executed transfer,
  obtaining an RPC-labeled recording with executable observations. It retains the raw import
  bundle separately. The historical runs documented above used offline imports instead.
- **generate.** The wrapper now runs real synthesis with explicit test decisions and a signed
  registry, followed by code generation, the reference suite and artifact reproduction.
  Synthesis admits the serialized recording as `self_supplied`. In the default native mode
  this path needs a reviewed new live run before it is evidence at the delivered revision.
  The subscription and Soroswap modes ran it live on 20 October 2026, at earlier commits
  recorded in the testnet evidence, and with the Blend mode most recently on 1 November 2026
  at `86854cee` (sections 21–23).
- **simulate.**
  - Runs: every transaction that carries the account's authorization is simulated in enforcing
    mode, with the signed entries, before the transaction is signed. Every denial is observed
    there.
  - Runs in the default pipeline: the layer-1 reference suite and modeled behavior checks
    within `verify`. These are not the full four-layer dry-run harness.
- **sign.**
  - Runs, on chain, with `OZPB_HARNESS_OWNER=passkey`: the account's owner is a passkey. It signs
    the recorded transfer and `add_context_rule` through WebAuthn, and the pinned OpenZeppelin
    WebAuthn verifier checks each signature on chain. A signature over a random challenge instead
    of the account's digest is refused by the verifier with `ChallengeInvalid` (#3114). Before signing, the script checks that the RPC asked for
    exactly the intended call. The delegate signs with an ed25519 key in both runs.
  - Not a device: the passkey is Chrome's virtual authenticator, its key exported to the run's
    secrets between steps.
- **install.**
  - Runs: `add_context_rule` on testnet, after which the policy enforces.
  - Runs, opt-in, with an `ozpb` built with this tree's authority check: the wallet decision
    on the install intent and the check. It ran on testnet once accepted and once refused, both
    with a passkey owner ([details](#the-wallet-decision-on-the-authority-check)). Neither
    those historical runs nor the offline tests establish acceptance at the current revision.
- **with a wallet.**
  - Runs: pollywallet's own wallet creation, driven headless in its real UI (`browser/`).
  - Closest that runs, with no wallet product involved: an account of pollywallet's shape, created
    by the harness on the pinned account and verifier. It has one passkey `External` signer on
    rule 0, with the same constructor arguments and key-data layout as pollywallet's
    (`src/hooks/useWallet.ts` and `src/lib/passkey.ts` there).
  - Does not run: installing into a stock pollywallet account. Its account wasm is not pinned and
    its verifier does not reproduce from our pinned inputs. pollywallet's UI cannot create the
    pinned account either, because it deploys its own wasm through its own relayer.
- **revoke and observe.** The wrapper now removes its own grant through owner authorization,
  verifies the removal event and checks a delegate denial attributed to the missing account
  rule. It separately observes policy cleanup and grant/code drift. This is an executable
  harness path awaiting current live evidence, not pollywallet's protected revocation UI or
  the complete post-install call-surface monitoring requirement.

The record of a run is the `run.json` in its run directory (`runs/<timestamp>-<pid>/` unless
`OZPB_HARNESS_OUT` says otherwise). Every transaction hash in it can be looked up at
`https://stellar.expert/explorer/testnet/tx/<hash>` until the next testnet reset.

The opt-in `protocol-dry-run.real.test.mjs` integration runs the real CLI and native
worker for both the two-rule Soroswap observation fixture and
`scripts/fixtures/synthetic-blend-claim-spec.json`. The Blend fixture is a synthetic
claim authorization with an exact reserve-index vector; it is not an RPC recording
or evidence that the Blend target executed. The test reads hash-checked pinned
account bytes from the committed capture unless `OZPB_ACCOUNT_WASM` is supplied.
Enable it with `OZPB_PROTOCOL_DRY_RUN_E2E=1`, `OZPB_BIN` and
`OZPB_NATIVE_WORKER`; it generates real policy Wasm and submits no transaction.
The manual/nightly Linux toolchain job runs this integration.
