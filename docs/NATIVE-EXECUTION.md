# Native candidate account execution

`execution-runtime` is a separate, operator-selected native worker for the `account_wasm`
layer. It runs the pinned account Wasm and the exact supplied generated policy Wasm through
real Soroban authorization, with real Ed25519 delegate signatures and committed local state.
Its result always has `complete: false`: this mode does not invoke the target contract, import
captured network state, perform live enforcement, or authorize installation. The source network
and ledger fields bind provenance; the executed network and boundary ledgers are counterfactual.
The separate [captured-target mode](CAPTURED-TARGET-EXECUTION.md) runs a native SAC target call
against captured state.

The worker requires successful trusted `prepare_dry_run` artifact reproduction and registry
recognition before its result is used. It checks byte hashes and candidate identities itself;
it does not reproduce the generated source or authenticate the supplied registry snapshot.
The synthetic fixture script tests execution only and is not a preparation trust receipt.

## Supported scope and execution evidence

The worker runs the request's selected rule, `candidate.rule_index`, of a specification that may
hold other rules. Only that rule is installed, with only its own policy binding; an index past
the last rule is refused. The selected rule must have one explicit delegated Ed25519 G signer,
exactly one generated policy and `any_of`, `all_of` or threshold-one authorization. A selected
rule composed with any other policy, such as a reviewed spending limit, is refused: it would run
here without that policy. The specification is at most 64 KiB, every rule has at most eight
allowed calls and sixteen arguments per call, because the suite is derived for every rule
before the selected rule's cases are kept, and the selected rule has at most 256 derived
boundary cases. A call cap may be at most 512. Larger valid grants and other signer/policy
compositions are unsupported; there is no substitute signer or passing fallback.

Each boundary case starts from a fresh local installation at the exact candidate account and
policy addresses. A distinct deterministic bootstrap owner signs the setup invocation in the
offline network. This proves no ownership of the real wallet. The candidate's local rule ID is
1; the proposed chain ID is reported separately and remains unobserved. Counter boundary seeds
and validity-window ledgers are synthetic and explicit in each case result.

A denial agrees only when its expected account/policy error is attributed to the actual contract
and all local entries remain unchanged. Successful calls must advance any configured counter
by exactly one. Separate controls exercise signature-bit corruption, nonce/preimage binding,
payload and context-rule binding, and reuse of a consumed nonce. Cryptographic failures must
match the host's specific authorization error and diagnostic stage, with unchanged state.

For a bounded call cap, one continuous installation permits N calls and refuses N+1. With one
call remaining, a two-context authorization first spends that call, then refuses the second
context; both counter and nonce writes must roll back before a final single call succeeds.
This establishes local account authorization behavior, not the target's effects or network fees.

The runtime pins SDK 30.0.0-rc.1 and stable host 30.0.0 in its own lockfile, and rejects source
protocol versions other than 30. Generated policies use SDK 28.0.0 and the stellar-accounts 0.8.0 policy interface.
The recognized account Wasm remains the separately pinned 0.7.2 implementation.
See [dependency migration](SOROBAN-DEPENDENCIES.md) for the compatibility boundary.
Only canonical XDR crosses this boundary. A shared [ABI vector](examples/native-runtime-abi.json)
is checked against both the actual SDK-28 policy/account-library types and the runtime's SDK-30 wire
types; the source-built Wasm test additionally exercises the real account ABI.

## Machine protocol

Build with `cargo build --locked --manifest-path execution-runtime/Cargo.toml`. The operator
chooses the executable; requests cannot select a binary, endpoint, path or private key.
The worker accepts exactly no arguments (interactive execution) or exactly `--prepare`
(preparation only). `--captured` and `--prepare-captured` are the
[captured-target](CAPTURED-TARGET-EXECUTION.md) equivalents. All other argument combinations fail.

The first UTF-8 NDJSON line is a `NativeJob` of at most 16 MiB:

```text
{ schema: 1,
  request: DryRunInput,
  account_wasm_base64: string,
  ledger: { protocol_version: 30, sequence: u32, timestamp: decimal-u64-string,
            base_reserve: u32, min_temp_entry_ttl: u32,
            min_persistent_entry_ttl: u32, max_entry_ttl: u32 } }
```

`request` is the exact typed [preparation request](DRY-RUN-PREPARATION.md), including the fresh
run nonce and generated Wasm in `artifact.claimed_wasm_base64`. Unknown fields are rejected.
The worker derives the suite; callers cannot supply arbitrary cases or previous results.

A coordinator (the wallet, or `ozpb dry-run` below) first invokes its trusted local binary with
the fixed `--prepare` argument and closes stdin after the job. That mode validates and hashes
the immutable job and emits exactly one `PreparedFrame`; it neither executes Wasm nor requests
signatures. The coordinator retains this trusted metadata. Interactive execution of the identical job begins with the same frame,
then emits sequential `sign_request` frames and one final `result`. Every repeated binding
must match the retained preparation frame. Repeats from the executing worker alone are not
an independent source of expected metadata.

`PreparedFrame` contains `binding` (run/job/suite/initialization hashes, source network/protocol/
ledger, account/delegate addresses), `execution_network_id`, account/policy code identities,
local/proposed rule IDs, boundary-case count and the allowed synthetic signature expiry ledger
set. Public Rust wire types are in `execution-runtime/src/{execution,protocol}.rs`.

Every later input or output line is at most 256 KiB; total output is at most 16 MiB. There are
at most 10,000 signature requests. The 120-second worker watchdog also bounds blocked input;
the wallet must independently enforce its deadline, bound stderr and kill the child process
group on cancellation. Each host invocation has a 200-million CPU-instruction and 128-MiB host
memory budget. These local limits are not claims of network transaction feasibility.

Exactly one signature request is outstanding. IDs are sequential canonical decimal strings
starting at `"1"`; a mismatched, repeated or out-of-order response fails. EOF, malformed input,
unknown fields, exceeded limits or child failure yield no usable passing report. The wallet
requires a zero child exit as well as a fully validated final report, and refuses a run that
leaves any process in the worker's group; every refusal kills the members of that group the
wallet can signal. The group check enforces the contract of a trusted local binary, not
containment: a descendant that calls `setsid` or `setpgid` leaves the group unseen.

The wallet keeps a registered, controlled delegate key in backend memory and exposes only its
address and opaque capability ID to the UI. `ozpb dry-run` reads the spec delegate's key from a
0600 file (see [running the layers from the CLI](#running-the-layers-from-the-cli)). In both,
the worker receives only the address. An arbitrary supplied delegate address without a matching
capability is unavailable; an owner passkey does not stand in for the delegate. The [Pollywallet backend](POLLYWALLET-INTEGRATION.md#account-wasm-execution)
implements this exchange for both modes, and kills the worker's group when its HTTP client
disconnects.

## Exact offline-domain encoding

Use the existing canonical-hashing XDR wrapper, with the **fixed ScVal sequence below**, not a JSON hash or a generic JSON-to-ScVal conversion:

```
ScVal::Vec(Some([
  ScVal::U32(2),
  ScVal::String("ozpb:v1:offline-execution"),
  ScVal::Vec(Some([
    ScVal::String(run_hash),
    ScVal::String(job_hash),
    ScVal::String(suite_hash),
    ScVal::String(state_hash),
    ScVal::String(source_network_id),
    ScVal::U32(source_protocol_version),
    ScVal::U32(source_ledger),
    ScVal::String(account_address),
    ScVal::String(delegate_address)
  ]))
]))
```

`execution_network_id` is lowercase hex SHA-256 of that XDR. Hash strings are canonical 64-character lowercase hex; addresses are canonical StrKeys. `job_hash` is the domain-separated canonical hash of the full typed immutable job under `ozpb:v1:native-execution-job`; the wallet obtains it from the fixed trusted local `--prepare` operation and checks every repeated binding. `run_hash` already binds the fresh run nonce, full spec, artifact claims and policy bindings. The runtime and wallet both reject execution-network equality with the source network and with known public/test/future network IDs. The source network is never rewritten inside captured ledger data.

## Signature exchange

Runner line:

```
{"type":"sign_request","request_id":"1","run_hash":"...","case_id":"case:0","delegate_address":"G...","execution_network_id":"...","nonce":"1001","expiration_ledger":123,"account_digest":"...","invocation_xdr":"...","preimage_xdr":"...","digest_hex":"..."}
```

Nonce is canonical signed-i64 decimal text; expiration is u32. Both XDR fields are canonical base64; digest fields are canonical lowercase hex. `preimage_xdr` is the protocol `HashIdPreimage::SorobanAuthorization` with the derived offline network, exact nonce/expiration and `invocation_xdr`. The root must be exactly the candidate account's `__check_auth` with one Bytes argument containing `account_digest` and no subinvocations. `digest_hex` is SHA-256 of the canonical preimage XDR. The coordinator (the wallet, or `ozpb dry-run`) independently parses and reconstructs this object and checks all fields, run/case/registered delegate and expiration bounds. `ozpb dry-run` then signs only that offline digest ([signing guard](#running-the-layers-from-the-cli)). The wallet hands only the reconstructed preimage to the delegate's offline capability. That capability derives the execution network from the binding itself and signs a `HashIdPreimage::SorobanAuthorization` in that network and nothing else: no digest or other supplied bytes, and no preimage for mainnet, testnet, futurenet or the source network. No live-domain signature is accepted here. The wallet's same in-memory key signs testnet authorizations only through two separate capabilities, which build them themselves and accept no bytes: the live capability for one consented [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check), and the use capability for one [use of an installed grant](POLLYWALLET-INTEGRATION.md#using-the-grant).

Wallet line:

```
{"type":"signature","request_id":"1","public_key_hex":"...","signature_hex":"..."}
```

The runtime checks the public key against the exact delegate, verifies the Ed25519 signature, and then executes the real account authorization. Keys never leave the coordinator: the wallet's backend memory or the `ozpb dry-run` process. Negative cryptographic tests alter a verified signature or local invocation inside the runtime and label that mutation; they do not ask the wallet to sign an unrelated live payload.

The final `result` repeats run/job/suite/state/source-network/execution-network/account/policy bindings, exact host/protocol versions, local state provenance and initial-state hash, case results/error attribution/delta hashes, required coverage and supported scope. This report cannot become full four-layer completion by itself. The wallet rejects any missing/mismatched binding or unsupported/failed case and separately requires captured-target and live-enforcement evidence.

The signature expiry is the derived case ledger plus 64, checked for overflow. Boundary case IDs
are `case:<index>`; controls use `control:signature_bit`, `control:nonce_binding`,
`control:payload_binding`, `control:context_rule_binding` and `control:nonce_replay`.
Stateful checks use `sequence:<index>`, `sequence:partial_rollback` and `sequence:overflow`.
The rule-ID control obtains an offline signature over a digest containing a different rule-ID
vector, then invokes the original candidate rule: the account must reject the digest mismatch.
The partial-rollback control signs the actual two-context rule-ID vector. No control asks for
a signature on a live network or releases bootstrap-owner material to the wallet.

The [offline-domain vector](examples/native-domain-vector.json) includes canonical preimage
bytes and the independently encoded expected hash. `state_hash` commits to the typed descriptor
`{job_hash, local_rule_id: 1, bootstrap_owner, provenance:
"fresh_local_candidate_boundary_states"}`. The bootstrap seed is the canonical hash of the run
hash string under `ozpb:v1:local-bootstrap`; it is deliberately public, for synthetic setup only.
Actual per-case entry hashes are reported separately.

## Validation

`cargo test --manifest-path execution-runtime/Cargo.toml --locked` runs offline framing,
domain and ABI checks. `bash scripts/test-native-execution.sh` reproduces the public account
artifact and a signable generated policy, then requires every actual-Wasm/process test to run.
An operator may supply `OZPB_ACCOUNT_WASM` to reuse an artifact; the runtime still checks its exact
pinned hash. Source reproduction of the account requires the documented aarch64-apple-darwin
build host. The existing nightly source-build gate runs this worker suite as well.

## Running the layers from the CLI

`ozpb dry-run` is the CLI coordinator for this worker: it prepares the candidate, runs `--prepare`
and then the interactive mode (and, with `--capture-request`, the
[captured-target](CAPTURED-TARGET-EXECUTION.md) modes), signs the worker's requests itself, and
prints one four-layer report ([report fields](DRY-RUN-PREPARATION.md#executed-layers-and-acceptance)).

```sh
ozpb dry-run --request dry-run-request.json \
  --registry-roots registry-roots.json --registry-min-version 3 --rpc-sources rpc-sources.json \
  --native-worker /abs/path/ozpb-execution-runtime \
  --delegate-key-file delegate.key --account-wasm pinned-account.wasm \
  --source-ledger ledger.json [--capture-request capture-request.json]
```

- **Worker.** The operator names the executable (`--native-worker` or `OZPB_NATIVE_WORKER`, an
  absolute path). It is trusted code: it runs unsandboxed as the caller's user and can read
  anything the caller can, including the delegate key file, whose path is on the command line.
  The guards below stop a confused worker, not a hostile one. A binary writable by its group or
  others, or owned by neither the caller nor root, is refused. It gets one fixed mode argument,
  an environment holding only `PATH` and `LANG`, `/` as its directory and its own process group. Each run has a 120-second deadline
  enforced by killing the group and the worker; once the worker ends, its pipes get five seconds
  to close. Stdout frames, total output (16 MiB) and stderr (64 KiB) are bounded. A nonzero
  exit, a refused frame, or a process or open pipe left behind fails the layer.
- **Bindings derived first.** Before the worker starts, the CLI derives the account-Wasm job,
  suite and initialization hashes, the allowed signature expiries and the offline execution
  network ID from the request and the preparation. The worker's `--prepare` frame must equal
  them exactly; only then is a signature requested. For the captured layer, whose candidate state
  only the worker can compute, the CLI derives every other identity and takes the suite and
  initialization hashes from the trusted `--prepare-captured` frame.
- **Key.** The spec delegate's Stellar secret seed is read only from `--delegate-key-file`: a
  regular file owned by the caller with mode exactly 0600, holding the key of the selected rule's
  delegate. It is opened without following links or blocking, never taken from an argument or
  the environment, never passed to the worker and never printed. It is cleared when the run
  ends, on a best-effort basis: a value the compiler moves can leave a stack copy. Mode and
  owner are the only access checks; an extended ACL granting others access is not detected.
- **Signing guard.** A request is signed only when the network ID inside its `HashIdPreimage` is
  the offline execution network ID derived by the CLI; a preimage naming the source, public, test
  or future network is refused as well. The request must also be the next expected one
  (sequential ID and nonce, an allowed unused case ID, an allowed expiry), and the invocation,
  preimage and digest are rebuilt and compared byte for byte. The first refusal ends the run.
  The signer allows only the case IDs a correct run asks to sign, and the report is accepted
  only if it answered exactly those.
- **Ledger and account.** `--source-ledger` supplies the job's protocol-30 ledger parameters
  (provenance only for this layer); `--account-wasm` must hash to the pinned account Wasm.
- **Exit status.** Zero only when the report's `acceptance.meets_minimum` holds; any other report
  is still printed. A refused key file prints no report. A requested capture that does not
  complete fails the captured layer, so such a run never exits zero. Worker stderr is printed
  for a failed run, at most 4 KiB, with control characters and bidirectional formatting
  characters replaced, as is endpoint error text.

Live-enforcement evidence remains missing outside the wallet: `ozpb dry-run` reports that layer
`unavailable` with `wallet_owner_consent_required`, and its report is never `complete`. The MCP
server exposes no signing dry run. The [atomic live-enforcement helper](ATOMIC-LIVE-HELPER.md) is
the contract the wallet's [live-enforcement check](POLLYWALLET-INTEGRATION.md#live-enforcement-check)
simulates on testnet; it refuses generated policies without a call cap, whose execution it cannot
observe.

`bash scripts/test-cli-dry-run.sh` runs `ozpb dry-run` with the actual CLI and worker over the
native fixture and, through a local endpoint replaying the recorded testnet capture, over the
captured layer. It needs `OZPB_REGISTRY_SNAPSHOT_ROOT` set to the root of
`docs/examples/registry.signed.json`; `OZPB_ACCOUNT_WASM`, `OZPB_BIN` and `OZPB_NATIVE_WORKER`
may reuse existing artifacts.


The CLI opens and validates the configured worker, then retains a private executable copy for
both preparation and execution. Replacing the configured pathname between modes cannot change
those bytes. This keeps the existing trust requirement: the worker runs with the caller's
privileges. Pipe cleanup grace begins when the worker process exits, even if a detached child
still holds stdout open.

Each native boundary case must report its exact derived execution ledger. Delegate signing
requests are bound to that case's own expiration ledger; control and stateful-sequence requests
use the original call's ledger. A contract-address delegate is outside the native execution
scope and is refused before opening a signing-key file. Captured reports require canonical
state hashes for rollback claims, no refusal code on a permit, and exactly one counter advance
for a counted permit (or no counter for an uncapped rule).
