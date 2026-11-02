# Pollywallet Policy Builder integration

The integration adds a Policy Builder route to a pinned Pollywallet checkout. Pollywallet
owns the passkey interaction; the local wallet backend owns its RPC connection, registry
roots, retained artifacts and disposable testnet fee payer. MCP output cannot select a
command, RPC endpoint, file path or signing identity.

Pollywallet is the wallet named in the public architecture. Its pinned upstream default
account differs from the account recognized by this toolkit. The integration therefore
creates or attaches a recognized account explicitly. It does not relabel an unknown account,
migrate an existing wallet, or broaden account/verifier recognition.

This integration supports recognized account creation, a fixed owner-authorized sample
transfer from that new account, confirmed-transaction recording, artifact generation and
reproduction, artifact deployment, live authority review and, when the operator configures
the [native worker](NATIVE-EXECUTION.md), local account-Wasm and captured-target execution of
the reviewed grant. When the operator names the deployed [atomic live helper](ATOMIC-LIVE-HELPER.md),
the owner can also consent to a [live-enforcement check](#live-enforcement-check): two
enforce-mode simulations on testnet, never submitted. When all four layers passed on recent
evidence and the live check's signatures expired unused, the owner can [install](#installation)
the reviewed grant with one passkey-signed transaction and later [revoke](#revocation) it with
another. [Revoke-first replacement](#revoke-first-replacement) is available for verified
session-local grants, and [on-demand monitoring](#on-demand-installed-grant-monitoring) is
available within the scope below. A virtual authenticator's signature is automation evidence,
not a human acceptance decision.

## Apply to the supported upstream revision

Use a dedicated clean checkout of
[`kalepail/pollywallet`](https://github.com/kalepail/pollywallet/tree/853b102983699726f918b68d8e42edbba74e65b9):

```sh
git clone https://github.com/kalepail/pollywallet.git /absolute/path/pollywallet
git -C /absolute/path/pollywallet checkout --detach 853b102983699726f918b68d8e42edbba74e65b9
python3 scripts/apply-pollywallet.py --revision HEAD /absolute/path/pollywallet
```

Run the apply command from a committed toolkit checkout containing this integration. It reads
only that immutable Git tree, refuses a different or dirty upstream revision, refuses source
symlinks and unlisted patch paths, and retains license attribution. Untracked toolkit files
and working-copy edits do not become integration inputs.

Install the two existing lockfiles separately:

```sh
cd /absolute/path/pollywallet
pnpm install --frozen-lockfile --ignore-scripts
npm --prefix src/policy-builder ci --ignore-scripts --no-audit --no-fund
pnpm build
pnpm exec vitest run src/lib/__tests__/policy-builder-bridge.test.ts
```

The upstream wallet keeps SDK 16.2.0. The nested validator package pins SDK 17.2.1.
Only serialized XDR crosses that boundary. Do not deduplicate the Stellar SDK packages or
silently replace the upstream dependency lock. The browser uses the upstream `buffer`
polyfill, so URL-safe base64 is encoded explicitly rather than relying on Node-only encodings.
The package-scoped `#wallet-stellar-sdk` import and explicit Vite alias keep the development
optimizer from reusing the upstream SDK 16 bundle for SDK 17 validators.

The Vite development server binds to `127.0.0.1:3000`, with a same-origin proxy for
`/api/policy-builder` to the local backend on `127.0.0.1:4317`. Open the UI through
`http://localhost:3000`: Chrome requires the `localhost` domain for WebAuthn registration
and rejects the numeric IP as a relying-party domain.
Open the backend's session launch URL. Its bearer credential is read once from the fragment,
removed from browser history, and held only in memory. A page reload requires a fresh launch
URL; the credential is not stored in local storage or sent in a query string.

This route is a local operator workflow. Building it does not deploy a Cloudflare service,
call the upstream shared relayer, publish an image, or establish a hosted endpoint.
The overlay disables upstream AI and sandbox service bindings, container startup, remote
bindings and the development inspector. Those unrelated upstream cloud features are
unavailable in this dedicated checkout. In particular, ordinary `pnpm dev` must not require
Cloudflare credentials or launch the upstream compiler container.

## Start the local backend

Build the toolkit CLI and prepare a signed registry snapshot and its trusted roots as
described in the registry documentation. Use Node 22.12 or newer and install the wallet
lockfile with `npm --prefix wallet ci --ignore-scripts --no-audit --no-fund`.
Create an operator-owned directory with mode `0700` for retained session state, then write
an operator JSON file using absolute canonical paths:

```json
{
  "executable": "/absolute/path/oz-policy-builder/target/debug/ozpb",
  "workRoot": "/absolute/path/wallet-state",
  "rpcUrl": "https://soroban-testnet.stellar.org",
  "registrySnapshotPath": "/absolute/path/registry.signed.json",
  "registryRootsPath": "/absolute/path/registry-roots.json",
  "registryMinimumVersion": 1,
  "buildJobs": 2,
  "buildTimeoutSecs": 600
}
```

Set the minimum registry version to the operator's accepted rollback floor. Optional
`stellarBinary`, `cargoHome`, `rustupHome`, and `buildCacheDir` fields select existing local
toolchain paths; the cache directory also requires mode `0700`. Optional `nativeExecutable`
names the operator-built `ozpb-execution-runtime` binary; without it both local execution checks
are unavailable. Optional `liveHelper` names the contract ID of the deployed atomic live helper
(see [Testnet deployment](ATOMIC-LIVE-HELPER.md#testnet-deployment)); without it the
live-enforcement layer is unavailable. The backend never trusts that ID: it reads the helper's code
back and requires the reviewed hash before every check. The CLI and optional Stellar and native binaries must be executable regular files. Configuration, registry and executable paths cannot
be symlinks or writable by other users. Arbitrary environment overrides are refused, builds
run offline, and HTTP requests cannot select these settings.

From the toolkit checkout:

```sh
node wallet/server/main.mjs --config /absolute/path/operator.json
```

In the applied Pollywallet checkout, run `pnpm dev`, then open the one-time session URL
printed by the backend. The equivalent backend entrypoint in that checkout is
`node src/policy-builder/server/main.mjs --config /absolute/path/operator.json`.
Startup does not fund an account, execute the CLI or submit a transaction. The backend
listens only on `127.0.0.1:4317`; the approved browser origin is exactly
`http://localhost:3000`; the numeric-IP browser origin is refused.

Each backend launch creates a separate private session directory and an in-memory disposable
testnet fee payer. Retain the session journal: an intended transaction hash is recorded before
submission, and an uncertain result blocks subsequent writes in that session. Inspect that
hash before starting another attempt. The fee payer key is not saved, printed or returned
to the browser. Fresh account confirmation separately discloses a fixed one-testnet-XLM
sample balance (`sampleFundingStroops: "10000000"`) and at most three testnet XLM in fees
across its three transactions (`maxTotalFeeStroops: 30000000`).
On SIGINT or SIGTERM the listener stops accepting new requests; an already admitted request
can finish and write its receipt before shutdown. Keep the journal when interrupting a session.

## Importing an agent proposal

After attaching the account, open **Import a grant proposal** under **Record and generate**.
Paste an `ozpb-grant-proposal/v1` document or choose a JSON file up to 16 KiB, then select
**Import and verify proposal**. The accepted grant is one exact native XLM transfer from this
account to a G-address recipient on testnet: one strict `any_of` delegated signer, an expiry
within 17,280 ledgers of the current ledger, and a cap of 1–10,000 calls. Widenings, spending
limits, unlimited grants, other networks and other call shapes are refused.

The backend records the confirmed transaction again through its configured RPC and synthesizes
from a fresh wallet-owned decisions document. Before compiling or retaining an artifact, it
compares the account, rule context and target code hash, ordered calls and argument constraints,
complete signer predicate, expiry, call cap and policy kinds with the proposal. Every difference
is refused. The browser repeats this comparison against the returned specification. Duplicate
JSON keys, lossy numeric literals, unknown fields and malformed or oversized input are refused.
The transaction must still be available in the RPC node's retention window.

Both specification hashes are displayed. Equality is not required: acquisition provenance may
change while the permissions stay equal. Import clears previous proposal previews and evidence,
but retains an existing installation's recovery and removal controls. It performs no deployment,
owner signing or submission. Continue through the separate deployment, four-layer checks,
installation consent and passkey steps below.

To complete account and live execution checks, the grant's delegate must be the automation
delegate held by this backend session. Create that delegate first and provide its public address
to the agent. A proposal naming an external delegate can be inspected and regenerated, but those
checks remain unavailable and installation stays blocked; importing never changes the delegate.

The import boundary has unit and action/controller tests plus a browser check against a synthetic
backend. With the applied checkout's Vite server running, run
`OZPB_BROWSER_CHANNEL=chrome node scripts/test-wallet-proposal-browser.mjs http://localhost:3000`
from the toolkit checkout (using the Playwright dependency documented under [Verification](#verification)). This covers paste/file input,
changed-grant refusal, failed-retry invalidation and size limits. It does not attest to a live
RPC acquisition, generated-Wasm build or passkey-approved installation of an imported proposal.

The separate [26 October 2026 testnet run](evidence/wallet-proposal-import-testnet-2026-10-26.json)
exercised a real CLI-to-wallet handoff: independent recording and synthesis, JSON file import,
wallet-owned recording and regeneration, reproduced generated Wasm, all four verification layers,
installation and revocation. The agent-side and wallet hashes differed; the permissions matched.
The replay check cleared after signature expiry, the installed rule read back identical, and
revocation left the rule absent and the policy marker unset. This used an automated virtual
passkey and a backend-held delegate: no human clarification or protected approval is attested,
and no delegated transaction was submitted under the installed rule.

## Review and consent

1. Create a passkey using Pollywallet's existing authenticator helper, then separately review
   and confirm recognized account deployment. Alternatively attach the public locator of an
   existing recognized account. Retain that locator to reconnect; it contains no private key.
2. For an account created in this session, prepare the fixed sample transfer, review its
   sender, recipient and fee, then separately approve it with the owner passkey. It transfers
   exactly 0.1 testnet XLM back to the local fee payer, which pays at most one testnet XLM in
   transaction fees. Recording remains a separate action after confirmation. An attached
   wallet must supply its own confirmed authorized transaction. Select the restricted
   delegate, grant name, expiry and call limit; the backend retains the resulting
   specification and generated artifact under opaque identifiers.
3. Inspect the immutable specification, generated files, Wasm hash, build manifest and
   verification limits. Deployment confirmation concerns that exact artifact and the testnet
   fee ceiling; it does not grant account authority. The policy's Wasm upload may cost the fee
   payer up to 15 testnet XLM. Every other transaction, installation and revocation included,
   stays at 1 testnet XLM. The upload ceiling was 10 XLM until testnet's resource fee for a
   policy Wasm of about 21 KB passed it (101,422,794 stroops on 22 October 2026). Testnet only.
4. Refresh the live authority and exact installation grant. The browser independently checks
   the recognized owner rule, full credential identifier, policy address and retained bindings.
   The selected owner rule comes from that evidence; rule zero is not assumed.
5. Optionally run the local execution checks described below: account-Wasm, then captured
   target. They sign nothing with the owner passkey and do not change the installation gate's
   other required layers.
6. Optionally prepare the [live-enforcement check](#live-enforcement-check), read its consent
   statement, and consent with the owner passkey. It is the only step in which the automation
   delegate signs for testnet, and its signatures, the owner's included, are simulated and never
   submitted.
7. Only when the required verification report is complete does the route offer
   [installation](#installation). It checks the fresh unsigned envelope against the immutable
   display and shows its own consent statement before asking Pollywallet for a passkey signature.
   It then independently checks the signed XDR, origin, challenge, user verification, full signer
   identity and exact owner rule before submission. [Revocation](#revocation) works the same way.

Account and policy deployment confirmations are distinct from owner authorization. A cancelled
or refused signing attempt consumes the prepared review. Sample preparation is available only
for the exact wallet created in this backend session and checks its retained full owner-zero
getter, including the fresh constructor's empty `policy_ids` and `signer_ids: [0]`.
A new preparation invalidates the old action; its 120-second token can expire sooner
under the ledger freshness checks. Cancellation before submission permits another preparation.
After any sample submission attempt, the client disables further attempts, including when a
response is lost. Backend enforcement, fresh code/owner/sequence checks and the journal still
apply before the fee payer signs or sends anything. The confirmed hash is offered for a
separate recording action.

Sample authorization preserves either direct `Address` or `AddressV2` credentials exactly.
For `AddressV2`, the SDK constructs the address-bound preimage described in Stellar's
[authorization migration guide](https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/).
The browser and backend reject a changed credential discriminator and do not downgrade V2
to the legacy payload. Source-account credentials and delegation wrappers are unsupported
for this owner-passkey flow.

## Account-Wasm execution

With `nativeExecutable` or `liveHelper` configured, the route can create a local automation
delegate. The backend generates an Ed25519 key in process memory and returns only its public
address and an opaque capability ID; at most eight exist per backend, and they disappear when it
stops. It also creates the key's classic testnet account through Friendbot, a testnet write that
costs the fee payer nothing: the authority review refuses a grant whose delegate account does not
exist, and the host checks the delegate's signatures against that account. If that account cannot
be created, the key is dropped and its slot freed, so the step can be retried. Use that address as the grant's restricted delegate. The owner passkey never stands in for
it, and a grant naming any other delegate address cannot run these checks. The key never signs
supplied bytes. It signs through two capabilities only, each refusing the other's network: the
offline capability signs authorization preimages in the derived offline execution network, and
the [live capability](#live-enforcement-check) builds and signs the two testnet transfers of one
consented live check.

`Run local execution checks` runs this layer and then the
[captured-target layer](#captured-target-execution) from one CLI preparation, so both report the
same run hash. The account-Wasm layer uses only state the backend retained for the reviewed
deployment:

1. `ozpb prepare-dry-run` binds the exact artifact claims, binding set, signed registry, the
   next context rule ID from the reviewed authority evidence and a fresh run nonce. Its run
   hash, suite hash and per-case reference expectations become the independent expectations.
   Without a bounded next-ID enumeration in that evidence, the layer stays `unavailable`.
2. The operator RPC supplies one coherent protocol-29 ledger header, the archival TTL limits
   and the pinned account Wasm bytes, within twelve ledgers of each other.
3. The worker runs once with `--prepare`; the wallet checks that frame against step 1 and the
   offline signing domain, then runs the identical job interactively. Every repeated frame
   must equal the retained one. The wallet signs only the offline-domain `__check_auth`
   preimages of IDs in the derived case, control and sequence inventory, each at most once,
   in the runner's exact request-ID and nonce order, through the offline capability, which
   refuses a preimage for any other network. The order of the IDs themselves is not enforced.
4. The final report is accepted only after the wallet recomputes agreement for every case
   from the CLI's expectations and the reported observations, checks all five cryptographic
   controls and the stateful call-cap sequence, and requires a zero worker exit that leaves no
   process in the worker's group; any refusal kills the group members it can signal.

Native case results are checked against the ordered synthetic case ledgers emitted by
`prepare-dry-run` as `reference_case_ledgers`. These are boundary-test ledgers,
not the RPC snapshot ledger. The wallet rejects missing metadata or a result at a
different ledger; deploy the updated CLI and wallet together. Historical Rust reports
without the metadata remain readable. This check does not add per-case signature
expiration authorization to the offline signer.

The wallet retains every checked account/captured case: its label, mutation class, expected and
observed outcome, refusal role/code and whether state stayed unchanged. The route shows these
under each layer. Account denials must match the mutation class's predicted policy/account error,
and each boundary case must start from its declared counter seed; worker verdicts alone are
insufficient. Shared positive/negative vectors exercise this attribution contract in Rust and JS.

The report also has an explicit `acceptance` block, matching the CLI's offline permit/deny bar:
the reference passes, every executed offline layer permits its original and passes, and at least
one layer reverts five derived denials with the predicted refusal and unchanged state. Denials
from different layers are not summed. This bar can pass while live enforcement is unavailable;
it does not make the four-layer report complete. The browser and backend require the bar in
addition to all four passed layers before installation; the backend recomputes it from retained
case observations at its installation gate. The browser independently recomputes the same bar
from the displayed per-case observations and rejects any mismatch with the supplied summary.

A passing result marks only the `account_wasm` layer. It is local execution in fresh synthetic
state: no target contract, captured network state or live enforcement runs, and it proves no
ownership of the real wallet. Every other outcome carries no evidence:

- `unsupported`: the grant is outside the worker's scope, for example a call cap above 512;
  nothing runs.
- `unavailable`: the next rule ID was not established, or CLI preparation or the operator
  RPC read did not complete; the worker does not run.
- `failed`: the preparation evidence, the worker or its report was refused.

## Captured-target execution

The second layer runs the reviewed grant's exact call against target state the operator RPC
reports now, through the worker's [captured-target mode](CAPTURED-TARGET-EXECUTION.md). It is
supported for the grant this route generates from the fixed sample transfer: one rule whose only
call is the testnet native SAC's `transfer(SELF, G recipient, exact amount)`.

1. The backend builds an unsigned envelope for that call, sourced from its fee payer at the
   current sequence, and runs `ozpb capture-target` through the operator RPC. The envelope is
   confidential input: it reaches the CLI only in a private request file, and neither that file
   nor the capture, which repeats the call, is kept once the CLI exits. The envelope is never
   signed, journaled or submitted, and no response, worker job or evidence contains it.
2. The capture is accepted only for this account's exact call on testnet, from the pinned
   account code, with exactly the SAC instance, the sender's balance and the recipient account
   as target entries and a header that hashes to itself and describes the captured ledger.
3. The worker runs once with `--prepare-captured` on the same preparation, at the capture's
   ledger and archival settings. The wallet checks that frame against the preparation, the offline
   signing domain and its own `ozpb:v1:target-capture` hash of the capture, which the binding's
   state hash, and so the signing domain, must also commit to. The run hash must be the CLI's;
   the source ledger, account, delegate, policy and its code, rule IDs, case IDs and signature
   expiry must be the ones expected. The captured job and suite hashes cover the capture job and
   the three planned cases, which the wallet cannot recompute: unlike the account layer, whose
   suite hash is the CLI's, they are taken from this trusted local preparation and must repeat
   exactly in the execution. The identical job then runs with `--captured`; the wallet signs
   only the original and adjacent-amount cases.
4. The report is accepted only after the wallet recomputes every case. The original must move
   exactly the amount from the sender's SAC balance to the recipient, advance the call counter
   from 0 to 1, create exactly the account's and the delegate's nonces and write nothing else. The
   adjacent amount and the unsigned call must be refused by the generated policy, with codes 6
   and 1 attributed to it, and leave state unchanged. No case may read a key outside the capture
   or report an unexpected change. A refusal by the target itself fails the layer rather than
   passing as a policy decision.

A passing result marks only the `captured_target` layer. It is offline and counterfactual over
`rpc_reported` state: it makes no owner-authority, fee, reserve or live-network claim. Every
other outcome carries no evidence:

- `unsupported`: the grant is not that single exact-amount native transfer, or its call cap is
  above 512; nothing is captured.
- `unavailable`: the next rule ID was not established; CLI preparation, the operator RPC, the
  envelope or `capture-target` did not complete; the captured ledger is older than the backend's
  read immediately before the capture or more than twelve ledgers newer; or the grant expires at
  or before the captured ledger. The worker does not run.
- `failed`: `capture-target` reports that the record-mode simulation failed
  (`E_TARGET_REFUSED`: the target refused the exact transfer, for example for an insufficient
  balance or a missing recipient, or the endpoint's simulator failed, which its withheld text
  does not distinguish), or that the call's state is archived (`E_TARGET_ARCHIVED`: a
  restoration preamble, a simulation that restored archived entries, or a footprint entry
  archived at or expiring at the captured ledger), so the worker does not run; or the
  preparation evidence, a capture for another call, network or account code, the worker or its
  report was refused. The backend reads only that code from the CLI's error output, never its
  text, and only from `capture-target`'s own refusal.

A passing layer records the captured ledger as `evidence.observedLedger`, and stored evidence
does not age by itself. The [installation gate](#installation) requires that ledger to lie at
most 360 ledgers before the installation's own ledger reads, and not after them.

A new review starts again without local execution evidence. Each worker run has a 120-second
deadline, `capture-target` 120 seconds, and the backend serves one request at a time. If the
browser disconnects during the checks, the backend records no evidence for that attempt and
accepts requests again once the running step stops; it checks for the disconnect before every
step, so nothing new starts. It kills the process group of a running `ozpb` call or native
worker at once. Two things are not stopped that way. A policy build that CLI preparation
started runs in its own process group until it finishes or reaches the build deadline
(`buildTimeoutSecs`). An operator RPC step the backend itself has started completes first: it
makes at most four requests (the ledger and account-code read), each bounded by 15 seconds.

`bash scripts/test-wallet-native-execution.sh` runs both layers against the actual CLI and
worker with the runtime test's public delegate seed. For the captured layer, the actual
`capture-target` reads the [recorded testnet responses](../crates/source-rpc/tests/captured-testnet/target-capture/)
through the wallet toolchain, served offline by a loopback endpoint. Like the testnet harness, the
script needs `OZPB_REGISTRY_SNAPSHOT_ROOT` set to the root of `docs/examples/registry.signed.json`;
`OZPB_ACCOUNT_WASM` may reuse a pinned account artifact.

## Live-enforcement check

The fourth layer shows the reviewed candidate deciding a real call on testnet: an enforce-mode
simulation of the [atomic live helper](ATOMIC-LIVE-HELPER.md), which installs the candidate rule
through the account's own `add_context_rule` and then makes the grant's exact transfer under it.
It needs `liveHelper` and a backend-created [automation delegate](#account-wasm-execution) as
the grant's delegate. Nothing is submitted, but the signatures are real: the owner's passkey
signature alone is a submittable installation, and with it the delegate's are a submittable
transfer, until they expire ([why](ATOMIC-LIVE-HELPER.md#signatures-are-real-and-usable-without-the-helper)).
So the check runs only after the owner consents to exactly what is signed.

It supports the grant this route generates from the sample transfer: one rule on the testnet
native asset, one Ed25519 delegate, a call cap, and one exact-amount `transfer` to a G account
of at most 1,000,000 stroops, so that the adjacent denial stays within the helper's bound. Two
cases run: the exact transfer (`target:original:0`), which the candidate must permit, and one
stroop more (`target:argument-denial:0`), which it must refuse with `NoTupleMatched` (6). This is
two named cases, not the derived deny suite.

1. **Prepare.** The backend reads, through the operator RPC: the helper's instance and code,
   which must run the reviewed helper Wasm and stay live past the signatures' expiry; the
   deployed candidate's code, which must be the reviewed Wasm; that the recipient exists and the
   account's balance covers the amount; and the account's `NextId` and `Count`, every rule below
   `NextId`, and the candidate's installation marker for the next rule ID, which must be the one
   the review established. It reads back the delegate's classic testnet account, which must be
   signable by its master key alone, and creates it through Friendbot if it is missing. It then
   fixes the expiry ledger N, 30 ledgers
   (about two and a half minutes) after the latest ledger, and returns the consent statement.
   Nothing is signed, and nothing signable has been released.
2. **Consent.** The browser derives the statement itself from the reviewed grant and the
   backend's inputs (helper, candidate hash, rule ID, ledgers) and shows it: both exact calls,
   the owner's installation and each delegate transfer, the expiry N, the labels and this
   warning: until ledger N the signatures are real and submittable; the owner's alone installs
   the rule, which gives the backend-held delegate the grant's authority until it expires;
   none of them names the helper; all of them reach the operator's RPC endpoint inside the
   simulation requests; and the replay check after N compares the account with the state read
   before they existed. Consent returns the statement's SHA-256. The backend accepts it only for
   the statement it prepared and only while at least 15 ledgers remain before N. Only then does
   it journal the replay obligation (below) and release the unsigned owner entry with a fresh
   nonce. The browser checks that entry is exactly the reviewed installation before the passkey
   sees it.
3. **Run.** The backend verifies the owner's passkey signature of that entry as for any owner
   signature (origin, challenge, user verification, full credential, owner rule). Only then does
   it mint the delegate's live capability for exactly the consented check. That capability takes
   a structure, never bytes: account, asset, recipient, amount, rule, nonce and expiry. It
   accepts only testnet, only the two consented amounts, each once, and only expiry N. It builds
   the account's transfer entry (no sub-invocations, checked under exactly the candidate rule)
   and the delegate's own `__check_auth` entry itself, and signs the latter. For each case, with
   at least 3 ledgers left before N, the backend builds an unsigned envelope from its fee payer
   with the helper call and the three entries. It sends that envelope to `simulateTransaction`
   in enforce mode and keeps the raw result, with its XDR still base64. Nothing is signed by the
   fee payer or sent. Each raw response must pass `validateLiveCase`.

Outcomes:

- `passed`: the exact transfer validated as a `permit` and the adjacent amount as a `deny` with
  code 6 from the candidate policy's contract ID.
- `failed`: a response the validator refused, a permitted adjacent amount, a denial with another
  code or from another contract, a helper refusal (7001–7009), or a deployed candidate that is not
  the reviewed Wasm. None counts as passing evidence.
- `unavailable`: no helper configured; the helper missing, not the reviewed Wasm, or its
  instance or code archived or ending before N
  ([extend or redeploy it](ATOMIC-LIVE-HELPER.md#keeping-the-helper-live)); the candidate missing
  on testnet; no established next rule ID, a moved `NextId`, or the candidate already installed
  for it; a delegate account that could not be created or read back; an RPC read or simulation
  that did not complete; a recipient or balance the transfer cannot run against; a grant expiring
  before the check; too few ledgers left; or a response needing restoration while the other case
  came out as expected. None of these is about the candidate.
- `unsupported`: any other grant shape, including a policy without a call cap, which the helper
  cannot observe.

A passing layer carries public evidence only: the helper, the candidate and their hashes, the
expected rule ID, the expiry ledger, the statement hash, each case's outcome, simulation ledger
and envelope hash. It also carries the owner's `webauthn_user_verified` with
`human_approval_attested: false`, and the labels `state_dependent`, `simulation_only`,
`signatures_valid_until_ledger:N` and `delegate_is_wallet_in_memory_automation_key`. It is
evidence about testnet state at the simulation ledgers. Stored evidence does not age by itself; the
[installation gate](#installation) bounds the simulation ledgers as it bounds the captured one.

**Replay check.** The prepared reads of `NextId`, `Count`, the rules and the installation
marker are the state before any signature existed. At consent, before the owner entry is
released, they are recorded with N and journaled in the session directory. While any recorded
signature is still valid, `Check that the live-check signatures were not used` reports `waiting`,
and a new live check is refused. After N, it re-reads the same state. The ledger it judges by is
that of the read itself, never a separate request, which a lagging node could answer. It reports
`unchanged`, or `changed` with what moved and an alert not to install. The check runs when the
owner asks for it; nothing runs it automatically. A record outlives an aborted run, but only in
the running backend: the journal entry is evidence for the operator, and a restarted backend does
not read an earlier session's journal. After a restart, wait until the earlier N has passed before
preparing another check. `requireNoReplay` in
[`wallet/server/live-check.mjs`](../wallet/server/live-check.mjs) is the guard the installation
flow must call before it signs anything; it refuses unless the check reports `unchanged`, and
without any record. [Installation](#installation) calls it before it releases an entry for the
passkey and again before the fee payer submits.

**Ledger clock.** The operator RPC's latest ledger fixes N, decides whether consent and each
simulation still fit before N, and decides whether N has passed for the replay check. Each of those
reads takes the header the RPC returns with the latest ledger, which must describe that ledger and
hash to its reported ID. Its close time must be a whole number of seconds within 60 seconds of the
backend machine's clock, or the step is refused and preparation reports `unavailable`. That catches
a stalled node, a node serving state from before a testnet reset, and a backend host whose own
clock is wrong. It does not check the ledger sequence: the RPC is trusted for the sequence without
a bound. A header with a current close time and an invented sequence passes, and could put N far
past the real ledger. The operator chooses that endpoint.

A passed live layer stays passed in the report even if a later replay check reports `changed`: the
replay check speaks about the account, not the candidate. Installation therefore refuses unless
`requireNoReplay` reports `unchanged`, whatever the layer says.

The browser clears the displayed replay result when the wallet, recording or grant changes,
when authority is reviewed again, and when a new live consent starts, even if that consent fails.
A refreshed authority review also invalidates any pending live consent preview before signing.

If the browser disconnects during the run, the backend checks for that before each step: it
signs and simulates nothing further, and records no layer. Signatures already created stay valid
until N, and the replay obligation stays recorded. The backend serves one live check at a time
and runs no local execution check alongside it.

## Installation

Installation needs the native worker and the live helper, so that all four layers can run. It is
offered for one review at a time, with one installation allowance. Verified revoke-first
replacement can open the next allowance. Status reports `install: true` only while some review
has a complete report and this allowance has not been spent,
and `installOpensAfterLedger` while an earlier released signature is still valid. Nothing is
released or spent while the fee payer cannot submit, for example after an uncertain result.
Starting another recording or generation for the same wallet clears proposal consent and
verification state while retaining an earlier installation and its recovery identity. Confirmed
grants remain revocable, and a lost submission response can still be reconciled by a status
refresh. Switching wallet identity clears that lifecycle state.

`Prepare installation` (`assemble`) and the passkey approval (`submit`) are two steps. A backend
refusal to prepare keeps the browser's review, since nothing was released; an answer the browser
itself refuses consumes it.

**Gate.** Before anything is released, and again before the fee payer submits, the backend
re-establishes the same conditions:

- The stored report for this exact review has the four layers, `reference`, `account_wasm`,
  `captured_target` and `live_enforcement`, all `passed`, about this artifact, deployment and
  binding set.
- The account and captured layers ran with this policy, its code hash, the grant's delegate and
  the rule ID the review established, from one CLI preparation (same run hash). The live layer
  names this account, policy, code hash and rule ID.
- The captured ledger and both live simulation ledgers lie at most 360 ledgers (about 30 minutes)
  before the latest ledger, read through the [ledger clock](#live-enforcement-check), and not
  after it.
- `requireNoReplay` reports `unchanged` for every replay obligation still open: the live check's,
  and those of earlier installation entries. While a signature is still valid it answers
  `waiting`, which refuses too. Without any obligation it refuses.

**Prepare.**

1. `ozpb assemble-install-transaction` re-runs the authority check for the retained deployment
   request and returns the unsigned `add_context_rule` transaction from the local fee payer. Its
   validity is 60 ledgers from the CLI's sequence read, and its fee ceiling is 1 testnet XLM.
2. The backend reads the owner rule again, which must be byte-identical to the reviewed one, and
   reads the fee payer's sequence. Both reads must lie within 12 ledgers of the CLI's authority
   read.
3. `validateAssembly` checks every field against the review, as the browser does again: the
   authority commitment, owner rule and grant, network, fee payer, sequence, fee, ledger bounds,
   the exact `add_context_rule` arguments, one address-bound owner entry with no
   sub-invocations, and the declared resources. Testnet records `AddressV2` credentials; either
   direct arm is kept as recorded.
4. The backend reads the account state the live check's replay obligation reads, then rechecks
   the four-layer evidence and assembly authority freshness against a fresh bounded ledger clock.
   It journals the entry's expiry with that state as a new obligation only after these checks,
   before the entry leaves the backend. From then on a
   passkey may have signed it. Until it expires, no other installation entry is released. After it
   expires, the replay check compares the account with that state. Like the live check's, these
   obligations exist only in the running backend; see [After a restart](#after-a-restart).
5. The browser derives the consent statement itself from the review and the validated assembly and
   requires it to equal the backend's. The statement shows the exact `add_context_rule` call, what
   installing grants (delegate, target, allowed calls, call cap, expiry, rule ID), the
   transaction's ledger window and the signature's expiry, and the fee prepared and at most. The
   delegate's key is the backend's automation key.

**Submit.**

1. Consuming the prepared action spends the review, whatever follows: a refused attempt is never
   re-released for the same review.
2. The gate runs again. A fresh `prepare-install-intent` must return the approved commitment and
   grant. Then the owner rule must read back unchanged and the fee payer's sequence unmoved, both
   within 12 ledgers of that authority read, and the transaction's ledger window must still be
   open.
3. The owner's signature is checked as for every owner signature: exact entry, origin, challenge,
   user verification, full credential and owner rule.
4. The fee payer enforce-simulates the signed transaction. Only fee and resource fields may change,
   and the fee stays at most 1 testnet XLM. The CLI's transaction has no time bounds, which the
   SDK's assembly cannot rebuild, so the simulated resources are set on its own XDR. The payer then
   signs, journals the intended hash, submits once and waits for the receipt. An uncertain
   result blocks every later write in the session, as for every other submission.
5. A confirmed transaction is listed in `status` at once, as `confirmed_unverified`, with its hash
   and ledger. It becomes an InstallationRecord only when all of the following hold:
   - `add_context_rule` returned exactly the reviewed rule with the expected ID;
   - the account emitted exactly one `context_rule_added` for that ID, whose data repeats the
     returned rule;
   - the rule reads back identical from a node at or past the transaction's ledger;
   - the policy's installation marker for the rule is set, read from such a node too.

   A lagging node is asked again, up to five times.

The record binds the transaction hash, ledger, account and rule ID to the policy and its code
hash, the spec and binding-set hashes, the authority commitment, the report's run ID and layers,
the evidence ledgers and the live check's consent hash. It also carries the owner's
`webauthn_user_verified` with `human_approval_attested: false`. Once it exists, it closes every
open replay obligation, so the replay check then reports `closed`. A confirmed installation whose
verification failed stays listed, and leaves the obligations open. It can still be revoked when its
own event named one rule ID.

When a `submit` response fails or is lost, the backend may still be working on the request and
answers every other request with "busy" until it is done. The browser therefore asks for the status
again every three seconds, for up to two minutes. Once the status lists a confirmed installation
of the expected rule for this wallet, the browser adopts it, so that it can be revoked. If the
backend is still busy after that, `Refresh backend status` asks again, and so does any later
status read.

### After a restart

Replay obligations, the one-installation-per-session limit and the installation records exist only
in the running backend. The session journal keeps every obligation (`live-check` and
`install-release` entries) and every submission for the operator, but a restarted backend does
not read it. So after a restart:

- The new backend does not know that an installation entry released before the restart may have
  been signed. Until that entry expires, it could still land, and it would install the same grant
  a second time, with a call cap of its own.
- The new backend cannot revoke a rule the earlier one installed.

Before installing again after a restart, the operator:

1. Reads the latest `signatureExpirationLedger` among the earlier session's `live-check` and
   `install-release` journal entries, and waits until that ledger has passed.
2. Checks the account's rules, for example with a new review, whose authority evidence lists
   every rule. A rule that is not expected must be removed first, outside this wallet session,
   for example with the harness's `lifecycle.mjs`.
3. Only then starts a new review.

An installation that needs a separate restoration transaction is refused. Restore the archived
entries, then review again.

## Revocation

`Prepare revocation` (`prepare-revoke`) is offered for an installation from this session:

1. The backend checks fresh account and owner-verifier code observations against their pins
   and reads the owner rule, which must be unchanged. Removal of the owner rule is forbidden.
2. It reads the installed rule, which must be present. Ordinarily it must match the recorded
   bytes; after fresh detected rule drift, the separate monitoring flow below may instead
   bind removal to the exact current bytes, with explicit saved-versus-current consent.
3. The fee payer's record-mode simulation drafts `remove_context_rule(rule_id)`. It must record
   exactly the account's own authorization of exactly that call, as for the sample transfer.
4. Browser and backend validate the draft (`validateRemovalAssembly`) against a removal approval
   bound to the wallet's owner rule and the installation's account, rule ID and transaction. The
   browser shows its own consent statement.

`confirm-revoke` repeats those reads, checks the owner's signature and submits once, as
installation does. A removal that was refused before anything was sent can be prepared again:

- a refused check or signature;
- a fee-payer refusal that leaves it able to submit, such as a failed enforce-mode simulation.

Once a removal may have reached the network, the installation is never offered for removal again
in this session. That covers a send whose result is uncertain and a confirmed removal.
`status` reports `removalAttempted` for each installation. The confirmed
removal's identity is kept before anything is verified. It is reported `removed` only when both
of these hold:

- the account emitted exactly one `context_rule_removed` for the rule, with the empty data map the
  pinned account emits;
- `get_context_rule` for that ID, simulated from a node at or past the removal's ledger, fails with
  the account's own contract error 3000 (no such rule).

A rule that still reads back, or any other answer, refuses success. Policy cleanup is reported
separately, from the policy's installation marker: `not_installed`, `still_installed`, or
`not_checked`. The pinned account removes a rule's policies on a best effort basis.

## Report layers

The four report layers are `reference`, `account_wasm`, `captured_target` and
`live_enforcement`. The UI distinguishes the first three local checks from full acceptance.
Missing, unsupported, failed, duplicated or mismatched evidence keeps acceptance closed.
An installation preflight is not counted as behavioral live-enforcement evidence. Backend
capabilities keep installation unavailable until a review's report is complete, and lifecycle
actions until an installation exists.

The `live_enforcement` layer comes only from the consented [live-enforcement
check](#live-enforcement-check), and each of its two responses must pass the validators in
[`wallet/shared/live-enforcement.mjs`](../wallet/shared/live-enforcement.mjs). The report is
`complete` only when all four layers passed. A complete report alone does not install anything:
[installation](#installation) adds its own evidence-age bound, replay check and authority
recheck.

Authentication with a virtual authenticator is automation evidence. The signature result
explicitly reports `human_approval_attested: false`; it does not establish a human acceptance
decision. This local design also does not protect against an agent or process with arbitrary
control of the operator's OS account or browser profile.

## Verification

The [20 October 2026 sample run](evidence/pollywallet-sample-2026-10-20.json) created and
funded a pinned testnet account, approved the fixed 0.1 XLM transfer using `AddressV2`,
confirmed it at ledger 5294119, and recorded the transaction through the CLI. It used the
actual browser integration with a virtual authenticator. This is sample-flow evidence;
the run did not install a generated grant or complete four-layer/lifecycle acceptance.

The [22 October 2026 live-check run](evidence/wallet-live-enforcement-testnet-2026-10-22.json)
went through this route end to end on testnet: a fresh account and its sample transfer, recording,
an automation delegate, generation, deployment and review of a one-call grant, then the
[live-enforcement check](#live-enforcement-check). The exact transfer validated as a permit and one
stroop more as `NoTupleMatched` (6) from the candidate policy. The layer passed against the deployed
helper, simulation only. After the signatures expired, the replay check found the account
unchanged. The owner was a virtual authenticator, so this is automation evidence with
`human_approval_attested: false`. No native worker was configured, so the report was not complete,
and nothing was installed.

The [22 October 2026 install-and-revoke run](evidence/wallet-install-revoke-testnet-2026-10-22.json)
took a fresh account through all four layers. The replay check reported the account unchanged
once the live-check signatures expired. The owner's passkey then [installed](#installation) the
one-call grant as rule 1, which the account's `context_rule_added`, a matching read-back and the
policy's marker confirmed. It then [revoked](#revocation) it: one `context_rule_removed`, the rule
absent (#3000), policy cleanup `not_installed`. The owner was a virtual authenticator, so this is
automation evidence with `human_approval_attested: false`. No delegated call was made under the
installed rule. [Section 15 of the testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md#15-wallet-installation-and-revocation-22-october-2026)
records the run and four earlier attempts that day that stopped before installing anything.

Toolkit tests exercise session authentication, one-shot state, transport limits, exact XDR
and signature checks, and the client controller's refusal paths. The installation and
revocation tests drive all four layers with a fake worker and RPC, then the gate, the replay
obligations, the authority recheck, single submission, and the event and read-back checks
against receipts in the shapes testnet returns. They are fixture evidence, not a testnet run. The apply-script tests cover
immutable inputs, dirty/different upstream checkouts, symlinks, missing lock metadata, and
binary/rename patches that omit ordinary text headers.

The upstream bridge test uses the actual Pollywallet SDK 16 passkey helper and nested SDK 17
validator with a generated test key. It checks the full credential, a nonzero installation
owner rule, and the exact fixed sample-transfer envelope with owner rule zero, using both
legacy and V2 credentials. It marks the
result as automated authentication.

With the applied checkout's development server running, the browser regression uses the
existing Playwright lockfile and a temporary virtual authenticator:

```sh
npm --prefix testnet-harness/browser ci --ignore-scripts --no-audit --no-fund
OZPB_BROWSER_CHANNEL=chrome node scripts/test-pollywallet-browser.mjs /absolute/path/pollywallet
```

Run this from the toolkit checkout. It calls the actual upstream registration and signing
helpers at the supported `localhost` origin, independently verifies installation and
sample-transfer signatures, and submits no transaction. It removes its temporary browser
module afterward. Omit
`OZPB_BROWSER_CHANNEL` to use the installed Playwright Chromium instead of local Chrome.

At the pinned upstream revision, `pnpm exec tsc --noEmit` already reports five errors in
`src/hooks/useWallet.ts` and `src/lib/tx-analyzer.ts`. The unchanged upstream checkout produces
the same diagnostics. Generate the route tree with `pnpm build` before comparing type checks;
this integration does not edit the generated route tree or suppress those upstream errors.

## Revoke-first replacement

After a session's latest installed grant is removed with a verified account event and absent-rule
readback, the route can prepare a replacement. The browser and backend independently derive
the acknowledgement from the previous installation and removal transaction. It explicitly
discloses that a new installation has a fresh counter: authority already used under the old
grant is additional to the new cap, rather than carried forward as a remaining allowance.

Preparation and confirmation each re-read the unchanged owner and every previously removed
rule, within a bounded ledger window. A revived rule, stale read, changed owner, unverified
removal or untracked installation attempt refuses replacement. Confirmation adds no authority
and signs/submits no transaction. It discards old candidate reviews, deployments and pending
actions; artifact IDs already attempted for deployment remain spent, and removal history remains visible in backend status. Earlier artifacts that were never deployed still need a fresh deployment, review and all checks.

Record or import a new grant, generate/deploy a fresh artifact, review it, rerun all four layers
and the replay checks, then approve the new installation with the owner passkey. The existing
live-check admission guard still waits until earlier released signatures expire, including a
previous installation entry. This can require waiting before the new live check. A cancelled
or refused replacement preserves the removed grant and the spent installation guard. There
is no add-before-remove path, automatic retry or rollover of old policy state. A lost confirmation
response is recovered from an action-bound acknowledgement retained in backend status; the
browser accepts it only for its pending action and independently derived removed-grant display. This flow is
session-local; it does not import lifecycle records from a prior backend process.

A lost `confirm-revoke` response is a separate limitation: status reports the removal
transaction and prevents resubmission, but does not reconstruct the full verified removal
record in the browser. The replacement button therefore stays closed in that browser.
Do not retry removal or treat its summary alone as replacement consent; recover and verify
the transaction outside this route. Automatic browser recovery of this case remains pending.

## Generated source support

This integration supports the fixed `policy-templates/scope@1` generator and reproduces its
source/Wasm itself. Proposal import regenerates a permission description; it does not execute
or install source code supplied in the proposal. Custom policy source is unavailable in this
wallet. A custom-source review, risk acknowledgement and installation flow is not implemented.

## On-demand installed-grant monitoring

`Check installed grant now` performs fresh, bounded, non-atomic RPC reads while this page is
open. It compares the exact recorded rule, account/policy/owner-verifier code and installation
marker, and rechecks modeled authority against the InstallationRecord commitment. The
supported native-token target has a Stellar Asset host executable, not a Wasm hash; monitoring
checks its canonical native-testnet address, executable kind and protocol 29 explicitly.

The ordinary install authority check correctly sees an already installed stateful rule as
an overlapping grant. The separate `ozpb check-installed-grant` command instead validates
the entire real scan first, requires the exact saved rule identity/ID vectors and the last
allocated rule ID, and projects only that rule out of the authority model. It preserves shared
closure entries and candidate-required classic/verifier observations. Its projected commitment
must equal the preinstallation commitment; no new baseline is learned. Actual scan digests
and ledger evidence remain separate from the counterfactual projection. This command returns
a distinct monitoring observation and cannot prepare an installation.

An `unchanged` result means the exact recorded grant and modeled authority matched within
the displayed ledger window. It does not cover unmodeled storage, signer/policy allocation
counters, storage reference counts, unrelated rule names, TTL continuity, policy-counter
integrity or changes between observations. Expiry alone is `inactive`: the modeled-authority
comparison continues after expiry, and simultaneous authority/code/rule drift remains `drift`.
Later allocations or a changed rule/authority/code are `drift`; incomplete, archived, stale or failed reads are
`unavailable`. Legitimate later rule allocations conservatively count as drift. This is
detection only, with no background process, signature, submission or safety verdict.

After fresh detected rule-configuration drift, revocation may remove that current rule only
after separately showing the saved and current configuration. The browser and backend derive
the same consent, including hashes of both configurations. Preparation requires the backend's
own fresh monitor result; submission rechecks the exact current bytes. Account and owner
verifier pins and the unchanged owner are checked before both steps, and removal of the owner
rule is forbidden. Changed account/verifier code or owner identity requires a trusted recovery
interface. Verified rule removal remains separate from best-effort policy cleanup. If the current policy
configuration differs from the recorded one, cleanup is reported `not_checked`; an observation
of the old policy is never attributed to the newly removed policy. Otherwise cleanup requires
the expected policy code and fresh instance/code/marker observations.
