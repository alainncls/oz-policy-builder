# Developer guide

How to use the toolkit, how the synthesizer decides scope, and how to extend it with a new
policy primitive. (Design rationale lives in `architecture.md`; this is the working guide.)

> **Scope markers.** The toolkit is delivered in milestones and this guide covers all of it.
> Anything a later milestone contracts is marked **Tranche 2**, in the same terms as the
> per-component banners in `architecture.md`; anything unmarked is Tranche 1. A marker says
> which milestone contracts the thing, never whether code for it exists in the checkout you
> are reading: scope is a fact of the plan and holds for any tree, whereas what a given tree
> contains differs between a development trunk and a milestone delivery, so a status claim
> here would be false in one of them. Read a marker as "not part of what a Tranche 1 delivery
> is reviewed against" — and read it before running the command, rather than discovering it
> when the command is not there.

## 0. One-time setup for a new clone

```sh
git config core.hooksPath .githooks
```

That points git at `.githooks/pre-push`, which checks commits before anything leaves the
machine. Git does not track `.git/hooks` and cloning does not carry hooks, which is why the hook
lives in a tracked directory and is pointed at rather than installed.

It matters here more than the one command suggests. The gate's strong check compares this
tracked tree against the private root that sits beside the checkout — by filename and by
content hash, so a confidential document is caught whatever it is renamed to — and that root
exists on a working machine and nowhere else. CI checks out one repository, `..` is empty
there, and it says so rather than reporting a pass it did not earn; what CI can still do is
match the shapes confidential material takes, which is its half of the check and the backstop
for anything pushed with `--no-verify`.

Changes are developed and reviewed in this repository first. The pre-push hook checks the
publication boundary; it does not require a commit-origin marker.

## 1. Using the toolkit

Two shells over one library (`crates/toolkit`): a CLI (`ozpb`) and an MCP server
(`ozpb-mcp-server`). Their available policy-drafting path is:

```
record → synthesize → reference_suite (layer 1) → generate → verify
```

`ozpb dry-run` runs the native worker's account-Wasm layer and, with a capture request, its
captured-target layer, signing only offline-domain requests with the spec delegate's key from a
0600 file; its live layer stays unavailable, so its report is never complete. It is a CLI
command only: the MCP server holds no keys and has no signing dry run. The live authority
check (`ozpb check-policy-call-surface`, `check_policy_call_surface`) and the install intent
built on it (`ozpb prepare-install-intent`, `prepare_install_intent`) are both; they are
advisory wherever they run. `ozpb capture-target` and `capture_target` read, through the same
kind of operator-configured source, the target state of one unsigned native Stellar Asset
Contract transfer for the native worker's
[captured-target layer](CAPTURED-TARGET-EXECUTION.md#producing-a-capture); they do not run that
layer, and `prepare_dry_run` still reports it unavailable. `reference_suite` is layer-1 evidence only;
`verify` reproduces source and Wasm but does not perform live preflight. `evaluate_spec` is
an optional pure check of a candidate invocation and returns `indeterminate` when a
reviewed policy would make a whole-composition verdict unsafe.

`preflight_transaction` is a separate network read for an exact transaction envelope
carrying the intended authorization entries. It uses RPC authorization enforcement and
reports the endpoint's simulation outcome at its reported ledger: `simulated_success`,
`simulation_failed`, `restoration_required`, or `declared_resources_insufficient`. The last
means the invocation succeeded in simulation but the envelope does not declare what it used:
`insufficient_declared_resources` names each declared footprint list that is not exactly the
simulated one (a key missing, extra, or repeated) and each disk-read or write limit below the
simulated use, never the keys. The endpoint reports instructions and the resource fee only as
padded estimates, so `below_endpoint_estimate` lists a declared value below either estimate as
advice beside `simulated_success` or `declared_resources_insufficient`; it never changes the
outcome, and `simulated_success` does not establish that the declared instructions and fee
suffice. It does not establish that the generated policy is installed or selected, and it
never commits writes.

That does not make preflight consequence-free. Enforcement-mode simulation of a smart account
needs signed `Address`-credential authorization entries, and a Soroban authorization signature
covers the network ID, the entry's nonce, its `signatureExpirationLedger` and the authorized
invocation, not the transaction or its source account. Anyone who holds a signed entry can put
it in a transaction of their own and submit it until it expires, and simulation does not
consume the nonce. The envelope reaches the RPC endpoint and, through MCP, the agent's
transcript. Prefer testnet, or sign with a short `signatureExpirationLedger`, and run
preflight from the CLI or a local stdio server against an RPC endpoint you trust. A hosted
(`--http`) server refuses any envelope carrying transaction signatures or signed authorization
entries with `E_UNSUPPORTED_ENVELOPE`, because the hosted service must never hold material
that can authorize on a user's account (architecture §6.2, §6.5).

An envelope refused before any request carries an input
code in both shells: `E_RESOURCE_LIMIT` over the XDR size bound, `E_ENVELOPE_PARSE` when it
is not one unbroken base64 string of transaction XDR, and `E_UNSUPPORTED_ENVELOPE` for a shape
simulation does not take (not exactly one `InvokeHostFunction` operation, or a memo). `E_RPC`
is left for the endpoint and its transport. Whitespace anywhere in the envelope is refused
rather than skipped; the CLI removes only the envelope file's final line ending. The endpoint
receives the canonical base64 of the bytes `envelope_xdr_sha256` hashes.

Every reported outcome is a completed observation, not a command failure: the CLI exits 0 for
`simulation_failed`, `restoration_required` and `declared_resources_insufficient` as well as
for `simulated_success`, and the MCP tool returns them as results. A script must read
`outcome`; a zero exit status says only that the endpoint answered.

### CLI

```bash
cargo build -p ozpb-cli          # produces target/debug/ozpb

# 1. record a transaction (by hash, via any Stellar RPC) → RecordingBundle JSON
ozpb record --tx-hash <hash> --rpc-url https://rpc.testnet.stellar.gateway.fm \
  --network "Test SDF Network ; September 2015" > rec.json
# …or offline from a raw evidence bundle:
ozpb import --bundle bundle.json > rec.json

# 2. synthesize a minimum-permission PolicySpec (needs your decisions: who/how-long/…)
export OZPB_REGISTRY_MIN_VERSION=<persisted-anti-rollback-floor>
ozpb synthesize --bundle rec.json --selected-authorizer <C…> \
  --account account.json --signed-registry registry.signed.json \
  --registry-roots registry-roots.json \
  --decisions decisions.json --template-family policy-templates/scope@1 > syn.json

# 3. inspect layer-1 reference evidence over the constraint-derived suite.
# This is offline evidence, not the full four-layer dry run or proof of all possible calls.
# `synthesize` prints an envelope — the spec, its canonical hash and the per-constraint rationale —
# while every stage below takes a bare PolicySpec. Handing over the envelope is a parse error rather
# than something quietly ignored, because `PolicySpec` is `deny_unknown_fields` — the envelope
# types around it, `SynthesizeOutput` and `RecordOutput`, are not — so lift the spec out first:
python3 -c 'import json,sys; json.dump(json.load(sys.stdin)["spec"], sys.stdout)' < syn.json > spec.json

ozpb reference-suite --spec spec.json

# The same suite as replayable cases rather than outcomes: every case's invocation (i128 values as
# decimal strings) and evaluation context, in suite order, with the spec hash and a `suite_hash`
# over exactly that list (format `ozpb-reference-suite-cases/v1`; the hash is
# sha256("ozpb-reference-suite-cases/v1\n" + spec_hash + "\n" + compact JSON of `cases`)). The
# testnet harness replays its live-realizable denials against an installed rule from this output.
ozpb reference-suite --spec spec.json --emit-cases > cases.json

# 4. generate the locked crate, build Wasm, and emit its binding BuildManifest (never deploys)
ozpb generate --spec spec.json --rule 0 --out ./generated

# 5. reproduce the complete generated crate + Wasm + manifest.
# The crate root matters: Cargo.toml, toolchain settings, and every src/ file are checked.
# Live network preflight remains separate.
ozpb verify --spec spec.json --rule 0 --generated-dir ./generated \
  --wasm ./generated/generated_sub_transfer_r0.wasm \
  --manifest ./generated/build-manifest.json

# Optional: simulate an exact envelope with its intended authorization entries.
# Read it from a file so the base64 and signatures stay out of shell history/process arguments.
# Signed entries are live authorizations until their signatureExpirationLedger: prefer testnet
# or a short expiration, and an RPC endpoint you trust. This never submits the envelope, and
# it reports endpoint state at one ledger, not an installed-policy or Safe verdict.
# It exits 0 for every reported outcome, simulation_failed included: check `outcome`.
ozpb preflight-transaction --envelope-file envelope.xdr.base64 \
  --rpc-url https://rpc.testnet.stellar.gateway.fm \
  --network "Test SDF Network ; September 2015"

# Optional: run the account-Wasm layer through the operator's native worker and print a
# four-layer report. The delegate key is read only from a 0600 file and signs only requests for
# the run's derived offline network; the live layer is reported unavailable. Exits 0 only when
# the report's `acceptance` meets the permit/deny bar.
ozpb dry-run --request dry-run-request.json --registry-roots registry-roots.json \
  --registry-min-version 3 --rpc-sources rpc-sources.json \
  --native-worker /abs/path/ozpb-execution-runtime --delegate-key-file delegate.key \
  --account-wasm pinned-account.wasm --source-ledger ledger.json > dry-run.json

# Optional: capture the target state of one unsigned native SAC transfer for the native
# worker's captured-target layer. The request names an operator source and network and carries
# the confidential envelope: {"network_id", "rpc_source", "envelope_xdr_base64"}.
# Record-mode simulation here is acquisition only, never evidence that a policy permits the call.
ozpb capture-target --request capture-request.json --rpc-sources rpc-sources.json > capture.json

```

The install-intent design in §4.8 derives the `add_context_rule` arguments from the same grant
the authority check commits to, and never says "safe": the wallet that holds the owner key
recomputes the check and decides (Decision D7). `ozpb check-policy-call-surface` produces the
advisory authority answer; `ozpb prepare-install-intent` runs it and, only when nothing is
refused and nothing is unresolved, prints the exact arguments with that answer attached.
Assembly, signing, and submission remain wallet-owned.

### Reference-suite coverage gate

`all_agree` covers the generated policy's modeled semantics. It does not establish the
behavior of a composed reviewed policy. CI checks the subscription example's report against
an exact list of acknowledged layer-1 gaps:

```bash
python3 scripts/check-unmodeled-acknowledged.py --run \
  scripts/layer1-unmodeled-acknowledged.txt subscription=docs/examples/subscription-spec.json
```

The command runs and checks every declared `label=spec-path` pair; producer failures stop it.
It reads each input spec to require the complete rule-index set and the exact number of each
reviewed-policy kind in the evidence. Spec and acknowledgement paths both resolve from the
caller's working directory; Cargo runs in the repository workspace.
It reconciles summary fields, coverage counts, and policy gaps against the detailed evidence.
Each declared rule needs an original permit and a denial control, and every required class
needs an outcome for that rule. New gaps, stale acknowledgements, or entries naming an
undeclared spec fail. Repeated policy kinds require one acknowledgement per instance.
Permit-only classes remain visible as limitations. An acknowledgement records what layer 1
does not test; it never waives a disagreement or proves the reviewed policy's on-chain behavior.
Add examples to the same invocation so no declared example can go unchecked. The stdin and
`--known-specs` modes are lower-level inspection helpers, not a complete gate. The checker
validates local report consistency, not imported evidence authenticity.

### Build configuration (operator-side)

`generate` and `verify` compile the policy and accept the same build flags (each with an
environment fallback the MCP server reads too):

| Flag | Env | Default |
|---|---|---|
| `--build-timeout-secs` | `OZPB_BUILD_TIMEOUT_SECS` | 600 |
| `--build-cache-dir` | `OZPB_BUILD_CACHE_DIR` | a shared dir under the system temp dir |
| `--build-jobs` | `OZPB_BUILD_JOBS` | available parallelism − 1 |
| `--stellar-binary` | `OZPB_STELLAR_BINARY` | `stellar` on `PATH` |

**Point the cache dir at persistent storage.** With a cold cache every build recompiles
`soroban-sdk` and `stellar-accounts` from scratch, which is what the timeout is mostly
spent on. Two properties of a shared cache to plan for: it is **not pruned** (cargo does not
GC target directories, so distinct specs accumulate — give the volume a quota and clear it on
a schedule), and it **serializes concurrent builds** on cargo's build-directory lock, so a
hosted worker should size its concurrency to one build at a time per cache. The default path
is per-uid and is refused if it is a symlink, not a directory, owned by another user, or
group/world-accessible — a shared cache an attacker can pre-create is a route to poisoned
dependency artifacts, and `verify` reproduces through the same cache, so a poisoned build
would reproduce identically.

These are deliberately *not* request fields: a caller-chosen timeout is resource exhaustion
and a caller-chosen builder path is arbitrary execution, so they stay operator configuration
(the same reasoning as the RPC allowlist). There is likewise no flag for the
builder kind — the hermetic stub emits unattestable wasm and is test-only. An unusable
binary or cache fails with `EBuildUnavailable`, distinct from `EBuildFailed`, so an operator
fault never reads to an agent as "your spec does not compile".

`registry-roots.json` is out-of-band trust configuration, not request data:
`{"threshold":2,"keys":{"ops-a":"<32-byte-hex>","ops-b":"<32-byte-hex>"}}`.
It may also contain a durable `checkpoint` (`version`, `log_index`, `root`) to reject
same-version equivocation after restart. The MCP server receives the same JSON through
`OZPB_REGISTRY_ROOTS_JSON`, paired with `OZPB_REGISTRY_MIN_VERSION`.

`OZPB_REGISTRY_SNAPSHOT_JSON` carries the signed snapshot to use when a request omits one. It
sits beside the roots rather than among them because it is data, not trust: a snapshot is
verified against those roots whether it arrives configured or in the request, so what this
variable decides is *which* snapshot is the default — never whether it is checked. A request
may still supply a newer one, and never its own root. Set all three together for a deployment
whose callers should not have to carry a signed document around;
`scripts/mcp-server-dev.sh` does exactly that with the committed development pair.

`docs/examples/` holds runnable inputs, some of which feed a later walkthrough rather than
the Tranche-1 demo. `bash scripts/verify-phase1.sh` is the strict first-milestone release
gate; `bash scripts/verify-phase1.sh --offline` is the explicitly reduced local gate.
`bash scripts/verify-phase2.sh` extends the release gate with focused Tranche 2 evidence checks
and a Soroswap Wasm build; `--offline` explicitly omits the release-only checks. For a shorter
run, `bash scripts/check-phase2-evidence.sh` checks the named reference, MCP, and partial layer-2
cases. None of these commands establishes full Tranche 2 acceptance: the
[Tranche 2 guide](TRANCHE-2-VERIFICATION.md) lists the separate live evidence requirements.

### Demonstrating the Tranche-1 outcome

```bash
bash scripts/demo-tranche1.sh          # ~2 min, live testnet, throwaway identities
OZPB_ACCOUNT=C... bash scripts/demo-tranche1.sh   # reuse an existing OZ smart account
```

Deploys OpenZeppelin's smart-account example, records what authorization a transfer from it
would require, synthesizes a minimum-permission spec, generates the policy crate, and has the
real `stellar contract build` accept it — the contractual outcome — then checks that source and
wasm are byte-identical across two runs. The script derives its policy expiry from the latest
testnet ledger and also exercises a deliberately incompatible account-hash input, which must be
refused by registry resolution. Account recognition is generation compatibility, not a claim
that installation on the live account is safe.

Three things it makes explicit, because each one broke a demo attempt:

- It records a **simulated** transfer. `simulateTransaction` with `authMode: record` returns the
  authorizations an invocation *would* need, so recording requires no signature and no custody.
  The executed path is the same code with `record --tx-hash`, and additionally needs the smart
  account's signer.
- **A transaction hash cannot be replayed later** — RPC retention drops it — so the script
  creates fresh state every run rather than referencing a hash from a document.
- **The authorizer must be a smart account.** A policy scopes a smart account's context rule, so
  synthesis fails closed on an ordinary `G` account. The script also asserts the deployed
  account's on-chain code hash equals the pinned one, which doubles as a live check of the pin.

### Verifying the pinned upstream trust anchors

`ozpb_domain::pinned_upstream` holds the wasm hashes of four OpenZeppelin contracts — the
spending-limit policy, the smart account, and the ed25519 and WebAuthn (passkey) verifiers. The
first two are Phase 1 trust anchors. The verifiers are recognized by the authority check as
owner verifiers only through the code observed at a signer's verifier address at the read
ledger; the script also checks that both export only the reviewed verifier methods and import
no ledger, contract-call or ledger-context host functions. A *spec* still cannot name an
external-verifier signer for the new rule (`E_SPEC_EXTERNAL_SIGNER_UNSUPPORTED`).

```bash
bash scripts/verify-pinned-upstream.sh    # clones the pinned tag, rebuilds, compares
```

Deliberately not part of `verify-phase1/2`: it clones and does a cold build of upstream's
workspace, which takes minutes. Run it when the pins change, when bumping the upstream tag, or
when reviewing the trust anchors.

Three things to know. **The hash depends on the compiler** — upstream's `rust-toolchain.toml`
says `channel = "stable"`, which floats, so the script forces this repository's pinned rustc;
building with another one legitimately yields a different hash from identical source.
**The account hash also depends on the build host** — it reproduces byte-for-byte only on Apple
Silicon (`aarch64-apple-darwin`). Elsewhere the account Wasm differs only in function order,
because Cargo hashes the build host into symbol names that rustc orders functions by
([rust-lang/cargo#8140](https://github.com/rust-lang/cargo/issues/8140), fix pending in
[rust-lang/cargo#17522](https://github.com/rust-lang/cargo/pull/17522)); the other two pins
reproduce on every host tested.
**Upstream publishes no wasm** — releases carry no assets and no deployed instance is blessed,
so these are our reproducible builds of their source, and the registry entries say exactly
that rather than claiming an upstream-signed artifact.

### MCP server

`docs/MCP-WALKTHROUGH.md` covers the server, the `policy-builder` Claude skill and the
human-invoked `policy-builder-install` skill that hands a confirmed grant off. Do not
pre-approve `prepare_install_intent`, `assemble_install_transaction` or `capture_target` in
Claude Code permissions; each call should prompt. The repository's `.mcp.json` exposes the
server for local tool use; `claude --plugin-dir .` loads the packaged skill and its server
entry. The wrapper refreshes a plugin binary from source in Claude's persistent plugin data
directory and launches a stdio server per session. The walkthrough also covers tool inputs and
raw JSON-RPC.

```bash
cargo build -r -p ozpb-mcp-server
# stdio (Claude Code, default) — see .mcp.json or .claude-plugin/plugin.json
target/release/ozpb-mcp-server
# streamable HTTP (self-hostable endpoint)
target/release/ozpb-mcp-server --http 127.0.0.1:8080   # → /v1/mcp
```

The tools, each with a JSON output schema generated from `crates/api-types`:

- **Tranche 1** — `record_transaction`, `record_simulation`, `import_recording`,
  `synthesize_policy`, `evaluate_spec`, `generate_code`.
- **Available reference and verification tools** — `reference_suite` (layer 1 only) and
  `verify` (artifact reproduction with separately labeled limits).
- **Exact-envelope network evidence** — `preflight_transaction` reports one
  authorization-enforcing RPC simulation; it does not identify an installed policy.
- **Account authority (advisory)** — `check_policy_call_surface` reads, through an
  operator-configured RPC source, who can change the account or reset the policies being
  installed for one spec rule, with refusals, evidence gaps, exclusions and an
  `authority_commitment`. It never says "safe": the wallet holding the owner key recomputes it
  and decides (architecture §4.8, Decision D7).
- **Install intent (advisory)** — `prepare_install_intent` runs the authority check itself
  (same request) and, only when nothing is refused and nothing is unresolved, returns the
  exact `add_context_rule` arguments derived from the grant the commitment covers, with the
  answer attached. Otherwise it is an error carrying every finding. It never assembles, signs
  or submits.
- **Unsigned install assembly (advisory)** — `assemble_install_transaction` reruns that check
  and returns bounded unsigned XDR with current sequence and fees. It never signs or
  submits; the wallet must validate it, recheck authority and enforce-simulate before signing
  ([INSTALL-ASSEMBLY.md](INSTALL-ASSEMBLY.md)).
- **Installed-rule prediction (advisory)** — `check_against_policy` predicts permit, deny or
  `unsupported` for one call against one explicitly selected installed rule at one reported
  ledger. It is recognition-scoped and does not verify signatures
  ([LIVE-POLICY-CHECK.md](LIVE-POLICY-CHECK.md)).
- **Dry-run preparation** — `prepare_dry_run` recognizes the candidate, reproduces its
  artifact and derives the selected-rule reference suite. It reports the account-Wasm,
  captured-target and live layers as unavailable
  ([DRY-RUN-PREPARATION.md](DRY-RUN-PREPARATION.md)).
- **Target capture (read-only)** — `capture_target` reads, through an operator-configured
  RPC source, the `rpc_reported` target state of one unsigned native Stellar Asset Contract
  transfer: the capture the native worker's captured-target layer reads
  ([CAPTURED-TARGET-EXECUTION.md](CAPTURED-TARGET-EXECUTION.md#producing-a-capture)). It does
  not run that layer. A failed simulation of the call is `E_TARGET_REFUSED` and archived call
  state (a preamble, restored entries, or an archived or expiring footprint entry)
  `E_TARGET_ARCHIVED`; every other endpoint answer or fault is `E_RPC`.
  The envelope is confidential input that no result or error echoes, but over MCP it passes
  through the conversation, and the capture repeats its call; prefer the CLI or a local stdio
  server.
- **CLI only, not exposed** — the signing dry run. `ozpb dry-run` runs the account-Wasm and
  supported captured-target layers with an offline-domain delegate key; this server holds no
  keys, so it serves `prepare_dry_run` and `capture_target` instead. A complete four-layer run
  needs the wallet's live layer.

This list separates tools the server exposes from operations still under development. Errors
carry stable machine-readable codes (`E_*`). The server never deploys,
signs, or holds keys.

`check_policy_call_surface`, `prepare_install_intent`, `assemble_install_transaction`,
`check_against_policy` and `capture_target` read through a source the operator names in
`OZPB_RPC_SOURCES_JSON` — `{"testnet": {"rpc_url": "https://…",
"network_passphrase": "Test SDF Network ; September 2015"}}` — and the request names only the
source; it never carries a URL. `prepare_dry_run` takes the same request and validates its
source, but reads nothing through it. `record_transaction` and `record_simulation` read through
the same map by default: the source named in `rpc_source`, or the only configured one when the
request names none. They still accept `rpc_url` with its `network_passphrase` instead, subject
to `OZPB_RPC_ALLOWLIST` on a hosted server. `verify` and `prepare_dry_run` also accept
`generated_artifact`, the `build_manifest_hash` of an artifact `generate_code` built earlier in
the same MCP session, in place of the claimed files, Wasm and manifest; the server substitutes
them before checking, keeps the last eight per session, and the CLI refuses a reference.
Eight artifacts is the count limit, not a fixed one-megabyte memory limit: size depends on the
generated source, Wasm and metadata. This in-memory store is not shared across sessions or
backend instances and is lost when the session ends or the process restarts. Keep a session
on the same backend; if its reference is unavailable, generate again or send the artifact bytes.
For a [paired local wallet](AGENT-WALLET-HANDOFF.md), `connect_wallet` exchanges the one-time
wallet code and `send_wallet_proposal` stages an unverified draft after chat confirmation.
Their failures use five `E_WALLET_*` codes, one per next step; see
[When the wallet refuses](AGENT-WALLET-HANDOFF.md#when-the-wallet-refuses).
The stdio launcher configures a literal-loopback bridge; hosted HTTP MCP disables it. This
credential grants no wallet signing or installation authority.

`scripts/mcp-server-dev.sh` configures exactly one source,
`testnet` (SDF's public testnet RPC unless `OZPB_DEV_TESTNET_RPC_URL` names another `https://`
endpoint), and replaces any map already in the environment; it never configures another
network.
The source must be for the request's network, and a hosted server also requires its URL on
`OZPB_RPC_ALLOWLIST`. For every one of them except `capture_target`, which needs no registry
trust, the pinned registry trust (`OZPB_REGISTRY_ROOTS_JSON`, `OZPB_REGISTRY_MIN_VERSION`)
bounds the read and recognizes the code. The CLI takes the same
map from `--rpc-sources` (or `OZPB_RPC_SOURCES_FILE`).

`--http` mode binds **loopback only** unless `OZPB_HTTP_ALLOWED_HOSTS` names the public hosts
an authenticated, TLS-terminating ingress forwards (a comma-separated `host[:port]` list, no
wildcards) that is not loopback. Only then does it accept a routable address, and it then answers
only those hosts; any other `Host`, loopback names included, is refused (`403`), as is any request
with an `Origin` header, in either mode. It refuses to start unless `OZPB_HTTP_BEARER_TOKEN`
(≥32 bytes) and `OZPB_RPC_ALLOWLIST` are set. The allowlist is a comma-separated list of the
full `https://` URLs the record tools may reach: each entry is parsed as a URL, so a bare
hostname is refused at startup rather than at first use. Every request to `/v1/mcp` then
passes three checks in order: the bearer token (`401`), a request quota (`429`) and a body
bound (`413`). A request without the token spends no quota and its body is never read. Builds
are bounded separately, by the build runner itself, because rmcp answers a tool call with a
stream before the tool runs and a build outlives a client that disconnects:

| Env | Default | What it bounds |
|---|---|---|
| `OZPB_HTTP_REQUESTS_PER_MINUTE` | 60 | HTTP requests admitted per fixed one-minute window, across all clients. A tool call is one request; opening a session takes several. A fixed window can admit up to twice the limit across a window boundary. |
| `OZPB_HTTP_MAX_BODY_BYTES` | 1048576 | Request body size, at most 25165824. Raise it to serve `verify` of a large artifact sent as bytes (not needed when `verify` names an artifact of the same session by `generated_artifact`) or `synthesize_policy` over large recordings: a 2 MiB Wasm alone is about 2.7 MiB of base64, and each recording may carry 1 MiB of base64 evidence. |
| `OZPB_HTTP_TOOL_REQUESTS_PER_MINUTE` | 60 | Calls admitted per fixed one-minute window to each tool, across all sessions and after the request quota. Tools that build or read an RPC endpoint (`generate_code`, `verify`, `prepare_dry_run`, `record_transaction`, `record_simulation`, `preflight_transaction`, `check_policy_call_surface`, `prepare_install_intent`, `assemble_install_transaction`, `check_against_policy`, `capture_target`, `connect_wallet`, `send_wallet_proposal`) default to the smaller of this and 4. A refused call answers `E_RESOURCE_LIMIT`; a call that reached its tool is counted even if it then fails. |
| `OZPB_HTTP_TOOL_LIMITS_JSON` | unset | A JSON object from tool name to its own positive per-minute limit, overriding the default above, e.g. `{"generate_code":2,"reference_suite":120}`. Empty means no overrides. An unknown tool name, a zero, or anything but positive integers stops startup. |
| `OZPB_HTTP_MAX_CONCURRENCY` | 1 | Policy builds running at once across all sessions, including `generate_code`, `verify`, and binding rebuilds during authority checks, install-intent planning, unsigned install assembly, installed-rule checks and dry-run preparation. One more is refused at once with `E_BUILD_BUSY`, which is retryable by design. A build holds its slot until it ends. Multiplied by `OZPB_BUILD_JOBS` it must not exceed the machine's available parallelism. With the one shared build cache, cargo serializes compiles, so a second slot queues a build behind the first on its own timeout rather than running it alongside. |

Zero or a malformed value stops startup. Authority checks, install-intent planning, unsigned
install assembly, installed-rule checks, dry-run preparation and target capture, every tool
that names an operator-configured source, also share a separate one-operation limit across
all sessions, held until their blocking work ends. That limit is
independent of build capacity; their binding rebuilds acquire the same build slots as other
tools. The RPC reads that take a caller-named endpoint (`record_*`, `preflight_transaction`)
and pure tools use neither limit and remain bounded by the quota
and their own size and time limits. Terminate TLS and add per-client authorization and per-client limits
at a reverse proxy in front of it. The [disposable build-worker mode](ISOLATED-BUILDS.md)
supplies OS-level compile isolation and a no-secrets worker role.

A client's `notifications/cancelled` for a tool call, or the end of its MCP session, stops the
work that call started; as MCP specifies, the cancelled call gets no response. A local build's whole process group
is killed and its slot released. A disposable worker's launcher is asked to stop (SIGTERM); its
slot is released only when the launcher confirms the job's removal, and otherwise retained as
after a launcher failure. Network reads make no further RPC call; a call already in flight ends
on its own transport timeout. Work that passes its own deadline is stopped the same way, and the
slots it holds are released when that stopped work ends.

The [self-hosting package](SELF-HOSTING.md) supplies a pinned container build, TLS proxy,
operator configuration and disposable endpoint/offline-build checks for one operator with
trusted clients. Its service resource limits do not establish the separate worker boundary.

## 2. How the synthesizer decides scope

`crates/synthesizer` is a pure function `RecordingBundle(s) + UserDecisions → PolicySpec`.
Its rules (all fail-closed — ambiguity is an error, never a guess):

- **Exact-by-default.** Every observed argument becomes a *deep exact-equality* constraint
  on the complete tuple (exact arg count; nested `ScVal` validated). This is the true
  minimum permission.
- **`SELF` resolution.** An observed address equal to the selected authorizer becomes the
  `SELF` marker (resolved at runtime), so generated wasm is account-independent.
- **Widening is never heuristic.** A bound (`<=`, `>=`) or a wildcard (`any_value`) enters
  a spec *only* through an explicit `Widening` decision carrying intent + blast radius, or
  an adapter (`crates/synthesizer/src/adapters.rs`) bound to a verified target code hash.
  The XDR type alone never implies a direction (lowering a `min_output` makes a swap
  *less* safe).
- **Signers are a required decision.** The delegate signer set + predicate can't be
  inferred from a recording; named-identity predicates are strict (a later `add_signer`
  can't silently broaden the grant).
- **Lifetime and call cap are required decisions.** `valid_until_ledger`, or
  `no_expiry_acknowledged: true`; `max_calls`, or `unlimited_calls_acknowledged: true` (absent
  reads as `false`). Neither answer is an `E_NEEDS_DECISION` finding; both answers to one
  question (a cap and the unlimited acknowledgement, or an expiry ledger and the no-expiry
  acknowledgement) are contradictory, an `E_INVALID_DECISION` finding. A refusal lists every
  finding in `details` under the first one's code. Before v0.2.0 a null `max_calls` alone produced
  an uncapped grant and a contradictory lifetime kept the ledger; those are the breaking changes
  in the [release notes](release-notes/v0.2.0.md).
- **Compose-first.** Where an audited OZ prebuilt (`spending_limit`, thresholds) expresses
  the constraint, it is configured rather than generated; the generated policy carries only
  what no prebuilt expresses (function/argument scope, call count, recipient/path).
- **Sequences → permission bundles, not workflows.** Multiple recorded contracts yield
  independent rules (one per contract); ordering/atomicity are not enforced and the spec
  says so.

The `PolicySpec` is validated into a `ValidatedSpec` typestate (`crates/policy-spec`); only
that typestate reaches codegen and the evaluator.

## 3. Extending the toolkit with a new policy primitive

Say you want a new constraint — e.g. a `MemoEquals` check. Touch these, in order, and let
the tests guide you (TDD: add the failing test first):

1. **`crates/policy-spec`** — add the `Constraint` variant. Update `is_widening()` if it's a
   relaxation, and add validation if it has provenance rules. Add it to a fixture.
2. **`crates/evaluator`** — handle the variant in `constraint_satisfied` (the independent
   reference semantics). This is the executable spec.
3. **`crates/codegen`** — emit the check in `emit_lib`'s per-arg match, embedding values as
   validated literals (never interpolated into identifiers); add pre-emission validation in
   `generate`. Regenerate both committed examples by running each fixture test explicitly:

   ```sh
   UPDATE_GOLDEN=1 cargo test -p ozpb-codegen --lib tests::golden_crate_matches_committed_output -- --exact
   UPDATE_GOLDEN=1 cargo test -p ozpb-codegen --lib tests::soroswap_crate_matches_committed_output -- --exact
   ```
4. **`crates/harness`** (Tranche 2) — add mutation cases for it in `build_suite` so the deny
   suite covers the new boundary; add its `concrete_for` arm.
5. **`crates/synthesizer`** — decide how it enters a spec (observed-exact by default, or via
   a `Widening`/adapter). Never let it in heuristically.
6. **`contracts/`** — the differential suite drives the generated transfer policy in the
   Soroban environment. The committed Soroswap policy is a second generated example; its
   complete file set must match regeneration, and it builds as a standalone crate. Add
   explicit evaluator/contract cases for new constraints. End-to-end account
   integration and policy-aware live preflight remain separate work.

Adding a new *template family* or reviewed prebuilt hash also means a
`crates/registry` capability entry (keyed by reviewed wasm hash) so validation can prove
what it enforces — an address or claimed kind is never sufficient.

### Invariants CI enforces (don't break these)

- `scripts/check-dep-rules.sh`: the evaluator/harness never depend on codegen (differential
  independence); cores stay transport/async-free. The harness half of that rule governs a
  Tranche-2 crate.
- Every generated crate builds standalone (`[profile.release]` with `overflow-checks`) and
  passes the same `rustfmt`/`clippy -D warnings` as handwritten code.
- Determinism: same `ValidatedSpec` ⇒ byte-identical source/wasm.
- `scripts/check-publication-allowlist.sh`: no confidential material in the public tree.
