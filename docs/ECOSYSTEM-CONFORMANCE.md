# Stellar ecosystem conformance

**Why this exists.** The project was written first as a correct system and second as a system
built the way Stellar smart contracts are built. This document records the platform's principles with links to
their sources, our current state against each, a verdict, and an action. It is what a design
decision is checked against, and what answers the question of whether we are reinventing
something the ecosystem already supplies.

Compiled 13 August 2026; last reconciled 24 August 2026 against the OpenZeppelin code-quality
conformance pass, which added §15 and closed §6's open decision. Verified against `stellar-cli`
27.0.0, `stellar-xdr` 26.0.1/27.0.0, `soroban-sdk` 26.1.0, `stellar-accounts` 0.7.2,
`OpenZeppelin/stellar-contracts` at tag v0.7.2 and at `main` where §15 cites their tooling, and
the repository as of that pass. Sections 9–14 record the subsystems that pass hardened; the
disallowed-type gate that was pending at first compilation has since landed (§4).

**Verdict legend:** ✅ conforms · 🗓 later-milestone scope · ⚠️ diverges · ❌ gap · ℹ️ open decision ·
— reference, not an assessment

The distinction between the first two and the rest is the one worth reading carefully. 🗓 is
not a softer ⚠️: it marks work this project has scoped and sequenced for a
later milestone, so the section states a boundary of *this* milestone rather than a departure
from anything the ecosystem asks. It is a statement about our own sequencing and not a delivery
commitment — where something *is* a named tranche deliverable the section says so in its own
words. ⚠️ appears once, on §15, where nine departures from OpenZeppelin's house rules are
deliberate and each is argued in place; ❌ appears nowhere, and stays in the legend because the
category exists and a later reading may need it.

## Summary

| § | Subject | Verdict | In one line |
|---|---|---|---|
| 1 | Serialization and hashing | ✅ | Canonical form is XDR throughout, with a versioned preimage an outside implementation can reproduce from `docs/CANONICAL-HASHING.md`. |
| 2 | Artifact identity and verification | ℹ️ | Artifacts are readable by standard tooling but carry no provenance of ours. Both verification SEPs are Draft and unimplemented by released tooling; one question in them is genuinely open for generated contracts. Separately, our reproducibility holds across comparable hosts, not across any host. |
| 3 | State archival and TTL | ✅ | Bounded, threshold-conditional extension that never reaches past the rule's own window; restoration semantics verified against the environment rather than assumed. |
| 4 | Value system and numeric types | ✅ | No type without a faithful `ScVal` form, and the ban is enforced by lint rather than declared. |
| 5 | Authorization model | ✅ / 🗓 | No authorization primitive of our own, and OpenZeppelin's `spending_limit` is used by hash. External-verifier signers are refused outright rather than half-supported. |
| 6 | Errors and observability | ✅ / ℹ️ | Stable machine-readable error codes throughout; whether to emit an event on a successful `enforce` is undecided. |
| 7 | External security tooling | ℹ️ | Scout and the Veridise checklist are customary, not required. We check the generator thoroughly; running them over what it generates is a decision, not a shortfall. |
| 8 | Upgradeability and immutability | ✅ | No setters, no upgrade entry point. For an artifact whose value is "the reader sees exactly what executes", immutability is the requirement. |
| 9 | Evidence provenance and RPC binding | ✅ | Requested and returned transaction identity is bound and re-derived under the verified network passphrase. It remains RPC evidence, not a ledger-inclusion proof. |
| 10 | Capability registry governance | ✅ / 🗓 | The mechanism conforms; the committed root is a deterministic development key, suitable for reproducible examples and not for production governance. |
| 11 | Evaluator and differential evidence | ✅ / 🗓 | An independent evaluator agrees with the real compiled contract on verdict and denial reason. It does not exercise a full smart account's `__check_auth` — later-milestone evidence. |
| 12 | MCP surface and machine-readable failures | ✅ | Closed request schemas, generated JSON schemas, stable `E_*` codes, structured tool errors. |
| 13 | Build containment | 🗓 | The local builder bounds environment, inputs, outputs and time, and on a hosted server the number of concurrent builds. It is not a multi-tenant sandbox and this milestone does not offer it as one. |
| 14 | Defaults and limits | — | Every default and bound, with the reasoning for each value. |
| 15 | Contract code conventions | ✅ / ⚠️ | Measured against OpenZeppelin's own house rules rather than the platform: the emitted crate now satisfies their layout, formatting, imports, docs, storage-key and event conventions. Nine departures are deliberate and argued, and three upstream defects were found while doing it. |

Read the section for the reasoning; nothing above is a claim the section does not support.

Every claim here is meant to be checkable against the source it names — a SEP, a documentation
page, a line of this repository, or a line of the platform's own implementation. Where something
is unresolved, the section says what would resolve it.

---

## 1. Serialization and hashing ✅

**Platform principle.** Stellar's canonical format is **XDR**: field order is fixed by the
schema, integers are fixed-width, padding is defined. Rust structures map onto values by a
documented convention: a named struct → `ScVal::Map` with `Symbol` keys, a tuple → `ScVal::Vec`.

**An important qualification, without which the statement would be wrong.** XDR gives one
encoding per *particular value*, but it does not remove canonicalization altogether: the value
is still ours to choose. `ScMap` is a `VecM<ScMapEntry>`, so entry order is part of the value,
and semantically equivalent maps in different orders produce **different bytes**. The host type
`soroban_sdk::Map` is documented as ordered by key and normalizes the order itself.

**Outside a contract the ordering rule is also supplied, and we would use it rather than
restate it.** `stellar_xdr::ScMap`'s bare constructor keeps whatever order it is handed, but the
crate ships the sorting constructors `ScMap::sorted_from_entries`, `sorted_from_pairs` and
`sorted_from` (`stellar-xdr-27.0.0/src/scmap.rs:8-39`), which sort by key and then validate; and
`impl Validate for ScMap` (`src/scval_validations.rs:58-75`) rejects any map that is not strictly
ascending by key, which also rejects duplicate keys. So key ordering is an ecosystem rule with an
ecosystem enforcer, not something we need to define. What remains genuinely ours to fix is the
mapping of each type onto `ScVal` and the representation of `Option` and of enumerations.
Checked against `stellar-xdr` 27.0.0 and `soroban-sdk` 26.1.0.

**The template for hashing a structure** is `HashIdPreimage`: an XDR union whose discriminant
(`EnvelopeType`: `OpId = 6`, `ContractId = 8`, `SorobanAuthorization = 9`) provides domain
separation, followed by SHA-256 over the XDR bytes.

**What is to be adopted is the template, not the union itself.** Reusing `HashIdPreimage` or the
values of the system `EnvelopeType` for application hashes is not an option: it is exactly the
domain collision that separation prevents — our hash would become indistinguishable from a
protocol one. What is needed is a **versioned XDR envelope of our own** with our own domain
identifiers.

**What we have.** Hash identity is canonical XDR, version 2 (`CANONICALIZATION_VERSION = 2`):
every artifact type carries its own application domain identifier and schema version in a
versioned preimage of our own; maps are built through `ScMap::sorted_from_entries`, so the
ordering rule and its validator come from `stellar-xdr` rather than from a rule of ours;
integer widths and the `Option`/enumeration encodings are fixed explicitly; and SHA-256 is
applied to the resulting bounded XDR bytes (`canonical_hash`, `crates/domain/src/canonical.rs:170`).
The normative mapping and its fixtures are `docs/CANONICAL-HASHING.md`, so an external
implementation reproduces a hash from the specification instead of mirroring Rust declaration
order. The signer set — previously the sharpest divergence, a hand-written
`"external:" + strkey + ":" + hex` string encoding — now hashes the `ScVal` representation the
account itself stores (`SignerSpec::to_stored_scval`, `crates/policy-spec/src/lib.rs:219`; the
sort over encodings in `signer_set_hash`, `:274`, sorted at `:279`). Call arguments inside the generated contract
compare as XDR, as they always did (`v{i}.to_xdr(e)`, emitted by `emit_lib`'s `EqScval` arm,
`crates/codegen/src/lib.rs:1614`).

Since the hardening pass the preimages are also **bounded before hashing**: encoded evidence is
capped below the 4 MiB canonical-hash preimage ceiling (per-value and total caps in §14), so a
recording the recorder accepts cannot fail only when it is hashed.

**Verdict.** Conforms. The earlier "diverges" — three inconsistent mechanisms: JSON bytes in
Rust declaration order, the hand-written signer encoding, and XDR only inside the contract —
was resolved by unifying on XDR, taken together with the schema-breaking rename in §3 so the
format broke once rather than twice.

**Honestly about the status of this requirement.** The platform does **not** oblige
off-chain artifacts to be XDR; a JSON artifact would not have been a violation. The move was a strong
decision taken for interoperability and to keep the road to on-chain verification open, not a
conformance item we were breaching. The earlier "diverges" verdict referred to the internal
inconsistency of the three schemes and to the interoperability we chose to aim for, not to an
obligation imposed by the platform.

**Why not RFC 8785 (JCS).** Checked: JCS canonicalizes numbers through a double, so it loses
precision above 2⁵³ — the author of the maintained crate recommends outright that such numbers
be stored as strings. Our `i128` values are already strings, so this is not a blocker, but JSON
is not the ecosystem's format, implementations of JCS diverge from one another in exactly the
place that matters — `serde_jcs` carries a known open deviation in number encoding, and was
dormant from 2020 until it shipped 0.2.0 in March 2026; it is neither yanked nor deprecated, and
the "abandoned" characterisation circulating in a competing crate's README is not accurate — and
a Stellar contract cannot parse JSON at all, which closes the road to on-chain verification.

---

## 2. Artifact identity and its verification ℹ️ (verification SEPs are Draft)

**What the platform has and ships.** The wasm section `contractmetav0` with serialized
`SCMetaEntry` — the standardized way for an artifact to describe itself, specified by
**SEP-46 — Contract Meta** (status Active). It is written by the `contractmeta!` macro from
`soroban-sdk` or by the flag `stellar contract build --meta KEY=VALUE`. This is standard,
released functionality.

Some of the keys the toolchain writes **itself**. Checked on our own artifact:

```
$ stellar contract info meta --wasm <our wasm>
 • rsver: 1.91.1                                                    (Rust version)
 • rssdkver: 28.0.0#48d506712f964094d14176e2f0b02afcd1054567        (SDK + commit)
 • rssdk_spec_shaking: 2
 • cliver: 27.0.0#5a7c5fe76530bf4248477ac812fc757146b98cc4          (CLI + commit)
```

**Verification on top of that metadata: two Draft SEPs, and no released tooling.** Two
complementary approaches are specified.

**SEP-58 — Contract Build Reproducibility for Verification** (status **Draft**, version 0.6.0,
updated 2026-07-15) defines the vocabulary for rebuild-based verification. The vocabulary is
storage-independent: these are fields, not `contractmetav0` keys, and SEP-46's section is one of
the three venues SEP-58 allows for carrying them.

| Field | Meaning |
|---|---|
| `bldimg` | the container image the build ran in, **pinned by digest**, with an explicit registry host and a reference to a single-architecture manifest |
| `bldarg` | one shell-style argument injected ahead of the flags; repeatable, **order significant**; defaults to `contract` then `build` when absent |
| `bldopt` | one shell-style flag passed verbatim; repeatable, order not significant |
| `source_sha256` | **required**: the SHA-256 of the source archive's bytes |
| `source_uri` | optional: a URI the archive can be downloaded from |

The reasoning behind `bldimg` is the part worth carrying over: a registry tag is mutable and a
content digest is not, and the image bundles the Rust toolchain along with every other
build-time dependency — so pinning the image by digest transitively pins the toolchain, and one
field captures the whole build-time stack.

**SEP-55 — Contract Build Verification** (status **Draft**) takes the attestation route
instead: the build CI signs an attestation and a verifier checks that attestation rather than
rebuilding. SEP-58 states that the two are complementary and can coexist on the same contract.

Maturity has to be stated exactly, because it is easy to overstate in either direction. Both
SEPs are Draft, and **no released `stellar-cli` implements SEP-58 support**. The command
`stellar contract build` carries no subcommands at any tag from v20.0.0 through the current
release v28.0.0 (2026-08-26), so `stellar contract build verify` does not exist — that spelling comes
from `stellar/stellar-cli` PR #2525, which was closed without merging, and must not be written
down as if it were shipped. Neither of the two PRs that would add the workflow has landed, and
they did not fail the same way: #2585, adding a `--verifiable` flag to `stellar contract build`,
is open; #2586, adding `stellar contract verify` as a **sibling** of `build` rather than a
subcommand of it, was closed unmerged on 2026-08-27. Implementations are in flight as well — the public repository
`stellar-experimental/contract-verifications` **calls itself an experiment** — while explorers
already surface a status of their own: Stellar Lab shows a "Build Verified" badge, citing
SEP-55, and StellarExpert's page is headed "Contract Code Validation", carrying a `Source code:`
field with a `verified`/`unverified` enum in its API. So: a specified direction with a named
vocabulary to stay compatible with, not a finalized standard we are in breach of.

**What we have.** `contractmeta!` is absent from the generator's template entirely, so a
generated artifact carries no meta we wrote — no reference to the spec it came from — and we
publish the SEP-58 fields nowhere at all, in that section or in any other venue the SEP allows:
no `bldimg`, `bldarg`, `bldopt`, `source_sha256` or `source_uri`. What stands in its place is
`BuildManifest`, an out-of-band record whose `ToolchainIdentity.rustc_version` restates
`rsver`, `stellar_cli_version` restates `cliver`, and `soroban_sdk_version` restates
`rssdkver` — and the platform's variants are more precise than ours, since they include commits.
In shape it is a **parallel invention of SEP-55**: an assertion by the builder about how the
artifact was produced. The difference is that SEP-55's attestation is signed by the CI that
performed the build and checkable against it, whereas `BuildManifest` is checkable only with our
CLI — which the build runner already says out loud, stamping every real build
`builder: BUILDER_LOCAL`, whose value is `local-unattested` (stamped in `build_local`,
`crates/build-runner/src/lib.rs:847`), with the reason in that function's doc comment (`:777-780`):
"trust requires local reproduction or a separately trusted build attestation".

Those three restatements are no longer taken on the builder's word, which is the one thing about
them that was cheap to fix. `manifest_for` reads the built wasm's own `contractmetav0` and refuses
the build when it contradicts the claim, naming the manifest field, the metadata key and both
values (`reconcile_declared_toolchain`, same file). It compares the version for all three, and for
`cliver` the git revision as well — that half is precisely what the platform's spelling has and
ours does not, and a CLI built from a fork or a dirty tree reports the same version with a
different revision and produces a different wasm. Absent metadata is a refusal too: a claim with
nothing behind it is the case the check exists for, so finding nothing must not read as agreement.
A key the wasm states twice is refused on the same principle from the other side — reading the
entries into a map would resolve it by last-wins, and which occurrence is last is a fact about the
reader's walk order, so a verifier walking the two sections differently would reconcile the other
value and reach the opposite verdict about identical bytes. The stub builder is the single
exemption, because its placeholder wasm is not a module and carries no metadata at all.

What this does **not** do is make the manifest verifiable by a third party — that still needs
SEP-55's signature or SEP-58's rebuild. It makes our own statement about the toolchain a checked
one instead of an asserted one.

**Verdict on the provenance half: a deliberate divergence, and an open question we did not
invent.** Our artifacts are **readable** by standard tooling already — `stellar contract info
meta` shows the SEP-46 keys the toolchain writes itself (`rsver`/`cliver`/`rssdkver`) and anyone
can compute the wasm hash. What they do not carry is any trace of provenance: neither a reference
to the spec the policy was derived from, nor the fields either verification SEP needs. So the
link "artifact ↔ specification" can today be checked only with our `BuildManifest` and our CLI.

Nothing requires otherwise. No SEP obliges a contract to write meta of its own; both
verification SEPs are Draft and no released `stellar-cli` implements either; neither the RFP this
work answers nor the proposal that answered it asks for artifact verification. This section
records a direction we intend to stay compatible with, not a rule we are failing. Adopting the
vocabulary early would mean guessing at one specific unresolved point — SEP-58 keys on the
SHA-256 of a *source archive*, and a contract generated on demand has no archive — and a guess
the standard later contradicts is worse than the absence. The question is written up and raised
where the SEP is being discussed; when it resolves, the answer is to adopt the standard's
spelling rather than to keep our own.

**Verdict on the reproducibility half: our own guarantee is narrower than it sounds, and this
one is not waiting on anybody.** It is worth separating from the paragraph above, because that
one is a standard in progress and this one is a limit of what we can currently promise. We pin
rustc through `rust-toolchain.toml`, pin
dependency versions, and build `--locked` (in `BUILD_ARGS`,
`crates/build-runner/src/lib.rs:463-469`). SEP-58 pins the
container image by digest, which covers the operating system, the system libraries, the linker
and the toolchain in a single field. We pin neither the OS nor a container, so an identical wasm
hash reproduces on a sufficiently similar host and is not guaranteed off it. Containerised builds
need no finished SEP, and as of `stellar-cli` **28.0.0** (released 26 August 2026) they need no
tooling work either: `stellar contract build` can now run inside a container, pinning the
toolchain by image tag or digest
([stellar-cli #2678](https://github.com/stellar/stellar-cli/pull/2678)). That closes the build
primitive and nothing else — the verification workflow SEP-58 assumes, `--verifiable` and
`stellar contract verify`, is still unreleased
([#2585](https://github.com/stellar/stellar-cli/pull/2585) is open;
[#2586](https://github.com/stellar/stellar-cli/pull/2586) was closed unmerged on 2026-08-27). So what remains here is
ours: adopting the container build and pinning a digest, which is sequencing and cost rather
than a missing standard or a missing tool. Until then, "byte-identical across
two cold runs" means on comparable hosts, which is what CI measures and all this repository
claims.

**What that measurement currently says.** `stellar contract build` produces a byte-identical
wasm across a full `cargo clean` rebuild: sha256 `9cf2a72a…` for the golden policy, and
`ded75163…` for the Soroswap policy under the same toolchain, measured in the same sweep. The
gate asserting it hashed `contracts/target/…` until 2026-08-13, a path the rebuild never
writes — the golden crate carries its own `[profile.release]` and so is excluded from the
contracts workspace, and `stellar contract build` writes to *its* target directory. That gate
compared one untouched file with itself and passed unconditionally. The claim was true
throughout; the check was not.

**A side consequence worth recording.** Because `cliver` and `rsver` land **inside** the wasm,
they are part of its bytes and therefore of its `wasm_hash`. A change of CLI version thus
changes the artifact hash mechanically, even with identical generator output. This confirms the
need to pin `stellar-cli` and not only rustc: the platform records the version in the artifact,
which is what makes the dependency visible, but reproducibility still requires the pin.

**Action.**
1. Emit `contractmeta!` into the generated crate with a reference to provenance: `spec_hash`,
   `normalized_input_hash`, `template_family`, `registry_snapshot`. The artifact then describes
   what it was derived from self-sufficiently, in the SEP-46 section, read by standard
   `stellar contract info meta` — without our `BuildManifest`.
2. ~~Stop duplicating what the toolchain writes itself; in `BuildManifest`, either reference the
   wasm metadata or reconcile against it and fail on divergence.~~ **Done** for the reconciling
   half: the three restated versions are now checked against the wasm's `contractmetav0` and a
   divergence refuses the build. The rest stands — where `BuildManifest` asserts what SEP-55
   attests, follow SEP-55's shape rather than a private one, once there is a released
   implementation to follow.
3. Decide whether to build inside a digest-pinned container image and record it as SEP-58
   `bldimg` (with `bldarg`/`bldopt` for the invocation). This is the ecosystem's answer to
   reproducibility, and it is strictly stronger than pinning rustc and dependency versions.
4. Settle an open design question (ℹ️): a generated contract **has no source in the
   repository** — it is created on demand. This is a smaller obstacle than it first appears,
   because SEP-58 keys verification to `source_sha256` over the bytes of a source archive and
   makes `source_uri` optional, rather than to a repository and revision; a generator can
   produce that archive and record its hash. What remains open is where the archive is
   published and by whom, and whether pointing at the generator plus `spec_hash` — so a
   verifier reproduces the source by re-running generation — is worth specifying alongside it.
   **Unresolved.** It is settled by choosing a publication point for the archive and writing it
   down, or by establishing with the SEP's authors that a generator-plus-spec pointer satisfies
   a verifier; neither has been done.

---

## 3. State archival and TTL ✅ (security and, since the hardening pass, operations)

**Platform principle.** `persistent` entries have a TTL. When it expires the entry is
**archived**, not deleted, and, verbatim: "Archived persistent entries can never be re-created.
They must instead be restored."

**Protocol 23 changed the restoration path, and that matters.** Archived `Persistent` and
`Instance` entries are restored **automatically, before the host function executes** — but only
if they made it into the transaction's `restore list`, which simulation populates: "if the
simulation detects an access to an archived entry, it adds that entry to the restore list".
`RestoreFootprintOp` remains for rare cases (a transaction too large, fee management by the
developer), but it stopped being the only and primary path.

A transaction whose footprint contains an archived `Persistent` key that did **not** make it into
the restore list still fails at the apply stage, before the contract executes.

**The guidance on extension is conditional, and one line of it cuts against us.** It lives on
the *Persisting data* page, not on the state-archival page, and it is phrased throughout as
"should": global state that cannot be `Temporary` should be in `Instance` storage so that its
TTL is aligned, and an autonomous contract "should extend the TTL of any shared state touched by
an invocation via the `extend_ttl()` host function". The same page then says, verbatim: **"TTL
extensions should never be relied on for functionality or safety."** The reasoning it gives is
that anyone may extend any entry's TTL without authorization, so an extension is not a
control — which is a caution against building a guarantee on top of extension, and equally a
caution against over-engineering extension itself. Both belong here: the guidance is worth
following for predictable cost and behaviour, and it is not a requirement we are in breach of.

**What we have.** The generated policy keeps its per-installation state in `persistent()` —
since the hardening pass that is an installation marker for **every** policy, scoped by
(smart account, context-rule id), plus the call counter where the rule has one — and it
**extends TTL deliberately and boundedly**. Exactly two entry points extend: a successful
`enforce` and a successful `install`. Both extend the same entries (the instance entry and the
policy's own persistent entries) to the same target, `ttl_target(e)`: the network's rolling
`e.storage().max_ttl()` (the SDK exposes the maximum on `Storage`, not on `Ledger`), clamped so
the target never outlives `VALID_UNTIL_LEDGER` — past expiry both of the entry points that
extend deny, so the policy can never permit anything again and extending further would buy rent
for an artifact with no remaining use. (`uninstall` and the two getters keep working past expiry
on purpose: an account must always be able to detach, and a query about a dead installation is
still a fair question. Two of the five entry points check the window, and
`the_validity_window_is_checked_by_the_two_entry_points_that_extend` is what holds that sentence
to the code.) A denied
call extends nothing, `uninstall` extends nothing, and the extension is threshold-conditional
rather than unconditional, so routine authorizations do not each buy rent. The policy does not
separately extend the **wasm code** entry (see action 2 below).

That the two agree is structural rather than asserted: the emitter has one extension block and
both write paths use it, and `only_the_write_paths_extend_and_the_getters_say_why_they_do_not`
compares the two emitted bodies against each other rather than against a written-down list.

**The getters extend nothing, and that is the library's rule for this kind of module rather than
a departure from it.** `code-quality.md:344` says library-managed entries extend TTL on read, not
on write; `:376-381` carries the exception, and the exception is this case: "Utility modules with
caller-managed instance state do NOT extend TTL on read. The pausable module is the canonical
example: its `paused()` reader explicitly does not call `extend_ttl` because the contract using
pausable already manages its instance TTL." A generated policy's entries are created by the smart
account's `install` and destroyed by its `uninstall`; the account's own calls are what keep them
alive. A query is not the account exercising its grant — any caller may make one — so it must not
buy rent for state it does not own. Both getters therefore carry the explanatory `// NOTE:` that
pattern asks for, citing the clause so a reader can check it.

**Which means the bound holds for every rule shape, including the one with no window.**
`ttl_target` is bounded twice only when the rule has a validity window; with no `valid_until` its
target is simply the rolling `max_ttl()`. That is not a hole, because the only callers who can
make this policy extend anything are the account itself, through `install`, and a *permitted*
authorization — and a rule with no window still caps calls or does not, and still refuses
everything it is not scoped to. There is no unauthenticated path to a write of any kind. An
earlier version of this section had one: the getters extended, so a third party could hold a
window-less policy's entries out of archival indefinitely by paying for it. Removing the
extension removed that, and removed the asymmetry behind it — the two getters had extended
different entry sets, so an installation polled only through `remaining_calls` kept its count
alive while its marker decayed.

**Security verdict — conforms, along two different paths.** The architecture requires
(`docs/architecture.md:598-600`): "a call cap never resets **within an installation** due to
inactivity, TTL expiry, or archival". The requirement is satisfied by **the platform's semantics
rather than by our code**, and in both modes:

- *the ordinary flow* (simulate → assemble): the entry is restored automatically before
  execution, the counter comes back, and `install` runs into `has(&key)` → `AlreadyInstalled`.
  There is no reset;
- *a manually assembled transaction without a restore list*: it is rejected at the apply stage,
  before the contract is invoked. Neither `enforce` nor `install` runs, so this is fail-closed
  by platform rejection, not by policy denial — the distinction matters, because the policy
  contributes nothing to the outcome here.

**A load-bearing question, and its evidence.** Whether automatic restoration preserves the
entry's previous value is what the security verdict rests on: if restoration zeroed the value,
the cap would be reset by archival and the architecture's requirement would be violated. It
**does** preserve the value, and since the prose documentation only says that a restored entry
receives a minimal TTL extension — leaving preservation to be inferred from "cannot be
re-created, only restored" — the evidence is the implementation and the protocol change itself:

- `soroban-env-host` 26.1.3, `src/e2e_invoke.rs:733-756`: for a footprint key whose entry has
  expired, the host fetches the entry from the ledger snapshot, checks it is persistent, and
  records it as auto-restored. It measures the encoded entry and marks the key; it never
  rewrites `le.data`.
- `soroban-env-host` 26.1.3, `src/e2e_invoke.rs:1007-1043`: the decoded entry is inserted into
  the storage map as `(le, live_until_ledger)` — the value the contract then reads. The only
  entries dropped for expiry are **temporary** ones, which are skipped explicitly.
- [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md) states the
  outcome at protocol level: a restore emits a `LEDGER_ENTRY_RESTORE` change that "will include
  the complete LedgerEntry of the restored entry."

Two things about the shape of that evidence, so the next reader does not repeat the search. It
is **not** in `src/storage.rs`, which is where a checker looks first and where it is not. And
the Rust host covers simulation and the restore-list path; the on-ledger restore itself is
implemented in stellar-core, so this is evidence about the path our flow takes rather than a
reading of every implementation of the rule.

The scope of "never resets" is one installation, and that limit is real: `uninstall` removes the
entry, after which `install` is possible and the counter starts from zero. Both require only
`smart_account.require_auth()`, which the account grants under any rule matching the policy's
address (`Default` or `CallContract(policy)`), not only the owner's. Whoever holds such a rule
can therefore reset an existing grant's cap. `account_wasm_invariants.rs` demonstrates this
through the pinned account. `check_policy_call_surface` lists such rules before installation and
refuses one the agent's key can use alone. A rule added later is detected only when someone runs
the wallet's on-demand check, and only for a grant installed by the running backend; it counts
any later rule allocation as drift (see "On-demand installed-grant monitoring" in
`docs/POLLYWALLET-INTEGRATION.md`). Nothing monitors in the background. The architecture states
the cap per installation — `docs/architecture.md:598-600` says "within an installation" rather
than "lifetime", and the reinstall invariant at `:586-591` is scoped to the installer flow
instead of being asserted of the policy contract, which cannot enforce it. The generated
contract enforces its half of that scoping since the hardening pass: `install` refuses a second
installation (`AlreadyInstalled`), `uninstall` of something never installed refuses
(`NotInstalled`), `uninstall` removes the policy-owned state, and `enforce` fails closed
(`MissingState`) when the installation marker is absent — so "a new grant" is a new marker,
never a resumed one.

**The code has followed.** The rename reached the generated artifact's header, the reference
evaluator's message, the spec type (`StateSpec::CallCountPerInstallation`) and — the expensive
one — the wire field, which is now `call_count_per_installation` in the committed example spec.
That last one changes a signed artifact and every consumer that parses a spec, which is why it
was taken together with the canonicalization change rather than paid for separately: both break
the schema, and one break is cheaper than two.

The signed registry snapshot briefly carried the same name in its list of permitted *constraint*
kinds. That was a filing error rather than part of the rename — a call cap is a `StateSpec`, not
an argument constraint — and that list is now exactly `Constraint`'s vocabulary, derived from the
enum. State capabilities are consequently not declared by a template entry at all:
`TemplateCapability` has no `state_kinds`, and adding one changes the snapshot's shape. Nothing
read the entry while it was there, so this removed a declaration and no control.

**Operational verdict — conforms since the hardening pass.** The earlier divergence was that
the policy extended nothing, leaving rent, restoration fees, and the moment of archival
unpredictable for the user. Extension is now emitted, bounded twice (the rolling `max_ttl()`
and the rule's own validity window), conditional on a threshold, and withheld on denial and on
`uninstall`. One thing about it is ours rather than the library's, and §15 lists it as a
deliberate divergence: the extension is **withheld once a call cap is spent**, which no upstream
policy does, and which is the reason the dynamic target exists. That the extension happens on the
write paths and not on reads is not a divergence — it is `code-quality.md:376-381`, the exception
for caller-managed state, applied to a module whose state the smart account creates and destroys. It remains what the platform says it may be — a predictability measure, never a
safety mechanism: the security verdict above rests on restore semantics and fail-closed reads,
not on who paid for an extension.

**Action.**

1. ~~Extend the counter's TTL on read and write in `enforce`, bounding **each** extension by the
   current `e.storage().max_ttl()` and going no further than `VALID_UNTIL_LEDGER`.~~ **Done.**
   `ttl_target(e)` clamps the extension to the rolling `max_ttl()` and saturates at
   `VALID_UNTIL_LEDGER`, so the entries live no longer than the policy can permit and are
   archived naturally after it expires.
2. Extend the TTL of the **contract instance and of the wasm code** — their own entries with
   their own deadlines. **Done for the instance entry**, extended alongside the persistent
   entries in `install` and in a permitting `enforce`. The **wasm code** entry is deliberately left
   to the operator/installer: anyone may extend it, an archived entry is restored rather than
   lost, and the code entry is shared with every other deployment of the same wasm, so its rent
   is not obviously this policy's to pay. Two emitted comments claimed the code entry was kept
   alive alongside the instance; they were wrong and now say what the block does. Keep both extensions proportionate: since extensions
   may not be relied on for functionality or safety, they buy predictability, and any design
   that would need them to hold a guarantee is the wrong design.
3. Do **not** reject, at generation time, a policy whose `valid_until` exceeds `max_ttl()`.
   `max_ttl()` is a sliding network bound counted from the current ledger, so an entry is carried
   to a distant future deadline by **successive** extensions. Rejection would cut off precisely
   the long-lived scenario the tool exists for. (Still holds; `ttl_target` is exactly that
   successive-extension mechanism.)
4. ~~Cover this with tests in the soroban test environment, advancing the ledger number.~~
   **Done.** `contracts/differential/tests/ttl.rs` advances the test ledger across eleven tests:
   install and enforce extending the counter and instance entries, the no-op above the
   threshold, a denied call extending nothing, `uninstall` extending nothing, the target never
   outliving the validity window, the last permitted call not buying rent,
   install-after-expiry refusing without writing state, what the two getters report, that a read
   buys no rent at any point in an installation's life, and that `remaining_calls` refuses an
   installation whose marker is gone.

---

## 4. The value system and numeric types ✅

**Platform principle.** The complete value system is `ScVal`, and in the pinned `stellar-xdr`
27.0.0 that is **22 variants** (recounted from `src/generated/sc_val.rs`), **not one of them
fractional**: `Bool, Void, Error, U32, I32, U64, I64, Timepoint, Duration, U128, I128, U256,
I256, Bytes, String, Symbol, Vec, Map, Address, ContractInstance, LedgerKeyContractInstance,
LedgerKeyNonce`. The XDR format can encode a float (`impl ReadXdr for f32` is present), but no
Stellar type uses it. Amounts are integers in stroops (`i128`), ledger numbers are `u32`.

`Symbol` constraints: the character set `[a-zA-Z0-9_]`, length up to 32 bytes. Addresses are
strkeys (base32, the set `A-Z2-7`, with a checksum).

**What we have.** No floats anywhere. Amounts are `i128`, serialized as a decimal **string** with
a canonicality check (`is_canonical_i128`). Every map is a `BTreeMap`.

**Verdict.** Conforms, and the ban is **checked** rather than declared: the workspace-wide
`clippy.toml` forbids `HashMap`/`HashSet`/`f32`/`f64` (per-process iteration order and values
with no faithful JSON or `ScVal` form), and the registry snapshot hash has a cross-process
determinism test. Since the hardening pass the values are also **bounded**, not merely typed:
exact `ScVal` constraints are size-capped per value and per rule, validation and codegen share
the builder's input ceiling so a spec that validates cannot generate a crate the next stage
refuses, and a maximum-shaped rule is generated in a non-vacuous boundary test (the caps are
tabulated in §14).

**A note on the move to XDR (§1), now carried out.** Field names became `Symbol`s, so both
constraints applied: length ≤ 32 bytes and the character set. The `$schema` field was the known
problem — `$` is not permitted in a `Symbol` — and it appeared in four structures, not one. All
four are now `schema`; the value was always a plain identifier rather than a JSON-Schema URI, so
the `$` carried no meaning worth an encoding exception.

---

## 5. Authorization model ✅ / 🗓 (external verifiers deferred)

**Platform principle.** A smart account is a contract implementing the custom account interface;
`__check_auth` validates the proofs presented. OpenZeppelin's `stellar-accounts` formalizes this
as signers, context rules, and policies; a policy is a separate contract with
`enforce`/`install`/`uninstall`, and denial is expressed by a panic.

**What we have.** The generated policy implements exactly the `Policy` trait from
`stellar-accounts` 0.7.2, reads
`soroban_sdk::auth::Context::Contract(ContractContext { contract, fn_name, args })`, and denies
by panicking. The order of checks is fixed and documented in the artifact's header: account
authorization and installation state first, then the signer predicate (the account defers
signer validation to policies), then the strict signer set, then target/function/argument
tuple, then stateful invariants. Named signer predicates are strict by default, so adding a
signer to a live account rule cannot silently widen the generated grant, and zero
authenticated signers always deny.

**External verifier signers are deliberately unsupported in this milestone (🗓).** An off-chain
spec can name a verifier address and a verifier wasm hash, but the runtime OpenZeppelin signer
value carries only the verifier address and key — nothing at authorization time binds that
address to the recognized code. Registry recognition of a caller-supplied hash does not prove
the address runs that code, so validation rejects the shape (`E_SPEC_EXTERNAL_SIGNER_UNSUPPORTED`)
for the new rule. The authority check does bind address to observed executable for the
account's existing owners: an external owner is an identity only while the code at its verifier
address, read at the same ledger, is a reviewed immutable and stateless verifier.

**The reviewed spending-limit composition is validated, not assumed.** Composition is accepted
only for a recognized SEP-41 `transfer` shape with the `i128` amount at argument index 2, a
positive limit and period, decisions that can replay the representative evidence, and never on
mixed transfer/non-transfer rules. Its stateful runtime behaviour is deliberately not
reimplemented by the Phase 1 evaluator — see §11.

**Verdict.** Conforms where it claims to; defers loudly where it cannot check. We invent no
authorization primitives of our own, and OpenZeppelin's `spending_limit` policy is **used by
hash** rather than replaced.

---

## 6. Errors and observability ✅

**Platform principle.** Errors are declared with `#[contracterror]` and numeric codes; denial is
`panic_with_error!`. Events (`events().publish`) are the standard way to make a contract's
behaviour observable outside the transaction.

**What we have.** `#[contracterror]` with eleven distinguishable codes, every denial path named
(`RuleExpired`, `TargetMismatch`, `CallCountExceeded`, `NoTupleMatched`, …), including the
lifecycle refusals the hardening pass added (`AlreadyInstalled`, `NotInstalled`, and
`MissingState` for an enforce without an installation marker). This is not cosmetic:
distinguishable codes are what let the differential test compare not only "yes/no" but the
reason for a denial. On the toolkit's wire, error codes are likewise stable machine-readable
identifiers, standardized as `SCREAMING_SNAKE_CASE` with an exhaustive round-trip test (§12).

**Verdict on errors — conforms.**

**Observability — resolved, and option (a) is what was taken.** This section previously recorded
an open decision: the policy published no events, so no on-chain trace remained of what it
permitted. It now emits three, following the shape of the library's own policies rather than one
of our own — `GeneratedPolicyInstalled`, `GeneratedPolicyEnforced` and
`GeneratedPolicyUninstalled`, each a `#[contractevent]` struct with `smart_account` as its single
`#[topic]` and `context_rule_id` in the data, and the enforcement event additionally carrying a
SHA-256 of the `Context` it permitted and, where the rule caps calls, the count remaining after
the one just spent. A digest and not the `Context` itself: that is the one place this shape
departs from theirs, §15 divergence 9 is the argument, and the departure is what keeps a permitted
call publishable at any argument size.
Compare `spending_limit`'s `SpendingLimitEnforced` / `Installed` / `Uninstalled`
(`stellar-accounts-0.7.2/src/policies/spending_limit.rs:46-53`, `:58-64`, `:79-83`, published at
`:281`, `:404`, `:442`), whose running number is `total_spent_in_period`; ours is
`remaining_calls`. The trait's own docstring asks for the install and uninstall events
(`policies/mod.rs:106-111`, `:144-149`); all three library policies also emit from `enforce`,
which is why ours does.

**The cost, measured rather than estimated — and the per-call cost is the one that was asked
about.** Two different numbers, and this section used to give only the first.

*Once, at deployment.* The golden policy's wasm went from 17,005 to 19,725 bytes — 2,720 bytes,
16% — under the pinned rustc 1.91.1 and stellar-cli 27.0.0, measured when the events were added.
That figure is not re-derivable from the tree today: no wasm is committed, and the artifact has
changed since (the crate split, the getter work, then the context digest of divergence 9), so
treat it as the price of the event machinery at the commit that introduced it rather than as a
current measurement. The golden policy's wasm is **20,028 bytes** as of this commit, and the
Soroswap policy's is 20,199.

Both numbers moved by 168 bytes when nothing but doc comments changed, which is worth stating
because it is easy to get wrong: `#[contractevent]` and `#[contracttype]` put the doc string of
the type and of every field into the contract spec section of the wasm
(`soroban-sdk-macros`, `derive_struct.rs`, `doc: docs_from_attrs(…)`), and the spec section is
part of the artifact that is hashed. So a documentation-only change to a generated event does
move the wasm hash, and any claim that it does not is wrong on its face.

*Every permitted call, forever.* This is what the objection was about, and a wasm is paid for
once. The fee-relevant quantity is the serialized size of the event that lands in the
transaction's metadata: **264 bytes** for `GeneratedPolicyEnforced`, and 172 each for
`GeneratedPolicyInstalled` and `GeneratedPolicyUninstalled`, which happen once per installation.
The enforcement event is the larger of the two shapes because it names the authorization it
approved — a 32-byte digest of the `Context`, which is what makes 264 a number at all rather than
a figure that moves with whatever the call was. Asserted exactly rather than bounded, in
`an_event_costs_what_the_conformance_record_says_it_costs`
(`contracts/differential/tests/events.rs`), so a field added to an event has to move the number
here too. That it does not move with the *arguments* is checked in
`contracts/differential/tests/event_payload.rs` over six permitted calls with an unconstrained
argument that crosses the host's event-size limit.

**What still cannot be observed, and why that is a property.** A **denial** leaves nothing behind,
and this is technically unrealizable rather than unimplemented — worth keeping recorded so it is
not revisited. `panic_with_error!` reverts the invocation, so an event published before the panic
is reverted with it and never becomes an ordinary on-chain event. Events are possible **only on a
successful** `enforce`. Denial reasons reach a caller through the error code and through RPC
diagnostics, where they were always available; a durable on-chain trace of denials would have to
be designed separately rather than bolted onto `enforce`.
`contracts/differential/tests/events.rs` asserts the emptiness as a property rather than leaving
it as a remark here: five refusals, one per entry point plus the two at the extremes of
`enforce`'s check order, each leaving the event log untouched. Five and not all twelve
`panic_with_error!` sites, because the mechanism is the host's and is uniform — a panic reverts
the invocation — so what varies between sites is how much work preceded it, and the five are
chosen along that axis. Every deny reason is covered against the reference evaluator in
`differential.rs`; that file is about the decision, this one about the log.

**Reading state without an event.** The artifact also exports `is_installed` and, where a cap
exists, `remaining_calls` — pure reads that extend no TTL, for the reason §3 gives. Between the
events and those
two, an indexer can reconstruct an installation's history and a caller can ask about its present
state, which is what the earlier "no on-chain trace" verdict was about.

---

## 7. External security tooling ℹ️ (customary tools, not protocol requirements)

**What the ecosystem has.**
- **Scout** (CoinFabrik) — a static analyzer specifically for Stellar contracts, with a catalog
  of known vulnerability classes. The analyzer is `CoinFabrik/scout-soroban`, installed as the
  cargo subcommand `cargo-scout-audit`; `CoinFabrik/scout-soroban-examples` is the companion
  repository of reviewed examples, not the tool. (`CoinFabrik/scout` is the ink! analyzer and
  does not apply here.)
- **The Soroban security checklist** from Veridise.
- **The Soroban Security Audit Bank** — an SDF programme funding audits: SDF has conducted over
  40 audits, deploying over $3 million. STRIDE appears there as the audit-readiness support SDF
  offers to participating projects, not as preparation those projects are required to bring.

**What we have.** Differential testing (an independent reference evaluator against the real
compiled contract), mutation testing of the core, property tests, reproducibility gates. That is
strong scaffolding — but all of it is about **our Rust code**. Not one Soroban-specific analyzer
runs on the **generated contracts**.

**Verdict.** A qualification about the frame: Scout and the Veridise checklist are **not protocol
requirements** and not "conformance" in the sense discussed in the other sections. They are
third-party tools that the ecosystem customarily applies. Our gap is not that we breach a norm,
but that we check the generator thoroughly and do not check what it generates.

**Action.**
1. Run Scout over the reference generated policies and look at the result. **Before** making a
   gate of it, three things are needed: pin the version (from `cargo-mutants` we already know
   that a tool's version changes the verdict, and that this is part of the point of a gate);
   establish that the analyzer applies to our kind of input at all — generated source or wasm;
   and define the false-positive policy. A gate without those three will be either noise that
   people start routing around, or theatre.
2. Work through the Veridise checklist against the generated template and record the result line
   by line.
3. **Apply to the Soroban Security Audit Bank.** An external audit is the control this section
   cannot substitute for, and the programme is a funded route to obtaining one.

---

## 8. Upgradeability and immutability ✅

**Platform principle.** Contracts may be upgraded via `update_current_contract_wasm`;
`stellar-accounts` ships an `Upgradeable` extension. Upgradeability is a choice, not an
obligation.

**What we have.** The generated policy **deliberately** has neither an upgrade entry point nor
setters — this is written in the artifact's header: "No setters, no upgrade entry point." The
constraints are fixed as constants in the source, so a limit cannot be changed without changing
the code, and changing the code changes the hash. The testnet harness's own copy of the
OpenZeppelin account, used for the on-chain install run, was likewise built without the
`Upgradeable` extension; the harness now deploys the pinned upstream example instead
(the second-milestone testnet evidence, `docs/TESTNET-EVIDENCE-TRANCHE-2.md` §4), where
upgradeability of the account is upstream's choice and
independent of the policy's immutability.

**Verdict.** Conforms, and the choice is deliberate: for an artifact whose value is "the user
read exactly what executes", immutability is a requirement rather than an omission. The header
is the thing a user reads, which is why the cap wording there was renamed to
"within an installation" when §3 settled what the platform actually guarantees — a name that
overstates a guarantee costs more in that header than the same name would anywhere else.

---

## 9. Evidence provenance and RPC binding ✅ (RPC evidence, not ledger inclusion)

**Platform principle.** Stellar RPC is a query interface, not a trust anchor: `getTransaction`
returns what the configured endpoint says, `getLedgerEntries` reads current state, and nothing
in the protocol makes a JSON response self-authenticating. Whatever trust a recording carries
has to be assigned by the party that fetched it, and downgraded the moment it leaves their
hands.

**What we have.** For an executed transaction, the RPC adapter (hardened in this pass): rejects
any requested hash that is not exactly 32 bytes of hexadecimal; verifies the configured network
passphrase through `getNetwork`; compares the response `txHash` against the canonical requested
hash; decodes `envelopeXdr` and independently recomputes the transaction hash under that
network, so a response body cannot smuggle a different transaction under the right label;
bounds the HTTP stream before allocating or parsing JSON; and decodes authorization/meta XDR
under depth and size limits.

`rpc_reported` means exactly "returned by the configured RPC endpoint" — it is not an inclusion
proof. More importantly, serialized JSON is caller-controlled: the toolkit downgrades every
bundle crossing the synthesize JSON boundary to `self_supplied`, so changing a `trust` field
cannot mint RPC or indexer assurance (a future hosted service could preserve stronger
provenance only with an authenticated receipt or a server-side recording ID).

`getLedgerEntries` observes contract executables at its reported latest ledger, which may be
later than the transaction's ledger. The observation ledger is stored with the observation; for
historical transactions the toolkit does not claim the current executable was the one at
execution time.

---

## 10. Capability registry governance ✅ / 🗓 (production governance is hosted-service work)

**What we have.** Registry snapshots are content-addressed, threshold-signed, network-bound,
versioned, chained by previous root, time-bounded, and checked against a persisted minimum
version or checkpoint, so a replayed older snapshot or a same-version fork is refused rather
than accepted. Capabilities are keyed by canonical lower-case wasm hashes (or a validated
template family), and unknown or revoked capabilities fail closed. Since the hardening pass,
accepted revocations are also **append-only across succession**: a signed successor snapshot
cannot remove a prior revocation or rewrite its reason or effective version, and revocations
survive registry restarts. Tests cover rollback, same-version equivocation with checkpoints,
transparency-chain forks, invalid key encodings, and revocation removal/mutation.

**Verdict.** Conforms as a mechanism; 🗓 as governance. The committed registry key is a
deterministic development root — suitable for reproducible examples, not production governance,
which needs independently controlled roots, durable checkpoints, rotation and revocation
operations, monitoring, and an incident process.

---

## 11. Evaluator and differential evidence ✅ / 🗓

**What we have.** The reference evaluator interprets validated spec structures directly; it
consumes no generated Rust and cannot depend on codegen — the missing edge is enforced in the
cargo dependency graph by `scripts/check-dep-rules.sh`. Structural independence reduces common
implementation coupling; it does not make either side correct by definition, which is why
property tests, mutation tests, canonical fixtures, and the compiled-contract comparison all
still run.

Since the hardening pass the full-spec evaluator is **honest about composition**: it returns
`deny` when the generated conjunct conclusively denies, `permit` only when every relevant
component is modelled, and `indeterminate` when an attached reviewed policy could still deny
and its state is not modelled — a whole-spec permit is never manufactured from a partial model.
The differential suite is correspondingly **scoped**: it invokes the generated policy contract
directly in a Soroban test environment and compares verdict plus denial reason against the
explicitly scoped `evaluate_generated_rule` model.

**Verdict.** Conforms for what it claims. 🗓 for what it does not: the suite does not exercise
a full OpenZeppelin smart account's `__check_auth`, reviewed-policy composition, wallet
installation, or live account state — later-milestone evidence, not implied by the phrase
"compiled contract".

---

## 12. MCP surface and machine-readable failures ✅

**What we have.** Request DTOs are closed schemas and reject unknown fields. The enum, the
published `ErrorCode::ALL` vocabulary and the wire spelling are generated from one list, so
every declared error code is necessarily in the vocabulary and in the serialization
round-trip table that walks it — exhaustive by construction rather than by diligence, which
is the fix for two codes that had been added to the enum and to `as_str` (a match the
compiler checks) while missing from `ALL` (an array nothing tied to the variants), silently
narrowing that table. Codes are standardized as `SCREAMING_SNAKE_CASE`, and public DTOs
generate JSON Schema. Tool execution and validation
failures return as MCP `CallToolResult` values with `isError: true` and structured
`{code, message, details}` data rather than being misclassified as JSON-RPC protocol failures,
so an agent can distinguish transaction-not-found, network mismatch, import parse, build
timeout/resource, and registry failures by stable wire codes.

The server never deploys, signs, or holds user keys. HTTP mode is loopback-only,
bearer-protected, body-bounded, rate-limited, build-concurrency-limited, and RPC-allowlisted.
MCP annotations remain hints, not authorization controls.

---

## 13. Build containment 🗓 (a local safeguard; hosted isolation is later-milestone work)

**What we have.** The local builder uses fixed commands and arguments, an offline `--locked`
Cargo build, bounded source/wasm/log sizes, a bounded timeout with bounded version probes,
process-group termination, a protected per-user cache, and — since the hardening pass — a
sanitized allowlisted child environment that excludes service and cloud credentials and proxy
variables, plus a combined CPU budget so the hosted server's concurrent-build slots multiplied
by Cargo jobs cannot exceed the detected budget. The slots are taken by the build itself and
held until it ends; a build beyond them is refused with `E_BUILD_BUSY`.

**Verdict.** A boundary of this milestone, stated rather than glossed: these controls are a
local safeguard, not the isolation a hosted multi-tenant build service would need. They provide
no
cgroup memory/CPU/disk/PID quotas, namespaces, seccomp, per-job filesystem isolation, egress
isolation, or cancellation on client disconnect. Tranche 1 therefore does not describe loopback
HTTP or the local compiler as a safe multi-tenant hosted service; before hosting, this needs a
secret-free worker identity, a digest-pinned image (§2 action 3), hard OS quotas, per-job
workspace and cache strategy, bounded egress, cancellation, durable rate limits, and
operational monitoring.

---

## 14. Defaults and limits

The knobs and caps the release ships with, and what each one does and does not promise:

| Setting | Interpretation |
|---|---|
| Generated policies: Rust 1.91.1 / CLI 27.0.0 / SDK 28.0.0 / OZ 0.8.0 | Current policy build set. Recognized upstream account/verifier/policy artifacts retain their independent SDK 26 / OZ 0.7.2 provenance. Upgrades change artifact hashes and require review. |
| Build timeout 600 s | Reasonable for a cold local build; hosted infrastructure still needs an outer deadline and hard quotas (§13). |
| Build jobs CPU−1, minimum 1 | Appropriate for one local build; HTTP defaults to one concurrent build and enforces a combined CPU budget. |
| HTTP request body 1 MiB / RPC response 24 MiB | Transport ceilings; nested domain and per-XDR limits still apply before evidence is accepted. |
| RPC timeout 30 s and bounded response stream | Prevents unbounded read/allocation; endpoint correctness is still part of `rpc_reported` trust (§9). |
| XDR 512 KiB per value / 1 MiB total encoded evidence | Deliberately below the 4 MiB canonical-hash preimage ceiling, so a recording accepted by the recorder does not fail only when hashed (§1). |
| Import document 1 MiB + 4 KiB | The total-evidence ceiling above plus the format's own JSON syntax — an import carries no simulated authorizations or state changes, so a longer document cannot describe admissible evidence. Refused on length before parsing, which is also the only bound on the supplied network passphrase. The syntax that allowance covers measures ~200 bytes, so the 4 KiB is headroom, not a fit. Over HTTP the default 1 MiB request-body limit binds first, so at that default the last 4 KiB of this range is reachable only over stdio and in-process. |
| 5 policies / 15 signers / 20-byte name | Equal to the pinned OpenZeppelin account constants and contract-tested. |
| 32 rules / 32 calls per rule / 32 args per call / 256 recordings | Defensive off-chain caps; text, evidence-reference and exact-ScVal limits prevent these counts from hiding unbounded payloads. |
| 64 KiB exact ScVal / 256 KiB exact-ScVal XDR per rule / 2 MiB generated crate | Validation and codegen share the builder's input ceiling; a maximum-shaped rule is generated in a non-vacuous boundary test (§4). |
| Example period 120,960 ledgers | Roughly seven days at an assumed five-second cadence; it is a ledger count, not seconds. |
| Example max calls 12 | Explicit demo decision, not inferred protocol truth; synthesis verifies it can cover representative calls. |
| No expiry | Allowed only with explicit high-blast-radius acknowledgement. |

---

## 15. Contract code conventions (OpenZeppelin's own checklist) ✅ / ⚠️

**Why this section exists at all.** Sections 1–14 measure us against the *platform*. This one
measures the generated policy against the *library's own house rules*, which is a different
question and, for this project, a sharper one. `stellar-contracts` documents them in
`.claude/commands/code-quality.md`, and their `CONTRIBUTING.md:99` says PRs that violate them "may
be rejected" — aimed explicitly at AI-assisted contributions, which ours are twice over, since a
program writes the code. The artifact this project ships is a Soroban contract that a
`stellar-contracts` maintainer is the natural reviewer of, so their conventions are the standard
it is read against whether or not we ever open a PR there.

Every path in this section that is not prefixed `crates/`, `contracts/`, `docs/` or `scripts/` is
a path in **their** repository, not ours — worth stating once, since the same document cites both
and our own `CONTRIBUTING.md` is 77 lines long.

The reference points throughout are the pinned audited release, `stellar-accounts` 0.7.2, and the
two sibling policy examples at tag v0.7.2:
`examples/multisig-smart-account/threshold-policy/src/contract.rs` and
`.../spending-limit-policy/src/contract.rs`.

### What we now satisfy

| Convention | Where it lands in the emitted crate |
|---|---|
| No lint suppression; `-D warnings` clean | The emitter wrote `authenticated_signers.len() == 0` — `clippy::len_zero`, warn-by-default — in every policy it had ever generated, and their rules forbid an `#[allow]`, so the emitter changed. `soroban_sdk::Vec::is_empty` exists (`soroban-sdk-26.1.0/src/vec.rs:835`). The contracts job now lints the generated crates directly; clippy does not lint dependencies, so nothing before this covered them. |
| `rustfmt.toml`, theirs | Emitted into the generated crate, option for option from their v0.7.2 file, and emission derives its layout from those settings rather than piping output through rustfmt — which would put the rustfmt version among the inputs to every shipped wasm hash. `cargo +nightly fmt --all -- --check`, the command their `CONTRIBUTING.md` step 4 prescribes, is now the same gate ours runs. |
| Imports: `imports_granularity = "Crate"`, `group_imports` | One grouped `use` per crate (`render::use_statement`), which is what their config produces and what both sibling examples show (`threshold-policy/src/contract.rs:8-12`, `spending-limit-policy/src/contract.rs:18-22`). |
| Module file layout: root + `contract.rs` | `src/lib.rs` is `#![no_std]` and a `pub mod contract;`; the contract is `src/contract.rs`. |
| Canonical section delimiters | `// ################## NAME ##################`, eighteen hashes each side. The **names** are theirs verbatim — ERRORS and EVENTS from `smart_account/mod.rs:532`, `:574`; CONSTANTS, QUERY STATE and CHANGE STATE from every policy module; HELPER FUNCTIONS from `policies/spending_limit.rs:445`. The **order** is ours, and divergence 8 says why: no upstream file declares all of these in one place, so there is no order of theirs to copy. `STORAGE KEYS` is a name of our own (divergence 8). |
| Storage keys named `<Module>StorageKey` | `PolicyStorageKey`, replacing the tutorial's `DataKey`; compare `SimpleThresholdStorageKey` (`policies/simple_threshold.rs:121`). |
| Doc comment on every public item | The error enum and all eleven variants, the storage-key enum, the contract struct, the associated type, and all five entry points. |
| `# Errors` on every public function that can panic, in their section order | `# Arguments` → `# Errors` → `# Events` → `# Notes`, and the list is **built from the rule's shape** rather than copied: a policy with no validity window does not document `RuleExpired`, one with no cap does not document `CallCountExceeded`. `each_entry_point_documents_exactly_the_refusals_its_body_can_raise` compares each list against the emitted `panic_with_error!` calls in both directions. |
| Events, `#[contractevent]`, `#[topic]` first, `# Events` documented | `GeneratedPolicyInstalled` / `Enforced` / `Uninstalled`, `smart_account` as the single topic, `context_rule_id` in the data, and the enforcement event also carrying what it permitted and the remaining call count — their shape (§6), with `spending_limit`'s `total_spent_in_period` as the analogue for ours. What it permitted is a digest rather than the `Context`, which is divergence 9. |
| Getters in an inherent `#[contractimpl]` block | `is_installed` and, where a cap exists, `remaining_calls`; compare `threshold-policy/src/contract.rs:62-78` and `spending-limit-policy/src/contract.rs:67-87`. |
| TTL on read: the caller-managed-state exception, not the extend-on-read rule | `:344` states the rule for **library-managed** entries; `:376-381` states the exception, and this artifact is the exception. A generated policy's entries are created by the smart account's `install` and destroyed by its `uninstall`, exactly as pausable's instance state is managed by the contract using it — so, like `paused()`, neither getter calls `extend_ttl`, and both carry the explanatory `// NOTE:` the pattern asks for, citing the clause. §3 has the argument. The one thing here that *is* a divergence is withholding the write-path extension once a call cap is spent (divergence 2). |
| `[package.metadata.stellar] cargo_inherit`, `doctest = false` | Both emitted into the manifest. |
| Panic only through `panic_with_error!`; no `unwrap` in non-test code | Held from the start, and `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]` on the *generator* (`crates/codegen/src/lib.rs:13`) is what keeps it that way on our side of the line. |
| Event assertions through the typed struct | `contracts/differential/tests/events.rs` compares each emitted entry with `Event::to_xdr`, the form their checklist prescribes; hand-decoding topics and data is a violation there, and would also let a wrong topic pass. |
| Panic tests by numeric code | Already the convention in `contracts/differential/tests/`, e.g. `Error::from_contract_error(9)` for `RuleExpired`. |

### What we deliberately diverge on

Each of these is a decision, not an omission, and each is written here because it reads as an
omission unless stated.

**1. Error codes 1–11, not a block at 3230.** Their policies take ten-wide blocks in order —
`simple_threshold` 3200–3203 (`policies/simple_threshold.rs:110-116`), `weighted_threshold`
3210–3214 (`policies/weighted_threshold.rs:141-149`), `spending_limit` 3220–3227
(`policies/spending_limit.rs:126-140`), with `SmartAccountError` itself running 3000–3016
(`smart_account/mod.rs:540-571`, overflowing its own block). The scheme is nowhere documented in
the crate, so the next free block is exactly 3230 — which is where *their* next policy goes.
"Conforming" here would have meant claiming the slot their next module needs.

There is no protocol-level reason to match either. A Soroban contract error is a bare `u32`
(`InvokeError::Contract(u32)`); the SDK reserves no ranges; and since `MAX_POLICIES = 5`
(`smart_account/mod.rs:524`) our policy and their `spending_limit` genuinely can sit on one
context rule — where the account invokes policies through the plain client method
(`PolicyClient::new(e, &policy).enforce(…)`, `smart_account/storage.rs:510`; `install` at `:692`
and again at `:1139` inside `add_policy`; `uninstall` is the one that uses `try_uninstall`, at
`:870` and at `:1195` inside `remove_policy`), so a refusal surfaces as the bare number with no
contract id attached to disambiguate it. **Distinct numbers are therefore better for
attribution, not merely tolerable.** And ours are load-bearing in their own right: 1–11 are the
published deny-reason contract, asserted by an independently written reference evaluator
(`contracts/differential/tests/differential.rs`), so renumbering speculatively would break a
checked property for no gain.

**2. A dynamic `ttl_target`, not fixed `*_EXTEND_AMOUNT` / `*_TTL_THRESHOLD` constants.** Their
pattern is a pair of constants per module (`policies/simple_threshold.rs:127-129`). Ours computes
the target from the network's rolling `max_ttl()` intersected with the rule's own validity window,
and withholds the extension once a call cap is spent. That buys a property constants cannot
express: an extension provably never reaches past the window, and never happens at all for an
installation that can no longer permit anything. Eleven TTL tests pin it
(`contracts/differential/tests/ttl.rs`), and §3 is the full argument — including why a rule with
no validity window, which has no ceiling for the intersection to find, still has no
unauthenticated path to an extension.

**3. Everything inlined in the trait impl, not delegated to a library module.** Each of their
policies is one module in `src/policies/` exposing free functions — `simple_threshold.rs`,
`weighted_threshold.rs`, `spending_limit.rs` — which the example contract's trait impl delegates
to. (`src/policies/` has no `storage.rs`; the `mod.rs` + `storage.rs` pair is `src/smart_account/`,
which is not a policy.) A generated policy cannot delegate anywhere: the claim this project rests
on is that the wasm is a pure function of the spec, and a shared library module would put code in
the artifact that no spec chose and that a spec change cannot move. The `# Errors` sections carry
the documentation those free functions would have carried.

**4. No setters and no upgrade entry point,** where all three sibling policies have setters
(`simple_threshold::set_threshold`, `:235`). This is security posture: a limit that can be changed
after review is a limit nobody reviewed, and immutability is what makes the wasm hash a statement
about behaviour rather than about a starting state. It is also why there is no `*Changed` event —
there is nothing to change. §8 covers it.

**5. `crate-type = ["lib", "cdylib"]`,** where their *example policies* declare `cdylib` alone —
though `stellar-accounts` itself declares the same pair, so this departs from their examples and
not from the library. The extra `lib` is what lets a generated crate be linked into a test
process and compared against the reference evaluator without going through the wasm host, which
is how the differential suite works at all. It is emitted for every generated policy, including
those nothing links yet; the emitted manifest says that rather than claiming a link that crate
does not have.

**6. No `#![allow(dead_code)]` in the crate root,** which their example roots carry. A suppression
is a violation of their own lint rule; ours is not needed, because the emitter never emits an
unused item and `unbalanced_constants` exists to prove it.

**7. Its own workspace root, with inline `=` pins,** where their packages use
`field.workspace = true` and `{ workspace = true }`. A generated crate ships standalone — there is
no workspace to inherit from — and the exact pins are what make its wasm hash reproducible by
someone who was not the generator. §2 covers the provenance chain this belongs to.

**8. `STORAGE KEYS` as a section name, and a section order of our own.** The delimiter *names* are
theirs; the sequence is not, and neither is that heading. No upstream file declares errors,
storage keys, constants, events, both entry-point groups and private helpers together:
`smart_account/mod.rs` runs CONSTANTS → ERRORS → EVENTS, `storage.rs` runs QUERY STATE → CHANGE
STATE → SIGNER MANAGEMENT → POLICY MANAGEMENT → HELPERS, and each policy module runs CONSTANTS →
QUERY STATE → CHANGE STATE with its error enum, event structs and storage-key enum in an
**undelimited preamble** above the first heading. A generated file has no undelimited region — it
opens with a delimiter, so that a reader can tell a section boundary from the top of the file —
which is why the storage-key enum needs a heading upstream never gives it. The order the emitter
uses instead is declarations before the code that reads them and exports before the arithmetic
they are built from; only the errors-then-storage-keys pair is taken directly from upstream, where
those two enums appear in that order in all three policy modules.

**9. The enforcement event names the `Context` by a hash instead of embedding it.** *New in this
review, and the only entry on this list that fixes a defect rather than declining a convention —
one we had inherited by mirroring their shape faithfully.*

All three of their policies embed the whole authorization in their enforce event:
`pub context: Context` at `policies/spending_limit.rs:49`, `simple_threshold.rs:62` and
`weighted_threshold.rs:78`. §6 above mirrored that deliberately. The shape carries a defect, and
it is ours as much as theirs for the commit that copied it.

A `Context::Contract` holds every invocation argument
(`ContractContext { contract, fn_name, args }`, `soroban-sdk-26.1.0/src/auth.rs:44-48`), so the
event's size is the *caller's* to choose wherever a rule leaves an argument unconstrained. Ours
do: `AnyValue` is the maximal widening, and a policy scoped to
`swap_exact_tokens_for_tokens` needs it for the caller-chosen `deadline`
(`crates/synthesizer/src/walkthroughs.rs:166`). Nothing bounded that payload against
`contract_events_size_bytes`, which mainnet meters at 16,384
(`soroban-sdk-26.1.0/src/testutils/cost_estimate.rs:147`, installed on every test environment at
`src/env.rs:719`).

**Reproduced** on the committed Soroswap policy at those default limits, with every argument at
the boundary the rule allows and a 20,000-byte value in the `AnyValue` position. Every policy
check passed and `enforce` reached its `publish`; the host then failed the invocation:

```text
contract events size bytes: 20508 > 16384
HostError: Error(Budget, ExceededLimit)
```

The host sums the emitted event bytes and compares them against the limit *after* the top-level
call has returned (`soroban-env-host-26.1.3/src/host/invocation_metering.rs:435-439`), then panics
(`:503-527`). So this is not a refusal a caller can read and act on: it is a budget error with no
`PolicyError` code, on a call the policy said yes to. **And the reference evaluator still reports
permit.** A disagreement between the evaluator and the artifact is the single failure mode every
gate in this repository exists to prevent, which is why this outranks any question of event shape.

**What the artifact does instead.** `GeneratedPolicyEnforced` carries
`context_hash: BytesN<32>` — `e.crypto().sha256(&context.to_xdr(e))` — in the field position their
`context` occupies. The event is then 264 bytes for every call the policy admits (§6), and a reader
who *holds* the authorization, from the transaction's own auth entries or from a simulation of it,
recomputes the digest and matches it to the event. What is given up is reading the arguments out of
the event alone; what is bought is that a permitted call is always publishable. The digest also lets
all three events derive `Clone, Debug, Eq, PartialEq`: `Context` implements none of the last three,
which is why all three of their `*Enforced` structs derive `Clone` alone and why ours did
until the field left.

One shape is worse than the caller-chosen one, and it is worth stating because it is not what
the reproduction used. `MAX_SCVAL_XDR_BYTES` is 64 KiB (`crates/policy-spec/src/lib.rs:44`), so a
validated spec may pin an *exact* `ScVal` of that size. A policy built from one would carry a
~64 KiB argument on its only admissible call, and an event embedding it would abort every permit
rather than the ones a caller chose to grow. No such crate is committed, so that is reasoning from
the validator's own ceiling rather than a measurement — but it is the reason the fix belongs on the
event and not on the arguments.

**Why not bound the arguments instead**, which is the other way to close it. An event-safe ceiling
on accepted argument sizes would have to be enforced identically by the spec, the generated
contract and the reference evaluator; it would add a twelfth reason to a published eleven-code deny
contract; it would change permit/deny for calls that are admissible today; and it would move every
spec hash, including the ones sealed into `docs/TESTNET-EVIDENCE.md`. Hashing changes what an event
*says* and nothing about what a policy *decides*, which is the smaller change by every measure that
matters here.

**What holds it.** The sweep runs against the committed generated Soroswap policy.
`contracts/differential/tests/event_payload.rs`: an admissible Soroswap call
swept over six `deadline` sizes from 0 to 65,536 bytes, asserting at each that the compiled
contract and the reference evaluator agree, that exactly one event is published, and that its
serialized size is identical at every size and below the limit. A sweep rather than one value,
because a single admissible argument is exactly what the suite had before and what let this
through. Three of the six sizes are under the limit and were publishable before the fix, so they
are the control that tells a red run from a broken one. Proved red by putting
`pub context: Context` back into the committed Soroswap crate: the two invariant tests then fail
with `contract events size bytes: 16508 > 16384` at the 16,000-byte size, and the non-vacuity test
still passes.

### Three upstream defects found while doing this

**Reportable, and the one worth reporting first: their own enforce events are unbounded.** This is
divergence 9 above, read as a finding about `stellar-accounts` rather than as a decision about our
emitter. `SpendingLimitEnforced`, `SimpleEnforced` and `WeightedEnforced` each embed a `Context`
(`policies/spending_limit.rs:49`, `simple_threshold.rs:62`, `weighted_threshold.rs:78`), and a
policy has no say in how large the authorization it is asked to approve is — the account passes it
whatever the caller signed. So any of their three policies, installed on a context rule for a
function with a large argument, publishes an event that can exceed
`contract_events_size_bytes` and fail a transaction it had approved. Their two threshold policies
additionally carry `authenticated_signers: Vec<Signer>`, which is bounded by `MAX_SIGNERS = 15`
(`smart_account/mod.rs:526`); the `Context` field is the unbounded one in all three.

Two things make it less severe for them than for us and neither removes it: their policies are
composed by an account whose other policies may bound the call, and they publish no
independently-implemented model that a divergence would contradict. What remains is a transaction
that fails on a resource limit rather than on a decision, at a size no reviewer of the policy would
think to check. The reproduction above is on a generated policy because that is the crate this
repository builds and tests; the field, the limit and the ordering are theirs unchanged, and the
fix — a digest, or any bounded projection of the context — is available to them at the same
cost.


**Reportable: their checklist's wasm build cannot succeed for any crate in their own workspace.**
Their `CONTRIBUTING.md:62` and `code-quality.md:150` both prescribe
`cargo build --target wasm32v1-none --release`. The workspace root enables soroban-sdk's
`experimental_spec_shaking_v2` (their workspace-root `Cargo.toml:55-57`), and that feature's
build script exits 1 on a
wasm target unless `SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2` is set — which
`stellar contract build` sets and `cargo build` does not
(`soroban-sdk-26.1.0/build.rs:26-46`). Reproduced here on a minimal crate that enables the
feature and nothing else: the build fails in the build script with *"requires stellar-cli
v25.2.0+"*, before compiling any of our code.

Nothing in their CI would notice: `generic.yml`'s `Check build` step is commented out
(`:80-82`, with a TODO about same-name functions across contracts — an unrelated reason), and the
only workflow that does build for wasm uses `stellar contract build`
(`publish-crates.yml:34`, `:79`). The command entered `CONTRIBUTING.md` through their issue #471,
which asked for `stellar contract build` **and/or** the cargo form. Searches of their tracker for
`experimental_spec_shaking`, `custom build command` and `build fails` return nothing, so this
appears unreported. The fix is one word in two documents.

**Not reportable, already fixed in flight:** their `CONTRIBUTING.md:99` links
`.claude/skills/code-quality.md` while the file is at `.claude/commands/code-quality.md` (there is
no `.claude/skills/` directory in the tree at all). Their open PR #836 already changes that exact
line, so it is recorded here only so a reader who follows the broken link knows it is known.

**Verdict.** Conforms on every rule their checklist states for a contract of this kind, with nine
divergences that are decisions rather than gaps — six forced by properties this project sells (a
pure function of the spec, a reproducible hash, an immutable limit, a checked deny-reason
contract), one by their own lint rule contradicting their own example, one by a generated file
having no undelimited preamble to put a storage-key enum in, and one — the newest, number 9 —
because the convention we mirrored turns a permitted call into a resource-limit failure at a large
enough argument.

One entry moved off this list while the section was being checked, and the direction is worth
recording. Extending TTL on a read was written up first as conformance, then as a divergence when
it turned out no upstream policy extends on a write, and is now conformance again — with the
getters extending *nothing* — because the rule at `:344` has an exception at `:376-381` that names
this exact shape. Reading half a clause produced a design that was coherent, bounded, tested, and
wrong: it made an unauthenticated `is_installed` a way for a third party to pay an installation's
rent, which the account can neither prevent nor want. The one thing this
section cannot substitute for is a review by the maintainers whose conventions these are; §7's
action 3 is the route to that for security, and a contribution upstream would be the route for
style.

## One thing we deliberately do not do

Reject a policy at generation time because `valid_until` exceeds `max_ttl()`. That bound is
sliding, measured from the current ledger, so a distant expiry is legitimate and is reached by
successive extensions; refusing it would cut off the long-lived grant the tool exists to produce
(§3, action 3).

---

## Sources

- [State archival — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival)
- [Persisting data — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/persisting-data) (the conditional extension guidance, and "TTL extensions should never be relied on for functionality or safety")
- [Choosing the right storage type — Stellar Docs](https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage)
- [Authorization — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization)
- [`contractmeta!` — soroban-sdk docs](https://docs.rs/soroban-sdk/latest/soroban_sdk/macro.contractmeta.html)
- [SEP-46 — Contract Meta (Active)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0046.md)
- [SEP-55 — Contract Build Verification (Draft)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0055.md)
- [SEP-58 — Contract Build Reproducibility for Verification (Draft, 0.6.0)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0058.md)
- SEP-58 support in `stellar-cli`, neither landed: [#2585 `--verifiable`, open](https://github.com/stellar/stellar-cli/pull/2585) · [#2586 `stellar contract verify`, closed unmerged on 2026-08-27](https://github.com/stellar/stellar-cli/pull/2586); the unshipped `build verify` spelling comes from [#2525, closed](https://github.com/stellar/stellar-cli/pull/2525)
- [stellar-experimental/contract-verifications](https://github.com/stellar-experimental/contract-verifications)
- [Contract code validation — StellarExpert](https://stellar.expert/explorer/public/contract/validation)
- [Contract Source Validation SEP — stellar/discussions#1573](https://github.com/orgs/stellar/discussions/1573)
- OpenZeppelin's contract conventions (§15): [`.claude/commands/code-quality.md`](https://github.com/OpenZeppelin/stellar-contracts/blob/main/.claude/commands/code-quality.md) · [`CONTRIBUTING.md`](https://github.com/OpenZeppelin/stellar-contracts/blob/main/CONTRIBUTING.md) · [`rustfmt.toml`](https://github.com/OpenZeppelin/stellar-contracts/blob/v0.7.2/rustfmt.toml) · the two sibling policy examples under [`examples/multisig-smart-account`](https://github.com/OpenZeppelin/stellar-contracts/tree/v0.7.2/examples/multisig-smart-account)
- [Contract Explorer — Stellar Docs](https://developers.stellar.org/docs/tools/lab/smart-contracts/contract-explorer)
- [OpenZeppelin stellar-contracts / accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts)
- [smart-account-kit](https://github.com/kalepail/smart-account-kit) · [passkey-kit](https://github.com/kalepail/passkey-kit)
- [Scout for Soroban — CoinFabrik (the analyzer, `cargo-scout-audit`)](https://github.com/CoinFabrik/scout-soroban) · [reviewed examples](https://github.com/CoinFabrik/scout-soroban-examples)
- [Soroban security checklist — Veridise](https://veridise.com/blog/audit-insights/building-on-stellar-soroban-grab-this-security-checklist-to-avoid-vulnerabilities/)
- [Soroban Security Audit Bank — Stellar](https://stellar.org/blog/developers/soroban-security-audit-bank-raising-the-standard-for-smart-contract-security)
- [serde_json_canonicalizer (JCS, for comparison)](https://docs.rs/serde_json_canonicalizer/latest/serde_json_canonicalizer/) · [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)
