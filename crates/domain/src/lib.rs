//! Shared domain vocabulary for the OZ Accounts Policy Builder.
//!
//! Architecture §4.11: this crate is pure — no I/O, no async, no framework deps.
//! Everything hashed in the toolkit goes through [`canonical_hash`] / [`canonical_hash_of`];
//! the `canonical` module documents the encoding rules, and `docs/CANONICAL-HASHING.md`
//! specifies them for an implementation that is not this crate.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

mod canonical;
pub mod target_adapters;
mod target_capture;
pub mod wide_int;
pub use canonical::{
    canonical_hash, canonical_hash_of, canonical_preimage_bytes, canonical_preimage_bytes_of,
    to_scval, MAX_CANONICAL_PREIMAGE_BYTES,
};
pub use target_capture::{TargetCapture, TargetEntry};

/// Canonicalization scheme version. Bumped whenever the canonical byte encoding of any
/// hashed structure changes; it participates in every full recording / spec hash.
///
/// **v2** encodes every hashed structure as an `ScVal` and hashes its XDR — see
/// the `canonical` module for the rules and `docs/CANONICAL-HASHING.md` for the specification an
/// external implementation follows. v1 hashed `serde_json` output, whose byte layout was
/// specified only by this crate's source, so nobody outside it could reproduce a hash.
pub const CANONICALIZATION_VERSION: u32 = 2;

/// Hash domains. Every hash in the toolkit is domain-separated so values from different
/// artifact kinds can never collide or be replayed across contexts.
///
/// One structure kind, one domain. A domain reused across two structures forfeits exactly the
/// separation this module exists to provide, and an unused constant is not evidence that some
/// other value belongs under it — it means the structure it names has not been hashed yet.
///
/// Adding a domain means adding it to [`ALL`](domains::ALL) as well;
/// `all_domains_are_declared_in_all` fails otherwise, so the list cannot silently fall behind
/// the constants.
pub mod domains {
    pub const TARGET_ADAPTER_SEMANTICS: &str = "ozpb:v1:target-adapter-semantics";
    pub const AUTH_FINGERPRINT: &str = "ozpb:v1:auth-fingerprint";
    pub const RECORDING: &str = "ozpb:v1:recording";
    pub const POLICY_SPEC: &str = "ozpb:v1:policy-spec";
    pub const SIGNER_SET: &str = "ozpb:v1:signer-set";
    pub const REGISTRY_SNAPSHOT: &str = "ozpb:v1:registry-snapshot";
    pub const CODEGEN_INPUT: &str = "ozpb:v1:codegen-input";
    pub const BUILD_MANIFEST: &str = "ozpb:v1:build-manifest";
    pub const POLICY_BINDING_SET: &str = "ozpb:v1:policy-binding-set";
    /// The full typed request for a state-dependent installed-policy check.
    pub const POLICY_CHECK_REQUEST: &str = "ozpb:v1:policy-check-request";
    /// Exact candidate, artifact claims and per-run nonce for a layered dry run.
    pub const DRY_RUN_REQUEST: &str = "ozpb:v1:dry-run-request";
    /// Ordered selected-rule constraint cases used by a layered dry run.
    pub const DRY_RUN_SUITE: &str = "ozpb:v1:dry-run-suite";
    /// Fixed XDR sequence defining a counterfactual execution network.
    pub const OFFLINE_EXECUTION: &str = "ozpb:v1:offline-execution";
    /// Complete typed NativeJob, including Wasm bytes and source ledger parameters.
    pub const NATIVE_EXECUTION_JOB: &str = "ozpb:v1:native-execution-job";
    /// Synthetic local candidate initialization descriptor, not captured live state.
    pub const NATIVE_INITIALIZATION: &str = "ozpb:v1:native-initialization";
    /// Sorted (ledger-key XDR, ledger-entry XDR, optional TTL) tuples.
    pub const NATIVE_STATE_ENTRIES: &str = "ozpb:v1:native-state-entries";
    /// Tuple of run hash, case ID and exact derived Case.
    pub const NATIVE_CASE_PAYLOAD: &str = "ozpb:v1:native-case-payload";
    /// Run hash used to derive a separate deterministic synthetic owner key.
    pub const NATIVE_BOOTSTRAP: &str = "ozpb:v1:local-bootstrap";
    /// Complete endpoint-reported `TargetCapture`: header, configuration, call and entries.
    pub const TARGET_CAPTURE: &str = "ozpb:v1:target-capture";
    /// Complete typed CapturedTargetJob: the native job plus its raw target capture.
    pub const CAPTURED_TARGET_JOB: &str = "ozpb:v1:captured-target-job";
    /// Ordered planned cases (ID, derived Case, exact call XDR, expected policy error) run
    /// against captured target state.
    pub const CAPTURED_TARGET_CASES: &str = "ozpb:v1:captured-target-cases";
    /// Capture hash plus fresh local candidate state for one captured-target run.
    pub const CAPTURED_INITIALIZATION: &str = "ozpb:v1:captured-initialization";
    /// The enumerated account rule-set a call-surface verdict was computed over.
    pub const ACCOUNT_STATE: &str = "ozpb:v1:account-state";
    /// Ordered raw account and policy-instance ledger values, TTLs, and omitted keys.
    pub const ACCOUNT_LEDGER_WITNESS: &str = "ozpb:v1:account-ledger-witness";
    /// Reviewed method inventory for an exact account Wasm hash.
    pub const ACCOUNT_METHOD_INVENTORY: &str = "ozpb:v1:account-method-inventory";
    /// A generated crate's source files, lockfile excluded — the value a BuildManifest records
    /// as `source_hash`.
    pub const GENERATED_SOURCE: &str = "ozpb:v1:generated-source";
    /// A generated crate's complete emitted file set, lockfile included. Used only to derive the
    /// stub builder's placeholder wasm deterministically; it attests nothing, and has its own
    /// domain because it hashes a different structure than [`GENERATED_SOURCE`] — reusing that
    /// one because the two look similar is how a domain comes to mean two things.
    pub const GENERATED_CRATE_FILES: &str = "ozpb:v1:generated-crate-files";
    /// The `authority_commitment`: authority-relevant state plus the exact install intent, the
    /// value a wallet's approval binds to and its pre-signing re-read recomputes (§4.8, D7). Reaching for it to hash
    /// anything else would put two structures under one domain, which is the collision the
    /// separation exists to prevent.
    pub const SURFACE_VERDICT: &str = "ozpb:v1:surface-verdict";

    /// Every domain declared above, so the invariants can be asserted over the whole set
    /// rather than over whichever pair a test happened to name.
    pub const ALL: &[&str] = &[
        TARGET_ADAPTER_SEMANTICS,
        AUTH_FINGERPRINT,
        RECORDING,
        POLICY_SPEC,
        SIGNER_SET,
        REGISTRY_SNAPSHOT,
        CODEGEN_INPUT,
        BUILD_MANIFEST,
        POLICY_BINDING_SET,
        POLICY_CHECK_REQUEST,
        DRY_RUN_REQUEST,
        DRY_RUN_SUITE,
        OFFLINE_EXECUTION,
        NATIVE_EXECUTION_JOB,
        NATIVE_INITIALIZATION,
        NATIVE_STATE_ENTRIES,
        NATIVE_CASE_PAYLOAD,
        NATIVE_BOOTSTRAP,
        TARGET_CAPTURE,
        CAPTURED_TARGET_JOB,
        CAPTURED_TARGET_CASES,
        CAPTURED_INITIALIZATION,
        ACCOUNT_STATE,
        ACCOUNT_LEDGER_WITNESS,
        ACCOUNT_METHOD_INVENTORY,
        GENERATED_SOURCE,
        GENERATED_CRATE_FILES,
        SURFACE_VERDICT,
    ];
}

/// A 32-byte hash, hex-encoded in serialized form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        let bytes = hex::decode(s).map_err(|_| DomainError::InvalidHash(s.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DomainError::InvalidHash(s.to_string()))?;
        Ok(Hash32(arr))
    }
}

/// Reviewed upstream artifacts, pinned by exact wasm hash.
///
/// Why these live here rather than in `registry`: the capability registry and the shared test
/// fixtures must agree on them exactly, and `domain` is the only crate both already depend on.
/// Duplicating a hash in two places is how the two drift apart.
///
/// **Provenance — reproduce with these exact inputs or you will get a different hash.**
///
/// | | |
/// |---|---|
/// | Source | `github.com/OpenZeppelin/stellar-contracts`, `examples/multisig-smart-account/` |
/// | Tag | `v0.7.2` |
/// | Commit | `a9c42169000638da937577f592ebf61a7a3c94ca` |
/// | `stellar-accounts` | 0.7.2 · `soroban-sdk` 26.1.0 (the workspace pins at that tag) |
/// | Rust | **1.91.1** — this repo's pinned toolchain, NOT upstream's |
/// | Command | `stellar contract build` in each example directory |
/// | Stellar CLI | 27.0.0 |
///
/// Two things about this that are easy to get wrong.
///
/// **The hash depends on the compiler.** Upstream's `rust-toolchain.toml` says
/// `channel = "stable"`, so it floats. Built with rustc 1.97.1 the spending-limit policy
/// hashes to `161cdae2b2f6ae5df8b688e580ff5e4ad25c9adf45f167c0a0cffc2c74a1e932`; with our
/// pinned 1.91.1 it is the value below. Same source, same tag, same SDK. A pinned hash
/// without a pinned compiler is not reproducible, so these are built with *our* toolchain —
/// the same one that builds our generated policies and backs our reproducibility gates.
///
/// **These are not artifacts OpenZeppelin publishes.** The wrapper contracts are theirs
/// (`examples/multisig-smart-account/`), and the library they delegate to is covered by the
/// audits in that repository's `audits/` — but upstream attaches no wasm to its releases and
/// blesses no deployed instance, so any hash is somebody's build. These are ours, from their
/// source, reproducible from the table above. A registry entry may say that and no more.
pub mod pinned_upstream {
    use super::Hash32;

    /// OpenZeppelin's `SpendingLimitPolicyContract` — rolling-window spend cap. Understands
    /// only `transfer`, reads the amount from arg index 2, does not constrain the recipient.
    /// Deployable once and shared: its state is keyed by (smart account, context rule id).
    pub const OZ_SPENDING_LIMIT_POLICY_WASM: Hash32 = Hash32([
        0x4e, 0x67, 0xaa, 0x6c, 0xa2, 0x26, 0xd3, 0xc1, 0x61, 0x06, 0xff, 0x2d, 0x95, 0xf3, 0xb4,
        0x4a, 0x8e, 0xfa, 0xbc, 0x2f, 0x2a, 0x76, 0x55, 0x68, 0x39, 0x57, 0xe3, 0x55, 0x3e, 0xd6,
        0xa4, 0x0c,
    ]);

    /// OpenZeppelin's multisig smart-account example — the `__check_auth` implementation that
    /// invokes installed policies. One instance per user, since it holds their signers and rules.
    pub const OZ_SMART_ACCOUNT_WASM: Hash32 = Hash32([
        0xa1, 0x27, 0x47, 0xff, 0x6c, 0x13, 0x9d, 0xc1, 0x4f, 0xc2, 0xfd, 0x30, 0xd2, 0x00, 0xd6,
        0xbb, 0xb5, 0xda, 0x7b, 0x5d, 0x59, 0x81, 0x2c, 0x04, 0x7c, 0xe1, 0xf9, 0xca, 0xd2, 0x26,
        0xb2, 0x89,
    ]);

    /// OpenZeppelin's WebAuthn (passkey) signature verifier: a 65-byte uncompressed P-256 key,
    /// then an optional credential id it ignores. No storage, constructor, upgrade or admin; its
    /// Wasm imports no ledger functions, so it is immutable and stateless. Built from the same
    /// commit and toolchain as the others (`examples/multisig-smart-account/webauthn-verifier`,
    /// stellar-cli 27.0.0); the code with this hash is on testnet.
    pub const OZ_WEBAUTHN_VERIFIER_WASM: Hash32 = Hash32([
        0xe6, 0x3a, 0x03, 0x0d, 0x0f, 0x1a, 0x14, 0x81, 0xe3, 0x60, 0x59, 0xa4, 0x83, 0x7c, 0x43,
        0x30, 0x83, 0xb3, 0x3e, 0x70, 0x4c, 0x1f, 0x96, 0x25, 0xb7, 0x31, 0x47, 0x95, 0xb6, 0xd7,
        0x2b, 0x76,
    ]);

    /// OpenZeppelin's ed25519 signature verifier: exactly a 32-byte key. Immutable, stateless
    /// and shareable: it exports only `verify`, `canonicalize_key` and `batch_canonicalize_key`,
    /// and its Wasm imports only buffer, vector and crypto host functions — no ledger access —
    /// as read from the testnet copy of this exact code.
    pub const OZ_ED25519_VERIFIER_WASM: Hash32 = Hash32([
        0x60, 0xe8, 0x79, 0x8d, 0xb6, 0x10, 0xbd, 0xaf, 0x33, 0x70, 0xd3, 0x9e, 0xbd, 0xa5, 0x6e,
        0xe1, 0xdc, 0x2c, 0x15, 0xce, 0x1c, 0x3a, 0x9e, 0x28, 0xb5, 0x28, 0xbf, 0xa2, 0x4a, 0x06,
        0xb4, 0x77,
    ]);
}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl core::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash32::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Plain SHA-256 (used only where an external format fixes the hashing, e.g. network IDs).
pub fn sha256(payload: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(payload);
    Hash32(h.finalize().into())
}

/// Stellar network identity: the SHA-256 of the network passphrase — never a display name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkId(pub Hash32);

impl NetworkId {
    pub fn from_passphrase(passphrase: &str) -> Self {
        NetworkId(sha256(passphrase.as_bytes()))
    }
}

/// Well-known network passphrases (convenience; any passphrase is accepted).
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// A ledger sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LedgerSeq(pub u32);

/// Evidence trust level — architecture §4.1.
///
/// A **descriptive provenance label, not a capability**. The constructors below are public
/// and deserialization accepts every Phase 1 level, so any caller — in code or in JSON — can
/// attach `rpc_reported` or `trusted_indexer` to evidence it invented. Acquisition adapters
/// label what they did honestly; no private field in this type can force a direct library
/// caller to do the same. A consumer must therefore treat the label as a claim whose weight
/// comes from where the value crossed into the process: the toolkit downgrades every bundle
/// arriving as JSON to `self_supplied` before it can drive synthesis (`ozpb-toolkit`,
/// `synthesize_policy`), and synthesis itself gates only on
/// [`allows_synthesis`](TrustLevel::allows_synthesis) — beyond that gate the level is
/// recorded in the spec's evidence, never widening what is generated.
///
/// One guarantee **is** type-level: `ledger_verified` has no constructor and no accepted
/// wire form in Phase 1, so it cannot exist until a future inclusion-proof checker mints it
/// (a proof-checking typestate, per §4.11). A forged label can overclaim acquisition,
/// never proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustLevel(Level);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    RpcReported,
    TrustedIndexer,
    SelfSupplied,
    Incomplete,
}

impl TrustLevel {
    /// Fetched live from the configured RPC endpoint — trusted exactly as far as that
    /// endpoint is trusted ("reported", not proven).
    pub fn rpc_reported() -> Self {
        TrustLevel(Level::RpcReported)
    }

    /// Supplied by an explicitly configured, trusted historical backend.
    pub fn trusted_indexer() -> Self {
        TrustLevel(Level::TrustedIndexer)
    }

    /// User-imported; internally consistent but unverified. The default for pure imports.
    pub fn self_supplied() -> Self {
        TrustLevel(Level::SelfSupplied)
    }

    /// Missing evidence; synthesis restricted or refused.
    pub fn incomplete() -> Self {
        TrustLevel(Level::Incomplete)
    }

    pub fn as_str(&self) -> &'static str {
        match self.0 {
            Level::RpcReported => "rpc_reported",
            Level::TrustedIndexer => "trusted_indexer",
            Level::SelfSupplied => "self_supplied",
            Level::Incomplete => "incomplete",
        }
    }

    /// Whether evidence at this level may drive synthesis at all.
    pub fn allows_synthesis(&self) -> bool {
        !matches!(self.0, Level::Incomplete)
    }

    /// Weaken an unauthenticated provenance claim to `self_supplied` — the strongest level
    /// a serialized bundle can earn without an authenticated acquisition receipt.
    ///
    /// This can only ever lower a label. `incomplete` is *weaker* than `self_supplied`, so
    /// it survives untouched: evidence that was missing does not become present by crossing
    /// a wire, and assigning `self_supplied` unconditionally would promote it past
    /// [`Self::allows_synthesis`]. The match is exhaustive over the private discriminant on
    /// purpose — a future stronger level (`ledger_verified`) cannot be added without
    /// deciding here whether it survives this boundary.
    pub fn downgraded_to_self_supplied(self) -> Self {
        match self.0 {
            Level::Incomplete => self,
            Level::RpcReported | Level::TrustedIndexer | Level::SelfSupplied => {
                TrustLevel::self_supplied()
            }
        }
    }
}

impl Serialize for TrustLevel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TrustLevel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "rpc_reported" => Ok(TrustLevel::rpc_reported()),
            "trusted_indexer" => Ok(TrustLevel::trusted_indexer()),
            "self_supplied" => Ok(TrustLevel::self_supplied()),
            "incomplete" => Ok(TrustLevel::incomplete()),
            other => Err(serde::de::Error::custom(format!(
                "unknown or unmintable trust level: {other}"
            ))),
        }
    }
}

/// How much a user-approved widening unconstrains the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Low,
    Medium,
    High,
}

/// Constraint provenance — architecture §4.2. Every constraint carries one.
///
/// Externally tagged on purpose: serde ignores `deny_unknown_fields` for internally
/// tagged enums, and closed schemas are an architecture requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    /// Deep exact equality with the observed value: the default and the true minimum.
    ObservedExact,
    /// An explicit user decision naming the semantic role and bound direction.
    UserWidened {
        intent: String,
        blast_radius: BlastRadius,
    },
    /// Derived through a versioned contract adapter bound to a verified target code hash.
    AdapterDerived { adapter: String, code_hash: Hash32 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid 32-byte hex hash: {0}")]
    InvalidHash(String),
    #[error("serialization failure: {0}")]
    Serialization(String),
    #[error("canonical preimage exceeds the {0}-byte ceiling")]
    PreimageTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- domain-separated hashing -------------------------------------------------

    #[test]
    fn oversized_preimages_fail_as_the_size_budget_not_as_serialization() {
        let oversized = "x".repeat(MAX_CANONICAL_PREIMAGE_BYTES + 1);
        assert_eq!(
            canonical_hash(domains::POLICY_SPEC, &oversized).unwrap_err(),
            DomainError::PreimageTooLarge(MAX_CANONICAL_PREIMAGE_BYTES),
        );
    }

    #[test]
    fn same_payload_different_domain_gives_different_hash() {
        let a = canonical_hash(domains::AUTH_FINGERPRINT, &"payload").unwrap();
        let b = canonical_hash(domains::RECORDING, &"payload").unwrap();
        assert_ne!(a, b, "domain separation must isolate artifact kinds");
    }

    /// The property above, over the whole set rather than one hand-picked pair. Two domains
    /// sharing a string would silently merge two artifact kinds, and a test naming two
    /// constants cannot see it happen between any other two.
    #[test]
    fn all_domains_are_pairwise_distinct() {
        for (i, a) in domains::ALL.iter().enumerate() {
            for b in &domains::ALL[i + 1..] {
                assert_ne!(a, b, "two domains share the string {a:?}");
            }
        }
    }

    /// `ALL` must list every declared constant, or the check above silently stops covering the
    /// ones left out. Counted from the source text because Rust cannot enumerate a module's
    /// constants, and a hand-maintained list that nothing verifies is how it falls behind.
    #[test]
    fn all_domains_are_declared_in_all() {
        let source = include_str!("lib.rs");
        let module = source
            .split_once("pub mod domains {")
            .expect("the domains module must be findable in the source")
            .1;
        let module = module
            .split_once("\n}\n")
            .expect("the domains module must be terminated")
            .0;
        let declared = module.matches("pub const ").count() - 1; // minus ALL itself

        assert_eq!(
            declared,
            domains::ALL.len(),
            "{declared} domain constants are declared but ALL lists {}; a domain missing from \
             ALL is excluded from the distinctness check",
            domains::ALL.len()
        );
    }

    #[test]
    fn hashing_is_stable_across_calls() {
        let a = canonical_hash(domains::POLICY_SPEC, &"x").unwrap();
        let b = canonical_hash(domains::POLICY_SPEC, &"x").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn domain_boundary_is_unambiguous() {
        // The domain and the value are separate length-prefixed fields of the XDR preimage,
        // so ("ab", "c") cannot collide with ("a", "bc") the way a raw concatenation would.
        let a = canonical_hash("ab", &"c").unwrap();
        let b = canonical_hash("a", &"bc").unwrap();
        assert_ne!(a, b);
    }

    // --- network id ----------------------------------------------------------------

    #[test]
    fn testnet_network_id_matches_well_known_value() {
        // sha256("Test SDF Network ; September 2015") — the canonical testnet network ID.
        let id = NetworkId::from_passphrase(TESTNET_PASSPHRASE);
        assert_eq!(
            id.0.to_hex(),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    // --- Hash32 hex round-trip -------------------------------------------------------

    #[test]
    fn hash32_hex_round_trip() {
        let h = sha256(b"round-trip");
        let parsed = Hash32::from_hex(&h.to_hex()).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn hash32_rejects_bad_hex() {
        assert!(Hash32::from_hex("not-hex").is_err());
        assert!(Hash32::from_hex("abcd").is_err()); // too short
    }

    // --- trust levels ----------------------------------------------------------------

    #[test]
    fn trust_levels_serialize_to_expected_strings() {
        assert_eq!(TrustLevel::rpc_reported().as_str(), "rpc_reported");
        assert_eq!(TrustLevel::self_supplied().as_str(), "self_supplied");
        assert_eq!(TrustLevel::trusted_indexer().as_str(), "trusted_indexer");
        assert_eq!(TrustLevel::incomplete().as_str(), "incomplete");
    }

    #[test]
    fn trust_level_round_trips_through_serde() {
        let l = TrustLevel::rpc_reported();
        let json = serde_json::to_string(&l).unwrap();
        let back: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn ledger_verified_cannot_be_deserialized_in_phase_1() {
        // No proof checker exists yet, so this toolkit version must refuse to mint or
        // accept `ledger_verified` — it would be an unearned trust claim.
        let r: Result<TrustLevel, _> = serde_json::from_str("\"ledger_verified\"");
        assert!(r.is_err());
    }

    /// Downgrading is monotone: every level ends at most as trusted as it started, and
    /// `incomplete` is never raised to something a synthesis gate would accept.
    #[test]
    fn downgrading_to_self_supplied_never_raises_a_level() {
        for level in [
            TrustLevel::rpc_reported(),
            TrustLevel::trusted_indexer(),
            TrustLevel::self_supplied(),
        ] {
            assert_eq!(
                level.downgraded_to_self_supplied().as_str(),
                "self_supplied",
                "{} must weaken to self_supplied",
                level.as_str()
            );
        }
        let incomplete = TrustLevel::incomplete().downgraded_to_self_supplied();
        assert_eq!(
            incomplete.as_str(),
            "incomplete",
            "missing evidence must not become self_supplied by crossing a boundary"
        );
        assert!(!incomplete.allows_synthesis());
    }

    #[test]
    fn incomplete_evidence_does_not_allow_synthesis() {
        assert!(!TrustLevel::incomplete().allows_synthesis());
        assert!(TrustLevel::rpc_reported().allows_synthesis());
        assert!(TrustLevel::self_supplied().allows_synthesis());
    }

    // --- provenance -------------------------------------------------------------------

    #[test]
    fn provenance_serializes_with_tag_and_rejects_unknown_fields() {
        let p = Provenance::UserWidened {
            intent: "cap amount at 100".into(),
            blast_radius: BlastRadius::Medium,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"user_widened\""));
        // Unit variants serialize as plain strings.
        assert_eq!(
            serde_json::to_string(&Provenance::ObservedExact).unwrap(),
            "\"observed_exact\""
        );
        let bad = r#"{"user_widened":{"intent":"x","blast_radius":"low","surprise":1}}"#;
        let r: Result<Provenance, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "closed schemas reject unknown fields");
    }

    proptest::proptest! {
        #[test]
        fn hashing_never_panics(domain in "\\PC*", payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            // An unencodable input must surface as an Err, never as a panic.
            let _ = canonical_hash(&domain, &payload);
        }
    }
}
