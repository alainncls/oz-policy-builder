//! Capability registries (architecture §4.10) — Phase 1 subset.
//!
//! Signed, versioned snapshots keyed by reviewed wasm hash; the registry is a security
//! root, so it gets real governance: a pinned root key, monotonically increasing
//! versions with rollback/freeze rejection, a canonical root hash that downstream
//! artifacts pin, and **fail-closed** resolution — an unknown hash is an error, never a
//! guess. An address, package version, or claimed kind is never sufficient.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

// Verification is deliberately `verify_strict`, never the `Verifier` trait's `verify`: the
// strict path additionally rejects small-order public keys and small-order signature `R`
// points (see `VerifyingKey::verify_strict` in ed25519-dalek). Together with the weak-key
// rejection in `with_pinned_roots` this closes the constant-signature forgery under a
// small-order root. A change of signature library or version is a security-review event:
// re-check that both protections still hold.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ozpb_domain::pinned_upstream;
use ozpb_domain::{domains, Hash32, NetworkId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod account_methods;

pub const REGISTRY_SCHEMA: &str = "registry/v1";

// ---------------------------------------------------------------------------------------
// Snapshot model (all maps BTreeMap; canonical hashing)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    /// Monotonically increasing snapshot version (rollback/freeze rejection).
    #[serde(with = "ozpb_domain::wide_int")]
    pub version: u64,
    /// Append-only transparency sequence. A successor must increment this exactly once and
    /// commit to the previously accepted snapshot root.
    #[serde(with = "ozpb_domain::wide_int")]
    pub log_index: u64,
    pub previous_root: Option<Hash32>,
    pub network_id: NetworkId,
    /// Signed validity interval. Consumers supply their trusted current time to `load_at`;
    /// an expired or not-yet-valid snapshot never becomes a capability oracle.
    #[serde(with = "ozpb_domain::wide_int")]
    pub valid_from_unix: i64,
    #[serde(with = "ozpb_domain::wide_int")]
    pub expires_at_unix: i64,
    /// Reviewed policy implementations, keyed by exact wasm hash (hex).
    pub policies: BTreeMap<String, PolicyCapability>,
    /// Recognized account implementations, keyed by exact wasm hash (hex).
    pub accounts: BTreeMap<String, AccountCapability>,
    /// Trusted signature verifiers, keyed by exact wasm hash (hex).
    pub verifiers: BTreeMap<String, VerifierCapability>,
    /// Governance-reviewed target implementations bound to locally implemented argument
    /// semantics. Empty is omitted to preserve existing signed snapshot roots.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub target_adapters: BTreeMap<String, TargetAdapterCapability>,
    /// Audited template families (pre-build identity of generated policies).
    pub templates: BTreeMap<String, TemplateCapability>,
    /// Permanently recorded capability revocations, keyed as `policy/<hash>`,
    /// `account/<hash>`, `verifier/<hash>`, `target_adapter/<hash>`, or `template/<family>`.
    pub revocations: BTreeMap<String, Revocation>,
}

/// A governance assertion about an exact target code hash, not a ledger attestation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterCapability {
    pub implementation: String,
    pub semantics_digest: Hash32,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub reason: String,
    #[serde(with = "ozpb_domain::wide_int")]
    pub effective_version: u64,
}

/// What a reviewed policy implementation actually enforces — derived from reviewed
/// source, per exact wasm hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCapability {
    pub kind: String,
    /// Signer predicates this implementation enforces (e.g. "threshold"); an empty list
    /// means it enforces none and can never satisfy a spec's predicate on its own.
    pub signer_predicates: Vec<String>,
    /// Exported security-relevant methods (input to the Phase 2 call-surface algebra).
    pub security_relevant_methods: Vec<String>,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCapability {
    pub release: String,
    /// `onchain_list` | `bounded_next_id` | `verified_event_index` | `none` (§4.8).
    pub rule_enumeration: String,
    /// Release-specific management-ID evidence strategy (Decision D3).
    pub management_evidence: String,
    /// Optional signed operational contract for bounded account-state reads. Older
    /// snapshots remain parseable but cannot satisfy an authority-capability request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_next_id: Option<BoundedNextIdCapability>,
    /// Signed commitment to the complete locally reviewed method map for this exact
    /// account Wasm hash. The map itself is compiled from source review and checked by
    /// `resolve_account_authority`; a hash claim alone grants no capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_inventory_digest: Option<Hash32>,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedNextIdCapability {
    pub schema_version: u32,
    pub max_scan_ids: u32,
    pub max_rpc_batches: u32,
    pub max_transitive_entries: u32,
    pub max_attempts: u32,
    pub archive_policy: AccountArchivePolicy,
    pub snapshot_policy: AccountSnapshotPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountArchivePolicy {
    RejectUnresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSnapshotPolicy {
    /// Require matching endpoint ledger metadata across batches and a matching account
    /// instance on a final read. The endpoint remains the trust boundary.
    SameLedgerAndInstance,
}

/// Signed scan bounds and an exact-hash source-reviewed method table. This still says
/// nothing about the live account's rule state or the wallet's intended administrator.
#[derive(Clone, Debug)]
pub struct ResolvedAccountAuthority {
    pub scan: BoundedNextIdCapability,
    pub methods: account_methods::AccountMethodInventory,
}

/// Registry value for management-rule identity backed by matching return and event IDs.
pub const MANAGEMENT_EVIDENCE_RETURN_VALUE_AND_EVENTS_MUST_AGREE: &str =
    "return_value_and_events_must_agree";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierCapability {
    pub implementation: String,
    pub key_encoding: String,
    pub immutable: bool,
    /// The key scheme the reviewed implementation verifies, which fixes how a signer's key data
    /// maps to one owner identity. Absent on entries signed before the field existed (it is
    /// skipped when absent, so their roots are unchanged); such a verifier recognizes code but
    /// cannot vouch for an owner identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_scheme: Option<VerifierKeyScheme>,
    /// The reviewed implementation cannot change what it accepts after review: no ledger access
    /// (storage, its own code, deployment), no calls into other contracts, no reads of ledger
    /// context (`scripts/check-wasm-imports.py` against
    /// `tests/fixtures/stateless_verifier_imports.txt`). Absent means not established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateless: Option<bool>,
    pub review_reference: String,
}

/// The verifier implementations whose key handling was reviewed from source, by exact Wasm
/// hash. See [`Registry::resolve_signature_verifier`].
const REVIEWED_VERIFIER_SCHEMES: [(Hash32, VerifierKeyScheme); 2] = [
    (
        pinned_upstream::OZ_ED25519_VERIFIER_WASM,
        VerifierKeyScheme::Ed25519,
    ),
    (
        pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM,
        VerifierKeyScheme::WebauthnP256,
    ),
];

/// How a reviewed verifier reads a signer's key data, and so what one owner identity is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyScheme {
    /// Exactly 32 bytes: an ed25519 public key (OZ `verifiers::ed25519`, `BytesN<32>`).
    Ed25519,
    /// A 65-byte uncompressed P-256 public key (`0x04‖X‖Y`) followed by an optional credential
    /// id the verifier ignores (OZ `verifiers::webauthn::canonicalize_key`: the first 65 bytes).
    WebauthnP256,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCapability {
    /// Hash of the template pack's declared capability algebra.
    pub capability_schema: Hash32,
    pub signer_predicates: Vec<String>,
    pub constraint_kinds: Vec<String>,
    pub review_reference: String,
}

/// Pinned registry governance roots. Signer identifiers are stable operator-chosen labels;
/// the map shape makes duplicate signer counting impossible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicy {
    pub threshold: u32,
    pub keys: BTreeMap<String, [u8; 32]>,
}

/// Durable anti-rollback/equivocation state persisted by the registry consumer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCheckpoint {
    #[serde(with = "ozpb_domain::wide_int")]
    pub version: u64,
    #[serde(with = "ozpb_domain::wide_int")]
    pub log_index: u64,
    pub root: Hash32,
    /// Revocations accepted at this root. The root commits to them, but retaining the set is
    /// necessary to enforce append-only succession after a process restart.
    pub revocations: BTreeMap<String, Revocation>,
}

/// A snapshot plus its root signature (ed25519 over the canonical root hash).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub snapshot: RegistrySnapshot,
    pub signatures: BTreeMap<String, String>,
}

/// Canonical root hash of a snapshot (what artifacts pin as `registry_snapshot`).
pub fn snapshot_root(snapshot: &RegistrySnapshot) -> Result<Hash32, RegistryError> {
    ozpb_domain::canonical_hash(domains::REGISTRY_SNAPSHOT, snapshot)
        .map_err(|e| RegistryError::Internal(e.to_string()))
}

/// Sign a snapshot with a root key (bootstrap/ops tooling and tests).
///
/// This is a low-level signing primitive, **not** a validation gate: it hashes and signs any
/// freely constructed [`RegistrySnapshot`], running none of the schema, validity-interval,
/// key, revocation, cross-role, chain or root-policy checks that [`Registry::load_at`]
/// applies. It can therefore mint a cryptographically authentic snapshot that loading will
/// reject (this is deliberate — verifier tests need such snapshots). Release tooling must not
/// treat a produced [`SignedSnapshot`] as loadable: load-verify it under the intended pinned
/// [`RootPolicy`], network, and version/checkpoint before distributing it.
pub fn sign_snapshot(
    key: &SigningKey,
    snapshot: RegistrySnapshot,
) -> Result<SignedSnapshot, RegistryError> {
    sign_snapshot_with_roots(
        &BTreeMap::from([("legacy".to_string(), key.clone())]),
        snapshot,
    )
}

/// Sign with one or more independently identified governance roots. Production release
/// tooling supplies the threshold-approved subset; verification applies the pinned policy.
pub fn sign_snapshot_with_roots(
    keys: &BTreeMap<String, SigningKey>,
    snapshot: RegistrySnapshot,
) -> Result<SignedSnapshot, RegistryError> {
    let root = snapshot_root(&snapshot)?;
    let signatures = keys
        .iter()
        .map(|(id, key)| {
            let signature = key.sign(&root.0);
            (id.clone(), hex::encode(signature.to_bytes()))
        })
        .collect();
    Ok(SignedSnapshot {
        snapshot,
        signatures,
    })
}

// ---------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("E_REGISTRY_SIGNATURE: snapshot signatures do not satisfy the pinned root policy")]
    Signature,
    #[error("E_REGISTRY_ROOT_POLICY: {0}")]
    RootPolicy(String),
    #[error("E_REGISTRY_TRANSPARENCY: {0}")]
    Transparency(String),
    #[error("E_REGISTRY_SCHEMA: expected {REGISTRY_SCHEMA}, got {0}")]
    Schema(String),
    #[error(
        "E_REGISTRY_ROLLBACK: snapshot version {offered} does not advance the current \
         version {current} (rollback/freeze rejected)"
    )]
    Rollback { offered: u64, current: u64 },
    #[error("E_REGISTRY_NETWORK: expected network {expected}, snapshot is for {found}")]
    Network { expected: String, found: String },
    #[error(
        "E_REGISTRY_NOT_YET_VALID: snapshot validity starts at {valid_from}, current time is {now}"
    )]
    NotYetValid { valid_from: i64, now: i64 },
    #[error("E_REGISTRY_EXPIRED: snapshot expired at {expires_at}, current time is {now}")]
    Expired { expires_at: i64, now: i64 },
    #[error(
        "E_REGISTRY_VALIDITY: snapshot valid_from {valid_from} is after expires_at {expires_at}"
    )]
    Validity { valid_from: i64, expires_at: i64 },
    #[error("E_UNREGISTERED_POLICY: no reviewed policy entry for wasm hash {0}")]
    UnknownPolicy(String),
    #[error("E_INCOMPATIBLE_ACCOUNT: no recognized account entry for wasm hash {0}")]
    UnknownAccount(String),
    #[error("E_INCOMPATIBLE_ACCOUNT: authority capability for account wasm {0} is incomplete or disagrees with the reviewed implementation")]
    AccountAuthorityUnsupported(String),
    /// The signed entry names a rule-enumeration strategy the account-state model cannot
    /// execute (§4.8). Distinct from an incomplete capability: the entry may be accurate.
    #[error(
        "E_ACCOUNT_RULE_ENUMERATION_UNSUPPORTED: account wasm {wasm_hash} declares rule \
         enumeration '{method}'; this checker supports only bounded_next_id"
    )]
    AccountRuleEnumerationUnsupported { wasm_hash: String, method: String },
    #[error("E_UNREGISTERED_VERIFIER: no trusted verifier entry for wasm hash {0}")]
    UnknownVerifier(String),
    #[error(
        "E_UNREGISTERED_VERIFIER: verifier entry for wasm hash {0} does not establish an \
         immutable, stateless implementation with a known key scheme"
    )]
    VerifierCapabilityIncomplete(String),
    #[error("E_TARGET_ADAPTER_UNSUPPORTED: target adapter for wasm {0} has unknown or inconsistent semantics")]
    TargetAdapterUnsupported(String),
    #[error("E_UNREGISTERED_TEMPLATE: no audited template family named {0}")]
    UnknownTemplate(String),
    #[error("E_REGISTRY_REVOKED: capability {capability} is revoked: {reason}")]
    Revoked { capability: String, reason: String },
    #[error("E_REGISTRY_EMPTY: no snapshot loaded")]
    NotLoaded,
    #[error("E_REGISTRY_PARSE: {0}")]
    Parse(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Registry client with a pinned root key. Fail-closed everywhere.
///
/// **Verification happens at load, not at resolve.** [`Self::load_at`] checks the signature,
/// network, validity interval, rollback floor and transparency chain against the trusted time
/// supplied *then*; the `resolve_*` methods take no time and do not re-check `expires_at_unix`.
/// A `Registry` is therefore a snapshot verified as of its load time: a long-lived instance
/// will keep resolving capabilities after the snapshot expires, so a caller that caches one
/// across time must recheck with `ensure_valid_at` and reload if it has expired. The Phase 1
/// toolkit sidesteps this by constructing and loading a fresh registry per synthesis call.
pub struct Registry {
    root_keys: BTreeMap<String, VerifyingKey>,
    root_threshold: u32,
    expected_network: Option<NetworkId>,
    minimum_version: u64,
    pinned_checkpoint: Option<RegistryCheckpoint>,
    current: Option<Loaded>,
}

struct Loaded {
    snapshot: RegistrySnapshot,
    root: Hash32,
}

fn check_snapshot_validity(
    snapshot: &RegistrySnapshot,
    now_unix: i64,
) -> Result<(), RegistryError> {
    if snapshot.valid_from_unix > snapshot.expires_at_unix {
        return Err(RegistryError::Validity {
            valid_from: snapshot.valid_from_unix,
            expires_at: snapshot.expires_at_unix,
        });
    }
    if now_unix < snapshot.valid_from_unix {
        return Err(RegistryError::NotYetValid {
            valid_from: snapshot.valid_from_unix,
            now: now_unix,
        });
    }
    if now_unix > snapshot.expires_at_unix {
        return Err(RegistryError::Expired {
            expires_at: snapshot.expires_at_unix,
            now: now_unix,
        });
    }
    Ok(())
}

impl Registry {
    /// Single-root, no network, no rollback floor — the weakest construction in this type, and
    /// deliberately **not public**. An instance built this way accepts a correctly signed
    /// snapshot for *any* network and, having no persisted version floor or checkpoint, accepts
    /// an old one after a restart. It exists for this crate's own tests; the audit's cheapest
    /// resolution for the constructor footgun was to keep the weak variants private, and with
    /// no caller outside this file there is nothing to break. `cfg(test)` rather than
    /// `pub(crate)`: nothing in the shipped library uses it, so it should not exist there.
    #[cfg(test)]
    fn with_pinned_root(root_key_bytes: &[u8; 32]) -> Result<Self, RegistryError> {
        Self::with_pinned_roots(RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), *root_key_bytes)]),
        })
    }

    /// Pin a threshold root policy, and **nothing else**: no expected network and no rollback
    /// floor. This is now the weakest public constructor, and both omissions are load-bearing.
    ///
    /// - No network: a correctly signed snapshot for *any* Stellar network is accepted, so a
    ///   testnet snapshot loads in a mainnet process. Pin the network unless the caller
    ///   independently verifies `network_id` against the recording it will synthesize from.
    /// - No rollback floor: with neither a persisted minimum version nor a checkpoint, a fresh
    ///   process accepts an older but correctly signed snapshot — a rollback/freeze replay
    ///   across restarts. In-process monotonicity still holds once a snapshot is loaded.
    ///
    /// Production consumers should use [`Self::with_pinned_roots_for_network_at_version`] or
    /// [`Self::with_pinned_roots_for_network_at_checkpoint`]. This variant stays public for
    /// validating a root policy on its own — the toolkit uses it to reject a bad operator
    /// configuration at startup, before any snapshot exists — and for offline tooling that
    /// checks network and version by other means.
    ///
    /// Root keys are validated here: threshold within `1..=keys.len()`, no empty signer id, no
    /// key repeated under two ids, every key a well-formed non-small-order ed25519 point.
    pub fn with_pinned_roots(policy: RootPolicy) -> Result<Self, RegistryError> {
        if policy.threshold == 0 || policy.threshold as usize > policy.keys.len() {
            return Err(RegistryError::RootPolicy(format!(
                "threshold {} is not within 1..={} trusted roots",
                policy.threshold,
                policy.keys.len()
            )));
        }
        if policy.keys.keys().any(|id| id.is_empty()) {
            return Err(RegistryError::RootPolicy(
                "root signer identifiers must not be empty".to_string(),
            ));
        }
        let unique_keys: std::collections::BTreeSet<[u8; 32]> =
            policy.keys.values().copied().collect();
        if unique_keys.len() != policy.keys.len() {
            return Err(RegistryError::RootPolicy(
                "the same root key must not appear under multiple signer identifiers".to_string(),
            ));
        }
        let root_keys = policy
            .keys
            .into_iter()
            .map(|(id, bytes)| {
                let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                    RegistryError::RootPolicy("invalid ed25519 root key".to_string())
                })?;
                // A small-order ("weak") public key verifies a forgeable constant signature
                // for almost every message; accepting one as a governance root would let a
                // single malformed or adversarial key entry defeat the whole threshold
                // policy. Root configuration is exactly the boundary this constructor
                // validates, so reject the key here rather than trusting later verification.
                if key.is_weak() {
                    // `{id:?}` rather than `{id}`: signer ids come from operator-supplied JSON,
                    // and this string reaches logs and terminals. Debug formatting escapes
                    // control characters and makes whitespace visible, so an id cannot forge log
                    // lines or hide as blank text. Same reason `validate_template_family` quotes
                    // the family it rejects. Bounding id length/charset belongs with the
                    // deferred registry limits, not here.
                    return Err(RegistryError::RootPolicy(format!(
                        "root key {id:?} is a small-order (weak) ed25519 point and can never \
                         carry a governance approval"
                    )));
                }
                Ok((id, key))
            })
            .collect::<Result<_, _>>()?;
        Ok(Registry {
            root_keys,
            root_threshold: policy.threshold,
            expected_network: None,
            minimum_version: 0,
            pinned_checkpoint: None,
            current: None,
        })
    }

    /// Construct a registry verifier pinned to a governance root and one Stellar network,
    /// but with **no persisted rollback floor**. Because it carries no minimum version or
    /// checkpoint, a fresh process built this way will accept an old but correctly signed
    /// snapshot — a rollback/freeze replay after restart. It is therefore not the production
    /// constructor: production consumers must persist anti-rollback state across processes and
    /// use [`Self::with_pinned_roots_for_network_at_version`] or
    /// [`Self::with_pinned_roots_for_network_at_checkpoint`]. This variant is for offline
    /// migration/bootstrap tooling and single-process tests where no prior snapshot exists to
    /// roll back to. Kept **crate-private** for that reason: it had no caller outside this
    /// file, so restricting it costs nothing and removes the footgun from the public surface.
    #[cfg(test)]
    fn with_pinned_root_for_network(
        root_key_bytes: &[u8; 32],
        expected_network: NetworkId,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_root(root_key_bytes)?;
        registry.expected_network = Some(expected_network);
        Ok(registry)
    }

    /// Construct with a version floor persisted by the caller across processes. Without a
    /// persisted floor, an old but correctly signed snapshot could be replayed after restart.
    pub fn with_pinned_root_for_network_at_version(
        root_key_bytes: &[u8; 32],
        expected_network: NetworkId,
        minimum_version: u64,
    ) -> Result<Self, RegistryError> {
        Self::with_pinned_roots_for_network_at_version(
            RootPolicy {
                threshold: 1,
                keys: BTreeMap::from([("legacy".to_string(), *root_key_bytes)]),
            },
            expected_network,
            minimum_version,
        )
    }

    pub fn with_pinned_roots_for_network_at_version(
        policy: RootPolicy,
        expected_network: NetworkId,
        minimum_version: u64,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_roots(policy)?;
        registry.expected_network = Some(expected_network);
        registry.minimum_version = minimum_version;
        Ok(registry)
    }

    pub fn with_pinned_roots_for_network_at_checkpoint(
        policy: RootPolicy,
        expected_network: NetworkId,
        checkpoint: RegistryCheckpoint,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_roots(policy)?;
        registry.expected_network = Some(expected_network);
        registry.minimum_version = checkpoint.version;
        registry.pinned_checkpoint = Some(checkpoint);
        Ok(registry)
    }

    /// Verify and load a signed snapshot. Enforces schema, signature under the pinned
    /// root, and strictly increasing versions (a re-offered or older snapshot is a
    /// rollback/freeze attempt and is rejected).
    pub fn load(&mut self, signed: &SignedSnapshot) -> Result<Hash32, RegistryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            .as_secs()
            .try_into()
            .map_err(|_| RegistryError::Internal("system time exceeds i64".to_string()))?;
        self.load_at(signed, now)
    }

    /// Verify and load at a caller-supplied trusted time. This makes expiry tests and offline
    /// verification deterministic while keeping the validity decision explicit.
    ///
    /// Signature policy is **strict on every supplied signature**, by design: each entry must
    /// name a configured signer and verify, and any unknown id or invalid signature rejects the
    /// whole snapshot even if a valid trusted threshold is otherwise present. This is
    /// fail-closed input handling, not threshold counting that ignores extras — a snapshot
    /// carrying an unrecognized or malformed signature is treated as malformed. It grants an
    /// attacker no new authorization (one who can add or alter a signature in transit can also
    /// remove a required one); the trade is that an altered optional extra signature can
    /// invalidate an otherwise-valid quorum. Keep supplied signatures to the configured roots.
    pub fn load_at(
        &mut self,
        signed: &SignedSnapshot,
        now_unix: i64,
    ) -> Result<Hash32, RegistryError> {
        if signed.snapshot.schema != REGISTRY_SCHEMA {
            return Err(RegistryError::Schema(signed.snapshot.schema.clone()));
        }
        let root = snapshot_root(&signed.snapshot)?;
        if signed.signatures.len() < self.root_threshold as usize {
            return Err(RegistryError::Signature);
        }
        let mut valid_signatures = 0u32;
        for (id, encoded) in &signed.signatures {
            let key = self.root_keys.get(id).ok_or(RegistryError::Signature)?;
            let sig_bytes: [u8; 64] = hex::decode(encoded)
                .map_err(|_| RegistryError::Signature)?
                .try_into()
                .map_err(|_| RegistryError::Signature)?;
            let signature = Signature::from_bytes(&sig_bytes);
            // Strict verification: defense in depth behind the constructor's weak-key
            // rejection (see the module-level note on the ed25519-dalek import).
            key.verify_strict(&root.0, &signature)
                .map_err(|_| RegistryError::Signature)?;
            valid_signatures = valid_signatures.saturating_add(1);
        }
        if valid_signatures < self.root_threshold {
            return Err(RegistryError::Signature);
        }

        if let Some(expected) = self.expected_network {
            if signed.snapshot.network_id != expected {
                return Err(RegistryError::Network {
                    expected: expected.0.to_hex(),
                    found: signed.snapshot.network_id.0.to_hex(),
                });
            }
        }
        check_snapshot_validity(&signed.snapshot, now_unix)?;
        validate_capability_keys(&signed.snapshot)?;
        for (capability, revocation) in &signed.snapshot.revocations {
            if revocation.reason.trim().is_empty() {
                return Err(RegistryError::Parse(
                    "revocations require a capability key and non-empty reason".to_string(),
                ));
            }
            if revocation.effective_version > signed.snapshot.version {
                return Err(RegistryError::Parse(format!(
                    "revocation {capability} becomes effective after snapshot version {}",
                    signed.snapshot.version
                )));
            }
        }

        if signed.snapshot.version < self.minimum_version {
            return Err(RegistryError::Rollback {
                offered: signed.snapshot.version,
                current: self.minimum_version,
            });
        }
        if self.current.is_none() {
            if let Some(checkpoint) = &self.pinned_checkpoint {
                if signed.snapshot.version == checkpoint.version {
                    if root != checkpoint.root
                        || signed.snapshot.log_index != checkpoint.log_index
                        || signed.snapshot.revocations != checkpoint.revocations
                    {
                        return Err(RegistryError::Transparency(format!(
                            "snapshot version {} conflicts with the persisted checkpoint",
                            checkpoint.version
                        )));
                    }
                } else {
                    let expected_index = checkpoint.log_index.checked_add(1).ok_or_else(|| {
                        RegistryError::Transparency("log index overflow".to_string())
                    })?;
                    if signed.snapshot.log_index != expected_index
                        || signed.snapshot.previous_root != Some(checkpoint.root)
                    {
                        return Err(RegistryError::Transparency(format!(
                            "snapshot does not directly extend persisted checkpoint {}",
                            checkpoint.root
                        )));
                    }
                    ensure_revocations_extend(
                        &checkpoint.revocations,
                        &signed.snapshot.revocations,
                    )?;
                }
            }
        }
        if let Some(current) = &self.current {
            if signed.snapshot.version <= current.snapshot.version {
                return Err(RegistryError::Rollback {
                    offered: signed.snapshot.version,
                    current: current.snapshot.version,
                });
            }
            let expected_index = current
                .snapshot
                .log_index
                .checked_add(1)
                .ok_or_else(|| RegistryError::Transparency("log index overflow".to_string()))?;
            if signed.snapshot.log_index != expected_index {
                return Err(RegistryError::Transparency(format!(
                    "expected log index {expected_index}, got {}",
                    signed.snapshot.log_index
                )));
            }
            if signed.snapshot.previous_root != Some(current.root) {
                return Err(RegistryError::Transparency(format!(
                    "snapshot does not extend the previously accepted root {}",
                    current.root
                )));
            }
            ensure_revocations_extend(&current.snapshot.revocations, &signed.snapshot.revocations)?;
        }
        self.current = Some(Loaded {
            snapshot: signed.snapshot.clone(),
            root,
        });
        Ok(root)
    }

    /// Parse and load a signed snapshot from JSON.
    ///
    /// **Parsing is not resource-bounded, and this crate publishes no registry limits.** The
    /// string is deserialized into unbounded maps, vectors and strings before any check runs;
    /// signer identifiers and the signature map are unbounded too. The 4 MiB ceiling in the
    /// canonical encoder is *not* a mitigation for this: it bounds the **hash preimage**, so it
    /// stops the hash from covering megabytes, but only after the whole input has been parsed
    /// and materialized. Measured: a 6.3 MB snapshot JSON parses completely and then fails
    /// during canonicalization, and it fails as [`RegistryError::Internal`] — which the toolkit
    /// maps to the wire code `E_INTERNAL`, so a caller's oversized input is reported as an
    /// internal server fault rather than a stable input error.
    ///
    /// A hosted deployment must therefore bound the request body itself; note the MCP server's
    /// cap is operator-settable *above* the preimage ceiling, so this path is reachable in a
    /// supported configuration, not merely in theory. Composable registry limits (encoded
    /// bytes, entries per map, signature count, identifier/value lengths) with a stable
    /// input-error code are deferred, not implemented.
    pub fn load_json(&mut self, json: &str) -> Result<Hash32, RegistryError> {
        let signed: SignedSnapshot =
            serde_json::from_str(json).map_err(|e| RegistryError::Parse(e.to_string()))?;
        self.load(&signed)
    }

    /// As [`Self::load_json`], at a caller-supplied trusted time. The same unbounded-parsing
    /// caveat applies.
    pub fn load_json_at(&mut self, json: &str, now_unix: i64) -> Result<Hash32, RegistryError> {
        let signed: SignedSnapshot =
            serde_json::from_str(json).map_err(|e| RegistryError::Parse(e.to_string()))?;
        self.load_at(&signed, now_unix)
    }

    /// Recheck the loaded, signature-verified snapshot's interval at a trusted current time.
    /// This neither reloads capabilities nor changes the version/checkpoint state. Cached
    /// consumers must call it before relying on capabilities after long-running work.
    pub fn ensure_valid_at(&self, now_unix: i64) -> Result<(), RegistryError> {
        check_snapshot_validity(&self.loaded()?.snapshot, now_unix)
    }

    pub fn root(&self) -> Result<Hash32, RegistryError> {
        Ok(self.loaded()?.root)
    }

    pub fn checkpoint(&self) -> Result<RegistryCheckpoint, RegistryError> {
        let loaded = self.loaded()?;
        Ok(RegistryCheckpoint {
            version: loaded.snapshot.version,
            log_index: loaded.snapshot.log_index,
            root: loaded.root,
            revocations: loaded.snapshot.revocations.clone(),
        })
    }

    pub fn resolve_policy(&self, wasm_hash: &Hash32) -> Result<&PolicyCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("policy", &wasm_hash.to_hex())?;
        l.snapshot
            .policies
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownPolicy(wasm_hash.to_hex()))
    }

    pub fn resolve_account(&self, wasm_hash: &Hash32) -> Result<&AccountCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("account", &wasm_hash.to_hex())?;
        l.snapshot
            .accounts
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownAccount(wasm_hash.to_hex()))
    }

    /// Resolve authority metadata only when the signed account entry commits to the
    /// supported scan protocol and the exact source-reviewed method inventory. This
    /// is a code-capability check, not an observation of account state.
    pub fn resolve_account_authority(
        &self,
        wasm_hash: &Hash32,
    ) -> Result<ResolvedAccountAuthority, RegistryError> {
        let capability = self.resolve_account(wasm_hash)?;
        let unsupported = || RegistryError::AccountAuthorityUnsupported(wasm_hash.to_hex());
        if capability.rule_enumeration != "bounded_next_id" {
            return Err(RegistryError::AccountRuleEnumerationUnsupported {
                wasm_hash: wasm_hash.to_hex(),
                method: capability.rule_enumeration.clone(),
            });
        }
        let scan = capability.bounded_next_id.clone().ok_or_else(unsupported)?;
        if scan.schema_version != 1
            || !(1..=10_000).contains(&scan.max_scan_ids)
            || !(1..=128).contains(&scan.max_rpc_batches)
            || !(1..=10_000).contains(&scan.max_transitive_entries)
            || !(1..=3).contains(&scan.max_attempts)
        {
            return Err(unsupported());
        }
        let claimed = capability.method_inventory_digest.ok_or_else(unsupported)?;
        // The compiled table was reviewed for one exact build. A signed entry under any
        // other hash cannot borrow it, even when it commits to the same digest.
        if *wasm_hash != pinned_upstream::OZ_SMART_ACCOUNT_WASM {
            return Err(unsupported());
        }
        let methods = account_methods::source_reviewed_oz_multisig_candidate();
        let actual = ozpb_domain::canonical_hash(domains::ACCOUNT_METHOD_INVENTORY, &methods)
            .map_err(|error| RegistryError::Internal(error.to_string()))?;
        if actual != claimed {
            return Err(unsupported());
        }
        Ok(ResolvedAccountAuthority { scan, methods })
    }

    pub fn resolve_verifier(
        &self,
        wasm_hash: &Hash32,
    ) -> Result<&VerifierCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("verifier", &wasm_hash.to_hex())?;
        l.snapshot
            .verifiers
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownVerifier(wasm_hash.to_hex()))
    }

    /// A verifier that may vouch for an owner identity: reviewed for this exact code, with an
    /// established key scheme, immutable and stateless. Recognizing the code is not enough on
    /// its own: an entry missing any of the three cannot say whose signature it accepts.
    ///
    /// The scheme is also compiled in per exact pinned hash, as the account method inventory
    /// is: a signed entry can recognize other code, but it cannot make that code an owner
    /// verifier, nor claim a scheme the reviewed source does not implement.
    pub fn resolve_signature_verifier(
        &self,
        wasm_hash: &Hash32,
    ) -> Result<VerifierKeyScheme, RegistryError> {
        let capability = self.resolve_verifier(wasm_hash)?;
        let reviewed = REVIEWED_VERIFIER_SCHEMES
            .iter()
            .find(|(hash, _)| hash == wasm_hash)
            .map(|(_, scheme)| *scheme);
        match (
            capability.immutable,
            capability.stateless,
            capability.key_scheme,
            reviewed,
        ) {
            (true, Some(true), Some(scheme), Some(reviewed)) if scheme == reviewed => Ok(scheme),
            _ => Err(RegistryError::VerifierCapabilityIncomplete(
                wasm_hash.to_hex(),
            )),
        }
    }

    /// No binding preserves exact synthesis. A revoked binding remains refused even if
    /// its entry was removed from the current snapshot.
    pub fn resolve_target_adapter(
        &self,
        wasm_hash: &Hash32,
    ) -> Result<Option<ozpb_domain::target_adapters::AdapterSemantics>, RegistryError> {
        let loaded = self.loaded()?;
        self.ensure_active("target_adapter", &wasm_hash.to_hex())?;
        let Some(binding) = loaded.snapshot.target_adapters.get(&wasm_hash.to_hex()) else {
            return Ok(None);
        };
        let unsupported = || RegistryError::TargetAdapterUnsupported(wasm_hash.to_hex());
        let semantics = ozpb_domain::target_adapters::implemented(&binding.implementation)
            .ok_or_else(unsupported)?;
        let digest = semantics
            .digest()
            .map_err(|e| RegistryError::Internal(e.to_string()))?;
        if digest != binding.semantics_digest || binding.review_reference.trim().is_empty() {
            return Err(unsupported());
        }
        Ok(Some(semantics))
    }

    pub fn resolve_template(&self, family: &str) -> Result<&TemplateCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("template", family)?;
        l.snapshot
            .templates
            .get(family)
            .ok_or_else(|| RegistryError::UnknownTemplate(family.to_string()))
    }

    fn loaded(&self) -> Result<&Loaded, RegistryError> {
        self.current.as_ref().ok_or(RegistryError::NotLoaded)
    }

    fn ensure_active(&self, kind: &str, identity: &str) -> Result<(), RegistryError> {
        let capability = format!("{kind}/{identity}");
        if let Some(revocation) = self.loaded()?.snapshot.revocations.get(&capability) {
            return Err(RegistryError::Revoked {
                capability,
                reason: revocation.reason.clone(),
            });
        }
        Ok(())
    }
}

fn ensure_revocations_extend(
    previous: &BTreeMap<String, Revocation>,
    next: &BTreeMap<String, Revocation>,
) -> Result<(), RegistryError> {
    for (capability, accepted) in previous {
        match next.get(capability) {
            Some(candidate) if candidate == accepted => {}
            Some(_) => {
                return Err(RegistryError::Transparency(format!(
                    "revocation {capability} was modified after acceptance"
                )))
            }
            None => {
                return Err(RegistryError::Transparency(format!(
                    "revocation {capability} was removed after acceptance"
                )))
            }
        }
    }
    Ok(())
}

fn validate_capability_keys(snapshot: &RegistrySnapshot) -> Result<(), RegistryError> {
    for (kind, keys) in [
        ("policy", snapshot.policies.keys().collect::<Vec<_>>()),
        ("account", snapshot.accounts.keys().collect::<Vec<_>>()),
        ("verifier", snapshot.verifiers.keys().collect::<Vec<_>>()),
        (
            "target_adapter",
            snapshot.target_adapters.keys().collect::<Vec<_>>(),
        ),
    ] {
        for key in keys {
            if !is_canonical_hash(key) {
                return Err(RegistryError::Parse(format!(
                    "{kind} capability key must be exactly 64 lowercase hexadecimal characters: {key}"
                )));
            }
        }
    }
    // The code-hash maps are role-separated so a hash resolves to exactly one kind; a
    // hash listed under two roles would let `resolve_*` hand back a capability of the wrong
    // kind for the same wasm. Governance signs the snapshot, so this guards against ambiguous
    // reviewed metadata rather than an untrusted request, but the confusion it prevents is one
    // the registry's own conformance language promises against — enforce it at load, not only
    // for the shipped dev fixture.
    // Probed rather than collected into sets: the maps are already keyed and sorted, so a
    // membership probe needs no allocation on a path that runs on every load. `or_else` keeps
    // the pairs lazy, so the first collision stops further scans.
    let collision = first_shared_key(&snapshot.policies, &snapshot.accounts)
        .map(|hash| (hash, "policy", "account"))
        .or_else(|| {
            first_shared_key(&snapshot.policies, &snapshot.verifiers)
                .map(|hash| (hash, "policy", "verifier"))
        })
        .or_else(|| {
            first_shared_key(&snapshot.accounts, &snapshot.verifiers)
                .map(|hash| (hash, "account", "verifier"))
        })
        .or_else(|| {
            first_shared_key(&snapshot.policies, &snapshot.target_adapters)
                .map(|hash| (hash, "policy", "target_adapter"))
        })
        .or_else(|| {
            first_shared_key(&snapshot.accounts, &snapshot.target_adapters)
                .map(|hash| (hash, "account", "target_adapter"))
        })
        .or_else(|| {
            first_shared_key(&snapshot.verifiers, &snapshot.target_adapters)
                .map(|hash| (hash, "verifier", "target_adapter"))
        });
    if let Some((shared, left_kind, right_kind)) = collision {
        // Phrased without indefinite articles so no kind needs "a"/"an" agreement — the
        // previous wording read "both a policy and a account".
        return Err(RegistryError::Parse(format!(
            "wasm hash {shared} is registered under two capability roles, \
             {left_kind} and {right_kind}"
        )));
    }
    for family in snapshot.templates.keys() {
        validate_template_family(family)?;
    }
    for capability in snapshot.revocations.keys() {
        let (kind, identity) = capability.split_once('/').ok_or_else(|| {
            RegistryError::Parse(format!(
                "revocation key must be kind/identity, got {capability}"
            ))
        })?;
        match kind {
            "policy" | "account" | "verifier" | "target_adapter" if is_canonical_hash(identity) => {
            }
            "template" => validate_template_family(identity)?,
            "policy" | "account" | "verifier" | "target_adapter" => {
                return Err(RegistryError::Parse(format!(
                    "revocation {capability} must contain a canonical wasm hash"
                )))
            }
            _ => {
                return Err(RegistryError::Parse(format!(
                    "revocation {capability} uses an unknown capability kind"
                )))
            }
        }
    }
    Ok(())
}

/// The lowest key present in both maps, or `None` if they are disjoint.
///
/// Scans the smaller map and probes the larger, so the cost is `O(min · log max)` with no
/// allocation. Both maps are sorted, so the first key found is the smallest shared one whichever
/// side is scanned — the reported hash stays deterministic, which matters because it appears in
/// an error message that tests and operators read.
fn first_shared_key<'a, L, R>(
    left: &'a BTreeMap<String, L>,
    right: &'a BTreeMap<String, R>,
) -> Option<&'a String> {
    if left.len() <= right.len() {
        left.keys().find(|key| right.contains_key(*key))
    } else {
        right.keys().find(|key| left.contains_key(*key))
    }
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_template_family(family: &str) -> Result<(), RegistryError> {
    if family.is_empty()
        || family.len() > 128
        || !family.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.' | b'@')
        })
    {
        return Err(RegistryError::Parse(format!(
            "template family is empty, too long, or non-canonical: {family:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Phase 1 development snapshot (deterministic; used by tests and the local toolchain)
// ---------------------------------------------------------------------------------------

pub mod dev {
    use super::*;
    use ozpb_domain::sha256;
    use ozpb_policy_spec::{Constraint, PredicateKind};

    /// Version of the committed, signed development example. Versions 1 to 3 remain
    /// historical parents; changing their contents would fork persisted checkpoints. The same
    /// holds for this version once published, so tests pin every root.
    pub const SIGNED_EXAMPLE_VERSION: u64 = 5;

    /// Deterministic development root key (NOT a production root; production roots are
    /// threshold-held and pinned at release time).
    pub fn dev_signing_key() -> SigningKey {
        SigningKey::from_bytes(&sha256(b"ozpb-dev-registry-root-key-v1").0)
    }

    /// The two trust documents a caller needs to run the pipeline against this snapshot: the
    /// signed snapshot, and the root policy that authenticates it.
    ///
    /// Returned as text rather than written to disk so the CLI and the drift test share one
    /// source. The copies committed under `docs/examples/` are what a reader actually runs, and
    /// a command that regenerated them immediately before use would repair drift instead of
    /// reporting it — so the demo consumes the committed files and `examples_are_current.rs`
    /// asserts they still match this.
    ///
    /// The signature key id must stay in step with [`crate::sign_snapshot`] (`legacy`), or
    /// verification fails with `E_REGISTRY_SIGNATURE` and no indication why.
    pub fn dev_trust_files(
        network_id: NetworkId,
        version: u64,
    ) -> Result<(String, String), RegistryError> {
        let snapshot = match version {
            5 => soroswap_deadline_successor(network_id)?,
            4 => soroswap_router_successor(network_id)?,
            3 => verifier_successor(network_id)?,
            2 => account_authority_successor(network_id)?,
            other => dev_snapshot(network_id, other),
        };
        let signed = crate::sign_snapshot(&dev_signing_key(), snapshot)?;
        let snapshot_json = serde_json::to_string_pretty(&signed)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            + "\n";
        let roots = serde_json::json!({
            "threshold": 1,
            "keys": { "legacy": hex::encode(dev_root_verifying_bytes()) },
        });
        let roots_json = serde_json::to_string_pretty(&roots)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            + "\n";
        Ok((snapshot_json, roots_json))
    }

    /// Public half of [`dev_signing_key`]: development-only, because anyone can sign with
    /// it. The operator account reader in `ozpb-source-rpc` refuses it outside testnet.
    pub fn dev_root_verifying_bytes() -> [u8; 32] {
        dev_signing_key().verifying_key().to_bytes()
    }

    /// Extend the original development snapshot with reviewed code-capability
    /// metadata for the pinned account. This signs no live state or administrator
    /// intent and cannot authorize a public `Safe` verdict.
    pub fn account_authority_successor(
        network_id: NetworkId,
    ) -> Result<RegistrySnapshot, RegistryError> {
        let previous = dev_snapshot(network_id, 1);
        let mut snapshot = dev_snapshot(network_id, 2);
        snapshot.previous_root = Some(snapshot_root(&previous)?);
        let account = snapshot
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .ok_or_else(|| {
                RegistryError::Internal("pinned development account is absent".into())
            })?;
        account.bounded_next_id = Some(BoundedNextIdCapability {
            schema_version: 1,
            max_scan_ids: 1_000,
            max_rpc_batches: 16,
            max_transitive_entries: 1_000,
            max_attempts: 2,
            archive_policy: AccountArchivePolicy::RejectUnresolved,
            snapshot_policy: AccountSnapshotPolicy::SameLedgerAndInstance,
        });
        account.method_inventory_digest = Some(
            ozpb_domain::canonical_hash(
                domains::ACCOUNT_METHOD_INVENTORY,
                &account_methods::source_reviewed_oz_multisig_candidate(),
            )
            .map_err(|error| RegistryError::Internal(error.to_string()))?,
        );
        Ok(snapshot)
    }

    /// Version 3: version 2 plus what lets a verifier vouch for an owner identity. The ed25519
    /// verifier gains its key scheme and statelessness; OpenZeppelin's WebAuthn (passkey)
    /// verifier joins, built from the same pinned commit and toolchain (provenance in
    /// [`ozpb_domain::pinned_upstream`]). Both are reviewed as storage-free with no upgrade
    /// path: their Wasm imports no ledger functions, so nothing they accept can change.
    pub fn verifier_successor(network_id: NetworkId) -> Result<RegistrySnapshot, RegistryError> {
        let previous = account_authority_successor(network_id)?;
        let mut snapshot = previous.clone();
        snapshot.version = 3;
        snapshot.log_index = 3;
        snapshot.previous_root = Some(snapshot_root(&previous)?);
        let ed25519 = snapshot
            .verifiers
            .get_mut(&pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex())
            .ok_or_else(|| {
                RegistryError::Internal("pinned development verifier is absent".into())
            })?;
        ed25519.key_scheme = Some(VerifierKeyScheme::Ed25519);
        ed25519.stateless = Some(true);
        ed25519
            .review_reference
            .push_str(" Exports only verify, canonicalize_key and batch_canonicalize_key; its Wasm imports no ledger functions (read from the testnet copy of this exact code), so it is stateless and cannot upgrade itself.");
        snapshot.verifiers.insert(
            pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex(),
            VerifierCapability {
                implementation: "oz webauthn (passkey) verifier".to_string(),
                key_encoding: "65-byte uncompressed P-256 public key, then an optional \
                               credential id the verifier ignores"
                    .to_string(),
                immutable: true,
                key_scheme: Some(VerifierKeyScheme::WebauthnP256),
                stateless: Some(true),
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/webauthn-verifier @ v0.7.2 (a9c4216), built here with rustc 1.91.1 and stellar-cli 27.0.0 — provenance in ozpb_domain::pinned_upstream. No storage, constructor, upgrade or admin; Wasm imports no ledger functions. Our build of their source, not an upstream-published artifact."
                    .to_string(),
            },
        );
        Ok(snapshot)
    }

    /// Version 4: version 3 plus the reviewed Soroswap router binding, so synthesis derives the
    /// W3 router's input bound and caller-chosen deadline from `soroswap-router@1` instead of
    /// the harness writing them as user decisions. It binds the testnet router's exact code.
    /// The root key is public and that code was not reproduced from source, so the entry is a
    /// development-registry assertion and says so; governance review is not claimed.
    pub fn soroswap_router_successor(
        network_id: NetworkId,
    ) -> Result<RegistrySnapshot, RegistryError> {
        use ozpb_domain::target_adapters;
        let previous = verifier_successor(network_id)?;
        let mut snapshot = previous.clone();
        snapshot.version = 4;
        snapshot.log_index = 4;
        snapshot.previous_root = Some(snapshot_root(&previous)?);
        let semantics = target_adapters::soroswap_router();
        snapshot.target_adapters.insert(
            target_adapters::SOROSWAP_ROUTER_TESTNET_WASM.to_hex(),
            TargetAdapterCapability {
                semantics_digest: semantics
                    .digest()
                    .map_err(|error| RegistryError::Internal(error.to_string()))?,
                implementation: semantics.name,
                review_reference: "Development-registry assertion, not governance: anyone can sign with this snapshot's development root. Roles of swap_exact_tokens_for_tokens read from the public router source, soroswap/core contracts/router at tag v1.0 (unchanged since 8a35511): amount_in is the exact input taken from `to`, amount_out_min an absolute output floor, path the exact route, `to` both payer and recipient and the only address asked to authorize, deadline compared with the ledger timestamp only. The deployed testnet code (router CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD) was not reproduced byte for byte: a rebuild with rustc 1.83.0 and soroban-sdk 20.2.0, the versions its metadata names, optimized as soroban-cli 22.0.1 does, differs only in the order of seven internal functions. See docs/TARGET-ADAPTERS.md."
                    .to_string(),
            },
        );
        Ok(snapshot)
    }

    /// Version 5 preserves v4 and replaces its router binding with v2's exact deadline.
    pub fn soroswap_deadline_successor(
        network_id: NetworkId,
    ) -> Result<RegistrySnapshot, RegistryError> {
        use ozpb_domain::target_adapters;
        let previous = soroswap_router_successor(network_id)?;
        let mut snapshot = previous.clone();
        snapshot.version = 5;
        snapshot.log_index = 5;
        snapshot.previous_root = Some(snapshot_root(&previous)?);
        let semantics = target_adapters::soroswap_router_v2();
        let binding = snapshot
            .target_adapters
            .get_mut(&target_adapters::SOROSWAP_ROUTER_TESTNET_WASM.to_hex())
            .ok_or_else(|| RegistryError::Internal("historical router binding is absent".into()))?;
        binding.implementation = semantics.name.clone();
        binding.semantics_digest = semantics
            .digest()
            .map_err(|error| RegistryError::Internal(error.to_string()))?;
        binding.review_reference.push_str(" Version 2 preserves the recorded deadline exactly instead of widening it; its input cap and other argument roles are unchanged.");
        Ok(snapshot)
    }

    /// A Phase 1 snapshot: the scope template family, a pinned spending-limit hash, a
    /// pinned account hash, and a pinned ed25519 verifier hash. The three wasm hashes are
    /// **real**, built from OpenZeppelin's own example contracts at a pinned tag — see
    /// [`ozpb_domain::pinned_upstream`] for the exact provenance and how to reproduce them.
    /// What remains a development stand-in is the *signing root*: [`dev_signing_key`] is
    /// derived from a fixed string, so this snapshot authenticates against a key anyone can
    /// recompute. A production deployment supplies its own governance root.
    pub fn dev_snapshot(network_id: NetworkId, version: u64) -> RegistrySnapshot {
        let mut policies = BTreeMap::new();
        policies.insert(
            pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex(),
            PolicyCapability {
                kind: "oz:spending_limit".to_string(),
                // The reviewed source requires >=1 authenticated signer but enforces no
                // configured predicate — it can never satisfy a spec predicate alone.
                signer_predicates: vec![],
                security_relevant_methods: vec![
                    "install".into(),
                    "enforce".into(),
                    "uninstall".into(),
                    "set_spending_limit".into(),
                ],
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/spending-limit-policy @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Upstream publishes no wasm, so this is our reproducible build of their source, not an artifact they signed."
                    .to_string(),
            },
        );
        let mut accounts = BTreeMap::new();
        accounts.insert(
            pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex(),
            AccountCapability {
                release: "stellar-accounts@0.7.x".to_string(),
                rule_enumeration: "bounded_next_id".to_string(),
                management_evidence:
                    MANAGEMENT_EVIDENCE_RETURN_VALUE_AND_EVENTS_MUST_AGREE.to_string(),
                bounded_next_id: None,
                method_inventory_digest: None,
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/account @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Our build of their source, not an upstream-published artifact."
                    .to_string(),
            },
        );
        let mut verifiers = BTreeMap::new();
        verifiers.insert(
            pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex(),
            VerifierCapability {
                implementation: "oz ed25519 verifier".to_string(),
                key_encoding: "raw ed25519 public key (32 bytes)".to_string(),
                immutable: true,
                key_scheme: None,
                stateless: None,
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/ed25519-verifier @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Our build of their source, not an upstream-published artifact."
                    .to_string(),
            },
        );
        let mut templates = BTreeMap::new();
        templates.insert(
            "policy-templates/scope@1".to_string(),
            TemplateCapability {
                capability_schema: sha256(b"policy-templates/scope@1:capability-algebra"),
                // Taken from the types a spec is built from, not written out here. Both used
                // to be hand-written literals, and both were wrong in both directions:
                // `strict_signer_set` is a `bool` on `AuthorizationSpec` and
                // `call_count_per_installation` is a `StateSpec` — neither is a kind a rule
                // can choose — while `any_of_current_rule_signers` and `any_value`, which
                // are, were missing. Nothing failed, because the only test compared the
                // literal against a second literal.
                //
                // Deriving them removes that whole class: `KINDS` and the `kind_name` a
                // checker reads are generated from one exhaustive list in `ozpb-policy-spec`,
                // so a new variant is a compile error there and this entry grows with it. The
                // scope template implements the full vocabulary of both types; a future
                // family that implements a subset would name that subset instead, which is
                // what makes these lists worth declaring at all.
                signer_predicates: PredicateKind::KINDS
                    .iter()
                    .map(|kind| (*kind).to_string())
                    .collect(),
                constraint_kinds: Constraint::KINDS
                    .iter()
                    .map(|kind| (*kind).to_string())
                    .collect(),
                review_reference: "audited with the template pack".to_string(),
            },
        );
        RegistrySnapshot {
            schema: REGISTRY_SCHEMA.to_string(),
            version,
            log_index: version,
            previous_root: None,
            network_id,
            valid_from_unix: i64::MIN,
            expires_at_unix: i64::MAX,
            policies,
            accounts,
            verifiers,
            target_adapters: BTreeMap::new(),
            templates,
            revocations: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_policy_spec::{Constraint, PredicateKind};

    #[test]
    fn historical_development_root_is_immutable() {
        let old = dev::dev_snapshot(
            NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            1,
        );
        assert_eq!(
            snapshot_root(&old).unwrap().to_hex(),
            "2957b9b07f55b960a58711c1935cb341dc5fe0b3f568b9bce85bbebfb9af0807"
        );
    }

    #[test]
    fn target_adapter_map_is_preserved_in_signed_snapshot_payload() {
        let mut wire = serde_json::to_value(dev::dev_snapshot(network(), 1)).unwrap();
        wire["target_adapters"] = serde_json::json!({
            "11".repeat(32): {"implementation":"soroswap-router@1", "semantics_digest":"22".repeat(32),
                "review_reference":"https://example.invalid/synthetic-fixture-review"}
        });
        let parsed: RegistrySnapshot = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), wire);
    }

    /// The committed signed example is published: an operator may have persisted a checkpoint
    /// at its root. Regenerating different contents under the same version would fork that
    /// checkpoint while `examples_are_current` passes, so new contents need a new
    /// `SIGNED_EXAMPLE_VERSION` that extends this root, and a new pin here.
    #[test]
    fn published_signed_example_root_is_immutable() {
        const PUBLISHED_V2_ROOT: &str =
            "4474ec405262f83c3d125cffde8f362eefcf4c90120cefa5cae74aec4e929ed9";
        const PUBLISHED_V3_ROOT: &str =
            "a035495a8a898ba123c0d63c3eedc2f433666110a32f5f56fd089f8c0663803f";
        const PUBLISHED_V4_ROOT: &str =
            "177de9ef770500e7f268c7e2692916c01e8dc031104d456f358d0c0a681548cf";
        assert_eq!(
            dev::SIGNED_EXAMPLE_VERSION,
            5,
            "a new signed example version must pin its own published root here"
        );
        // Version 2 is a published parent: the verifier fields it never carried must not move
        // its root, which is why they are skipped when absent.
        let v2 = dev::account_authority_successor(network()).unwrap();
        assert_eq!(
            snapshot_root(&v2).unwrap().to_hex(),
            PUBLISHED_V2_ROOT,
            "published development example v2 changed; publish new contents as a new version"
        );
        let v3 = dev::verifier_successor(network()).unwrap();
        assert_eq!(
            snapshot_root(&v3).unwrap().to_hex(),
            PUBLISHED_V3_ROOT,
            "published development example v3 changed; publish new contents as a new version"
        );
        assert_eq!(v3.previous_root, Some(snapshot_root(&v2).unwrap()));
        let v4 = dev::soroswap_router_successor(network()).unwrap();
        assert_eq!(
            snapshot_root(&v4).unwrap().to_hex(),
            PUBLISHED_V4_ROOT,
            "published development example v4 changed; publish new contents as a new version"
        );
        assert_eq!(v4.previous_root, Some(snapshot_root(&v3).unwrap()));
        let v5 = dev::soroswap_deadline_successor(network()).unwrap();
        assert_eq!(v5.previous_root, Some(snapshot_root(&v4).unwrap()));
        let committed: SignedSnapshot =
            serde_json::from_str(include_str!("../../../docs/examples/registry.signed.json"))
                .unwrap();
        assert_eq!(v5, committed.snapshot);
        assert_eq!(
            snapshot_root(&v5).unwrap().to_hex(),
            "3e7c6ca88af0aa98b9153986d07a8e871538991981a82fe2406550187e18f5a6"
        );
    }

    /// A verifier vouches for an owner identity only when its entry says how it reads keys
    /// and that nothing it accepts can change; recognizing its code is not enough.
    #[test]
    fn signature_verifiers_need_a_scheme_and_must_be_immutable_and_stateless() {
        let v2 = sign_snapshot(
            &dev::dev_signing_key(),
            dev::account_authority_successor(network()).unwrap(),
        )
        .unwrap();
        let v3 = sign_snapshot(
            &dev::dev_signing_key(),
            dev::verifier_successor(network()).unwrap(),
        )
        .unwrap();
        let mut registry = pinned_test_registry();
        registry.load_at(&v2, 100).unwrap();
        // Recognized code, but v2 never said how it reads keys.
        assert!(registry
            .resolve_verifier(&pinned_upstream::OZ_ED25519_VERIFIER_WASM)
            .is_ok());
        assert_eq!(
            registry.resolve_signature_verifier(&pinned_upstream::OZ_ED25519_VERIFIER_WASM),
            Err(RegistryError::VerifierCapabilityIncomplete(
                pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex()
            ))
        );
        // v3 directly extends a persisted v2.
        registry.load_at(&v3, 100).unwrap();
        assert_eq!(
            registry.resolve_signature_verifier(&pinned_upstream::OZ_ED25519_VERIFIER_WASM),
            Ok(VerifierKeyScheme::Ed25519)
        );
        assert_eq!(
            registry.resolve_signature_verifier(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM),
            Ok(VerifierKeyScheme::WebauthnP256)
        );

        // Each of the three properties is required on its own.
        for edit in [
            |c: &mut VerifierCapability| c.immutable = false,
            |c: &mut VerifierCapability| c.stateless = Some(false),
            |c: &mut VerifierCapability| c.stateless = None,
            |c: &mut VerifierCapability| c.key_scheme = None,
        ] {
            let mut snapshot = dev::verifier_successor(network()).unwrap();
            edit(
                snapshot
                    .verifiers
                    .get_mut(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex())
                    .unwrap(),
            );
            let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
            let mut fresh = pinned_test_registry();
            fresh.load_at(&signed, 100).unwrap();
            assert!(matches!(
                fresh.resolve_signature_verifier(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM),
                Err(RegistryError::VerifierCapabilityIncomplete(_))
            ));
        }
    }

    #[test]
    fn committed_development_successor_extends_a_persisted_v3_checkpoint() {
        let roots = || RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
        };
        let v1 = sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let v2 = sign_snapshot(
            &dev::dev_signing_key(),
            dev::account_authority_successor(network()).unwrap(),
        )
        .unwrap();
        let v3 = sign_snapshot(
            &dev::dev_signing_key(),
            dev::verifier_successor(network()).unwrap(),
        )
        .unwrap();
        let committed: SignedSnapshot =
            serde_json::from_str(include_str!("../../../docs/examples/registry.signed.json"))
                .unwrap();
        assert_eq!(committed.snapshot.version, dev::SIGNED_EXAMPLE_VERSION);

        // An operator persisted a checkpoint at v3: the committed v4 extends it directly.
        let mut registry = pinned_test_registry();
        for signed in [&v1, &v2, &v3] {
            registry.load_at(signed, 100).unwrap();
        }
        let v3_checkpoint = registry.checkpoint().unwrap();
        let v4 = sign_snapshot(
            &dev::dev_signing_key(),
            dev::soroswap_router_successor(network()).unwrap(),
        )
        .unwrap();
        assert_eq!(v4.snapshot.previous_root, Some(v3_checkpoint.root));
        let mut restored = Registry::with_pinned_roots_for_network_at_checkpoint(
            roots(),
            network(),
            v3_checkpoint,
        )
        .unwrap();
        restored.load_at(&v4, 100).unwrap();
        assert_eq!(
            committed.snapshot.previous_root,
            Some(restored.checkpoint().unwrap().root)
        );
        restored.load_at(&committed, 100).unwrap();
        restored
            .resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM)
            .unwrap();
        restored
            .resolve_signature_verifier(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM)
            .unwrap();
        assert!(restored
            .resolve_target_adapter(&ozpb_domain::target_adapters::SOROSWAP_ROUTER_TESTNET_WASM)
            .unwrap()
            .is_some());

        // One persisted at v2 cannot jump to v4: v4 does not directly extend it.
        let mut at_v2 = pinned_test_registry();
        at_v2.load_at(&v1, 100).unwrap();
        at_v2.load_at(&v2, 100).unwrap();
        let v2_checkpoint = at_v2.checkpoint().unwrap();
        let mut skipping = Registry::with_pinned_roots_for_network_at_checkpoint(
            roots(),
            network(),
            v2_checkpoint,
        )
        .unwrap();
        assert!(matches!(
            skipping.load_at(&committed, 100),
            Err(RegistryError::Transparency(_))
        ));
    }

    /// A revoked verifier vouches for nobody, however complete its entry.
    #[test]
    fn a_revoked_signature_verifier_is_refused() {
        let mut snapshot = dev::verifier_successor(network()).unwrap();
        snapshot.revocations.insert(
            format!(
                "verifier/{}",
                pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex()
            ),
            Revocation {
                reason: "test revocation".to_string(),
                effective_version: 3,
            },
        );
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut registry = registry();
        registry.load_at(&signed, 100).unwrap();
        assert!(matches!(
            registry.resolve_signature_verifier(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM),
            Err(RegistryError::Revoked { .. })
        ));
    }

    /// A signed entry may recognize other verifier code, but cannot make it an owner verifier,
    /// nor give a reviewed one a scheme its source does not implement.
    #[test]
    fn the_key_scheme_must_match_the_reviewed_source() {
        let mut snapshot = dev::verifier_successor(network()).unwrap();
        snapshot
            .verifiers
            .get_mut(&pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex())
            .unwrap()
            .key_scheme = Some(VerifierKeyScheme::Ed25519);
        let other = sha256(b"some other verifier");
        let mut entry =
            snapshot.verifiers[&pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex()].clone();
        entry.implementation = "other".into();
        snapshot.verifiers.insert(other.to_hex(), entry);
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut registry = registry();
        registry.load_at(&signed, 100).unwrap();
        for hash in [pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM, other] {
            assert!(registry.resolve_verifier(&hash).is_ok());
            assert!(matches!(
                registry.resolve_signature_verifier(&hash),
                Err(RegistryError::VerifierCapabilityIncomplete(_))
            ));
        }
    }

    /// The shipped snapshot must carry the *pinned upstream* hashes, not values derived
    /// locally. It previously held `sha256("dev:oz:spending_limit:wasm")` — a hash of a text
    /// label, not of any code — so the mechanism worked while recognizing nothing real. A
    /// literal here would drift silently from `domain`, which is why both sides read one
    /// constant; this test asserts the snapshot actually uses it.
    #[test]
    fn the_shipped_snapshot_pins_real_upstream_wasm_hashes() {
        let snapshot = dev::dev_snapshot(
            NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            1,
        );
        // Each hash must appear in ITS OWN table. Checking the union of the three would pass
        // even with the policy, account and verifier keys swapped between them — and a
        // verifier resolved as a policy is precisely the confusion the registry prevents.
        let policy = pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex();
        let account = pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex();
        let verifier = pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex();

        assert!(
            snapshot.policies.contains_key(&policy),
            "spending-limit policy {policy} is not in snapshot.policies"
        );
        assert!(
            snapshot.accounts.contains_key(&account),
            "smart account {account} is not in snapshot.accounts"
        );
        assert!(
            snapshot.verifiers.contains_key(&verifier),
            "ed25519 verifier {verifier} is not in snapshot.verifiers"
        );
        // And not cross-registered, which the union check would have allowed.
        assert!(!snapshot.accounts.contains_key(&policy));
        assert!(!snapshot.verifiers.contains_key(&policy));
        assert!(!snapshot.policies.contains_key(&account));
        assert!(!snapshot.policies.contains_key(&verifier));

        // A hash of a label rather than of code is the failure being guarded against, so the
        // old placeholders are spelled out.
        for placeholder in [
            "dev:oz:spending_limit:wasm",
            "dev:stellar-accounts:wasm",
            "dev:ed25519-verifier:wasm",
        ] {
            let stale = sha256(placeholder.as_bytes()).to_hex();
            for (label, real) in [
                ("policy", &policy),
                ("account", &account),
                ("verifier", &verifier),
            ] {
                assert_ne!(
                    real, &stale,
                    "{label} is still the {placeholder:?} placeholder"
                );
            }
        }

        // The shipped provenance must not still call these placeholders.
        for reference in snapshot
            .policies
            .values()
            .map(|c| &c.review_reference)
            .chain(snapshot.accounts.values().map(|c| &c.review_reference))
            .chain(snapshot.verifiers.values().map(|c| &c.review_reference))
        {
            assert!(
                !reference.contains("placeholder"),
                "a pinned entry still describes itself as a placeholder: {reference}"
            );
        }
    }

    use ozpb_domain::{sha256, NetworkId, TESTNET_PASSPHRASE};

    fn network() -> NetworkId {
        NetworkId::from_passphrase(TESTNET_PASSPHRASE)
    }

    fn registry() -> Registry {
        Registry::with_pinned_root(&dev::dev_root_verifying_bytes()).unwrap()
    }

    fn pinned_test_registry() -> Registry {
        Registry::with_pinned_roots_for_network_at_version(
            RootPolicy {
                threshold: 1,
                keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
            },
            network(),
            1,
        )
        .unwrap()
    }

    fn signed_authority_snapshot() -> SignedSnapshot {
        sign_snapshot(
            &dev::dev_signing_key(),
            dev::account_authority_successor(network()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn signed_account_authority_requires_exact_method_and_scan_bindings() {
        let legacy =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut registry = pinned_test_registry();
        registry.load_at(&legacy, 100).unwrap();
        assert!(matches!(
            registry.resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM),
            Err(RegistryError::AccountAuthorityUnsupported(_))
        ));

        let signed = signed_authority_snapshot();
        registry.load_at(&signed, 100).unwrap();
        let resolved = registry
            .resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM)
            .unwrap();
        assert_eq!(resolved.methods.methods.len(), 17);
        assert_eq!(resolved.scan.max_scan_ids, 1_000);
        assert!(matches!(
            registry.resolve_account_authority(&Hash32([99; 32])),
            Err(RegistryError::UnknownAccount(_))
        ));

        let mut tampered = signed.clone();
        tampered
            .snapshot
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap()
            .method_inventory_digest = Some(Hash32([0; 32]));
        assert_eq!(
            pinned_test_registry().load_at(&tampered, 100),
            Err(RegistryError::Signature)
        );

        let mut tampered = signed.clone();
        tampered
            .snapshot
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap()
            .bounded_next_id
            .as_mut()
            .unwrap()
            .max_scan_ids = 9_999;
        assert_eq!(
            pinned_test_registry().load_at(&tampered, 100),
            Err(RegistryError::Signature)
        );

        let mut wrong = signed.snapshot.clone();
        wrong
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap()
            .method_inventory_digest = Some(Hash32([0; 32]));
        let signed_wrong = sign_snapshot(&dev::dev_signing_key(), wrong).unwrap();
        let mut registry = pinned_test_registry();
        registry.load_at(&signed_wrong, 100).unwrap();
        assert!(matches!(
            registry.resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM),
            Err(RegistryError::AccountAuthorityUnsupported(_))
        ));

        let mut wrong_bounds = signed.snapshot.clone();
        wrong_bounds
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap()
            .bounded_next_id
            .as_mut()
            .unwrap()
            .max_scan_ids = 10_001;
        let signed_wrong_bounds = sign_snapshot(&dev::dev_signing_key(), wrong_bounds).unwrap();
        let mut registry = pinned_test_registry();
        registry.load_at(&signed_wrong_bounds, 100).unwrap();
        assert!(matches!(
            registry.resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM),
            Err(RegistryError::AccountAuthorityUnsupported(_))
        ));

        // Each entry below is governance-signed, so only the resolver's own checks can
        // refuse it. The unedited copy under the pinned hash is the passing control.
        let resolve_signed = |hash: Hash32, edit: &dyn Fn(&mut AccountCapability)| {
            let mut snapshot = signed.snapshot.clone();
            let mut entry =
                snapshot.accounts[&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()].clone();
            edit(&mut entry);
            snapshot.accounts.insert(hash.to_hex(), entry);
            let mut registry = pinned_test_registry();
            registry
                .load_at(
                    &sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap(),
                    100,
                )
                .unwrap();
            registry.resolve_account_authority(&hash)
        };
        let pinned = pinned_upstream::OZ_SMART_ACCOUNT_WASM;
        assert!(resolve_signed(pinned, &|_| {}).is_ok());
        // The method table was reviewed for one build. Another registered hash with the
        // same signed fields and digest has no reviewed methods of its own.
        assert!(matches!(
            resolve_signed(Hash32([98; 32]), &|_| {}),
            Err(RegistryError::AccountAuthorityUnsupported(_))
        ));
        type Edit = fn(&mut AccountCapability);
        let edits: [(&str, Edit); 8] = [
            ("schema version 2", |entry| {
                entry.bounded_next_id.as_mut().unwrap().schema_version = 2
            }),
            ("zero scan IDs", |entry| {
                entry.bounded_next_id.as_mut().unwrap().max_scan_ids = 0
            }),
            ("zero attempts", |entry| {
                entry.bounded_next_id.as_mut().unwrap().max_attempts = 0
            }),
            ("four attempts", |entry| {
                entry.bounded_next_id.as_mut().unwrap().max_attempts = 4
            }),
            ("zero batches", |entry| {
                entry.bounded_next_id.as_mut().unwrap().max_rpc_batches = 0
            }),
            ("129 batches", |entry| {
                entry.bounded_next_id.as_mut().unwrap().max_rpc_batches = 129
            }),
            ("zero transitive entries", |entry| {
                entry
                    .bounded_next_id
                    .as_mut()
                    .unwrap()
                    .max_transitive_entries = 0
            }),
            ("10001 transitive entries", |entry| {
                entry
                    .bounded_next_id
                    .as_mut()
                    .unwrap()
                    .max_transitive_entries = 10_001
            }),
        ];
        for (case, edit) in edits {
            assert!(
                matches!(
                    resolve_signed(pinned, &edit),
                    Err(RegistryError::AccountAuthorityUnsupported(_))
                ),
                "{case}"
            );
        }
        // §4.8: a strategy this checker does not implement has its own refusal, distinct
        // from an incomplete or mismatched capability.
        for method in ["onchain_list", "verified_event_index", "none"] {
            assert!(
                matches!(
                    resolve_signed(pinned, &|entry| entry.rule_enumeration = method.into()),
                    Err(RegistryError::AccountRuleEnumerationUnsupported { method: found, .. })
                        if found == method
                ),
                "{method}"
            );
        }
    }

    #[test]
    fn sign_load_resolve_round_trip() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        let root = r.load(&signed).unwrap();
        assert_eq!(root, r.root().unwrap());

        let cap = r
            .resolve_policy(&pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM)
            .unwrap();
        assert_eq!(cap.kind, "oz:spending_limit");
        assert!(
            cap.signer_predicates.is_empty(),
            "spending limit enforces no configured predicate"
        );
        // Compared against the generated vocabularies, never against a second literal. The
        // previous form probed for one entry (`strict_signer_set`) and kept passing while the
        // list named two things that are not kinds and omitted two that are. A literal set
        // written out here would have the same defect one step later: add a `Constraint`
        // variant, satisfy the compiler, and both sides of the comparison stay stale together
        // — green CI, and the first spec reaching the new kind refused in production. Since
        // `KINDS` is generated from the same exhaustive list as `kind_name`, this assertion
        // grows with the enum and cannot be quietly narrowed.
        let t = r.resolve_template("policy-templates/scope@1").unwrap();
        assert_eq!(
            t.signer_predicates,
            PredicateKind::KINDS,
            "the scope template declares PredicateKind's full vocabulary"
        );
        assert_eq!(
            t.constraint_kinds,
            Constraint::KINDS,
            "the scope template declares Constraint's full vocabulary"
        );
    }

    /// `KINDS` is written in sorted order and consumed as-is by `dev_snapshot`, so an entry
    /// added out of order would put an unsorted list into a signed document — legal, but it
    /// makes a reader diffing the entry against the enum do needless work, and it is free to
    /// prevent here.
    #[test]
    fn kinds_are_sorted() {
        for (label, kinds) in [
            ("Constraint", Constraint::KINDS),
            ("PredicateKind", PredicateKind::KINDS),
        ] {
            let mut sorted = kinds.to_vec();
            sorted.sort_unstable();
            assert_eq!(kinds, sorted.as_slice(), "{label}::KINDS must be sorted");
        }
    }

    #[test]
    fn snapshot_root_is_deterministic_and_content_sensitive() {
        let a = snapshot_root(&dev::dev_snapshot(network(), 1)).unwrap();
        let b = snapshot_root(&dev::dev_snapshot(network(), 1)).unwrap();
        assert_eq!(a, b);
        let c = snapshot_root(&dev::dev_snapshot(network(), 2)).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn bad_signature_is_rejected() {
        let mut signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        // Tamper after signing.
        signed.snapshot.version = 99;
        let mut r = registry();
        assert_eq!(r.load(&signed).unwrap_err(), RegistryError::Signature);

        // Wrong key entirely.
        let other = SigningKey::from_bytes(&sha256(b"attacker-key").0);
        let forged = sign_snapshot(&other, dev::dev_snapshot(network(), 1)).unwrap();
        assert_eq!(r.load(&forged).unwrap_err(), RegistryError::Signature);
    }

    #[test]
    fn threshold_root_policy_requires_distinct_trusted_signers() {
        let first = SigningKey::from_bytes(&sha256(b"registry-root-1").0);
        let second = SigningKey::from_bytes(&sha256(b"registry-root-2").0);
        let third = SigningKey::from_bytes(&sha256(b"registry-root-3").0);
        let roots = RootPolicy {
            threshold: 2,
            keys: BTreeMap::from([
                ("first".to_string(), first.verifying_key().to_bytes()),
                ("second".to_string(), second.verifying_key().to_bytes()),
                ("third".to_string(), third.verifying_key().to_bytes()),
            ]),
        };
        let snapshot = dev::dev_snapshot(network(), 1);
        let under_threshold = sign_snapshot_with_roots(
            &BTreeMap::from([("first".to_string(), first.clone())]),
            snapshot.clone(),
        )
        .unwrap();
        let mut registry = Registry::with_pinned_roots(roots.clone()).unwrap();
        assert_eq!(
            registry.load(&under_threshold).unwrap_err(),
            RegistryError::Signature
        );

        let signed = sign_snapshot_with_roots(
            &BTreeMap::from([("first".to_string(), first), ("second".to_string(), second)]),
            snapshot,
        )
        .unwrap();
        let mut registry = Registry::with_pinned_roots(roots).unwrap();
        registry.load(&signed).unwrap();
    }

    /// The compressed encodings of **all eight** ed25519 small-order (torsion) points, in
    /// curve25519-dalek's `EIGHT_TORSION` order so they can be diffed against that published
    /// constant directly. A signature under any of them verifies for almost every message, so
    /// one of these entering a root policy would turn threshold governance into universal
    /// forgery. Hex rather than byte arrays precisely so the values stay comparable by eye: an
    /// earlier revision of this test carried six of the eight while claiming all eight, which
    /// hand-written byte rows hid.
    const EIGHT_TORSION_ROOT_KEYS: [&str; 8] = [
        // Order 1: the identity point.
        "0100000000000000000000000000000000000000000000000000000000000000",
        // Order 8.
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        // Order 4: y = 0, with the sign bit set.
        "0000000000000000000000000000000000000000000000000000000000000080",
        // Order 8.
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        // Order 2: y = -1.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // Order 8.
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        // Order 4: y = 0, sign bit clear.
        "0000000000000000000000000000000000000000000000000000000000000000",
        // Order 8.
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    fn torsion_key(encoded: &str) -> [u8; 32] {
        hex::decode(encoded)
            .expect("a torsion vector must be hex")
            .try_into()
            .expect("a torsion vector must be 32 bytes")
    }

    #[test]
    fn small_order_root_keys_are_rejected_at_construction() {
        // Coverage self-check: eight *distinct* vectors. A duplicated row would otherwise
        // silently shrink the set while the count still read as complete.
        let distinct: std::collections::BTreeSet<&str> =
            EIGHT_TORSION_ROOT_KEYS.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            8,
            "the torsion set must hold eight distinct encodings"
        );

        for (index, encoded) in EIGHT_TORSION_ROOT_KEYS.iter().enumerate() {
            let bytes = torsion_key(encoded);
            // Self-check each vector before asserting on the constructor: it must decompress
            // and must be what the test claims it is — a weak key. This is what makes the
            // "all eight" claim machine-checked rather than a comment.
            let key = VerifyingKey::from_bytes(&bytes)
                .unwrap_or_else(|_| panic!("torsion vector {index} ({encoded}) must decompress"));
            assert!(
                key.is_weak(),
                "vector {index} ({encoded}) is not actually small-order"
            );
            assert!(
                matches!(
                    Registry::with_pinned_roots(RootPolicy {
                        threshold: 1,
                        keys: BTreeMap::from([("root".to_string(), bytes)]),
                    }),
                    Err(RegistryError::RootPolicy(_))
                ),
                "small-order root {index} ({encoded}) was accepted as a governance root"
            );
        }

        // One weak key poisons the whole policy even alongside a strong root: in an m-of-n
        // policy every accepted weak root reduces the number of real approvals needed.
        let mixed = RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([
                ("strong".to_string(), dev::dev_root_verifying_bytes()),
                ("weak".to_string(), torsion_key(EIGHT_TORSION_ROOT_KEYS[0])),
            ]),
        };
        assert!(matches!(
            Registry::with_pinned_roots(mixed),
            Err(RegistryError::RootPolicy(_))
        ));
    }

    /// Signer ids arrive from operator-supplied JSON, so a rejected id must not be able to forge
    /// log lines through the error message that quotes it.
    #[test]
    fn a_rejected_signer_id_cannot_inject_control_characters_into_the_message() {
        let policy = RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([(
                "governance\n[ERROR] all roots trusted".to_string(),
                torsion_key(EIGHT_TORSION_ROOT_KEYS[0]),
            )]),
        };
        let Err(RegistryError::RootPolicy(message)) = Registry::with_pinned_roots(policy) else {
            panic!("a weak root must be refused whatever its id");
        };
        assert!(
            !message.contains('\n'),
            "the message carries a raw newline and can forge a log line: {message}"
        );
        assert!(
            message.contains("\\n"),
            "the id should appear escaped, so an operator can still see what was configured: \
             {message}"
        );
    }

    /// The exact forgery shape from the R-01 audit reproduction: the compressed Edwards
    /// identity as the pinned root, and the constant signature (R = identity, S = 0), which
    /// requires no secret key and verifies for every message under non-strict verification.
    #[test]
    fn the_identity_root_and_constant_signature_cannot_load_a_snapshot() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        // First line of defense: the constructor refuses the weak root outright.
        assert!(matches!(
            Registry::with_pinned_root(&identity),
            Err(RegistryError::RootPolicy(_))
        ));

        // Second line: even a registry assembled around the constructor (possible only inside
        // this crate — the fields are private) must reject the constant signature, because
        // verification is strict and strict verification rejects small-order keys and R.
        let key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(key.is_weak());
        let mut registry = Registry {
            root_keys: BTreeMap::from([("legacy".to_string(), key)]),
            root_threshold: 1,
            expected_network: None,
            minimum_version: 0,
            pinned_checkpoint: None,
            current: None,
        };
        let mut constant_signature = [0u8; 64];
        constant_signature[0] = 1; // R = identity point, S = 0.
        let forged = SignedSnapshot {
            snapshot: dev::dev_snapshot(network(), 1),
            signatures: BTreeMap::from([("legacy".to_string(), hex::encode(constant_signature))]),
        };
        assert_eq!(
            registry.load_at(&forged, 0).unwrap_err(),
            RegistryError::Signature
        );
    }

    #[test]
    fn threshold_root_policy_rejects_the_same_key_under_multiple_ids() {
        let key = dev::dev_root_verifying_bytes();
        let policy = RootPolicy {
            threshold: 2,
            keys: BTreeMap::from([("alias-a".to_string(), key), ("alias-b".to_string(), key)]),
        };
        assert!(matches!(
            Registry::with_pinned_roots(policy),
            Err(RegistryError::RootPolicy(_))
        ));
    }

    #[test]
    fn rollback_and_freeze_are_rejected() {
        let key = dev::dev_signing_key();
        let v2 = sign_snapshot(&key, dev::dev_snapshot(network(), 2)).unwrap();
        let v1 = sign_snapshot(&key, dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        r.load(&v2).unwrap();
        assert_eq!(
            r.load(&v1).unwrap_err(),
            RegistryError::Rollback {
                offered: 1,
                current: 2
            }
        );
        // Re-offering the same version (freeze) is also rejected.
        assert_eq!(
            r.load(&v2).unwrap_err(),
            RegistryError::Rollback {
                offered: 2,
                current: 2
            }
        );
    }

    #[test]
    fn transparency_chain_rejects_a_fork_from_an_old_root() {
        let key = dev::dev_signing_key();
        let v1_snapshot = dev::dev_snapshot(network(), 1);
        let v1_root = snapshot_root(&v1_snapshot).unwrap();
        let v1 = sign_snapshot(&key, v1_snapshot).unwrap();

        let mut v2_snapshot = dev::dev_snapshot(network(), 2);
        v2_snapshot.previous_root = Some(v1_root);
        let v2_root = snapshot_root(&v2_snapshot).unwrap();
        let v2 = sign_snapshot(&key, v2_snapshot).unwrap();

        let mut forked_v3 = dev::dev_snapshot(network(), 3);
        forked_v3.previous_root = Some(v1_root);
        let forked_v3 = sign_snapshot(&key, forked_v3).unwrap();

        let mut registry = registry();
        registry.load(&v1).unwrap();
        registry.load(&v2).unwrap();
        assert_eq!(registry.root().unwrap(), v2_root);
        assert!(matches!(
            registry.load(&forked_v3),
            Err(RegistryError::Transparency(_))
        ));
    }

    #[test]
    fn network_and_snapshot_validity_are_pinned() {
        let root = dev::dev_root_verifying_bytes();
        let mainnet = NetworkId::from_passphrase("Public Global Stellar Network ; September 2015");
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut wrong_network = Registry::with_pinned_root_for_network(&root, mainnet).unwrap();
        assert!(
            wrong_network.load_at(&signed, 100).is_err(),
            "a correctly signed snapshot for another network must fail closed"
        );

        let mut snapshot = dev::dev_snapshot(network(), 1);
        snapshot.valid_from_unix = 100;
        snapshot.expires_at_unix = 200;
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut before = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        assert!(matches!(
            before.load_at(&signed, 99),
            Err(RegistryError::NotYetValid { .. })
        ));
        let mut active = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        active.load_at(&signed, 100).unwrap();
        assert!(active.ensure_valid_at(100).is_ok());
        assert!(active.ensure_valid_at(200).is_ok());
        assert!(matches!(
            active.ensure_valid_at(99),
            Err(RegistryError::NotYetValid { .. })
        ));
        assert!(matches!(
            active.ensure_valid_at(201),
            Err(RegistryError::Expired { .. })
        ));
        let mut expired = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        assert!(matches!(
            expired.load_at(&signed, 201),
            Err(RegistryError::Expired { .. })
        ));
    }

    #[test]
    fn a_fresh_process_enforces_the_persisted_minimum_version() {
        let root = dev::dev_root_verifying_bytes();
        let v1 = sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let v2 = sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 2)).unwrap();
        let mut registry =
            Registry::with_pinned_root_for_network_at_version(&root, network(), 2).unwrap();
        assert_eq!(
            registry.load(&v1).unwrap_err(),
            RegistryError::Rollback {
                offered: 1,
                current: 2
            }
        );
        registry.load(&v2).unwrap();
    }

    #[test]
    fn a_persisted_checkpoint_rejects_same_version_equivocation_after_restart() {
        let roots = RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
        };
        let v1_snapshot = dev::dev_snapshot(network(), 1);
        let v1 = sign_snapshot(&dev::dev_signing_key(), v1_snapshot.clone()).unwrap();
        let mut first = Registry::with_pinned_roots(roots.clone()).unwrap();
        first.load(&v1).unwrap();
        let checkpoint = first.checkpoint().unwrap();

        let mut equivocation = v1_snapshot;
        equivocation.expires_at_unix -= 1;
        let equivocation = sign_snapshot(&dev::dev_signing_key(), equivocation).unwrap();
        let mut restarted =
            Registry::with_pinned_roots_for_network_at_checkpoint(roots, network(), checkpoint)
                .unwrap();
        assert!(matches!(
            restarted.load(&equivocation),
            Err(RegistryError::Transparency(_))
        ));
        restarted.load(&v1).unwrap();
    }

    #[test]
    fn unknown_hashes_fail_closed() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        r.load(&signed).unwrap();
        assert!(matches!(
            r.resolve_policy(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownPolicy(_)
        ));
        assert!(matches!(
            r.resolve_account(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownAccount(_)
        ));
        assert!(matches!(
            r.resolve_verifier(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownVerifier(_)
        ));
        assert!(matches!(
            r.resolve_template("no-such-family").unwrap_err(),
            RegistryError::UnknownTemplate(_)
        ));
    }

    #[test]
    fn revoked_capabilities_fail_resolution_with_the_recorded_reason() {
        let account_hash = pinned_upstream::OZ_SMART_ACCOUNT_WASM;
        let mut snapshot = dev::dev_snapshot(network(), 1);
        snapshot.revocations.insert(
            format!("account/{}", account_hash.to_hex()),
            Revocation {
                reason: "critical authorization bypass".to_string(),
                effective_version: 1,
            },
        );
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut registry = registry();
        registry.load(&signed).unwrap();

        assert!(matches!(
            registry.resolve_account(&account_hash),
            Err(RegistryError::Revoked { reason, .. })
                if reason == "critical authorization bypass"
        ));
    }

    fn signed_successor(previous: &RegistrySnapshot, mut next: RegistrySnapshot) -> SignedSnapshot {
        next.log_index = previous.log_index + 1;
        next.previous_root = Some(snapshot_root(previous).unwrap());
        sign_snapshot(&dev::dev_signing_key(), next).unwrap()
    }

    #[test]
    fn accepted_revocations_are_append_only_and_immutable() {
        let hash = pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex();
        let key = format!("account/{hash}");
        let mut first_snapshot = dev::dev_snapshot(network(), 1);
        first_snapshot.revocations.insert(
            key.clone(),
            Revocation {
                reason: "reviewed authorization bypass".to_string(),
                effective_version: 1,
            },
        );
        let first = sign_snapshot(&dev::dev_signing_key(), first_snapshot.clone()).unwrap();

        for tamper in ["remove", "rewrite"] {
            let mut next = dev::dev_snapshot(network(), 2);
            if tamper == "rewrite" {
                next.revocations.insert(
                    key.clone(),
                    Revocation {
                        reason: "quietly weakened reason".to_string(),
                        effective_version: 2,
                    },
                );
            }
            let next = signed_successor(&first_snapshot, next);
            let mut registry = registry();
            registry.load(&first).unwrap();
            assert!(matches!(
                registry.load(&next),
                Err(RegistryError::Transparency(_))
            ));
        }

        let mut valid_next = dev::dev_snapshot(network(), 2);
        valid_next.revocations.insert(
            key,
            first_snapshot.revocations.values().next().unwrap().clone(),
        );
        valid_next.revocations.insert(
            format!(
                "policy/{}",
                pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex()
            ),
            Revocation {
                reason: "new independent finding".to_string(),
                effective_version: 2,
            },
        );
        let valid_next = signed_successor(&first_snapshot, valid_next);
        let mut registry = registry();
        registry.load(&first).unwrap();
        registry.load(&valid_next).unwrap();
    }

    #[test]
    fn persisted_checkpoint_preserves_revocation_append_only_state() {
        let mut first_snapshot = dev::dev_snapshot(network(), 1);
        first_snapshot.revocations.insert(
            format!(
                "account/{}",
                pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()
            ),
            Revocation {
                reason: "accepted finding".to_string(),
                effective_version: 1,
            },
        );
        let first = sign_snapshot(&dev::dev_signing_key(), first_snapshot.clone()).unwrap();
        let mut original = registry();
        original.load(&first).unwrap();
        let checkpoint = original.checkpoint().unwrap();

        let successor = signed_successor(&first_snapshot, dev::dev_snapshot(network(), 2));
        let roots = RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
        };
        let mut restarted =
            Registry::with_pinned_roots_for_network_at_checkpoint(roots, network(), checkpoint)
                .unwrap();
        assert!(matches!(
            restarted.load(&successor),
            Err(RegistryError::Transparency(_))
        ));
    }

    #[test]
    fn capability_and_revocation_keys_must_be_canonical() {
        let invalid_hashes = [
            "ABCD".to_string(),
            "A".repeat(64),
            format!("{}g", "0".repeat(63)),
        ];
        for invalid in invalid_hashes {
            let mut snapshot = dev::dev_snapshot(network(), 1);
            let capability = snapshot.policies.pop_first().unwrap().1;
            snapshot.policies.insert(invalid, capability);
            let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
            assert!(matches!(
                registry().load(&signed),
                Err(RegistryError::Parse(_))
            ));
        }

        for invalid in [
            "policy/not-a-hash",
            "unknown/0000000000000000000000000000000000000000000000000000000000000000",
            "template/contains a space",
            "missing-separator",
        ] {
            let mut snapshot = dev::dev_snapshot(network(), 1);
            snapshot.revocations.insert(
                invalid.to_string(),
                Revocation {
                    reason: "test".to_string(),
                    effective_version: 1,
                },
            );
            let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
            assert!(matches!(
                registry().load(&signed),
                Err(RegistryError::Parse(_))
            ));
        }
    }

    #[test]
    fn the_same_wasm_hash_cannot_hold_two_capability_roles() {
        // The role-separated maps exist to stop a verifier from resolving as a policy (or any
        // other cross-role confusion). A signed snapshot that lists one hash under two roles is
        // ambiguous reviewed metadata; loading must reject it rather than let `resolve_*` return
        // a capability of the wrong kind for the same code.
        // An enum, not string matching: the check is pairwise over three maps, so the test
        // enumerates all three pairs and the compiler — not a `_` arm — decides that every role
        // is handled. The earlier version matched on `"account"` with a catch-all that would
        // have silently treated a fourth role as `verifier`.
        #[derive(Clone, Copy, Debug)]
        enum Role {
            Policy,
            Account,
            Verifier,
        }

        fn insert_under(snapshot: &mut RegistrySnapshot, role: Role, hash: &str) {
            match role {
                Role::Policy => {
                    snapshot.policies.insert(
                        hash.to_string(),
                        PolicyCapability {
                            kind: "collision".to_string(),
                            signer_predicates: vec![],
                            security_relevant_methods: vec![],
                            review_reference: "collision".to_string(),
                        },
                    );
                }
                Role::Account => {
                    snapshot.accounts.insert(
                        hash.to_string(),
                        AccountCapability {
                            release: "collision".to_string(),
                            rule_enumeration: "none".to_string(),
                            management_evidence: "none".to_string(),
                            bounded_next_id: None,
                            method_inventory_digest: None,
                            review_reference: "collision".to_string(),
                        },
                    );
                }
                Role::Verifier => {
                    snapshot.verifiers.insert(
                        hash.to_string(),
                        VerifierCapability {
                            implementation: "collision".to_string(),
                            key_encoding: "raw ed25519 public key (32 bytes)".to_string(),
                            immutable: true,
                            key_scheme: None,
                            stateless: None,
                            review_reference: "collision".to_string(),
                        },
                    );
                }
            }
        }

        // A hash that is in none of the dev fixture's maps, so each case below registers it
        // under exactly the two roles under test — including account/verifier, the pair the
        // previous version of this test never reached.
        let shared = sha256(b"cross-role-collision-subject").to_hex();
        for (first, second) in [
            (Role::Policy, Role::Account),
            (Role::Policy, Role::Verifier),
            (Role::Account, Role::Verifier),
        ] {
            let mut snapshot = dev::dev_snapshot(network(), 1);
            insert_under(&mut snapshot, first, &shared);
            insert_under(&mut snapshot, second, &shared);
            let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
            assert!(
                matches!(registry().load(&signed), Err(RegistryError::Parse(_))),
                "a hash shared between {first:?} and {second:?} must fail closed"
            );
        }

        // Control: the same hash under one role only must still load, so the assertions above
        // are detecting the collision rather than the injected entry.
        for role in [Role::Policy, Role::Account, Role::Verifier] {
            let mut snapshot = dev::dev_snapshot(network(), 1);
            insert_under(&mut snapshot, role, &shared);
            let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
            registry()
                .load(&signed)
                .unwrap_or_else(|e| panic!("one {role:?} entry alone must load, got {e}"));
        }
    }

    #[test]
    fn queries_before_load_fail_closed() {
        let r = registry();
        assert_eq!(
            r.resolve_template("policy-templates/scope@1").unwrap_err(),
            RegistryError::NotLoaded
        );
    }

    #[test]
    fn json_round_trip() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let mut r = registry();
        r.load_json(&json).unwrap();
    }
}

#[cfg(test)]
mod target_adapter_tests;
