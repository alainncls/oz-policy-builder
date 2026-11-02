//! Account authority check (architecture §4.8, Decisions D6/D7).
//!
//! Pure logic over an in-memory account rule-set model (as if read from
//! `getLedgerEntries`). It answers one question, fail-closed and for a stated scope — the new
//! rule's target, the account's management surface (`Default`, `CallContract(account)`) and
//! the bound policies: *who can change this account or reset the policies being installed, and
//! can the restricted key reach the target outside the new limit?* Who else can call the
//! target is shown for information: their access is their own, not a way around the agent's
//! limit. It never answers "is it safe": whether the listed
//! identities are the user's own, or trusted by the user, is decided by the wallet that holds
//! the owner key (Decision D7), which recomputes this result itself rather than trusting one
//! it is handed. Rules for other contracts are listed as coverage exclusions, never declared
//! harmless.
//!
//! The result has three blocking parts and some notes:
//! - `authority_list` — every live rule that can change the account or reach a bound policy,
//!   each as the identities who must all sign;
//! - `refusals` — unconditional inside the scope: the agent's own key can change the account
//!   or reset a bound policy alone, another rule on the target lets it around the new limit,
//!   the new rule targets something it must not, or an in-scope rule has a shape this version
//!   does not support;
//! - `unresolved` — evidence missing inside the scope (a classic account that was not read, a
//!   verifier whose code was not observed).
//!
//! Why these rules matter: the account's management methods (`add_context_rule`,
//! `remove_policy`, `add_signer`, …) and every bound policy's `install` / `uninstall` are
//! guarded only by the account's own authorization, and `CallContract` scoping discards
//! function names. So any live rule matching the account's address (or `Default`, which
//! matches everything) can strip the new rule of its policies; any rule matching a bound
//! policy can uninstall and reinstall it to reset its counters; and any other rule on the
//! target is a second way to call it.
//!
//! Accepted forms are surface-specific (OZ `stellar-accounts` 0.7.2, `storage.rs`
//! `get_validated_context_by_id` and `do_check_auth`). A rule that can change the account or
//! reach a bound policy must be policy-free: every signer must sign. A rule with policies skips
//! that check, lets the submitter choose it, and hands whatever signers authenticated —
//! possibly none — to its policies, so on those surfaces any policy is refused. On the target,
//! a rule is described by its policies' established semantics (a recognized policy demanding
//! at least one of the rule's own signers), never projected to "all of" from its stored signer
//! list; an unreadable one is refused. A classic-account signer authorizes through the classic
//! account's own signers and thresholds, so it is one identity only when its entry exists and
//! its master key alone meets the medium threshold. Contract (nested-account) signers and
//! unrecognized external verifiers are refused by name. There is no dominance algebra and no
//! override.
//!
//! Enumeration is `bounded_next_id` (D6): read `NextId` + extant `Count` + the rule entries
//! and their transitive signer/policy closure; a count deficit or a missing transitive entry
//! fails closed (`E_INCOMPLETE_ACCOUNT_STATE`) rather than yielding a partial answer — an
//! archived rule could be restored and used in the same invocation.
//!
//! The refusals work on key material, so the restricted key is recognized whether stored as a
//! classic account or as raw key bytes behind a verifier (sharing its first 32 bytes). The
//! `authority_commitment` binds the authority-relevant state and the exact install intent;
//! ledger numbers and TTLs do not move it, while any change to the account's stored rules —
//! in scope or not — does (the safe direction: approval is asked again).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------------------
// In-memory account state (the enumeration input; produced by an acquisition adapter that
// reads ledger entries — kept out of this pure crate).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    /// Monotonic rule-id counter (next id to be assigned).
    pub next_id: u32,
    /// Active (non-removed, incl. expired) rule count — the reconciliation target.
    pub active_count: u32,
    /// Live rules by id (ids in 0..next_id that were not removed). Archived-but-not-
    /// removed rules are absent here and MUST cause a count deficit.
    pub rules: BTreeMap<u32, StoredRule>,
    /// Global signer registry (transitive closure target).
    pub signers: BTreeMap<u32, StoredSigner>,
    /// Global policy registry (transitive closure target).
    pub policies: BTreeMap<u32, StoredPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRule {
    pub id: u32,
    pub context_type: StoredContextType,
    pub valid_until: Option<u32>,
    pub signer_ids: Vec<u32>,
    pub policy_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredContextType {
    Default,
    CallContract { address: String },
    CreateContract { wasm_hash: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSigner {
    pub id: u32,
    /// The on-chain signer variant. An opaque string cannot distinguish a delegated
    /// signer from an external verifier whose code must be recognized separately.
    pub key: StoredSignerKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredSignerKey {
    Delegated { address: String },
    External { verifier: String, key_hex: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPolicy {
    pub id: u32,
    pub address: String,
    /// Wasm hash observed in the same ledger snapshot as the account state.
    pub observed_wasm_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BoundPolicy {
    pub address: String,
    /// Code observed at this address in the same ledger snapshot as `account_state`.
    pub observed_wasm_hash: String,
}

/// Recognition evidence already validated by the trusted adapter. The pure core checks
/// the observed code hash; it does not validate registry signatures or reproduce builds.
#[derive(Clone, Debug)]
pub struct VerifiedPolicy {
    pub wasm_hash: String,
    pub path: PolicyRecognitionPath,
    /// What the recognized implementation demands of the rule's signers.
    pub signers: PolicySignerSemantics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRecognitionPath {
    ReviewedRegistry,
    VerifiedGeneratedManifest,
}

/// How a recognized policy treats the signers of the rule it is attached to. A rule with
/// policies skips the account's own all-signers check (OZ `storage.rs`), so this is the only
/// thing that says who can use such a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySignerSemantics {
    /// `enforce` refuses unless at least one of the rule's own signers authenticated (OZ's
    /// spending limit: `authenticated_signers.is_empty()` panics).
    AtLeastOneRuleSigner,
    /// Not established: the policy may accept any subset of signers, including none.
    Unknown,
}

/// A classic Stellar account's signing configuration, read in the same capture as the
/// smart account. `Delegated(G…)` authorizes through `require_auth_for_args` on the classic
/// account, which accepts any signer set meeting its medium threshold, not just the key the
/// address encodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassicAccount {
    /// No account entry. Such an account cannot authenticate now (the host fails to load
    /// it), so a rule naming it is refused until a rescan finds it.
    NotFound,
    Found {
        master_weight: u8,
        low_threshold: u8,
        medium_threshold: u8,
        high_threshold: u8,
        /// Additional signers (strkey-encoded signer keys) and their weights.
        signers: Vec<ClassicSigner>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassicSigner {
    pub key: String,
    pub weight: u32,
}

/// What the reader observed at a verifier address named by an external signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifierObservation {
    /// The verifier's code, at the same ledger as the account state.
    pub code_hash: String,
    /// The key scheme, when that code is a reviewed owner verifier (immutable, stateless,
    /// scheme established); `None` for code nobody recognizes as one.
    pub scheme: Option<KeyScheme>,
}

/// How a recognized verifier reads a signer's key data: what one owner identity is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyScheme {
    /// Exactly a 32-byte ed25519 public key.
    Ed25519,
    /// A 65-byte uncompressed P-256 key (`0x04‖X‖Y`); a credential id after it is ignored.
    WebauthnP256,
}

/// The rule about to be installed. It comes from the hashed spec the binding set names,
/// never from a separate claim, and it is what the findings measure the account against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Grant {
    /// The spec rule this is. Carried into the result and its digest so an answer computed
    /// for one rule cannot be presented for another.
    pub rule_index: u32,
    /// The contract the new `CallContract` rule targets.
    pub target: String,
    /// Whether the new rule keeps state between calls (a counter, a spending window). Two
    /// rules for the same key on the same target hold independent state, so a stateful
    /// grant next to another usable rule is not the limit it claims to be (§4.8 step 8).
    pub stateful: bool,
    /// The restricted keys: the new rule's signers.
    pub signers: Vec<StoredSignerKey>,
    /// The rest of the exact `add_context_rule` arguments, so the commitment binds what will
    /// be signed and not only what was checked.
    pub name: String,
    pub valid_until: Option<u32>,
    pub policies: Vec<GrantPolicy>,
}

/// One entry of the new rule's `policies` map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantPolicy {
    pub address: String,
    pub install_params: GrantPolicyParams,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantPolicyParams {
    Generated,
    SpendingLimit {
        spending_limit: String,
        period_ledgers: u32,
    },
}

// ---------------------------------------------------------------------------------------
// Check inputs
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CheckInput<'a> {
    /// Network identity (hex), committed with the answer.
    pub network_id: String,
    /// Hash of the spec the grant and bindings come from, committed with the answer.
    pub spec_hash: Hash32,
    pub account_state: &'a AccountState,
    /// The account's own C-address (management surface).
    pub account_address: String,
    /// Observed account wasm hash (recorded in the result; recognition is the caller's).
    pub account_code_hash: String,
    /// Canonical exact binding set the protected policy addresses came from.
    pub binding_set_hash: Hash32,
    /// Whether the account implementation is recognized by the registry.
    pub account_recognized: bool,
    /// The exact policy instances being installed. The acquisition adapter must re-read
    /// their code hashes in the same ledger snapshot as the account state, rather than
    /// copying a previously resolved binding's hash after a possible upgrade.
    pub bound_policies: Vec<BoundPolicy>,
    /// Policies validated by a reviewed registry entry or a reproduced generated artifact
    /// manifest, as address → validated code identity, recognition path and signer
    /// semantics. A policy counts as recognized only while its same-ledger observed hash
    /// equals the validated hash: an address reviewed once can be serving other code now.
    /// Every bound policy must be here.
    pub recognized_policies: BTreeMap<String, VerifiedPolicy>,
    /// Classic accounts read in the same capture, by G-address. Every `Delegated(G…)` signer
    /// on a rule that can change the account, reach a bound policy or call the target — and
    /// every restricted key that is a classic account — needs an entry here.
    pub classic_accounts: BTreeMap<String, ClassicAccount>,
    /// Verifiers named by external signers, by contract address, as observed in the same
    /// capture. Every external signer on an in-scope rule or on the new rule needs an entry.
    pub verifiers: BTreeMap<String, VerifierObservation>,
    /// Root of the signed registry snapshot that recognized the code above. Committed, so a
    /// revocation or any registry change asks for approval again.
    pub registry_snapshot_root: Hash32,
    /// The rule being installed.
    pub grant: Grant,
    pub current_ledger: u32,
    /// Declared enumeration capability of the account (D6). This state model requires
    /// a real NextId value, so only bounded_next_id is currently supported.
    pub enumeration: Enumeration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enumeration {
    OnchainList,
    BoundedNextId,
    VerifiedEventIndex,
    None,
}

// ---------------------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------------------

/// The authority answer at one ledger, for a stated scope. There is no "safe" anywhere in
/// it: the wallet that holds the owner key recomputes it and decides, only when `refusals` and
/// `unresolved` are both empty and every `authority_list` entry is satisfied by identities it
/// trusts (see [`Requirement`]).
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceVerdict {
    /// The result is an observation at exactly one ledger (freshness is retry policy,
    /// never a security-validity interval — §4.8). Not committed.
    pub observed_ledger: u32,
    pub network_id: String,
    pub account_address: String,
    pub account_code_hash: String,
    pub spec_hash: Hash32,
    pub binding_set_hash: Hash32,
    pub bound_policy_addresses: Vec<String>,
    /// The rule the answer is about, with its exact `add_context_rule` arguments.
    pub grant: Grant,
    /// What the answer covers. Rules outside it are `coverage_exclusions`, never "nothing".
    pub scope: Scope,
    /// Every live rule that can change the account or reach a bound policy, with exactly who
    /// must sign. Rule order.
    pub authority_list: Vec<AuthorityEntry>,
    /// Unconditional refusals inside the scope: authority already proven unacceptable, or a
    /// shape this version does not support. Trust never overrides one.
    pub refusals: Vec<Finding>,
    /// Evidence gaps inside the scope. Any entry blocks acceptance.
    pub unresolved: Vec<Finding>,
    /// Live rules outside the scope, listed by id: not analysed.
    pub coverage_exclusions: Vec<ExcludedRule>,
    /// Information for the screen; none of it blocks.
    pub notes: Notes,
    /// The authority-relevant state the answer was computed from.
    pub authority_state: AuthorityState,
    /// Hash, under `domains::SURFACE_VERDICT`, of everything above except `observed_ledger`:
    /// the authority-relevant state and the exact intent (network, account, spec, bindings,
    /// rule index, `add_context_rule` arguments). Approval binds to it; the pre-signing
    /// re-read recomputes it at the new ledger, and any difference needs approval again. It
    /// identifies a result; it authenticates nothing, so a wallet recomputes the result
    /// rather than trusting one it is handed.
    pub authority_commitment: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scope {
    /// The contract(s) the new rule lets the agent call.
    pub targets: Vec<String>,
    /// The account whose management surface is covered.
    pub account: String,
    /// The policies being installed.
    pub bound_policies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityEntry {
    pub rule_id: u32,
    pub reach: Reach,
    pub valid_until: Option<u32>,
    pub requirement: Requirement,
}

/// What a rule can reach on the protected surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reach {
    /// `Default`: every call the account authorizes, management and policies included.
    AnyCall,
    /// `CallContract(account)`: every method of the account itself. That is its management, and
    /// for a wrapper with `execute`, any call the account makes on its own authority, policy
    /// resets included; `upgrade` replaces its code.
    AccountCalls,
    /// `CallContract(bound policy)`: that policy's `install` / `uninstall` for this account,
    /// which resets its state.
    Policy { address: String },
    /// `CallContract(target)`: the contract the new rule lets the agent call.
    Target { address: String },
}

/// Who must sign for a rule to authorize anything. The wallet's acceptance test differs by
/// kind: an `all_of` rule is held back if any one of its signers is trusted (that signer will
/// not sign for others); an `any_of` rule only if every one of its signers is trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Requirement {
    /// A policy-free rule: every one of these must sign (OZ `storage.rs`).
    AllOf { signers: Vec<Identity> },
    /// A rule whose every policy is recognized as demanding at least one of the rule's own
    /// signers: any one of these, subject to those policies' further limits.
    AnyOf {
        signers: Vec<Identity>,
        policies: Vec<String>,
    },
}

/// One required identity, with what a wallet compares against its own keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Identity {
    /// A classic Stellar account controlled by its master key alone (no other signers, the
    /// master key meets the medium threshold). A missing account is refused, never an identity.
    ClassicAccount {
        address: String,
        /// The master key: the only key that can authorize through this account.
        ed25519_public_key: String,
        /// The key is (or may be) one of the restricted keys. A wallet must never count it
        /// as an owner, even if it holds it.
        aliases_restricted_key: bool,
    },
    /// A key behind a recognized owner verifier. The identity is the scheme and the canonical
    /// key; the verifier address is where this account checks it, and the same key behind
    /// another copy of the same verifier is the same identity.
    External {
        verifier: String,
        verifier_code_hash: String,
        scheme: KeyScheme,
        /// Canonical key, hex: 32 bytes for ed25519, the first 65 bytes for WebAuthn.
        public_key: String,
        aliases_restricted_key: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Notes {
    /// Every live rule, in any context, naming one of the restricted keys: what the agent can
    /// already do outside the new rule.
    pub restricted_key_rules: Vec<RestrictedKeyRule>,
    /// Other rules on the new rule's target that the agent cannot use alone: who else can
    /// call it. Described exactly, like the authority list, but not part of the decision.
    pub target_rules: Vec<AuthorityEntry>,
    /// Rules that would reach a protected surface or the target but have expired. Reviving
    /// one takes `update_context_rule_valid_until`, which needs an account-reaching rule above.
    pub expired_rules: Vec<ExpiredRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RestrictedKeyRule {
    pub rule_id: u32,
    pub context: StoredContextType,
    pub valid_until: Option<u32>,
    /// The restricted keys can use this rule without anyone else.
    pub usable_alone: bool,
    pub policy_addresses: Vec<String>,
}

/// A live rule for some other contract: outside the scope, not analysed. The agent may be able
/// to call that contract through it (see `notes.restricted_key_rules`); it cannot touch the
/// account, the bound policies or the target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExcludedRule {
    pub rule_id: u32,
    pub context: StoredContextType,
    pub policy_addresses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpiredRule {
    pub rule_id: u32,
    pub context: StoredContextType,
    pub valid_until: u32,
}

/// The authority-relevant state behind the answer, beyond the codes and bindings above.
/// Ledger numbers, TTLs and acquisition metadata are deliberately absent: they are evidence,
/// recorded by the acquiring shell, never compared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityState {
    /// Hash over the ordered enumerated state (rules + transitive closure, with every
    /// installed policy's observed code hash).
    pub ordered_state_digest: Hash32,
    /// The signing configuration of every classic account the answer consulted: the new
    /// rule's own `G…` signers and those of in-scope rules.
    pub classic_accounts: BTreeMap<String, ClassicAccount>,
    /// The code (and recognized scheme) of every verifier the answer consulted.
    pub verifiers: BTreeMap<String, VerifierObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: FindingCode,
    /// The rule the finding is about; absent when it is about the new rule itself.
    pub rule_id: Option<u32>,
    /// Present on `E_UNSUPPORTED_AUTHORITY`: which shape this version does not support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<UnsupportedReason>,
    pub reason: String,
    pub remediation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum FindingCode {
    /// A restricted key can already change the account or reset a bound policy on its own.
    #[serde(rename = "E_DELEGATE_HAS_AUTHORITY")]
    DelegateHasAuthority,
    /// Another rule on the new rule's target lets the restricted key around the new limit.
    #[serde(rename = "E_DELEGATE_GRANT_OVERLAP")]
    DelegateGrantOverlap,
    /// The new rule targets a bound policy, or a policy, verifier or contract signer the
    /// account already trusts.
    #[serde(rename = "E_UNSAFE_CALL_SURFACE")]
    UnsafeCallSurface,
    /// The new rule targets the account itself.
    #[serde(rename = "E_UNSAFE_MANAGEMENT_SURFACE")]
    UnsafeManagementSurface,
    /// A relevant rule uses a shape this version does not support.
    #[serde(rename = "E_UNSUPPORTED_AUTHORITY")]
    UnsupportedAuthority,
    /// Evidence inside the scope is missing.
    #[serde(rename = "E_INCOMPLETE_ACCOUNT_STATE")]
    IncompleteAccountState,
}

impl FindingCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DelegateHasAuthority => "E_DELEGATE_HAS_AUTHORITY",
            Self::DelegateGrantOverlap => "E_DELEGATE_GRANT_OVERLAP",
            Self::UnsafeCallSurface => "E_UNSAFE_CALL_SURFACE",
            Self::UnsafeManagementSurface => "E_UNSAFE_MANAGEMENT_SURFACE",
            Self::UnsupportedAuthority => "E_UNSUPPORTED_AUTHORITY",
            Self::IncompleteAccountState => "E_INCOMPLETE_ACCOUNT_STATE",
        }
    }
}

/// Rule shapes Tranche 2 refuses rather than describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The rule carries a policy whose treatment of signers is not established, so it — not
    /// the signer list — decides who may act: a k-of-n threshold, a timelock, a guarded
    /// recovery rule, or simply an unrecognized policy. It may accept no signer at all.
    PolicyGuarded,
    /// A signer is a contract address (a nested smart account) authorizing through its own
    /// rules, which this check does not read.
    ContractSigner,
    /// A signer is verified by an external contract this check cannot recognize.
    ExternalSigner,
    /// A signer is an address that is neither a classic account nor a contract.
    UnrecognizedSigner,
    /// A classic-account signer has other signers, or its master key does not meet its
    /// medium threshold: classic multisig is not analysed.
    ClassicMultisig,
    /// A classic-account signer that does not exist, so cannot authenticate now.
    ClassicAccountMissing,
    /// Key data a recognized verifier can never accept (wrong length, not an uncompressed
    /// P-256 point): a signer that can never sign, so not an identity anyone holds.
    MalformedKey,
    /// The rule has neither signers nor policies (the account refuses to store one).
    EmptyRule,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error(
        "E_ACCOUNT_RULE_ENUMERATION_UNSUPPORTED: account enumeration capability is \
         '{0:?}'; the current state model requires bounded_next_id"
    )]
    EnumerationUnsupported(Enumeration),
    #[error(
        "E_INCOMPLETE_ACCOUNT_STATE: {cause:?}: {detail} — a complete result is \
         unavailable; resolve the missing or undecodable state and re-run the check"
    )]
    IncompleteState {
        cause: IncompleteCause,
        detail: String,
    },
    #[error("E_INCOMPATIBLE_ACCOUNT: account implementation {0} is not recognized")]
    IncompatibleAccount(String),
    #[error(
        "E_UNREGISTERED_POLICY: bound policy address {0} or its observed code is not recognized"
    )]
    UnrecognizedBoundPolicy(String),
    #[error("E_POLICY_BINDING_INVALID: {0}")]
    InvalidBindingSet(String),
    #[error("E_INTERNAL: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteCause {
    /// Fewer decoded live rules than the active count; the pure core cannot distinguish
    /// an archived entry from a missing or undecodable one.
    UnresolvedRule,
    /// A referenced signer/policy registry entry is absent.
    Missing,
    /// A snapshot inconsistency (ids beyond next_id, duplicate ids, …).
    SnapshotMismatch,
}

// ---------------------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------------------

pub fn check(input: &CheckInput) -> Result<SurfaceVerdict, CheckError> {
    // Enumeration capability gate (D6).
    match input.enumeration {
        Enumeration::BoundedNextId => {}
        other => return Err(CheckError::EnumerationUnsupported(other)),
    }
    if !input.account_recognized {
        return Err(CheckError::IncompatibleAccount(
            input.account_code_hash.clone(),
        ));
    }
    if input.bound_policies.is_empty() {
        return Err(CheckError::InvalidBindingSet(
            "at least one exact bound policy address is required".to_string(),
        ));
    }
    let bound: BTreeSet<&str> = input
        .bound_policies
        .iter()
        .map(|p| p.address.as_str())
        .collect();
    if bound.len() != input.bound_policies.len() {
        return Err(CheckError::InvalidBindingSet(
            "bound policy addresses must be unique".to_string(),
        ));
    }
    if input.grant.signers.is_empty() {
        return Err(CheckError::InvalidBindingSet(
            "the new rule names no signer, so there is no restricted key to check".to_string(),
        ));
    }
    // A bound instance need not yet be in account state, but its executable code is
    // already observable. Compare that same-ledger observation with the validated hash.
    if let Some(unrecognized) = input.bound_policies.iter().find(|policy| {
        input
            .recognized_policies
            .get(&policy.address)
            .is_none_or(|verified| verified.wasm_hash != policy.observed_wasm_hash)
    }) {
        return Err(CheckError::UnrecognizedBoundPolicy(
            unrecognized.address.clone(),
        ));
    }

    let st = input.account_state;
    let stored = reconcile(st)?;
    let ordered_state_digest = state_digest(st)?;

    let restricted: Vec<KeyMaterial> = input.grant.signers.iter().map(key_material).collect();
    let is_restricted = |key: &StoredSignerKey| {
        let material = key_material(key);
        restricted.iter().any(|other| material.aliases(other))
    };
    let target = input.grant.target.as_str();

    let mut answer = Answer::default();
    grant_findings(input, &mut answer);

    for rule in &stored {
        let signers: Vec<&StoredSignerKey> = rule
            .signer_ids
            .iter()
            .filter_map(|id| st.signers.get(id).map(|signer| &signer.key))
            .collect();
        let policies: Vec<&StoredPolicy> = rule
            .policy_ids
            .iter()
            .filter_map(|id| st.policies.get(id))
            .collect();
        let policy_addresses: Vec<String> = policies.iter().map(|p| p.address.clone()).collect();
        let reach = match &rule.context_type {
            StoredContextType::Default => Some(Reach::AnyCall),
            StoredContextType::CallContract { address } if *address == input.account_address => {
                Some(Reach::AccountCalls)
            }
            StoredContextType::CallContract { address } if bound.contains(address.as_str()) => {
                Some(Reach::Policy {
                    address: address.clone(),
                })
            }
            StoredContextType::CallContract { address } if address == target => {
                Some(Reach::Target {
                    address: address.clone(),
                })
            }
            _ => None,
        };

        if is_expired(rule, input.current_ledger) {
            if let (Some(valid_until), true) = (rule.valid_until, reach.is_some()) {
                answer.notes.expired_rules.push(ExpiredRule {
                    rule_id: rule.id,
                    context: rule.context_type.clone(),
                    valid_until,
                });
            }
            continue;
        }

        // Who can use this rule. Without policies, every signer must sign. With policies the
        // account skips that check and lets the submitter pick the rule, so the policies
        // decide; a recognized "at least one rule signer" policy keeps the rule to its
        // signers, anything else may let anyone through.
        let readable = policies.iter().all(|policy| {
            policy_semantics(input, policy) == PolicySignerSemantics::AtLeastOneRuleSigner
        });
        let names_restricted = signers.iter().any(|key| is_restricted(key));
        let usable_alone = if policies.is_empty() {
            names_restricted && signers.iter().all(|key| is_restricted(key))
        } else {
            names_restricted
        };
        if names_restricted {
            answer.notes.restricted_key_rules.push(RestrictedKeyRule {
                rule_id: rule.id,
                context: rule.context_type.clone(),
                valid_until: rule.valid_until,
                usable_alone,
                policy_addresses: policy_addresses.clone(),
            });
        }

        let Some(reach) = reach else {
            answer.coverage_exclusions.push(ExcludedRule {
                rule_id: rule.id,
                context: rule.context_type.clone(),
                policy_addresses,
            });
            continue;
        };

        // Every classic account and verifier an in-scope rule names is part of what decides
        // the answer.
        for key in &signers {
            match key {
                StoredSignerKey::Delegated { address } => {
                    answer.classic_used.insert(address.clone());
                }
                StoredSignerKey::External { verifier, .. } => {
                    answer.verifiers_used.insert(verifier.clone());
                }
            }
        }

        let on_target = matches!(reach, Reach::Target { .. });
        if on_target {
            // On the new rule's own target a policy-bearing rule always defeats the new
            // limit's claim to be the only one: an unreadable policy may let the agent through
            // with no signature, and a readable one keeps its own state.
            if usable_alone || (!policies.is_empty() && !readable) {
                if usable_alone && policies.is_empty() && !input.grant.stateful {
                    // The agent can already call the target without limit; a stateless rule
                    // beside it adds nothing but breaks nothing. Shown, not refused.
                    continue;
                }
                answer
                    .refusals
                    .push(overlap_finding(rule, target, &policy_addresses, &bound));
                continue;
            }
        } else if usable_alone {
            answer
                .refusals
                .push(delegate_authority_finding(rule, &reach));
        }

        match describe(
            input,
            rule,
            &signers,
            &policy_addresses,
            readable,
            on_target,
            &is_restricted,
        ) {
            Ok(requirement) => {
                let entry = AuthorityEntry {
                    rule_id: rule.id,
                    reach,
                    valid_until: rule.valid_until,
                    requirement,
                };
                if on_target {
                    answer.notes.target_rules.push(entry);
                } else {
                    answer.authority_list.push(entry);
                }
            }
            // The agent's authority is the stronger reason; do not bury it under a second
            // finding for the same rule.
            Err(_) if usable_alone => {}
            Err(finding) => answer.push_problem(finding),
        }
    }

    let scope = Scope {
        targets: vec![input.grant.target.clone()],
        account: input.account_address.clone(),
        bound_policies: input
            .bound_policies
            .iter()
            .map(|p| p.address.clone())
            .collect(),
    };
    // Only the classic accounts the answer consulted are committed: a reader that fetched
    // more (every classic signer in the closure, say) must not make two equal answers differ.
    for key in &input.grant.signers {
        match key {
            StoredSignerKey::Delegated { address } => {
                answer.classic_used.insert(address.clone());
            }
            StoredSignerKey::External { verifier, .. } => {
                answer.verifiers_used.insert(verifier.clone());
            }
        }
    }
    let authority_state = AuthorityState {
        ordered_state_digest,
        classic_accounts: input
            .classic_accounts
            .iter()
            .filter(|(address, _)| answer.classic_used.contains(*address))
            .map(|(address, entry)| (address.clone(), entry.clone()))
            .collect(),
        verifiers: input
            .verifiers
            .iter()
            .filter(|(address, _)| answer.verifiers_used.contains(*address))
            .map(|(address, entry)| (address.clone(), entry.clone()))
            .collect(),
    };
    let authority_commitment = ozpb_domain::canonical_hash(
        domains::SURFACE_VERDICT,
        &CommitmentPreimage {
            network_id: &input.network_id,
            registry_snapshot_root: input.registry_snapshot_root,
            account_address: &input.account_address,
            account_code_hash: &input.account_code_hash,
            spec_hash: input.spec_hash,
            binding_set_hash: input.binding_set_hash,
            bound_policies: &input.bound_policies,
            grant: &input.grant,
            scope: &scope,
            authority_list: &answer.authority_list,
            refusals: &answer.refusals,
            unresolved: &answer.unresolved,
            coverage_exclusions: &answer.coverage_exclusions,
            notes: &answer.notes,
            authority_state: &authority_state,
        },
    )
    .map_err(|error| CheckError::Internal(format!("committing the authority result: {error}")))?;

    Ok(SurfaceVerdict {
        observed_ledger: input.current_ledger,
        network_id: input.network_id.clone(),
        account_address: input.account_address.clone(),
        account_code_hash: input.account_code_hash.clone(),
        spec_hash: input.spec_hash,
        binding_set_hash: input.binding_set_hash,
        bound_policy_addresses: scope.bound_policies.clone(),
        grant: input.grant.clone(),
        scope,
        authority_list: answer.authority_list,
        refusals: answer.refusals,
        unresolved: answer.unresolved,
        coverage_exclusions: answer.coverage_exclusions,
        notes: answer.notes,
        authority_state,
        authority_commitment,
    })
}

#[derive(Default)]
struct Answer {
    authority_list: Vec<AuthorityEntry>,
    refusals: Vec<Finding>,
    unresolved: Vec<Finding>,
    coverage_exclusions: Vec<ExcludedRule>,
    notes: Notes,
    classic_used: BTreeSet<String>,
    verifiers_used: BTreeSet<String>,
}

impl Answer {
    fn push_problem(&mut self, problem: Finding) {
        if problem.code == FindingCode::IncompleteAccountState {
            self.unresolved.push(problem);
        } else {
            self.refusals.push(problem);
        }
    }
}

/// Canonical commitment input, including the registry root and bound-policy code observations
/// that are not carried by [`SurfaceVerdict`]. Excludes the observed ledger and acquisition evidence.
#[derive(Serialize)]
struct CommitmentPreimage<'a> {
    network_id: &'a str,
    registry_snapshot_root: Hash32,
    account_address: &'a str,
    account_code_hash: &'a str,
    spec_hash: Hash32,
    binding_set_hash: Hash32,
    bound_policies: &'a [BoundPolicy],
    grant: &'a Grant,
    scope: &'a Scope,
    authority_list: &'a [AuthorityEntry],
    refusals: &'a [Finding],
    unresolved: &'a [Finding],
    coverage_exclusions: &'a [ExcludedRule],
    notes: &'a Notes,
    authority_state: &'a AuthorityState,
}

fn policy_semantics(input: &CheckInput<'_>, policy: &StoredPolicy) -> PolicySignerSemantics {
    match input.recognized_policies.get(&policy.address) {
        Some(verified) if verified.wasm_hash == policy.observed_wasm_hash => verified.signers,
        _ => PolicySignerSemantics::Unknown,
    }
}

/// Findings about the new rule itself, before any stored rule is read.
fn grant_findings(input: &CheckInput<'_>, answer: &mut Answer) {
    let st = input.account_state;
    let target = input.grant.target.as_str();
    // A restricted key that is a contract is a nested account controlled through its own
    // rules, which this check does not read: who really holds the agent's power is unknown.
    for key in &input.grant.signers {
        if let StoredSignerKey::External { verifier, key_hex } = key {
            // Who holds a key behind a verifier is whatever that verifier accepts; one this
            // check does not recognize could accept other keys, or the agent's under another
            // encoding the aliasing would miss.
            if let Err(problem) = external_key(input, verifier, key_hex) {
                answer.push_problem(problem.into_finding(
                    None,
                    "the new rule's signer",
                    "name the agent's own classic account as the signer, or a well-formed key \
                     behind a verifier the registry recognizes",
                ));
            }
        }
        if let StoredSignerKey::Delegated { address } = key {
            if matches!(
                stellar_strkey::Strkey::from_string(address),
                Ok(stellar_strkey::Strkey::PublicKeyEd25519(_))
            ) {
                // The agent's own classic account is read like any other: one with other
                // signers is controlled by keys this check cannot name, and one that does not
                // exist cannot authenticate now.
                if let Err(problem) = classic_account(input, address) {
                    answer.push_problem(problem.into_finding(
                        None,
                        "the new rule's signer",
                        "name an existing agent account controlled by its master key alone",
                    ));
                }
            } else {
                answer.refusals.push(Finding {
                    code: FindingCode::UnsupportedAuthority,
                    rule_id: None,
                    unsupported: Some(UnsupportedReason::ContractSigner),
                    reason: format!(
                        "the new rule's signer {address} is not a classic account key; a \
                         contract signer acts through its own rules, which this check does not \
                         read, so it cannot tell who would hold the agent's power"
                    ),
                    remediation: "name the agent's own key (a G… account or a key behind a \
                                  recognized verifier) as the signer"
                        .to_string(),
                });
            }
        }
    }

    // Contracts the account itself trusts: installed policies (any rule, expired too), the
    // verifiers and contract signers it names. Their `install`/`uninstall` and admin paths
    // accept the account's own authorization, so a grant on one would let the agent reset
    // another rule's state or act as the account towards it.
    let mut trusted: BTreeMap<&str, &'static str> = BTreeMap::new();
    for policy in st.policies.values() {
        trusted.insert(
            policy.address.as_str(),
            "a policy installed on this account",
        );
    }
    for signer in st.signers.values() {
        match &signer.key {
            StoredSignerKey::External { verifier, .. } => {
                trusted.insert(verifier.as_str(), "a signature verifier this account uses");
            }
            StoredSignerKey::Delegated { address }
                if matches!(
                    stellar_strkey::Strkey::from_string(address),
                    Ok(stellar_strkey::Strkey::Contract(_))
                ) =>
            {
                trusted.insert(address.as_str(), "a contract that signs for this account");
            }
            StoredSignerKey::Delegated { .. } => {}
        }
    }

    if target == input.account_address {
        answer.refusals.push(Finding {
            code: FindingCode::UnsafeManagementSurface,
            rule_id: None,
            unsupported: None,
            reason: "the new rule targets the account itself, so it would let the agent call \
                     the account's management methods"
                .to_string(),
            remediation: "target the contract the agent should call, never the account".to_string(),
        });
    } else if input.bound_policies.iter().any(|p| p.address == target) {
        answer.refusals.push(Finding {
            code: FindingCode::UnsafeCallSurface,
            rule_id: None,
            unsupported: None,
            reason: format!(
                "the new rule targets {target}, one of the policies it installs, so the agent \
                 could uninstall and reinstall that policy"
            ),
            remediation: "target the contract the agent should call, never one of its policies"
                .to_string(),
        });
    } else if let Some(what) = trusted.get(target) {
        answer.refusals.push(Finding {
            code: FindingCode::UnsafeCallSurface,
            rule_id: None,
            unsupported: None,
            reason: format!(
                "the new rule targets {target}, which is {what}; its methods accept the \
                 account's own authorization, so the agent could reset another rule's state or \
                 act as the account there"
            ),
            remediation: "target the contract the agent should call".to_string(),
        });
    }
}

fn delegate_authority_finding(rule: &StoredRule, reach: &Reach) -> Finding {
    let what = match reach {
        Reach::Policy { address } => format!(
            "call policy {address} directly, so it could uninstall and reinstall the policy and \
             reset its counters"
        ),
        _ => "act on the account, so it could remove or widen this limit itself".to_string(),
    };
    Finding {
        code: FindingCode::DelegateHasAuthority,
        rule_id: Some(rule.id),
        unsupported: None,
        reason: format!(
            "rule {} lets the agent's key, without anyone else, {what}",
            rule.id
        ),
        remediation: format!(
            "remove the agent's key from rule {}, or use a different agent key, then re-run \
             the check",
            rule.id
        ),
    }
}

fn overlap_finding(
    rule: &StoredRule,
    target: &str,
    policy_addresses: &[String],
    bound: &BTreeSet<&str>,
) -> Finding {
    let installed = policy_addresses
        .iter()
        .find(|address| bound.contains(address.as_str()));
    let reason = match installed {
        Some(policy) => format!(
            "rule {} on {target} already carries policy {policy}: this grant looks installed \
             already, and a second copy would keep its own counters",
            rule.id
        ),
        None if !policy_addresses.is_empty() => format!(
            "rule {} can authorize calls to {target} under policies ({}) that may let the agent \
             through, so the new limit would not be the only one",
            rule.id,
            policy_addresses.join(", ")
        ),
        None => format!(
            "the agent can already call {target} through rule {} without anyone else, so the \
             new limit would not bound what the agent can do there",
            rule.id
        ),
    };
    Finding {
        code: FindingCode::DelegateGrantOverlap,
        rule_id: Some(rule.id),
        unsupported: None,
        reason,
        remediation: format!(
            "remove rule {} first (two rules on one contract never share a limit), then re-run \
             the check",
            rule.id
        ),
    }
}

/// Why something inside the scope cannot be described: a shape this version refuses, or a
/// piece of evidence that was not read.
struct Problem {
    code: FindingCode,
    unsupported: Option<UnsupportedReason>,
    what: String,
}

impl Problem {
    fn unsupported(reason: UnsupportedReason, what: String) -> Self {
        Problem {
            code: FindingCode::UnsupportedAuthority,
            unsupported: Some(reason),
            what,
        }
    }

    fn into_finding(self, rule_id: Option<u32>, subject: &str, remediation: &str) -> Finding {
        let reason = match self.code {
            FindingCode::IncompleteAccountState => format!(
                "{subject}: {}; this check cannot answer without it, so it does not",
                self.what
            ),
            _ => format!(
                "{subject}: {}; this version does not support that, so it refuses",
                self.what
            ),
        };
        Finding {
            code: self.code,
            rule_id,
            unsupported: self.unsupported,
            reason,
            remediation: remediation.to_string(),
        }
    }
}

/// Describe a live in-scope rule exactly, or say by name why it cannot be. Accepted forms
/// are surface-specific: a rule that can change the account or reach a bound policy must be
/// policy-free (all signers sign); a rule on the target may carry policies whose signer
/// semantics are established, and is then described by those semantics — never projected to
/// "all of" from its stored signer list.
fn describe(
    input: &CheckInput<'_>,
    rule: &StoredRule,
    signers: &[&StoredSignerKey],
    policy_addresses: &[String],
    readable: bool,
    on_target: bool,
    is_restricted: &impl Fn(&StoredSignerKey) -> bool,
) -> Result<Requirement, Finding> {
    let subject = format!("rule {}", rule.id);
    let remediation = format!(
        "replace rule {} with a policy-free rule whose signers are existing classic accounts \
         controlled by their master keys (or narrow its context away from the account, the \
         policies and the target), then re-run the check",
        rule.id
    );
    let fail = |problem: Problem| problem.into_finding(Some(rule.id), &subject, &remediation);
    if !policy_addresses.is_empty() && (!on_target || !readable) {
        return Err(fail(Problem::unsupported(
            UnsupportedReason::PolicyGuarded,
            format!(
                "its policies ({}) decide who may sign — a k-of-n threshold, a guarded recovery \
                 rule, or a policy whose treatment of signers is not established, which may \
                 accept no signer at all",
                policy_addresses.join(", ")
            ),
        )));
    }
    if signers.is_empty() && policy_addresses.is_empty() {
        return Err(fail(Problem::unsupported(
            UnsupportedReason::EmptyRule,
            "it names neither signers nor policies".to_string(),
        )));
    }
    let mut identities = Vec::with_capacity(signers.len());
    for key in signers {
        identities.push(identity(input, key, is_restricted(key)).map_err(fail)?);
    }
    Ok(if policy_addresses.is_empty() {
        Requirement::AllOf {
            signers: identities,
        }
    } else {
        Requirement::AnyOf {
            signers: identities,
            policies: policy_addresses.to_vec(),
        }
    })
}

/// One signer as a required identity, or why it cannot be one.
fn identity(
    input: &CheckInput<'_>,
    key: &StoredSignerKey,
    aliases_restricted_key: bool,
) -> Result<Identity, Problem> {
    match key {
        StoredSignerKey::Delegated { address } => {
            match stellar_strkey::Strkey::from_string(address) {
                Ok(stellar_strkey::Strkey::PublicKeyEd25519(public_key)) => {
                    classic_account(input, address)?;
                    Ok(Identity::ClassicAccount {
                        address: address.clone(),
                        ed25519_public_key: hex::encode(public_key.0),
                        aliases_restricted_key,
                    })
                }
                Ok(stellar_strkey::Strkey::Contract(_)) => Err(Problem::unsupported(
                    UnsupportedReason::ContractSigner,
                    format!(
                        "its signer {address} is a contract (a nested smart account) that \
                         authorizes through rules this check does not read"
                    ),
                )),
                _ => Err(Problem::unsupported(
                    UnsupportedReason::UnrecognizedSigner,
                    format!("its signer {address} is neither a classic account nor a contract"),
                )),
            }
        }
        StoredSignerKey::External { verifier, key_hex } => {
            let (observation, scheme, public_key) = external_key(input, verifier, key_hex)?;
            Ok(Identity::External {
                verifier: verifier.clone(),
                verifier_code_hash: observation.code_hash.clone(),
                scheme,
                public_key: hex::encode(public_key),
                aliases_restricted_key,
            })
        }
    }
}

/// An external signer's verifier and canonical key, or why it cannot be an identity. The
/// canonical forms follow OZ `stellar-accounts` 0.7.2: the ed25519 verifier takes exactly a
/// `BytesN<32>`; the WebAuthn verifier reads the first 65 bytes (`canonicalize_key`) and
/// ignores any credential id after them.
fn external_key<'a>(
    input: &'a CheckInput<'_>,
    verifier: &str,
    key_hex: &str,
) -> Result<(&'a VerifierObservation, KeyScheme, Vec<u8>), Problem> {
    if !matches!(
        stellar_strkey::Strkey::from_string(verifier),
        Ok(stellar_strkey::Strkey::Contract(_))
    ) {
        return Err(Problem::unsupported(
            UnsupportedReason::ExternalSigner,
            format!("its verifier {verifier} is not a contract, so no code can check its key"),
        ));
    }
    let observation = input.verifiers.get(verifier).ok_or_else(|| Problem {
        code: FindingCode::IncompleteAccountState,
        unsupported: None,
        what: format!("the code of verifier {verifier} was not observed with the rest"),
    })?;
    let Some(scheme) = observation.scheme else {
        return Err(Problem::unsupported(
            UnsupportedReason::ExternalSigner,
            format!(
                "it is checked by verifier contract {verifier}, whose code {} is not a \
                 recognized immutable, stateless owner verifier",
                observation.code_hash
            ),
        ));
    };
    let malformed = |why: &str| {
        Problem::unsupported(
            UnsupportedReason::MalformedKey,
            format!("its key for verifier {verifier} {why}, so it can never sign"),
        )
    };
    let bytes = hex::decode(key_hex).map_err(|_| malformed("is not hex"))?;
    let canonical = match scheme {
        KeyScheme::Ed25519 if bytes.len() == 32 => bytes,
        KeyScheme::Ed25519 => return Err(malformed("is not exactly a 32-byte ed25519 key")),
        KeyScheme::WebauthnP256 if bytes.len() >= 65 && bytes[0] == 0x04 => bytes[..65].to_vec(),
        KeyScheme::WebauthnP256 => {
            return Err(malformed(
                "does not start with a 65-byte uncompressed P-256 point",
            ))
        }
    };
    Ok((observation, scheme, canonical))
}

/// A `Delegated(G…)` signer authorizes through the classic account: the host loads its entry
/// and accepts any signer set meeting the medium threshold. So it is one identity — its
/// master key — only when the entry exists, names no other signer, and the master key alone
/// meets the threshold.
fn classic_account(input: &CheckInput<'_>, address: &str) -> Result<(), Problem> {
    match input.classic_accounts.get(address) {
        None => Err(Problem {
            code: FindingCode::IncompleteAccountState,
            unsupported: None,
            what: format!("classic account {address} was not read with the rest"),
        }),
        Some(ClassicAccount::NotFound) => Err(Problem::unsupported(
            UnsupportedReason::ClassicAccountMissing,
            format!(
                "classic account {address} does not exist and cannot authenticate now; a \
                 rescan after it is created is needed"
            ),
        )),
        Some(ClassicAccount::Found {
            master_weight,
            medium_threshold,
            signers,
            ..
        }) if !signers.is_empty() || *master_weight == 0 || master_weight < medium_threshold => {
            Err(Problem::unsupported(
                UnsupportedReason::ClassicMultisig,
                format!(
                    "classic account {address} has other signers, or its master key alone does \
                     not meet its medium threshold, so keys other than its own decide for it; \
                     classic multisig is not analysed"
                ),
            ))
        }
        Some(ClassicAccount::Found { .. }) => Ok(()),
    }
}

/// Reconcile the enumerated rules against `NextId` and `Count`, and require the transitive
/// closure. Returns the stored (non-removed) rules, expired ones included.
fn reconcile(st: &AccountState) -> Result<Vec<&StoredRule>, CheckError> {
    let mut stored: Vec<&StoredRule> = Vec::new();
    for (id, rule) in &st.rules {
        if *id >= st.next_id {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule id {id} >= next_id {}", st.next_id),
            });
        }
        if rule.id != *id {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule keyed {id} carries id {}", rule.id),
            });
        }
        stored.push(rule);
    }
    // Both directions fail closed. A deficit means some rule did not decode; this core
    // cannot tell whether it was archived, missing, or undecodable. An archived rule could
    // be restored and used in the same invocation, so the scan cannot proceed (D6). A
    // surplus says the supplied snapshot disagrees with itself and must be re-read.
    if (stored.len() as u32) < st.active_count {
        return Err(CheckError::IncompleteState {
            cause: IncompleteCause::UnresolvedRule,
            detail: format!(
                "decoded {} live rules but active_count is {}",
                stored.len(),
                st.active_count
            ),
        });
    }
    if (stored.len() as u32) > st.active_count {
        return Err(CheckError::IncompleteState {
            cause: IncompleteCause::SnapshotMismatch,
            detail: format!(
                "decoded {} live rules but active_count is only {}",
                stored.len(),
                st.active_count
            ),
        });
    }
    for rule in &stored {
        let signer_ids: BTreeSet<&u32> = rule.signer_ids.iter().collect();
        let policy_ids: BTreeSet<&u32> = rule.policy_ids.iter().collect();
        if signer_ids.len() != rule.signer_ids.len() || policy_ids.len() != rule.policy_ids.len() {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule {} contains duplicate signer or policy ids", rule.id),
            });
        }
        for sid in &rule.signer_ids {
            match st.signers.get(sid) {
                None => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::Missing,
                        detail: format!("rule {} references absent signer id {sid}", rule.id),
                    })
                }
                Some(signer) if signer.id != *sid => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::SnapshotMismatch,
                        detail: format!("signer keyed {sid} carries id {}", signer.id),
                    });
                }
                Some(_) => {}
            }
        }
        for pid in &rule.policy_ids {
            match st.policies.get(pid) {
                None => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::Missing,
                        detail: format!("rule {} references absent policy id {pid}", rule.id),
                    })
                }
                Some(policy) if policy.id != *pid => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::SnapshotMismatch,
                        detail: format!("policy keyed {pid} carries id {}", policy.id),
                    });
                }
                Some(_) => {}
            }
        }
    }
    Ok(stored)
}

/// Expired exactly when OZ refuses the rule: `valid_until < ledger` (`storage.rs`).
fn is_expired(rule: &StoredRule, ledger: u32) -> bool {
    matches!(rule.valid_until, Some(v) if ledger > v)
}

/// The key bytes a signer authenticates with, as far as this crate can tell.
#[derive(Debug, PartialEq, Eq)]
enum KeyMaterial {
    /// A classic account's ed25519 key, or an external signer's raw key data.
    Bytes(Vec<u8>),
    /// A contract address, or anything that did not decode: compared as stored.
    Opaque(StoredSignerKey),
}

fn key_material(key: &StoredSignerKey) -> KeyMaterial {
    match key {
        StoredSignerKey::Delegated { address } => {
            match stellar_strkey::Strkey::from_string(address) {
                Ok(stellar_strkey::Strkey::PublicKeyEd25519(public_key)) => {
                    KeyMaterial::Bytes(public_key.0.to_vec())
                }
                _ => KeyMaterial::Opaque(key.clone()),
            }
        }
        StoredSignerKey::External { key_hex, .. } => match hex::decode(key_hex) {
            Ok(bytes) => KeyMaterial::Bytes(bytes),
            Err(_) => KeyMaterial::Opaque(key.clone()),
        },
    }
}

impl KeyMaterial {
    /// Whether two signers may be the same key. Deliberately an over-approximation: the
    /// same bytes behind any verifier, or key data sharing its first 32 bytes (an ed25519
    /// key; a WebAuthn key with different credential-id suffixes), count as the same key.
    /// Treating two keys as one can only add a refusal or remove an owner, never hide the
    /// agent.
    fn aliases(&self, other: &KeyMaterial) -> bool {
        match (self, other) {
            (KeyMaterial::Bytes(a), KeyMaterial::Bytes(b)) => {
                a == b || (a.len() >= 32 && b.len() >= 32 && a[..32] == b[..32])
            }
            (a, b) => a == b,
        }
    }
}

/// Identity of the enumerated state a result was computed over, so a consumer can tell
/// whether the result still describes the account it is holding.
///
/// **Domain.** `ACCOUNT_STATE`, which names this structure. Not `REGISTRY_SNAPSHOT`, which names
/// another one — two structures under one domain forfeit the separation the domains exist for.
/// Not `SURFACE_VERDICT` either: that names the whole result, digested separately as
/// `authority_commitment`.
///
/// **Version prefix.** Present, matching `spec_hash`, `recording_hash`, `BuildManifest::hash`
/// and `snapshot_root`. The workspace is not uniform here — `signer_set_hash`,
/// `codegen_input_hash`, `binding_set_hash` and `auth_fingerprint` omit it, so a
/// canonicalization bump would move four of the eight preimages and leave four still. That
/// inconsistency is real and is not this function's to resolve; the prefix is included because
/// the alternative is to add a fifth omission.
///
/// **Ordering.** The maps in `AccountState` are `BTreeMap`, but `StoredRule::signer_ids` and
/// `policy_ids` are `Vec<u32>`, so their order is part of the digest. `check` does not depend on
/// that order — it reads both as sets — so permuting a rule's ids yields a different digest for
/// a state the logic treats as identical. The direction is safe: the consumer sees "state
/// changed" and re-runs a check that returns the same answer. Normalizing the vecs into the
/// preimage would remove the spurious difference, and would also silently equate two stored
/// states that the account itself stores differently.
///
/// **Fallible rather than lossy.** A serialization failure must not resolve to a digest. Falling
/// back to empty bytes would hand every failing state the same identity, and a consumer
/// comparing digests would read that as a match.
fn state_digest(st: &AccountState) -> Result<Hash32, CheckError> {
    ozpb_domain::canonical_hash(domains::ACCOUNT_STATE, st)
        .map_err(|error| CheckError::Internal(format!("digesting account state: {error}")))
}

#[cfg(test)]
mod tests;
