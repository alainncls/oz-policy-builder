//! Wire types for reference evaluation, verification, live policy checks, and install intent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The caller's transaction envelope, including any intended authorization entries,
/// simulated with authorization enforced by the RPC endpoint.
/// The envelope is the exact transaction being tested. `rpc_url` is subject to the
/// server's operator allowlist in hosted mode; a local CLI or stdio server uses the
/// caller's chosen endpoint. Simulation does not submit the transaction, but that does not
/// make a signed envelope harmless: a Soroban authorization signature covers the network,
/// the entry's nonce, its `signatureExpirationLedger` and the invocation, not the transaction
/// that carries it, so anyone who sees the entry can submit it until it expires, and
/// simulation does not consume the nonce. The envelope reaches the RPC endpoint and, through
/// MCP, the agent's transcript. A hosted server refuses an envelope carrying transaction
/// signatures or signed entries with `E_UNSUPPORTED_ENVELOPE`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightTransactionInput {
    pub rpc_url: String,
    pub network_passphrase: String,
    pub envelope_xdr_base64: String,
}

/// One RPC-reported simulation of the exact envelope. `simulated_success` means that
/// this transaction's invocation simulated successfully at the reported ledger with
/// authorization enforcement, with exactly the envelope's declared Soroban footprint and at
/// least the simulated disk-read and write bytes declared. It does not establish that the
/// declared instructions and resource fee suffice (see `below_endpoint_estimate`), identify
/// which policy was selected, predict a later ledger, or say that any writes were committed.
/// Required restoration and an insufficient declaration are separate outcomes.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightTransactionOutput {
    /// SHA-256 of canonical envelope XDR bytes, not a transaction hash. The endpoint received
    /// exactly these bytes, base64-encoded.
    pub envelope_xdr_sha256: String,
    pub network_id: String,
    /// Ledger sequence as reported by the selected RPC endpoint.
    pub reported_ledger: u32,
    pub outcome: PreflightTransactionOutcome,
    /// Each declared Soroban resource that does not match what the simulation used. Non-empty
    /// exactly when `outcome` is `declared_resources_insufficient`. Footprint keys are not
    /// named: they are confidential envelope content.
    pub insufficient_declared_resources: Vec<PreflightDeclaredResource>,
    /// Advice only: declared values below the endpoint's padded estimate, compared only after
    /// a simulated success (`simulated_success` or `declared_resources_insufficient`) and empty
    /// otherwise. It never changes `outcome`: a declaration below an estimate can still cover
    /// the use, and one above it can still fall short at the network's rates.
    pub below_endpoint_estimate: Vec<PreflightEstimatedResource>,
    /// `enforce`, as opposed to recording authorization without enforcing it.
    pub auth_mode: String,
    /// `rpc_reported`; the endpoint supplies the simulation result.
    pub evidence_trust: String,
    /// Always true for a live RPC simulation.
    pub state_dependent: bool,
    /// Always false for a simulation.
    pub writes_committed: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreflightTransactionOutcome {
    /// The invocation succeeded at the endpoint's state. The envelope declares exactly the
    /// simulated footprint and at least the simulated disk-read and write bytes; its
    /// instructions and resource fee are not established.
    SimulatedSuccess,
    /// The endpoint reported an error after reading its ledger: an invocation or authorization
    /// failure, or an error inside its simulator. The endpoint's text is withheld because it
    /// can echo the envelope. A refusal before the endpoint read its ledger is an error.
    SimulationFailed,
    /// Success needed archived entries restored first, whether by a separate restoration
    /// preamble or inside the simulation. It is not a success against current state.
    RestorationRequired,
    /// The invocation succeeded in simulation, but in each listed dimension the envelope as
    /// written does not declare what the simulation used, so the simulation does not show that
    /// the envelope can succeed.
    DeclaredResourcesInsufficient,
}

/// A part of the envelope's declared Soroban transaction data that must match the simulated
/// one, which the endpoint reports as used, without padding. An envelope without Soroban
/// transaction data declares an empty footprint and zero limits.
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum PreflightDeclaredResource {
    /// The declared read-only list is not exactly the simulated one, in any order: a key is
    /// missing, extra, or repeated. Extra keys are not harmless: the network charges for the
    /// declared footprint.
    ReadOnlyFootprint,
    /// The declared read-write list is not exactly the simulated one, in any order.
    ReadWriteFootprint,
    /// The declared disk-read bytes are below the simulated use.
    DiskReadBytes,
    /// The declared write bytes are below the simulated use.
    WriteBytes,
}

/// A declared value below the endpoint's own padded estimate for it. Advice only, because the
/// endpoint reports these padded rather than as used.
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum PreflightEstimatedResource {
    /// Below the endpoint's recommended instruction budget, which pads the simulated use.
    Instructions,
    /// Below the endpoint's resource fee estimate, priced from padded resources at its
    /// reported ledger's rates.
    ResourceFee,
}

/// Require a nullable wire field to be present: omission must not deserialize as an
/// explicit `null` value. `#[schemars(required)]` keeps the JSON Schema aligned.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// --- reference_suite (layer 1 of the future four-layer dry_run) --------------------------

/// Layer-1 reference evaluation only. The full `dry_run` operation also needs contract
/// integration, a disposable environment, and live preflight (§4.5); this type does not
/// claim those layers or expose mutation modes.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferenceSuiteInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceSuiteOutput {
    /// The labeled permit/deny evidence report (layer 1) as JSON.
    pub report: serde_json::Value,
    pub total: usize,
    pub disagreements: usize,
    /// True iff the original permits and every derived deny-case denies.
    pub all_agree: bool,
    /// Composed **reviewed** policies (e.g. `oz:spending_limit`) that layer 1 does NOT
    /// model, as `"rule[<i>]: <kind>"`. When non-empty, `all_agree` covers only the
    /// scope+count semantics — the listed policies are enforced on-chain but their stateful
    /// caps/windows are outside this report. Never read `all_agree` as coverage of these.
    pub unmodeled_reviewed_policies: Vec<String>,
    /// Boundary classes actually exercised, as `"<class>: <count>"`. `all_agree` is silent
    /// about coverage, so this is what says how wide the evidence is.
    pub coverage: Vec<String>,
    /// Classes a rule's shape requires but the suite did not exercise, as
    /// `"rule[<i>]: <class>"`. Checked per rule, so one rule's coverage cannot vouch for
    /// another's gap. Non-empty means the evidence is narrower than `all_agree` implies — a
    /// gate failure, not a warning.
    pub missing_classes: Vec<String>,
    /// Classes exercised but never shown to *deny*, as `"rule[<i>]: <class>"`. Usually a
    /// degenerate bound rather than a gap — a cap of `i128::MAX` cannot be exceeded — so this
    /// is reported, not gated. It means the grant is effectively unbounded on that axis.
    pub permit_only_classes: Vec<String>,
}

// --- verify ----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    pub rule_index: usize,
    /// Every generated file except `Cargo.lock`, as relative path → contents. This is
    /// exactly the set hashed into `source_hash`: it includes `Cargo.toml`,
    /// `rust-toolchain.toml`, `rustfmt.toml`, `src/lib.rs`, and `src/contract.rs`.
    ///
    /// The implementation must compare the complete key set as well as contents. A missing
    /// manifest/toolchain file or an extra source module is a mismatch, not reproduction.
    #[serde(default)]
    pub claimed_generated_files: std::collections::BTreeMap<String, String>,
    /// Built artifact to reproduce. Omission is reported as not verified, never success.
    #[serde(default)]
    pub claimed_wasm_base64: Option<String>,
    /// BuildManifest supplied with the artifact. Omission is reported separately.
    #[serde(default)]
    pub claimed_build_manifest: Option<serde_json::Value>,
    /// Instead of the three claimed fields: the `build_manifest_hash` that `generate_code`
    /// returned earlier in the same MCP session. That server substitutes the files, Wasm and
    /// manifest it built before anything is checked or hashed, so the request is evaluated
    /// exactly as if they had been sent — without copying a crate and its Wasm through the
    /// conversation. Every other entry point refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_artifact: Option<String>,
}

/// Each dimension is reported separately — never collapsed into one "pure" boolean
/// (architecture §6.3). Live preflight remains state-dependent and separate.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VerifyOutput {
    pub spec_conformance: String,
    pub source_reproduction: String,
    pub offline_behavioral_conformance: String,
    pub wasm_reproduction: String,
    pub current_network_preflight: String,
    pub normalized_input_hash: String,
    /// Whether layer 1 models **every** policy composed into this rule. Its own dimension,
    /// deliberately not folded into `matches`: "the reproductions agree" and "the evidence
    /// covers every composed policy" are different claims, and collapsing them would let a
    /// green `matches` imply coverage the report does not have.
    pub models_all_policies: bool,
    /// The composed reviewed policies layer 1 does not model, as `"rule[<i>]: <kind>"`.
    /// Non-empty means those policies are enforced only on-chain.
    pub unmodeled_reviewed_policies: Vec<String>,
    pub matches: bool,
}

// --- check_against_policy --------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckAgainstPolicyInput {
    /// PolicySpec and exact installed instance bindings. Recognition is verified by the
    /// toolkit; there is deliberately no caller-supplied `recognized` boolean.
    pub spec: serde_json::Value,
    pub binding_set: PolicyBindingSet,
    pub signed_registry_snapshot: serde_json::Value,
    /// Index of the policy rule in `spec`; this is not an on-chain rule ID.
    pub rule_index: usize,
    /// On-chain context-rule ID selected for this check, not a claim about its state.
    /// The server must read the rule at the observation ledger, verify its context,
    /// validity and policy addresses against the selected spec rule and binding set,
    /// then evaluate its live signers under the spec's authorization semantics. A missing
    /// or mismatched rule cannot produce a permit. Never infer this ID from `rule_index`.
    pub installed_context_rule_id: u32,
    /// Smart account whose installed rule and policy state will be read.
    pub account_address: String,
    /// Must match the spec and binding set; the server selects a configured endpoint.
    pub network_id: String,
    /// Name of a configured RPC source, never an arbitrary client URL.
    pub rpc_source: String,
    /// Candidate signer identities for this authorization. The server reads live rule
    /// signers, verifier code, counters and ledger state from the selected network.
    pub candidate_signers: Vec<PolicyCheckSigner>,
    /// Proposed invocation, not an observation of installed policy state.
    pub invocation: serde_json::Value,
}

impl CheckAgainstPolicyInput {
    /// Hash the complete typed request, including the spec, bindings, signed snapshot,
    /// account, network, both rule selectors, signer list, and invocation. The trusted
    /// server records this hash in every permit/deny result after validating the input.
    pub fn request_hash(&self) -> Result<ozpb_domain::Hash32, ozpb_domain::DomainError> {
        ozpb_domain::canonical_hash(ozpb_domain::domains::POLICY_CHECK_REQUEST, self)
    }
}

/// Signer identities proposed for a policy check. The current verifier implementation
/// hash is an observation, so an external signer cannot supply it here.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyCheckSigner {
    Delegated { address: String },
    External { verifier: String, key_hex: String },
}

/// A live permit/deny prediction must carry the observations on which it depends. If the
/// ledger state was not acquired, the only honest result is `Unsupported` (§4.6).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "prediction", rename_all = "snake_case", deny_unknown_fields)]
// Every tagged variant is an object; MCP also requires this at the schema root.
#[schemars(extend("type" = "object"))]
pub enum CheckAgainstPolicyOutput {
    Permit {
        evidence: PolicyCheckEvidence,
    },
    Deny {
        deny_reason: String,
        evidence: PolicyCheckEvidence,
    },
    Unsupported {
        reason: String,
        /// Present only when a complete endpoint observation was acquired.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<Box<PolicyCheckEvidence>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckEvidence {
    pub evidence_trust: PolicyCheckTrust,
    pub authentication_assumption: PolicyAuthenticationAssumption,
    /// Request identities. A consumer must compare these to the original request and
    /// independently verify the trusted server's response before relying on a prediction.
    pub account_address: String,
    pub network_id: String,
    pub rule_index: usize,
    /// The on-chain rule whose signer set and policy state were read. The wallet must
    /// select this same rule when authorizing the eventual transaction.
    pub installed_context_rule_id: u32,
    /// Hash of the validated PolicySpec and exact PolicyBindingSet used for this check.
    pub spec_hash: String,
    pub binding_set_hash: String,
    /// Root of the verified registry snapshot used to recognize policy implementations.
    pub registry_snapshot_root: String,
    /// Domain-separated canonical hash of the full [`CheckAgainstPolicyInput`], including
    /// the invocation and ordered candidate-signer identities. The server computes this
    /// via [`CheckAgainstPolicyInput::request_hash`]; it never accepts a caller claim.
    pub request_hash: String,
    /// Ledger at which every storage and configuration entry below was read.
    pub observed_ledger: u32,
    pub ledger_hash: String,
    /// Exact XDR key/value pairs and TTLs used to evaluate installed policy state.
    pub storage_reads: Vec<PolicyStateRead>,
    /// Exact XDR key/value pairs and TTLs used to resolve the selected account rule,
    /// its signers and policies, and the policies' own configuration.
    pub configuration_reads: Vec<PolicyStateRead>,
    /// Classic accounts have no TTL and are never encoded as contract-data observations.
    pub classic_account_reads: Vec<PolicyClassicAccountRead>,
    pub target_drift: Option<PolicyTargetDrift>,
    pub restoration: PolicyStateRestoration,
    /// State may change immediately after this observation. A new live check is needed
    /// immediately before a transaction is signed; this is not a validity interval.
    pub recheck_before_signing: RecheckBeforeSigning,
}

impl PolicyCheckEvidence {
    /// Check that this evidence belongs to the exact request the caller submitted.
    /// Artifact hashes and live observations still require validation by the trusted server.
    pub fn matches_request(
        &self,
        request: &CheckAgainstPolicyInput,
    ) -> Result<bool, ozpb_domain::DomainError> {
        Ok(self.account_address == request.account_address
            && self.network_id == request.network_id
            && self.rule_index == request.rule_index
            && self.installed_context_rule_id == request.installed_context_rule_id
            && self.request_hash == request.request_hash()?.to_hex())
    }
}

/// A prediction always requires a fresh live check immediately before signing.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecheckBeforeSigning {
    Required,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckTrust {
    RpcReported,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAuthenticationAssumption {
    CandidateSignersMustAuthenticate,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyClassicAccountRead {
    pub account_address: String,
    pub key_xdr_base64: String,
    /// Canonical Account LedgerEntryData XDR; None records endpoint omission.
    pub value_xdr_base64: Option<String>,
    pub last_modified_ledger: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyTargetDrift {
    pub expected_hash: String,
    pub observed_hash: String,
    /// True for an adapter-required or refuse-on-drift identity.
    pub refusal_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyStateRead {
    pub contract_address: String,
    pub key_xdr_base64: String,
    /// A checked absence or the exact value and TTL observed at the ledger anchor.
    pub observation: PolicyStateObservation,
}

/// A missing key is a real observation, not a missing field. A present entry always
/// carries both the XDR value and its TTL, so incomplete evidence cannot claim either.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyStateObservation {
    Absent,
    Present {
        /// Canonical full LedgerEntryData XDR, including its embedded key identity.
        value_xdr_base64: String,
        last_modified_ledger: u32,
        live_until_ledger: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStateRestoration {
    NotRequired,
    Restored,
    Required,
    /// Required persistence was omitted: it may never have existed or be archived.
    Unknown,
}

// --- policy binding + call-surface check ----------------------------------------------

pub const POLICY_BINDING_SET_SCHEMA: &str = "policy-binding-set/v1";

/// Exact deployed instances corresponding positionally to every PolicyRef in a spec.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBindingSet {
    pub schema: String,
    pub spec_hash: String,
    pub network_id: String,
    pub bindings: Vec<PolicyBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    pub rule_index: usize,
    pub policy_index: usize,
    pub contract_address: String,
    pub observed_wasm_hash: String,
    pub recognition: PolicyRecognition,
    /// Deployment transaction hash or immutable registry reference used to resolve this
    /// exact instance. Informational evidence; recognition is verified independently.
    pub resolution_reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRecognition {
    ReviewedRegistry,
    VerifiedGeneratedManifest { build_manifest: serde_json::Value },
}

/// Network-read operation. The trusted acquisition shell resolves `rpc_source` from configured
/// endpoints for `network_id`, validates both against the spec and binding set, and acquires
/// the account code, rule state, policy and verifier code and ledger anchor itself. Clients
/// cannot supply those observations, and nothing about who owns the account is accepted from
/// them: the authority list is derived from the ledger (Decision D7).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicyCallSurfaceInput {
    pub spec: serde_json::Value,
    /// The spec rule about to be installed. Its signers are the restricted keys the findings
    /// look for, and its target is the contract they may call. An index into the hashed
    /// spec, not a separate claim.
    pub rule_index: usize,
    pub binding_set: PolicyBindingSet,
    pub signed_registry_snapshot: serde_json::Value,
    pub account_address: String,
    pub network_id: String,
    /// Name of a configured RPC source, not an arbitrary client-provided URL.
    pub rpc_source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicyCallSurfaceOutput {
    pub spec_hash: String,
    pub binding_set_hash: String,
    /// Root of the verified signed snapshot used to recognize account and policy code.
    pub registry_snapshot_root: String,
    pub verdict: PolicyCallSurfaceVerdict,
    /// The verdict in plain words, for a person: scope, refusals first, who can change the
    /// account, what was not checked. Derived from `verdict`; never says "safe".
    pub summary: String,
}

/// Who could change the account, reset the bound policies, or call the new rule's target, at
/// one observed ledger, for the stated `scope` only. Never a safety verdict, and advisory to
/// whoever receives it over MCP: the wallet that holds the owner key recomputes it against its
/// own RPC and accepts only when `refusals` and `unresolved` are both empty and every
/// `authority_list` entry names at least one identity it trusts (its own keys, or identities
/// trusted through its protected UI, never one marked `aliases_restricted_key`) (Decision D7).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCallSurfaceVerdict {
    /// Not part of the commitment.
    pub observed_ledger: u32,
    pub network_id: String,
    pub account_address: String,
    pub account_code_hash: String,
    pub spec_hash: String,
    pub binding_set_hash: String,
    pub bound_policy_addresses: Vec<String>,
    /// The spec rule the answer is about, with its exact `add_context_rule` arguments.
    pub grant: PolicyGrant,
    /// What the answer covers: the target(s), the account's management surface and the bound
    /// policies. Never an account-wide "nothing else".
    pub scope: PolicyAuthorityScope,
    /// Every live rule that can change the account or reach a bound policy, as policy-free
    /// `all_of` requirements over resolved identities, in rule order.
    pub authority_list: Vec<PolicyAuthorityEntry>,
    /// Unconditional refusals inside the scope. Trust never overrides one.
    pub refusals: Vec<PolicySurfaceFinding>,
    /// Evidence gaps inside the scope. Any entry blocks acceptance.
    pub unresolved: Vec<PolicySurfaceFinding>,
    /// Live rules for other contracts: not analysed.
    pub coverage_exclusions: Vec<PolicyExcludedRule>,
    /// Information for the screen; none of it blocks.
    pub notes: PolicyAuthorityNotes,
    /// The authority-relevant state behind the answer (committed).
    pub authority_state: PolicyAuthorityState,
    /// How the state was acquired (recorded, never compared).
    pub evidence: PolicyAuthorityEvidence,
    /// Hash of the separate canonical `CommitmentPreimage` in `ozpb-call-surface-core`,
    /// documented in `docs/CANONICAL-HASHING.md`. It includes the registry snapshot root
    /// and each bound policy's address/code observation, not just the verdict's addresses.
    /// The observed ledger and acquisition evidence are excluded. Approval binds to this
    /// hash and the pre-signing re-read recomputes it; it authenticates nothing by itself.
    pub authority_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityScope {
    pub targets: Vec<String>,
    pub account: String,
    pub bound_policies: Vec<String>,
}

/// The rule being installed, as the check read it from the hashed spec.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrant {
    pub rule_index: u32,
    /// The contract the new `CallContract` rule targets.
    pub target: String,
    /// The rule keeps state between calls (a counter or a spending window).
    pub stateful: bool,
    /// The new rule's signers: the restricted keys the refusals look for.
    pub signers: Vec<PolicySignerKey>,
    pub name: String,
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub valid_until: Option<u32>,
    /// The new rule's `policies` map, in spec order.
    pub policies: Vec<PolicyGrantPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantPolicy {
    pub address: String,
    pub install_params: InstallPolicyParams,
}

/// A signer exactly as the account stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicySignerKey {
    Delegated { address: String },
    External { verifier: String, key_hex: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityEntry {
    pub rule_id: u32,
    pub reach: PolicyReach,
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub valid_until: Option<u32>,
    pub requirement: PolicyRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyReach {
    /// A `Default` rule: every call the account authorizes, management included.
    AnyCall,
    /// `CallContract(account)`: the account's own management methods.
    AccountCalls,
    /// `CallContract(bound policy)`: that policy's install/uninstall, which resets its state.
    Policy { address: String },
    /// `CallContract(target)`: a second way to call the new rule's target.
    Target { address: String },
}

/// Who must sign for the rule to authorize anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRequirement {
    /// A policy-free rule: every one of these must sign.
    AllOf { signers: Vec<PolicyIdentity> },
    /// Every policy is recognized as demanding at least one of the rule's own signers: any
    /// one of these, within those policies' further limits.
    AnyOf {
        signers: Vec<PolicyIdentity>,
        policies: Vec<String>,
    },
}

/// A required identity with what a wallet compares against its own keys. One marked
/// `aliases_restricted_key` must never be counted as an owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyIdentity {
    /// An existing classic Stellar account controlled by its master key alone.
    ClassicAccount {
        address: String,
        ed25519_public_key: String,
        aliases_restricted_key: bool,
    },
    /// A key behind a recognized owner verifier. Match on `scheme` + `public_key` (the
    /// canonical key); the verifier address is only where this account checks it, and the
    /// same key behind another copy of that verifier is the same identity. An ed25519 key here
    /// is also the same identity as a classic account whose master key it is.
    External {
        verifier: String,
        verifier_code_hash: String,
        scheme: PolicyKeyScheme,
        /// Canonical key, hex: 32 bytes for ed25519, the first 65 bytes for WebAuthn.
        public_key: String,
        aliases_restricted_key: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKeyScheme {
    Ed25519,
    WebauthnP256,
}

/// The code observed at a verifier, and its scheme when that code is a recognized owner
/// verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyVerifierObservation {
    pub code_hash: String,
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub scheme: Option<PolicyKeyScheme>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityNotes {
    /// Every live rule, in any context, naming one of the restricted keys.
    pub restricted_key_rules: Vec<PolicyRestrictedKeyRule>,
    /// Other rules on the target the agent cannot use alone: who else can call it.
    pub target_rules: Vec<PolicyAuthorityEntry>,
    /// Expired rules that would reach a protected surface or the target if revived.
    pub expired_rules: Vec<PolicyExpiredRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRestrictedKeyRule {
    pub rule_id: u32,
    pub context: PolicyRuleContext,
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub valid_until: Option<u32>,
    /// The restricted keys can use the rule without anyone else.
    pub usable_alone: bool,
    pub policy_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyExcludedRule {
    pub rule_id: u32,
    pub context: PolicyRuleContext,
    pub policy_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyExpiredRule {
    pub rule_id: u32,
    pub context: PolicyRuleContext,
    pub valid_until: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRuleContext {
    Default,
    CallContract { address: String },
    CreateContract { wasm_hash: String },
}

/// The authority-relevant state behind the answer; part of the commitment.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityState {
    /// Canonical hash of the ordered account rules and transitive storage entries, with every
    /// installed policy's observed code hash. TTLs are not in it.
    pub ordered_state_digest: String,
    /// Signing configuration of every classic account the answer consulted.
    pub classic_accounts: std::collections::BTreeMap<String, PolicyClassicAccount>,
    /// Code of every verifier the answer consulted.
    pub verifiers: std::collections::BTreeMap<String, PolicyVerifierObservation>,
}

/// How the state was acquired. Not part of the approval commitment — ledger numbers, TTLs and
/// endpoint metadata move without any change in authority — but every read was validated
/// against it (one reported ledger, requested keys only, complete reconciliation).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityEvidence {
    pub enumeration_evidence: PolicyRuleEnumerationEvidence,
    /// The operator's name for the RPC source; never its URL.
    pub source: String,
    /// `rpc_reported`: as trustworthy as the configured endpoint, no ledger proof.
    pub evidence_trust: String,
    /// Digest of every raw entry the read used (keys, values, TTLs, absences); it moves with
    /// every payment by a classic signer, which is why it is evidence and not the commitment.
    pub raw_ordered_entry_digest: String,
    pub rpc_batches: u32,
    pub attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyClassicAccount {
    NotFound,
    Found {
        master_weight: u8,
        low_threshold: u8,
        medium_threshold: u8,
        high_threshold: u8,
        signers: Vec<PolicyClassicSigner>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyClassicSigner {
    pub key: String,
    pub weight: u32,
}

/// Only complete enumeration strategies can produce a verdict. The reader must verify
/// the active count and resolve every rule's transitive signer and policy references.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRuleEnumerationEvidence {
    OnchainList {
        active_count: u32,
        rule_ids: Vec<u32>,
        signer_ids: Vec<u32>,
        policy_ids: Vec<u32>,
    },
    BoundedNextId {
        next_id: u32,
        active_count: u32,
        rule_ids: Vec<u32>,
        signer_ids: Vec<u32>,
        policy_ids: Vec<u32>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicySurfaceFinding {
    pub code: crate::ErrorCode,
    /// Absent when the finding is about the new rule itself.
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub rule_id: Option<u32>,
    /// Which shape this version refuses, on `E_UNSUPPORTED_AUTHORITY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<PolicyUnsupportedReason>,
    pub reason: String,
    pub remediation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyUnsupportedReason {
    /// A policy decides who may act: any policy on a rule that can change the account or reach
    /// a bound policy (a k-of-n threshold, a guarded recovery rule), or an unreadable one.
    PolicyGuarded,
    /// A contract signer (nested smart account).
    ContractSigner,
    /// An external signer whose verifier is not recognized.
    ExternalSigner,
    UnrecognizedSigner,
    /// A classic account with other signers or thresholds the master key cannot meet.
    ClassicMultisig,
    /// A classic account that does not exist, so cannot authenticate now.
    ClassicAccountMissing,
    /// Key data a recognized verifier can never accept.
    MalformedKey,
    EmptyRule,
}

// --- prepare_install_intent ------------------------------------------------------------

/// Exactly the authority check's request: the intent runs the check itself, so there is no
/// verdict for a caller to supply.
pub type PrepareInstallIntentInput = CheckPolicyCallSurfaceInput;

/// The install intent: the exact `add_context_rule` arguments, derived from the same `grant`
/// the authority answer's commitment covers, offered only when that answer has no refusal and
/// nothing unresolved. It is NOT a signed or even assembled transaction — assembling one needs
/// current sequence, fees, ledger bounds and restoration preambles (wallet-owned) — and NOT a
/// safety verdict: the wallet holding the owner key recomputes the answer, matches the listed
/// owners, and signs only on the user's confirmation (§6.2, Decision D7).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareInstallIntentOutput {
    pub operation: InstallOperation,
    /// The smart-account contract on which `add_context_rule` is invoked.
    pub account_contract: String,
    /// The contract named by the new rule's `CallContract` context.
    pub context_contract: String,
    pub rule_name: String,
    /// Explicit `null` means no expiration; omission must not silently grant one.
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub valid_until_ledger: Option<u32>,
    /// The account's typed signer arguments for `add_context_rule`, in the same shape the
    /// authority answer reports them.
    pub delegate_signers: Vec<PolicySignerKey>,
    /// One entry per policy in the selected spec rule. The preparer must match each
    /// index and address to the binding set, match the install parameters to the spec,
    /// and reject missing or duplicate indexes and addresses before returning an intent.
    pub policies: Vec<InstallPolicy>,
    pub next_steps: Vec<String>,
    /// The live authority answer these arguments were checked against; its
    /// `authority_commitment` covers them.
    pub authority: CheckPolicyCallSurfaceOutput,
}

/// The only account operation represented by a prepared install intent.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstallOperation {
    AddContextRule,
}

/// One address and its value in the account's `Map<Address, Val>` policy argument.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstallPolicy {
    /// Position in the selected PolicySpec rule and its PolicyBindingSet.
    pub policy_index: usize,
    /// The exact deployed address from that binding.
    pub address: String,
    pub install_params: InstallPolicyParams,
}

/// Account-install arguments for the policy kinds this toolkit composes. The assembler
/// encodes `Generated` as the generated policy's ignored `u32` value `0`. The spending
/// limit fields encode `SpendingLimitAccountParams` from the reviewed account library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallPolicyParams {
    Generated,
    SpendingLimit {
        /// Canonical decimal i128 from the spec's reviewed `limit` parameter.
        spending_limit: String,
        period_ledgers: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::no_build_settings_on_the_wire;

    /// A dry-run run hash covers its `VerifyInput`. With no reference — which is all the toolkit
    /// ever receives — the field is absent from JSON and from the canonical preimage, so the
    /// request hashes exactly as it did before the field existed.
    #[test]
    fn an_absent_artifact_reference_leaves_the_hashed_request_unchanged() {
        #[derive(Serialize)]
        struct Before {
            spec: serde_json::Value,
            rule_index: usize,
            claimed_generated_files: std::collections::BTreeMap<String, String>,
            claimed_wasm_base64: Option<String>,
            claimed_build_manifest: Option<serde_json::Value>,
        }
        let files = std::collections::BTreeMap::from([("src/lib.rs".into(), "x".into())]);
        let now = VerifyInput {
            spec: serde_json::json!({"schema": "policy-spec/v1"}),
            rule_index: 0,
            claimed_generated_files: files.clone(),
            claimed_wasm_base64: Some("AGFzbQ==".into()),
            claimed_build_manifest: Some(serde_json::json!({"m": 1})),
            generated_artifact: None,
        };
        let before = Before {
            spec: now.spec.clone(),
            rule_index: 0,
            claimed_generated_files: files,
            claimed_wasm_base64: now.claimed_wasm_base64.clone(),
            claimed_build_manifest: now.claimed_build_manifest.clone(),
        };
        assert_eq!(
            serde_json::to_value(&now).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        let domain = ozpb_domain::domains::DRY_RUN_REQUEST;
        assert_eq!(
            ozpb_domain::canonical_preimage_bytes(domain, &now).unwrap(),
            ozpb_domain::canonical_preimage_bytes(domain, &before).unwrap()
        );
    }

    #[test]
    fn the_wire_contract_carries_no_build_configuration() {
        for (dto, schema) in [
            (
                "PreflightTransactionInput",
                schemars::schema_for!(PreflightTransactionInput),
            ),
            ("VerifyInput", schemars::schema_for!(VerifyInput)),
            (
                "CheckAgainstPolicyInput",
                schemars::schema_for!(CheckAgainstPolicyInput),
            ),
            (
                "CheckPolicyCallSurfaceInput",
                schemars::schema_for!(CheckPolicyCallSurfaceInput),
            ),
        ] {
            no_build_settings_on_the_wire(dto, schema);
        }
    }

    #[test]
    fn every_policy_operations_dto_has_a_schema() {
        let _ = schemars::schema_for!(PreflightTransactionInput);
        let _ = schemars::schema_for!(PreflightTransactionOutput);
        let _ = schemars::schema_for!(PreflightTransactionOutcome);
        let _ = schemars::schema_for!(PreflightDeclaredResource);
        let _ = schemars::schema_for!(PreflightEstimatedResource);
        let _ = schemars::schema_for!(ReferenceSuiteInput);
        let _ = schemars::schema_for!(ReferenceSuiteOutput);
        let _ = schemars::schema_for!(VerifyInput);
        let _ = schemars::schema_for!(VerifyOutput);
        let _ = schemars::schema_for!(CheckAgainstPolicyInput);
        let _ = schemars::schema_for!(PolicyCheckSigner);
        let _ = schemars::schema_for!(CheckAgainstPolicyOutput);
        let _ = schemars::schema_for!(PolicyCheckEvidence);
        let _ = schemars::schema_for!(RecheckBeforeSigning);
        let _ = schemars::schema_for!(PolicyStateRead);
        let _ = schemars::schema_for!(PolicyStateObservation);
        let _ = schemars::schema_for!(PolicyStateRestoration);
        let _ = schemars::schema_for!(PolicyBindingSet);
        let _ = schemars::schema_for!(PolicyBinding);
        let _ = schemars::schema_for!(PolicyRecognition);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceInput);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceOutput);
        let _ = schemars::schema_for!(PolicyCallSurfaceVerdict);
        let _ = schemars::schema_for!(PolicyRuleEnumerationEvidence);
        let _ = schemars::schema_for!(PolicyGrant);
        let _ = schemars::schema_for!(PolicyAuthorityEntry);
        let _ = schemars::schema_for!(PolicyAuthorityNotes);
        let _ = schemars::schema_for!(PolicyAuthorityEvidence);
        let _ = schemars::schema_for!(PolicyAuthorityState);
        let _ = schemars::schema_for!(PolicyAuthorityScope);
        let _ = schemars::schema_for!(PolicyVerifierObservation);
        let _ = schemars::schema_for!(PolicyExpiredRule);
        let _ = schemars::schema_for!(PolicySurfaceFinding);
        let _ = schemars::schema_for!(PrepareInstallIntentInput);
        let _ = schemars::schema_for!(PrepareInstallIntentOutput);
        let _ = schemars::schema_for!(InstallOperation);
        let _ = schemars::schema_for!(InstallPolicy);
        let _ = schemars::schema_for!(InstallPolicyParams);
    }

    #[test]
    fn preflight_request_requires_the_exact_envelope_and_network() {
        let input = serde_json::json!({
            "rpc_url": "https://rpc.example",
            "network_passphrase": "Test SDF Network ; September 2015",
            "envelope_xdr_base64": "AAAA"
        });
        assert!(serde_json::from_value::<PreflightTransactionInput>(input.clone()).is_ok());
        for field in ["rpc_url", "network_passphrase", "envelope_xdr_base64"] {
            let mut absent = input.clone();
            absent.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<PreflightTransactionInput>(absent).is_err(),
                "missing {field} must fail"
            );
        }
        let mut extra = input;
        extra["auth_mode"] = serde_json::json!("record");
        assert!(serde_json::from_value::<PreflightTransactionInput>(extra).is_err());
    }

    #[test]
    fn preflight_outcome_and_resource_wire_strings_are_stable() {
        for (outcome, wire) in [
            (
                PreflightTransactionOutcome::SimulatedSuccess,
                "simulated_success",
            ),
            (
                PreflightTransactionOutcome::SimulationFailed,
                "simulation_failed",
            ),
            (
                PreflightTransactionOutcome::RestorationRequired,
                "restoration_required",
            ),
            (
                PreflightTransactionOutcome::DeclaredResourcesInsufficient,
                "declared_resources_insufficient",
            ),
        ] {
            assert_eq!(serde_json::to_value(outcome).unwrap(), wire);
        }
        for (resource, wire) in [
            (
                PreflightDeclaredResource::ReadOnlyFootprint,
                "read_only_footprint",
            ),
            (
                PreflightDeclaredResource::ReadWriteFootprint,
                "read_write_footprint",
            ),
            (PreflightDeclaredResource::DiskReadBytes, "disk_read_bytes"),
            (PreflightDeclaredResource::WriteBytes, "write_bytes"),
        ] {
            assert_eq!(serde_json::to_value(resource).unwrap(), wire);
        }
        for (resource, wire) in [
            (PreflightEstimatedResource::Instructions, "instructions"),
            (PreflightEstimatedResource::ResourceFee, "resource_fee"),
        ] {
            assert_eq!(serde_json::to_value(resource).unwrap(), wire);
        }
    }

    #[test]
    fn a_policy_prediction_cannot_claim_permit_without_observation_evidence() {
        let missing = serde_json::json!({"prediction": "permit"});
        assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(missing).is_err());

        let mut evidence_without_rule = serde_json::json!({
            "prediction": "permit",
            "evidence": {
                "account_address": "CACCOUNT",
                "network_id": "network",
                "rule_index": 0,
                "spec_hash": "spec-hash",
                "binding_set_hash": "binding-hash",
                "registry_snapshot_root": "registry-root",
                "request_hash": "request-hash",
                "observed_ledger": 100,
                "ledger_hash": "ledger-hash",
                "evidence_trust": "rpc_reported",
                "authentication_assumption": "candidate_signers_must_authenticate",
                "classic_account_reads": [],
                "target_drift": null,
                "storage_reads": [],
                "configuration_reads": [],
                "restoration": "not_required",
                "recheck_before_signing": "required"
            }
        });
        assert!(
            serde_json::from_value::<CheckAgainstPolicyOutput>(evidence_without_rule.clone())
                .is_err()
        );
        evidence_without_rule["evidence"]["installed_context_rule_id"] = serde_json::json!(42);
        assert!(
            serde_json::from_value::<CheckAgainstPolicyOutput>(evidence_without_rule.clone())
                .is_ok()
        );
        for invalid in [serde_json::json!(false), serde_json::json!(true)] {
            let mut unsafe_evidence = evidence_without_rule.clone();
            unsafe_evidence["evidence"]["recheck_before_signing"] = invalid;
            assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(unsafe_evidence).is_err());
        }
        for field in [
            "account_address",
            "network_id",
            "rule_index",
            "spec_hash",
            "binding_set_hash",
            "registry_snapshot_root",
            "request_hash",
            "evidence_trust",
            "authentication_assumption",
            "classic_account_reads",
        ] {
            let mut detached = evidence_without_rule.clone();
            detached["evidence"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(detached).is_err());
        }

        let unavailable = serde_json::json!({
            "prediction": "unsupported",
            "reason": "no coherent ledger snapshot"
        });
        assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(unavailable).is_ok());
    }

    #[test]
    fn callers_cannot_supply_live_account_observations() {
        let mut request = serde_json::json!({
            "spec": {},
            "rule_index": 0,
            "binding_set": {
                "schema": POLICY_BINDING_SET_SCHEMA,
                "spec_hash": "spec",
                "network_id": "network",
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "account_address": "CACCOUNT",
            "network_id": "network",
            "rpc_source": "configured-testnet"
        });
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceInput>(request.clone()).is_ok());
        // Nothing about who owns the account is accepted from the caller either (D7).
        for field in [
            "account_state",
            "account_code_hash",
            "admin_rule_id",
            "observed_ledger",
            "expected_owners",
            "authority",
        ] {
            request[field] = serde_json::json!(0);
            let error = serde_json::from_value::<CheckPolicyCallSurfaceInput>(request.clone())
                .expect_err("caller-supplied authority observations must be refused");
            assert!(error.to_string().contains("unknown field"));
            request.as_object_mut().unwrap().remove(field);
        }
    }

    /// A complete, well-typed authority answer as a client receives it.
    fn check_output_wire() -> serde_json::Value {
        serde_json::json!({
            "spec_hash": "spec",
            "binding_set_hash": "binding",
            "registry_snapshot_root": "registry",
            "verdict": {
                "observed_ledger": 100,
                "network_id": "network",
                "account_address": "CACCOUNT",
                "account_code_hash": "code",
                "binding_set_hash": "binding",
                "spec_hash": "spec",
                "bound_policy_addresses": ["CPOLICY"],
                "grant": {
                    "rule_index": 0,
                    "target": "CTARGET",
                    "stateful": true,
                    "signers": [{"kind": "delegated", "address": "GAGENT"}],
                    "name": "transfer-cap",
                    "valid_until": 1000,
                    "policies": [{
                        "address": "CPOLICY",
                        "install_params": {"kind": "generated"}
                    }]
                },
                "scope": {
                    "targets": ["CTARGET"],
                    "account": "CACCOUNT",
                    "bound_policies": ["CPOLICY"]
                },
                "authority_list": [{
                    "rule_id": 1,
                    "reach": {"kind": "any_call"},
                    "valid_until": null,
                    "requirement": {
                        "kind": "all_of",
                        "signers": [{
                            "kind": "classic_account",
                            "address": "GOWNER",
                            "ed25519_public_key": "owner-key",
                            "aliases_restricted_key": false
                        }, {
                            "kind": "external",
                            "verifier": "CPASSKEYVERIFIER",
                            "verifier_code_hash": "verifier-code",
                            "scheme": "webauthn_p256",
                            "public_key": "04aa",
                            "aliases_restricted_key": false
                        }]
                    }
                }],
                "refusals": [],
                "unresolved": [],
                "coverage_exclusions": [{
                    "rule_id": 2,
                    "context": {"call_contract": {"address": "COTHER"}},
                    "policy_addresses": []
                }],
                "notes": {
                    "restricted_key_rules": [{
                        "rule_id": 2,
                        "context": {"call_contract": {"address": "COTHER"}},
                        "valid_until": 500,
                        "usable_alone": true,
                        "policy_addresses": []
                    }],
                    "target_rules": [{
                        "rule_id": 4,
                        "reach": {"kind": "target", "address": "CTARGET"},
                        "valid_until": 900,
                        "requirement": {
                            "kind": "any_of",
                            "signers": [],
                            "policies": ["CLIMIT"]
                        }
                    }],
                    "expired_rules": [{
                        "rule_id": 3,
                        "context": "default",
                        "valid_until": 50
                    }]
                },
                "authority_state": {
                    "ordered_state_digest": "state-digest",
                    "classic_accounts": {
                        "GOWNER": {
                            "state": "found",
                            "master_weight": 1,
                            "low_threshold": 0,
                            "medium_threshold": 1,
                            "high_threshold": 1,
                            "signers": []
                        },
                        "GMISSING": {"state": "not_found"}
                    },
                    "verifiers": {
                        "CPASSKEYVERIFIER": {"code_hash": "verifier-code", "scheme": "webauthn_p256"},
                        "CUNKNOWN": {"code_hash": "other-code", "scheme": null}
                    }
                },
                "evidence": {
                    "enumeration_evidence": {
                        "method": "bounded_next_id",
                        "next_id": 5,
                        "active_count": 4,
                        "rule_ids": [1, 2, 3, 4],
                        "signer_ids": [0],
                        "policy_ids": [0]
                    },
                    "source": "testnet",
                    "evidence_trust": "rpc_reported",
                    "raw_ordered_entry_digest": "raw-digest",
                    "rpc_batches": 5,
                    "attempts": 1
                },
                "authority_commitment": "authority-commitment"
            },
            "summary": "plain words"
        })
    }

    #[test]
    fn call_surface_artifact_requires_typed_observation_and_evidence() {
        let complete = check_output_wire();
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(complete.clone()).is_ok());
        for field in [
            "spec_hash",
            "binding_set_hash",
            "registry_snapshot_root",
            "verdict",
            "summary",
        ] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete).is_err());
        }
        for field in [
            "observed_ledger",
            "network_id",
            "account_address",
            "account_code_hash",
            "spec_hash",
            "binding_set_hash",
            "grant",
            "scope",
            "authority_list",
            "refusals",
            "unresolved",
            "coverage_exclusions",
            "notes",
            "authority_state",
            "evidence",
            "authority_commitment",
        ] {
            let mut incomplete = complete.clone();
            incomplete["verdict"].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete).is_err(),
                "{field}"
            );
        }
        let mut null_verdict = complete.clone();
        null_verdict["verdict"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(null_verdict).is_err());
        let mut unsupported_scan = complete.clone();
        unsupported_scan["verdict"]["evidence"]["enumeration_evidence"]["method"] =
            serde_json::json!("none");
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(unsupported_scan).is_err());
        // There is no verdict field to claim "safe" in, and an omitted expiry is not "never".
        let mut claimed_safe = complete.clone();
        claimed_safe["verdict"]["result"] = serde_json::json!("safe");
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(claimed_safe).is_err());
        let mut omitted_expiry = complete.clone();
        omitted_expiry["verdict"]["authority_list"][0]
            .as_object_mut()
            .unwrap()
            .remove("valid_until");
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(omitted_expiry).is_err());
        let mut refused = complete;
        refused["verdict"]["refusals"] = serde_json::json!([{
            "code": "E_DELEGATE_HAS_AUTHORITY",
            "rule_id": 4,
            "reason": "rule 4 lets the agent act alone",
            "remediation": "remove the agent from rule 4"
        }]);
        refused["verdict"]["unresolved"] = serde_json::json!([{
            "code": "E_UNSUPPORTED_AUTHORITY",
            "rule_id": 5,
            "unsupported": "classic_account_missing",
            "reason": "classic account has other signers",
            "remediation": "replace rule 5"
        }]);
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(refused).is_ok());
    }

    fn policy_check_request_wire() -> serde_json::Value {
        serde_json::json!({
            "spec": {},
            "binding_set": {
                "schema": POLICY_BINDING_SET_SCHEMA,
                "spec_hash": "spec",
                "network_id": "network",
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "rule_index": 0,
            "installed_context_rule_id": 42,
            "account_address": "CACCOUNT",
            "network_id": "network",
            "rpc_source": "configured-testnet",
            "candidate_signers": [],
            "invocation": {}
        })
    }

    #[test]
    fn policy_check_request_cannot_supply_evaluator_state() {
        let mut request = policy_check_request_wire();
        assert!(serde_json::from_value::<CheckAgainstPolicyInput>(request.clone()).is_ok());
        let mut without_installed_id = request.clone();
        without_installed_id
            .as_object_mut()
            .unwrap()
            .remove("installed_context_rule_id");
        assert!(serde_json::from_value::<CheckAgainstPolicyInput>(without_installed_id).is_err());
        for field in [
            "context",
            "smart_account",
            "current_ledger",
            "rule_live_signers",
            "call_count_so_far",
            "authenticated_signers",
        ] {
            request[field] = serde_json::json!(0);
            let error = serde_json::from_value::<CheckAgainstPolicyInput>(request.clone())
                .expect_err("caller-supplied evaluator state must be refused");
            assert!(error.to_string().contains("unknown field"));
            request.as_object_mut().unwrap().remove(field);
        }
        assert!(
            serde_json::from_value::<PolicyCheckSigner>(serde_json::json!({
                "external": {
                    "verifier": "CVERIFIER",
                    "key_hex": "01",
                    "verifier_code_hash": "forged"
                }
            }))
            .is_err()
        );
    }

    #[test]
    fn policy_check_evidence_binds_the_complete_request() {
        let request = policy_check_request_wire();
        let baseline: CheckAgainstPolicyInput = serde_json::from_value(request.clone()).unwrap();
        let baseline_hash = baseline.request_hash().unwrap();
        assert_eq!(baseline_hash, baseline.request_hash().unwrap());
        let evidence: PolicyCheckEvidence = serde_json::from_value(serde_json::json!({
            "account_address": baseline.account_address,
            "network_id": baseline.network_id,
            "rule_index": baseline.rule_index,
            "installed_context_rule_id": baseline.installed_context_rule_id,
            "spec_hash": "spec-hash",
            "binding_set_hash": "binding-hash",
            "registry_snapshot_root": "registry-root",
            "request_hash": baseline_hash.to_hex(),
            "observed_ledger": 100,
            "ledger_hash": "ledger-hash",
            "evidence_trust": "rpc_reported",
            "authentication_assumption": "candidate_signers_must_authenticate",
            "classic_account_reads": [],
            "target_drift": null,
            "storage_reads": [],
            "configuration_reads": [],
            "restoration": "not_required",
            "recheck_before_signing": "required"
        }))
        .unwrap();
        assert!(evidence.matches_request(&baseline).unwrap());
        for (field, value) in [
            ("account_address", serde_json::json!("COTHER")),
            ("network_id", serde_json::json!("other-network")),
            ("rpc_source", serde_json::json!("other-configured-source")),
            ("rule_index", serde_json::json!(1)),
            ("installed_context_rule_id", serde_json::json!(43)),
            ("spec", serde_json::json!({"changed": true})),
            (
                "binding_set",
                serde_json::json!({
                    "schema": POLICY_BINDING_SET_SCHEMA,
                    "spec_hash": "other-spec",
                    "network_id": "network",
                    "bindings": []
                }),
            ),
            (
                "signed_registry_snapshot",
                serde_json::json!({"changed": true}),
            ),
            (
                "candidate_signers",
                serde_json::json!([{"delegated": {"address": "CDELEGATE"}}]),
            ),
            ("invocation", serde_json::json!({"changed": true})),
        ] {
            let mut changed = request.clone();
            changed[field] = value;
            let changed: CheckAgainstPolicyInput = serde_json::from_value(changed).unwrap();
            assert_ne!(changed.request_hash().unwrap(), baseline_hash, "{field}");
            assert!(!evidence.matches_request(&changed).unwrap(), "{field}");
        }
    }

    #[test]
    fn install_intent_preserves_typed_operation_arguments() {
        let intent = PrepareInstallIntentOutput {
            operation: InstallOperation::AddContextRule,
            account_contract: "CACCOUNT".into(),
            context_contract: "CCONTEXT".into(),
            rule_name: "limited".into(),
            valid_until_ledger: Some(1234),
            delegate_signers: vec![
                PolicySignerKey::Delegated {
                    address: "CDELEGATE".into(),
                },
                PolicySignerKey::External {
                    verifier: "CVERIFIER".into(),
                    key_hex: "0123".into(),
                },
            ],
            policies: vec![
                InstallPolicy {
                    policy_index: 0,
                    address: "CSPENDING".into(),
                    install_params: InstallPolicyParams::SpendingLimit {
                        spending_limit: "500000000".into(),
                        period_ledgers: 120_960,
                    },
                },
                InstallPolicy {
                    policy_index: 1,
                    address: "CGENERATED".into(),
                    install_params: InstallPolicyParams::Generated,
                },
            ],
            next_steps: vec![],
            authority: serde_json::from_value(check_output_wire()).unwrap(),
        };

        let wire = serde_json::to_value(&intent).unwrap();
        assert_eq!(wire["operation"], "add_context_rule");
        assert_eq!(
            wire["delegate_signers"],
            serde_json::json!([
                {"kind": "delegated", "address": "CDELEGATE"},
                {"kind": "external", "verifier": "CVERIFIER", "key_hex": "0123"}
            ])
        );
        let decoded: PrepareInstallIntentOutput = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(decoded.delegate_signers, intent.delegate_signers);
        let mut wrong_operation = wire.clone();
        wrong_operation["operation"] = serde_json::json!("remove_context_rule");
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(wrong_operation).is_err());
        assert_eq!(
            wire["policies"],
            serde_json::json!([
                {
                    "policy_index": 0,
                    "address": "CSPENDING",
                    "install_params": {
                        "kind": "spending_limit",
                        "spending_limit": "500000000",
                        "period_ledgers": 120960
                    }
                },
                {
                    "policy_index": 1,
                    "address": "CGENERATED",
                    "install_params": {"kind": "generated"}
                }
            ])
        );

        let mut flattened = wire;
        flattened["delegate_signers"] = serde_json::json!(["CDELEGATE", "external:CVERIFIER:0123"]);
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(flattened).is_err());
    }

    #[test]
    fn install_intent_rejects_address_only_policy_entries() {
        let base = serde_json::json!({
            "operation": "add_context_rule",
            "account_contract": "CACCOUNT",
            "context_contract": "CCONTEXT",
            "rule_name": "limited",
            "valid_until_ledger": 1234,
            "delegate_signers": [],
            "policies": [{"policy_index": 0, "address": "CSPENDING"}],
            "next_steps": [],
            "authority": check_output_wire()
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(base.clone()).is_err());

        let mut missing_period = base.clone();
        missing_period["policies"][0]["install_params"] = serde_json::json!({
            "kind": "spending_limit",
            "spending_limit": "500000000"
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(missing_period).is_err());

        let mut addresses_only = base;
        addresses_only.as_object_mut().unwrap().remove("policies");
        addresses_only["policy_addresses"] = serde_json::json!(["CSPENDING"]);
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(addresses_only).is_err());
    }

    #[test]
    fn state_reads_and_no_expiration_require_explicit_evidence() {
        let absent = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": "absent"
        });
        assert!(serde_json::from_value::<PolicyStateRead>(absent.clone()).is_ok());
        let mut false_absence = absent.clone();
        false_absence["observation"] = serde_json::json!({"absent": {"value_xdr_base64": "value"}});
        assert!(serde_json::from_value::<PolicyStateRead>(false_absence).is_err());
        let mut missing_observation = absent;
        missing_observation
            .as_object_mut()
            .unwrap()
            .remove("observation");
        assert!(serde_json::from_value::<PolicyStateRead>(missing_observation).is_err());

        let present = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": {
                "present": {
                    "value_xdr_base64": "value",
                    "last_modified_ledger": 123,
                    "live_until_ledger": 1234
                }
            }
        });
        assert!(serde_json::from_value::<PolicyStateRead>(present.clone()).is_ok());
        for field in [
            "value_xdr_base64",
            "last_modified_ledger",
            "live_until_ledger",
        ] {
            let mut missing = present.clone();
            missing["observation"]["present"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(serde_json::from_value::<PolicyStateRead>(missing).is_err());
        }
        let mut missing_ttl = present;
        missing_ttl["observation"]["present"]["live_until_ledger"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<PolicyStateRead>(missing_ttl).is_err());
        let mut extra_evidence = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": {
                "present": {
                    "value_xdr_base64": "value",
                    "last_modified_ledger": 123,
                    "live_until_ledger": 1234,
                    "source": "caller_supplied"
                }
            }
        });
        assert!(serde_json::from_value::<PolicyStateRead>(extra_evidence.clone()).is_err());
        extra_evidence["observation"]["present"]
            .as_object_mut()
            .unwrap()
            .remove("source");
        assert!(serde_json::from_value::<PolicyStateRead>(extra_evidence).is_ok());

        let intent = serde_json::json!({
            "operation": "add_context_rule",
            "account_contract": "CACCOUNT",
            "context_contract": "CCONTEXT",
            "rule_name": "limited",
            "valid_until_ledger": null,
            "delegate_signers": [],
            "policies": [],
            "next_steps": [],
            "authority": check_output_wire()
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(intent.clone()).is_ok());
        let mut without_authority = intent.clone();
        without_authority
            .as_object_mut()
            .unwrap()
            .remove("authority");
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(without_authority).is_err());
        let mut missing_expiration = intent;
        missing_expiration
            .as_object_mut()
            .unwrap()
            .remove("valid_until_ledger");
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(missing_expiration).is_err());

        for (schema, fields) in [
            (
                serde_json::to_value(schemars::schema_for!(PolicyStateRead)).unwrap(),
                &["observation"][..],
            ),
            (
                serde_json::to_value(schemars::schema_for!(PrepareInstallIntentOutput)).unwrap(),
                &["valid_until_ledger"][..],
            ),
        ] {
            let required = schema["required"].as_array().unwrap();
            for field in fields {
                assert!(required.contains(&serde_json::json!(field)));
            }
        }
    }
}
