//! Pure recorder core (architecture §4.1, §4.11).
//!
//! Acquisition adapters (`source-rpc`, `source-bundle`) produce immutable, trust-labeled
//! [`EvidenceSnapshot`]s; this crate is a pure function over snapshots:
//! `record(snapshot, options) -> RecordingBundle`. No I/O, no async.
//!
//! Enforcement facts come exclusively from the authorization entries (what
//! `__check_auth` will see); token movements and state diffs are explanatory evidence.
//! Args in an auth entry are what was *authorized* (`require_auth_for_args` may differ
//! from the actual call args) and are labeled as such.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32, LedgerSeq, NetworkId, TrustLevel, CANONICALIZATION_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractEvent, ContractEventBody, ContractEventType, HostFunction, Limits, OperationBody,
    ReadXdr, ScAddress, ScBytes, ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, TransactionMeta,
    WriteXdr,
};

pub const RECORDING_SCHEMA: &str = "recording/v2";
/// Highest acquisition protocol supported by the pinned XDR decoder. Protocol 30
/// adds ledger-header and address variants; the RPC compatibility test pins its XDR revision.
pub const MAX_ACQUISITION_PROTOCOL: u32 = 30;
// Soroban transactions and ledger entries are far smaller than this in practice. Keep a
// defensive per-value bound, then separately cap the total encoded evidence below the canonical
// hash preimage ceiling. This makes every accepted recording hashable instead of discovering an
// incompatible 4 MiB limit only after decoding and summarizing it.
const MAX_XDR_BYTES: usize = 512 * 1024;
const MAX_XDR_BASE64_BYTES: usize = MAX_XDR_BYTES.div_ceil(3) * 4;
/// The most encoded evidence any recording can carry. Public because an acquisition adapter
/// reading caller-controlled input has to bound that input *before* parsing it, and the bound
/// it should use is this one — a document carrying more than this describes evidence
/// [`record`] will refuse, so two independently chosen numbers would only drift apart.
pub const MAX_TOTAL_EVIDENCE_BASE64_BYTES: usize = 1024 * 1024;
const MAX_XDR_DEPTH: u32 = 128;
const MAX_SIMULATED_AUTH_ENTRIES: usize = 256;
const MAX_SIMULATED_STATE_CHANGES: usize = 4_096;
// One observation per contract an authorization can reference, bounded like the auth entries
// that reach those contracts. Its own constant, so raising either bound is a decision about
// that bound and the message names the limit that actually applied.
const MAX_CONTRACT_EXECUTABLE_OBSERVATIONS: usize = 256;

fn xdr_limits() -> Limits {
    Limits {
        depth: MAX_XDR_DEPTH,
        len: MAX_XDR_BYTES,
    }
}

// ---------------------------------------------------------------------------------------
// EvidenceSnapshot — trust is derived by the constructor for each acquisition path; no
// constructor takes a trust argument (§4.1). That is an in-process discipline, not an
// authentication: in safe Rust any library caller can invoke an acquisition constructor
// and attach observations, so a snapshot's label states which acquisition path the
// constructing code claims to have run, and is trustworthy exactly as far as that code
// is. Where evidence crosses a serialization boundary the label is therefore downgraded
// to self_supplied and the recording re-verified against its raw evidence (toolkit
// synthesis boundary; RecordingBundle::verify).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct EvidenceSnapshot {
    network_passphrase: String,
    envelope_xdr_base64: String,
    result_meta_xdr_base64: Option<String>,
    /// Raw `TransactionResult` XDR for executed evidence. Verified against the
    /// claimed outcome in [`record`]; an executed import without it is `incomplete`.
    result_xdr_base64: Option<String>,
    /// Auth entries returned by `simulateTransaction` in record mode (unsigned).
    simulated_auth_xdr_base64: Vec<String>,
    simulated_state_changes: Vec<StateChange>,
    acquisition: Option<AcquisitionMetadata>,
    contract_executables: BTreeMap<String, ExecutableObservation>,
    ledger: Option<u32>,
    created_at_unix: Option<i64>,
    execution: Execution,
    trust: TrustLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Execution {
    ExecutedSuccess,
    ExecutedFailed,
    Simulated,
}

impl EvidenceSnapshot {
    /// An executed transaction fetched live from the configured RPC. Attach its raw
    /// result with [`Self::with_rpc_result`] to retain `rpc_reported` on the recording;
    /// executed evidence without it is recorded as `incomplete`.
    pub fn from_rpc_transaction(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        result_meta_xdr_base64: Option<String>,
        ledger: u32,
        created_at_unix: i64,
        successful: bool,
    ) -> Self {
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64,
            // The adapter attaches the checked result with `with_rpc_result`. A caller
            // omitting it cannot mint a synthesis-eligible executed recording.
            result_xdr_base64: None,
            simulated_auth_xdr_base64: vec![],
            simulated_state_changes: vec![],
            acquisition: None,
            contract_executables: BTreeMap::new(),
            ledger: Some(ledger),
            created_at_unix: Some(created_at_unix),
            execution: if successful {
                Execution::ExecutedSuccess
            } else {
                Execution::ExecutedFailed
            },
            trust: TrustLevel::rpc_reported(),
        }
    }

    /// Record the endpoint protocol at acquisition time, not the transaction's historical
    /// protocol. Decoder identity is filled by the implementation that reads the evidence.
    pub fn with_acquisition_protocol(mut self, protocol_version: u32) -> Self {
        self.acquisition = Some(AcquisitionMetadata {
            protocol_version,
            decoder_version: stellar_xdr::VERSION.pkg.to_string(),
            decoder_xdr_revision: stellar_xdr::VERSION.xdr.trim().to_string(),
        });
        self
    }

    /// Preserve the transaction result fetched by the RPC adapter. The pure recorder
    /// checks it against the envelope and claimed outcome before admitting the snapshot.
    pub fn with_rpc_result(mut self, result_xdr_base64: String) -> Self {
        self.result_xdr_base64 = Some(result_xdr_base64);
        self
    }

    /// A local simulation acquired via RPC `simulateTransaction` with `authMode: record`
    /// (`rpc_reported`; confidential input — §6.5).
    pub fn from_rpc_simulation(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        simulated_auth_xdr_base64: Vec<String>,
        latest_ledger: Option<u32>,
    ) -> Self {
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64: None,
            result_xdr_base64: None,
            simulated_auth_xdr_base64,
            simulated_state_changes: vec![],
            acquisition: None,
            contract_executables: BTreeMap::new(),
            ledger: latest_ledger,
            created_at_unix: None,
            execution: Execution::Simulated,
            trust: TrustLevel::rpc_reported(),
        }
    }

    /// A user-imported raw evidence bundle: internally consistent but unverified
    /// (`self_supplied`). Never described as a verified executed transaction.
    ///
    /// The claimed outcome is evidence-backed only when the raw `TransactionResult` XDR
    /// accompanies it — [`record`] checks the two agree. Without it, the outcome is a bare
    /// assertion, so the snapshot is labeled `incomplete` (recordable and viewable, but
    /// synthesis refuses it) rather than "internally consistent".
    pub fn from_import(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        result_meta_xdr_base64: Option<String>,
        result_xdr_base64: Option<String>,
        ledger: Option<u32>,
        created_at_unix: Option<i64>,
        successful: bool,
    ) -> Self {
        // Presence is not backing: the label says the outcome claim is supported by evidence,
        // so it is earned only by a result that decodes and describes the claimed outcome.
        // `record` still reports a decodable contradiction as E_RESULT_MISMATCH — a weaker
        // label is not a substitute for naming the disagreement.
        let backed = result_xdr_base64.as_deref().is_some_and(|encoded| {
            // Size before decoding. Import JSON is caller-controlled and this constructor runs
            // before `record`'s resource admission, so the label is decided without handing an
            // unbounded string to the parser. Defence in depth rather than the only guard: the
            // XDR reader's own length limit refuses oversized input as well, and a test that
            // claimed this comparison was what produced the outcome would be green either way
            // (a 512 KiB run of 'A' is not a transaction result under any bound). What it buys
            // is independence from how the reader orders base64 decoding against that limit.
            encoded.len() <= MAX_XDR_BASE64_BYTES
                && stellar_xdr::TransactionResult::from_xdr_base64(encoded, xdr_limits()).is_ok_and(
                    |result| {
                        matches!(
                            result.result,
                            stellar_xdr::TransactionResultResult::TxSuccess(_)
                                | stellar_xdr::TransactionResultResult::TxFeeBumpInnerSuccess(_)
                        ) == successful
                    },
                )
        });
        let trust = if backed {
            TrustLevel::self_supplied()
        } else {
            TrustLevel::incomplete()
        };
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64,
            result_xdr_base64,
            simulated_auth_xdr_base64: vec![],
            simulated_state_changes: vec![],
            acquisition: None,
            contract_executables: BTreeMap::new(),
            ledger,
            created_at_unix,
            execution: if successful {
                Execution::ExecutedSuccess
            } else {
                Execution::ExecutedFailed
            },
            trust,
        }
    }

    pub fn trust(&self) -> TrustLevel {
        self.trust
    }

    /// Attach state changes parsed by the RPC acquisition adapter. Kept separate from the
    /// public constructor so existing callers cannot accidentally confuse meta-derived and
    /// simulation-derived evidence.
    pub fn with_simulated_state_changes(mut self, changes: Vec<StateChange>) -> Self {
        self.simulated_state_changes = changes;
        self
    }

    /// Attach executable observations acquired from `getLedgerEntries` at a known ledger.
    /// The map key is the contract strkey; `BTreeMap` provides canonical ordering for hashes.
    ///
    /// Observations are acquisition facts asserted by the calling adapter — raw XDR cannot
    /// re-derive them, so they stay claims under the snapshot's trust label; synthesis
    /// separately checks the selected account's observation against the registry-resolved
    /// account record.
    pub fn with_contract_executables(
        mut self,
        observations: BTreeMap<String, ExecutableObservation>,
    ) -> Self {
        self.contract_executables = observations;
        self
    }
}

// ---------------------------------------------------------------------------------------
// RecordingBundle
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingBundle {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    pub canonicalization_version: u32,
    pub network_id: NetworkId,
    pub trust: TrustLevel,
    /// Execution outcome, re-derived from preserved result XDR during verification.
    /// Executed evidence lacking a result is explicitly `incomplete`.
    pub execution: Execution,
    pub ledger: Option<LedgerSeq>,
    pub created_at_unix: Option<i64>,
    pub operation_index: u32,
    /// One record per address-level authorization entry.
    pub authorizations: Vec<AuthorizationRecord>,
    /// Explanatory evidence only — never drives constraints automatically.
    pub token_movements: Vec<TokenMovement>,
    /// Ledger-entry state changes (created/updated/removed/restored). Explanatory
    /// evidence only — like token movements, these are never turned into constraints
    /// (effects can't be reliably attributed to a specific authorization; §4.1).
    pub state_changes: Vec<StateChange>,
    /// Contract executable/code hashes captured by the acquisition adapter. This is the
    /// evidence used to bind account recognition and code-hash-specific adapters.
    pub contract_executables: BTreeMap<String, ExecutableObservation>,
    /// Current acquisition context; not a historical transaction protocol anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquisition: Option<AcquisitionMetadata>,
    /// Effects that could not be decoded/attributed; preserved, labeled, never guessed at.
    pub evidence_notes: Vec<String>,
    /// Raw evidence is always preserved — decoding never replaces it.
    pub raw: RawEvidence,
}

/// A summarized ledger-entry change from transaction meta (evidence only).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateChange {
    pub kind: StateChangeKind,
    /// The kind of ledger entry affected (contract_data / contract_code / account / …).
    pub entry: String,
    /// For contract-data entries, the owning contract (strkey), if resolvable.
    pub contract: Option<String>,
    /// Which meta section this change came from.
    pub source: StateChangeSource,
    /// Exact simulation evidence, when the source is `simulation`. Meta-derived entries use
    /// their decoded ledger-key summary and leave these fields empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_xdr_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_xdr_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_xdr_base64: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionMetadata {
    pub protocol_version: u32,
    pub decoder_version: String,
    pub decoder_xdr_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableObservation {
    pub executable: ObservedExecutable,
    pub observed_ledger: LedgerSeq,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified_ledger: Option<LedgerSeq>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_until_ledger: Option<LedgerSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedExecutable {
    Wasm { code_hash: Hash32 },
    StellarAsset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateChangeKind {
    Created,
    Updated,
    Removed,
    /// The pre-image `State` half of a `State → Updated` pair (recorded for completeness).
    State,
    /// Protocol 23+: an archived entry restored during application.
    Restored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateChangeSource {
    TxChangesBefore,
    Operation,
    TxChangesAfter,
    Simulation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_xdr_base64: Option<String>,
    pub envelope_xdr_base64: String,
    pub result_meta_xdr_base64: Option<String>,
    pub simulated_auth_xdr_base64: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    /// The authorizing address (strkey).
    pub authorizer: String,
    pub credential: CredentialRecord,
    /// Replay-invariant authorization fingerprint:
    /// `H(domain, authorizer XDR || root_invocation XDR)`. Identical for the same
    /// authorized shape whether executed or simulated.
    pub fingerprint: Hash32,
    pub root: InvocationNode,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialRecord {
    SourceAccount,
    Address {
        #[serde(with = "ozpb_domain::wide_int")]
        nonce: i64,
        signature_expiration_ledger: u32,
    },
    /// Protocol 27 (CAP-71): address-bound signature payload.
    AddressV2 {
        #[serde(with = "ozpb_domain::wide_int")]
        nonce: i64,
        signature_expiration_ledger: u32,
    },
    /// Protocol 27 (CAP-71): delegate signature tree (recursively counted).
    AddressWithDelegates {
        #[serde(with = "ozpb_domain::wide_int")]
        nonce: i64,
        signature_expiration_ledger: u32,
        delegate_count: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationNode {
    pub call: AuthorizedCall,
    pub sub_invocations: Vec<InvocationNode>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizedCall {
    Contract {
        contract: String,
        fn_name: String,
        /// The AUTHORIZED args (`require_auth_for_args` may expose a subset or transform
        /// of the actual call args — never assume equality).
        args: Vec<ArgSummary>,
    },
    CreateContract,
}

/// Decoded argument summary. Anything outside the simple shapes keeps its exact
/// canonical XDR so no information is lost.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgSummary {
    Address(String),
    I128(#[serde(with = "ozpb_domain::wide_int")] i128),
    U64(#[serde(with = "ozpb_domain::wide_int")] u64),
    U32(u32),
    Symbol(String),
    Other { xdr_base64: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMovement {
    pub kind: MovementKind,
    pub token_contract: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spender: Option<String>,
    #[serde(default, with = "ozpb_domain::wide_int::option")]
    pub amount: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_ledger: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementKind {
    Transfer,
    Mint,
    Burn,
    Approve,
}

impl RecordingBundle {
    /// Full recording hash: canonicalization version + the complete canonical bundle
    /// (raw XDR, anchors, decoded evidence, trust, schema) under the recording domain.
    pub fn recording_hash(&self) -> Result<Hash32, RecordError> {
        ozpb_domain::canonical_hash(domains::RECORDING, self)
            .map_err(|e| RecordError::Internal(e.to_string()))
    }

    /// Verify a (possibly deserialized, caller-supplied) recording: the schema and
    /// canonicalization version must be current, the raw evidence must fit the same
    /// resource bounds [`record`] enforces, the raw shape must be one an acquisition path
    /// can produce, and every decoded view must be exactly what the recorder re-derives
    /// from the raw evidence. Serialized identity is not coherence: [`Self::recording_hash`]
    /// proves only that an object is stably named, while `verify` proves its decoded
    /// claims come from its own raw XDR.
    ///
    /// Acquisition facts (network/trust labels, ledger anchors, timestamps and executable
    /// observations) remain claims. Execution results and simulation summaries are checked
    /// against preserved XDR. This establishes internal coherence, not ledger inclusion.
    pub fn verify(&self) -> Result<Hash32, RecordError> {
        if self.schema != RECORDING_SCHEMA {
            return Err(RecordError::EvidenceIncoherent(format!(
                "schema '{}' is not '{RECORDING_SCHEMA}'; reimport the original raw evidence or record it again",
                self.schema
            )));
        }
        if self.canonicalization_version != CANONICALIZATION_VERSION {
            return Err(RecordError::EvidenceIncoherent(format!(
                "canonicalization version {} is not {CANONICALIZATION_VERSION}",
                self.canonicalization_version
            )));
        }
        // Shapes no acquisition path mints fail closed, even where decoding would merely
        // ignore the extraneous half.
        if self.execution == Execution::Simulated {
            if self.raw.result_meta_xdr_base64.is_some() || self.raw.result_xdr_base64.is_some() {
                return Err(RecordError::EvidenceIncoherent(
                    "a simulated recording cannot carry result meta or a transaction result"
                        .to_string(),
                ));
            }
            // The rebuild below would refuse this too, but as a generic divergence: a
            // simulation has no meta sections for a change to have come from, so name the
            // shape instead of leaving the reader to work out which field diverged and why.
            if let Some(foreign) = self
                .state_changes
                .iter()
                .find(|change| change.source != StateChangeSource::Simulation)
            {
                return Err(RecordError::EvidenceIncoherent(format!(
                    "a simulated recording carries a state change sourced from {:?}; a \
                     simulation has no meta sections",
                    foreign.source
                )));
            }
        } else if !self.raw.simulated_auth_xdr_base64.is_empty() {
            return Err(RecordError::EvidenceIncoherent(
                "an executed recording cannot carry simulated authorization entries".to_string(),
            ));
        } else if self
            .state_changes
            .iter()
            .any(|change| change.source == StateChangeSource::Simulation)
        {
            // Simulation-sourced changes are minted only by the simulation adapter, so on an
            // executed recording they are injected evidence: unattributable to the meta this
            // recording preserves, and inside the hashed artifact an auditor reads.
            return Err(RecordError::EvidenceIncoherent(
                "an executed recording cannot carry simulation-sourced state changes".to_string(),
            ));
        }
        let simulated_state_changes: Vec<StateChange> = self
            .state_changes
            .iter()
            .filter(|change| change.source == StateChangeSource::Simulation)
            .cloned()
            .collect();
        validate_raw_evidence_limits(
            &self.raw.envelope_xdr_base64,
            self.raw.result_meta_xdr_base64.as_deref(),
            self.raw.result_xdr_base64.as_deref(),
            &self.raw.simulated_auth_xdr_base64,
            &simulated_state_changes,
            self.contract_executables.len(),
        )?;
        let rebuilt = decode_recording(RecordingParts {
            raw: self.raw.clone(),
            execution: self.execution,
            trust: self.trust,
            network_id: self.network_id,
            ledger: self.ledger,
            created_at_unix: self.created_at_unix,
            operation_index: Some(self.operation_index),
            simulated_state_changes,
            acquisition: self.acquisition.clone(),
            contract_executables: self.contract_executables.clone(),
        })?;
        if rebuilt != *self {
            return Err(RecordError::EvidenceIncoherent(describe_divergence(
                self, &rebuilt,
            )));
        }
        self.hash_within_the_domain_boundary()
    }

    /// The recording hash, with a hash failure reported as the resource failure it is.
    /// `record` and `verify` both admit recordings and must describe an over-large canonical
    /// preimage the same way; a shared helper is what keeps that true rather than two call
    /// sites agreeing by habit. All fields use supported canonical types, so a failure here
    /// is about size, not about an unencodable value.
    fn hash_within_the_domain_boundary(&self) -> Result<Hash32, RecordError> {
        self.recording_hash().map_err(|error| {
            RecordError::ResourceLimit(format!(
                "recording does not fit the canonical hash boundary: {error}"
            ))
        })
    }
}

/// Name the first decoded view that disagrees with what the raw evidence derives to,
/// without echoing potentially large forged content into the error.
fn describe_divergence(supplied: &RecordingBundle, rebuilt: &RecordingBundle) -> String {
    let field = if supplied.authorizations != rebuilt.authorizations {
        "authorizations"
    } else if supplied.token_movements != rebuilt.token_movements {
        "token_movements"
    } else if supplied.state_changes != rebuilt.state_changes {
        "state_changes"
    } else if supplied.evidence_notes != rebuilt.evidence_notes {
        "evidence_notes"
    } else {
        "decoded fields"
    };
    format!("supplied {field} are not what the recorder derives from the raw evidence")
}

// ---------------------------------------------------------------------------------------
// Errors — stable machine-readable codes (architecture §4.6)
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("E_ENVELOPE_PARSE: {0}")]
    EnvelopeParse(String),
    #[error("E_UNSUPPORTED_ENVELOPE: {0}")]
    UnsupportedEnvelope(String),
    #[error("E_NO_SOROBAN_OP: transaction contains no InvokeHostFunction operation")]
    NoSorobanOp,
    #[error(
        "E_OPERATION_SELECTION: transaction has {0} InvokeHostFunction operations; \
         explicit operation_index required"
    )]
    OperationSelection(usize),
    #[error(
        "E_TX_FAILED: transaction failed on-chain; failed executions are not behavior \
         examples (pass allow_failed for failure analysis)"
    )]
    TxFailed,
    #[error("E_UNSUPPORTED_META_VERSION: meta v{0} is not a Soroban meta version")]
    UnsupportedMetaVersion(i32),
    #[error("E_META_PARSE: {0}")]
    MetaParse(String),
    #[error("E_RESULT_MISMATCH: {0}")]
    ResultMismatch(String),
    /// A recording's decoded views disagree with its own raw evidence, or a snapshot mixes
    /// evidence from two acquisitions. The prefix is the public wire code deliberately: an
    /// agent reads code and message together, so the two must name one failure.
    #[error("E_EVIDENCE_INCOHERENT: {0}")]
    EvidenceIncoherent(String),
    #[error("E_UNSUPPORTED_ADDRESS: {0}")]
    UnsupportedAddress(String),
    #[error("E_AUTH_PARSE: {0}")]
    AuthParse(String),
    #[error("E_RESOURCE_LIMIT: {0}")]
    ResourceLimit(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RecordOptions {
    /// Required when the transaction has more than one InvokeHostFunction operation.
    pub operation_index: Option<u32>,
    /// Failure-analysis mode: explicitly opt in to record a failed transaction.
    pub allow_failed: bool,
}

// ---------------------------------------------------------------------------------------
// record(): the pure core
// ---------------------------------------------------------------------------------------

pub fn record(
    snapshot: &EvidenceSnapshot,
    options: RecordOptions,
) -> Result<RecordingBundle, RecordError> {
    validate_evidence_limits(snapshot)?;

    if snapshot.execution == Execution::ExecutedFailed && !options.allow_failed {
        return Err(RecordError::TxFailed);
    }

    // `with_simulated_state_changes` names its own provenance, so what it carries must match
    // the acquisition that attached it — in both directions, because `verify` rebuilds a
    // recording from its simulation-sourced changes only and would reject either mismatch.
    // Refused here too, so `record` cannot mint a recording its own verification rejects.
    if snapshot.execution == Execution::Simulated {
        if let Some(foreign) = snapshot
            .simulated_state_changes
            .iter()
            .find(|change| change.source != StateChangeSource::Simulation)
        {
            return Err(RecordError::EvidenceIncoherent(format!(
                "a simulated acquisition attached a state change sourced from {:?}; only \
                 simulation-sourced changes can accompany a simulation",
                foreign.source
            )));
        }
    } else if !snapshot.simulated_state_changes.is_empty() {
        return Err(RecordError::EvidenceIncoherent(
            "executed evidence cannot carry simulation-sourced state changes".to_string(),
        ));
    }

    let bundle = decode_recording(RecordingParts {
        raw: RawEvidence {
            result_xdr_base64: snapshot.result_xdr_base64.clone(),
            envelope_xdr_base64: snapshot.envelope_xdr_base64.clone(),
            result_meta_xdr_base64: snapshot.result_meta_xdr_base64.clone(),
            simulated_auth_xdr_base64: snapshot.simulated_auth_xdr_base64.clone(),
        },
        execution: snapshot.execution,
        trust: if snapshot.execution != Execution::Simulated && snapshot.result_xdr_base64.is_none()
        {
            TrustLevel::incomplete()
        } else {
            snapshot.trust
        },
        network_id: NetworkId::from_passphrase(&snapshot.network_passphrase),
        ledger: snapshot.ledger.map(LedgerSeq),
        created_at_unix: snapshot.created_at_unix,
        operation_index: options.operation_index,
        simulated_state_changes: snapshot.simulated_state_changes.clone(),
        acquisition: snapshot.acquisition.clone(),
        contract_executables: snapshot.contract_executables.clone(),
    })?;
    // Resource admission and hashing are one boundary: never return a recording that the next
    // pipeline stage can only reject because its canonical preimage exceeds the domain limit.
    bundle.hash_within_the_domain_boundary()?;
    Ok(bundle)
}

/// Everything a recording is derived from: the raw evidence plus the acquisition claims
/// that raw XDR cannot express. [`record`] fills it from a snapshot;
/// [`RecordingBundle::verify`] fills it from a supplied bundle to rebuild and compare.
struct RecordingParts {
    raw: RawEvidence,
    execution: Execution,
    trust: TrustLevel,
    network_id: NetworkId,
    ledger: Option<LedgerSeq>,
    created_at_unix: Option<i64>,
    operation_index: Option<u32>,
    simulated_state_changes: Vec<StateChange>,
    acquisition: Option<AcquisitionMetadata>,
    contract_executables: BTreeMap<String, ExecutableObservation>,
}

/// Decode raw evidence into the canonical bundle. Pure and deterministic: the same parts
/// always yield the same bundle, which is what makes verification-by-rebuild sound.
fn decode_recording(parts: RecordingParts) -> Result<RecordingBundle, RecordError> {
    if let Some(acquisition) = &parts.acquisition {
        if !(1..=MAX_ACQUISITION_PROTOCOL).contains(&acquisition.protocol_version)
            || acquisition.decoder_version != stellar_xdr::VERSION.pkg
            || acquisition.decoder_xdr_revision != stellar_xdr::VERSION.xdr.trim()
        {
            return Err(RecordError::EvidenceIncoherent(
                "unsupported acquisition protocol or decoder identity".to_string(),
            ));
        }
    }
    for observation in parts.contract_executables.values() {
        if observation
            .last_modified_ledger
            .is_some_and(|modified| modified > observation.observed_ledger)
            || observation
                .live_until_ledger
                .is_some_and(|live_until| live_until < observation.observed_ledger)
        {
            return Err(RecordError::EvidenceIncoherent(
                "contract-instance modification/lifetime contradicts its observed ledger"
                    .to_string(),
            ));
        }
    }
    for change in &parts.simulated_state_changes {
        let rebuilt = simulation_state_change(
            change.kind,
            change.key_xdr_base64.clone().ok_or_else(|| {
                RecordError::EvidenceIncoherent("simulation change has no key XDR".to_string())
            })?,
            change.before_xdr_base64.clone(),
            change.after_xdr_base64.clone(),
        )?;
        if rebuilt != *change {
            return Err(RecordError::EvidenceIncoherent(
                "simulation change summary does not match its key XDR".to_string(),
            ));
        }
    }
    let envelope =
        TransactionEnvelope::from_xdr_base64(&parts.raw.envelope_xdr_base64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("envelope", e, RecordError::EnvelopeParse))?;

    if parts.execution == Execution::Simulated {
        if parts.raw.result_xdr_base64.is_some() || parts.raw.result_meta_xdr_base64.is_some() {
            return Err(RecordError::EvidenceIncoherent(
                "simulation cannot carry executed result evidence".to_string(),
            ));
        }
    } else if let Some(encoded) = &parts.raw.result_xdr_base64 {
        let result = stellar_xdr::TransactionResult::from_xdr_base64(encoded, xdr_limits())
            .map_err(|e| {
                map_xdr_parse_error("transaction result", e, RecordError::ResultMismatch)
            })?;
        verify_transaction_result(&envelope, &result, parts.execution, parts.network_id)?;
    } else if parts.trust != TrustLevel::incomplete() {
        return Err(RecordError::EvidenceIncoherent(
            "executed evidence without transaction result XDR must remain incomplete".to_string(),
        ));
    }

    // Fee-bump envelopes are unwrapped explicitly; V0 envelopes predate Soroban.
    let tx = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(RecordError::UnsupportedEnvelope(
                "TransactionV0 envelopes cannot carry Soroban operations".to_string(),
            ))
        }
    };

    // Locate InvokeHostFunction operations; multi-op requires explicit selection.
    let soroban_ops: Vec<(u32, &stellar_xdr::InvokeHostFunctionOp)> = tx
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match &op.body {
            OperationBody::InvokeHostFunction(ihf) => Some((i as u32, ihf)),
            _ => None,
        })
        .collect();

    let (operation_index, op) = match (soroban_ops.len(), parts.operation_index) {
        (0, _) => return Err(RecordError::NoSorobanOp),
        (1, None) => soroban_ops[0],
        (n, None) => return Err(RecordError::OperationSelection(n)),
        (_, Some(want)) => *soroban_ops
            .iter()
            .find(|(i, _)| *i == want)
            .ok_or(RecordError::NoSorobanOp)?,
    };

    // Auth entries: executed txs carry them in the envelope; simulations supply them
    // from the RPC record-mode response. Same XDR type either way.
    let auth_entries: Vec<SorobanAuthorizationEntry> = if parts.execution == Execution::Simulated {
        parts
            .raw
            .simulated_auth_xdr_base64
            .iter()
            .map(|b64| {
                SorobanAuthorizationEntry::from_xdr_base64(b64, xdr_limits())
                    .map_err(|e| map_xdr_parse_error("authorization", e, RecordError::AuthParse))
            })
            .collect::<Result<_, _>>()?
    } else {
        op.auth.iter().cloned().collect()
    };

    let mut authorizations = Vec::new();
    let mut evidence_notes = Vec::new();
    for entry in &auth_entries {
        authorizations.push(decode_auth_entry(entry, tx)?);
    }

    // Token movements + state changes from meta (evidence only). Tolerant: undecodable
    // events become notes, never guesses.
    let mut token_movements = Vec::new();
    let mut state_changes = parts.simulated_state_changes;
    if let Some(meta_b64) = &parts.raw.result_meta_xdr_base64 {
        let meta = TransactionMeta::from_xdr_base64(meta_b64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("result meta", e, RecordError::MetaParse))?;
        let events = match &meta {
            TransactionMeta::V3(v3) => {
                collect_changes(
                    &v3.tx_changes_before,
                    StateChangeSource::TxChangesBefore,
                    &mut state_changes,
                );
                if let Some(om) = v3.operations.get(operation_index as usize) {
                    collect_changes(
                        &om.changes,
                        StateChangeSource::Operation,
                        &mut state_changes,
                    );
                }
                collect_changes(
                    &v3.tx_changes_after,
                    StateChangeSource::TxChangesAfter,
                    &mut state_changes,
                );
                v3.soroban_meta
                    .as_ref()
                    .map(|sm| sm.events.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            }
            TransactionMeta::V4(v4) => {
                collect_changes(
                    &v4.tx_changes_before,
                    StateChangeSource::TxChangesBefore,
                    &mut state_changes,
                );
                if let Some(om) = v4.operations.get(operation_index as usize) {
                    collect_changes(
                        &om.changes,
                        StateChangeSource::Operation,
                        &mut state_changes,
                    );
                }
                collect_changes(
                    &v4.tx_changes_after,
                    StateChangeSource::TxChangesAfter,
                    &mut state_changes,
                );
                v4.operations
                    .get(operation_index as usize)
                    .map(|om| om.events.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            }
            TransactionMeta::V0(_) => return Err(RecordError::UnsupportedMetaVersion(0)),
            TransactionMeta::V1(_) => return Err(RecordError::UnsupportedMetaVersion(1)),
            TransactionMeta::V2(_) => return Err(RecordError::UnsupportedMetaVersion(2)),
        };
        for ev in &events {
            match decode_token_event(ev) {
                Some(m) => token_movements.push(m),
                None => evidence_notes.push(format!(
                    "unattributed contract event (kept in raw meta): {:?}",
                    ev.type_
                )),
            }
        }
    } else if parts.execution != Execution::Simulated {
        evidence_notes.push("no result meta available; token movements unknown".to_string());
    }

    Ok(RecordingBundle {
        schema: RECORDING_SCHEMA.to_string(),
        canonicalization_version: CANONICALIZATION_VERSION,
        network_id: parts.network_id,
        trust: parts.trust,
        execution: parts.execution,
        ledger: parts.ledger,
        created_at_unix: parts.created_at_unix,
        operation_index,
        authorizations,
        token_movements,
        state_changes,
        acquisition: parts.acquisition,
        contract_executables: parts.contract_executables,
        evidence_notes,
        raw: parts.raw,
    })
}

/// Check result/envelope coherence for all operation kinds. This does not authenticate a
/// result's inclusion in a ledger; it prevents contradictory evidence from claiming success.
pub fn verify_transaction_result(
    envelope: &TransactionEnvelope,
    result: &stellar_xdr::TransactionResult,
    execution: Execution,
    network_id: NetworkId,
) -> Result<(), RecordError> {
    use stellar_xdr::{InnerTransactionResultResult as Inner, TransactionResultResult as Outer};
    let mismatch = |message: &str| RecordError::ResultMismatch(message.to_string());
    let envelope_operations = match envelope {
        TransactionEnvelope::Tx(v1) => v1.tx.operations.as_slice(),
        TransactionEnvelope::TxV0(v0) => v0.tx.operations.as_slice(),
        TransactionEnvelope::TxFeeBump(bump) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
            inner.tx.operations.as_slice()
        }
    };
    let (success, operations): (bool, Option<&[stellar_xdr::OperationResult]>) =
        match &result.result {
            Outer::TxSuccess(operations) | Outer::TxFailed(operations) => {
                if matches!(envelope, TransactionEnvelope::TxFeeBump(_)) {
                    return Err(mismatch(
                        "fee-bump envelope requires a fee-bump inner result",
                    ));
                }
                (
                    matches!(result.result, Outer::TxSuccess(_)),
                    Some(operations),
                )
            }
            Outer::TxFeeBumpInnerSuccess(pair) | Outer::TxFeeBumpInnerFailed(pair) => {
                let TransactionEnvelope::TxFeeBump(bump) = envelope else {
                    return Err(mismatch("fee-bump result requires a fee-bump envelope"));
                };
                let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
                let hash = TransactionEnvelope::Tx(inner.clone())
                    .hash(network_id.0 .0)
                    .map_err(|error| {
                        RecordError::ResultMismatch(format!("cannot hash inner envelope: {error}"))
                    })?;
                if pair.transaction_hash.0 != hash {
                    return Err(mismatch(
                        "fee-bump result inner transaction hash does not match envelope",
                    ));
                }
                let outer_success = matches!(result.result, Outer::TxFeeBumpInnerSuccess(_));
                let inner_success = matches!(pair.result.result, Inner::TxSuccess(_));
                if outer_success != inner_success {
                    return Err(mismatch(
                        "fee-bump inner success/failure contradicts its outer result",
                    ));
                }
                let operations = match &pair.result.result {
                    Inner::TxSuccess(operations) | Inner::TxFailed(operations) => {
                        Some(operations.as_slice())
                    }
                    _ => None,
                };
                (outer_success, operations)
            }
            _ => (false, None),
        };
    if execution == Execution::Simulated || success != (execution == Execution::ExecutedSuccess) {
        return Err(mismatch(
            "claimed execution contradicts the decoded transaction result",
        ));
    }
    if let Some(operations) = operations {
        // txFAILED means an operation failed. Unlike transaction-level rejection codes,
        // an empty or entirely successful operation list cannot support that outcome.
        if !success && operations.iter().all(operation_succeeded) {
            return Err(mismatch(
                "failed transaction result contains no failed operation",
            ));
        }
        if (success && operations.len() != envelope_operations.len())
            || operations.len() > envelope_operations.len()
        {
            return Err(RecordError::ResultMismatch(format!(
                "the transaction result reports {} operation results for an envelope with {} operations",
                operations.len(), envelope_operations.len()
            )));
        }
        for (index, (result, operation)) in operations.iter().zip(envelope_operations).enumerate() {
            if let stellar_xdr::OperationResult::OpInner(inner) = result {
                if inner.discriminant() != operation.body.discriminant() {
                    return Err(RecordError::ResultMismatch(format!(
                        "operation {index} result kind contradicts its envelope operation"
                    )));
                }
            }
            if success && !operation_succeeded(result) {
                return Err(RecordError::ResultMismatch(format!(
                    "operation {index} of the transaction result did not succeed"
                )));
            }
        }
    }
    Ok(())
}

fn operation_succeeded(operation: &stellar_xdr::OperationResult) -> bool {
    use stellar_xdr::{OperationResult, OperationResultTr as Op};
    let OperationResult::OpInner(inner) = operation else {
        return false;
    };
    // Every operation's success code in the pinned XDR is zero. Enumerate every union arm
    // explicitly so a newly supported operation cannot silently inherit a success answer.
    match inner {
        Op::CreateAccount(value) => value.discriminant() as i32 == 0,
        Op::Payment(value) => value.discriminant() as i32 == 0,
        Op::PathPaymentStrictReceive(value) => value.discriminant() as i32 == 0,
        Op::ManageSellOffer(value) => value.discriminant() as i32 == 0,
        Op::CreatePassiveSellOffer(value) => value.discriminant() as i32 == 0,
        Op::SetOptions(value) => value.discriminant() as i32 == 0,
        Op::ChangeTrust(value) => value.discriminant() as i32 == 0,
        Op::AllowTrust(value) => value.discriminant() as i32 == 0,
        Op::AccountMerge(value) => value.discriminant() as i32 == 0,
        Op::Inflation(value) => value.discriminant() as i32 == 0,
        Op::ManageData(value) => value.discriminant() as i32 == 0,
        Op::BumpSequence(value) => value.discriminant() as i32 == 0,
        Op::ManageBuyOffer(value) => value.discriminant() as i32 == 0,
        Op::PathPaymentStrictSend(value) => value.discriminant() as i32 == 0,
        Op::CreateClaimableBalance(value) => value.discriminant() as i32 == 0,
        Op::ClaimClaimableBalance(value) => value.discriminant() as i32 == 0,
        Op::BeginSponsoringFutureReserves(value) => value.discriminant() as i32 == 0,
        Op::EndSponsoringFutureReserves(value) => value.discriminant() as i32 == 0,
        Op::RevokeSponsorship(value) => value.discriminant() as i32 == 0,
        Op::Clawback(value) => value.discriminant() as i32 == 0,
        Op::ClawbackClaimableBalance(value) => value.discriminant() as i32 == 0,
        Op::SetTrustLineFlags(value) => value.discriminant() as i32 == 0,
        Op::LiquidityPoolDeposit(value) => value.discriminant() as i32 == 0,
        Op::LiquidityPoolWithdraw(value) => value.discriminant() as i32 == 0,
        Op::InvokeHostFunction(value) => value.discriminant() as i32 == 0,
        Op::ExtendFootprintTtl(value) => value.discriminant() as i32 == 0,
        Op::RestoreFootprint(value) => value.discriminant() as i32 == 0,
    }
}

/// Return every contract address whose executable can influence a recording of this
/// snapshot: address-level authorizers and every contract call in the auth trees of every
/// InvokeHostFunction operation. Operation selection is deliberately not taken here —
/// acquisition adapters prefetch contract-instance ledger entries once per snapshot,
/// before a caller has chosen an operation index.
pub fn referenced_contract_addresses(
    snapshot: &EvidenceSnapshot,
) -> Result<Vec<String>, RecordError> {
    validate_evidence_limits(snapshot)?;
    let envelope =
        TransactionEnvelope::from_xdr_base64(&snapshot.envelope_xdr_base64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("envelope", e, RecordError::EnvelopeParse))?;
    let tx = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(RecordError::UnsupportedEnvelope(
                "TransactionV0 envelopes cannot carry Soroban operations".to_string(),
            ))
        }
    };

    let mut addresses = std::collections::BTreeSet::new();

    for operation in tx.operations.iter() {
        let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
            continue;
        };
        if let HostFunction::InvokeContract(call) = &invoke.host_function {
            insert_contract_address(&call.contract_address, &mut addresses);
        }
        if snapshot.execution != Execution::Simulated {
            for entry in invoke.auth.iter() {
                collect_auth_contract_addresses(entry, &mut addresses);
            }
        }
    }
    if snapshot.execution == Execution::Simulated {
        for encoded in &snapshot.simulated_auth_xdr_base64 {
            let entry = SorobanAuthorizationEntry::from_xdr_base64(encoded, xdr_limits())
                .map_err(|e| map_xdr_parse_error("authorization", e, RecordError::AuthParse))?;
            collect_auth_contract_addresses(&entry, &mut addresses);
        }
    }
    if addresses.len() > MAX_CONTRACT_EXECUTABLE_OBSERVATIONS {
        return Err(RecordError::ResourceLimit(format!(
            "snapshot references {} contract instances; maximum is {MAX_CONTRACT_EXECUTABLE_OBSERVATIONS}",
            addresses.len()
        )));
    }
    Ok(addresses.into_iter().collect())
}

fn collect_auth_contract_addresses(
    entry: &SorobanAuthorizationEntry,
    addresses: &mut std::collections::BTreeSet<String>,
) {
    match &entry.credentials {
        SorobanCredentials::Address(credentials) => {
            insert_contract_address(&credentials.address, addresses);
        }
        SorobanCredentials::AddressV2(credentials) => {
            insert_contract_address(&credentials.address, addresses);
        }
        SorobanCredentials::AddressWithDelegates(credentials) => {
            insert_contract_address(&credentials.address_credentials.address, addresses);
        }
        SorobanCredentials::SourceAccount => {}
    }
    let mut invocations = vec![&entry.root_invocation];
    while let Some(invocation) = invocations.pop() {
        if let SorobanAuthorizedFunction::ContractFn(call) = &invocation.function {
            insert_contract_address(&call.contract_address, addresses);
        }
        invocations.extend(invocation.sub_invocations.iter());
    }
}

fn insert_contract_address(
    address: &ScAddress,
    addresses: &mut std::collections::BTreeSet<String>,
) {
    if let ScAddress::Contract(contract) = address {
        addresses.insert(format!("{}", stellar_strkey::Contract(contract.0 .0)));
    }
}

fn decode_auth_entry(
    entry: &SorobanAuthorizationEntry,
    tx: &stellar_xdr::Transaction,
) -> Result<AuthorizationRecord, RecordError> {
    // Resolve the authorizer + credential arm. All four Protocol ≤27 arms are handled;
    // anything new fails closed at the XDR parse layer.
    let (authorizer_sc, credential): (ScAddress, CredentialRecord) = match &entry.credentials {
        SorobanCredentials::SourceAccount => {
            let source = muxed_to_scaddress(&tx.source_account)?;
            (source, CredentialRecord::SourceAccount)
        }
        SorobanCredentials::Address(c) => (
            c.address.clone(),
            CredentialRecord::Address {
                nonce: c.nonce,
                signature_expiration_ledger: c.signature_expiration_ledger,
            },
        ),
        SorobanCredentials::AddressV2(c) => (
            c.address.clone(),
            CredentialRecord::AddressV2 {
                nonce: c.nonce,
                signature_expiration_ledger: c.signature_expiration_ledger,
            },
        ),
        SorobanCredentials::AddressWithDelegates(c) => (
            c.address_credentials.address.clone(),
            CredentialRecord::AddressWithDelegates {
                nonce: c.address_credentials.nonce,
                signature_expiration_ledger: c.address_credentials.signature_expiration_ledger,
                delegate_count: count_delegates(&c.delegates),
            },
        ),
    };

    let authorizer = scaddress_to_strkey(&authorizer_sc)?;
    let fingerprint = auth_fingerprint(&authorizer_sc, &entry.root_invocation)?;
    let root = decode_invocation(&entry.root_invocation)?;

    Ok(AuthorizationRecord {
        authorizer,
        credential,
        fingerprint,
        root,
    })
}

fn count_delegates(delegates: &stellar_xdr::VecM<stellar_xdr::SorobanDelegateSignature>) -> u32 {
    let mut n = 0u32;
    for d in delegates.iter() {
        n = n
            .saturating_add(1)
            .saturating_add(count_delegates(&d.nested_delegates));
    }
    n
}

/// Replay-invariant authorization fingerprint over canonical XDR.
///
/// The two hashed values are unchanged — the authorizer and the root authorized invocation — but
/// they now sit inside the versioned preimage every other hash uses, so this one is not the sole
/// exception whose domain lives outside the encoding. The authorizer is carried as `ScVal::Address`
/// because that is exactly what an `ScAddress` is; the invocation has no `ScVal` counterpart, so
/// it stays as its own canonical XDR bytes.
pub(crate) fn auth_fingerprint(
    authorizer: &ScAddress,
    root: &SorobanAuthorizedInvocation,
) -> Result<Hash32, RecordError> {
    let invocation = root
        .to_xdr(xdr_limits())
        .map_err(|e| map_xdr_write_error("authorized invocation", e))?;
    let invocation: ScBytes = invocation.try_into().map_err(|_| {
        RecordError::Internal("the authorized invocation exceeds the XDR length limit".to_string())
    })?;
    let preimage = ScVal::Vec(Some(
        vec![ScVal::Address(authorizer.clone()), ScVal::Bytes(invocation)]
            .try_into()
            .map_err(|_| {
                RecordError::Internal("the fingerprint vector was rejected".to_string())
            })?,
    ));
    ozpb_domain::canonical_hash_of(domains::AUTH_FINGERPRINT, preimage)
        .map_err(|e| RecordError::Internal(e.to_string()))
}

fn decode_invocation(inv: &SorobanAuthorizedInvocation) -> Result<InvocationNode, RecordError> {
    let call = match &inv.function {
        SorobanAuthorizedFunction::ContractFn(args) => AuthorizedCall::Contract {
            contract: scaddress_to_strkey(&args.contract_address)?,
            fn_name: symbol_text(&args.function_name).ok_or_else(|| {
                RecordError::AuthParse(
                    "authorized function name contains bytes outside the Soroban symbol \
                     grammar"
                        .to_string(),
                )
            })?,
            args: args
                .args
                .iter()
                .map(summarize_arg)
                .collect::<Result<_, _>>()?,
        },
        SorobanAuthorizedFunction::CreateContractHostFn(_)
        | SorobanAuthorizedFunction::CreateContractV2HostFn(_) => AuthorizedCall::CreateContract,
    };
    let sub_invocations = inv
        .sub_invocations
        .iter()
        .map(decode_invocation)
        .collect::<Result<_, _>>()?;
    Ok(InvocationNode {
        call,
        sub_invocations,
    })
}

fn summarize_arg(v: &ScVal) -> Result<ArgSummary, RecordError> {
    Ok(match v {
        ScVal::Address(a) => ArgSummary::Address(scaddress_to_strkey(a)?),
        ScVal::I128(p) => ArgSummary::I128(int128_parts_to_i128(p)),
        ScVal::U64(u) => ArgSummary::U64(*u),
        ScVal::U32(u) => ArgSummary::U32(*u),
        ScVal::Symbol(s) => ArgSummary::Symbol(symbol_text(s).ok_or_else(|| {
            RecordError::AuthParse(
                "authorized symbol argument contains bytes outside the Soroban symbol \
                 grammar"
                    .to_string(),
            )
        })?),
        other => ArgSummary::Other {
            xdr_base64: other
                .to_xdr_base64(xdr_limits())
                .map_err(|e| map_xdr_write_error("argument", e))?,
        },
    })
}

fn validate_evidence_limits(snapshot: &EvidenceSnapshot) -> Result<(), RecordError> {
    validate_raw_evidence_limits(
        &snapshot.envelope_xdr_base64,
        snapshot.result_meta_xdr_base64.as_deref(),
        snapshot.result_xdr_base64.as_deref(),
        &snapshot.simulated_auth_xdr_base64,
        &snapshot.simulated_state_changes,
        snapshot.contract_executables.len(),
    )
}

/// The shared resource boundary over raw evidence, taken by both admission paths:
/// [`record`] passes snapshot fields, [`RecordingBundle::verify`] passes the supplied
/// bundle's raw evidence and simulation-sourced state changes.
fn validate_raw_evidence_limits(
    envelope_xdr_base64: &str,
    result_meta_xdr_base64: Option<&str>,
    result_xdr_base64: Option<&str>,
    simulated_auth_xdr_base64: &[String],
    simulated_state_changes: &[StateChange],
    contract_executable_count: usize,
) -> Result<(), RecordError> {
    ensure_base64_size("envelope", envelope_xdr_base64)?;
    if let Some(meta) = result_meta_xdr_base64 {
        ensure_base64_size("result meta", meta)?;
    }
    if let Some(result) = result_xdr_base64 {
        ensure_base64_size("transaction result", result)?;
    }
    if simulated_auth_xdr_base64.len() > MAX_SIMULATED_AUTH_ENTRIES {
        return Err(RecordError::ResourceLimit(format!(
            "simulation returned {} authorization entries; maximum is {MAX_SIMULATED_AUTH_ENTRIES}",
            simulated_auth_xdr_base64.len()
        )));
    }
    let auth_bytes = simulated_auth_xdr_base64
        .iter()
        .try_fold(0usize, |total, auth| {
            ensure_base64_size("authorization", auth)?;
            total.checked_add(auth.len()).ok_or_else(|| {
                RecordError::ResourceLimit("authorization evidence size overflow".to_string())
            })
        })?;
    if auth_bytes > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "authorization evidence is {auth_bytes} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}"
        )));
    }
    if simulated_state_changes.len() > MAX_SIMULATED_STATE_CHANGES {
        return Err(RecordError::ResourceLimit(format!(
            "simulation returned {} state changes; maximum is {MAX_SIMULATED_STATE_CHANGES}",
            simulated_state_changes.len()
        )));
    }
    if contract_executable_count > MAX_CONTRACT_EXECUTABLE_OBSERVATIONS {
        return Err(RecordError::ResourceLimit(format!(
            "recording contains {contract_executable_count} contract executable observations; \
             maximum is {MAX_CONTRACT_EXECUTABLE_OBSERVATIONS}"
        )));
    }
    let state_bytes = simulated_state_changes
        .iter()
        .flat_map(|change| {
            [
                change.key_xdr_base64.as_deref(),
                change.before_xdr_base64.as_deref(),
                change.after_xdr_base64.as_deref(),
            ]
        })
        .flatten()
        .try_fold(0usize, |total, value| {
            ensure_base64_size("state change", value)?;
            total.checked_add(value.len()).ok_or_else(|| {
                RecordError::ResourceLimit("state-change evidence size overflow".to_string())
            })
        })?;
    if state_bytes > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "state-change evidence is {state_bytes} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}"
        )));
    }
    let encoded_evidence_bytes = envelope_xdr_base64
        .len()
        .checked_add(result_meta_xdr_base64.map_or(0, str::len))
        .and_then(|total| total.checked_add(result_xdr_base64.map_or(0, str::len)))
        .and_then(|total| total.checked_add(auth_bytes))
        .and_then(|total| total.checked_add(state_bytes))
        .ok_or_else(|| {
            RecordError::ResourceLimit("total encoded evidence size overflow".to_string())
        })?;
    if encoded_evidence_bytes > MAX_TOTAL_EVIDENCE_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "encoded evidence is {encoded_evidence_bytes} bytes; maximum is \
             {MAX_TOTAL_EVIDENCE_BASE64_BYTES}"
        )));
    }
    Ok(())
}

fn ensure_base64_size(label: &str, value: &str) -> Result<(), RecordError> {
    if value.len() > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "{label} XDR is {} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

fn map_xdr_parse_error(
    label: &str,
    error: stellar_xdr::Error,
    parse_error: impl FnOnce(String) -> RecordError,
) -> RecordError {
    if matches!(
        error,
        stellar_xdr::Error::DepthLimitExceeded | stellar_xdr::Error::LengthLimitExceeded
    ) {
        RecordError::ResourceLimit(format!("{label} XDR exceeded decoding limits"))
    } else {
        parse_error(error.to_string())
    }
}

fn map_xdr_write_error(label: &str, error: stellar_xdr::Error) -> RecordError {
    if matches!(
        error,
        stellar_xdr::Error::DepthLimitExceeded | stellar_xdr::Error::LengthLimitExceeded
    ) {
        RecordError::ResourceLimit(format!("{label} XDR exceeded encoding limits"))
    } else {
        RecordError::Internal(error.to_string())
    }
}

fn int128_parts_to_i128(p: &stellar_xdr::Int128Parts) -> i128 {
    (i128::from(p.hi) << 64) | i128::from(p.lo)
}

/// Decode a symbol under the host's own grammar (`[A-Za-z0-9_]`). The host validates
/// symbol bytes, so genuine network evidence never fails this; self-supplied raw XDR can,
/// and lossy replacement would collapse distinct raw values into one decoded text.
/// Callers decide whether an invalid symbol is an error (authorization facts) or an
/// unattributed note (event evidence).
fn symbol_text(s: &stellar_xdr::ScSymbol) -> Option<String> {
    let bytes = s.0.as_slice();
    if bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    } else {
        None
    }
}

fn muxed_to_scaddress(m: &stellar_xdr::MuxedAccount) -> Result<ScAddress, RecordError> {
    match m {
        stellar_xdr::MuxedAccount::Ed25519(key) => Ok(ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(key.clone()),
        ))),
        stellar_xdr::MuxedAccount::MuxedEd25519(m) => {
            Ok(ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(m.ed25519.clone()),
            )))
        }
    }
}

fn scaddress_to_strkey(a: &ScAddress) -> Result<String, RecordError> {
    match a {
        ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key)),
        )) => Ok(format!("{}", stellar_strkey::ed25519::PublicKey(*key))),
        ScAddress::Contract(cid) => Ok(format!("{}", stellar_strkey::Contract(cid.0 .0))),
        other => Err(RecordError::UnsupportedAddress(format!(
            "unsupported authorizer/argument address kind: {other:?}"
        ))),
    }
}

/// Summarize a `LedgerEntryChanges` list into evidence-only [`StateChange`]s. A
/// `State → Updated` pair yields two entries (the `State` pre-image is kept for
/// completeness); the summary is deliberately shallow (kind + entry type + owning
/// contract) — full values stay in the raw meta.
fn collect_changes(
    changes: &stellar_xdr::LedgerEntryChanges,
    source: StateChangeSource,
    out: &mut Vec<StateChange>,
) {
    use stellar_xdr::LedgerEntryChange as C;
    for change in changes.iter() {
        let (kind, (entry, contract)) = match change {
            C::Created(e) => (StateChangeKind::Created, entry_summary(&e.data)),
            C::Updated(e) => (StateChangeKind::Updated, entry_summary(&e.data)),
            C::State(e) => (StateChangeKind::State, entry_summary(&e.data)),
            C::Restored(e) => (StateChangeKind::Restored, entry_summary(&e.data)),
            C::Removed(k) => (StateChangeKind::Removed, ledger_key_summary(k)),
        };
        out.push(StateChange {
            kind,
            entry,
            contract,
            source,
            key_xdr_base64: None,
            before_xdr_base64: None,
            after_xdr_base64: None,
        });
    }
}

fn entry_summary(data: &stellar_xdr::LedgerEntryData) -> (String, Option<String>) {
    use stellar_xdr::LedgerEntryData as D;
    match data {
        D::ContractData(cd) => (
            "contract_data".to_string(),
            scaddress_to_strkey(&cd.contract).ok(),
        ),
        D::ContractCode(_) => ("contract_code".to_string(), None),
        D::Account(_) => ("account".to_string(), None),
        D::Trustline(_) => ("trustline".to_string(), None),
        D::Ttl(_) => ("ttl".to_string(), None),
        D::Offer(_) => ("offer".to_string(), None),
        D::Data(_) => ("data".to_string(), None),
        D::ClaimableBalance(_) => ("claimable_balance".to_string(), None),
        D::LiquidityPool(_) => ("liquidity_pool".to_string(), None),
        D::ConfigSetting(_) => ("config_setting".to_string(), None),
    }
}

/// The `(entry kind, owning contract)` pair a [`StateChange`] carries for a ledger key.
///
/// Public because the RPC acquisition adapter summarizes simulation state changes from the
/// `LedgerKey` the endpoint returns for each one. Two vocabularies for one field would drift,
/// and a reader of a recording could not then tell whether `contract_data` in a
/// simulation-sourced change means the same thing as `contract_data` in a meta-derived one.
pub fn ledger_key_summary(key: &stellar_xdr::LedgerKey) -> (String, Option<String>) {
    use stellar_xdr::LedgerKey as K;
    match key {
        K::ContractData(cd) => (
            "contract_data".to_string(),
            scaddress_to_strkey(&cd.contract).ok(),
        ),
        K::ContractCode(_) => ("contract_code".to_string(), None),
        K::Account(_) => ("account".to_string(), None),
        K::Trustline(_) => ("trustline".to_string(), None),
        K::Ttl(_) => ("ttl".to_string(), None),
        K::Offer(_) => ("offer".to_string(), None),
        K::Data(_) => ("data".to_string(), None),
        K::ClaimableBalance(_) => ("claimable_balance".to_string(), None),
        K::LiquidityPool(_) => ("liquidity_pool".to_string(), None),
        K::ConfigSetting(_) => ("config_setting".to_string(), None),
    }
}

/// Decode a simulation change's preserved XDR and derive its explanatory identity.
/// Both acquisition and serialized-artifact verification use this pure boundary. Entry
/// values must name the same key and agree with the change's created/updated/removed shape;
/// these are internal consistency checks, not proof of the endpoint's claimed ledger state.
pub fn simulation_state_change(
    kind: StateChangeKind,
    key_xdr_base64: String,
    before_xdr_base64: Option<String>,
    after_xdr_base64: Option<String>,
) -> Result<StateChange, RecordError> {
    fn decode<T: ReadXdr>(field: &str, encoded: &str) -> Result<T, RecordError> {
        if encoded.len() > MAX_XDR_BASE64_BYTES {
            return Err(RecordError::EvidenceIncoherent(format!(
                "simulation change {field} exceeds the XDR size limit"
            )));
        }
        T::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RecordError::EvidenceIncoherent(format!(
                "simulation change {field} is not valid XDR: {error}"
            ))
        })
    }
    let key: stellar_xdr::LedgerKey = decode("key", &key_xdr_base64)?;
    for (field, encoded) in [
        ("before", before_xdr_base64.as_deref()),
        ("after", after_xdr_base64.as_deref()),
    ] {
        if let Some(encoded) = encoded {
            let entry: stellar_xdr::LedgerEntry = decode(field, encoded)?;
            if entry.to_key() != key {
                return Err(RecordError::EvidenceIncoherent(format!(
                    "simulation change {field} is a ledger entry for a different key"
                )));
            }
        }
    }
    let sides = (before_xdr_base64.is_some(), after_xdr_base64.is_some());
    let valid = match kind {
        StateChangeKind::Created => sides == (false, true),
        StateChangeKind::Updated => sides == (true, true),
        StateChangeKind::Removed => sides == (true, false),
        StateChangeKind::Restored => sides != (false, false),
        StateChangeKind::State => false,
    };
    if !valid {
        return Err(RecordError::EvidenceIncoherent(format!(
            "simulation change {kind:?} contradicts its before/after evidence"
        )));
    }
    let (entry, contract) = ledger_key_summary(&key);
    Ok(StateChange {
        kind,
        entry,
        contract,
        source: StateChangeSource::Simulation,
        key_xdr_base64: Some(key_xdr_base64),
        before_xdr_base64,
        after_xdr_base64,
    })
}

/// Decode a SEP-41/CAP-67 token event into a typed movement, or `None` (the caller turns
/// that into an unattributed evidence note). Fail-closed shape checks: the event must be a
/// `Contract` event with an emitting contract, its kind topic a valid symbol, the roles
/// that kind requires present as addresses, and a decodable amount — a look-alike missing
/// any of these is preserved in the raw meta and labeled, never confidently typed.
fn decode_token_event(ev: &ContractEvent) -> Option<TokenMovement> {
    if ev.type_ != ContractEventType::Contract {
        return None;
    }
    let token_contract = Some(format!(
        "{}",
        stellar_strkey::Contract(ev.contract_id.as_ref()?.0 .0)
    ));
    let ContractEventBody::V0(v0) = &ev.body;
    let kind = match v0.topics.first()? {
        ScVal::Symbol(s) => match symbol_text(s)?.as_str() {
            "transfer" => MovementKind::Transfer,
            "mint" => MovementKind::Mint,
            "burn" => MovementKind::Burn,
            "approve" => MovementKind::Approve,
            _ => return None,
        },
        _ => return None,
    };
    let addr_at = |i: usize| -> Option<String> {
        match v0.topics.get(i) {
            Some(ScVal::Address(a)) => scaddress_to_strkey(a).ok(),
            _ => None,
        }
    };
    let (from, to, spender) = match kind {
        MovementKind::Transfer => (Some(addr_at(1)?), Some(addr_at(2)?), None),
        MovementKind::Mint => (None, Some(addr_at(1)?), None),
        MovementKind::Burn => (Some(addr_at(1)?), None, None),
        MovementKind::Approve => (Some(addr_at(1)?), None, Some(addr_at(2)?)),
    };
    let amount = Some(match &v0.data {
        ScVal::I128(p) => int128_parts_to_i128(p),
        ScVal::Map(Some(m)) => m.iter().find_map(|entry| match (&entry.key, &entry.val) {
            (ScVal::Symbol(k), ScVal::I128(p)) if symbol_text(k).as_deref() == Some("amount") => {
                Some(int128_parts_to_i128(p))
            }
            _ => None,
        })?,
        _ => return None,
    });
    let expiration_ledger = match &v0.data {
        ScVal::Map(Some(m)) => m.iter().find_map(|entry| match (&entry.key, &entry.val) {
            (ScVal::Symbol(k), ScVal::U32(ledger))
                if symbol_text(k).as_deref() == Some("expiration_ledger") =>
            {
                Some(*ledger)
            }
            _ => None,
        }),
        _ => None,
    };
    Some(TokenMovement {
        kind,
        token_contract,
        from,
        to,
        spender,
        amount,
        expiration_ledger,
    })
}

// ---------------------------------------------------------------------------------------
// Tests — fixtures constructed from real XDR types (deterministic, no network)
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Deterministic fixtures (public: shared by downstream crates' tests and the e2e check)
// ---------------------------------------------------------------------------------------

// Deterministic test-support builders shared across crates' tests. `unwrap` on
// known-good literal XDR is intentional here; the core-logic lint stays in force
// everywhere else.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod fixtures {
    use super::*;
    use stellar_xdr::{
        AccountId, ContractEventType, ContractEventV0, ContractId, ExtensionPoint, Hash,
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo, MuxedAccount, Operation,
        Preconditions, PublicKey, ScMapEntry, ScSymbol, SequenceNumber, SorobanAddressCredentials,
        SorobanTransactionMeta, SorobanTransactionMetaExt, Transaction, TransactionExt,
        TransactionMetaV3, TransactionV1Envelope, Uint256,
    };

    pub const ACCOUNT_CID: [u8; 32] = [1u8; 32];
    pub const TOKEN_CID: [u8; 32] = [2u8; 32];
    pub const MERCHANT_KEY: [u8; 32] = [3u8; 32];
    pub const AMOUNT: i128 = 500_000_000;

    pub fn account_sc() -> ScAddress {
        ScAddress::Contract(ContractId(Hash(ACCOUNT_CID)))
    }
    pub fn token_sc() -> ScAddress {
        ScAddress::Contract(ContractId(Hash(TOKEN_CID)))
    }
    pub fn merchant_sc() -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            MERCHANT_KEY,
        ))))
    }

    pub fn i128_val(v: i128) -> ScVal {
        ScVal::I128(stellar_xdr::Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        })
    }

    pub fn transfer_invocation() -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: token_sc(),
                function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                args: vec![
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                    i128_val(AMOUNT),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: Default::default(),
        }
    }

    pub fn address_credentials(nonce: i64) -> SorobanCredentials {
        SorobanCredentials::Address(SorobanAddressCredentials {
            address: account_sc(),
            nonce,
            signature_expiration_ledger: 4_210_000,
            signature: ScVal::Void,
        })
    }

    pub fn auth_entry(credentials: SorobanCredentials) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials,
            root_invocation: transfer_invocation(),
        }
    }

    pub fn envelope_with(auth: Vec<SorobanAuthorizationEntry>) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: transaction_with(auth),
            signatures: Default::default(),
        })
    }

    pub fn transaction_with(auth: Vec<SorobanAuthorizationEntry>) -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([9u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(7),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(InvokeContractArgs {
                        contract_address: token_sc(),
                        function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                        args: Default::default(),
                    }),
                    auth: auth.try_into().unwrap(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        }
    }

    pub fn transfer_event() -> ContractEvent {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash(TOKEN_CID))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol("transfer".as_bytes().try_into().unwrap())),
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                ]
                .try_into()
                .unwrap(),
                data: i128_val(AMOUNT),
            }),
        }
    }

    pub fn approve_event() -> ContractEvent {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash(TOKEN_CID))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol("approve".as_bytes().try_into().unwrap())),
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                ]
                .try_into()
                .unwrap(),
                data: ScVal::Map(Some(
                    vec![
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol("amount".as_bytes().try_into().unwrap())),
                            val: i128_val(AMOUNT),
                        },
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol(
                                "expiration_ledger".as_bytes().try_into().unwrap(),
                            )),
                            val: ScVal::U32(4_210_000),
                        },
                    ]
                    .try_into()
                    .unwrap(),
                )),
            }),
        }
    }

    pub fn transaction_result(success: bool) -> stellar_xdr::TransactionResult {
        use stellar_xdr::{TransactionResult, TransactionResultExt, TransactionResultResult};
        TransactionResult {
            fee_charged: 100,
            result: if success {
                TransactionResultResult::TxSuccess(
                    vec![stellar_xdr::OperationResult::OpInner(
                        stellar_xdr::OperationResultTr::InvokeHostFunction(
                            stellar_xdr::InvokeHostFunctionResult::Success(stellar_xdr::Hash(
                                [0; 32],
                            )),
                        ),
                    )]
                    .try_into()
                    .unwrap(),
                )
            } else {
                TransactionResultResult::TxFailed(
                    vec![stellar_xdr::OperationResult::OpInner(
                        stellar_xdr::OperationResultTr::InvokeHostFunction(
                            stellar_xdr::InvokeHostFunctionResult::Trapped,
                        ),
                    )]
                    .try_into()
                    .unwrap(),
                )
            },
            ext: TransactionResultExt::V0,
        }
    }

    /// The fixture transaction result, base64 XDR — the encoding callers outside this
    /// crate need, without each of them depending on `stellar-xdr` to produce it.
    pub fn transaction_result_base64(success: bool) -> String {
        transaction_result(success)
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    pub fn meta_v3() -> TransactionMeta {
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![transfer_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }

    pub fn meta_v3_with_approve() -> TransactionMeta {
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![approve_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }

    /// The contract-instance observations an acquisition adapter would have fetched for
    /// the fixture transaction: the smart account's pinned upstream wasm and the token SAC.
    pub fn observed_executables() -> BTreeMap<String, ExecutableObservation> {
        let mut observations = BTreeMap::new();
        observations.insert(
            format!("{}", stellar_strkey::Contract(ACCOUNT_CID)),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        observations.insert(
            format!("{}", stellar_strkey::Contract(TOKEN_CID)),
            ExecutableObservation {
                executable: ObservedExecutable::StellarAsset,
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        observations
    }

    pub fn executed_snapshot() -> EvidenceSnapshot {
        EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(12345))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap()),
            4_200_100,
            1_780_000_000,
            true,
        )
        .with_rpc_result(transaction_result_base64(true))
        .with_contract_executables(observed_executables())
    }

    /// Exactly the evidence of [`executed_snapshot`], acquired by import instead of from
    /// RPC: `self_supplied` when the transaction result accompanies the outcome claim,
    /// `incomplete` without it. The pair differs in nothing else, so a test can attribute
    /// a difference in outcome to the missing result alone.
    pub fn imported_snapshot(with_transaction_result: bool) -> EvidenceSnapshot {
        EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(12345))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap()),
            with_transaction_result.then(|| transaction_result_base64(true)),
            Some(4_200_100),
            Some(1_780_000_000),
            true,
        )
        .with_contract_executables(observed_executables())
    }

    /// A ContractData ledger entry owned by the token contract.
    pub fn contract_data_entry(val: i128) -> stellar_xdr::LedgerEntry {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, LedgerEntry, LedgerEntryData, LedgerEntryExt,
        };
        LedgerEntry {
            last_modified_ledger_seq: 4_200_099,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: token_sc(),
                key: ScVal::Symbol(ScSymbol("balance".as_bytes().try_into().unwrap())),
                durability: ContractDataDurability::Persistent,
                val: i128_val(val),
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    /// Meta v3 carrying a `State → Updated` contract-data change in operation 0.
    pub fn meta_v3_with_changes() -> TransactionMeta {
        use stellar_xdr::{LedgerEntryChange, OperationMeta};
        let changes: stellar_xdr::LedgerEntryChanges = vec![
            LedgerEntryChange::State(contract_data_entry(1)),
            LedgerEntryChange::Updated(contract_data_entry(2)),
        ]
        .try_into()
        .unwrap();
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMeta { changes }].try_into().unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![transfer_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    // Only the XDR types the test bodies construct directly; the fixture builders live
    // in the `fixtures` module with their own imports.
    use stellar_xdr::{
        ExtensionPoint, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, MuxedAccount, Operation, SorobanAddressCredentials,
        SorobanTransactionMetaExt, TransactionV1Envelope, Uint256,
    };

    #[test]
    fn protocol30_muxed_contract_arguments_are_refused_without_address_normalization() {
        let muxed = ScVal::Address(ScAddress::MuxedContract(stellar_xdr::MuxedContract {
            id: 7,
            contract_id: stellar_xdr::ContractId(stellar_xdr::Hash([1; 32])),
        }));
        let mut snapshot = executed_snapshot();
        let mut envelope =
            TransactionEnvelope::from_xdr_base64(&snapshot.envelope_xdr_base64, Limits::none())
                .unwrap();
        let TransactionEnvelope::Tx(ref mut tx) = envelope else {
            panic!("v1 fixture")
        };
        for operation in tx.tx.operations.iter_mut() {
            if let OperationBody::InvokeHostFunction(invoke) = &mut operation.body {
                for auth in invoke.auth.iter_mut() {
                    if let SorobanAuthorizedFunction::ContractFn(call) =
                        &mut auth.root_invocation.function
                    {
                        let mut args = call.args.to_vec();
                        assert!(!args.is_empty(), "recorded authorization has arguments");
                        args[0] = muxed.clone();
                        call.args = args.try_into().unwrap();
                    }
                }
            }
        }
        snapshot.envelope_xdr_base64 = envelope.to_xdr_base64(Limits::none()).unwrap();
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::UnsupportedAddress(_))
        ));
    }

    #[test]
    fn executed_transfer_records_authorization_and_movement() {
        let bundle = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(bundle.trust.as_str(), "rpc_reported");
        assert_eq!(bundle.execution, Execution::ExecutedSuccess);
        assert_eq!(bundle.authorizations.len(), 1);

        let auth = &bundle.authorizations[0];
        assert!(
            auth.authorizer.starts_with('C'),
            "smart account is a C-address"
        );
        assert!(matches!(
            auth.credential,
            CredentialRecord::Address {
                nonce: 12345,
                signature_expiration_ledger: 4_210_000
            }
        ));
        match &auth.root.call {
            AuthorizedCall::Contract {
                contract,
                fn_name,
                args,
            } => {
                assert!(contract.starts_with('C'));
                assert_eq!(fn_name, "transfer");
                assert_eq!(args.len(), 3);
                assert!(matches!(&args[0], ArgSummary::Address(a) if a.starts_with('C')));
                assert!(matches!(&args[1], ArgSummary::Address(a) if a.starts_with('G')));
                assert_eq!(args[2], ArgSummary::I128(AMOUNT));
            }
            other => panic!("unexpected call: {other:?}"),
        }

        assert_eq!(bundle.token_movements.len(), 1);
        let m = &bundle.token_movements[0];
        assert_eq!(m.kind, MovementKind::Transfer);
        assert_eq!(m.amount, Some(AMOUNT));
        assert_eq!(m.spender, None);
        assert_eq!(m.expiration_ledger, None);
    }

    #[test]
    fn approve_event_records_spender_amount_and_expiration() {
        let snapshot = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(12345))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(
                meta_v3_with_approve()
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            ),
            4_200_100,
            1_780_000_000,
            true,
        );
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();

        assert_eq!(bundle.token_movements.len(), 1);
        let approval = &bundle.token_movements[0];
        let expected_owner = format!("{}", stellar_strkey::Contract(ACCOUNT_CID));
        let expected_spender = format!("{}", stellar_strkey::ed25519::PublicKey(MERCHANT_KEY));
        assert_eq!(approval.kind, MovementKind::Approve);
        assert_eq!(approval.from.as_deref(), Some(expected_owner.as_str()));
        assert_eq!(approval.to, None);
        assert_eq!(approval.spender.as_deref(), Some(expected_spender.as_str()));
        assert_eq!(approval.amount, Some(AMOUNT));
        assert_eq!(approval.expiration_ledger, Some(4_210_000));
    }

    #[test]
    fn fingerprint_is_replay_invariant_across_executed_and_simulated() {
        // Same authorized shape via simulation (unsigned entry, different nonce):
        // the AUTH fingerprint must match; the full recording hash must differ.
        let executed = record(&executed_snapshot(), RecordOptions::default()).unwrap();

        let sim_entry = auth_entry(address_credentials(999_999)); // different nonce
        let sim = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![sim_entry.to_xdr_base64(Limits::none()).unwrap()],
            Some(4_200_101),
        );
        let simulated = record(&sim, RecordOptions::default()).unwrap();

        assert_eq!(
            executed.authorizations[0].fingerprint, simulated.authorizations[0].fingerprint,
            "fingerprint is over (authorizer, root invocation) only"
        );
        assert_ne!(
            executed.recording_hash().unwrap(),
            simulated.recording_hash().unwrap(),
            "full recording hash covers raw evidence + anchors + trust"
        );
    }

    #[test]
    fn empty_simulation_auth_never_falls_back_to_envelope_auth() {
        let executed = executed_snapshot();
        let simulated = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            executed.envelope_xdr_base64.clone(),
            vec![],
            Some(4_200_101),
        );
        let bundle = record(&simulated, RecordOptions::default()).unwrap();
        assert!(
            bundle.authorizations.is_empty(),
            "simulation evidence must use exactly the auth array returned by RPC"
        );
    }

    #[test]
    fn recording_hash_is_deterministic() {
        let a = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        let b = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(a.recording_hash().unwrap(), b.recording_hash().unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn observed_contract_executables_are_preserved_in_the_recording_hash() {
        let address = format!("{}", stellar_strkey::Contract(ACCOUNT_CID));
        let mut observations = std::collections::BTreeMap::new();
        observations.insert(
            address.clone(),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: ozpb_domain::sha256(b"fixture-account-wasm"),
                },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        let snapshot = executed_snapshot().with_contract_executables(observations);
        let observed = record(&snapshot, RecordOptions::default()).unwrap();
        let baseline = record(
            &executed_snapshot().with_contract_executables(BTreeMap::new()),
            RecordOptions::default(),
        )
        .unwrap();

        assert!(observed.contract_executables.contains_key(&address));
        assert_ne!(
            observed.recording_hash().unwrap(),
            baseline.recording_hash().unwrap(),
            "executable observations are trust-bearing recording evidence"
        );
    }

    #[test]
    fn oversized_xdr_is_rejected_before_decode() {
        let snapshot = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            "A".repeat(MAX_XDR_BASE64_BYTES + 1),
            None,
            None,
            None,
            None,
            true,
        );

        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResourceLimit(message)) if message.contains("envelope")
        ));
    }

    #[test]
    fn aggregate_evidence_size_is_rejected_before_decode() {
        let each = MAX_TOTAL_EVIDENCE_BASE64_BYTES / 2 + 1;
        assert!(each <= MAX_XDR_BASE64_BYTES);
        let snapshot = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            "A".repeat(each),
            Some("A".repeat(each)),
            None,
            None,
            None,
            true,
        );

        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResourceLimit(message)) if message.contains("encoded evidence")
        ));
    }

    #[test]
    fn all_credential_arms_are_recorded() {
        use stellar_xdr::{SorobanAddressCredentialsWithDelegates, SorobanDelegateSignature};

        // SourceAccount resolves the authorizer from the tx source account.
        let env = envelope_with(vec![auth_entry(SorobanCredentials::SourceAccount)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::SourceAccount
        ));
        assert!(b.authorizations[0].authorizer.starts_with('G'));

        // AddressV2 (CAP-71).
        let v2 = SorobanCredentials::AddressV2(SorobanAddressCredentials {
            address: account_sc(),
            nonce: 5,
            signature_expiration_ledger: 10,
            signature: ScVal::Void,
        });
        let env = envelope_with(vec![auth_entry(v2)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::AddressV2 { nonce: 5, .. }
        ));

        // AddressWithDelegates with a nested delegate tree (recursive count).
        let awd =
            SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account_sc(),
                    nonce: 6,
                    signature_expiration_ledger: 11,
                    signature: ScVal::Void,
                },
                delegates: vec![SorobanDelegateSignature {
                    address: merchant_sc(),
                    signature: ScVal::Void,
                    nested_delegates: vec![SorobanDelegateSignature {
                        address: merchant_sc(),
                        signature: ScVal::Void,
                        nested_delegates: Default::default(),
                    }]
                    .try_into()
                    .unwrap(),
                }]
                .try_into()
                .unwrap(),
            });
        let env = envelope_with(vec![auth_entry(awd)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::AddressWithDelegates {
                delegate_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn fee_bump_envelopes_are_unwrapped() {
        let inner = TransactionV1Envelope {
            tx: transaction_with(vec![auth_entry(address_credentials(1))]),
            signatures: Default::default(),
        };
        let fb = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([8u8; 32])),
                fee: 1000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            fb.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.authorizations.len(), 1);
    }

    #[test]
    fn failed_transactions_are_rejected_unless_analysis_mode() {
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            false, // failed
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::TxFailed
        );
        let b = record(
            &snap,
            RecordOptions {
                allow_failed: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(b.execution, Execution::ExecutedFailed);
    }

    #[test]
    fn multi_operation_requires_explicit_selection() {
        let mut tx = transaction_with(vec![auth_entry(address_credentials(1))]);
        let ops: Vec<Operation> = tx.operations.iter().cloned().collect();
        let mut doubled = ops.clone();
        doubled.extend(ops);
        tx.operations = doubled.try_into().unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::OperationSelection(2)
        );
        let b = record(
            &snap,
            RecordOptions {
                operation_index: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(b.operation_index, 1);
    }

    /// Two InvokeHostFunction operations carrying distinguishable auth entries. The
    /// duplicate-operation test above proves only that selection is *demanded*; this one
    /// proves the selected index decodes that operation's auth and nobody else's.
    #[test]
    fn operation_selection_decodes_only_the_selected_operations_auth() {
        use stellar_xdr::{ContractId, Hash, InvokeContractArgs, InvokeHostFunctionOp, ScSymbol};
        let entry = |cid: [u8; 32], fn_name: &str, nonce: i64| SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(cid))),
                nonce,
                signature_expiration_ledger: 100,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: token_sc(),
                    function_name: ScSymbol(fn_name.as_bytes().try_into().unwrap()),
                    args: Default::default(),
                }),
                sub_invocations: Default::default(),
            },
        };
        let op = |auth: Vec<SorobanAuthorizationEntry>| Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: token_sc(),
                    function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                    args: Default::default(),
                }),
                auth: auth.try_into().unwrap(),
            }),
        };
        let mut tx = transaction_with(vec![]);
        tx.operations = vec![
            op(vec![entry([0x11; 32], "transfer", 1)]),
            op(vec![entry([0x22; 32], "swap", 2)]),
        ]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );

        for (index, cid, fn_name, nonce) in [
            (0u32, [0x11u8; 32], "transfer", 1i64),
            (1, [0x22; 32], "swap", 2),
        ] {
            let b = record(
                &snap,
                RecordOptions {
                    operation_index: Some(index),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(b.operation_index, index);
            assert_eq!(b.authorizations.len(), 1);
            let auth = &b.authorizations[0];
            assert_eq!(
                auth.authorizer,
                format!("{}", stellar_strkey::Contract(cid)),
                "operation {index} must decode its own authorizer"
            );
            assert!(
                matches!(auth.credential, CredentialRecord::Address { nonce: n, .. } if n == nonce)
            );
            assert!(
                matches!(&auth.root.call, AuthorizedCall::Contract { fn_name: f, .. } if f == fn_name),
                "operation {index} must decode its own authorized function"
            );
        }
    }

    /// Meta V4 events are per-operation; with two distinct event lists, each selection
    /// must yield exactly its own list (the single-operation V4 test above cannot tell
    /// per-operation extraction from collecting everything).
    #[test]
    fn meta_v4_event_selection_takes_only_the_selected_operations_events() {
        use stellar_xdr::{
            InvokeContractArgs, InvokeHostFunctionOp, OperationMetaV2, ScSymbol,
            SorobanTransactionMetaV2, TransactionMetaV4,
        };
        let op = || Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: token_sc(),
                    function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                    args: Default::default(),
                }),
                auth: Default::default(),
            }),
        };
        let mut tx = transaction_with(vec![]);
        tx.operations = vec![op(), op()].try_into().unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let op_meta = |events: Vec<ContractEvent>| OperationMetaV2 {
            ext: ExtensionPoint::V0,
            changes: Default::default(),
            events: events.try_into().unwrap(),
        };
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![
                op_meta(vec![transfer_event()]),
                op_meta(vec![approve_event()]),
            ]
            .try_into()
            .unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: None,
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );

        for (index, kind) in [(0u32, MovementKind::Transfer), (1, MovementKind::Approve)] {
            let b = record(
                &snap,
                RecordOptions {
                    operation_index: Some(index),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(
                b.token_movements.len(),
                1,
                "operation {index} must contribute exactly its own events"
            );
            assert_eq!(b.token_movements[0].kind, kind);
        }
    }

    /// Meta V3 predates per-operation events: `sorobanMeta.events` is transaction-level.
    /// The network caps Soroban transactions at one operation, so a multi-operation
    /// envelope here is synthetic; for that case the recorder keeps the transaction-level
    /// events for whichever operation is selected instead of guessing an attribution.
    /// This test documents and pins that boundary.
    #[test]
    fn meta_v3_transaction_level_events_are_kept_for_any_selected_operation() {
        let mut tx = transaction_with(vec![]);
        let ops: Vec<Operation> = tx.operations.iter().cloned().collect();
        let mut doubled = ops.clone();
        doubled.extend(ops);
        tx.operations = doubled.try_into().unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        let b = record(
            &snap,
            RecordOptions {
                operation_index: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(b.token_movements.len(), 1);
        assert_eq!(b.token_movements[0].kind, MovementKind::Transfer);
    }

    /// A SourceAccount credential must resolve to the *inner* transaction source, not the
    /// fee-bump fee source (the Soroban host's SOURCE_ACCOUNT identity is the inner tx's).
    #[test]
    fn source_account_credential_resolves_to_the_inner_transaction_source() {
        let inner_source_key = [9u8; 32]; // transaction_with()'s source account
        let fee_source_key = [8u8; 32];
        let inner = TransactionV1Envelope {
            tx: transaction_with(vec![auth_entry(SorobanCredentials::SourceAccount)]),
            signatures: Default::default(),
        };
        let fb = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256(fee_source_key)),
                fee: 1000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            fb.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(
            b.authorizations[0].authorizer,
            format!("{}", stellar_strkey::ed25519::PublicKey(inner_source_key))
        );
        assert_ne!(
            b.authorizations[0].authorizer,
            format!("{}", stellar_strkey::ed25519::PublicKey(fee_source_key)),
            "the fee source must never be presented as the authorizer"
        );
    }

    #[test]
    fn no_soroban_op_fails() {
        let mut tx = transaction_with(vec![]);
        tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::SetOptions(stellar_xdr::SetOptionsOp {
                inflation_dest: None,
                clear_flags: None,
                set_flags: None,
                master_weight: None,
                low_threshold: None,
                med_threshold: None,
                high_threshold: None,
                home_domain: None,
                signer: None,
            }),
        }]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::NoSorobanOp
        );
    }

    #[test]
    fn meta_v4_events_are_extracted_per_operation() {
        use stellar_xdr::{OperationMetaV2, SorobanTransactionMetaV2, TransactionMetaV4};
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMetaV2 {
                ext: ExtensionPoint::V0,
                changes: Default::default(),
                events: vec![transfer_event()].try_into().unwrap(),
            }]
            .try_into()
            .unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: None,
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.token_movements.len(), 1);
        assert_eq!(b.token_movements[0].kind, MovementKind::Transfer);
    }

    #[test]
    fn meta_v3_state_changes_are_extracted_as_evidence() {
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(
                meta_v3_with_changes()
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            ),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        // A State→Updated pair on a contract-data entry owned by the token contract.
        assert_eq!(
            b.state_changes.len(),
            2,
            "state changes: {:?}",
            b.state_changes
        );
        let kinds: Vec<_> = b.state_changes.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&StateChangeKind::State));
        assert!(kinds.contains(&StateChangeKind::Updated));
        for c in &b.state_changes {
            assert_eq!(c.entry, "contract_data");
            assert_eq!(c.source, StateChangeSource::Operation);
            assert!(c.contract.as_deref().is_some_and(|s| s.starts_with('C')));
        }
        // Evidence-only: state changes never turn into token movements or constraints.
        assert_eq!(b.token_movements.len(), 1);
    }

    #[test]
    fn meta_v4_state_changes_are_extracted() {
        use stellar_xdr::{OperationMetaV2, SorobanTransactionMetaV2, TransactionMetaV4};
        let changes: stellar_xdr::LedgerEntryChanges =
            vec![stellar_xdr::LedgerEntryChange::Created(
                fixtures::contract_data_entry(7),
            )]
            .try_into()
            .unwrap();
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMetaV2 {
                ext: ExtensionPoint::V0,
                changes,
                events: Default::default(),
            }]
            .try_into()
            .unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: None,
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.state_changes.len(), 1);
        assert_eq!(b.state_changes[0].kind, StateChangeKind::Created);
        assert_eq!(b.state_changes[0].entry, "contract_data");
    }

    #[test]
    fn pre_soroban_meta_versions_fail_closed() {
        let meta = TransactionMeta::V0(Default::default());
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::UnsupportedMetaVersion(0)
        );
    }

    #[test]
    fn imported_snapshots_are_self_supplied_at_most() {
        let snap = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            Some(
                transaction_result(true)
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            ),
            None,
            None,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.trust.as_str(), "self_supplied");
    }

    /// An executed-outcome claim with nothing to check it against is not "internally
    /// consistent but unverified" — it is missing evidence, and `incomplete` trust keeps
    /// it recordable and viewable while the existing synthesis gate refuses it.
    #[test]
    fn imported_evidence_without_a_transaction_result_is_incomplete() {
        let snap = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            None,
            None,
            None,
            true,
        );
        assert_eq!(snap.trust().as_str(), "incomplete");
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.trust.as_str(), "incomplete");
        assert!(
            !b.trust.allows_synthesis(),
            "a result-less outcome claim must not drive synthesis"
        );
    }

    /// `trust()` is readable before `record`, so the label must not claim the outcome is
    /// backed by evidence when the shipped result cannot back it. Presence alone is not
    /// backing: an undecodable result, or one that decodes and contradicts the claim, leaves
    /// the evidence `incomplete` — `record` still reports the contradiction as
    /// E_RESULT_MISMATCH rather than silently downgrading.
    #[test]
    fn a_result_that_cannot_back_the_claim_does_not_earn_self_supplied() {
        let envelope = envelope_with(vec![auth_entry(address_credentials(1))])
            .to_xdr_base64(Limits::none())
            .unwrap();
        let import = |result: Option<String>, successful: bool| {
            EvidenceSnapshot::from_import(
                ozpb_domain::TESTNET_PASSPHRASE,
                envelope.clone(),
                None,
                result,
                None,
                None,
                successful,
            )
        };

        // Not XDR at all.
        assert_eq!(
            import(Some("not xdr".to_string()), true).trust().as_str(),
            "incomplete"
        );
        // Decodable, but it describes the opposite outcome.
        assert_eq!(
            import(
                Some(
                    transaction_result(false)
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                ),
                true
            )
            .trust()
            .as_str(),
            "incomplete"
        );
        // Decodable and agreeing: this is what earns the label.
        assert_eq!(
            import(
                Some(
                    transaction_result(true)
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                ),
                true
            )
            .trust()
            .as_str(),
            "self_supplied"
        );
        // A failure claim backed by a failure result is equally backed.
        assert_eq!(
            import(
                Some(
                    transaction_result(false)
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                ),
                false
            )
            .trust()
            .as_str(),
            "self_supplied"
        );
        // Oversized input: `incomplete` here and a named resource violation from `record`.
        // This pins the end-to-end behavior, not the length comparison specifically — the XDR
        // reader would refuse this string too (see the note in `from_import`).
        let oversized = import(Some("A".repeat(MAX_XDR_BASE64_BYTES + 1)), true);
        assert_eq!(oversized.trust().as_str(), "incomplete");
        assert!(matches!(
            record(&oversized, RecordOptions::default()),
            Err(RecordError::ResourceLimit(ref m)) if m.contains("transaction result")
        ));

        // And a contradiction is still reported as one, not just weakly labeled.
        assert!(matches!(
            record(
                &import(
                    Some(
                        transaction_result(false)
                            .to_xdr_base64(Limits::none())
                            .unwrap()
                    ),
                    true
                ),
                RecordOptions::default()
            ),
            Err(RecordError::ResultMismatch(_))
        ));
    }

    /// The supplier's `successful` flag must agree with the transaction result it ships:
    /// an actually-failed transaction cannot be presented as a successful behavior
    /// example by flipping a boolean, in either direction, and an undecodable result
    /// supports no claim at all.
    #[test]
    fn imported_outcome_claims_must_match_the_supplied_result() {
        let envelope = envelope_with(vec![auth_entry(address_credentials(1))])
            .to_xdr_base64(Limits::none())
            .unwrap();
        let import = |result: &str, successful: bool| {
            EvidenceSnapshot::from_import(
                ozpb_domain::TESTNET_PASSPHRASE,
                envelope.clone(),
                None,
                Some(result.to_string()),
                None,
                None,
                successful,
            )
        };
        let failed_result = transaction_result(false)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let success_result = transaction_result(true)
            .to_xdr_base64(Limits::none())
            .unwrap();

        assert!(matches!(
            record(&import(&failed_result, true), RecordOptions::default()),
            Err(RecordError::ResultMismatch(_))
        ));
        assert!(matches!(
            record(
                &import(&success_result, false),
                RecordOptions {
                    allow_failed: true,
                    ..Default::default()
                },
            ),
            Err(RecordError::ResultMismatch(_))
        ));
        assert!(matches!(
            record(&import("not xdr", true), RecordOptions::default()),
            Err(RecordError::ResultMismatch(_))
        ));
        // And the agreeing pair records, including the failure-analysis direction.
        assert!(record(&import(&success_result, true), RecordOptions::default()).is_ok());
        assert!(record(
            &import(&failed_result, false),
            RecordOptions {
                allow_failed: true,
                ..Default::default()
            },
        )
        .is_ok());
    }

    // ----- raw/decoded coherence: verify() -----

    fn simulation_change() -> StateChange {
        let entry = stellar_xdr::LedgerEntry {
            last_modified_ledger_seq: 4_200_100,
            data: stellar_xdr::LedgerEntryData::ContractData(stellar_xdr::ContractDataEntry {
                ext: stellar_xdr::ExtensionPoint::V0,
                contract: ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
                    TOKEN_CID,
                ))),
                key: ScVal::U32(7),
                durability: stellar_xdr::ContractDataDurability::Persistent,
                val: ScVal::U32(42),
            }),
            ext: stellar_xdr::LedgerEntryExt::V0,
        };
        StateChange {
            kind: StateChangeKind::Created,
            entry: "contract_data".to_string(),
            contract: Some(format!("{}", stellar_strkey::Contract(TOKEN_CID))),
            source: StateChangeSource::Simulation,
            key_xdr_base64: Some(entry.to_key().to_xdr_base64(Limits::none()).unwrap()),
            before_xdr_base64: None,
            after_xdr_base64: Some(entry.to_xdr_base64(Limits::none()).unwrap()),
        }
    }

    fn snapshot_with_change(change: StateChange) -> EvidenceSnapshot {
        EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![],
            Some(4_200_101),
        )
        .with_simulated_state_changes(vec![change])
    }

    #[test]
    fn simulation_summary_is_derived_from_key_at_admission() {
        let good = simulation_change();
        record(
            &snapshot_with_change(good.clone()),
            RecordOptions::default(),
        )
        .unwrap();
        for mutate in [
            |change: &mut StateChange| change.entry = "account".to_string(),
            |change: &mut StateChange| {
                change.contract = Some(format!("{}", stellar_strkey::Contract(ACCOUNT_CID)));
            },
        ] {
            let mut changed = good.clone();
            mutate(&mut changed);
            assert!(matches!(
                record(&snapshot_with_change(changed), RecordOptions::default()),
                Err(RecordError::EvidenceIncoherent(_))
            ));
        }
    }

    #[test]
    fn simulation_summary_cannot_be_rewritten_after_recording() {
        let good = record(
            &snapshot_with_change(simulation_change()),
            RecordOptions::default(),
        )
        .unwrap();
        good.verify().unwrap();
        let mut forged = good;
        forged.state_changes[0].entry = "account".to_string();
        forged.state_changes[0].contract = None;
        assert!(forged.recording_hash().is_ok());
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(_))
        ));
    }

    #[test]
    fn simulation_raw_entries_and_change_shape_are_rechecked() {
        let good = record(
            &snapshot_with_change(simulation_change()),
            RecordOptions::default(),
        )
        .unwrap();
        let mut other = simulation_change();
        let mut other_entry = stellar_xdr::LedgerEntry::from_xdr_base64(
            other.after_xdr_base64.as_ref().unwrap(),
            Limits::none(),
        )
        .unwrap();
        if let stellar_xdr::LedgerEntryData::ContractData(data) = &mut other_entry.data {
            data.key = ScVal::U32(8);
        }
        other.after_xdr_base64 = Some(other_entry.to_xdr_base64(Limits::none()).unwrap());
        for bad in [
            StateChange {
                key_xdr_base64: None,
                ..simulation_change()
            },
            StateChange {
                key_xdr_base64: Some("AAAA".into()),
                ..simulation_change()
            },
            StateChange {
                after_xdr_base64: Some("AAAB".into()),
                ..simulation_change()
            },
            StateChange {
                kind: StateChangeKind::Updated,
                ..simulation_change()
            },
            StateChange {
                kind: StateChangeKind::State,
                ..simulation_change()
            },
            other,
        ] {
            let mut forged = good.clone();
            forged.state_changes[0] = bad.clone();
            assert!(
                matches!(forged.verify(), Err(RecordError::EvidenceIncoherent(_))),
                "forged change was accepted: {bad:?}"
            );
            assert!(matches!(
                record(&snapshot_with_change(bad), RecordOptions::default()),
                Err(RecordError::EvidenceIncoherent(_))
            ));
        }
    }

    #[test]
    fn recording_v2_checks_acquisition_metadata_without_inventing_history() {
        let snapshot = executed_snapshot().with_acquisition_protocol(MAX_ACQUISITION_PROTOCOL);
        let good = record(&snapshot, RecordOptions::default()).unwrap();
        assert!(good.acquisition.is_some());
        good.verify().unwrap();
        let absent = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert!(absent.acquisition.is_none());
        assert_ne!(
            good.recording_hash().unwrap(),
            absent.recording_hash().unwrap()
        );
        for protocol in [0, MAX_ACQUISITION_PROTOCOL + 1, u32::MAX] {
            assert!(record(
                &executed_snapshot().with_acquisition_protocol(protocol),
                RecordOptions::default()
            )
            .is_err());
            let mut forged = good.clone();
            forged.acquisition.as_mut().unwrap().protocol_version = protocol;
            assert!(matches!(
                forged.verify(),
                Err(RecordError::EvidenceIncoherent(_))
            ));
        }
        let mut forged = good.clone();
        forged.acquisition.as_mut().unwrap().decoder_version = "unknown decoder".to_string();
        assert!(forged.verify().is_err());
        let mut forged = good;
        forged.acquisition.as_mut().unwrap().decoder_xdr_revision = "unknown revision".to_string();
        assert!(forged.verify().is_err());
    }

    #[test]
    fn recording_v2_checks_optional_instance_lifetime_at_both_boundaries() {
        let mut observations = observed_executables();
        for observation in observations.values_mut() {
            observation.last_modified_ledger = Some(LedgerSeq(4_200_099));
            observation.live_until_ledger = Some(observation.observed_ledger);
        }
        let good = record(
            &executed_snapshot().with_contract_executables(observations.clone()),
            RecordOptions::default(),
        )
        .unwrap();
        good.verify().unwrap();
        let old = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_ne!(
            old.recording_hash().unwrap(),
            good.recording_hash().unwrap()
        );
        for future_modification in [true, false] {
            let mut forged = good.clone();
            let observation = forged.contract_executables.values_mut().next().unwrap();
            if future_modification {
                observation.last_modified_ledger =
                    Some(LedgerSeq(observation.observed_ledger.0 + 1));
            } else {
                observation.live_until_ledger = Some(LedgerSeq(observation.observed_ledger.0 - 1));
            }
            assert!(matches!(
                forged.verify(),
                Err(RecordError::EvidenceIncoherent(_))
            ));
            assert!(record(
                &executed_snapshot().with_contract_executables(forged.contract_executables),
                RecordOptions::default()
            )
            .is_err());
        }
    }

    #[test]
    fn recording_v2_fee_bump_results_bind_inner_envelope_and_outcome() {
        use stellar_xdr::{
            Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
            InnerTransactionResultResult, TransactionResultResult,
        };
        let inner = TransactionV1Envelope {
            tx: transaction_with(vec![auth_entry(address_credentials(1))]),
            signatures: Default::default(),
        };
        let network = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        let inner_envelope = TransactionEnvelope::Tx(inner.clone());
        let inner_hash = inner_envelope.hash(network.0 .0).unwrap();
        let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([8; 32])),
                fee: 1000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        });
        let TransactionResultResult::TxSuccess(operations) = transaction_result(true).result else {
            unreachable!()
        };
        let pair = InnerTransactionResultPair {
            transaction_hash: Hash(inner_hash),
            result: InnerTransactionResult {
                fee_charged: 100,
                result: InnerTransactionResultResult::TxSuccess(operations),
                ext: InnerTransactionResultExt::V0,
            },
        };
        let mut good = transaction_result(true);
        good.result = TransactionResultResult::TxFeeBumpInnerSuccess(pair.clone());
        verify_transaction_result(&envelope, &good, Execution::ExecutedSuccess, network).unwrap();
        let snapshot = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        )
        .with_rpc_result(good.to_xdr_base64(Limits::none()).unwrap());
        record(&snapshot, RecordOptions::default())
            .unwrap()
            .verify()
            .unwrap();
        assert!(verify_transaction_result(
            &inner_envelope,
            &good,
            Execution::ExecutedSuccess,
            network
        )
        .is_err());
        assert!(verify_transaction_result(
            &envelope,
            &transaction_result(true),
            Execution::ExecutedSuccess,
            network
        )
        .is_err());
        let mut wrong_hash = pair.clone();
        wrong_hash.transaction_hash = Hash([7; 32]);
        let mut wrong_inner = pair.clone();
        wrong_inner.result.result = InnerTransactionResultResult::TxBadSeq;
        for result in [
            TransactionResultResult::TxFeeBumpInnerSuccess(wrong_hash),
            TransactionResultResult::TxFeeBumpInnerSuccess(wrong_inner),
            TransactionResultResult::TxFeeBumpInnerFailed(pair),
        ] {
            let mut forged = good.clone();
            forged.result = result;
            assert!(matches!(
                verify_transaction_result(&envelope, &forged, Execution::ExecutedSuccess, network),
                Err(RecordError::ResultMismatch(_))
            ));
        }
    }

    #[test]
    fn raw_import_and_serialized_recording_reject_classic_result_contradictions() {
        use stellar_xdr::{
            Asset, OperationResult, OperationResultTr, PaymentOp, PaymentResult,
            TransactionResultResult,
        };
        let mut envelope = envelope_with(vec![auth_entry(address_credentials(1))]);
        let TransactionEnvelope::Tx(ref mut tx) = envelope else {
            unreachable!()
        };
        let mut operations = tx.tx.operations.to_vec();
        operations.push(Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256([3; 32])),
                asset: Asset::Native,
                amount: 1,
            }),
        });
        tx.tx.operations = operations.try_into().unwrap();
        let TransactionResultResult::TxSuccess(invoke) = transaction_result(true).result else {
            unreachable!()
        };
        let invoke = invoke[0].clone();
        let result_for = |results: Vec<OperationResult>| {
            let mut result = transaction_result(true);
            result.result = TransactionResultResult::TxSuccess(results.try_into().unwrap());
            result.to_xdr_base64(Limits::none()).unwrap()
        };
        let snapshot_for = |result: String| {
            EvidenceSnapshot::from_import(
                ozpb_domain::TESTNET_PASSPHRASE,
                envelope.to_xdr_base64(Limits::none()).unwrap(),
                None,
                Some(result),
                Some(1),
                Some(1),
                true,
            )
        };
        let good = record(
            &snapshot_for(result_for(vec![
                invoke.clone(),
                OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::Success)),
            ])),
            RecordOptions::default(),
        )
        .unwrap();
        good.verify().unwrap();
        for operations in [
            vec![
                invoke.clone(),
                OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::Underfunded)),
            ],
            vec![invoke.clone(), invoke.clone()],
            vec![invoke],
        ] {
            let result = result_for(operations);
            assert!(matches!(
                record(&snapshot_for(result.clone()), RecordOptions::default()),
                Err(RecordError::ResultMismatch(_))
            ));
            let mut forged = good.clone();
            forged.raw.result_xdr_base64 = Some(result);
            assert!(matches!(
                forged.verify(),
                Err(RecordError::ResultMismatch(_))
            ));
        }
    }

    #[test]
    fn a_failed_result_requires_an_operation_that_failed() {
        use stellar_xdr::TransactionResultResult;
        let envelope = envelope_with(vec![auth_entry(address_credentials(1))]);
        let network = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        verify_transaction_result(
            &envelope,
            &transaction_result(false),
            Execution::ExecutedFailed,
            network,
        )
        .unwrap();
        let TransactionResultResult::TxSuccess(successes) = transaction_result(true).result else {
            unreachable!()
        };
        for operations in [successes, Default::default()] {
            let mut result = transaction_result(false);
            result.result = TransactionResultResult::TxFailed(operations);
            assert!(matches!(
                verify_transaction_result(&envelope, &result, Execution::ExecutedFailed, network),
                Err(RecordError::ResultMismatch(_))
            ));
        }
    }

    #[test]
    fn every_operation_failure_code_is_refused_inside_success() {
        use stellar_xdr::{OperationResult, OperationResultTr};
        for kind in OperationResultTr::VARIANTS {
            let bytes = [
                0_i32.to_be_bytes(),
                (kind as i32).to_be_bytes(),
                (-1_i32).to_be_bytes(),
            ]
            .concat();
            let failure = OperationResult::from_xdr(&bytes, Limits::none()).unwrap();
            assert!(
                !operation_succeeded(&failure),
                "failure accepted for {kind:?}"
            );
        }
    }

    #[test]
    fn recording_v2_checks_result_arity_operation_kind_and_classic_failure() {
        use stellar_xdr::{
            BumpSequenceOp, BumpSequenceResult, Operation, OperationResult, OperationResultTr,
            SequenceNumber, TransactionResultResult,
        };
        let mut envelope = envelope_with(vec![auth_entry(address_credentials(1))]);
        let TransactionEnvelope::Tx(ref mut tx) = envelope else {
            unreachable!()
        };
        let mut operations = tx.tx.operations.to_vec();
        operations.push(Operation {
            source_account: None,
            body: OperationBody::BumpSequence(BumpSequenceOp {
                bump_to: SequenceNumber(5),
            }),
        });
        tx.tx.operations = operations.try_into().unwrap();
        let invoke = match transaction_result(true).result {
            TransactionResultResult::TxSuccess(results) => results[0].clone(),
            _ => unreachable!(),
        };
        let good_classic =
            OperationResult::OpInner(OperationResultTr::BumpSequence(BumpSequenceResult::Success));
        let result_for = |results: Vec<OperationResult>| {
            let mut result = transaction_result(true);
            result.result = TransactionResultResult::TxSuccess(results.try_into().unwrap());
            result
        };
        let network = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        verify_transaction_result(
            &envelope,
            &result_for(vec![invoke.clone(), good_classic.clone()]),
            Execution::ExecutedSuccess,
            network,
        )
        .unwrap();
        for operations in [
            vec![invoke.clone()],
            vec![invoke.clone(), invoke.clone()],
            vec![
                invoke,
                OperationResult::OpInner(OperationResultTr::BumpSequence(
                    BumpSequenceResult::BadSeq,
                )),
            ],
        ] {
            assert!(matches!(
                verify_transaction_result(
                    &envelope,
                    &result_for(operations),
                    Execution::ExecutedSuccess,
                    network
                ),
                Err(RecordError::ResultMismatch(_))
            ));
        }
    }

    #[test]
    fn recording_v2_refuses_legacy_artifacts_without_inventing_evidence() {
        let mut bundle = record(&imported_snapshot(true), RecordOptions::default()).unwrap();
        bundle.schema = "recording/v1".to_string();
        assert!(matches!(
            bundle.verify(),
            Err(RecordError::EvidenceIncoherent(_))
        ));
    }

    #[test]
    fn recording_v2_result_presence_matches_execution_shape() {
        let simulation = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![],
            Some(1),
        );
        let mut bundle = record(&simulation, RecordOptions::default()).unwrap();
        bundle.raw.result_xdr_base64 = Some(transaction_result_base64(true));
        assert!(bundle.verify().is_err());
        assert!(record(
            &simulation.with_rpc_result(transaction_result_base64(true)),
            RecordOptions::default()
        )
        .is_err());
        let mut executed = record(&imported_snapshot(true), RecordOptions::default()).unwrap();
        executed.raw.result_xdr_base64 = None;
        assert!(executed.verify().is_err());
        executed.trust = TrustLevel::incomplete();
        executed.verify().unwrap();
    }

    #[test]
    fn recording_v2_missing_result_cannot_gain_synthesis_eligibility() {
        let mut bundle = record(&imported_snapshot(false), RecordOptions::default()).unwrap();
        assert_eq!(bundle.trust.as_str(), "incomplete");
        bundle.verify().unwrap();
        bundle.trust = TrustLevel::self_supplied();
        assert!(matches!(
            bundle.verify(),
            Err(RecordError::EvidenceIncoherent(_))
        ));
    }

    #[test]
    fn recording_v2_rechecks_the_recorded_execution_outcome() {
        let snapshot = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap()),
            Some(transaction_result_base64(false)),
            Some(1),
            Some(1),
            false,
        );
        let mut bundle = record(
            &snapshot,
            RecordOptions {
                allow_failed: true,
                ..Default::default()
            },
        )
        .unwrap();
        bundle.verify().unwrap();
        bundle.execution = Execution::ExecutedSuccess;
        assert!(matches!(
            bundle.verify(),
            Err(RecordError::ResultMismatch(_))
        ));
    }

    #[test]
    fn recordings_straight_from_record_verify() {
        // Executed, with meta, movements, state and executables.
        let executed = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(
            executed.verify().unwrap(),
            executed.recording_hash().unwrap()
        );

        // Simulated, auth from the record-mode response.
        let sim_entry = auth_entry(address_credentials(7));
        let sim = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![sim_entry.to_xdr_base64(Limits::none()).unwrap()],
            Some(4_200_101),
        )
        .with_simulated_state_changes(vec![simulation_change()]);
        let simulated = record(&sim, RecordOptions::default()).unwrap();
        simulated.verify().unwrap();

        // The synthesis JSON boundary downgrades trust before use; a downgraded label is
        // an acquisition claim and must not break coherence.
        let mut downgraded = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        downgraded.trust = ozpb_domain::TrustLevel::self_supplied();
        downgraded.verify().unwrap();
    }

    /// The audit reproduction: edit decoded views, schema or version while leaving the
    /// raw evidence untouched. The bundle still serializes and hashes (identity), but
    /// verification must refuse every mutation — hashing an edited, contradictory object
    /// proves it has a stable name, not that its views agree with its evidence.
    #[test]
    fn edited_decoded_views_fail_verification_even_though_they_still_hash() {
        let good = record(&executed_snapshot(), RecordOptions::default()).unwrap();

        let mut forged = good.clone();
        forged.schema = "attacker/schema".to_string();
        assert!(forged.recording_hash().is_ok(), "identity is not coherence");
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(_))
        ));

        let mut forged = good.clone();
        forged.canonicalization_version = u32::MAX;
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(_))
        ));

        // The decoded rule a policy would be derived from.
        let mut forged = good.clone();
        let AuthorizedCall::Contract { fn_name, .. } = &mut forged.authorizations[0].root.call
        else {
            panic!("fixture records a contract call");
        };
        *fn_name = "drain_everything".to_string();
        assert!(forged.recording_hash().is_ok());
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("authorizations")
        ));

        // Explanatory evidence must also be derived, not asserted.
        let mut forged = good.clone();
        forged.token_movements.clear();
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("token_movements")
        ));

        let mut forged = good.clone();
        forged.evidence_notes.push("looks legit".to_string());
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("evidence_notes")
        ));

        // A meta-sourced state change nothing in the meta produced.
        let mut forged = good.clone();
        forged.state_changes.push(StateChange {
            kind: StateChangeKind::Removed,
            entry: "contract_data".to_string(),
            contract: None,
            source: StateChangeSource::Operation,
            key_xdr_base64: None,
            before_xdr_base64: None,
            after_xdr_base64: None,
        });
        assert!(matches!(
            forged.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("state_changes")
        ));

        // An operation index the envelope does not have.
        let mut forged = good.clone();
        forged.operation_index = 5;
        assert!(forged.verify().is_err());

        // And the untouched original still verifies.
        good.verify().unwrap();
    }

    /// Whatever `record` accepts, `verify` must accept: an admission path that mints a
    /// recording its own verification rejects would make the two disagree about what a
    /// valid artifact is. Simulated state on executed evidence is the pair that could,
    /// since the public API can attach it.
    #[test]
    fn record_cannot_mint_a_recording_verify_would_reject() {
        let simulated_state = vec![simulation_change()];
        let snapshot = executed_snapshot().with_simulated_state_changes(simulated_state.clone());
        assert!(
            matches!(
                record(&snapshot, RecordOptions::default()),
                Err(RecordError::EvidenceIncoherent(ref m)) if m.contains("simulation-sourced")
            ),
            "executed acquisition must not accept simulated state: {:?}",
            record(&snapshot, RecordOptions::default())
        );

        // The same evidence acquired by simulation is exactly what that field is for.
        let simulated = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![],
            Some(4_200_101),
        )
        .with_simulated_state_changes(simulated_state);
        let bundle = record(&simulated, RecordOptions::default()).unwrap();
        assert_eq!(bundle.state_changes.len(), 1);
        bundle.verify().unwrap();

        // The mirror case: a simulated snapshot whose attached change claims a meta section
        // as its source. `verify` rebuilds from simulation-sourced changes only, so such an
        // entry cannot survive a rebuild — admission must refuse it rather than mint a
        // recording that fails its own verification.
        let mislabeled = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![],
            Some(4_200_101),
        )
        .with_simulated_state_changes(vec![StateChange {
            kind: StateChangeKind::Updated,
            entry: "contract_data".to_string(),
            contract: None,
            source: StateChangeSource::Operation,
            key_xdr_base64: None,
            before_xdr_base64: None,
            after_xdr_base64: None,
        }]);
        assert!(
            matches!(
                record(&mislabeled, RecordOptions::default()),
                Err(RecordError::EvidenceIncoherent(ref m)) if m.contains("simulation")
            ),
            "a simulated snapshot must not attach meta-sourced changes: {:?}",
            record(&mislabeled, RecordOptions::default())
        );

        // And the shape verify() must reject for a hand-edited artifact, which is what made
        // minting it a contradiction rather than merely untidy. The message names the shape
        // and the offending source rather than reporting a bare divergence.
        let mut edited = record(&simulated, RecordOptions::default()).unwrap();
        edited.state_changes[0].source = StateChangeSource::Operation;
        assert!(
            matches!(
                edited.verify(),
                Err(RecordError::EvidenceIncoherent(ref m))
                    if m.contains("no meta sections") && m.contains("Operation")
            ),
            "expected a named shape violation: {:?}",
            edited.verify()
        );
    }

    /// Raw-evidence shapes no acquisition path can mint are refused even though decoding
    /// would silently ignore the extraneous half.
    #[test]
    fn unmintable_raw_shapes_fail_verification() {
        let mut executed = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        executed.raw.simulated_auth_xdr_base64.push(
            auth_entry(address_credentials(1))
                .to_xdr_base64(Limits::none())
                .unwrap(),
        );
        assert!(matches!(
            executed.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("simulated authorization")
        ));

        let mut executed = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        executed.state_changes.push(StateChange {
            kind: StateChangeKind::Updated,
            entry: "simulation_xdr".to_string(),
            contract: None,
            source: StateChangeSource::Simulation,
            key_xdr_base64: Some("AAAA".to_string()),
            before_xdr_base64: None,
            after_xdr_base64: Some("AAAB".to_string()),
        });
        assert!(
            matches!(
                executed.verify(),
                Err(RecordError::EvidenceIncoherent(ref m)) if m.contains("simulation-sourced")
            ),
            "injected simulation evidence on an executed recording must be refused: {:?}",
            executed.verify()
        );

        let sim = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![],
            Some(4_200_101),
        );
        let mut simulated = record(&sim, RecordOptions::default()).unwrap();
        simulated.raw.result_meta_xdr_base64 =
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap());
        assert!(matches!(
            simulated.verify(),
            Err(RecordError::EvidenceIncoherent(m)) if m.contains("result meta")
        ));

        // The mirror shape, named as a shape violation rather than reached as a generic
        // divergence: a simulation has no meta sections for a change to have come from.
        let mut simulated = record(&sim, RecordOptions::default()).unwrap();
        simulated.state_changes.push(StateChange {
            kind: StateChangeKind::Updated,
            entry: "contract_data".to_string(),
            contract: None,
            source: StateChangeSource::TxChangesAfter,
            key_xdr_base64: None,
            before_xdr_base64: None,
            after_xdr_base64: None,
        });
        assert!(
            matches!(
                simulated.verify(),
                Err(RecordError::EvidenceIncoherent(ref m))
                    if m.contains("no meta sections") && m.contains("TxChangesAfter")
            ),
            "the error must name the shape and the offending source: {:?}",
            simulated.verify()
        );
    }

    // ----- symbol fidelity and token-event shape (evidence, never guessed) -----

    fn snapshot_with_event(event: ContractEvent) -> EvidenceSnapshot {
        use stellar_xdr::{SorobanTransactionMeta, TransactionMetaV3};
        let meta = TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![event].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        });
        EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        )
    }

    /// The host validates symbol bytes ([A-Za-z0-9_]), so genuine network evidence never
    /// carries anything else; self-supplied raw XDR can. Lossy replacement would collapse
    /// distinct raw values into one decoded name, so authorization facts must fail closed.
    #[test]
    fn invalid_symbol_bytes_in_authorized_calls_fail_closed() {
        use stellar_xdr::{InvokeContractArgs, ScSymbol};
        // 0xFF cannot appear in a symbol (and is not valid UTF-8 either).
        let entry = SorobanAuthorizationEntry {
            credentials: address_credentials(1),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: token_sc(),
                    function_name: ScSymbol(vec![b't', 0xFF, b'x'].try_into().unwrap()),
                    args: Default::default(),
                }),
                sub_invocations: Default::default(),
            },
        };
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![entry])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            true,
        );
        assert!(matches!(
            record(&snap, RecordOptions::default()),
            Err(RecordError::AuthParse(_))
        ));

        // A dash is valid UTF-8 but not a valid symbol character: lossy decoding passes
        // it through untouched, minting a name the host could never have produced.
        let mut invocation = transfer_invocation();
        let SorobanAuthorizedFunction::ContractFn(args) = &mut invocation.function else {
            unreachable!()
        };
        args.args = vec![ScVal::Symbol(ScSymbol(
            "not-a-symbol".as_bytes().try_into().unwrap(),
        ))]
        .try_into()
        .unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: address_credentials(1),
            root_invocation: invocation,
        };
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![entry])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            true,
        );
        assert!(matches!(
            record(&snap, RecordOptions::default()),
            Err(RecordError::AuthParse(_))
        ));
    }

    #[test]
    fn mint_and_burn_events_are_recorded_with_their_required_fields() {
        use stellar_xdr::{ContractEventType, ContractEventV0, ContractId, Hash, ScSymbol};
        let event = |kind: &str, addr: ScAddress| ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash(TOKEN_CID))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol(kind.as_bytes().try_into().unwrap())),
                    ScVal::Address(addr),
                ]
                .try_into()
                .unwrap(),
                data: i128_val(AMOUNT),
            }),
        };

        let b = record(
            &snapshot_with_event(event("mint", merchant_sc())),
            RecordOptions::default(),
        )
        .unwrap();
        assert_eq!(b.token_movements.len(), 1);
        let m = &b.token_movements[0];
        assert_eq!(m.kind, MovementKind::Mint);
        assert_eq!(m.from, None);
        assert_eq!(
            m.to.as_deref(),
            Some(format!("{}", stellar_strkey::ed25519::PublicKey(MERCHANT_KEY)).as_str())
        );
        assert_eq!(m.amount, Some(AMOUNT));

        let b = record(
            &snapshot_with_event(event("burn", account_sc())),
            RecordOptions::default(),
        )
        .unwrap();
        assert_eq!(b.token_movements.len(), 1);
        let m = &b.token_movements[0];
        assert_eq!(m.kind, MovementKind::Burn);
        assert_eq!(
            m.from.as_deref(),
            Some(format!("{}", stellar_strkey::Contract(ACCOUNT_CID)).as_str())
        );
        assert_eq!(m.to, None);
        assert_eq!(m.amount, Some(AMOUNT));
    }

    /// Token events are Contract events; a System event with transfer-shaped topics is a
    /// look-alike the host would never emit for a token and must stay an unattributed note.
    #[test]
    fn non_contract_events_are_never_typed_as_movements() {
        let mut event = transfer_event();
        event.type_ = stellar_xdr::ContractEventType::System;
        let b = record(&snapshot_with_event(event), RecordOptions::default()).unwrap();
        assert!(
            b.token_movements.is_empty(),
            "a System event must not be typed as a token movement: {:?}",
            b.token_movements
        );
        assert_eq!(b.evidence_notes.len(), 1);
    }

    #[test]
    fn events_without_a_contract_id_are_notes_not_movements() {
        let mut event = transfer_event();
        event.contract_id = None;
        let b = record(&snapshot_with_event(event), RecordOptions::default()).unwrap();
        assert!(b.token_movements.is_empty());
        assert_eq!(b.evidence_notes.len(), 1);
    }

    #[test]
    fn transfer_events_missing_counterparty_or_amount_are_notes_not_movements() {
        use stellar_xdr::ScSymbol;
        // Missing `to` topic.
        let mut event = transfer_event();
        let ContractEventBody::V0(v0) = &mut event.body;
        v0.topics = vec![
            ScVal::Symbol(ScSymbol("transfer".as_bytes().try_into().unwrap())),
            ScVal::Address(account_sc()),
        ]
        .try_into()
        .unwrap();
        let b = record(&snapshot_with_event(event), RecordOptions::default()).unwrap();
        assert!(b.token_movements.is_empty());
        assert_eq!(b.evidence_notes.len(), 1);

        // Data that carries no decodable amount.
        let mut event = transfer_event();
        let ContractEventBody::V0(v0) = &mut event.body;
        v0.data = ScVal::Void;
        let b = record(&snapshot_with_event(event), RecordOptions::default()).unwrap();
        assert!(b.token_movements.is_empty());
        assert_eq!(b.evidence_notes.len(), 1);
    }

    /// An event whose kind topic is not even a valid symbol is malformed, not a movement.
    #[test]
    fn malformed_kind_topics_are_notes_not_movements() {
        use stellar_xdr::ScSymbol;
        let mut event = transfer_event();
        let ContractEventBody::V0(v0) = &mut event.body;
        let mut topics: Vec<ScVal> = v0.topics.iter().cloned().collect();
        topics[0] = ScVal::Symbol(ScSymbol(vec![b't', 0xFF].try_into().unwrap()));
        v0.topics = topics.try_into().unwrap();
        let b = record(&snapshot_with_event(event), RecordOptions::default()).unwrap();
        assert!(b.token_movements.is_empty());
        assert_eq!(b.evidence_notes.len(), 1);
    }

    #[test]
    fn sub_invocation_trees_are_preserved() {
        let mut root = transfer_invocation();
        root.sub_invocations = vec![transfer_invocation()].try_into().unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: address_credentials(1),
            root_invocation: root,
        };
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![entry])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.authorizations[0].root.sub_invocations.len(), 1);
    }
}
