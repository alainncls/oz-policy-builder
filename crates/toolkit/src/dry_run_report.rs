//! The pure half of a dry-run coordinator: the native worker's wire types, the identities a
//! coordinator derives for itself before it runs that worker, and the assembler that turns a
//! preparation plus worker reports into one four-layer report.
//!
//! Nothing here runs a process, reads a file, holds a key or signs. The shell that runs the
//! worker hands its raw frames and exit status here. Every worker binding is re-checked against
//! the preparation and against identities derived here from the same request; agreement is
//! recomputed from the preparation's reference expectations; and a layer that did not run, or
//! whose report was refused, is never reported as passed.

use ozpb_api_types::{
    DryRunAcceptance, DryRunCaseResult, DryRunControlResult, DryRunEnforcer, DryRunInput,
    DryRunLayer, DryRunLayerAcceptance, DryRunLayerExecution, DryRunLayerId as Layer,
    DryRunLayerStatus as Status, DryRunOutput, DryRunStatefulResult,
};
use ozpb_domain::{
    canonical_hash, canonical_hash_of, domains, pinned_upstream::OZ_SMART_ACCOUNT_WASM, NetworkId,
    TargetCapture,
};
use ozpb_harness::{Case, EvidenceReport, MutationClass};
use ozpb_policy_spec::{PolicyRef, PolicySpec, PredicateKind, SignerSpec, StateSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{Limits, ReadXdr, ScString, ScVal};

/// The host the worker pins; a report naming another host is refused.
pub const HOST_VERSION: &str = "soroban-env-host/29.0.1";
/// The source protocol the worker accepts.
pub const SOURCE_PROTOCOL_VERSION: u32 = 29;
/// The candidate's rule ID inside the worker's fresh local installation.
pub const LOCAL_RULE_ID: u32 = 1;
/// Delegate signatures expire this many ledgers after the case ledger.
pub const SIGNATURE_WINDOW: u32 = 64;
/// Fewest derived denials one executed layer must revert for the report to meet the bar.
pub const REQUIRED_REVERTED_DENIALS: usize = 5;
/// The first delegate nonce; each later request takes the next one.
pub const FIRST_DELEGATE_NONCE: i64 = 1001;
const NATIVE_PROVENANCE: &str = "fresh_local_candidate_boundary_states; counter seeds and ledgers \
                                 are synthetic; no wallet ownership or live state claim";
const CAPTURED_PROVENANCE: &str = "rpc_reported target entries with outer LedgerEntry extension \
                                   reconstructed as V0; fresh local candidate installation and \
                                   synthetic counter seed; offline execution network; no owner \
                                   authority, fee, reserve or live-network claim";
const NATIVE_INITIALIZATION_PROVENANCE: &str = "fresh_local_candidate_boundary_states";
const STORAGE_MODE: &str = "strict_snapshot_source";
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";
/// The account's `UnvalidatedContext` and `UnauthorizedSigner` errors.
const ACCOUNT_UNVALIDATED_CONTEXT: u32 = 3002;
const ACCOUNT_UNAUTHORIZED_SIGNER: u32 = 3016;
/// The account-Wasm layer's cryptographic controls and the diagnostic stage each must hit.
pub const NATIVE_CONTROLS: [(&str, &str); 5] = [
    ("signature_bit", "failed account authentication"),
    ("nonce_binding", "failed account authentication"),
    ("payload_binding", "Unauthorized function call"),
    ("context_rule_binding", "Unauthorized function call"),
    ("nonce_replay", "nonce already exists for address"),
];
/// The captured-target layer's three cases, in order.
pub const CAPTURED_CASE_IDS: [&str; 3] = [
    "target:original:0",
    "target:argument-denial:0",
    "target:empty-signers:0",
];

/// The worker's offline binding: every identity its counterfactual network ID commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineBinding {
    pub run_hash: String,
    pub job_hash: String,
    pub suite_hash: String,
    pub state_hash: String,
    pub source_network_id: String,
    pub source_protocol_version: u32,
    pub source_ledger: u32,
    pub account_address: String,
    pub delegate_address: String,
}

/// The ledger parameters a native job runs under. Decimal text keeps the timestamp exact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLedger {
    pub protocol_version: u32,
    pub sequence: u32,
    pub timestamp: String,
    pub base_reserve: u32,
    pub min_temp_entry_ttl: u32,
    pub min_persistent_entry_ttl: u32,
    pub max_entry_ttl: u32,
}

/// The worker's start frame for the account-Wasm layer, field for field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeJob {
    pub schema: u32,
    pub request: DryRunInput,
    pub account_wasm_base64: String,
    pub ledger: SourceLedger,
}

/// The worker's start frame for the captured-target layer, field for field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedTargetJob {
    pub schema: u32,
    pub native: NativeJob,
    pub capture: TargetCapture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePreparedFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub schema: u32,
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub account_code_hash: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub local_rule_id: u32,
    pub candidate_context_rule_id: u32,
    pub boundary_cases: usize,
    pub signature_expiration_ledgers: BTreeSet<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeResultFrame {
    #[serde(rename = "type")]
    frame_type: String,
    schema: u32,
    binding: OfflineBinding,
    execution_network_id: String,
    account_code_hash: String,
    policy_address: String,
    policy_code_hash: String,
    host_version: String,
    local_rule_id: u32,
    candidate_context_rule_id: u32,
    provenance: String,
    cases: Vec<NativeCase>,
    controls: Vec<NativeControl>,
    stateful: Option<NativeStateful>,
    required_classes: BTreeSet<MutationClass>,
    passed: bool,
    complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCase {
    case_id: String,
    label: String,
    class: MutationClass,
    expected_permit: bool,
    permitted: bool,
    agree: bool,
    refusal_contract: Option<String>,
    refusal_code: Option<u32>,
    state_before_hash: String,
    state_after_hash: String,
    state_changed: bool,
    ledger: u32,
    counter_seed: Option<u32>,
    counter_before: Option<u32>,
    counter_after: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeControl {
    name: String,
    passed: bool,
    refusal_stage: String,
    state_before_hash: String,
    state_after_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStateful {
    successful_calls: u32,
    counter_before: u32,
    counter_after: u32,
    overflow_refused: bool,
    overflow_rolled_back: bool,
    partial_rollback_refused: bool,
    partial_rollback_preserved_counter: bool,
    passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedPreparedFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub schema: u32,
    pub layer: String,
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub account_code_hash: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub local_rule_id: u32,
    pub candidate_context_rule_id: u32,
    pub capture_hash: String,
    pub candidate_state_hash: String,
    pub target_contract: String,
    pub observed_ledger: u32,
    pub case_ids: Vec<String>,
    pub signing_case_ids: Vec<String>,
    pub signature_expiration_ledgers: BTreeSet<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedResultFrame {
    #[serde(rename = "type")]
    frame_type: String,
    schema: u32,
    layer: String,
    binding: OfflineBinding,
    execution_network_id: String,
    capture_hash: String,
    candidate_state_hash: String,
    capture_provenance: String,
    observed_ledger: u32,
    target_contract: String,
    account_code_hash: String,
    policy_address: String,
    policy_code_hash: String,
    host_version: String,
    local_rule_id: u32,
    candidate_context_rule_id: u32,
    storage_mode: String,
    provenance: String,
    cases: Vec<CapturedCase>,
    passed: bool,
    complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedCase {
    case_id: String,
    label: String,
    class: MutationClass,
    expected_permit: bool,
    permitted: bool,
    agree: bool,
    refusal_contract: Option<String>,
    refusal_code: Option<u32>,
    host_error: Option<String>,
    state_before_hash: String,
    state_after_hash: String,
    sender_delta: String,
    recipient_delta: String,
    counter_seed: Option<u32>,
    counter_before: Option<u32>,
    counter_after: Option<u32>,
    // Parsed so the frame is held to its exact shape. The worker classifies these key sets;
    // anything outside the expected change is in `unexpected_changes`, which is checked.
    #[allow(dead_code)]
    captured_reads: Vec<String>,
    #[allow(dead_code)]
    created_keys: Vec<String>,
    #[allow(dead_code)]
    written_keys: Vec<String>,
    #[allow(dead_code)]
    ttl_extended_keys: Vec<String>,
    undeclared_reads: Vec<String>,
    unexpected_changes: Vec<String>,
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Network IDs an offline execution domain must never equal: the run's source network and the
/// public, test and future networks.
pub fn live_network_ids(source_network_id: &str) -> [String; 4] {
    [
        source_network_id.to_string(),
        NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
            .0
            .to_hex(),
        NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE)
            .0
            .to_hex(),
        NetworkId::from_passphrase(FUTURENET_PASSPHRASE).0.to_hex(),
    ]
}

/// The counterfactual network ID the worker executes and asks signatures in, derived here
/// independently from its binding with the fixed public ScVal vector. Refuses a binding that
/// is not canonical, and a result equal to any live network ID.
pub fn offline_execution_network_id(binding: &OfflineBinding) -> Result<String, &'static str> {
    if binding.source_protocol_version != SOURCE_PROTOCOL_VERSION || binding.source_ledger == 0 {
        return Err("unsupported source protocol or ledger");
    }
    let hashes = [
        &binding.run_hash,
        &binding.job_hash,
        &binding.suite_hash,
        &binding.state_hash,
        &binding.source_network_id,
    ];
    if hashes.iter().any(|value| !is_hash(value)) {
        return Err("noncanonical binding hash");
    }
    let account = stellar_strkey::Contract::from_string(&binding.account_address)
        .map_err(|_| "account must be a contract address")?;
    let delegate = stellar_strkey::ed25519::PublicKey::from_string(&binding.delegate_address)
        .map_err(|_| "delegate must be an Ed25519 account")?;
    if account.to_string().as_str() != binding.account_address
        || delegate.to_string().as_str() != binding.delegate_address
    {
        return Err("noncanonical address");
    }
    let text = |value: &str| -> Result<ScVal, &'static str> {
        Ok(ScVal::String(ScString(
            value.try_into().map_err(|_| "string too long")?,
        )))
    };
    let mut values = Vec::with_capacity(9);
    for value in hashes {
        values.push(text(value)?);
    }
    values.push(ScVal::U32(binding.source_protocol_version));
    values.push(ScVal::U32(binding.source_ledger));
    values.push(text(&binding.account_address)?);
    values.push(text(&binding.delegate_address)?);
    let payload = ScVal::Vec(Some(
        values.try_into().map_err(|_| "domain vector too long")?,
    ));
    let network = canonical_hash_of(domains::OFFLINE_EXECUTION, payload)
        .map_err(|_| "offline domain encoding failed")?
        .to_hex();
    if live_network_ids(&binding.source_network_id).contains(&network) {
        return Err("offline execution domain equals a live network");
    }
    Ok(network)
}

/// The checks the worker applies to its ledger, applied before it is started.
pub fn check_source_ledger(ledger: &SourceLedger) -> Result<(), &'static str> {
    let canonical_timestamp = ledger
        .timestamp
        .parse::<u64>()
        .is_ok_and(|t| t.to_string() == ledger.timestamp);
    if ledger.protocol_version != SOURCE_PROTOCOL_VERSION
        || ledger.sequence == 0
        || !canonical_timestamp
        || ledger.base_reserve == 0
        || ledger.max_entry_ttl == 0
        || ledger.min_temp_entry_ttl == 0
        || ledger.min_persistent_entry_ttl == 0
        || ledger.min_temp_entry_ttl > ledger.max_entry_ttl
        || ledger.min_persistent_entry_ttl > ledger.max_entry_ttl
    {
        return Err("source ledger is not a protocol-29 ledger with consistent TTL bounds");
    }
    Ok(())
}

/// The selected rule's shape inside the native worker's scope, read from the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeScope {
    pub delegate_address: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub target_contract: String,
    pub max_calls: Option<u32>,
}

/// The worker's size bounds: the specification, every rule's calls and arguments, the selected
/// rule's derived cases and its call cap.
const MAX_SPEC_BYTES: usize = 64 * 1024;
const MAX_CALLS_PER_RULE: usize = 8;
const MAX_ARGS_PER_CALL: usize = 16;
const MAX_DERIVED_CASES: usize = 256;
const MAX_CALL_CAP: u32 = 512;

/// Whether the selected rule is one the native worker can run, applying every scope check the
/// worker applies before execution: its size bounds, one explicit delegated G signer, a
/// supported predicate, exactly one generated policy with exactly one binding, a derived suite
/// of at most 256 cases covering its required classes, and a call cap of at most 512. The worker
/// re-checks all of this; asking first keeps an out-of-scope rule `unsupported` rather than a
/// failed run, without reading a key, and names the delegate whose key the coordinator must hold.
pub fn native_scope(input: &DryRunInput) -> Result<NativeScope, &'static str> {
    scoped(input).map(|(scope, _)| scope)
}

fn scoped(input: &DryRunInput) -> Result<(NativeScope, Vec<Case>), &'static str> {
    let spec: PolicySpec = serde_json::from_value(input.candidate.spec.clone())
        .map_err(|_| "the candidate spec does not parse")?;
    let rule_index = input.candidate.rule_index;
    if rule_index >= spec.rules.len() {
        return Err("the selected rule index is outside the spec");
    }
    if serde_json::to_vec(&spec).map_or(true, |bytes| bytes.len() > MAX_SPEC_BYTES)
        || spec.rules.iter().any(|rule| {
            rule.allowed_calls.len() > MAX_CALLS_PER_RULE
                || rule
                    .allowed_calls
                    .iter()
                    .any(|call| call.args.len() > MAX_ARGS_PER_CALL)
        })
    {
        return Err("the spec exceeds the native worker's size bounds");
    }
    let spec = spec
        .validate()
        .map_err(|_| "the candidate spec does not validate")?;
    let rule = &spec.spec().rules[rule_index];
    let [SignerSpec::Delegated { address }] = rule.authorization.signers.as_slice() else {
        return Err("the selected rule does not have exactly one delegated signer");
    };
    if stellar_strkey::ed25519::PublicKey::from_string(address)
        .map_or(true, |key| key.to_string().as_str() != address.as_str())
    {
        return Err("the native worker requires one canonical Ed25519 delegated address");
    }
    if !matches!(
        rule.authorization.kind,
        PredicateKind::AnyOf | PredicateKind::AllOf | PredicateKind::Threshold { n: 1 }
    ) {
        return Err("the selected rule's signer predicate is outside the native scope");
    }
    let [PolicyRef::Generated { .. }] = rule.policies.as_slice() else {
        return Err("the selected rule is composed with another policy");
    };
    let bindings: Vec<_> = input
        .candidate
        .binding_set
        .bindings
        .iter()
        .filter(|binding| binding.rule_index == rule_index)
        .collect();
    let [binding] = bindings.as_slice() else {
        return Err("the selected rule does not have exactly one policy binding");
    };
    if binding.policy_index != 0 {
        return Err("the selected rule's binding is not its generated policy");
    }
    let max_calls = rule
        .state
        .iter()
        .map(|state| match state {
            StateSpec::CallCountPerInstallation { max_calls } => *max_calls,
        })
        .next();
    if max_calls.is_some_and(|cap| cap > MAX_CALL_CAP) {
        return Err("the selected rule's call cap exceeds the native worker's sequence");
    }
    let suite: Vec<_> = ozpb_harness::build_suite(&spec)
        .into_iter()
        .filter(|case| case.rule_index == rule_index)
        .collect();
    let observed: BTreeSet<_> = suite.iter().map(|case| case.class).collect();
    let covered = ozpb_harness::expected_classes(&spec)
        .remove(&rule_index)
        .is_some_and(|required| required.is_subset(&observed));
    if suite.is_empty() || suite.len() > MAX_DERIVED_CASES || !covered {
        return Err("the selected rule's derived suite is outside the native worker's bounds");
    }
    Ok((
        NativeScope {
            delegate_address: address.clone(),
            policy_address: binding.contract_address.clone(),
            policy_code_hash: binding.observed_wasm_hash.clone(),
            target_contract: rule.context.contract.clone(),
            max_calls,
        },
        suite,
    ))
}

/// The account-Wasm layer's start frame for exactly the prepared request.
pub fn native_job(input: &DryRunInput, account_wasm: &[u8], ledger: SourceLedger) -> NativeJob {
    use base64::Engine;
    NativeJob {
        schema: 1,
        request: input.clone(),
        account_wasm_base64: base64::engine::general_purpose::STANDARD.encode(account_wasm),
        ledger,
    }
}

/// Everything the coordinator expects of one account-Wasm run, derived here from the request,
/// the preparation and the job before the worker starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeExpectation {
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub scope: NativeScope,
    pub candidate_context_rule_id: u32,
    pub boundary_cases: usize,
    /// Exact execution ledger for each derived case, in suite order.
    pub case_ledgers: Vec<u32>,
    /// Each signing case is bound to its own ledger; controls/sequences use the original's.
    pub signing_expirations: BTreeMap<String, u32>,
    pub signature_expiration_ledgers: BTreeSet<u32>,
    /// Exactly the case IDs a correct run asks the delegate to sign: every derived case the
    /// delegate authenticates, every control and, for a capped rule, the call-cap sequence.
    pub signing_cases: BTreeSet<String>,
}

impl NativeExpectation {
    /// Exactly the case IDs the worker may request a delegate signature for, in no order.
    pub fn signing_case_ids(&self) -> BTreeSet<String> {
        self.signing_cases.clone()
    }
}

/// The case IDs a correct account-Wasm run asks the delegate to sign: each derived case the
/// delegate authenticates, each control, and for a capped rule each sequence call, the
/// partial-rollback attempt and the overflow attempt.
fn native_signing_cases(suite: &[Case], scope: &NativeScope) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = suite
        .iter()
        .enumerate()
        .filter(|(_, case)| {
            case.context.authenticated_signers.iter().any(|signer| {
                matches!(signer, SignerSpec::Delegated { address } if *address == scope.delegate_address)
            })
        })
        .map(|(index, _)| format!("case:{index}"))
        .collect();
    ids.extend(
        NATIVE_CONTROLS
            .iter()
            .map(|(name, _)| format!("control:{name}")),
    );
    if let Some(max_calls) = scope.max_calls {
        ids.extend((0..max_calls).map(|index| format!("sequence:{index}")));
        if max_calls > 0 {
            ids.insert("sequence:partial_rollback".into());
        }
        ids.insert("sequence:overflow".into());
    }
    ids
}

fn hash<T: Serialize>(domain: &str, value: &T) -> Result<String, &'static str> {
    canonical_hash(domain, value)
        .map(|digest| digest.to_hex())
        .map_err(|_| "a dry-run identity exceeds canonical bounds")
}

/// Derive the account-Wasm layer's offline binding without the worker: the request must be the
/// prepared one, the suite must hash to the preparation's, and the job and initialization
/// hashes are computed from the job as the worker computes them. The result is the network ID
/// the coordinator will sign in, and nothing else.
pub fn native_expectation(
    preparation: &DryRunOutput,
    job: &NativeJob,
) -> Result<NativeExpectation, &'static str> {
    let input = &job.request;
    let (scope, suite) = scoped(input)?;
    check_source_ledger(&job.ledger)?;
    if hash(domains::DRY_RUN_REQUEST, input)? != preparation.run_hash {
        return Err("the job's request is not the prepared request");
    }
    if hash(domains::DRY_RUN_SUITE, &suite)? != preparation.binding.suite_hash {
        return Err("the derived suite is not the prepared suite");
    }
    let signature_expiration_ledgers = suite
        .iter()
        .map(|case| case.context.current_ledger.0.checked_add(SIGNATURE_WINDOW))
        .collect::<Option<BTreeSet<_>>>()
        .ok_or("signature expiry overflow")?;
    let case_ledgers: Vec<_> = suite
        .iter()
        .map(|case| case.context.current_ledger.0)
        .collect();
    if preparation
        .reference_case_ledgers
        .as_ref()
        .is_some_and(|ledgers| ledgers != &case_ledgers)
    {
        return Err("reference case ledgers differ from the derived suite");
    }
    let original_ledger = suite
        .iter()
        .find(|case| case.class == MutationClass::Original)
        .ok_or("the suite has no original call")?
        .context
        .current_ledger
        .0;
    let signing_cases = native_signing_cases(&suite, &scope);
    let signing_expirations = signing_cases
        .iter()
        .map(|id| {
            let ledger = if let Some(index) = id.strip_prefix("case:") {
                *case_ledgers
                    .get(index.parse::<usize>().map_err(|_| "invalid case index")?)
                    .ok_or("invalid case index")?
            } else {
                original_ledger
            };
            Ok((
                id.clone(),
                ledger
                    .checked_add(SIGNATURE_WINDOW)
                    .ok_or("signature expiry overflow")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, &'static str>>()?;
    let job_hash = hash(domains::NATIVE_EXECUTION_JOB, job)?;
    // The worker's synthetic local owner. Its seed is deliberately public (the run hash under
    // its own domain); only its public key is computed here, to bind the initialization.
    let seed = canonical_hash(domains::NATIVE_BOOTSTRAP, &preparation.run_hash)
        .map_err(|_| "bootstrap seed")?;
    let bootstrap_owner = stellar_strkey::ed25519::PublicKey(
        ed25519_dalek::SigningKey::from_bytes(&seed.0)
            .verifying_key()
            .to_bytes(),
    )
    .to_string()
    .as_str()
    .to_owned();
    if bootstrap_owner == scope.delegate_address {
        return Err("the bootstrap owner and the delegate overlap");
    }
    #[derive(Serialize)]
    struct Initialization<'a> {
        job_hash: &'a str,
        local_rule_id: u32,
        bootstrap_owner: &'a str,
        provenance: &'a str,
    }
    let state_hash = hash(
        domains::NATIVE_INITIALIZATION,
        &Initialization {
            job_hash: &job_hash,
            local_rule_id: LOCAL_RULE_ID,
            bootstrap_owner: &bootstrap_owner,
            provenance: NATIVE_INITIALIZATION_PROVENANCE,
        },
    )?;
    let binding = OfflineBinding {
        run_hash: preparation.run_hash.clone(),
        job_hash,
        suite_hash: preparation.binding.suite_hash.clone(),
        state_hash,
        source_network_id: input.candidate.network_id.clone(),
        source_protocol_version: job.ledger.protocol_version,
        source_ledger: job.ledger.sequence,
        account_address: input.candidate.account_address.clone(),
        delegate_address: scope.delegate_address.clone(),
    };
    let execution_network_id = offline_execution_network_id(&binding)?;
    let expectation = NativeExpectation {
        binding,
        execution_network_id,
        signing_cases,
        signing_expirations,
        case_ledgers,
        scope,
        candidate_context_rule_id: input.candidate_context_rule_id,
        boundary_cases: suite.len(),
        signature_expiration_ledgers,
    };
    bound_to_preparation(preparation, &expectation.binding, &expectation)?;
    Ok(expectation)
}

/// The identities an offline binding shares with the preparation.
fn bound_to_preparation(
    preparation: &DryRunOutput,
    binding: &OfflineBinding,
    expectation: &NativeExpectation,
) -> Result<(), &'static str> {
    let prepared = &preparation.binding;
    if binding.run_hash != preparation.run_hash
        || binding.account_address != prepared.account_address
        || binding.source_network_id != prepared.network_id
        || binding.delegate_address != expectation.scope.delegate_address
        || prepared.account_code_hash != OZ_SMART_ACCOUNT_WASM.to_hex()
        || prepared
            .policy_code_hashes
            .get(&expectation.scope.policy_address)
            != Some(&expectation.scope.policy_code_hash)
        || prepared.candidate_context_rule_id != expectation.candidate_context_rule_id
    {
        return Err("the offline binding is not bound to the preparation");
    }
    Ok(())
}

/// Check the worker's trusted `--prepare` frame against the locally derived expectation before
/// any signature is requested. Every field must equal what was derived here.
pub fn check_native_prepared(
    frame: &serde_json::Value,
    expectation: &NativeExpectation,
) -> Result<NativePreparedFrame, &'static str> {
    let frame: NativePreparedFrame =
        serde_json::from_value(frame.clone()).map_err(|_| "malformed preparation frame")?;
    let expected = NativePreparedFrame {
        frame_type: "prepared".into(),
        schema: 1,
        binding: expectation.binding.clone(),
        execution_network_id: expectation.execution_network_id.clone(),
        account_code_hash: OZ_SMART_ACCOUNT_WASM.to_hex(),
        policy_address: expectation.scope.policy_address.clone(),
        policy_code_hash: expectation.scope.policy_code_hash.clone(),
        local_rule_id: LOCAL_RULE_ID,
        candidate_context_rule_id: expectation.candidate_context_rule_id,
        boundary_cases: expectation.boundary_cases,
        signature_expiration_ledgers: expectation.signature_expiration_ledgers.clone(),
    };
    if frame != expected {
        return Err("the worker's preparation differs from the derived expectation");
    }
    Ok(frame)
}

/// The ledger a captured job must run under: the capture's own header and archival settings.
pub fn captured_source_ledger(capture: &TargetCapture) -> Result<SourceLedger, &'static str> {
    let limits = || Limits {
        depth: 64,
        len: 256 * 1024,
    };
    let header =
        stellar_xdr::LedgerHeaderHistoryEntry::from_xdr_base64(&capture.header_xdr, limits())
            .map_err(|_| "capture header is not ledger-header XDR")?;
    let archival =
        stellar_xdr::LedgerEntryData::from_xdr_base64(&capture.state_archival.data_xdr, limits())
            .map_err(|_| "capture archival setting is not ledger-entry XDR")?;
    let stellar_xdr::LedgerEntryData::ConfigSetting(
        stellar_xdr::ConfigSettingEntry::StateArchival(settings),
    ) = archival
    else {
        return Err("capture archival setting holds other data");
    };
    let ledger = SourceLedger {
        protocol_version: header.header.ledger_version,
        sequence: header.header.ledger_seq,
        timestamp: header.header.scp_value.close_time.0.to_string(),
        base_reserve: header.header.base_reserve,
        min_temp_entry_ttl: settings.min_temporary_ttl,
        min_persistent_entry_ttl: settings.min_persistent_ttl,
        max_entry_ttl: settings.max_entry_ttl,
    };
    if ledger.sequence != capture.observed_ledger {
        return Err("capture header is not the observed ledger");
    }
    check_source_ledger(&ledger)?;
    Ok(ledger)
}

/// The captured call's amount, which the original must move exactly.
fn captured_amount(capture: &TargetCapture) -> Result<i128, &'static str> {
    let call = stellar_xdr::InvokeContractArgs::from_xdr_base64(
        &capture.invocation_xdr,
        Limits {
            depth: 64,
            len: 64 * 1024,
        },
    )
    .map_err(|_| "capture invocation is not call XDR")?;
    match call.args.as_slice() {
        [_, _, ScVal::I128(parts)] => Ok((i128::from(parts.hi) << 64) | i128::from(parts.lo)),
        _ => Err("capture invocation is not transfer(from, to, amount)"),
    }
}

/// The captured-target layer's start frame: the prepared request at the capture's ledger.
pub fn captured_job(
    input: &DryRunInput,
    account_wasm: &[u8],
    capture: &TargetCapture,
) -> Result<CapturedTargetJob, &'static str> {
    if capture.network_id != input.candidate.network_id {
        return Err("the capture is from another network than the candidate");
    }
    Ok(CapturedTargetJob {
        schema: 1,
        native: native_job(input, account_wasm, captured_source_ledger(capture)?),
        capture: capture.clone(),
    })
}

/// Everything the coordinator expects of one captured-target run. The suite and initialization
/// hashes need the candidate installed over the capture, which only the worker can do; they are
/// taken from its trusted `--prepare-captured` frame once every identity derivable here agrees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedExpectation {
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub capture_hash: String,
    pub candidate_state_hash: String,
    pub target_contract: String,
    pub observed_ledger: u32,
    pub amount: i128,
    pub counter_seed: Option<u32>,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub candidate_context_rule_id: u32,
    pub signing_case_ids: BTreeSet<String>,
    pub signature_expiration_ledgers: BTreeSet<u32>,
}

/// Check the worker's trusted `--prepare-captured` frame against what is derivable here, and
/// return the expectation the run and its report are held to.
pub fn captured_expectation(
    preparation: &DryRunOutput,
    job: &CapturedTargetJob,
    frame: &serde_json::Value,
) -> Result<CapturedExpectation, &'static str> {
    let input = &job.native.request;
    let scope = native_scope(input)?;
    if hash(domains::DRY_RUN_REQUEST, input)? != preparation.run_hash {
        return Err("the job's request is not the prepared request");
    }
    let frame: CapturedPreparedFrame =
        serde_json::from_value(frame.clone()).map_err(|_| "malformed preparation frame")?;
    let capture = &job.capture;
    let observed_ledger = capture.observed_ledger;
    let expiry = observed_ledger
        .checked_add(SIGNATURE_WINDOW)
        .ok_or("signature expiry overflow")?;
    let binding = OfflineBinding {
        run_hash: preparation.run_hash.clone(),
        job_hash: hash(domains::CAPTURED_TARGET_JOB, job)?,
        suite_hash: frame.binding.suite_hash.clone(),
        state_hash: frame.binding.state_hash.clone(),
        source_network_id: capture.network_id.clone(),
        source_protocol_version: job.native.ledger.protocol_version,
        source_ledger: observed_ledger,
        account_address: input.candidate.account_address.clone(),
        delegate_address: scope.delegate_address.clone(),
    };
    let execution_network_id = offline_execution_network_id(&binding)?;
    let expectation = CapturedExpectation {
        execution_network_id,
        capture_hash: hash(domains::TARGET_CAPTURE, capture)?,
        candidate_state_hash: frame.candidate_state_hash.clone(),
        target_contract: scope.target_contract.clone(),
        observed_ledger,
        amount: captured_amount(capture)?,
        counter_seed: scope.max_calls.map(|_| 0),
        policy_address: scope.policy_address.clone(),
        policy_code_hash: scope.policy_code_hash.clone(),
        candidate_context_rule_id: input.candidate_context_rule_id,
        signing_case_ids: CAPTURED_CASE_IDS[..2]
            .iter()
            .map(|id| id.to_string())
            .collect(),
        signature_expiration_ledgers: BTreeSet::from([expiry]),
        binding,
    };
    let expected = CapturedPreparedFrame {
        frame_type: "prepared".into(),
        schema: 1,
        layer: "captured_target".into(),
        binding: expectation.binding.clone(),
        execution_network_id: expectation.execution_network_id.clone(),
        account_code_hash: OZ_SMART_ACCOUNT_WASM.to_hex(),
        policy_address: expectation.policy_address.clone(),
        policy_code_hash: expectation.policy_code_hash.clone(),
        local_rule_id: LOCAL_RULE_ID,
        candidate_context_rule_id: expectation.candidate_context_rule_id,
        capture_hash: expectation.capture_hash.clone(),
        candidate_state_hash: expectation.candidate_state_hash.clone(),
        target_contract: expectation.target_contract.clone(),
        observed_ledger,
        case_ids: CAPTURED_CASE_IDS.iter().map(|id| id.to_string()).collect(),
        signing_case_ids: CAPTURED_CASE_IDS[..2]
            .iter()
            .map(|id| id.to_string())
            .collect(),
        signature_expiration_ledgers: expectation.signature_expiration_ledgers.clone(),
    };
    if frame != expected
        || !is_hash(&expectation.binding.suite_hash)
        || !is_hash(&expectation.binding.state_hash)
        || !is_hash(&expectation.candidate_state_hash)
        || capture.provenance != "rpc_reported"
        || capture.account_code_hash != OZ_SMART_ACCOUNT_WASM.to_hex()
    {
        return Err("the worker's captured preparation differs from the derived expectation");
    }
    let native = NativeExpectation {
        binding: expectation.binding.clone(),
        execution_network_id: expectation.execution_network_id.clone(),
        scope,
        candidate_context_rule_id: expectation.candidate_context_rule_id,
        boundary_cases: 0,
        case_ledgers: Vec::new(),
        signing_expirations: BTreeMap::new(),
        signature_expiration_ledgers: BTreeSet::new(),
        signing_cases: BTreeSet::new(),
    };
    bound_to_preparation(preparation, &expectation.binding, &native)?;
    Ok(expectation)
}

/// How a worker process ended, as the coordinator observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerExit {
    /// Exit status zero, with no process left in its group.
    Success,
    /// A nonzero exit status.
    Code(i32),
    /// Ended by a signal it did not receive from the coordinator.
    Signal,
}

/// One runtime layer as the coordinator ran it, or why it did not.
#[derive(Clone, Debug)]
pub enum LayerRun {
    /// The layer did not run. Never becomes `passed` or `failed`.
    NotRun { unsupported: bool, reason: String },
    /// The coordinator stopped the exchange (refused a frame or a signature request, hit the
    /// deadline or an output bound); no report from it is accepted.
    Refused { reason: String },
    /// The worker ran to its own exit; its final report, if any, is still unchecked. `signed`
    /// holds the case IDs the coordinator's signer answered.
    Ran {
        exit: WorkerExit,
        result: Option<serde_json::Value>,
        signed: BTreeSet<String>,
    },
}

fn exit_reason(exit: WorkerExit) -> Option<&'static str> {
    match exit {
        WorkerExit::Success => None,
        WorkerExit::Code(_) => Some("worker_exit_nonzero"),
        WorkerExit::Signal => Some("worker_ended_by_signal"),
    }
}

/// The reference expectations, read back from the preparation's own report.
struct Reference {
    passed: bool,
    outcomes: Vec<ozpb_harness::Outcome>,
    required_classes: BTreeSet<MutationClass>,
}

fn reference(preparation: &DryRunOutput) -> Option<Reference> {
    let report: EvidenceReport =
        serde_json::from_value(preparation.reference_report.clone()).ok()?;
    let rule_index = preparation.binding.rule_index;
    let outcomes: Vec<_> = report
        .outcomes
        .into_iter()
        .filter(|outcome| outcome.rule_index == rule_index)
        .collect();
    let required_classes = report.expected_classes.get(&rule_index)?.clone();
    let layer_passed = preparation
        .layers
        .iter()
        .any(|layer| layer.id == Layer::Reference && layer.status == Status::Passed);
    let passed = layer_passed
        && !outcomes.is_empty()
        && outcomes.iter().all(|outcome| outcome.agree)
        && required_classes
            .iter()
            .all(|class| outcomes.iter().any(|outcome| outcome.class == *class));
    Some(Reference {
        passed,
        outcomes,
        required_classes,
    })
}

/// Whether a refusal is the error the class predicts, from the contract that raises it. The
/// numbering is the generated policy's published deny-reason contract and the pinned account's
/// own errors; the worker applies the same table, and this is the coordinator's own copy.
fn predicted_refusal(class: MutationClass, enforcer: DryRunEnforcer, code: u32) -> bool {
    use MutationClass as C;
    match (class, enforcer) {
        (C::DifferentContract | C::TimeBoundary, DryRunEnforcer::Account) => {
            code == ACCOUNT_UNVALIDATED_CONTEXT
        }
        (C::WrongSigner | C::SignerBoundary | C::StrictSetMutation, DryRunEnforcer::Account) => {
            code == ACCOUNT_UNAUTHORIZED_SIGNER
        }
        (C::ZeroSigners, DryRunEnforcer::Policy) => code == 1,
        (C::WrongSigner | C::SignerBoundary, DryRunEnforcer::Policy) => (1..=3).contains(&code),
        (C::StrictSetMutation, DryRunEnforcer::Policy) => code == 3,
        (C::DifferentFunction, DryRunEnforcer::Policy) => code == 5,
        (
            C::ArgEquality
            | C::NumericBoundary
            | C::DifferentAddressArg
            | C::ArgArity
            | C::TypeConfusion
            | C::TupleCrossProduct,
            DryRunEnforcer::Policy,
        ) => code == 6,
        (C::CallCountBoundary, DryRunEnforcer::Policy) => code == 7,
        (C::MissingState, DryRunEnforcer::Policy) => code == 8,
        (C::TimeBoundary, DryRunEnforcer::Policy) => code == 9,
        _ => false,
    }
}

fn class_name(class: MutationClass) -> String {
    serde_json::to_value(class)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn enforcer(contract: &Option<String>, account: &str, policy: &str) -> Option<DryRunEnforcer> {
    match contract.as_deref() {
        Some(c) if c == account => Some(DryRunEnforcer::Account),
        Some(c) if c == policy => Some(DryRunEnforcer::Policy),
        _ => None,
    }
}

fn layer(id: Layer, status: Status, reason: &str) -> DryRunLayer {
    DryRunLayer {
        id,
        status,
        reason: reason.into(),
        cases: 0,
        state_dependent: matches!(id, Layer::CapturedTarget | Layer::LiveEnforcement),
        writes_committed: false,
        execution: None,
    }
}

fn not_executed(id: Layer, run: &LayerRun) -> Option<DryRunLayer> {
    match run {
        LayerRun::NotRun {
            unsupported,
            reason,
        } => {
            let status = if *unsupported {
                Status::Unsupported
            } else {
                Status::Unavailable
            };
            Some(layer(id, status, reason))
        }
        LayerRun::Refused { reason } => Some(layer(id, Status::Failed, reason)),
        LayerRun::Ran { .. } => None,
    }
}

fn native_layer(
    preparation: &DryRunOutput,
    reference: Option<&Reference>,
    expectation: Option<&NativeExpectation>,
    run: &LayerRun,
) -> DryRunLayer {
    let id = Layer::AccountWasm;
    if let Some(layer) = not_executed(id, run) {
        return layer;
    }
    let LayerRun::Ran {
        exit,
        result,
        signed,
    } = run
    else {
        return layer(id, Status::Failed, "worker_result_missing");
    };
    let fail = |reason: &str| layer(id, Status::Failed, reason);
    let (Some(expectation), Some(reference)) = (expectation, reference) else {
        return fail("preparation_expectations_unavailable");
    };
    if bound_to_preparation(preparation, &expectation.binding, expectation).is_err()
        || preparation
            .reference_case_ledgers
            .as_ref()
            .is_some_and(|ledgers| ledgers != &expectation.case_ledgers)
        || expectation.binding.suite_hash != preparation.binding.suite_hash
        || offline_execution_network_id(&expectation.binding).as_deref()
            != Ok(expectation.execution_network_id.as_str())
    {
        return fail("expectation_not_bound_to_preparation");
    }
    let Some(result) = result else {
        return fail(exit_reason(*exit).unwrap_or("worker_result_missing"));
    };
    let Ok(frame) = serde_json::from_value::<NativeResultFrame>(result.clone()) else {
        return fail("worker_result_malformed");
    };
    let account = &expectation.binding.account_address;
    let policy = &expectation.scope.policy_address;
    if frame.frame_type != "result"
        || frame.schema != 1
        || frame.binding != expectation.binding
        || frame.execution_network_id != expectation.execution_network_id
        || frame.account_code_hash != OZ_SMART_ACCOUNT_WASM.to_hex()
        || frame.policy_address != *policy
        || frame.policy_code_hash != expectation.scope.policy_code_hash
        || frame.host_version != HOST_VERSION
        || frame.local_rule_id != LOCAL_RULE_ID
        || frame.candidate_context_rule_id != expectation.candidate_context_rule_id
        || frame.provenance != NATIVE_PROVENANCE
        || frame.complete
    {
        return fail("worker_binding_mismatch");
    }
    // A run that did not ask for exactly the expected signatures did not exercise the
    // delegate's authorization the report describes, whatever the report says.
    if *signed != expectation.signing_cases {
        return fail("signatures_differ_from_expectation");
    }
    if frame.cases.len() != reference.outcomes.len()
        || frame.cases.len() != expectation.boundary_cases
        || frame.cases.len() != expectation.case_ledgers.len()
        || frame.required_classes != reference.required_classes
        || frame.cases.iter().zip(&reference.outcomes).enumerate().any(
            |(index, (case, outcome))| {
                case.case_id != format!("case:{index}")
                    || case.ledger != expectation.case_ledgers[index]
                    || case.label != outcome.label
                    || case.class != outcome.class
                    || case.expected_permit != (outcome.expected == "permit")
                    || case.state_changed != (case.state_before_hash != case.state_after_hash)
                    || !is_hash(&case.state_before_hash)
                    || !is_hash(&case.state_after_hash)
            },
        )
    {
        return fail("worker_cases_differ_from_preparation");
    }
    let cases: Vec<_> = frame
        .cases
        .iter()
        .zip(&reference.outcomes)
        .map(|(case, outcome)| {
            let expected_permit = outcome.expected == "permit";
            let refused_by = enforcer(&case.refusal_contract, account, policy);
            let state_unchanged = case.state_before_hash == case.state_after_hash;
            let seeded = case.counter_before == case.counter_seed;
            let agree = case.agree
                && seeded
                && case.permitted == expected_permit
                && if case.permitted {
                    case.refusal_contract.is_none()
                        && case.refusal_code.is_none()
                        && match case.counter_before {
                            Some(before) => before.checked_add(1) == case.counter_after,
                            None => case.counter_after.is_none(),
                        }
                } else {
                    state_unchanged
                        && case.counter_after == case.counter_before
                        && match (refused_by, case.refusal_code) {
                            (Some(by), Some(code)) => predicted_refusal(case.class, by, code),
                            _ => false,
                        }
                };
            DryRunCaseResult {
                case_id: case.case_id.clone(),
                label: case.label.clone(),
                class: class_name(case.class),
                expected_permit,
                permitted: case.permitted,
                refused_by,
                refusal_code: case.refusal_code,
                state_unchanged,
                agree,
            }
        })
        .collect();
    let controls_ok = frame.controls.len() == NATIVE_CONTROLS.len()
        && frame
            .controls
            .iter()
            .zip(NATIVE_CONTROLS)
            .all(|(control, (name, stage))| {
                control.name == name
                    && control.passed
                    && control.refusal_stage == stage
                    && is_hash(&control.state_before_hash)
                    && control.state_before_hash == control.state_after_hash
            });
    let stateful_ok = match (expectation.scope.max_calls, &frame.stateful) {
        (None, None) => true,
        (Some(max_calls), Some(s)) => {
            s.successful_calls == max_calls
                && s.counter_before == 0
                && s.counter_after == max_calls
                && s.overflow_refused
                && s.overflow_rolled_back
                && s.partial_rollback_refused
                && s.partial_rollback_preserved_counter
                && s.passed
        }
        _ => false,
    };
    let reason = if let Some(reason) = exit_reason(*exit) {
        reason
    } else if !cases.iter().all(|case| case.agree) {
        "case_disagreement"
    } else if !controls_ok {
        "control_failed"
    } else if !stateful_ok {
        "stateful_sequence_failed"
    } else if !frame.passed {
        "worker_reported_failure"
    } else {
        "pinned_account_and_generated_policy_executed_offline"
    };
    let status = if exit_reason(*exit).is_none()
        && cases.iter().all(|case| case.agree)
        && controls_ok
        && stateful_ok
        && frame.passed
    {
        Status::Passed
    } else {
        Status::Failed
    };
    DryRunLayer {
        id,
        status,
        reason: reason.into(),
        cases: cases.len(),
        state_dependent: false,
        writes_committed: false,
        execution: Some(DryRunLayerExecution {
            run_hash: frame.binding.run_hash.clone(),
            job_hash: frame.binding.job_hash.clone(),
            suite_hash: frame.binding.suite_hash.clone(),
            state_hash: frame.binding.state_hash.clone(),
            source_network_id: frame.binding.source_network_id.clone(),
            source_ledger: frame.binding.source_ledger,
            execution_network_id: frame.execution_network_id.clone(),
            delegate_address: frame.binding.delegate_address.clone(),
            policy_address: frame.policy_address.clone(),
            policy_code_hash: frame.policy_code_hash.clone(),
            host_version: frame.host_version.clone(),
            provenance: frame.provenance.clone(),
            cases,
            controls: frame
                .controls
                .iter()
                .map(|control| DryRunControlResult {
                    name: control.name.clone(),
                    passed: control.passed,
                })
                .collect(),
            stateful: expectation
                .scope
                .max_calls
                .zip(frame.stateful.as_ref())
                .map(|(max_calls, s)| DryRunStatefulResult {
                    max_calls,
                    successful_calls: s.successful_calls,
                    passed: stateful_ok,
                }),
        }),
    }
}

fn captured_layer(
    preparation: &DryRunOutput,
    expectation: Option<&CapturedExpectation>,
    run: &LayerRun,
) -> DryRunLayer {
    let id = Layer::CapturedTarget;
    if let Some(layer) = not_executed(id, run) {
        return layer;
    }
    let LayerRun::Ran {
        exit,
        result,
        signed,
    } = run
    else {
        return layer(id, Status::Failed, "worker_result_missing");
    };
    let fail = |reason: &str| layer(id, Status::Failed, reason);
    let Some(expectation) = expectation else {
        return fail("preparation_expectations_unavailable");
    };
    if expectation.binding.run_hash != preparation.run_hash
        || expectation.binding.account_address != preparation.binding.account_address
        || expectation.binding.source_network_id != preparation.binding.network_id
        || preparation
            .binding
            .policy_code_hashes
            .get(&expectation.policy_address)
            != Some(&expectation.policy_code_hash)
        || preparation.binding.candidate_context_rule_id != expectation.candidate_context_rule_id
        || offline_execution_network_id(&expectation.binding).as_deref()
            != Ok(expectation.execution_network_id.as_str())
    {
        return fail("expectation_not_bound_to_preparation");
    }
    let Some(result) = result else {
        return fail(exit_reason(*exit).unwrap_or("worker_result_missing"));
    };
    let Ok(frame) = serde_json::from_value::<CapturedResultFrame>(result.clone()) else {
        return fail("worker_result_malformed");
    };
    let policy = &expectation.policy_address;
    if frame.frame_type != "result"
        || frame.schema != 1
        || frame.layer != "captured_target"
        || frame.binding != expectation.binding
        || frame.execution_network_id != expectation.execution_network_id
        || frame.capture_hash != expectation.capture_hash
        || frame.candidate_state_hash != expectation.candidate_state_hash
        || frame.capture_provenance != "rpc_reported"
        || frame.observed_ledger != expectation.observed_ledger
        || frame.target_contract != expectation.target_contract
        || frame.account_code_hash != OZ_SMART_ACCOUNT_WASM.to_hex()
        || frame.policy_address != *policy
        || frame.policy_code_hash != expectation.policy_code_hash
        || frame.host_version != HOST_VERSION
        || frame.local_rule_id != LOCAL_RULE_ID
        || frame.candidate_context_rule_id != expectation.candidate_context_rule_id
        || frame.storage_mode != STORAGE_MODE
        || frame.provenance != CAPTURED_PROVENANCE
        || frame.complete
    {
        return fail("worker_binding_mismatch");
    }
    if *signed != expectation.signing_case_ids {
        return fail("signatures_differ_from_expectation");
    }
    let planned = [
        (MutationClass::Original, true, None),
        (MutationClass::ArgEquality, false, Some(6)),
        (MutationClass::ZeroSigners, false, Some(1)),
    ];
    if frame.cases.len() != planned.len()
        || frame
            .cases
            .iter()
            .zip(CAPTURED_CASE_IDS.iter().zip(planned))
            .any(|(case, (case_id, (class, permit, _)))| {
                case.case_id != *case_id || case.class != class || case.expected_permit != permit
            })
    {
        return fail("worker_cases_differ_from_preparation");
    }
    let amount = expectation.amount.to_string();
    let cases: Vec<_> = frame
        .cases
        .iter()
        .zip(planned)
        .map(|(case, (_, expected_permit, code))| {
            let refused_by = enforcer(
                &case.refusal_contract,
                &expectation.binding.account_address,
                policy,
            );
            let state_unchanged = case.state_before_hash == case.state_after_hash;
            let clean = case.unexpected_changes.is_empty()
                && is_hash(&case.state_before_hash)
                && is_hash(&case.state_after_hash)
                && case.undeclared_reads.is_empty()
                && case.counter_seed == expectation.counter_seed
                && case.counter_before == case.counter_seed;
            let agree = case.agree
                && clean
                && case.permitted == expected_permit
                && match code {
                    None => {
                        case.refusal_contract.is_none()
                            && case.refusal_code.is_none()
                            && match case.counter_before {
                                Some(before) => before.checked_add(1) == case.counter_after,
                                None => case.counter_after.is_none(),
                            }
                            && case.host_error.is_none()
                            && case.sender_delta == format!("-{amount}")
                            && case.recipient_delta == amount
                    }
                    Some(code) => {
                        refused_by == Some(DryRunEnforcer::Policy)
                            && case.refusal_code == Some(code)
                            && state_unchanged
                            && case.counter_after == case.counter_before
                            && case.sender_delta == "0"
                            && case.recipient_delta == "0"
                    }
                };
            DryRunCaseResult {
                case_id: case.case_id.clone(),
                label: case.label.clone(),
                class: class_name(case.class),
                expected_permit,
                permitted: case.permitted,
                refused_by,
                refusal_code: case.refusal_code,
                state_unchanged,
                agree,
            }
        })
        .collect();
    let all_agree = cases.iter().all(|case| case.agree);
    let (status, reason) = match exit_reason(*exit) {
        Some(reason) => (Status::Failed, reason),
        None if !all_agree => (Status::Failed, "case_disagreement"),
        None if !frame.passed => (Status::Failed, "worker_reported_failure"),
        None => (Status::Passed, "captured_target_executed_offline"),
    };
    DryRunLayer {
        id,
        status,
        reason: reason.into(),
        cases: cases.len(),
        state_dependent: true,
        writes_committed: false,
        execution: Some(DryRunLayerExecution {
            run_hash: frame.binding.run_hash.clone(),
            job_hash: frame.binding.job_hash.clone(),
            suite_hash: frame.binding.suite_hash.clone(),
            state_hash: frame.binding.state_hash.clone(),
            source_network_id: frame.binding.source_network_id.clone(),
            source_ledger: frame.binding.source_ledger,
            execution_network_id: frame.execution_network_id.clone(),
            delegate_address: frame.binding.delegate_address.clone(),
            policy_address: frame.policy_address.clone(),
            policy_code_hash: frame.policy_code_hash.clone(),
            host_version: frame.host_version.clone(),
            provenance: frame.provenance.clone(),
            cases,
            controls: Vec::new(),
            stateful: None,
        }),
    }
}

fn layer_acceptance(layer: &DryRunLayer) -> DryRunLayerAcceptance {
    let passed = layer.status == Status::Passed;
    let cases = layer
        .execution
        .as_ref()
        .map(|execution| execution.cases.as_slice())
        .unwrap_or_default();
    let original = class_name(MutationClass::Original);
    DryRunLayerAcceptance {
        layer: layer.id,
        status: layer.status,
        original_permitted: passed
            && cases.iter().any(|case| {
                case.class == original && case.expected_permit && case.permitted && case.agree
            }),
        reverted_denials: if passed {
            cases
                .iter()
                .filter(|case| !case.expected_permit && !case.permitted && case.agree)
                .count()
        } else {
            0
        },
    }
}

/// Assemble the four-layer report from a preparation and the runtime layers the coordinator
/// ran. Pure: the same inputs give the same report.
///
/// The reference layer is the preparation's. The account-Wasm and captured-target layers come
/// only from `account` and `captured`: a preparation that claims either passed changes nothing.
/// The live layer is always `unavailable`: it needs the wallet owner's consent and signature,
/// which no coordinator outside the wallet holds.
pub fn assemble_dry_run_report(
    preparation: &DryRunOutput,
    native: Option<&NativeExpectation>,
    account: &LayerRun,
    captured_expectation: Option<&CapturedExpectation>,
    captured: &LayerRun,
) -> DryRunOutput {
    let reference = reference(preparation);
    let reference_layer = preparation
        .layers
        .iter()
        .find(|layer| layer.id == Layer::Reference)
        .map(|layer| DryRunLayer {
            execution: None,
            ..layer.clone()
        })
        .unwrap_or_else(|| layer(Layer::Reference, Status::Failed, "reference_layer_missing"));
    let layers = vec![
        reference_layer,
        native_layer(preparation, reference.as_ref(), native, account),
        captured_layer(preparation, captured_expectation, captured),
        layer(
            Layer::LiveEnforcement,
            Status::Unavailable,
            "wallet_owner_consent_required",
        ),
    ];
    let executed_layers: Vec<_> = layers
        .iter()
        .filter(|layer| layer.execution.is_some() || layer.status == Status::Failed)
        .filter(|layer| matches!(layer.id, Layer::AccountWasm | Layer::CapturedTarget))
        .map(layer_acceptance)
        .collect();
    let original_permitted = !executed_layers.is_empty()
        && executed_layers
            .iter()
            .all(|layer| layer.status == Status::Passed && layer.original_permitted);
    let meets_minimum = reference.as_ref().is_some_and(|r| r.passed)
        && original_permitted
        && executed_layers
            .iter()
            .any(|layer| layer.reverted_denials >= REQUIRED_REVERTED_DENIALS);
    DryRunOutput {
        schema: preparation.schema.clone(),
        run_hash: preparation.run_hash.clone(),
        binding: preparation.binding.clone(),
        artifact_verification: preparation.artifact_verification.clone(),
        reference_report: preparation.reference_report.clone(),
        reference_case_ledgers: preparation.reference_case_ledgers.clone(),
        layers,
        complete: false,
        acceptance: Some(DryRunAcceptance {
            required_reverted_denials: REQUIRED_REVERTED_DENIALS,
            original_permitted,
            executed_layers,
            meets_minimum,
        }),
        disclaimer: "Executed layers ran offline: the pinned account and the exact generated \
                     policy, in fresh synthetic local state and, for the captured layer, \
                     endpoint-reported target state, under a counterfactual network ID. Live \
                     enforcement did not run; it needs the wallet owner's consent. \
                     Constraint-derived evidence is not proof about untested inputs. This report \
                     does not authorize installation, establish ownership, or claim current \
                     deployed code."
            .into(),
    }
}

#[cfg(test)]
#[path = "dry_run_report_tests.rs"]
mod tests;
