use crate::wire::{
    AccountEd25519Signature, AuthPayload, ContextRule, ContextRuleType, PolicyStorageKey, Signer,
};
use crate::{
    canonical_hex, make_sign_request, offline_network, verify_signature_response, xdr_limits,
    DelegateSigner, OfflineBinding, RuntimeResult,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey};
use ozpb_api_types::DryRunInput;
use ozpb_domain::{canonical_hash, domains, pinned_upstream::OZ_SMART_ACCOUNT_WASM, Hash32};
use ozpb_evaluator::ArgValue;
use ozpb_harness::{Case, MutationClass};
use ozpb_policy_spec::{
    PolicyRef, PolicySpec, PredicateKind, SignerSpec, StateSpec, ValidatedSpec,
};
use serde::{Deserialize, Serialize};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{EnvTestConfig, Ledger};
use soroban_sdk::xdr::{self, ReadXdr, ToXdr, WriteXdr};
use soroban_sdk::{
    vec as svec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec as SVec,
};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Instant;

pub(crate) const LOCAL_RULE_ID: u32 = 1;
const MAX_STATEFUL_CALLS: u32 = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLedger {
    pub protocol_version: u32,
    pub sequence: u32,
    /// Decimal text avoids JSON's floating point integer conversion.
    pub timestamp: String,
    pub base_reserve: u32,
    pub min_temp_entry_ttl: u32,
    pub min_persistent_entry_ttl: u32,
    pub max_entry_ttl: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeJob {
    pub schema: u32,
    pub request: DryRunInput,
    pub account_wasm_base64: String,
    pub ledger: SourceLedger,
}

pub struct PreparedExecution {
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub account_code_hash: String,
    pub candidate_context_rule_id: u32,
    pub(crate) job: NativeJob,
    pub(crate) spec: ValidatedSpec,
    pub(crate) suite: Vec<Case>,
    account_wasm: Vec<u8>,
    policy_wasm: Vec<u8>,
    pub(crate) bootstrap: SigningKey,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreparedFrame {
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

impl PreparedFrame {
    pub fn from_execution(input: &PreparedExecution) -> RuntimeResult<Self> {
        let signature_expiration_ledgers = input
            .suite
            .iter()
            .map(|case| {
                case.context
                    .current_ledger
                    .0
                    .checked_add(64)
                    .ok_or_else(|| "signature expiry overflow".into())
            })
            .collect::<RuntimeResult<_>>()?;
        Ok(Self {
            frame_type: "prepared".into(),
            schema: 1,
            binding: input.binding.clone(),
            execution_network_id: input.execution_network_id.clone(),
            account_code_hash: input.account_code_hash.clone(),
            policy_address: input.policy_address.clone(),
            policy_code_hash: input.policy_code_hash.clone(),
            local_rule_id: LOCAL_RULE_ID,
            candidate_context_rule_id: input.candidate_context_rule_id,
            boundary_cases: input.suite.len(),
            signature_expiration_ledgers,
        })
    }
}

pub(crate) fn hash<T: Serialize>(domain: &str, value: &T) -> RuntimeResult<String> {
    canonical_hash(domain, value)
        .map(|h| h.to_hex())
        .map_err(|e| e.to_string())
}

fn decode_wasm(value: &str) -> RuntimeResult<Vec<u8>> {
    if value.len() > 4 * 1024 * 1024 {
        return Err("Wasm byte limit exceeded".into());
    }
    let bytes = STANDARD.decode(value).map_err(|_| "invalid Wasm base64")?;
    if STANDARD.encode(&bytes) != value || !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Err("noncanonical Wasm bytes".into());
    }
    Ok(bytes)
}

pub fn prepare(job: NativeJob) -> RuntimeResult<PreparedExecution> {
    if job.schema != 1 || job.ledger.protocol_version != 30 || job.ledger.sequence == 0 {
        return Err("unsupported job schema or source protocol".into());
    }
    let timestamp: u64 = job.ledger.timestamp.parse().map_err(|_| "timestamp")?;
    if timestamp.to_string() != job.ledger.timestamp
        || job.ledger.max_entry_ttl == 0
        || job.ledger.min_temp_entry_ttl == 0
        || job.ledger.min_persistent_entry_ttl == 0
        || job.ledger.min_temp_entry_ttl > job.ledger.max_entry_ttl
        || job.ledger.min_persistent_entry_ttl > job.ledger.max_entry_ttl
    {
        return Err("invalid source ledger parameters".into());
    }
    canonical_hex::<32>(&job.request.run_nonce)?;
    if job.request.candidate.spec != job.request.artifact.spec
        || job.request.candidate.rule_index != job.request.artifact.rule_index
    {
        return Err("candidate and artifact differ".into());
    }
    let raw: PolicySpec =
        serde_json::from_value(job.request.candidate.spec.clone()).map_err(|e| e.to_string())?;
    // Only the selected rule runs, and only its policy is installed; the other rules of the
    // same specification are context. Its index is checked here, not clamped.
    let rule_index = job.request.candidate.rule_index;
    if rule_index >= raw.rules.len() {
        return Err("selected rule index is outside the specification".into());
    }
    // Bound suite expansion before it clones argument tuples. The suite is derived for every
    // rule before the selected rule's cases are kept, so the per-rule bounds hold for all of
    // them. Larger valid specifications are outside this worker's supported scope.
    if serde_json::to_vec(&raw).map_err(|e| e.to_string())?.len() > 64 * 1024
        || raw
            .rules
            .iter()
            .any(|r| r.allowed_calls.len() > 8 || r.allowed_calls.iter().any(|c| c.args.len() > 16))
    {
        return Err("unsupported native scope: at most eight calls per rule, sixteen arguments and 64 KiB of specification".into());
    }
    let spec = raw.validate().map_err(|e| format!("{e:?}"))?;
    let rule = spec
        .spec()
        .rules
        .get(rule_index)
        .ok_or("missing selected rule")?;
    if spec.spec().smart_account.address != job.request.candidate.account_address
        || spec.spec().network_id.0.to_hex() != job.request.candidate.network_id
        || spec.hash().to_hex() != job.request.candidate.binding_set.spec_hash
        || job.request.candidate.binding_set.network_id != job.request.candidate.network_id
        || spec.spec().smart_account.observed_code_hash != OZ_SMART_ACCOUNT_WASM
    {
        return Err("candidate identity or account pin mismatch".into());
    }
    let [SignerSpec::Delegated { address: delegate }] = rule.authorization.signers.as_slice()
    else {
        return Err(
            "unsupported signer configuration: one explicit delegated G identity required".into(),
        );
    };
    if !matches!(
        rule.authorization.kind,
        PredicateKind::AnyOf | PredicateKind::AllOf | PredicateKind::Threshold { n: 1 }
    ) {
        return Err("unsupported signer predicate".into());
    }
    // A selected rule composed with another policy (a reviewed spending limit, say) would run
    // here without it, so its evidence would describe a rule nobody installs.
    let [PolicyRef::Generated { .. }] = rule.policies.as_slice() else {
        return Err(
            "unsupported policy composition: the selected rule must carry exactly one generated policy"
                .into(),
        );
    };
    let bindings: Vec<_> = job
        .request
        .candidate
        .binding_set
        .bindings
        .iter()
        .filter(|b| b.rule_index == rule_index)
        .collect();
    if bindings.len() != 1 || bindings[0].policy_index != 0 {
        return Err("selected policy binding mismatch".into());
    }
    let policy_address = bindings[0].contract_address.clone();
    let policy_code_hash = bindings[0].observed_wasm_hash.clone();
    if policy_address == job.request.candidate.account_address {
        return Err("account/policy address overlap".into());
    }
    stellar_strkey::Contract::from_string(&policy_address).map_err(|_| "policy address")?;
    let account_wasm = decode_wasm(&job.account_wasm_base64)?;
    let policy_wasm = decode_wasm(
        job.request
            .artifact
            .claimed_wasm_base64
            .as_deref()
            .ok_or("missing generated Wasm")?,
    )?;
    if ozpb_domain::sha256(&account_wasm) != OZ_SMART_ACCOUNT_WASM
        || ozpb_domain::sha256(&policy_wasm).to_hex() != policy_code_hash
    {
        return Err("account/policy Wasm byte hash mismatch".into());
    }
    let suite: Vec<_> = ozpb_harness::build_suite(&spec)
        .into_iter()
        .filter(|c| c.rule_index == rule_index)
        .collect();
    if suite.is_empty() || suite.len() > 256 {
        return Err("unsupported native scope: at most 256 derived cases".into());
    }
    if rule.state.iter().any(|s| matches!(s, StateSpec::CallCountPerInstallation { max_calls } if *max_calls > MAX_STATEFUL_CALLS)) {
        return Err("unsupported stateful sequence: call cap exceeds 512".into());
    }
    let observed: BTreeSet<_> = suite.iter().map(|c| c.class).collect();
    let required = ozpb_harness::expected_classes(&spec)
        .remove(&rule_index)
        .ok_or("missing coverage requirements")?;
    if !required.is_subset(&observed) {
        return Err("derived suite misses required boundary classes".into());
    }
    let run_hash = hash(domains::DRY_RUN_REQUEST, &job.request)?;
    let job_hash = hash(domains::NATIVE_EXECUTION_JOB, &job)?;
    let suite_hash = hash(domains::DRY_RUN_SUITE, &suite)?;
    // This owner exists only in synthetic local setup. It proves no wallet ownership.
    let bootstrap_seed =
        canonical_hash(domains::NATIVE_BOOTSTRAP, &run_hash).map_err(|e| e.to_string())?;
    let bootstrap = SigningKey::from_bytes(&bootstrap_seed.0);
    let bootstrap_address =
        stellar_strkey::ed25519::PublicKey(bootstrap.verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned();
    if bootstrap_address.as_str() == delegate.as_str() {
        return Err("bootstrap owner and delegate overlap".into());
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
            bootstrap_owner: &bootstrap_address,
            provenance: "fresh_local_candidate_boundary_states",
        },
    )?;
    let binding = OfflineBinding {
        run_hash,
        job_hash,
        suite_hash,
        state_hash,
        source_network_id: job.request.candidate.network_id.clone(),
        source_protocol_version: job.ledger.protocol_version,
        source_ledger: job.ledger.sequence,
        account_address: job.request.candidate.account_address.clone(),
        delegate_address: delegate.clone(),
    };
    let execution_network_id = offline_network(&binding)?;
    Ok(PreparedExecution {
        binding,
        execution_network_id,
        policy_address,
        policy_code_hash,
        account_code_hash: OZ_SMART_ACCOUNT_WASM.to_hex(),
        candidate_context_rule_id: job.request.candidate_context_rule_id,
        job,
        spec,
        suite,
        account_wasm,
        policy_wasm,
        bootstrap,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseResult {
    pub case_id: String,
    pub label: String,
    pub class: MutationClass,
    pub expected_permit: bool,
    pub permitted: bool,
    pub agree: bool,
    pub refusal_contract: Option<String>,
    pub refusal_code: Option<u32>,
    pub state_before_hash: String,
    pub state_after_hash: String,
    pub state_changed: bool,
    pub ledger: u32,
    pub counter_seed: Option<u32>,
    pub counter_before: Option<u32>,
    pub counter_after: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionReport {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub schema: u32,
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub account_code_hash: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub host_version: String,
    pub local_rule_id: u32,
    pub candidate_context_rule_id: u32,
    pub provenance: String,
    pub cases: Vec<CaseResult>,
    pub controls: Vec<ControlResult>,
    pub stateful: Option<StatefulResult>,
    pub required_classes: BTreeSet<MutationClass>,
    pub passed: bool,
    pub complete: bool,
}

pub(crate) fn scval<T: IntoVal<Env, Val>>(env: &Env, value: T) -> RuntimeResult<xdr::ScVal> {
    xdr::ScVal::try_from_val(env, &value.into_val(env))
        .map_err(|e| format!("ScVal conversion: {e:?}"))
}
pub(crate) fn scaddress(env: &Env, address: &Address) -> RuntimeResult<xdr::ScAddress> {
    match scval(env, address.clone())? {
        xdr::ScVal::Address(a) => Ok(a),
        _ => Err("expected address".into()),
    }
}
fn account_entry(env: &Env, public_key: [u8; 32]) -> RuntimeResult<()> {
    let account_id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        public_key,
    )));
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        last_modified_ledger_seq: env.ledger().sequence(),
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id,
            balance: 100_000_000,
            seq_num: xdr::SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: xdr::Thresholds([1, 1, 1, 1]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        ext: xdr::LedgerEntryExt::V0,
    });
    env.host()
        .add_ledger_entry(&key, &entry, None)
        .map_err(|e| format!("account setup: {e:?}"))
}
fn signer(env: &Env, value: &SignerSpec) -> RuntimeResult<Signer> {
    match value {
        SignerSpec::Delegated { address } => {
            stellar_strkey::Strkey::from_string(address).map_err(|_| "signer address")?;
            Ok(Signer::Delegated(Address::from_str(env, address)))
        }
        _ => Err("external signer unsupported".into()),
    }
}
fn ids(env: &Env) -> SVec<u32> {
    svec![env, LOCAL_RULE_ID]
}
pub(crate) fn auth_digest(env: &Env, payload: &[u8; 32], rule_ids: &SVec<u32>) -> Hash32 {
    let mut bytes = Bytes::from_array(env, payload);
    bytes.append(&rule_ids.to_xdr(env));
    Hash32(env.crypto().sha256(&bytes).to_array())
}
pub(crate) fn delegate_entry(
    env: &Env,
    request: &crate::SignRequest,
    key: [u8; 32],
    signature: [u8; 64],
) -> RuntimeResult<xdr::SorobanAuthorizationEntry> {
    let sig = AccountEd25519Signature {
        public_key: BytesN::from_array(env, &key),
        signature: BytesN::from_array(env, &signature),
    };
    Ok(xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: xdr::ScAddress::Account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(
                xdr::Uint256(key),
            ))),
            nonce: request.nonce.parse().map_err(|_| "nonce")?,
            signature_expiration_ledger: request.expiration_ledger,
            signature: scval(env, svec![env, sig])?,
        }),
        root_invocation: xdr::SorobanAuthorizedInvocation::from_xdr_base64(
            &request.invocation_xdr,
            xdr_limits(),
        )
        .map_err(|e| e.to_string())?,
    })
}
pub(crate) fn snapshot_hash(env: &Env) -> RuntimeResult<String> {
    let snapshot = env.to_ledger_snapshot();
    let mut entries = Vec::new();
    for (key, (entry, ttl)) in snapshot.ledger_entries {
        entries.push((
            key.to_xdr_base64(xdr_limits()).map_err(|e| e.to_string())?,
            entry
                .to_xdr_base64(xdr_limits())
                .map_err(|e| e.to_string())?,
            ttl,
        ));
    }
    entries.sort();
    hash(domains::NATIVE_STATE_ENTRIES, &entries)
}
pub(crate) fn arg(env: &Env, value: &ArgValue) -> RuntimeResult<Val> {
    match value {
        ArgValue::Address(s) => {
            stellar_strkey::Strkey::from_string(s).map_err(|_| "argument address")?;
            Ok(Address::from_str(env, s).into_val(env))
        }
        ArgValue::I128(v) => Ok(v.into_val(env)),
        ArgValue::ScvalXdr(encoded) => {
            let decoded =
                xdr::ScVal::from_xdr_base64(encoded, xdr_limits()).map_err(|e| e.to_string())?;
            if decoded
                .to_xdr_base64(xdr_limits())
                .map_err(|e| e.to_string())?
                != *encoded
            {
                return Err("noncanonical argument XDR".into());
            }
            Val::try_from_val(env, &decoded).map_err(|e| format!("argument conversion: {e:?}"))
        }
    }
}
pub(crate) fn setup(
    input: &PreparedExecution,
    case: &Case,
) -> RuntimeResult<(Env, Address, Address)> {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    setup_in(env, input, case)
}

/// Install the candidate into a caller-supplied fresh environment.
pub(crate) fn setup_in(
    env: Env,
    input: &PreparedExecution,
    case: &Case,
) -> RuntimeResult<(Env, Address, Address)> {
    let rule = &input.spec.spec().rules[input.job.request.candidate.rule_index];
    let setup_ledger = rule
        .valid_until
        .as_ref()
        .map_or(case.context.current_ledger.0, |v| {
            v.ledger.0.min(case.context.current_ledger.0)
        });
    let timestamp = input
        .job
        .ledger
        .timestamp
        .parse()
        .map_err(|_| "timestamp")?;
    let network = canonical_hex(&input.execution_network_id)?;
    env.ledger().with_mut(|l| {
        l.protocol_version = input.job.ledger.protocol_version;
        l.sequence_number = setup_ledger;
        l.timestamp = timestamp;
        l.network_id = network;
        l.base_reserve = input.job.ledger.base_reserve;
        l.min_temp_entry_ttl = input.job.ledger.min_temp_entry_ttl;
        l.min_persistent_entry_ttl = input.job.ledger.min_persistent_entry_ttl;
        l.max_entry_ttl = input.job.ledger.max_entry_ttl;
    });
    env.host()
        .with_budget(|b| b.reset_limits(200_000_000, 128 * 1024 * 1024))
        .map_err(|e| format!("budget: {e:?}"))?;
    let account = Address::from_str(&env, &input.binding.account_address);
    let policy = Address::from_str(&env, &input.policy_address);
    let owner_key = input.bootstrap.verifying_key().to_bytes();
    let owner_name = stellar_strkey::ed25519::PublicKey(owner_key).to_string();
    let owner = Address::from_str(&env, owner_name.as_str());
    account_entry(&env, owner_key)?;
    let delegate_key =
        stellar_strkey::ed25519::PublicKey::from_string(&input.binding.delegate_address)
            .map_err(|_| "delegate")?
            .0;
    account_entry(&env, delegate_key)?;
    env.register_at(&policy, input.policy_wasm.as_slice(), ());
    env.register_at(
        &account,
        input.account_wasm.as_slice(),
        (
            svec![&env, Signer::Delegated(owner.clone())],
            Map::<Address, Val>::new(&env),
        ),
    );
    let mut live = SVec::new(&env);
    for s in &case.context.rule_live_signers {
        live.push_back(signer(&env, s)?);
    }
    let mut policies = Map::<Address, Val>::new(&env);
    policies.set(policy.clone(), 0u32.into_val(&env));
    let args = svec![
        &env,
        ContextRuleType::CallContract(Address::from_str(&env, &rule.context.contract))
            .into_val(&env),
        soroban_sdk::String::from_str(&env, "local candidate").into_val(&env),
        rule.valid_until.as_ref().map(|v| v.ledger.0).into_val(&env),
        live.into_val(&env),
        policies.into_val(&env)
    ];
    let root = xdr::SorobanAuthorizedInvocation {
        function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
            contract_address: scaddress(&env, &account)?,
            function_name: "add_context_rule".try_into().map_err(|_| "method")?,
            args: args
                .iter()
                .map(|v| scval(&env, v))
                .collect::<RuntimeResult<Vec<_>>>()?
                .try_into()
                .map_err(|_| "args")?,
        }),
        sub_invocations: Default::default(),
    };
    let expiry = setup_ledger.saturating_add(64);
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(canonical_hex(&input.execution_network_id)?),
            nonce: 1,
            signature_expiration_ledger: expiry,
            invocation: root.clone(),
        });
    let payload = ozpb_domain::sha256(&preimage.to_xdr(xdr_limits()).map_err(|e| e.to_string())?);
    let rule_ids = svec![&env, 0u32];
    let digest = auth_digest(&env, &payload.0, &rule_ids);
    // Local bootstrap signatures are generated only for this fresh synthetic owner.
    // They use the same offline domain but never enter the wallet capability protocol.
    let owner_root = xdr::SorobanAuthorizedInvocation {
        function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
            contract_address: scaddress(&env, &account)?,
            function_name: "__check_auth".try_into().map_err(|_| "method")?,
            args: vec![xdr::ScVal::Bytes(
                digest.0.to_vec().try_into().map_err(|_| "digest")?,
            )]
            .try_into()
            .map_err(|_| "args")?,
        }),
        sub_invocations: Default::default(),
    };
    let owner_preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(network),
            nonce: 2,
            signature_expiration_ledger: expiry,
            invocation: owner_root.clone(),
        });
    let owner_digest = ozpb_domain::sha256(
        &owner_preimage
            .to_xdr(xdr_limits())
            .map_err(|e| e.to_string())?,
    );
    let owner_signature = input.bootstrap.sign(&owner_digest.0).to_bytes();
    let owner_auth = xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: scaddress(&env, &owner)?,
            nonce: 2,
            signature_expiration_ledger: expiry,
            signature: scval(
                &env,
                svec![
                    &env,
                    AccountEd25519Signature {
                        public_key: BytesN::from_array(&env, &owner_key),
                        signature: BytesN::from_array(&env, &owner_signature),
                    }
                ],
            )?,
        }),
        root_invocation: owner_root,
    };
    let mut signers = Map::new(&env);
    signers.set(Signer::Delegated(owner), Bytes::new(&env));
    let account_auth = xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: scaddress(&env, &account)?,
            nonce: 1,
            signature_expiration_ledger: expiry,
            signature: scval(
                &env,
                AuthPayload {
                    signers,
                    context_rule_ids: rule_ids,
                },
            )?,
        }),
        root_invocation: root,
    };
    env.set_auths(&[account_auth, owner_auth]);
    let installed: ContextRule =
        env.invoke_contract(&account, &Symbol::new(&env, "add_context_rule"), args);
    if installed.id != LOCAL_RULE_ID {
        return Err("local context-rule mapping changed".into());
    }
    env.set_auths(&[]);
    if rule
        .state
        .iter()
        .any(|s| matches!(s, StateSpec::CallCountPerInstallation { .. }))
    {
        env.as_contract(&policy, || {
            let key = PolicyStorageKey::CallCount(account.clone(), LOCAL_RULE_ID);
            match case.context.call_count_so_far {
                Some(value) => env.storage().persistent().set(&key, &value),
                None => env.storage().persistent().remove(&key),
            }
        });
    }
    env.ledger()
        .with_mut(|l| l.sequence_number = case.context.current_ledger.0);
    env.host()
        .with_budget(|b| b.reset_limits(200_000_000, 128 * 1024 * 1024))
        .map_err(|e| format!("budget: {e:?}"))?;
    Ok((env, account, policy))
}

pub(crate) fn attributed_error(env: &Env, contract: &Address, code: u32) -> RuntimeResult<bool> {
    let xdr::ScAddress::Contract(id) = scaddress(env, contract)? else {
        return Ok(false);
    };
    let topics = [
        scval(env, Symbol::new(env, "error"))?,
        xdr::ScVal::Error(xdr::ScError::Contract(code)),
    ];
    Ok(env
        .host()
        .get_diagnostic_events()
        .map_err(|e| format!("diagnostics: {e:?}"))?
        .0
        .iter()
        .any(|event| {
            let xdr::ContractEventBody::V0(body) = &event.event.body;
            event.event.type_ == xdr::ContractEventType::Diagnostic
                && event.event.contract_id.as_ref() == Some(&id)
                && body.topics.as_slice() == topics.as_slice()
        }))
}
pub(crate) fn expected_error(class: MutationClass, code: u32, account: bool) -> bool {
    match (class, account) {
        (MutationClass::DifferentContract | MutationClass::TimeBoundary, true) => code == 3002,
        (
            MutationClass::WrongSigner
            | MutationClass::SignerBoundary
            | MutationClass::StrictSetMutation,
            true,
        ) => code == 3016,
        (MutationClass::ZeroSigners, false) => code == 1,
        (MutationClass::WrongSigner | MutationClass::SignerBoundary, false) => {
            matches!(code, 1..=3)
        }
        (MutationClass::StrictSetMutation, false) => code == 3,
        (MutationClass::DifferentFunction, false) => code == 5,
        (
            MutationClass::ArgEquality
            | MutationClass::NumericBoundary
            | MutationClass::DifferentAddressArg
            | MutationClass::ArgArity
            | MutationClass::TypeConfusion
            | MutationClass::TupleCrossProduct,
            false,
        ) => code == 6,
        (MutationClass::CallCountBoundary, false) => code == 7,
        (MutationClass::MissingState, false) => code == 8,
        (MutationClass::TimeBoundary, false) => code == 9,
        _ => false,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlResult {
    pub name: String,
    pub passed: bool,
    pub refusal_stage: String,
    pub state_before_hash: String,
    pub state_after_hash: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct StatefulResult {
    pub successful_calls: u32,
    pub counter_before: u32,
    pub counter_after: u32,
    pub overflow_refused: bool,
    pub overflow_rolled_back: bool,
    pub partial_rollback_refused: bool,
    pub partial_rollback_preserved_counter: bool,
    pub passed: bool,
}
#[derive(Clone, Copy)]
enum Mutation {
    None,
    SignatureBit,
    Nonce,
    Payload,
    RuleId,
    DoubleContext,
}
struct Attempt {
    result: Result<(), Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
    auth: Option<xdr::SorobanAuthorizationEntry>,
    before: String,
    after: String,
    counter_before: Option<u32>,
    counter_after: Option<u32>,
    diagnostics: String,
    policy_attributed: bool,
    account_attributed: bool,
}
pub(crate) fn counter(env: &Env, account: &Address, policy: &Address) -> Option<u32> {
    env.as_contract(policy, || {
        env.storage()
            .persistent()
            .get(&PolicyStorageKey::CallCount(account.clone(), LOCAL_RULE_ID))
    })
}
struct Runner<'a, S> {
    input: &'a PreparedExecution,
    capability: &'a mut S,
    request_count: u32,
    started: Instant,
}
impl<S: DelegateSigner> Runner<'_, S> {
    #[allow(clippy::too_many_arguments)]
    fn attempt(
        &mut self,
        env: &Env,
        account: &Address,
        policy: &Address,
        case: &Case,
        case_id: &str,
        mutation: Mutation,
        reused: Option<xdr::SorobanAuthorizationEntry>,
    ) -> RuntimeResult<Attempt> {
        if self.started.elapsed() > crate::DEADLINE {
            return Err("execution deadline exceeded".into());
        }
        env.host()
            .with_budget(|b| b.reset_limits(200_000_000, 128 * 1024 * 1024))
            .map_err(|e| format!("budget: {e:?}"))?;
        let payload = canonical_hash(
            domains::NATIVE_CASE_PAYLOAD,
            &(self.input.binding.run_hash.clone(), case_id, case),
        )
        .map_err(|e| e.to_string())?;
        let rule_ids = if matches!(mutation, Mutation::DoubleContext) {
            svec![env, LOCAL_RULE_ID, LOCAL_RULE_ID]
        } else {
            ids(env)
        };
        let signed_rule_ids = if matches!(mutation, Mutation::RuleId) {
            svec![env, 0u32]
        } else {
            rule_ids.clone()
        };
        let digest = auth_digest(env, &payload.0, &signed_rule_ids);
        let mut signers = Map::new(env);
        for s in &case.context.authenticated_signers {
            signers.set(signer(env, s)?, Bytes::new(env));
        }
        let mut auth = reused;
        if auth.is_none() && case.context.authenticated_signers.iter().any(|s| matches!(s, SignerSpec::Delegated { address } if address == &self.input.binding.delegate_address)) {
            self.request_count += 1;
            let request = make_sign_request(&self.input.binding, self.request_count, case_id, digest, 1000 + i64::from(self.request_count), case.context.current_ledger.0.checked_add(64).ok_or("signature expiry overflow")?)?;
            let answer = self.capability.sign(&request)?;
            let mut signature = verify_signature_response(&request, &answer)?;
            if matches!(mutation, Mutation::SignatureBit) { signature[0] ^= 1; }
            let mut entry = delegate_entry(env, &request, canonical_hex(&answer.public_key_hex)?, signature)?;
            if matches!(mutation, Mutation::Nonce) {
                if let xdr::SorobanCredentials::Address(ref mut credentials) = entry.credentials { credentials.nonce += 1; }
            }
            auth = Some(entry);
        }
        let mut args = SVec::new(env);
        for a in &case.invocation.args {
            args.push_back(arg(env, a)?);
        }
        let mut contexts = svec![
            env,
            Context::Contract(ContractContext {
                contract: Address::from_str(env, &case.invocation.contract),
                fn_name: Symbol::new(env, &case.invocation.fn_name),
                args,
            })
        ];
        if matches!(mutation, Mutation::DoubleContext) {
            contexts.push_back(contexts.get(0).ok_or("missing context")?);
        }
        let counter_before = counter(env, account, policy);
        let before = snapshot_hash(env)?;
        env.set_auths(&auth.clone().into_iter().collect::<Vec<_>>());
        let mut actual_payload = payload.0;
        if matches!(mutation, Mutation::Payload) {
            actual_payload[0] ^= 1;
        }
        let actual_rule_ids = rule_ids;
        let result = env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            account,
            &BytesN::from_array(env, &actual_payload),
            AuthPayload {
                signers,
                context_rule_ids: actual_rule_ids,
            }
            .into_val(env),
            &contexts,
        );
        // Capture refusal attribution before the state observation enters another context.
        let diagnostics = format!(
            "{:?}",
            env.host()
                .get_diagnostic_events()
                .map_err(|e| format!("diagnostics: {e:?}"))?
        );
        let code = match &result {
            Err(Ok(e)) if e.is_type(xdr::ScErrorType::Contract) => Some(e.get_code()),
            _ => None,
        };
        let policy_attributed = if let Some(code) = code {
            attributed_error(env, policy, code)?
        } else {
            false
        };
        let account_attributed = if let Some(code) = code {
            attributed_error(env, account, code)?
        } else {
            false
        };
        let after = snapshot_hash(env)?;
        let counter_after = counter(env, account, policy);
        Ok(Attempt {
            result,
            auth,
            before,
            after,
            counter_before,
            counter_after,
            diagnostics,
            policy_attributed,
            account_attributed,
        })
    }
}
fn auth_refused(attempt: &Attempt, expected_stage: &str, code: xdr::ScErrorCode) -> bool {
    let expected = soroban_sdk::Error::from_type_and_code(xdr::ScErrorType::Auth, code);
    let correct_error = matches!(&attempt.result, Err(Ok(e)) if *e == expected);
    correct_error && attempt.diagnostics.contains(expected_stage) && attempt.before == attempt.after
}

fn refusal_stage(attempt: &Attempt) -> String {
    let markers = [
        "failed account authentication",
        "Unauthorized function call",
        "nonce already exists for address",
    ];
    let found: Vec<_> = markers
        .into_iter()
        .filter(|m| attempt.diagnostics.contains(m))
        .collect();
    if found.len() == 1 {
        found[0].into()
    } else {
        "unattributed".into()
    }
}

pub fn execute(
    input: &PreparedExecution,
    signer_capability: &mut impl DelegateSigner,
) -> RuntimeResult<ExecutionReport> {
    let mut runner = Runner {
        input,
        capability: signer_capability,
        request_count: 0,
        started: Instant::now(),
    };
    let mut results = Vec::new();
    for (index, case) in input.suite.iter().enumerate() {
        let (env, account, policy) = setup(input, case)?;
        let case_id = format!("case:{index}");
        let attempt = runner.attempt(
            &env,
            &account,
            &policy,
            case,
            &case_id,
            Mutation::None,
            None,
        )?;
        let permitted = attempt.result.is_ok();
        let mut refusal_contract = None;
        let mut refusal_code = None;
        let attributed = if let Err(Ok(error)) = &attempt.result {
            if error.is_type(xdr::ScErrorType::Contract) {
                let code = error.get_code();
                refusal_code = Some(code);
                if expected_error(case.class, code, false) && attempt.policy_attributed {
                    refusal_contract = Some(input.policy_address.clone());
                    true
                } else if expected_error(case.class, code, true) && attempt.account_attributed {
                    refusal_contract = Some(input.binding.account_address.clone());
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        let counter_agrees = !permitted
            || match attempt.counter_before {
                Some(before) => before.checked_add(1) == attempt.counter_after,
                None => attempt.counter_after.is_none(),
            };
        results.push(CaseResult {
            case_id,
            label: case.label.clone(),
            class: case.class,
            expected_permit: case.expect_permit,
            permitted,
            agree: permitted == case.expect_permit
                && (permitted || attributed)
                && (permitted || attempt.before == attempt.after)
                && counter_agrees,
            refusal_contract,
            refusal_code,
            state_changed: attempt.before != attempt.after,
            state_before_hash: attempt.before,
            state_after_hash: attempt.after,
            ledger: case.context.current_ledger.0,
            counter_seed: case.context.call_count_so_far,
            counter_before: attempt.counter_before,
            counter_after: attempt.counter_after,
        });
    }
    let mut original = input
        .suite
        .iter()
        .find(|c| c.class == MutationClass::Original && c.expect_permit)
        .ok_or("missing permitted baseline")?
        .clone();
    original.context.call_count_so_far = Some(0);
    let mut controls = Vec::new();
    for (name, mutation, stage) in [
        (
            "signature_bit",
            Mutation::SignatureBit,
            "failed account authentication",
        ),
        (
            "nonce_binding",
            Mutation::Nonce,
            "failed account authentication",
        ),
        (
            "payload_binding",
            Mutation::Payload,
            "Unauthorized function call",
        ),
        (
            "context_rule_binding",
            Mutation::RuleId,
            "Unauthorized function call",
        ),
    ] {
        let (env, account, policy) = setup(input, &original)?;
        let attempt = runner.attempt(
            &env,
            &account,
            &policy,
            &original,
            &format!("control:{name}"),
            mutation,
            None,
        )?;
        controls.push(ControlResult {
            name: name.into(),
            passed: auth_refused(&attempt, stage, xdr::ScErrorCode::InvalidAction),
            refusal_stage: refusal_stage(&attempt),
            state_before_hash: attempt.before,
            state_after_hash: attempt.after,
        });
    }
    let (env, account, policy) = setup(input, &original)?;
    let first = runner.attempt(
        &env,
        &account,
        &policy,
        &original,
        "control:nonce_replay",
        Mutation::None,
        None,
    )?;
    let replay = runner.attempt(
        &env,
        &account,
        &policy,
        &original,
        "control:nonce_replay",
        Mutation::None,
        first.auth,
    )?;
    controls.push(ControlResult {
        name: "nonce_replay".into(),
        passed: first.result.is_ok()
            && auth_refused(
                &replay,
                "nonce already exists for address",
                xdr::ScErrorCode::ExistingValue,
            ),
        refusal_stage: refusal_stage(&replay),
        state_before_hash: replay.before,
        state_after_hash: replay.after,
    });
    let max_calls = input.spec.spec().rules[input.job.request.candidate.rule_index]
        .state
        .iter()
        .map(|s| match s {
            StateSpec::CallCountPerInstallation { max_calls } => *max_calls,
        })
        .next();
    let stateful = if let Some(max_calls) = max_calls {
        let (env, account, policy) = setup(input, &original)?;
        let counter_before =
            counter(&env, &account, &policy).ok_or("stateful setup missing counter")?;
        let mut successful_calls = 0;
        let mut sequential_counts = true;
        let mut partial_rollback_refused = false;
        let mut partial_rollback_preserved_counter = false;
        for index in 0..max_calls {
            if index == max_calls - 1 {
                // The first context spends the final call; the second must refuse,
                // rolling the first write and the consumed nonce back atomically.
                let partial = runner.attempt(
                    &env,
                    &account,
                    &policy,
                    &original,
                    "sequence:partial_rollback",
                    Mutation::DoubleContext,
                    None,
                )?;
                partial_rollback_refused = matches!(partial.result, Err(Ok(e)) if e == soroban_sdk::Error::from_contract_error(7))
                    && partial.policy_attributed;
                partial_rollback_preserved_counter = partial.before == partial.after
                    && partial.counter_before == Some(index)
                    && partial.counter_after == Some(index);
            }
            let a = runner.attempt(
                &env,
                &account,
                &policy,
                &original,
                &format!("sequence:{index}"),
                Mutation::None,
                None,
            )?;
            if a.result.is_ok() {
                successful_calls += 1;
            }
            sequential_counts &=
                a.counter_before == Some(index) && a.counter_after == Some(index + 1);
        }
        let overflow = runner.attempt(
            &env,
            &account,
            &policy,
            &original,
            "sequence:overflow",
            Mutation::None,
            None,
        )?;
        let overflow_refused = matches!(overflow.result, Err(Ok(e)) if e == soroban_sdk::Error::from_contract_error(7))
            && overflow.policy_attributed;
        let overflow_rolled_back = overflow.before == overflow.after;
        let counter_after =
            counter(&env, &account, &policy).ok_or("stateful counter disappeared")?;
        Some(StatefulResult {
            successful_calls,
            counter_before,
            counter_after,
            overflow_refused,
            overflow_rolled_back,
            partial_rollback_refused,
            partial_rollback_preserved_counter,
            passed: counter_before == 0
                && counter_after == max_calls
                && successful_calls == max_calls
                && sequential_counts
                && overflow_refused
                && overflow_rolled_back
                && partial_rollback_refused
                && partial_rollback_preserved_counter,
        })
    } else {
        None
    };
    let passed = !results.is_empty()
        && results.iter().all(|r| r.agree)
        && controls.iter().all(|c| c.passed)
        && stateful.as_ref().is_none_or(|s| s.passed);
    Ok(ExecutionReport {
        frame_type: "result".into(), schema: 1, binding: input.binding.clone(), execution_network_id: input.execution_network_id.clone(),
        account_code_hash: input.account_code_hash.clone(), policy_address: input.policy_address.clone(), policy_code_hash: input.policy_code_hash.clone(),
        host_version: "soroban-env-host/30.0.0".into(), local_rule_id: LOCAL_RULE_ID, candidate_context_rule_id: input.candidate_context_rule_id,
        provenance: "fresh_local_candidate_boundary_states; counter seeds and ledgers are synthetic; no wallet ownership or live state claim".into(),
        cases: results, controls, stateful, required_classes: ozpb_harness::expected_classes(&input.spec).remove(&input.job.request.candidate.rule_index).ok_or("coverage requirements")?, passed, complete: false,
    })
}

#[cfg(test)]
mod protocol30_compatibility {
    use super::*;

    struct Capability(SigningKey);
    impl DelegateSigner for Capability {
        fn sign(
            &mut self,
            request: &crate::SignRequest,
        ) -> RuntimeResult<crate::SignatureResponse> {
            Ok(crate::SignatureResponse {
                frame_type: "signature".into(),
                request_id: request.request_id.clone(),
                public_key_hex: hex::encode(self.0.verifying_key().to_bytes()),
                signature_hex: hex::encode(
                    self.0
                        .sign(&hex::decode(&request.digest_hex).unwrap())
                        .to_bytes(),
                ),
            })
        }
    }

    #[test]
    #[ignore = "requires freshly generated SDK28 policy Wasm; run scripts/test-native-execution.sh"]
    fn sdk28_generated_wasm_refuses_a_muxed_form_of_allowed_contract_address_on_host30() {
        let job: NativeJob = serde_json::from_slice(
            &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
        )
        .unwrap();
        let input = prepare(job).unwrap();
        let original = input
            .suite
            .iter()
            .find(|case| case.class == MutationClass::Original)
            .unwrap()
            .clone();
        let mut capability = Capability(SigningKey::from_bytes(&[42; 32]));
        let mut runner = Runner {
            input: &input,
            capability: &mut capability,
            request_count: 0,
            started: Instant::now(),
        };
        let (env, account, policy) = setup(&input, &original).unwrap();
        let allowed = runner
            .attempt(
                &env,
                &account,
                &policy,
                &original,
                "p30:plain",
                Mutation::None,
                None,
            )
            .unwrap();
        assert!(
            allowed.result.is_ok(),
            "plain address control: {:?}",
            allowed.result
        );

        let mut muxed = original;
        let account_id =
            stellar_strkey::Contract::from_string(&input.binding.account_address).unwrap();
        let value = xdr::ScVal::Address(xdr::ScAddress::MuxedContract(xdr::MuxedContract {
            id: 7,
            contract_id: xdr::ContractId(xdr::Hash(account_id.0)),
        }));
        muxed.invocation.args[0] = ArgValue::ScvalXdr(value.to_xdr_base64(xdr_limits()).unwrap());
        let (env, account, policy) = setup(&input, &muxed).unwrap();
        let denied = runner
            .attempt(
                &env,
                &account,
                &policy,
                &muxed,
                "p30:muxed",
                Mutation::None,
                None,
            )
            .unwrap();
        assert!(
            matches!(&denied.result,Err(Ok(error)) if *error == soroban_sdk::Error::from_contract_error(6)),
            "{:?}",
            denied.result
        );
        assert!(denied.policy_attributed);
        assert_eq!(denied.before, denied.after);
        assert_eq!(denied.counter_before, denied.counter_after);
    }
}
