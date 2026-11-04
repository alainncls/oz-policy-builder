//! Captured-target execution: the candidate's exact native Stellar Asset Contract transfer,
//! authorized through the pinned account Wasm and the generated policy Wasm, against
//! endpoint-reported target state. The account/policy installation is fresh local state;
//! the target entries are byte-exact captures served by a strict snapshot source. Once the
//! candidate is installed, a read of any key that is neither captured, candidate state, nor an
//! expected new nonce is a host error and is logged, never answered as absent. This is an
//! offline counterfactual: it proves neither owner authority, fees, reserves nor live-network
//! behavior, and `complete` stays false.

use crate::execution::{
    attributed_error, auth_digest, counter, delegate_entry, hash, scaddress, scval, setup_in,
    LOCAL_RULE_ID,
};
use crate::wire::{AuthPayload, PolicyStorageKey, Signer};
use crate::{
    canonical_hex, make_sign_request, offline_network, prepare, verify_signature_response,
    xdr_limits, DelegateSigner, NativeJob, OfflineBinding, PreparedExecution, RuntimeResult,
};
use ozpb_domain::{domains, TargetCapture};
use ozpb_harness::{Case, MutationClass};
use ozpb_policy_spec::{Constraint, SignerSpec, StateSpec};
use serde::{Deserialize, Serialize};
use soroban_sdk::testutils::{EnvTestConfig, HostError, SnapshotSource, SnapshotSourceInput};
use soroban_sdk::xdr::{self, ReadXdr, WriteXdr};
use soroban_sdk::{Address, Bytes, Env, Map, Symbol, TryFromVal, Val, Vec as SVec};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Instant;

/// Signature expiry offset from the captured ledger, as in the account-Wasm layer.
const SIGNATURE_WINDOW: u32 = 64;
/// First account nonce used by target cases; setup consumes nonces 1 and 2.
const ACCOUNT_NONCE_BASE: i64 = 100;
/// Delegate nonces follow the native worker's sequence: 1000 + request number.
const DELEGATE_NONCE_BASE: i64 = 1000;
const STORAGE_MODE: &str = "strict_snapshot_source";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedTargetJob {
    pub schema: u32,
    pub native: NativeJob,
    pub capture: TargetCapture,
}

#[derive(Clone)]
struct CapturedEntry {
    key: xdr::LedgerKey,
    entry: xdr::LedgerEntry,
    live_until: Option<u32>,
    writable: bool,
}

#[derive(Default)]
struct SourceState {
    /// False while the candidate is installed: unknown keys are then fresh candidate state.
    strict: bool,
    expected_absent: BTreeSet<xdr::LedgerKey>,
    captured_reads: BTreeSet<xdr::LedgerKey>,
    undeclared: BTreeSet<xdr::LedgerKey>,
}

/// Serves captured entries byte for byte. Before `strict`, a captured key is refused (the
/// candidate must not touch target state) and any other key is absent. After `strict`, only
/// captured keys and the exact expected nonce keys are answered; anything else is an error.
/// The log survives host rollback, so a refused read in a failed call is still reported.
struct StrictSource {
    captured: BTreeMap<xdr::LedgerKey, (Rc<xdr::LedgerEntry>, Option<u32>)>,
    state: RefCell<SourceState>,
}

impl SnapshotSource for StrictSource {
    fn get(
        &self,
        key: &Rc<xdr::LedgerKey>,
    ) -> Result<Option<(Rc<xdr::LedgerEntry>, Option<u32>)>, HostError> {
        let refused = || {
            HostError::from(soroban_sdk::Error::from_type_and_code(
                xdr::ScErrorType::Storage,
                xdr::ScErrorCode::MissingValue,
            ))
        };
        let mut state = self.state.borrow_mut();
        if let Some(found) = self.captured.get(key.as_ref()) {
            if !state.strict {
                state.undeclared.insert((**key).clone());
                return Err(refused());
            }
            state.captured_reads.insert((**key).clone());
            return Ok(Some(found.clone()));
        }
        if !state.strict || state.expected_absent.contains(key.as_ref()) {
            return Ok(None);
        }
        state.undeclared.insert((**key).clone());
        Err(refused())
    }
}

#[derive(Clone, Debug, Serialize)]
struct PlannedCase {
    case_id: String,
    case: Case,
    /// Exact target call, canonical `InvokeContractArgs` XDR.
    call_xdr: String,
    /// Generated-policy error a denial must be attributed to; `None` for the original.
    expected_policy_code: Option<u32>,
}

pub struct PreparedCaptured {
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub capture_hash: String,
    pub candidate_state_hash: String,
    pub target_contract: String,
    pub observed_ledger: u32,
    execution: PreparedExecution,
    entries: Vec<CapturedEntry>,
    cases: Vec<PlannedCase>,
    sender_balance_key: xdr::LedgerKey,
    recipient_key: xdr::LedgerKey,
    amount: i128,
    max_entry_ttl: u32,
}

#[derive(Clone, Debug, Serialize)]
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
    /// Cases that request exactly one delegate signature each, in this order.
    pub signing_case_ids: Vec<String>,
    pub signature_expiration_ledgers: BTreeSet<u32>,
}

impl CapturedPreparedFrame {
    pub fn from_prepared(input: &PreparedCaptured) -> RuntimeResult<Self> {
        let expiry = input
            .observed_ledger
            .checked_add(SIGNATURE_WINDOW)
            .ok_or("signature expiry overflow")?;
        Ok(Self {
            frame_type: "prepared".into(),
            schema: 1,
            layer: "captured_target".into(),
            binding: input.binding.clone(),
            execution_network_id: input.execution_network_id.clone(),
            account_code_hash: input.execution.account_code_hash.clone(),
            policy_address: input.execution.policy_address.clone(),
            policy_code_hash: input.execution.policy_code_hash.clone(),
            local_rule_id: LOCAL_RULE_ID,
            candidate_context_rule_id: input.execution.candidate_context_rule_id,
            capture_hash: input.capture_hash.clone(),
            candidate_state_hash: input.candidate_state_hash.clone(),
            target_contract: input.target_contract.clone(),
            observed_ledger: input.observed_ledger,
            case_ids: input.cases.iter().map(|c| c.case_id.clone()).collect(),
            signing_case_ids: input
                .cases
                .iter()
                .filter(|c| !c.case.context.authenticated_signers.is_empty())
                .map(|c| c.case_id.clone())
                .collect(),
            signature_expiration_ledgers: BTreeSet::from([expiry]),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CapturedCaseResult {
    pub case_id: String,
    pub label: String,
    pub class: MutationClass,
    pub expected_permit: bool,
    pub permitted: bool,
    pub agree: bool,
    pub refusal_contract: Option<String>,
    pub refusal_code: Option<u32>,
    pub host_error: Option<String>,
    pub state_before_hash: String,
    pub state_after_hash: String,
    /// Sender SAC balance change, decimal i128.
    pub sender_delta: String,
    /// Recipient classic native balance change, decimal i128.
    pub recipient_delta: String,
    pub counter_seed: Option<u32>,
    pub counter_before: Option<u32>,
    pub counter_after: Option<u32>,
    pub captured_reads: Vec<String>,
    pub created_keys: Vec<String>,
    pub written_keys: Vec<String>,
    pub ttl_extended_keys: Vec<String>,
    pub undeclared_reads: Vec<String>,
    pub unexpected_changes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapturedReport {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub schema: u32,
    pub layer: String,
    pub binding: OfflineBinding,
    pub execution_network_id: String,
    pub capture_hash: String,
    pub candidate_state_hash: String,
    pub capture_provenance: String,
    pub observed_ledger: u32,
    pub target_contract: String,
    pub account_code_hash: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub host_version: String,
    pub local_rule_id: u32,
    pub candidate_context_rule_id: u32,
    pub storage_mode: String,
    pub provenance: String,
    pub cases: Vec<CapturedCaseResult>,
    pub passed: bool,
    pub complete: bool,
}

fn refuse(reason: &str) -> String {
    format!("captured target refused: {reason}")
}

fn decode<T: ReadXdr + WriteXdr>(encoded: &str, what: &str) -> RuntimeResult<T> {
    let value = T::from_xdr_base64(encoded, xdr_limits())
        .map_err(|_| refuse(&format!("{what} is not valid XDR")))?;
    if encode(&value)? != encoded {
        return Err(refuse(&format!("{what} is not canonical XDR")));
    }
    Ok(value)
}

fn encode<T: WriteXdr>(value: &T) -> RuntimeResult<String> {
    value.to_xdr_base64(xdr_limits()).map_err(|e| e.to_string())
}

fn native_asset_contract(network: [u8; 32]) -> RuntimeResult<xdr::ScAddress> {
    let preimage = xdr::HashIdPreimage::ContractId(xdr::HashIdPreimageContractId {
        network_id: xdr::Hash(network),
        contract_id_preimage: xdr::ContractIdPreimage::Asset(xdr::Asset::Native),
    });
    let bytes = preimage.to_xdr(xdr_limits()).map_err(|e| e.to_string())?;
    Ok(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
        ozpb_domain::sha256(&bytes).0,
    ))))
}

fn strkey(address: &xdr::ScAddress) -> RuntimeResult<String> {
    match address {
        xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(id))) => {
            Ok(stellar_strkey::Contract(*id)
                .to_string()
                .as_str()
                .to_owned())
        }
        xdr::ScAddress::Account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(
            xdr::Uint256(key),
        ))) => Ok(stellar_strkey::ed25519::PublicKey(*key)
            .to_string()
            .as_str()
            .to_owned()),
        _ => Err(refuse("unsupported address kind")),
    }
}

fn transfer_call(
    call: &xdr::InvokeContractArgs,
    amount: i128,
) -> RuntimeResult<xdr::InvokeContractArgs> {
    let mut args = call.args.to_vec();
    args[2] = xdr::ScVal::I128(xdr::Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    });
    Ok(xdr::InvokeContractArgs {
        contract_address: call.contract_address.clone(),
        function_name: call.function_name.clone(),
        args: args.try_into().map_err(|_| "argument vector")?,
    })
}

fn contract_data_key(
    contract: &xdr::ScAddress,
    key: xdr::ScVal,
    durability: xdr::ContractDataDurability,
) -> xdr::LedgerKey {
    xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
        contract: contract.clone(),
        key,
        durability,
    })
}

fn nonce_key(address: xdr::ScAddress, nonce: i64) -> xdr::LedgerKey {
    contract_data_key(
        &address,
        xdr::ScVal::LedgerKeyNonce(xdr::ScNonceKey { nonce }),
        xdr::ContractDataDurability::Temporary,
    )
}

/// Validate every capture binding before any Wasm runs or any signature is requested.
pub fn prepare_captured(job: CapturedTargetJob) -> RuntimeResult<PreparedCaptured> {
    let capture = &job.capture;
    if job.schema != 1 || capture.schema != 1 || capture.provenance != "rpc_reported" {
        return Err(refuse("unsupported job or capture schema"));
    }
    let mut execution = prepare(job.native.clone())?;
    let ledger = &job.native.ledger;
    let observed = capture.observed_ledger;
    let source_network = canonical_hex::<32>(&capture.network_id)?;
    if capture.network_id != execution.binding.source_network_id || observed != ledger.sequence {
        return Err(refuse(
            "capture network or ledger differs from the native job",
        ));
    }
    // The candidate runs the pinned account Wasm, so the observed account must run it too.
    if capture.account_code_hash != execution.account_code_hash {
        return Err(refuse(
            "captured account does not execute the pinned account Wasm",
        ));
    }

    let header: xdr::LedgerHeaderHistoryEntry = decode(&capture.header_xdr, "ledger header")?;
    let header_hash = ozpb_domain::sha256(
        &header
            .header
            .to_xdr(xdr_limits())
            .map_err(|e| e.to_string())?,
    );
    if header.hash.0 != header_hash.0
        || header.header.ledger_seq != observed
        || header.header.ledger_version != ledger.protocol_version
        || header.header.scp_value.close_time.0.to_string() != ledger.timestamp
        || header.header.base_reserve != ledger.base_reserve
    {
        return Err(refuse(
            "ledger header does not hash to or describe the job ledger",
        ));
    }

    let archival = &capture.state_archival;
    let archival_key: xdr::LedgerKey = decode(&archival.key_xdr, "state-archival key")?;
    let archival_data: xdr::LedgerEntryData = decode(&archival.data_xdr, "state-archival entry")?;
    let xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) =
        &archival_data
    else {
        return Err(refuse("state-archival entry holds other data"));
    };
    if archival_key
        != xdr::LedgerKey::ConfigSetting(xdr::LedgerKeyConfigSetting {
            config_setting_id: xdr::ConfigSettingId::StateArchival,
        })
        || archival_data.to_key() != archival_key
        || archival.last_modified_ledger > observed
        || archival.live_until_ledger.is_some()
        || settings.min_temporary_ttl != ledger.min_temp_entry_ttl
        || settings.min_persistent_ttl != ledger.min_persistent_entry_ttl
        || settings.max_entry_ttl != ledger.max_entry_ttl
    {
        return Err(refuse(
            "state-archival configuration differs from the job ledger",
        ));
    }

    // Supported shape: transfer(candidate account, existing G, positive i128) on the
    // source network's native asset contract.
    let call: xdr::InvokeContractArgs = decode(&capture.invocation_xdr, "invocation")?;
    let sac = native_asset_contract(source_network)?;
    let target_contract = strkey(&sac)?;
    let [xdr::ScVal::Address(sender), xdr::ScVal::Address(recipient @ xdr::ScAddress::Account(recipient_id)), xdr::ScVal::I128(amount)] =
        call.args.as_slice()
    else {
        return Err(refuse(
            "only transfer(account, G recipient, i128) is supported",
        ));
    };
    let amount = i128::from(amount);
    if call.contract_address != sac
        || call.function_name.as_slice() != b"transfer"
        || strkey(sender)? != execution.binding.account_address
        || amount <= 0
        || amount >= i128::from(i64::MAX)
    {
        return Err(refuse(
            "invocation is not a positive native transfer from the candidate account",
        ));
    }

    let spec = execution.spec.spec();
    let rule = &spec.rules[execution.job.request.candidate.rule_index];
    let [allowed] = rule.allowed_calls.as_slice() else {
        return Err(refuse("exactly one allowed call tuple is supported"));
    };
    let amount_text = amount.to_string();
    if rule.context.contract != target_contract
        || allowed.fn_name != "transfer"
        || !allowed.args.iter().any(|a| {
            a.index == 2
                && matches!(&a.constraint, Constraint::EqI128 { value } if *value == amount_text)
        })
    {
        return Err(refuse(
            "selected rule is not an exact-amount transfer on the captured native contract",
        ));
    }
    let originals: Vec<_> = execution
        .suite
        .iter()
        .filter(|c| c.class == MutationClass::Original && c.expect_permit)
        .collect();
    let [original] = originals.as_slice() else {
        return Err(refuse("exactly one permitted original case is supported"));
    };
    let derived_args = original
        .invocation
        .args
        .iter()
        .map(|a| match a {
            ozpb_evaluator::ArgValue::Address(s) => Ok(s.clone()),
            ozpb_evaluator::ArgValue::I128(v) => Ok(v.to_string()),
            ozpb_evaluator::ArgValue::ScvalXdr(_) => Err(refuse("unsupported argument type")),
        })
        .collect::<RuntimeResult<Vec<_>>>()?;
    if original.invocation.contract != target_contract
        || original.invocation.fn_name != "transfer"
        || derived_args
            != [
                execution.binding.account_address.clone(),
                strkey(recipient)?,
                amount_text.clone(),
            ]
    {
        return Err(refuse(
            "captured invocation differs from the candidate's original call",
        ));
    }

    let recorded: xdr::SorobanAuthorizationEntry =
        decode(&capture.recording_auth_xdr, "recorded authorization")?;
    let recorded_address = match &recorded.credentials {
        xdr::SorobanCredentials::Address(c) => &c.address,
        xdr::SorobanCredentials::AddressV2(c) => &c.address,
        _ => return Err(refuse("recorded authorization is not address-bound")),
    };
    if recorded_address != sender
        || recorded.root_invocation.function
            != xdr::SorobanAuthorizedFunction::ContractFn(call.clone())
        || !recorded.root_invocation.sub_invocations.is_empty()
    {
        return Err(refuse(
            "recorded authorization root is not exactly the account's transfer",
        ));
    }

    // The closure: exactly the SAC instance (read-only), the sender balance and the recipient
    // account (both read-write). Anything more or less is outside the supported scope.
    let instance_key = contract_data_key(
        &sac,
        xdr::ScVal::LedgerKeyContractInstance,
        xdr::ContractDataDurability::Persistent,
    );
    let sender_balance_key = contract_data_key(
        &sac,
        xdr::ScVal::Vec(Some(
            vec![
                xdr::ScVal::Symbol("Balance".try_into().map_err(|_| "symbol")?),
                xdr::ScVal::Address(sender.clone()),
            ]
            .try_into()
            .map_err(|_| "balance key")?,
        )),
        xdr::ContractDataDurability::Persistent,
    );
    let recipient_key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: recipient_id.clone(),
    });
    let expected_read_only = BTreeSet::from([encode(&instance_key)?]);
    let expected_read_write =
        BTreeSet::from([encode(&sender_balance_key)?, encode(&recipient_key)?]);
    let strictly_sorted = |keys: &[String]| keys.windows(2).all(|w| w[0] < w[1]);
    if !strictly_sorted(&capture.read_only_keys)
        || !strictly_sorted(&capture.read_write_keys)
        || capture
            .read_only_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_read_only
        || capture
            .read_write_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_read_write
        || capture.entries.len() != 3
        || !capture
            .entries
            .windows(2)
            .all(|w| w[0].key_xdr < w[1].key_xdr)
    {
        return Err(refuse(
            "footprint is not exactly the native transfer closure (incomplete, extra or overlapping keys)",
        ));
    }
    let mut entries = Vec::new();
    for captured in &capture.entries {
        let key: xdr::LedgerKey = decode(&captured.key_xdr, "captured key")?;
        let data: xdr::LedgerEntryData = decode(&captured.data_xdr, "captured entry")?;
        let writable = if expected_read_only.contains(&captured.key_xdr) {
            false
        } else if expected_read_write.contains(&captured.key_xdr) {
            true
        } else {
            return Err(refuse("captured entry outside the declared footprint"));
        };
        let has_ttl = matches!(
            key,
            xdr::LedgerKey::ContractData(_) | xdr::LedgerKey::ContractCode(_)
        );
        if data.to_key() != key
            || captured.last_modified_ledger > observed
            || has_ttl != captured.live_until_ledger.is_some()
            // A submission based on this capture lands at L + 1 or later, where an entry
            // living only until L is archived.
            || captured.live_until_ledger.is_some_and(|ttl| ttl <= observed)
        {
            return Err(refuse(
                "captured entry is mismatched, from a later ledger, or not live",
            ));
        }
        if key == instance_key
            && !matches!(&data, xdr::LedgerEntryData::ContractData(d)
                if matches!(&d.val, xdr::ScVal::ContractInstance(i)
                    if i.executable == xdr::ContractExecutable::StellarAsset))
        {
            return Err(refuse(
                "native contract instance is not the built-in asset contract",
            ));
        }
        entries.push(CapturedEntry {
            key,
            // The outer extension (RPC's `extXdr`, including any sponsor) is not captured;
            // it is rebuilt as V0.
            entry: xdr::LedgerEntry {
                last_modified_ledger_seq: captured.last_modified_ledger,
                data,
                ext: xdr::LedgerEntryExt::V0,
            },
            live_until: captured.live_until_ledger,
            writable,
        });
    }

    // Three cases, each from identical initial state at the captured ledger.
    let counted = rule
        .state
        .iter()
        .any(|s| matches!(s, StateSpec::CallCountPerInstallation { .. }));
    let mut base = (*original).clone();
    base.context.current_ledger.0 = observed;
    base.context.call_count_so_far = counted.then_some(0);
    let denied_amount = amount.checked_add(1).ok_or("amount overflow")?;
    let mut argument = base.clone();
    argument.class = MutationClass::ArgEquality;
    argument.label = format!("captured amount[2] = {denied_amount}");
    argument.expect_permit = false;
    argument.invocation.args[2] = ozpb_evaluator::ArgValue::I128(denied_amount);
    let mut unsigned = base.clone();
    unsigned.class = MutationClass::ZeroSigners;
    unsigned.label = "captured call with no authenticated signers".into();
    unsigned.expect_permit = false;
    unsigned.context.authenticated_signers.clear();
    base.label = "captured original call".into();
    let cases = vec![
        PlannedCase {
            case_id: "target:original:0".into(),
            case: base.clone(),
            call_xdr: encode(&call)?,
            expected_policy_code: None,
        },
        PlannedCase {
            case_id: "target:argument-denial:0".into(),
            case: argument,
            call_xdr: encode(&transfer_call(&call, denied_amount)?)?,
            expected_policy_code: Some(6),
        },
        PlannedCase {
            case_id: "target:empty-signers:0".into(),
            case: unsigned,
            call_xdr: encode(&call)?,
            expected_policy_code: Some(1),
        },
    ];

    // Candidate state is computed once here and must be reproduced exactly per case.
    let ((env, _, _), source) = candidate_env(&execution, &entries, &base)?;
    let candidate_keys = stored_keys(&env)?;
    let candidate_state_hash = state_hash(&stored_state(&env)?)?;
    if !source.state.borrow().undeclared.is_empty()
        || entries.iter().any(|e| candidate_keys.contains(&e.key))
    {
        return Err(refuse(
            "captured target state overlaps candidate account or policy state",
        ));
    }

    let capture_hash = hash(domains::TARGET_CAPTURE, capture)?;
    let bootstrap_owner =
        stellar_strkey::ed25519::PublicKey(execution.bootstrap.verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned();
    #[derive(Serialize)]
    struct Initialization<'a> {
        capture_hash: &'a str,
        candidate_state_hash: &'a str,
        local_rule_id: u32,
        bootstrap_owner: &'a str,
        provenance: &'a str,
    }
    let binding = OfflineBinding {
        run_hash: execution.binding.run_hash.clone(),
        job_hash: hash(domains::CAPTURED_TARGET_JOB, &job)?,
        suite_hash: hash(domains::CAPTURED_TARGET_CASES, &cases)?,
        state_hash: hash(
            domains::CAPTURED_INITIALIZATION,
            &Initialization {
                capture_hash: &capture_hash,
                candidate_state_hash: &candidate_state_hash,
                local_rule_id: LOCAL_RULE_ID,
                bootstrap_owner: &bootstrap_owner,
                provenance: "rpc_reported_target_with_fresh_local_candidate",
            },
        )?,
        source_network_id: capture.network_id.clone(),
        source_protocol_version: ledger.protocol_version,
        source_ledger: observed,
        account_address: execution.binding.account_address.clone(),
        delegate_address: execution.binding.delegate_address.clone(),
    };
    let execution_network_id = offline_network(&binding)?;
    execution.binding = binding.clone();
    execution.execution_network_id = execution_network_id.clone();
    Ok(PreparedCaptured {
        binding,
        execution_network_id,
        capture_hash,
        candidate_state_hash,
        target_contract,
        observed_ledger: observed,
        execution,
        entries,
        cases,
        sender_balance_key,
        recipient_key,
        amount,
        max_entry_ttl: ledger.max_entry_ttl,
    })
}

type State = BTreeMap<String, (String, Option<u32>)>;

/// A fresh candidate installation over a non-strict source holding the captured entries.
fn candidate_env(
    execution: &PreparedExecution,
    entries: &[CapturedEntry],
    case: &Case,
) -> RuntimeResult<((Env, Address, Address), Rc<StrictSource>)> {
    let source = Rc::new(StrictSource {
        captured: entries
            .iter()
            .map(|e| (e.key.clone(), (Rc::new(e.entry.clone()), e.live_until)))
            .collect(),
        state: RefCell::new(SourceState::default()),
    });
    let mut env = Env::from_ledger_snapshot(SnapshotSourceInput {
        source: source.clone(),
        ledger_info: None,
        snapshot: None,
    });
    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    Ok((setup_in(env, execution, case)?, source))
}

fn keys_text(keys: &BTreeSet<xdr::LedgerKey>) -> RuntimeResult<Vec<String>> {
    keys.iter().map(encode).collect()
}

fn stored_keys(env: &Env) -> RuntimeResult<BTreeSet<xdr::LedgerKey>> {
    Ok(env
        .host()
        .get_stored_entries()
        .map_err(|e| format!("storage: {e:?}"))?
        .into_iter()
        .map(|(key, _)| (*key).clone())
        .collect())
}

/// Every present entry, keyed by canonical key XDR. Absent accessed keys are omitted.
fn stored_state(env: &Env) -> RuntimeResult<State> {
    let mut state = State::new();
    for (key, value) in env
        .host()
        .get_stored_entries()
        .map_err(|e| format!("storage: {e:?}"))?
    {
        if let Some((entry, ttl)) = value {
            state.insert(encode(&*key)?, (encode(&*entry)?, ttl));
        }
    }
    Ok(state)
}

/// The logical ledger: captured entries not yet read through, overridden by host storage.
fn effective_state(env: &Env, entries: &[CapturedEntry]) -> RuntimeResult<State> {
    let mut state = State::new();
    for e in entries {
        state.insert(encode(&e.key)?, (encode(&e.entry)?, e.live_until));
    }
    for (key, value) in env
        .host()
        .get_stored_entries()
        .map_err(|e| format!("storage: {e:?}"))?
    {
        let key = encode(&*key)?;
        match value {
            Some((entry, ttl)) => {
                state.insert(key, (encode(&*entry)?, ttl));
            }
            None => {
                state.remove(&key);
            }
        }
    }
    Ok(state)
}

fn state_hash(state: &State) -> RuntimeResult<String> {
    let entries: Vec<_> = state
        .iter()
        .map(|(k, (e, ttl))| (k.clone(), e.clone(), *ttl))
        .collect();
    hash(domains::NATIVE_STATE_ENTRIES, &entries)
}

fn entry_of(state: &State, key: &xdr::LedgerKey) -> RuntimeResult<Option<xdr::LedgerEntry>> {
    state
        .get(&encode(key)?)
        .map(|(entry, _)| xdr::LedgerEntry::from_xdr_base64(entry, xdr_limits()))
        .transpose()
        .map_err(|e| e.to_string())
}

fn sac_balance(state: &State, key: &xdr::LedgerKey) -> RuntimeResult<i128> {
    let Some(entry) = entry_of(state, key)? else {
        return Err("captured sender balance disappeared".into());
    };
    let xdr::LedgerEntryData::ContractData(data) = entry.data else {
        return Err("sender balance is not contract data".into());
    };
    let xdr::ScVal::Map(Some(map)) = data.val else {
        return Err("sender balance is not a map".into());
    };
    map.iter()
        .find(|e| e.key == xdr::ScVal::Symbol("amount".try_into().expect("symbol")))
        .and_then(|e| match &e.val {
            xdr::ScVal::I128(v) => Some(i128::from(v)),
            _ => None,
        })
        .ok_or_else(|| "sender balance lacks amount".into())
}

fn classic_balance(state: &State, key: &xdr::LedgerKey) -> RuntimeResult<i128> {
    match entry_of(state, key)?.map(|e| e.data) {
        Some(xdr::LedgerEntryData::Account(account)) => Ok(account.balance.into()),
        _ => Err("captured recipient account disappeared".into()),
    }
}

struct Changes {
    created: Vec<String>,
    written: Vec<String>,
    ttl_extended: Vec<String>,
    unexpected: Vec<String>,
}

/// Classify every difference: only expected nonce keys may appear, only writable keys may
/// change data, and TTLs may only grow within the captured maximum.
fn classify(
    before: &State,
    after: &State,
    writable: &BTreeSet<String>,
    expected_new: &BTreeSet<String>,
    max_live_until: u32,
) -> Changes {
    let mut changes = Changes {
        created: vec![],
        written: vec![],
        ttl_extended: vec![],
        unexpected: vec![],
    };
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    for key in keys {
        match (before.get(key), after.get(key)) {
            (None, Some(_)) if expected_new.contains(key) => changes.created.push(key.clone()),
            (None, Some(_)) => changes.unexpected.push(format!("created {key}")),
            (Some(_), None) => changes.unexpected.push(format!("removed {key}")),
            (Some((be, bt)), Some((ae, at))) => {
                if be != ae {
                    if writable.contains(key) {
                        changes.written.push(key.clone());
                    } else {
                        changes.unexpected.push(format!("wrote {key}"));
                    }
                }
                if bt != at {
                    match (bt, at) {
                        (Some(b), Some(a)) if a > b && *a <= max_live_until => {
                            changes.ttl_extended.push(key.clone())
                        }
                        _ => changes.unexpected.push(format!("ttl {key}")),
                    }
                }
            }
            (None, None) => {}
        }
    }
    for key in expected_new {
        if !after.contains_key(key) {
            changes.unexpected.push(format!("missing expected {key}"));
        }
    }
    changes
}

pub fn execute_captured(
    input: &PreparedCaptured,
    signer_capability: &mut impl DelegateSigner,
) -> RuntimeResult<CapturedReport> {
    let started = Instant::now();
    let execution = &input.execution;
    let network = canonical_hex::<32>(&input.execution_network_id)?;
    let expiry = input
        .observed_ledger
        .checked_add(SIGNATURE_WINDOW)
        .ok_or("signature expiry overflow")?;
    let max_live_until = input
        .observed_ledger
        .saturating_add(input.max_entry_ttl)
        .saturating_sub(1);
    let mut request_count = 0u32;
    let mut results = Vec::new();
    for (index, planned) in input.cases.iter().enumerate() {
        if started.elapsed() > crate::DEADLINE {
            return Err("execution deadline exceeded".into());
        }
        let case = &planned.case;
        let ((env, account, policy), source) = candidate_env(execution, &input.entries, case)?;
        if state_hash(&stored_state(&env)?)? != input.candidate_state_hash
            || !source.state.borrow().undeclared.is_empty()
        {
            return Err("candidate initialization differs from preparation".into());
        }
        let account_address = scaddress(&env, &account)?;
        let account_nonce = ACCOUNT_NONCE_BASE + index as i64;
        let signing = !case.context.authenticated_signers.is_empty();
        let delegate_nonce = DELEGATE_NONCE_BASE + i64::from(request_count) + 1;
        let delegate_key =
            stellar_strkey::ed25519::PublicKey::from_string(&input.binding.delegate_address)
                .map_err(|_| "delegate")?
                .0;
        let delegate_address = xdr::ScAddress::Account(xdr::AccountId(
            xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(delegate_key)),
        ));
        let mut expected_new =
            BTreeSet::from([encode(&nonce_key(account_address.clone(), account_nonce))?]);
        if signing {
            expected_new.insert(encode(&nonce_key(
                delegate_address.clone(),
                delegate_nonce,
            ))?);
        }
        {
            let mut state = source.state.borrow_mut();
            state.strict = true;
            for key in &expected_new {
                state.expected_absent.insert(decode(key, "nonce key")?);
            }
        }
        env.host()
            .with_budget(|b| b.reset_limits(200_000_000, 128 * 1024 * 1024))
            .map_err(|e| format!("budget: {e:?}"))?;

        let call: xdr::InvokeContractArgs = decode(&planned.call_xdr, "planned call")?;
        let root = xdr::SorobanAuthorizedInvocation {
            function: xdr::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: Default::default(),
        };
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(network),
                nonce: account_nonce,
                signature_expiration_ledger: expiry,
                invocation: root.clone(),
            });
        let payload =
            ozpb_domain::sha256(&preimage.to_xdr(xdr_limits()).map_err(|e| e.to_string())?);
        let rule_ids = soroban_sdk::vec![&env, LOCAL_RULE_ID];
        let mut signers = Map::new(&env);
        let mut auths = Vec::new();
        if signing {
            let [SignerSpec::Delegated { address }] = case.context.authenticated_signers.as_slice()
            else {
                return Err("captured cases support one delegated signer".into());
            };
            if *address != input.binding.delegate_address {
                return Err("authenticated signer is not the bound delegate".into());
            }
            signers.set(
                Signer::Delegated(Address::from_str(&env, address)),
                Bytes::new(&env),
            );
            request_count += 1;
            let request = make_sign_request(
                &input.binding,
                request_count,
                &planned.case_id,
                auth_digest(&env, &payload.0, &rule_ids),
                delegate_nonce,
                expiry,
            )?;
            let answer = signer_capability.sign(&request)?;
            let signature = verify_signature_response(&request, &answer)?;
            auths.push(delegate_entry(
                &env,
                &request,
                canonical_hex(&answer.public_key_hex)?,
                signature,
            )?);
        }
        auths.insert(
            0,
            xdr::SorobanAuthorizationEntry {
                credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                    address: account_address,
                    nonce: account_nonce,
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
            },
        );
        let mut args = SVec::<Val>::new(&env);
        for value in call.args.iter() {
            args.push_back(Val::try_from_val(&env, value).map_err(|e| format!("argument: {e:?}"))?);
        }
        // An uncapped rule's policy defines no counter key and setup never writes one, so a
        // read would leave the candidate cache and reach the strict source.
        let counted = case.context.call_count_so_far.is_some();
        let read_counter = || counted.then(|| counter(&env, &account, &policy)).flatten();
        // Observe first: a test contract frame ends the host's authorization scope.
        let counter_before = read_counter();
        let before = effective_state(&env, &input.entries)?;
        env.set_auths(&auths);
        let target = Address::from_str(&env, &input.target_contract);
        let result = env.try_invoke_contract::<Val, soroban_sdk::Error>(
            &target,
            &Symbol::new(&env, "transfer"),
            args,
        );
        let permitted = matches!(result, Ok(Ok(_)));
        let host_error = match &result {
            Ok(_) => None,
            Err(error) => Some(format!("{error:?}")),
        };
        let policy_attributed = match planned.expected_policy_code {
            Some(code) => attributed_error(&env, &policy, code)?,
            None => false,
        };
        let after = effective_state(&env, &input.entries)?;
        let counter_after = read_counter();
        // Captured read-write keys, plus the candidate counter when one is configured.
        let mut writable = input
            .entries
            .iter()
            .filter(|e| e.writable)
            .map(|e| encode(&e.key))
            .collect::<RuntimeResult<BTreeSet<_>>>()?;
        if counted {
            let key = scval(
                &env,
                PolicyStorageKey::CallCount(account.clone(), LOCAL_RULE_ID),
            )?;
            writable.insert(encode(&contract_data_key(
                &scaddress(&env, &policy)?,
                key,
                xdr::ContractDataDurability::Persistent,
            ))?);
        }
        // A denial rolls everything back, nonces included, so it may create nothing.
        let may_create = if planned.expected_policy_code.is_none() {
            expected_new.clone()
        } else {
            BTreeSet::new()
        };
        let mut changes = classify(&before, &after, &writable, &may_create, max_live_until);
        let (captured_reads, undeclared_reads) = {
            let state = source.state.borrow();
            (
                keys_text(&state.captured_reads)?,
                keys_text(&state.undeclared)?,
            )
        };
        for key in &undeclared_reads {
            changes.unexpected.push(format!("undeclared read {key}"));
        }
        let sender_delta = sac_balance(&after, &input.sender_balance_key)?
            - sac_balance(&before, &input.sender_balance_key)?;
        let recipient_delta = classic_balance(&after, &input.recipient_key)?
            - classic_balance(&before, &input.recipient_key)?;
        let state_before_hash = state_hash(&before)?;
        let state_after_hash = state_hash(&after)?;
        let agree = match planned.expected_policy_code {
            None => {
                let counter_advanced = match counter_before {
                    Some(value) => value.checked_add(1) == counter_after,
                    None => counter_after.is_none(),
                };
                permitted
                    && sender_delta == -input.amount
                    && recipient_delta == input.amount
                    && counter_advanced
                    && changes.unexpected.is_empty()
                    && changes
                        .written
                        .contains(&encode(&input.sender_balance_key)?)
                    && changes.written.contains(&encode(&input.recipient_key)?)
            }
            Some(_) => {
                !permitted
                    && policy_attributed
                    && state_before_hash == state_after_hash
                    && counter_before == counter_after
                    && changes.unexpected.is_empty()
            }
        };
        results.push(CapturedCaseResult {
            case_id: planned.case_id.clone(),
            label: case.label.clone(),
            class: case.class,
            expected_permit: case.expect_permit,
            permitted,
            agree,
            refusal_contract: policy_attributed.then(|| execution.policy_address.clone()),
            refusal_code: if policy_attributed {
                planned.expected_policy_code
            } else {
                None
            },
            host_error,
            state_before_hash,
            state_after_hash,
            sender_delta: sender_delta.to_string(),
            recipient_delta: recipient_delta.to_string(),
            counter_seed: case.context.call_count_so_far,
            counter_before,
            counter_after,
            captured_reads,
            created_keys: changes.created,
            written_keys: changes.written,
            ttl_extended_keys: changes.ttl_extended,
            undeclared_reads,
            unexpected_changes: changes.unexpected,
        });
    }
    let passed = results.len() == input.cases.len() && results.iter().all(|r| r.agree);
    Ok(CapturedReport {
        frame_type: "result".into(),
        schema: 1,
        layer: "captured_target".into(),
        binding: input.binding.clone(),
        execution_network_id: input.execution_network_id.clone(),
        capture_hash: input.capture_hash.clone(),
        candidate_state_hash: input.candidate_state_hash.clone(),
        capture_provenance: "rpc_reported".into(),
        observed_ledger: input.observed_ledger,
        target_contract: input.target_contract.clone(),
        account_code_hash: execution.account_code_hash.clone(),
        policy_address: execution.policy_address.clone(),
        policy_code_hash: execution.policy_code_hash.clone(),
        host_version: "soroban-env-host/30.0.0".into(),
        local_rule_id: LOCAL_RULE_ID,
        candidate_context_rule_id: execution.candidate_context_rule_id,
        storage_mode: STORAGE_MODE.into(),
        provenance: "rpc_reported target entries with outer LedgerEntry extension reconstructed \
                     as V0; fresh local candidate installation and synthetic counter seed; \
                     offline execution network; no owner authority, fee, reserve or live-network claim"
            .into(),
        cases: results,
        passed,
        complete: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_key(n: u8) -> xdr::LedgerKey {
        xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
            account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([n; 32]))),
        })
    }

    fn account_entry(n: u8) -> xdr::LedgerEntry {
        xdr::LedgerEntry {
            last_modified_ledger_seq: 1,
            data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                    [n; 32],
                ))),
                ..Default::default()
            }),
            ext: xdr::LedgerEntryExt::V0,
        }
    }

    #[test]
    fn strict_source_answers_only_declared_keys_and_logs_the_rest() {
        let source = StrictSource {
            captured: BTreeMap::from([(account_key(1), (Rc::new(account_entry(1)), None))]),
            state: RefCell::new(SourceState::default()),
        };
        // Installing the candidate: unknown keys are fresh state; target state is off limits.
        assert!(source.get(&Rc::new(account_key(2))).unwrap().is_none());
        assert!(source.get(&Rc::new(account_key(1))).is_err());
        assert_eq!(
            source.state.borrow().undeclared,
            BTreeSet::from([account_key(1)])
        );
        source.state.borrow_mut().undeclared.clear();
        {
            let mut state = source.state.borrow_mut();
            state.strict = true;
            state.expected_absent.insert(account_key(3));
        }
        assert!(source.get(&Rc::new(account_key(1))).unwrap().is_some());
        assert!(source.get(&Rc::new(account_key(3))).unwrap().is_none());
        assert!(source.get(&Rc::new(account_key(2))).is_err());
        let state = source.state.borrow();
        assert_eq!(state.captured_reads, BTreeSet::from([account_key(1)]));
        assert_eq!(state.undeclared, BTreeSet::from([account_key(2)]));
    }

    #[test]
    fn classify_flags_every_unexpected_difference() {
        let entry = |v: &str, ttl: Option<u32>| (v.to_string(), ttl);
        let before = State::from([
            ("writable".into(), entry("a", Some(10))),
            ("read_only".into(), entry("b", Some(10))),
            ("removed".into(), entry("c", None)),
            ("ttl_down".into(), entry("d", Some(10))),
            ("ttl_far".into(), entry("e", Some(10))),
            ("ttl_up".into(), entry("f", Some(10))),
        ]);
        let after = State::from([
            ("writable".into(), entry("A", Some(10))),
            ("read_only".into(), entry("B", Some(10))),
            ("ttl_down".into(), entry("d", Some(9))),
            ("ttl_far".into(), entry("e", Some(101))),
            ("ttl_up".into(), entry("f", Some(100))),
            ("nonce".into(), entry("n", Some(64))),
            ("stray".into(), entry("s", Some(64))),
        ]);
        let changes = classify(
            &before,
            &after,
            &BTreeSet::from(["writable".to_string()]),
            &BTreeSet::from(["nonce".to_string(), "absent_nonce".to_string()]),
            100,
        );
        assert_eq!(changes.created, ["nonce"]);
        assert_eq!(changes.written, ["writable"]);
        assert_eq!(changes.ttl_extended, ["ttl_up"]);
        assert_eq!(
            changes.unexpected,
            [
                "wrote read_only",
                "removed removed",
                "created stray",
                "ttl ttl_down",
                "ttl ttl_far",
                "missing expected absent_nonce",
            ]
        );
    }
}
