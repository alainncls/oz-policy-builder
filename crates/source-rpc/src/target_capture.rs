//! Read-only acquisition of one native Stellar Asset Contract transfer's target state.
//!
//! Record-mode simulation discovers the target's authorization root and footprint. That is
//! acquisition only: recording mode records the authorization a call needs instead of
//! enforcing it, so a successful simulation is never evidence that a policy permits the call.
//! The footprint is then re-read in one bounded `getLedgerEntries` batch together with the
//! network's state-archival configuration, and the exact ledger header comes from `getLedgers`.
//! Every value is endpoint-reported (`rpc_reported`); none of it is an inclusion proof. The
//! network is checked once, before the simulation, so nothing is requested between the
//! simulation and the entry read; a ledger can still close between them, and then the attempt
//! is retried.
//!
//! The envelope is confidential input. A shape this capture does not take is refused locally
//! under the same input errors as preflight, and nothing is sent. Once simulation has run the
//! endpoint holds the envelope and could quote it in any later reply, so no endpoint-controlled
//! text reaches an error: the category survives, the words do not.

use crate::preflight::{local_envelope, restores_archived_entries, validate_restoration};
use crate::{
    envelope_carries_signatures, read_invocation_footprint, verify_network, xdr_limits,
    CapturedFootprintEntry, FootprintCaptureError, OneNetworkCheck, RpcError, RpcTransport,
    MAX_XDR_BASE64_BYTES,
};
use ozpb_domain::{sha256, NetworkId, TargetCapture, TargetEntry};
use serde_json::{json, Value};
use stellar_xdr::{
    Asset, ConfigSettingEntry, ConfigSettingId, ContractDataDurability, ContractExecutable,
    ContractId, ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId, HostFunction,
    LedgerEntryData, LedgerHeaderHistoryEntry, LedgerKey, LedgerKeyConfigSetting,
    LedgerKeyContractCode, LedgerKeyContractData, OperationBody, ReadXdr, ScAddress, ScNonceKey,
    ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials,
    SorobanTransactionData, TransactionEnvelope, TransactionExt, WriteXdr,
};

/// The only source protocol whose captured state the execution runtime reproduces.
const CAPTURE_PROTOCOL: u32 = 30;
/// Simulation and the entry read may observe different ledgers; retry once, then give up.
const CAPTURE_ATTEMPTS: usize = 2;
/// Bound on the captured entry payload carried into an execution job.
const MAX_CAPTURED_ENTRY_BYTES: usize = 2 * 1024 * 1024;

fn refuse(reason: &str) -> RpcError {
    RpcError::Malformed(format!("native target capture refused: {reason}"))
}

/// Archived target state: the call `subject` names needs restoration first, which capture
/// never performs. Fixed text, as for every endpoint-derived refusal.
fn archived(subject: &str) -> RpcError {
    RpcError::TargetArchived(format!(
        "native target capture refused: {subject} requires restoration, which this capture does \
         not perform"
    ))
}

/// The caller's envelope decodes but is not a call this capture takes. Refused before any
/// request, under the input code preflight uses for an envelope shape it does not take.
fn unsupported(reason: &str) -> RpcError {
    RpcError::UnsupportedEnvelope(format!("native target capture refused: {reason}"))
}

/// An endpoint error with its endpoint-controlled text removed. A network mismatch keeps the
/// configured passphrase, which is the caller's, and loses the reported one; a protocol
/// refusal carries only numbers.
fn withhold(error: RpcError) -> RpcError {
    match error {
        RpcError::NetworkMismatch { expected, .. } => RpcError::NetworkMismatch {
            expected,
            actual: "withheld".to_string(),
        },
        error @ RpcError::UnsupportedProtocol { .. } => error,
        RpcError::Transport(_) => RpcError::Transport(
            "the RPC source could not be reached or did not answer in JSON-RPC (endpoint \
             detail withheld)"
                .to_string(),
        ),
        RpcError::Rpc(_) => {
            RpcError::Rpc("the RPC source refused a request (endpoint detail withheld)".to_string())
        }
        _ => RpcError::Malformed(
            "the RPC source returned an invalid response (endpoint detail withheld)".to_string(),
        ),
    }
}

/// The caller's transport with every error passed through [`withhold`].
struct Withheld<'a, T>(&'a T);

impl<T: RpcTransport> RpcTransport for Withheld<'_, T> {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.0.call(method, params).map_err(withhold)
    }
}

/// Decode canonical base64 XDR, refusing any encoding that does not round-trip byte for byte.
fn decode<T: ReadXdr + WriteXdr>(encoded: &str, what: &str) -> Result<T, RpcError> {
    if encoded.len() > MAX_XDR_BASE64_BYTES {
        return Err(refuse(&format!("{what} exceeds the XDR size bound")));
    }
    let value = T::from_xdr_base64(encoded, xdr_limits())
        .map_err(|_| refuse(&format!("{what} is not valid XDR")))?;
    if encode(&value, what)? != encoded {
        return Err(refuse(&format!("{what} is not canonical XDR")));
    }
    Ok(value)
}

fn encode<T: WriteXdr>(value: &T, what: &str) -> Result<String, RpcError> {
    value
        .to_xdr_base64(xdr_limits())
        .map_err(|_| refuse(&format!("cannot encode {what}")))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, RpcError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(&format!("response lacks string {field}")))
}

fn ledger(value: &Value, field: &str) -> Result<u32, RpcError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| refuse(&format!("response lacks positive u32 {field}")))
}

/// The native asset's contract address on `network`.
pub fn native_asset_contract(network: &NetworkId) -> Result<ScAddress, RpcError> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network.0 .0),
        contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
    });
    let bytes = preimage
        .to_xdr(xdr_limits())
        .map_err(|_| refuse("cannot encode the native asset contract preimage"))?;
    Ok(ScAddress::Contract(ContractId(Hash(sha256(&bytes).0))))
}

fn target_entry(entry: &CapturedFootprintEntry) -> Result<TargetEntry, RpcError> {
    Ok(TargetEntry {
        key_xdr: encode(&entry.key, "captured key")?,
        data_xdr: encode(&entry.data, "captured entry")?,
        last_modified_ledger: entry.last_modified_ledger.0,
        live_until_ledger: entry.live_until_ledger.map(|v| v.0),
    })
}

/// Acquire the target state of one native SAC `transfer(C-account, existing G, amount)`.
///
/// The envelope must be unsigned, carry no authorization entries, and call the source network's
/// native asset contract. Simulation must report exactly one authorization root, for the account,
/// equal to the call itself with no sub-invocations; a restoration preamble is refused rather
/// than performed. Every footprint key and the state-archival configuration are read at the
/// simulation's ledger, and that ledger's header must hash to the reported hash. No signature
/// is accepted or created and nothing is submitted. The caller binds the returned invocation to
/// its independently prepared candidate; this function does not know the candidate.
///
/// An envelope this capture does not take is refused before any request as
/// `EnvelopeTooLarge`, `EnvelopeParse` or `UnsupportedEnvelope`. Endpoint errors keep their
/// category without the endpoint's text, which could quote the envelope.
///
/// Record-mode footprints also name the account's own instance, its code and the recorded
/// authorization's fresh nonce. The nonce key is new by construction and is not read; instance
/// and code are read only to bind the account's executable hash. None of them become target
/// entries, and a footprint touching any other account storage is refused.
pub fn capture_native_target<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<TargetCapture, RpcError> {
    let envelope = local_envelope(envelope_xdr_base64)?;
    if encode(&envelope, "envelope")? != envelope_xdr_base64 {
        return Err(RpcError::EnvelopeParse(
            "native target capture refused: the envelope is not canonical XDR".to_string(),
        ));
    }
    if envelope_carries_signatures(envelope_xdr_base64)? {
        return Err(unsupported("the envelope carries signatures"));
    }
    let TransactionEnvelope::Tx(v1) = &envelope else {
        return Err(unsupported("only an unwrapped v1 transaction is supported"));
    };
    let OperationBody::InvokeHostFunction(operation) = &v1.tx.operations[0].body else {
        return Err(unsupported("the operation is not InvokeHostFunction"));
    };
    if !operation.auth.is_empty() {
        return Err(unsupported(
            "the envelope already carries authorization entries",
        ));
    }
    let HostFunction::InvokeContract(call) = &operation.host_function else {
        return Err(unsupported("the host function is not InvokeContract"));
    };
    let network = NetworkId::from_passphrase(network_passphrase);
    let [ScVal::Address(account @ ScAddress::Contract(_)), ScVal::Address(ScAddress::Account(_)), ScVal::I128(amount)] =
        call.args.as_slice()
    else {
        return Err(unsupported(
            "only transfer(contract account, G recipient, i128) is supported",
        ));
    };
    let amount = i128::from(amount);
    if call.contract_address != native_asset_contract(&network)?
        || call.function_name.as_slice() != b"transfer"
        || amount <= 0
        || amount >= i128::from(i64::MAX)
    {
        return Err(unsupported(
            "only a positive native-asset transfer below i64::MAX is supported",
        ));
    }
    let config_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let encoded_config_key = encode(&config_key, "state-archival key")?;
    let withheld = Withheld(transport);
    // The footprint reader's own network check is answered from this one.
    let transport = OneNetworkCheck::new(&withheld);
    verify_network(&transport, network_passphrase).map_err(withhold)?;
    for _ in 0..CAPTURE_ATTEMPTS {
        let simulation = transport.call(
            "simulateTransaction",
            json!({
                "transaction": envelope_xdr_base64,
                "authMode": "record",
                "xdrFormat": "base64",
            }),
        )?;
        // The call's own outcome, named apart from endpoint faults so a caller can attribute
        // it to the target, by the rules preflight applies. The endpoint's description is
        // withheld: it could quote the envelope.
        let failed = match simulation.get("error") {
            None => false,
            Some(Value::String(message)) if !message.is_empty() => true,
            Some(_) => return Err(refuse("the simulation error is not a non-empty string")),
        };
        if failed
            && (simulation.get("results").is_some() || simulation.get("restorePreamble").is_some())
        {
            return Err(refuse(
                "a failed simulation also reports success or restoration",
            ));
        }
        let reported = simulation
            .get("latestLedger")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| refuse("response lacks u32 latestLedger"))?;
        if reported == 0 {
            // stellar-rpc answers a request it refuses before reading its ledger with the error
            // and `latestLedger` 0: nothing was simulated, so the target decided nothing.
            return Err(if failed {
                RpcError::Rpc(
                    "the RPC source refused the simulation before simulating (endpoint detail \
                     withheld)"
                        .to_string(),
                )
            } else {
                refuse("response lacks positive u32 latestLedger")
            });
        }
        if failed {
            return Err(RpcError::TargetRefused(
                "native target capture refused: the record-mode simulation failed; the target \
                 refused the call or the simulator failed (endpoint detail withheld)"
                    .to_string(),
            ));
        }
        // A preamble is archived state only once it is well formed, as preflight requires;
        // its fixed refusal texts carry nothing of the endpoint's.
        if let Some(restore) = simulation.get("restorePreamble") {
            validate_restoration(restore)?;
            return Err(archived("the target footprint"));
        }
        let observed = reported;
        let [result] = simulation
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("simulation lacks results"))?
        else {
            return Err(refuse("simulation must report exactly one result"));
        };
        if decode::<ScVal>(text(result, "xdr")?, "simulation result")? != ScVal::Void {
            return Err(refuse("transfer simulation did not return void"));
        }
        let [recorded] = result
            .get("auth")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("simulation lacks recorded authorization"))?
        else {
            return Err(refuse(
                "exactly one recorded authorization root is supported",
            ));
        };
        let recording_auth_xdr = recorded
            .as_str()
            .ok_or_else(|| refuse("recorded authorization is not a string"))?;
        let recorded: SorobanAuthorizationEntry =
            decode(recording_auth_xdr, "recorded authorization")?;
        let (address, nonce) = match &recorded.credentials {
            SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
                (&c.address, c.nonce)
            }
            _ => return Err(refuse("recorded authorization is not address-bound")),
        };
        if address != account
            || recorded.root_invocation.function
                != SorobanAuthorizedFunction::ContractFn(call.clone())
            || !recorded.root_invocation.sub_invocations.is_empty()
        {
            return Err(refuse(
                "the recorded authorization root is not exactly the account's transfer",
            ));
        }
        let mut resources: SorobanTransactionData =
            decode(text(&simulation, "transactionData")?, "transaction data")?;
        let min_fee = text(&simulation, "minResourceFee")?
            .parse::<u64>()
            .map_err(|_| refuse("simulation minResourceFee is not a u64"))?;
        if i64::try_from(min_fee).ok() != Some(resources.resource_fee) {
            return Err(refuse(
                "simulation minResourceFee differs from its transaction data fee",
            ));
        }
        // Since protocol 23 the endpoint restores archived entries inside the simulated call
        // and lists them here instead of sending a preamble: the same archived target state.
        if restores_archived_entries(&resources)? {
            return Err(archived(
                "the simulation restored archived entries: the target footprint",
            ));
        }
        let footprint = &mut resources.resources.footprint;
        if footprint
            .read_only
            .iter()
            .chain(footprint.read_write.iter())
            .any(|key| key == &config_key)
        {
            return Err(refuse(
                "the target footprint already names network configuration",
            ));
        }
        let mut read_only = footprint.read_only.to_vec();
        read_only.push(config_key.clone());
        footprint.read_only = read_only
            .try_into()
            .map_err(|_| refuse("footprint too large"))?;
        // The recorded authorization's nonce is a fresh temporary key: absent by construction,
        // and replaced by the execution's own nonce. It is the only key not read back.
        let nonce_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: account.clone(),
            key: ScVal::LedgerKeyNonce(ScNonceKey { nonce }),
            durability: ContractDataDurability::Temporary,
        });
        footprint.read_write = footprint
            .read_write
            .iter()
            .filter(|key| **key != nonce_key)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| refuse("footprint too large"))?;
        let mut acquisition = envelope.clone();
        let TransactionEnvelope::Tx(acquisition_v1) = &mut acquisition else {
            unreachable!("checked above");
        };
        acquisition_v1.tx.ext = TransactionExt::V1(resources);
        let mut capture = match read_invocation_footprint(
            &transport,
            network_passphrase,
            &encode(&acquisition, "acquisition envelope")?,
        ) {
            Ok(capture) => capture,
            // The reader judges archival at the ledger it reports. Only at the simulation's
            // ledger is that the call's state; from a node behind or ahead it is retried like
            // any ledger mismatch.
            Err(FootprintCaptureError::ArchivedDeclaredKey { reported, .. })
                if reported == observed =>
            {
                return Err(archived(
                    "a footprint entry is archived at the captured ledger: the call",
                ))
            }
            Err(FootprintCaptureError::ArchivedDeclaredKey { .. }) => continue,
            // Its reported network is the endpoint's text. The transport has already withheld
            // every endpoint error, and the reader's own refusals are fixed descriptions, so
            // both keep their variant.
            Err(FootprintCaptureError::Rpc(error @ RpcError::NetworkMismatch { .. })) => {
                return Err(withhold(error))
            }
            Err(FootprintCaptureError::Rpc(error)) => return Err(error),
            Err(error) => return Err(refuse(&error.to_string())),
        };
        if capture.reported_ledger.0 != observed {
            continue;
        }
        // A submission based on this capture lands at L + 1 or later; an entry living only
        // until L would be archived by then.
        if capture
            .entries
            .values()
            .any(|entry| entry.live_until_ledger.is_some_and(|ttl| ttl.0 <= observed))
        {
            return Err(archived(
                "a footprint entry expires at the captured ledger: a call based on it",
            ));
        }
        let headers = transport.call(
            "getLedgers",
            json!({
                "startLedger": observed,
                "pagination": { "limit": 1 },
                "xdrFormat": "base64",
            }),
        )?;
        let [returned] = headers
            .get("ledgers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("getLedgers lacks ledgers"))?
        else {
            return Err(refuse("getLedgers must return exactly the captured ledger"));
        };
        let header_xdr = text(returned, "headerXdr")?;
        let header: LedgerHeaderHistoryEntry = decode(header_xdr, "ledger header")?;
        let header_hash = sha256(
            &header
                .header
                .to_xdr(xdr_limits())
                .map_err(|_| refuse("cannot encode the ledger header"))?,
        );
        if header.hash.0 != header_hash.0
            || text(returned, "hash")? != header_hash.to_hex()
            || header.header.ledger_seq != observed
            || ledger(returned, "sequence")? != observed
            || header.header.ledger_version != CAPTURE_PROTOCOL
            || text(returned, "ledgerCloseTime")?
                != header.header.scp_value.close_time.0.to_string()
        {
            return Err(refuse(
                "the ledger header does not hash to, or describe, the captured ledger",
            ));
        }
        let config = capture
            .entries
            .remove(&encoded_config_key)
            .ok_or_else(|| refuse("state-archival configuration was not returned"))?;
        capture.read_only_keys.remove(&encoded_config_key);
        let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) =
            &config.data
        else {
            return Err(refuse("state-archival key returned other data"));
        };
        if settings.min_temporary_ttl == 0
            || settings.min_persistent_ttl == 0
            || settings.max_entry_ttl < settings.min_temporary_ttl
            || settings.max_entry_ttl < settings.min_persistent_ttl
            || config.live_until_ledger.is_some()
        {
            return Err(refuse("state-archival configuration is inconsistent"));
        }
        // Partition the account's own instance and code out of the target state.
        let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: account.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_instance_key = encode(&instance_key, "account instance key")?;
        let instance = capture
            .entries
            .remove(&encoded_instance_key)
            .ok_or_else(|| refuse("the account instance was not in the footprint"))?;
        capture.read_only_keys.remove(&encoded_instance_key);
        let LedgerEntryData::ContractData(instance) = &instance.data else {
            return Err(refuse("the account instance key returned other data"));
        };
        let ScVal::ContractInstance(instance) = &instance.val else {
            return Err(refuse("the account instance holds no instance value"));
        };
        let ContractExecutable::Wasm(account_code) = &instance.executable else {
            return Err(refuse("the account is not a Wasm contract"));
        };
        let encoded_code_key = encode(
            &LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: account_code.clone(),
            }),
            "account code key",
        )?;
        if capture.entries.remove(&encoded_code_key).is_none() {
            return Err(refuse("the account code was not in the footprint"));
        }
        capture.read_only_keys.remove(&encoded_code_key);
        if capture.entries.values().any(|entry| {
            matches!(&entry.key, LedgerKey::ContractData(data) if data.contract == *account)
        }) {
            return Err(refuse("the target reads account storage"));
        }
        let entries = capture
            .entries
            .values()
            .map(target_entry)
            .collect::<Result<Vec<_>, _>>()?;
        if entries
            .iter()
            .map(|v| v.key_xdr.len() + v.data_xdr.len())
            .sum::<usize>()
            > MAX_CAPTURED_ENTRY_BYTES
        {
            return Err(refuse("captured entries exceed the job size bound"));
        }
        return Ok(TargetCapture {
            schema: 1,
            provenance: "rpc_reported".into(),
            network_id: network.0.to_hex(),
            observed_ledger: observed,
            header_xdr: header_xdr.into(),
            state_archival: target_entry(&config)?,
            invocation_xdr: encode(call, "invocation")?,
            recording_auth_xdr: recording_auth_xdr.into(),
            account_code_hash: hex::encode(account_code.0),
            read_only_keys: capture.read_only_keys.into_iter().collect(),
            read_write_keys: capture.read_write_keys.into_iter().collect(),
            entries,
        });
    }
    Err(refuse(
        "simulation and entry reads kept observing different ledgers",
    ))
}

#[cfg(test)]
mod tests;
