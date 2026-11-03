//! Exact contract code observations for a bounded set of contract instances.
//!
//! This is a prerequisite for an account authority scanner, not a rule-state snapshot. RPC's
//! `latestLedger` is the ledger the endpoint says it read the request at; it is endpoint
//! metadata, not a proof that the returned entries are one coherent ledger state, so this
//! value cannot by itself construct a trusted `AccountState` or a Safe authority verdict. The
//! per-instance checks here (live at the reported ledger, a Wasm executable) are shared with
//! the account scan, which reads instances in the same response as the account's storage.

use super::{
    instance_executable, ledger_witness::LedgerWitness, parse_contract_executables, require_live,
    verify_network, xdr_limits, ObservedExecutable, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    ContractDataDurability, ContractId, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    ReadXdr, ScAddress, ScVal, WriteXdr,
};

/// Wasm code identities returned in one checked `getLedgerEntries` response.
/// `reported_latest_ledger` is RPC metadata, not a coherent-snapshot attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCodeRead {
    pub network_id: NetworkId,
    pub reported_latest_ledger: LedgerSeq,
    pub wasm_hashes: BTreeMap<String, Hash32>,
}

/// Read the current instance code for at most one RPC request's worth of C-addresses.
///
/// A successful read establishes that the configured endpoint returned a complete, exact set
/// of well-formed contract instances with Wasm executables. It does not establish account
/// rule completeness, a coherent cross-entry snapshot, or code identity at signing time. The
/// endpoint is the trust boundary; this read verifies no cryptographic ledger proof.
pub fn read_contract_wasm_hashes<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    addresses: &[String],
) -> Result<ContractCodeRead, RpcError> {
    read_contract_wasm_hashes_with_witnesses(transport, network_passphrase, addresses)
        .map(|(read, _)| read)
}

/// Preserve validated full entry payloads for a scanner without changing the public
/// code-read result shape.
pub(crate) fn read_contract_wasm_hashes_with_witnesses<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    addresses: &[String],
) -> Result<(ContractCodeRead, BTreeMap<Vec<u8>, LedgerWitness>), RpcError> {
    if addresses.is_empty() || addresses.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(RpcError::InvalidRequest(format!(
            "contract code read requires 1..={MAX_LEDGER_ENTRY_KEYS} unique addresses"
        )));
    }

    let mut requested = BTreeMap::new();
    let mut seen_contracts = BTreeSet::new();
    for address in addresses {
        let contract = address
            .parse::<stellar_strkey::Contract>()
            .map_err(|error| {
                RpcError::InvalidRequest(format!("invalid contract address {address:?}: {error}"))
            })?;
        if !seen_contracts.insert(contract.0) {
            return Err(RpcError::InvalidRequest(
                "contract code read contains a duplicate contract address".to_string(),
            ));
        }
        let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_key = key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| RpcError::InvalidRequest(error.to_string()))?;
        requested.insert(encoded_key, (address.clone(), sc_address));
    }

    verify_network(transport, network_passphrase)?;
    let keys: Vec<&String> = requested.keys().collect();
    let result = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": keys, "xdrFormat": "base64" }),
        )
        .map_err(super::redact_ledger_request_error)?;
    let reported_latest_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getLedgerEntries has no integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".to_string()))?;
    if reported_latest_ledger == 0 {
        return Err(RpcError::Malformed(
            "getLedgerEntries reported ledger zero for deployed contract instances".to_string(),
        ));
    }
    let observations = parse_contract_executables(&result, &requested).map_err(code_read)?;
    // A contract instance is persistent storage. Require its TTL metadata to be present and
    // still live at the reported ledger, instead of silently accepting an archived entry.
    let entries = result["entries"]
        .as_array()
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".to_string()))?;
    let mut witnesses = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let live_until: u32 = entry
            .get("liveUntilLedgerSeq")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} has no integer liveUntilLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} liveUntilLedgerSeq exceeds u32"
                ))
            })?;
        require_live(index, live_until, reported_latest_ledger).map_err(code_read)?;
        let key = entry["key"]
            .as_str()
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string key")))?;
        let key_xdr = LedgerKey::from_xdr_base64(key, xdr_limits())
            .and_then(|key| key.to_xdr(xdr_limits()))
            .map_err(|error| RpcError::Malformed(format!("entry {index} key XDR: {error}")))?;
        let data = entry["xdr"]
            .as_str()
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string xdr")))?;
        let LedgerEntryData::ContractData(data) =
            LedgerEntryData::from_xdr_base64(data, xdr_limits()).map_err(|error| {
                RpcError::Malformed(format!("entry {index} value XDR: {error}"))
            })?
        else {
            return Err(RpcError::Malformed(format!(
                "entry {index} is not contract data"
            )));
        };
        let entry_data_xdr = LedgerEntryData::ContractData(data)
            .to_xdr(xdr_limits())
            .map_err(|error| RpcError::Malformed(format!("entry {index} payload XDR: {error}")))?;
        let last_modified_ledger: u32 = entry["lastModifiedLedgerSeq"]
            .as_u64()
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "entry {index} has no integer lastModifiedLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!("entry {index} lastModifiedLedgerSeq exceeds u32"))
            })?;
        witnesses.insert(
            key_xdr,
            LedgerWitness::Present {
                entry_data_xdr,
                last_modified_ledger,
                live_until_ledger: live_until,
            },
        );
    }

    let mut wasm_hashes = BTreeMap::new();
    for (address, observation) in observations {
        let code_hash = wasm_hash(&address, observation.executable)?;
        wasm_hashes.insert(address, code_hash);
    }
    Ok((
        ContractCodeRead {
            network_id: NetworkId::from_passphrase(network_passphrase),
            reported_latest_ledger: LedgerSeq(reported_latest_ledger),
            wasm_hashes,
        },
        witnesses,
    ))
}

/// The code hash of one returned contract instance, as this reader would accept it: live at
/// the ledger its response reports and running Wasm. The account scan's closure read uses it
/// for every policy, verifier and candidate instance in its response.
pub(crate) fn live_wasm_hash(
    index: usize,
    address: &str,
    value: ScVal,
    live_until_ledger: u32,
    reported_latest_ledger: u32,
) -> Result<Hash32, RpcError> {
    require_live(index, live_until_ledger, reported_latest_ledger).map_err(code_read)?;
    wasm_hash(address, instance_executable(index, address, value)?)
}

fn wasm_hash(address: &str, executable: ObservedExecutable) -> Result<Hash32, RpcError> {
    let ObservedExecutable::Wasm { code_hash } = executable else {
        return Err(RpcError::CodeRead(format!(
            "contract {address} does not run a Wasm executable"
        )));
    };
    Ok(code_hash)
}

fn code_read(error: RpcError) -> RpcError {
    match error {
        RpcError::Evidence(message) => RpcError::CodeRead(message),
        other => other,
    }
}
