//! Bounded raw contract-data reads. An omitted key has an unknown history;
//! this adapter does not interpret it as account state or an authorization verdict.

use super::{
    verify_network, xdr_limits, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS, MAX_XDR_BASE64_BYTES,
};
use ozpb_domain::{LedgerSeq, NetworkId};
use serde_json::json;
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractId, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, ReadXdr, ScAddress, ScVal,
    WriteXdr,
};

// Contract-data keys are usually small. Bound them separately from the 512 KiB value limit,
// and bound the entire request before any network I/O or XDR decoding.
const MAX_KEY_BASE64_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BASE64_BYTES: usize = 256 * 1024;
const MAX_CONTRACT_ADDRESS_BYTES: usize = 128;

/// One requested key's status in a single `getLedgerEntries` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractDataStatus {
    /// The endpoint omitted this key. Omission is not proof that it never existed.
    Absent,
    /// The endpoint returned this entry but its TTL has expired at the reported ledger.
    Archived {
        value: ScVal,
        last_modified_ledger: u32,
    },
    /// An entry whose XDR and metadata matched the requested key, with a TTL at least as
    /// high as the RPC's reported latest ledger. This is not a cross-call state anchor.
    Present {
        value: ScVal,
        last_modified_ledger: u32,
        live_until_ledger: u32,
    },
}

/// Results from one RPC call. `reported_latest_ledger` dates the response but does not
/// establish a coherent snapshot across calls, or prove completeness of an account's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDataRead {
    pub network_id: NetworkId,
    pub reported_latest_ledger: LedgerSeq,
    /// Canonical base64 XDR ledger keys; every requested key appears exactly once.
    pub entries: BTreeMap<String, ContractDataStatus>,
}

/// Read 1–200 contract-data ledger keys for one contract from a configured RPC endpoint.
///
/// The caller supplies the requested keys and network passphrase. The endpoint is checked
/// with `getNetwork` before the read, but endpoint selection and authentication remain the
/// caller's responsibility. This function does not derive the complete key set or an authority
/// verdict. An omitted key remains uncertain even when the endpoint reports archives.
pub fn read_contract_data<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    contract_id: &str,
    key_xdr_base64: &[String],
) -> Result<ContractDataRead, RpcError> {
    read_contract_data_with_payloads(transport, network_passphrase, contract_id, key_xdr_base64)
        .map(|(read, _)| read)
}

/// Retain validated full entry payloads for the account scanner without changing the
/// public raw-read result shape. Omitted keys have no payload.
pub(crate) fn read_contract_data_with_payloads<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    contract_id: &str,
    key_xdr_base64: &[String],
) -> Result<(ContractDataRead, BTreeMap<String, Vec<u8>>), RpcError> {
    if key_xdr_base64.is_empty() || key_xdr_base64.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(RpcError::InvalidRequest(format!(
            "contract-data read requires 1–{MAX_LEDGER_ENTRY_KEYS} keys"
        )));
    }
    if contract_id.len() > MAX_CONTRACT_ADDRESS_BYTES {
        return Err(RpcError::InvalidRequest(
            "contract address exceeds the encoded address size limit".to_string(),
        ));
    }
    let contract = contract_id
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| {
            RpcError::InvalidRequest(format!("invalid contract address {contract_id}: {error}"))
        })?;
    let expected_address = ScAddress::Contract(ContractId(Hash(contract.0)));
    let mut requested = BTreeMap::<String, LedgerKeyContractData>::new();
    let mut total_bytes = 0usize;
    for (index, encoded) in key_xdr_base64.iter().enumerate() {
        if encoded.len() > MAX_KEY_BASE64_BYTES {
            return Err(RpcError::InvalidRequest(format!(
                "contract-data key {index} exceeds the encoded key size limit"
            )));
        }
        total_bytes = total_bytes.saturating_add(encoded.len());
        if total_bytes > MAX_REQUEST_BASE64_BYTES {
            return Err(RpcError::InvalidRequest(
                "contract-data request exceeds the encoded key budget".to_string(),
            ));
        }
        let key = LedgerKey::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::InvalidRequest(format!("contract-data key {index} is invalid XDR: {error}"))
        })?;
        let LedgerKey::ContractData(key) = key else {
            return Err(RpcError::InvalidRequest(format!(
                "contract-data key {index} is not a contract-data ledger key"
            )));
        };
        if key.contract != expected_address {
            return Err(RpcError::InvalidRequest(format!(
                "contract-data key {index} belongs to another contract"
            )));
        }
        let canonical = LedgerKey::ContractData(key.clone())
            .to_xdr_base64(xdr_limits())
            .map_err(|error| {
                RpcError::InvalidRequest(format!("contract-data key {index}: {error}"))
            })?;
        if requested.insert(canonical, key).is_some() {
            return Err(RpcError::InvalidRequest(format!(
                "contract-data key {index} duplicates a requested key"
            )));
        }
    }

    verify_network(transport, network_passphrase)?;
    let network_id = NetworkId::from_passphrase(network_passphrase);
    let keys: Vec<&String> = requested.keys().collect();
    let result = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": keys, "xdrFormat": "base64" }),
        )
        .map_err(super::redact_ledger_request_error)?;
    parse_contract_data(&result, network_id, requested)
}

fn parse_contract_data(
    result: &serde_json::Value,
    network_id: NetworkId,
    requested: BTreeMap<String, LedgerKeyContractData>,
) -> Result<(ContractDataRead, BTreeMap<String, Vec<u8>>), RpcError> {
    let latest: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no integer latestLedger".into()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".into()))?;
    if latest == 0 {
        return Err(RpcError::Malformed(
            "getLedgerEntries reported unusable latestLedger zero".into(),
        ));
    }
    let entries = result
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".into()))?;
    let mut observed = requested
        .keys()
        .map(|key| (key.clone(), ContractDataStatus::Absent))
        .collect::<BTreeMap<_, _>>();
    let mut entry_payloads = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let key = entry
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string key")))?;
        let expected = requested.get(key).ok_or_else(|| {
            RpcError::Malformed(format!(
                "getLedgerEntries returned unrequested key at entry {index}"
            ))
        })?;
        if !matches!(observed.get(key), Some(ContractDataStatus::Absent)) {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries returned duplicate key at entry {index}"
            )));
        }
        let encoded = entry
            .get("xdr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string xdr")))?;
        if encoded.len() > MAX_XDR_BASE64_BYTES {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} exceeds the XDR size limit"
            )));
        }
        // The RPC field contains LedgerEntryData, not a whole LedgerEntry wrapper.
        let data = LedgerEntryData::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is invalid XDR: {error}"
            ))
        })?;
        let LedgerEntryData::ContractData(data) = data else {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is not contract data"
            )));
        };
        if data.contract != expected.contract
            || data.key != expected.key
            || data.durability != expected.durability
        {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} payload does not match its requested key"
            )));
        }
        let payload_xdr = LedgerEntryData::ContractData(data.clone())
            .to_xdr(xdr_limits())
            .map_err(|error| RpcError::Malformed(format!("entry {index} payload XDR: {error}")))?;
        let last_modified = ledger_field(entry, index, "lastModifiedLedgerSeq")?;
        let live_until = ledger_field(entry, index, "liveUntilLedgerSeq")?;
        if last_modified > latest {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} was modified after reported latestLedger"
            )));
        }
        observed.insert(
            key.to_string(),
            returned_status(data.val, last_modified, live_until, latest),
        );
        entry_payloads.insert(key.to_string(), payload_xdr);
    }
    Ok((
        ContractDataRead {
            network_id,
            reported_latest_ledger: LedgerSeq(latest),
            entries: observed,
        },
        entry_payloads,
    ))
}

/// A returned value's status at the ledger its response reports: archived once its TTL has
/// ended there. Shared with the account scan's closure read.
pub(crate) fn returned_status(
    value: ScVal,
    last_modified_ledger: u32,
    live_until_ledger: u32,
    reported_latest_ledger: u32,
) -> ContractDataStatus {
    if live_until_ledger < reported_latest_ledger {
        ContractDataStatus::Archived {
            value,
            last_modified_ledger,
        }
    } else {
        ContractDataStatus::Present {
            value,
            last_modified_ledger,
            live_until_ledger,
        }
    }
}

fn ledger_field(entry: &serde_json::Value, index: usize, field: &str) -> Result<u32, RpcError> {
    entry
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no integer {field}")))?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("entry {index} {field} exceeds u32")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ExtensionPoint, LedgerKeyContractCode, ScBytes,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const CID: [u8; 32] = [7; 32];

    struct Mock {
        network: Value,
        ledger: Value,
        calls: RefCell<Vec<String>>,
    }

    impl RpcTransport for Mock {
        fn call(&self, method: &str, _params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            Ok(match method {
                "getNetwork" => self.network.clone(),
                "getLedgerEntries" => self.ledger.clone(),
                _ => panic!("unexpected method: {method}"),
            })
        }
    }

    fn mock(ledger: Value) -> Mock {
        Mock {
            network: json!({"passphrase": NETWORK, "protocolVersion": 28}),
            ledger,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn address() -> String {
        format!("{}", stellar_strkey::Contract(CID))
    }

    fn key(n: u32) -> String {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(CID))),
            key: ScVal::U32(n),
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap()
    }

    fn entry(n: u32) -> Value {
        let xdr = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(CID))),
            key: ScVal::U32(n),
            durability: ContractDataDurability::Persistent,
            val: ScVal::U32(n + 100),
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        json!({
            "key": key(n),
            "xdr": xdr,
            "lastModifiedLedgerSeq": 9,
            "liveUntilLedgerSeq": 20
        })
    }

    fn read(mock: &Mock, keys: Vec<String>) -> Result<ContractDataRead, RpcError> {
        read_contract_data(mock, NETWORK, &address(), &keys)
    }

    fn malformed(mock: &Mock, keys: Vec<String>, contains: &str) {
        let error = read(mock, keys).unwrap_err().to_string();
        assert!(error.contains(contains), "{error}");
    }

    #[test]
    fn present_and_absent_are_exact_and_distinct() {
        let mock = mock(json!({"latestLedger": 10, "entries": [entry(1)]}));
        let result = read(&mock, vec![key(1), key(2)]).unwrap();
        assert_eq!(result.network_id, NetworkId::from_passphrase(NETWORK));
        assert_eq!(result.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[&key(2)], ContractDataStatus::Absent);
        assert_eq!(
            result.entries[&key(1)],
            ContractDataStatus::Present {
                value: ScVal::U32(101),
                last_modified_ledger: 9,
                live_until_ledger: 20,
            }
        );
        assert_eq!(*mock.calls.borrow(), ["getNetwork", "getLedgerEntries"]);
    }

    #[test]
    fn invalid_requests_stop_before_network_access() {
        let mock = mock(json!({"latestLedger": 10, "entries": []}));
        assert!(matches!(
            read(&mock, vec![]),
            Err(RpcError::InvalidRequest(_))
        ));
        malformed(&mock, vec![], "requires 1");
        malformed(&mock, vec![key(1); 201], "requires 1");
        malformed(&mock, vec![key(1), key(1)], "duplicates");
        malformed(&mock, vec!["not-base64".into()], "invalid XDR");
        let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash([3; 32]),
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        malformed(&mock, vec![code_key], "not a contract-data ledger key");
        malformed(
            &mock,
            vec!["A".repeat(MAX_KEY_BASE64_BYTES + 1)],
            "size limit",
        );
        let large_keys = (0..18)
            .map(|n| {
                LedgerKey::ContractData(LedgerKeyContractData {
                    contract: ScAddress::Contract(ContractId(Hash(CID))),
                    key: ScVal::Bytes(ScBytes::try_from(vec![n; 11_000]).unwrap()),
                    durability: ContractDataDurability::Persistent,
                })
                .to_xdr_base64(xdr_limits())
                .unwrap()
            })
            .collect::<Vec<_>>();
        malformed(&mock, large_keys, "encoded key budget");
        let wrong = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([8; 32]))),
            key: ScVal::U32(1),
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        malformed(&mock, vec![wrong], "another contract");
        let oversized_address = "C".repeat(MAX_CONTRACT_ADDRESS_BYTES + 1);
        let error = read_contract_data(&mock, NETWORK, &oversized_address, &[key(1)]).unwrap_err();
        assert!(matches!(error, RpcError::InvalidRequest(_)));
        let error = error.to_string();
        assert!(error.contains("address size limit"), "{error}");
        assert!(mock.calls.borrow().is_empty());
    }

    #[test]
    fn network_and_protocol_are_checked_before_ledger_read() {
        let mut wrong_network = mock(json!({"latestLedger": 10, "entries": [entry(1)]}));
        wrong_network.network["passphrase"] = json!("another network");
        let error = read(&wrong_network, vec![key(1)]).unwrap_err();
        assert!(matches!(error, RpcError::NetworkMismatch { .. }));
        assert_eq!(*wrong_network.calls.borrow(), ["getNetwork"]);

        let mut newer_protocol = mock(json!({"latestLedger": 10, "entries": [entry(1)]}));
        newer_protocol.network["protocolVersion"] = json!(crate::MAX_SUPPORTED_PROTOCOL + 1);
        let error = read(&newer_protocol, vec![key(1)]).unwrap_err();
        assert!(matches!(error, RpcError::UnsupportedProtocol { .. }));
        assert_eq!(*newer_protocol.calls.borrow(), ["getNetwork"]);
    }

    #[test]
    fn returned_keys_and_payloads_must_match_exactly() {
        let keys = vec![key(1), key(2)];
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [entry(1), entry(1)]})),
            vec![key(1)],
            "duplicate key",
        );
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [entry(1), entry(1)]})),
            keys.clone(),
            "duplicate key",
        );
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [entry(3)]})),
            keys.clone(),
            "unrequested key",
        );
        let mut mismatch = entry(1);
        mismatch["key"] = json!(key(2));
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [mismatch]})),
            keys.clone(),
            "payload does not match",
        );
        let mut malformed_xdr = entry(1);
        malformed_xdr["xdr"] = json!("malformed");
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [malformed_xdr]})),
            keys,
            "invalid XDR",
        );
    }

    #[test]
    fn unusable_metadata_is_rejected() {
        let mut zero_anchor = entry(1);
        zero_anchor["lastModifiedLedgerSeq"] = json!(0);
        zero_anchor["liveUntilLedgerSeq"] = json!(0);
        malformed(
            &mock(json!({"latestLedger": 0, "entries": [zero_anchor]})),
            vec![key(1)],
            "latestLedger zero",
        );
        let mut zero_modified = entry(1);
        zero_modified["lastModifiedLedgerSeq"] = json!(0);
        let result = read(
            &mock(json!({"latestLedger": 10, "entries": [zero_modified]})),
            vec![key(1)],
        )
        .unwrap();
        assert!(matches!(
            result.entries[&key(1)],
            ContractDataStatus::Present {
                last_modified_ledger: 0,
                ..
            }
        ));
        let mut missing_ttl = entry(1);
        missing_ttl
            .as_object_mut()
            .unwrap()
            .remove("liveUntilLedgerSeq");
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [missing_ttl]})),
            vec![key(1)],
            "liveUntilLedgerSeq",
        );
        for live_until in [0, 9] {
            let mut archived = entry(1);
            archived["liveUntilLedgerSeq"] = json!(live_until);
            let result = read(
                &mock(json!({"latestLedger": 10, "entries": [archived]})),
                vec![key(1)],
            )
            .unwrap();
            assert_eq!(
                result.entries[&key(1)],
                ContractDataStatus::Archived {
                    value: ScVal::U32(101),
                    last_modified_ledger: 9,
                }
            );
        }
        let mut future = entry(1);
        future["lastModifiedLedgerSeq"] = json!(11);
        malformed(
            &mock(json!({"latestLedger": 10, "entries": [future]})),
            vec![key(1)],
            "modified after",
        );
    }
}
