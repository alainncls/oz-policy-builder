//! One `getLedgerEntries` request for the keys an account's authority closure names: the
//! account's own storage, other contracts' instances and classic accounts, mixed.
//!
//! stellar-rpc reads every key of one request at the single ledger it reports (v30.0.0,
//! `13e53516`: `GetLedgerEntries` in `cmd/stellar-rpc/internal/ledgerentries/main.go`, whose
//! ledger `methods/get_ledger_entries.go` returns as `latestLedger`). So one response is one
//! ledger's state as that endpoint served it: the endpoint's behaviour, not a proof, and the
//! endpoint stays the trust boundary. This reader checks the response's shape, as
//! `policy_state_capture` does: canonical key and value XDR, requested keys only and each at
//! most once, every value naming its own key, bounded sizes. It does not ask for the network:
//! its caller checked that once for the attempt. What a value means is decided by the
//! per-type decoders the public readers share.

use super::{
    account_entry_page::{ledger_key, AccountEntryKey},
    account_state_scan::{AccountScanError, MAX_SCAN_WITNESS_BYTES},
    redact_ledger_request_error, xdr_limits, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS,
    MAX_XDR_BASE64_BYTES,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    AccountId, ContractDataDurability, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyAccount, LedgerKeyContractData, PublicKey, ReadXdr, ScAddress, ScVal, Uint256,
    WriteXdr,
};

/// The same bound as a raw contract-data read: every key is small, the whole request is not.
const MAX_REQUEST_BASE64_BYTES: usize = 256 * 1024;

/// A key the closure can name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ClosureKey {
    /// The pinned account's own storage, its instance included.
    Account(AccountEntryKey),
    /// Another contract's instance: an installed policy, a contract verifier, or a caller's
    /// target. The account's own instance is only ever `Account(Instance)`.
    Instance(String),
    /// A classic account, by canonical G-address.
    Classic(String),
}

/// A returned entry whose key and value passed the shape checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReturnedEntry {
    pub data: LedgerEntryData,
    /// Canonical XDR of `data`, byte for byte what the endpoint sent.
    pub data_xdr: Vec<u8>,
    pub last_modified_ledger: u32,
    /// Contract data carries a TTL; a classic account entry has none.
    pub live_until_ledger: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestedEntry {
    /// Canonical XDR of the requested ledger key.
    pub key_xdr: Vec<u8>,
    /// The entry and its position in the response, or `None` when the endpoint omitted it.
    pub returned: Option<(usize, ReturnedEntry)>,
}

impl RequestedEntry {
    /// The same answer in two responses: the same bytes and ledger metadata.
    pub fn same_answer(&self, other: &Self) -> bool {
        self.returned.as_ref().map(|(_, entry)| entry)
            == other.returned.as_ref().map(|(_, entry)| entry)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ClosureResponse {
    pub reported_latest_ledger: u32,
    /// Every requested key.
    pub entries: BTreeMap<ClosureKey, RequestedEntry>,
}

/// Read 1–200 closure keys in one `getLedgerEntries` request. More returned entry bytes than
/// one scan may retain is a budget error, checked as the response is decoded.
pub(crate) fn read_closure_entries<T: RpcTransport>(
    transport: &T,
    account: &ContractId,
    keys: &BTreeSet<ClosureKey>,
) -> Result<ClosureResponse, AccountScanError> {
    if keys.is_empty() || keys.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(invalid(format!(
            "closure read requires 1–{MAX_LEDGER_ENTRY_KEYS} keys"
        )));
    }
    let mut requested = BTreeMap::new();
    let mut request_bytes = 0usize;
    for key in keys {
        let ledger_key = closure_ledger_key(account, key)?;
        let encoded = ledger_key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| invalid(format!("cannot encode closure key: {error}")))?;
        request_bytes = request_bytes.saturating_add(encoded.len());
        if request_bytes > MAX_REQUEST_BASE64_BYTES {
            return Err(invalid(
                "closure request exceeds the encoded key budget".into(),
            ));
        }
        let key_xdr = ledger_key
            .to_xdr(xdr_limits())
            .map_err(|error| invalid(format!("cannot encode closure key: {error}")))?;
        if requested.insert(encoded, (key.clone(), key_xdr)).is_some() {
            return Err(invalid("closure request repeats a ledger key".into()));
        }
    }
    let encoded: Vec<&String> = requested.keys().collect();
    let response = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": encoded, "xdrFormat": "base64" }),
        )
        .map_err(redact_ledger_request_error)?;
    let ledger = ledger_field(&response, "latestLedger")?;
    if ledger == 0 {
        return Err(malformed("getLedgerEntries reported ledger zero".into()));
    }
    let values = response
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("getLedgerEntries has no entries array".into()))?;
    if values.len() > requested.len() {
        return Err(malformed(
            "getLedgerEntries returned more entries than keys".into(),
        ));
    }
    let mut returned = BTreeMap::new();
    let mut retained = 0usize;
    for (index, value) in values.iter().enumerate() {
        let key_text = xdr_text(value, index, "key")?;
        let key = LedgerKey::from_xdr_base64(key_text, xdr_limits())
            .map_err(|error| malformed(format!("entry {index} key XDR: {error}")))?;
        if key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| malformed(format!("entry {index} key XDR: {error}")))?
            != key_text
        {
            return Err(malformed(format!("entry {index} key is not canonical XDR")));
        }
        let Some((closure_key, key_xdr)) = requested.get(key_text) else {
            return Err(malformed(format!(
                "getLedgerEntries returned unrequested key at entry {index}"
            )));
        };
        if returned.contains_key(closure_key) {
            return Err(malformed(format!(
                "getLedgerEntries returned duplicate key at entry {index}"
            )));
        }
        let data_text = xdr_text(value, index, "xdr")?;
        let data = LedgerEntryData::from_xdr_base64(data_text, xdr_limits())
            .map_err(|error| malformed(format!("entry {index} value XDR: {error}")))?;
        let data_xdr = data
            .to_xdr(xdr_limits())
            .map_err(|error| malformed(format!("entry {index} value XDR: {error}")))?;
        if data.to_key() != key
            || data.to_xdr_base64(xdr_limits()).ok().as_deref() != Some(data_text)
        {
            return Err(malformed(format!(
                "getLedgerEntries entry {index} payload does not match its requested key"
            )));
        }
        retained = retained
            .saturating_add(key_xdr.len())
            .saturating_add(data_xdr.len());
        if retained > MAX_SCAN_WITNESS_BYTES {
            return Err(AccountScanError::Budget(
                "retained entry bytes exceed bound",
            ));
        }
        let last_modified_ledger = entry_ledger(value, index, "lastModifiedLedgerSeq")?;
        if last_modified_ledger > ledger {
            return Err(malformed(format!(
                "getLedgerEntries entry {index} was modified after reported latestLedger"
            )));
        }
        let live_until_ledger = match &data {
            LedgerEntryData::ContractData(_) => {
                Some(entry_ledger(value, index, "liveUntilLedgerSeq")?)
            }
            LedgerEntryData::Account(_) => None,
            _ => {
                return Err(malformed(format!(
                    "getLedgerEntries entry {index} is not contract data or an account"
                )))
            }
        };
        returned.insert(
            closure_key.clone(),
            (
                index,
                ReturnedEntry {
                    data,
                    data_xdr,
                    last_modified_ledger,
                    live_until_ledger,
                },
            ),
        );
    }
    let entries = requested
        .into_values()
        .map(|(key, key_xdr)| {
            let entry = returned.remove(&key);
            (
                key,
                RequestedEntry {
                    key_xdr,
                    returned: entry,
                },
            )
        })
        .collect();
    Ok(ClosureResponse {
        reported_latest_ledger: ledger,
        entries,
    })
}

fn closure_ledger_key(
    account: &ContractId,
    key: &ClosureKey,
) -> Result<LedgerKey, AccountScanError> {
    Ok(match key {
        ClosureKey::Account(request) => LedgerKey::ContractData(ledger_key(account, *request)),
        ClosureKey::Instance(address) => {
            let contract = address
                .parse::<stellar_strkey::Contract>()
                .map_err(|_| invalid("closure instance is not a C-address".into()))?;
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: ScAddress::Contract(ContractId(Hash(contract.0))),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            })
        }
        ClosureKey::Classic(address) => {
            let account = address
                .parse::<stellar_strkey::ed25519::PublicKey>()
                .map_err(|_| invalid("closure classic account is not a G-address".into()))?;
            LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account.0))),
            })
        }
    })
}

fn xdr_text<'a>(value: &'a Value, index: usize, field: &str) -> Result<&'a str, AccountScanError> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("entry {index} has no string {field}")))?;
    if text.len() > MAX_XDR_BASE64_BYTES {
        return Err(malformed(format!(
            "getLedgerEntries entry {index} exceeds the XDR size limit"
        )));
    }
    Ok(text)
}

fn entry_ledger(value: &Value, index: usize, field: &str) -> Result<u32, AccountScanError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|ledger| u32::try_from(ledger).ok())
        .ok_or_else(|| malformed(format!("entry {index} has no u32 {field}")))
}

fn ledger_field(value: &Value, field: &str) -> Result<u32, AccountScanError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|ledger| u32::try_from(ledger).ok())
        .ok_or_else(|| malformed(format!("getLedgerEntries has no u32 {field}")))
}

fn malformed(message: String) -> AccountScanError {
    AccountScanError::Rpc(RpcError::Malformed(message))
}

fn invalid(message: String) -> AccountScanError {
    AccountScanError::Rpc(RpcError::InvalidRequest(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classic_account::tests::{account_entry, account_key};
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ExtensionPoint, ScBytes, ScContractInstance,
        ScMapEntry,
    };

    struct Endpoint {
        response: Value,
        requests: RefCell<Vec<(String, Value)>>,
    }

    impl RpcTransport for Endpoint {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.requests.borrow_mut().push((method.into(), params));
            Ok(self.response.clone())
        }
    }

    fn contract(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn classic(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    fn instance_entry(contract: [u8; 32], blob: usize) -> Value {
        let key = LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(contract))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        };
        let storage = (blob > 0).then(|| {
            vec![ScMapEntry {
                key: ScVal::Symbol("blob".try_into().unwrap()),
                val: ScVal::Bytes(ScBytes(vec![1; blob].try_into().unwrap())),
            }]
            .try_into()
            .unwrap()
        });
        json!({
            "key": LedgerKey::ContractData(key.clone()).to_xdr_base64(xdr_limits()).unwrap(),
            "xdr": LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: key.contract,
                key: key.key,
                durability: key.durability,
                val: ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([3; 32])),
                    storage,
                }),
            })
            .to_xdr_base64(xdr_limits())
            .unwrap(),
            "lastModifiedLedgerSeq": 9,
            "liveUntilLedgerSeq": 20,
        })
    }

    fn classic_entry(byte: u8) -> Value {
        json!({
            "key": account_key(byte),
            "xdr": account_entry(byte, [1, 0, 0, 0], &[]),
            "lastModifiedLedgerSeq": 9,
        })
    }

    fn keys() -> BTreeSet<ClosureKey> {
        BTreeSet::from([
            ClosureKey::Account(AccountEntryKey::Instance),
            ClosureKey::Instance(contract(8)),
            ClosureKey::Classic(classic(1)),
            ClosureKey::Classic(classic(2)),
        ])
    }

    fn read(
        response: Value,
        keys: &BTreeSet<ClosureKey>,
    ) -> (Result<ClosureResponse, AccountScanError>, Endpoint) {
        let endpoint = Endpoint {
            response,
            requests: RefCell::new(Vec::new()),
        };
        let result = read_closure_entries(&endpoint, &ContractId(Hash([7; 32])), keys);
        (result, endpoint)
    }

    /// One request carries every kind of closure key; an omitted key is reported omitted, a
    /// classic entry has no TTL, and the network is not asked for.
    #[test]
    fn one_request_answers_mixed_keys_and_reports_omissions() {
        let (result, endpoint) = read(
            json!({
                "latestLedger": 10,
                "entries": [instance_entry([7; 32], 0), classic_entry(1)],
            }),
            &keys(),
        );
        let response = result.unwrap();
        assert_eq!(response.reported_latest_ledger, 10);
        let returned = |key: &ClosureKey| response.entries[key].returned.clone();
        let (_, instance) = returned(&ClosureKey::Account(AccountEntryKey::Instance)).unwrap();
        assert_eq!(instance.live_until_ledger, Some(20));
        let (_, account) = returned(&ClosureKey::Classic(classic(1))).unwrap();
        assert_eq!(account.live_until_ledger, None);
        assert!(returned(&ClosureKey::Instance(contract(8))).is_none());
        assert!(returned(&ClosureKey::Classic(classic(2))).is_none());
        let requests = endpoint.requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "getLedgerEntries");
        assert_eq!(requests[0].1["keys"].as_array().unwrap().len(), 4);
    }

    /// The account's instance requested again as a target would be the same ledger key twice.
    #[test]
    fn a_request_naming_one_ledger_key_twice_is_refused_before_io() {
        let (result, endpoint) = read(
            json!({"latestLedger": 10, "entries": []}),
            &BTreeSet::from([
                ClosureKey::Account(AccountEntryKey::Instance),
                ClosureKey::Instance(contract(7)),
            ]),
        );
        assert!(matches!(
            result,
            Err(AccountScanError::Rpc(RpcError::InvalidRequest(_)))
        ));
        assert!(endpoint.requests.borrow().is_empty());
    }

    #[test]
    fn each_response_defect_is_refused() {
        let mut swapped = classic_entry(1);
        swapped["xdr"] = classic_entry(2)["xdr"].clone();
        let mut untimed = instance_entry([7; 32], 0);
        untimed
            .as_object_mut()
            .unwrap()
            .remove("liveUntilLedgerSeq");
        let mut future = classic_entry(1);
        future["lastModifiedLedgerSeq"] = json!(11);
        let five = (0..5).map(|_| classic_entry(1)).collect::<Vec<_>>();
        for (name, response) in [
            (
                "unrequested",
                json!({"latestLedger": 10, "entries": [classic_entry(3)]}),
            ),
            (
                "duplicate",
                json!({"latestLedger": 10, "entries": [classic_entry(1), classic_entry(1)]}),
            ),
            (
                "another key's value",
                json!({"latestLedger": 10, "entries": [swapped]}),
            ),
            ("no TTL", json!({"latestLedger": 10, "entries": [untimed]})),
            (
                "modified later",
                json!({"latestLedger": 10, "entries": [future]}),
            ),
            ("ledger zero", json!({"latestLedger": 0, "entries": []})),
            ("no entries", json!({"latestLedger": 10})),
            (
                "more entries than keys",
                json!({"latestLedger": 10, "entries": five}),
            ),
        ] {
            let (result, _) = read(response, &keys());
            assert!(
                matches!(result, Err(AccountScanError::Rpc(RpcError::Malformed(_)))),
                "{name}: {result:?}"
            );
        }
    }

    /// Entries no request could need cannot make the scan retain more than its bound.
    #[test]
    fn returned_entry_bytes_are_bounded_while_decoding() {
        const PAYLOAD: usize = 500 * 1024;
        let count = MAX_SCAN_WITNESS_BYTES / PAYLOAD + 1;
        let mut keys = BTreeSet::new();
        let mut entries = Vec::new();
        for index in 0..count {
            let mut id = [100; 32];
            id[0] = u8::try_from(index).unwrap();
            keys.insert(ClosureKey::Instance(format!(
                "{}",
                stellar_strkey::Contract(id)
            )));
            entries.push(instance_entry(id, PAYLOAD));
        }
        let (result, _) = read(json!({"latestLedger": 10, "entries": entries}), &keys);
        assert!(matches!(
            result,
            Err(AccountScanError::Budget(
                "retained entry bytes exceed bound"
            ))
        ));
    }
}
