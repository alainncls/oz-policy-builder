//! One bounded read of selected pinned account storage entries.
//!
//! The endpoint supplies values and ledger metadata. This page does not authenticate the
//! endpoint, infer the history of an omitted key, or establish a coherent
//! snapshot with another call. No authority decision may be inferred from this page alone.
//! The account scan reads pages only for a closure above one request's key limit; otherwise it
//! reads the account's keys in its own mixed request and decodes them with
//! [`decode_account_entry`], as a page does.

use super::{
    account_storage::{decode_account_storage, AccountStorageEntry},
    contract_data::{read_contract_data_with_payloads, ContractDataStatus},
    ledger_witness::LedgerWitness,
    xdr_limits, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{LedgerSeq, NetworkId};
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, ScAddress, ScVal,
    WriteXdr,
};

const MAX_CONTRACT_ADDRESS_BYTES: usize = 128;

/// A key in the pinned `stellar-accounts` 0.7.2 storage schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AccountEntryKey {
    Instance,
    Rule(u32),
    Signer(u32),
    Policy(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AccountEntryStatus {
    /// The endpoint omitted this key; its history is unknown.
    Absent,
    Archived {
        entry: AccountStorageEntry,
        last_modified_ledger: u32,
    },
    Present {
        entry: AccountStorageEntry,
        last_modified_ledger: u32,
        live_until_ledger: u32,
    },
}

/// Typed values from one RPC call. The ledger number is endpoint-reported metadata, not
/// proof that separate pages or even values within this page formed a coherent snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountEntryPage {
    pub network_id: NetworkId,
    pub rpc_reported_latest_ledger: LedgerSeq,
    pub entries: BTreeMap<AccountEntryKey, AccountEntryStatus>,
    /// Raw XDR and metadata for the ordered scan digest. Returned archived entries are
    /// omitted because the scanner rejects them before constructing a digest.
    pub witnesses: BTreeMap<Vec<u8>, LedgerWitness>,
}

/// Derive exact ledger keys locally, read them once, and decode any returned live entries.
///
/// The caller chooses the endpoint and requested IDs. Network identity is checked against
/// `getNetwork`, but endpoint authentication remains the caller's responsibility. This
/// function makes no completeness claim about omitted keys.
pub(crate) fn read_account_entry_page<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    contract_id: &str,
    requested: &[AccountEntryKey],
) -> Result<AccountEntryPage, RpcError> {
    if requested.is_empty() || requested.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(RpcError::InvalidRequest(format!(
            "account entry page requires 1–{MAX_LEDGER_ENTRY_KEYS} keys"
        )));
    }
    if contract_id.len() > MAX_CONTRACT_ADDRESS_BYTES {
        return Err(RpcError::InvalidRequest(
            "contract address exceeds the encoded address size limit".into(),
        ));
    }
    let contract = contract_id
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| RpcError::InvalidRequest(format!("invalid contract address: {error}")))?;
    let contract = ContractId(Hash(contract.0));

    let mut keyed = BTreeMap::new();
    for &request in requested {
        let key = ledger_key(&contract, request);
        let encoded = LedgerKey::ContractData(key)
            .to_xdr_base64(xdr_limits())
            .map_err(|error| {
                RpcError::InvalidRequest(format!("cannot encode account key: {error}"))
            })?;
        if keyed.insert(encoded, request).is_some() {
            return Err(RpcError::InvalidRequest(
                "duplicate account entry key".into(),
            ));
        }
    }
    let encoded_keys = keyed.keys().cloned().collect::<Vec<_>>();
    let (read, entry_payloads) = read_contract_data_with_payloads(
        transport,
        network_passphrase,
        contract_id,
        &encoded_keys,
    )?;
    let mut statuses = BTreeMap::new();
    let mut witnesses = BTreeMap::new();
    for (encoded, request) in keyed {
        let status = read.entries.get(&encoded).ok_or_else(|| {
            RpcError::Malformed("contract-data reader omitted a requested key".into())
        })?;
        let key_xdr = LedgerKey::ContractData(ledger_key(&contract, request))
            .to_xdr(xdr_limits())
            .map_err(|error| RpcError::Malformed(format!("account key XDR: {error}")))?;
        let (status, witness) = decode_account_entry(
            &contract,
            request,
            status,
            entry_payloads.get(&encoded).map(Vec::as_slice),
        )?;
        if let Some(witness) = witness {
            witnesses.insert(key_xdr, witness);
        }
        statuses.insert(request, status);
    }
    Ok(AccountEntryPage {
        network_id: read.network_id,
        rpc_reported_latest_ledger: read.reported_latest_ledger,
        entries: statuses,
        witnesses,
    })
}

/// Decode one requested key's status against the pinned schema, with the digest witness of an
/// omitted or live entry. A returned archived entry is decoded but has no witness: the scanner
/// refuses it before building a digest. `payload` is the validated entry XDR of a returned key.
pub(crate) fn decode_account_entry(
    contract: &ContractId,
    request: AccountEntryKey,
    status: &ContractDataStatus,
    payload: Option<&[u8]>,
) -> Result<(AccountEntryStatus, Option<LedgerWitness>), RpcError> {
    let witness = match status {
        ContractDataStatus::Absent => Some(LedgerWitness::Absent),
        ContractDataStatus::Present {
            value: _,
            last_modified_ledger,
            live_until_ledger,
        } => Some(LedgerWitness::Present {
            entry_data_xdr: payload.map(<[u8]>::to_vec).ok_or_else(|| {
                RpcError::Malformed("present account entry lacks validated payload".into())
            })?,
            last_modified_ledger: *last_modified_ledger,
            live_until_ledger: *live_until_ledger,
        }),
        ContractDataStatus::Archived { .. } => None,
    };
    let status = match status {
        ContractDataStatus::Absent => AccountEntryStatus::Absent,
        ContractDataStatus::Archived {
            value,
            last_modified_ledger,
        } => {
            let entry =
                decode_account_storage(&ledger_key(contract, request), value).map_err(|error| {
                    RpcError::UndecodableAccountStorage(format!(
                        "archived account entry {request:?} has invalid pinned storage: {error}"
                    ))
                })?;
            AccountEntryStatus::Archived {
                entry,
                last_modified_ledger: *last_modified_ledger,
            }
        }
        ContractDataStatus::Present {
            value,
            last_modified_ledger,
            live_until_ledger,
        } => {
            let entry =
                decode_account_storage(&ledger_key(contract, request), value).map_err(|error| {
                    RpcError::UndecodableAccountStorage(format!(
                        "account entry {request:?} has invalid pinned storage: {error}"
                    ))
                })?;
            AccountEntryStatus::Present {
                entry,
                last_modified_ledger: *last_modified_ledger,
                live_until_ledger: *live_until_ledger,
            }
        }
    };
    Ok((status, witness))
}

pub(super) fn ledger_key(contract: &ContractId, request: AccountEntryKey) -> LedgerKeyContractData {
    let key = match request {
        AccountEntryKey::Instance => ScVal::LedgerKeyContractInstance,
        AccountEntryKey::Rule(id) => enum_key("ContextRuleData", id),
        AccountEntryKey::Signer(id) => enum_key("SignerData", id),
        AccountEntryKey::Policy(id) => enum_key("PolicyData", id),
    };
    LedgerKeyContractData {
        contract: ScAddress::Contract(contract.clone()),
        key,
        durability: ContractDataDurability::Persistent,
    }
}

fn enum_key(name: &'static str, id: u32) -> ScVal {
    let tag = ScVal::Symbol(name.try_into().expect("pinned storage tag fits ScSymbol"));
    ScVal::Vec(Some(
        vec![tag, ScVal::U32(id)]
            .try_into()
            .expect("two values fit ScVec"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_storage::{ContextRuleRecord, ContextType, InstanceCounters};
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ExtensionPoint, LedgerEntryData, ReadXdr,
        ScContractInstance, WriteXdr,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const CONTRACT: [u8; 32] = [7; 32];

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
                _ => panic!("unexpected method {method}"),
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
        format!("{}", stellar_strkey::Contract(CONTRACT))
    }

    fn fixture(name: &str) -> ScVal {
        let (_, hex) = include_str!("../tests/fixtures/account_storage_sdk_0_7_2.txt")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.split_once(' ').filter(|(found, _)| *found == name))
            .unwrap_or_else(|| panic!("missing SDK fixture {name}"));
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        ScVal::from_xdr(bytes, xdr_limits()).unwrap()
    }

    fn response_entry(request: AccountEntryKey, value: ScVal) -> Value {
        let contract = ContractId(Hash(CONTRACT));
        let key = ledger_key(&contract, request);
        let encoded_key = LedgerKey::ContractData(key.clone())
            .to_xdr_base64(xdr_limits())
            .unwrap();
        let xdr = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: key.contract,
            key: key.key,
            durability: key.durability,
            val: value,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        json!({
            "key": encoded_key,
            "xdr": xdr,
            "lastModifiedLedgerSeq": 9,
            "liveUntilLedgerSeq": 20
        })
    }

    fn read(mock: &Mock, requested: &[AccountEntryKey]) -> Result<AccountEntryPage, RpcError> {
        read_account_entry_page(mock, NETWORK, &address(), requested)
    }

    #[test]
    fn generated_keys_match_sdk_contracttype_fixtures() {
        let contract = ContractId(Hash(CONTRACT));
        let instance = ledger_key(&contract, AccountEntryKey::Instance);
        assert_eq!(instance.contract, ScAddress::Contract(contract.clone()));
        assert_eq!(instance.durability, ContractDataDurability::Persistent);
        assert_eq!(instance.key, ScVal::LedgerKeyContractInstance);
        for (request, fixture_name) in [
            (AccountEntryKey::Rule(17), "rule_key"),
            (AccountEntryKey::Signer(9), "signer_key"),
            (AccountEntryKey::Policy(11), "policy_key"),
        ] {
            let key = ledger_key(&contract, request);
            assert_eq!(key.contract, ScAddress::Contract(contract.clone()));
            assert_eq!(key.durability, ContractDataDurability::Persistent);
            assert_eq!(key.key, fixture(fixture_name));
        }
    }

    #[test]
    fn one_page_preserves_present_values_and_absent_uncertainty() {
        // These requested IDs are intentionally not the rule's closure: a page only
        // acquires selected keys and does not assert account-state completeness.
        let mock = mock(json!({
            "latestLedger": 10,
            "entries": [
                response_entry(AccountEntryKey::Rule(17), fixture("rule_value")),
                response_entry(AccountEntryKey::Signer(9), fixture("signer_value"))
            ]
        }));
        let page = read(
            &mock,
            &[
                AccountEntryKey::Rule(17),
                AccountEntryKey::Signer(9),
                AccountEntryKey::Policy(11),
            ],
        )
        .unwrap();
        assert_eq!(page.network_id, NetworkId::from_passphrase(NETWORK));
        assert_eq!(page.rpc_reported_latest_ledger, LedgerSeq(10));
        assert_eq!(page.entries.len(), 3);
        let rule_key = LedgerKey::ContractData(ledger_key(
            &ContractId(Hash(CONTRACT)),
            AccountEntryKey::Rule(17),
        ))
        .to_xdr(xdr_limits())
        .unwrap();
        let LedgerWitness::Present { entry_data_xdr, .. } = &page.witnesses[&rule_key] else {
            panic!("expected present rule witness");
        };
        let LedgerEntryData::ContractData(payload) =
            LedgerEntryData::from_xdr(entry_data_xdr.clone(), xdr_limits()).unwrap()
        else {
            panic!("witness must contain the complete contract-data payload");
        };
        assert_eq!(payload.ext, ExtensionPoint::V0);
        assert_eq!(payload.val, fixture("rule_value"));
        assert_eq!(
            page.entries[&AccountEntryKey::Policy(11)],
            AccountEntryStatus::Absent
        );
        assert_eq!(
            page.entries[&AccountEntryKey::Rule(17)],
            AccountEntryStatus::Present {
                entry: AccountStorageEntry::ContextRule(ContextRuleRecord {
                    id: 17,
                    name: "admin".into(),
                    context_type: ContextType::CallContract(format!(
                        "{}",
                        stellar_strkey::Contract([8; 32])
                    )),
                    valid_until: None,
                    signer_ids: vec![2],
                    policy_ids: vec![3],
                }),
                last_modified_ledger: 9,
                live_until_ledger: 20,
            }
        );
        assert_eq!(*mock.calls.borrow(), ["getNetwork", "getLedgerEntries"]);
    }

    #[test]
    fn present_instance_without_counters_remains_undecided() {
        let instance = ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([9; 32])),
            storage: None,
        });
        let mock = mock(json!({
            "latestLedger": 10,
            "entries": [response_entry(AccountEntryKey::Instance, instance)]
        }));
        let page = read(&mock, &[AccountEntryKey::Instance]).unwrap();
        assert_eq!(
            page.entries[&AccountEntryKey::Instance],
            AccountEntryStatus::Present {
                entry: AccountStorageEntry::Instance(InstanceCounters {
                    wasm_hash: ozpb_domain::Hash32([9; 32]),
                    next_id: None,
                    count: None,
                }),
                last_modified_ledger: 9,
                live_until_ledger: 20,
            }
        );
    }

    #[test]
    fn archived_entry_is_distinct_from_an_omitted_key() {
        let mut archived = response_entry(AccountEntryKey::Rule(17), fixture("rule_value"));
        archived["liveUntilLedgerSeq"] = json!(0);
        let mock = mock(json!({"latestLedger": 10, "entries": [archived]}));
        let page = read(
            &mock,
            &[AccountEntryKey::Rule(17), AccountEntryKey::Rule(18)],
        )
        .unwrap();
        assert_eq!(
            page.entries[&AccountEntryKey::Rule(18)],
            AccountEntryStatus::Absent
        );
        assert!(matches!(
            &page.entries[&AccountEntryKey::Rule(17)],
            AccountEntryStatus::Archived {
                entry: AccountStorageEntry::ContextRule(ContextRuleRecord { id: 17, .. }),
                last_modified_ledger: 9,
            }
        ));
    }

    #[test]
    fn malformed_values_and_cross_key_payloads_are_refused() {
        let bad_value = mock(json!({
            "latestLedger": 10,
            "entries": [response_entry(AccountEntryKey::Rule(17), ScVal::U32(1))]
        }));
        let error = read(&bad_value, &[AccountEntryKey::Rule(17)]).unwrap_err();
        assert!(
            matches!(&error, RpcError::UndecodableAccountStorage(detail)
                if detail.contains("invalid pinned storage")),
            "{error}"
        );

        let mut wrong_payload = response_entry(AccountEntryKey::Signer(9), fixture("signer_value"));
        wrong_payload["key"] =
            response_entry(AccountEntryKey::Rule(17), fixture("rule_value"))["key"].clone();
        let crossed = mock(json!({"latestLedger": 10, "entries": [wrong_payload]}));
        let error = read(
            &crossed,
            &[AccountEntryKey::Rule(17), AccountEntryKey::Signer(9)],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("payload does not match"), "{error}");
    }

    #[test]
    fn invalid_request_and_network_mismatch_do_not_yield_a_page() {
        let mock = mock(json!({"latestLedger": 10, "entries": []}));
        for requests in [
            vec![],
            vec![AccountEntryKey::Rule(1); 201],
            vec![AccountEntryKey::Rule(1), AccountEntryKey::Rule(1)],
        ] {
            assert!(matches!(
                read(&mock, &requests),
                Err(RpcError::InvalidRequest(_))
            ));
        }
        assert!(mock.calls.borrow().is_empty());

        let wrong_network = Mock {
            network: json!({"passphrase": "another network", "protocolVersion": 28}),
            ledger: json!({"latestLedger": 10, "entries": []}),
            calls: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            read(&wrong_network, &[AccountEntryKey::Instance]),
            Err(RpcError::NetworkMismatch { .. })
        ));
        assert_eq!(*wrong_network.calls.borrow(), ["getNetwork"]);
    }
}
