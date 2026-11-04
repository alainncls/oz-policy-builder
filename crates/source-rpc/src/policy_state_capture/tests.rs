use super::*;
use crate::RpcTransport;
use serde_json::{json, Value};
use std::cell::RefCell;
use stellar_xdr::{
    ContractCodeEntry, ContractCodeEntryExt, ContractDataEntry, ExtensionPoint, ScContractInstance,
    ScMapEntry,
};

struct EmptyRpc {
    requests: RefCell<Vec<String>>,
}
impl RpcTransport for EmptyRpc {
    fn call(&self, method: &str, _: Value) -> Result<Value, RpcError> {
        self.requests.borrow_mut().push(method.into());
        Ok(match method {
            "getNetwork" => {
                json!({"passphrase": ozpb_domain::TESTNET_PASSPHRASE,"protocolVersion": 25})
            }
            "getLatestLedger" => {
                json!({"id": "11".repeat(32),"sequence": 100,"protocolVersion": 25})
            }
            "getLedgerEntries" => json!({"entries": [],"latestLedger": 100}),
            _ => panic!("unexpected method"),
        })
    }
}

#[test]
fn omission_is_captured_with_a_real_ledger_hash_and_final_brackets() {
    let rpc = EmptyRpc {
        requests: RefCell::new(vec![]),
    };
    let address = format!("{}", stellar_strkey::Contract([1; 32]));
    let capture = capture_policy_state(
        &rpc,
        ozpb_domain::TESTNET_PASSPHRASE,
        &address,
        42,
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(capture.installed_context_rule_id, 42);
    assert_eq!(capture.observed_ledger, 100);
    assert_eq!(capture.ledger_hash, Hash32([0x11; 32]));
    assert_eq!(capture.entries.len(), 2);
    assert!(capture.entries.values().all(Option::is_none));
    assert!(rpc.requests.borrow().ends_with(&[
        "getLatestLedger".into(),
        "getLedgerEntries".into(),
        "getLatestLedger".into()
    ]));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    HashDrift,
    LedgerDrift,
    MissingTtl,
    FutureModified,
    Expired,
    Duplicate,
    Unexpected,
    WrongValue,
    InvalidXdr,
    MissingHash,
    HeaderMismatch,
    CodeHash,
    MissingCode,
    ClosureDrift,
    Leak,
}
struct FixtureRpc {
    fault: Fault,
    headers: RefCell<u32>,
    entries: BTreeMap<String, Value>,
    account: String,
}
fn vecval(values: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(values.try_into().unwrap()))
}
fn fields(values: Vec<(&str, ScVal)>) -> ScVal {
    let mut values: Vec<_> = values
        .into_iter()
        .map(|(k, val)| ScMapEntry {
            key: ScVal::Symbol(k.try_into().unwrap()),
            val,
        })
        .collect();
    values.sort_by(|a, b| a.key.cmp(&b.key));
    ScVal::Map(Some(values.try_into().unwrap()))
}
fn rule(id: u32) -> ScVal {
    fields(vec![
        (
            "name",
            ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
        ),
        (
            "context_type",
            vecval(vec![
                ScVal::Symbol("CallContract".try_into().unwrap()),
                ScVal::Address(
                    contract_address(&format!("{}", stellar_strkey::Contract([3; 32]))).unwrap(),
                ),
            ]),
        ),
        ("valid_until", ScVal::Void),
        ("signer_ids", vecval(vec![ScVal::U32(id)])),
        ("policy_ids", vecval(vec![])),
    ])
}
fn data(key: LedgerKey, val: ScVal) -> LedgerEntryData {
    let LedgerKey::ContractData(key) = key else {
        panic!("contract key")
    };
    LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: key.contract,
        key: key.key,
        durability: key.durability,
        val,
    })
}
fn wire(value: LedgerEntryData) -> Value {
    json!({"key":value.to_key().to_xdr_base64(xdr_limits()).unwrap(),
    "xdr":value.to_xdr_base64(xdr_limits()).unwrap(),"lastModifiedLedgerSeq":20,"liveUntilLedgerSeq":200})
}
impl FixtureRpc {
    fn new(fault: Fault) -> Self {
        let account = format!("{}", stellar_strkey::Contract([1; 32]));
        let addr = contract_address(&account).unwrap();
        let code = b"reader fixture code";
        let hash = Hash(sha256(code).0);
        let values = vec![
            wire(data(
                data_key(addr.clone(), ScVal::LedgerKeyContractInstance),
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(hash.clone()),
                    storage: None,
                }),
            )),
            wire(data(
                account_key(&addr, "ContextRuleData", 42).unwrap(),
                rule(7),
            )),
            wire(data(
                account_key(&addr, "SignerData", 7).unwrap(),
                fields(vec![
                    ("count", ScVal::U32(1)),
                    (
                        "signer",
                        vecval(vec![
                            ScVal::Symbol("Delegated".try_into().unwrap()),
                            ScVal::Address(
                                contract_address(&format!("{}", stellar_strkey::Contract([8; 32])))
                                    .unwrap(),
                            ),
                        ]),
                    ),
                ]),
            )),
            wire(LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: ContractCodeEntryExt::V0,
                hash,
                code: code.to_vec().try_into().unwrap(),
            })),
        ];
        Self {
            fault,
            headers: RefCell::new(0),
            entries: values
                .into_iter()
                .map(|v| (v["key"].as_str().unwrap().into(), v))
                .collect(),
            account,
        }
    }
    fn capture(&self) -> Result<PolicyStateCapture, RpcError> {
        capture_policy_state(
            self,
            ozpb_domain::TESTNET_PASSPHRASE,
            &self.account,
            42,
            &[],
            &[],
        )
    }
}
impl RpcTransport for FixtureRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        if self.fault == Fault::Leak {
            return Err(RpcError::Malformed("secret authorization payload".into()));
        }
        match method {
            "getNetwork" => {
                Ok(json!({"passphrase":ozpb_domain::TESTNET_PASSPHRASE,"protocolVersion":25}))
            }
            "getLatestLedger" => {
                *self.headers.borrow_mut() += 1;
                let odd = *self.headers.borrow() % 2 == 1;
                let mut result = json!({"id":if self.fault==Fault::HashDrift && !odd {"22".repeat(32)}else{"11".repeat(32)},
                    "sequence":if self.fault==Fault::LedgerDrift && !odd {101}else{100},"protocolVersion":25});
                if self.fault == Fault::MissingHash {
                    result.as_object_mut().unwrap().remove("id");
                }
                if self.fault == Fault::HeaderMismatch {
                    result["headerXdr"] = json!("AAAA");
                }
                Ok(result)
            }
            "getLedgerEntries" => {
                let mut entries: Vec<_> = params["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|key| self.entries.get(key.as_str().unwrap()).cloned())
                    .collect();
                if self.fault == Fault::ClosureDrift && *self.headers.borrow() % 2 == 1 {
                    let replacement = wire(data(
                        account_key(
                            &contract_address(&self.account).unwrap(),
                            "ContextRuleData",
                            42,
                        )
                        .unwrap(),
                        rule(8),
                    ));
                    for entry in &mut entries {
                        if entry["key"] == replacement["key"] {
                            *entry = replacement.clone();
                        }
                    }
                }
                if let Some(first) = entries.first_mut() {
                    match self.fault {
                        Fault::MissingTtl => {
                            first.as_object_mut().unwrap().remove("liveUntilLedgerSeq");
                        }
                        Fault::FutureModified => first["lastModifiedLedgerSeq"] = json!(101),
                        Fault::Expired => first["liveUntilLedgerSeq"] = json!(99),
                        Fault::InvalidXdr => first["xdr"] = json!("AAAA"),
                        Fault::WrongValue => {
                            first["xdr"] = wire(data(
                                data_key(
                                    contract_address(&format!(
                                        "{}",
                                        stellar_strkey::Contract([99; 32])
                                    ))
                                    .unwrap(),
                                    ScVal::LedgerKeyContractInstance,
                                ),
                                ScVal::Bool(true),
                            ))["xdr"]
                                .clone()
                        }
                        _ => {}
                    }
                }
                if self.fault == Fault::CodeHash {
                    for entry in &mut entries {
                        let value = LedgerEntryData::from_xdr_base64(
                            entry["xdr"].as_str().unwrap(),
                            xdr_limits(),
                        )
                        .unwrap();
                        if let LedgerEntryData::ContractCode(mut code) = value {
                            code.code = vec![1].try_into().unwrap();
                            entry["xdr"] = json!(LedgerEntryData::ContractCode(code)
                                .to_xdr_base64(xdr_limits())
                                .unwrap());
                        }
                    }
                }
                if self.fault == Fault::MissingCode {
                    entries.retain(|entry| {
                        !matches!(
                            LedgerKey::from_xdr_base64(
                                entry["key"].as_str().unwrap(),
                                xdr_limits()
                            )
                            .unwrap(),
                            LedgerKey::ContractCode(_)
                        )
                    });
                }
                if self.fault == Fault::Duplicate {
                    entries.push(entries[0].clone());
                }
                if self.fault == Fault::Unexpected {
                    entries.push(wire(data(
                        data_key(
                            contract_address(&format!("{}", stellar_strkey::Contract([99; 32])))
                                .unwrap(),
                            ScVal::LedgerKeyContractInstance,
                        ),
                        ScVal::Bool(true),
                    )));
                }
                Ok(json!({"latestLedger":100,"entries":entries}))
            }
            _ => panic!("unexpected RPC"),
        }
    }
}

#[test]
fn final_capture_contains_selected_rule_transitive_state_and_checked_code() {
    let rpc = FixtureRpc::new(Fault::None);
    let capture = rpc.capture().unwrap();
    assert_eq!(capture.entries.len(), 4);
    assert!(capture.entries.values().all(Option::is_some));
    assert_eq!(*rpc.headers.borrow(), 2);
}

#[test]
fn drift_and_hostile_metadata_never_produce_a_capture() {
    for fault in [
        Fault::HashDrift,
        Fault::LedgerDrift,
        Fault::MissingTtl,
        Fault::FutureModified,
        Fault::Duplicate,
        Fault::Unexpected,
        Fault::WrongValue,
        Fault::InvalidXdr,
        Fault::MissingHash,
        Fault::HeaderMismatch,
        Fault::CodeHash,
        Fault::ClosureDrift,
    ] {
        let rpc = FixtureRpc::new(fault);
        assert!(rpc.capture().is_err());
        assert!(*rpc.headers.borrow() <= 4);
    }
}

#[test]
fn archive_is_preserved_as_evidence_and_never_relabeled_live() {
    let capture = FixtureRpc::new(Fault::Expired).capture().unwrap();
    assert!(capture
        .entries
        .values()
        .flatten()
        .any(|entry| entry.live_until_ledger == Some(99)));
}

#[test]
fn request_and_response_failures_do_not_echo_transport_details() {
    let error = FixtureRpc::new(Fault::Leak)
        .capture()
        .unwrap_err()
        .to_string();
    assert!(!error.contains("secret authorization"));
    let rpc = EmptyRpc {
        requests: RefCell::new(vec![]),
    };
    let keys: Vec<_> = (0..201)
        .map(|i| {
            account_key(
                &contract_address(&format!("{}", stellar_strkey::Contract([1; 32]))).unwrap(),
                "SignerData",
                i,
            )
            .unwrap()
        })
        .collect();
    assert!(capture_policy_state(
        &rpc,
        ozpb_domain::TESTNET_PASSPHRASE,
        &format!("{}", stellar_strkey::Contract([1; 32])),
        42,
        &[],
        &keys
    )
    .is_err());
    assert!(rpc.requests.borrow().is_empty());
}

#[test]
fn a_present_instance_does_not_hide_omitted_code() {
    let capture = FixtureRpc::new(Fault::MissingCode).capture().unwrap();
    assert!(capture
        .entries
        .iter()
        .any(|(key, value)| matches!(key, LedgerKey::ContractCode(_)) && value.is_none()));
    assert!(capture.entries.iter().any(|(key,value)| matches!(key,LedgerKey::ContractData(data) if data.key==ScVal::LedgerKeyContractInstance)&&value.is_some()));
}

#[test]
fn policy_state_accepts_a_real_protocol30_header() {
    struct HeaderOnly(Value);
    impl RpcTransport for HeaderOnly {
        fn call(&self, method: &str, _: Value) -> Result<Value, RpcError> {
            assert_eq!(method, "getLatestLedger");
            Ok(self.0.clone())
        }
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/captured-testnet/protocol30-headers.json"
    ))
    .unwrap();
    for value in fixture["ledgers"].as_array().unwrap() {
        let captured = stellar_xdr::LedgerHeaderHistoryEntry::from_xdr_base64(
            value["headerXdr"].as_str().unwrap(),
            xdr_limits(),
        )
        .unwrap();
        let rpc = HeaderOnly(json!({
            "id":value["hash"],"sequence":value["sequence"],"protocolVersion":30,
            "headerXdr":captured.header.to_xdr_base64(xdr_limits()).unwrap()
        }));
        let checked = header(&rpc).unwrap();
        assert_eq!(checked.protocol, 30);
        assert_eq!(checked.sequence, captured.header.ledger_seq);
    }
}
