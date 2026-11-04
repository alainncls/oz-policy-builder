//! Execution of one reconstructed target call against an exact, captured-key source.
//!
//! The RPC replies here are deterministic fixture data. The code really runs the
//! captured Wasm and refuses uncaptured reads. The SDK supplies default ledger
//! configuration and the target has no account authorization, so this is partial
//! disposable-execution evidence, not the complete dry-run layer.

use ozpb_recorder_core::{fixtures, record, RecordOptions};
use ozpb_source_rpc::{read_invocation_footprint, FootprintCaptureError, RpcError, RpcTransport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    testutils::{HostError, Ledger, SnapshotSource, SnapshotSourceInput},
    xdr::{self as sdk_xdr, ReadXdr as _, WriteXdr as _},
    Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec as SVec,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use stellar_xdr::{
    ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
    ContractExecutable, ContractId, ExtensionPoint, Hash, HostFunction, InvokeContractArgs,
    LedgerEntryData, LedgerFootprint, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData,
    OperationBody, ScAddress, ScContractInstance, ScVal, SorobanTransactionData,
    TransactionEnvelope, TransactionExt, VecM,
};

const NETWORK: &str = "Test SDF Network ; September 2015";
const CONTRACT_ID: [u8; 32] = [7; 32];
// soroban-sdk 26.1.0 test_wasms/test_contract_data.wasm. Its put(Symbol,
// Symbol) writes a persistent key; get(Symbol) reads that key.
const TARGET_WASM: &[u8] = include_bytes!("fixtures/test_contract_data.wasm");

fn limits() -> stellar_xdr::Limits {
    stellar_xdr::Limits::none()
}

fn contract() -> ScAddress {
    ScAddress::Contract(ContractId(Hash(CONTRACT_ID)))
}

fn symbol(name: &str) -> ScVal {
    ScVal::Symbol(name.as_bytes().to_vec().try_into().unwrap())
}

fn key_and_value() -> (String, Value, Value, Value, String) {
    let hash = Hash(Sha256::digest(TARGET_WASM).into());
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(hash.clone()),
            storage: None,
        }),
    });
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
    let code = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash,
        code: TARGET_WASM.try_into().unwrap(),
    });
    let storage_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract(),
        key: symbol("known"),
        durability: ContractDataDurability::Persistent,
    });
    let storage = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract(),
        key: symbol("known"),
        durability: ContractDataDurability::Persistent,
        val: symbol("before"),
    });
    let raw = record(&fixtures::executed_snapshot(), RecordOptions::default())
        .unwrap()
        .raw
        .envelope_xdr_base64;
    let mut envelope = TransactionEnvelope::from_xdr_base64(&raw, limits()).unwrap();
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        panic!("fixture has a v1 envelope")
    };
    let mut operations: Vec<_> = v1.tx.operations.iter().cloned().collect();
    let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        panic!("fixture invokes a host function")
    };
    op.host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract(),
        function_name: "put".as_bytes().to_vec().try_into().unwrap(),
        args: vec![symbol("known"), symbol("after")].try_into().unwrap(),
    });
    op.auth = VecM::default();
    v1.tx.operations = operations.try_into().unwrap();
    let mut data = SorobanTransactionData::default();
    data.resources.footprint = LedgerFootprint {
        read_only: vec![instance_key.clone(), code_key.clone()]
            .try_into()
            .unwrap(),
        read_write: vec![storage_key.clone()].try_into().unwrap(),
    };
    v1.tx.ext = TransactionExt::V1(data);
    let envelope = envelope.to_xdr_base64(limits()).unwrap();
    let entry = |key: LedgerKey, data: LedgerEntryData| {
        json!({
            "key": key.to_xdr_base64(limits()).unwrap(),
            "xdr": data.to_xdr_base64(limits()).unwrap(),
            "lastModifiedLedgerSeq": 95,
            "liveUntilLedgerSeq": 120
        })
    };
    (
        envelope,
        entry(instance_key, instance),
        entry(code_key, code),
        entry(storage_key.clone(), storage),
        storage_key.to_xdr_base64(limits()).unwrap(),
    )
}

struct FixtureRpc {
    entries: Vec<Value>,
    calls: RefCell<Vec<String>>,
}

impl RpcTransport for FixtureRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push(method.to_string());
        match method {
            "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 26})),
            "getLedgerEntries" => {
                assert_eq!(params["xdrFormat"], "base64");
                assert_eq!(params["keys"].as_array().unwrap().len(), 3);
                Ok(json!({"latestLedger": 101, "entries": self.entries}))
            }
            other => panic!("unexpected RPC method: {other}"),
        }
    }
}

struct ExactSource {
    entries: BTreeMap<String, (Rc<sdk_xdr::LedgerEntry>, Option<u32>)>,
    rejected: Rc<RefCell<usize>>,
}

impl SnapshotSource for ExactSource {
    fn get(
        &self,
        key: &Rc<sdk_xdr::LedgerKey>,
    ) -> Result<Option<(Rc<sdk_xdr::LedgerEntry>, Option<u32>)>, HostError> {
        let encoded = key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap();
        match self.entries.get(&encoded) {
            Some(entry) => Ok(Some(entry.clone())),
            None => {
                *self.rejected.borrow_mut() += 1;
                Err(HostError::from((
                    sdk_xdr::ScErrorType::Storage,
                    sdk_xdr::ScErrorCode::ExceededLimit,
                )))
            }
        }
    }
}

#[test]
fn exact_captured_call_executes_and_missing_state_refuses() {
    let (envelope, instance, code, storage, storage_key) = key_and_value();
    let rpc = FixtureRpc {
        entries: vec![instance.clone(), code.clone(), storage.clone()],
        calls: RefCell::new(Vec::new()),
    };
    let capture = read_invocation_footprint(&rpc, NETWORK, &envelope).unwrap();
    assert_eq!(*rpc.calls.borrow(), ["getNetwork", "getLedgerEntries"]);
    assert_eq!(capture.reported_ledger.0, 101);
    assert_eq!(capture.entries.len(), 3);
    assert_eq!(capture.validated_wasm_instances, 1);
    assert!(capture.read_write_keys.contains(&storage_key));
    let call = capture.invocation.as_ref().expect("InvokeContract call");
    assert_eq!(call.function_name, "put");
    assert_eq!(call.args_xdr_base64.len(), 2);

    // SDK and RPC use different stellar-xdr revisions. Re-decode each vetted
    // entry from its canonical XDR and reject a key/data disagreement.
    let mut entries = BTreeMap::new();
    for (encoded, captured) in &capture.entries {
        let sdk_key = sdk_xdr::LedgerKey::from_xdr_base64(encoded, sdk_xdr::Limits::none())
            .expect("captured key is SDK-readable");
        let data_xdr =
            xdr30::WriteXdr::to_xdr_base64(&captured.data, xdr30::Limits::none()).unwrap();
        let sdk_data =
            sdk_xdr::LedgerEntryData::from_xdr_base64(&data_xdr, sdk_xdr::Limits::none())
                .expect("captured data is SDK-readable");
        assert_eq!(sdk_data.to_key(), sdk_key);
        entries.insert(
            encoded.clone(),
            (
                Rc::new(sdk_xdr::LedgerEntry {
                    last_modified_ledger_seq: captured.last_modified_ledger.0,
                    data: sdk_data,
                    ext: sdk_xdr::LedgerEntryExt::V0,
                }),
                captured.live_until_ledger.map(|seq| seq.0),
            ),
        );
    }
    let rejected = Rc::new(RefCell::new(0));
    let mut ledger_info = Env::default().ledger().get();
    ledger_info.sequence_number = capture.reported_ledger.0;
    ledger_info.network_id = capture.network_id.0 .0;
    let env = Env::from_ledger_snapshot(SnapshotSourceInput {
        source: Rc::new(ExactSource {
            entries,
            rejected: rejected.clone(),
        }),
        ledger_info: Some(ledger_info),
        snapshot: None,
    });
    let target = Address::from_str(&env, &call.contract_address);
    let args = SVec::from_iter(
        &env,
        call.args_xdr_base64.iter().map(|encoded| {
            let sdk_value = sdk_xdr::ScVal::from_xdr_base64(encoded, sdk_xdr::Limits::none())
                .expect("captured argument is SDK-readable");
            Val::try_from_val(&env, &sdk_value).expect("captured argument is a host value")
        }),
    );
    env.invoke_contract::<()>(&target, &Symbol::new(&env, &call.function_name), args);
    assert_eq!(*rejected.borrow(), 0);
    env.ledger().with_mut(|ledger| ledger.sequence_number += 1);
    let committed = env.to_ledger_snapshot();
    assert_eq!(committed.sequence_number, 102);
    let later = Env::from_ledger_snapshot(committed);
    let target = Address::from_str(&later, &call.contract_address);
    let after: Option<Symbol> = later.invoke_contract(
        &target,
        &Symbol::new(&later, "get"),
        soroban_sdk::vec![&later, Symbol::new(&later, "known").into_val(&later)],
    );
    assert_eq!(after, Some(Symbol::new(&later, "after")));

    // The original declared keys cannot justify a changed invocation that
    // reaches a different storage key.
    let unknown = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.try_invoke_contract::<Option<Symbol>, soroban_sdk::Error>(
            &Address::from_str(&env, &call.contract_address),
            &Symbol::new(&env, "get"),
            soroban_sdk::vec![&env, Symbol::new(&env, "unknown").into_val(&env)],
        )
    }));
    assert!(unknown.is_err() || unknown.unwrap().is_err());
    assert!(*rejected.borrow() > 0);

    let incomplete = FixtureRpc {
        entries: vec![instance, code],
        calls: RefCell::new(Vec::new()),
    };
    assert!(matches!(
        read_invocation_footprint(&incomplete, NETWORK, &envelope),
        Err(FootprintCaptureError::MissingDeclaredKey { .. })
    ));
}
