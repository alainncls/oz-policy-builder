//! A deliberately narrow selected-key execution fixture. It checks that a
//! captured Wasm target can run from a strict SDK snapshot source, and that an
//! uncaptured storage read fails. It does not reconstruct authorization or
//! establish the target's complete storage closure.

use ozpb_source_rpc::{read_target_capture, RpcError, RpcTransport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    testutils::{HostError, Ledger, SnapshotSource, SnapshotSourceInput},
    xdr::{self as sdk_xdr, ReadXdr as _, WriteXdr as _},
    Address, Env, IntoVal, Symbol,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use stellar_xdr::{
    ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
    ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, ScAddress, ScContractInstance, ScVal,
};

const NETWORK: &str = "Test SDF Network ; September 2015";
const CONTRACT_ID: [u8; 32] = [7; 32];
// From soroban-sdk 26.1.0 test_wasms/test_contract_data.wasm, sha256
// fd41d2f77920ca07b723e05f732a82db4c2f6459eb2be6b40c4f225434569550.
// Its contract spec exports put(Symbol, Symbol), get(Symbol) -> Option<Symbol>, del(Symbol).
const TARGET_WASM: &[u8] = include_bytes!("fixtures/test_contract_data.wasm");

fn limits() -> stellar_xdr::Limits {
    stellar_xdr::Limits::none()
}

fn address() -> String {
    stellar_strkey::Contract(CONTRACT_ID)
        .to_string()
        .as_str()
        .to_owned()
}

fn entries() -> (Value, Value, Value, String) {
    let hash = Hash(Sha256::digest(TARGET_WASM).into());
    let contract = ScAddress::Contract(ContractId(Hash(CONTRACT_ID)));
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let instance_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(hash.clone()),
            storage: None,
        }),
    });
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
    let code_data = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash,
        code: TARGET_WASM.try_into().unwrap(),
    });
    let storage_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key: ScVal::Symbol("known".try_into().unwrap()),
        durability: ContractDataDurability::Persistent,
    });
    let storage_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract,
        key: ScVal::Symbol("known".try_into().unwrap()),
        durability: ContractDataDurability::Persistent,
        val: ScVal::Symbol("value".try_into().unwrap()),
    });
    let entry = |key: LedgerKey, data: LedgerEntryData| {
        json!({
            "key": key.to_xdr_base64(limits()).unwrap(),
            "xdr": data.to_xdr_base64(limits()).unwrap(),
            "lastModifiedLedgerSeq": 95,
            "liveUntilLedgerSeq": 120
        })
    };
    (
        entry(instance_key, instance_data),
        entry(code_key, code_data),
        entry(storage_key.clone(), storage_data),
        storage_key.to_xdr_base64(limits()).unwrap(),
    )
}

struct FixtureRpc {
    instance: Value,
    code: Value,
    final_response: Value,
    calls: RefCell<usize>,
}

impl RpcTransport for FixtureRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        *self.calls.borrow_mut() += 1;
        match method {
            "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 26})),
            "getLedgerEntries" => {
                let keys = params["keys"].as_array().unwrap();
                if keys.len() > 1 {
                    return Ok(self.final_response.clone());
                }
                let key = LedgerKey::from_xdr_base64(keys[0].as_str().unwrap(), limits()).unwrap();
                match key {
                    LedgerKey::ContractData(_) => {
                        Ok(json!({"latestLedger": 100, "entries": [self.instance.clone()]}))
                    }
                    LedgerKey::ContractCode(_) => {
                        Ok(json!({"latestLedger": 100, "entries": [self.code.clone()]}))
                    }
                    other => panic!("unexpected key: {other:?}"),
                }
            }
            other => panic!("unexpected method: {other}"),
        }
    }
}

struct StrictCapturedSource {
    entries: BTreeMap<String, (Rc<sdk_xdr::LedgerEntry>, Option<u32>)>,
    rejected: Rc<RefCell<usize>>,
}

impl SnapshotSource for StrictCapturedSource {
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
fn captured_wasm_runs_for_selected_key_and_refuses_uncaptured_read() {
    let (instance, code, storage, selected_key) = entries();
    let rpc = FixtureRpc {
        instance: instance.clone(),
        code: code.clone(),
        final_response: json!({"latestLedger": 101, "entries": [instance, code, storage]}),
        calls: RefCell::new(0),
    };
    let capture = read_target_capture(&rpc, NETWORK, &address(), &[selected_key]).unwrap();
    assert_eq!(*rpc.calls.borrow(), 4);
    assert_eq!(capture.entries.len(), 3);

    // The SDK's XDR revision is older than the RPC adapter's. Encode each
    // vetted entry through XDR rather than assuming their Rust types match.
    let mut snapshot_entries = BTreeMap::new();
    for (encoded, captured) in &capture.entries {
        let sdk_key =
            sdk_xdr::LedgerKey::from_xdr_base64(encoded, sdk_xdr::Limits::none()).unwrap();
        let data_xdr =
            xdr30::WriteXdr::to_xdr_base64(&captured.data, xdr30::Limits::none()).unwrap();
        let sdk_data =
            sdk_xdr::LedgerEntryData::from_xdr_base64(&data_xdr, sdk_xdr::Limits::none()).unwrap();
        assert_eq!(sdk_data.to_key(), sdk_key);
        let full_entry = sdk_xdr::LedgerEntry {
            last_modified_ledger_seq: captured.last_modified_ledger.0,
            data: sdk_data,
            ext: sdk_xdr::LedgerEntryExt::V0,
        };
        snapshot_entries.insert(
            sdk_key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap(),
            (Rc::new(full_entry), Some(captured.live_until_ledger.0)),
        );
    }
    let rejected = Rc::new(RefCell::new(0));
    let source = StrictCapturedSource {
        entries: snapshot_entries,
        rejected: rejected.clone(),
    };
    // The RPC reply does not contain a full ledger header or network config.
    // This test supplies SDK defaults and binds only the reported sequence and
    // network ID; the result cannot describe execution at the endpoint's state.
    let mut ledger_info = Env::default().ledger().get();
    ledger_info.sequence_number = capture.reported_ledger.0;
    ledger_info.network_id = capture.network_id.0 .0;
    let env = Env::from_ledger_snapshot(SnapshotSourceInput {
        source: Rc::new(source),
        ledger_info: Some(ledger_info),
        snapshot: None,
    });
    let target = Address::from_str(&env, &capture.contract_address);
    let known: Option<Symbol> = env.invoke_contract(
        &target,
        &Symbol::new(&env, "get"),
        soroban_sdk::vec![&env, Symbol::new(&env, "known").into_val(&env)],
    );
    assert_eq!(known, Some(Symbol::new(&env, "value")));
    assert_eq!(*rejected.borrow(), 0);

    let unknown = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.try_invoke_contract::<Option<Symbol>, soroban_sdk::Error>(
            &target,
            &Symbol::new(&env, "get"),
            soroban_sdk::vec![&env, Symbol::new(&env, "unknown").into_val(&env)],
        )
    }));
    assert!(unknown.is_err() || unknown.unwrap().is_err());
    assert!(*rejected.borrow() > 0);

    let refused_before_write = *rejected.borrow();
    let unlisted_write = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.try_invoke_contract::<(), soroban_sdk::Error>(
            &target,
            &Symbol::new(&env, "put"),
            soroban_sdk::vec![
                &env,
                Symbol::new(&env, "unknown").into_val(&env),
                Symbol::new(&env, "untrusted").into_val(&env),
            ],
        )
    }));
    assert!(unlisted_write.is_err() || unlisted_write.unwrap().is_err());
    assert!(*rejected.borrow() > refused_before_write);
    let still_known: Option<Symbol> = env.invoke_contract(
        &target,
        &Symbol::new(&env, "get"),
        soroban_sdk::vec![&env, Symbol::new(&env, "known").into_val(&env)],
    );
    assert_eq!(still_known, Some(Symbol::new(&env, "value")));

    // A write to an already captured key commits in the disposable environment.
    // A later ledger and a fresh environment observe the changed value. This
    // deliberately says nothing about new keys or account authorization.
    env.invoke_contract::<()>(
        &target,
        &Symbol::new(&env, "put"),
        soroban_sdk::vec![
            &env,
            Symbol::new(&env, "known").into_val(&env),
            Symbol::new(&env, "changed").into_val(&env),
        ],
    );
    env.ledger().with_mut(|ledger| ledger.sequence_number += 1);
    let committed = env.to_ledger_snapshot();
    assert_eq!(committed.sequence_number, capture.reported_ledger.0 + 1);
    let later = Env::from_ledger_snapshot(committed);
    let later_target = Address::from_str(&later, &capture.contract_address);
    let changed: Option<Symbol> = later.invoke_contract(
        &later_target,
        &Symbol::new(&later, "get"),
        soroban_sdk::vec![&later, Symbol::new(&later, "known").into_val(&later)],
    );
    assert_eq!(changed, Some(Symbol::new(&later, "changed")));
}
