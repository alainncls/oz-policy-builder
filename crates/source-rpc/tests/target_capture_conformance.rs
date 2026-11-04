//! Native target capture against **verbatim protocol-30 testnet responses**.
//!
//! The unit tests in `target_capture/tests.rs` mock RPC with JSON we wrote, which can only
//! confirm our own assumption about which field carries which XDR type (see
//! `rpc_conformance.rs` for the bug that taught us this). The fixtures in
//! `captured-testnet/target-capture-protocol30/` are the `result` objects a real endpoint returned for one
//! read-only capture: `getNetwork`, record-mode `simulateTransaction`, `getLedgerEntries` and
//! `getLedgers`. The transfer uses a recently active pinned testnet account and a funded recipient.
//! The protocol-29 fixture remains in its original directory as historical data; it is
//! explicitly refused for capture by this protocol-30 build.
//! The only edit is dropping `getLedgers`' `metadataXdr`, the ledger's whole close meta (~140 KB),
//! which capture never reads. Nothing is signed or submitted. Refresh with
//! `cargo test -p ozpb-source-rpc --test target_capture_conformance -- --ignored`.

use ozpb_source_rpc::{capture_native_target, xdr_limits, RpcError, RpcTransport};
use serde_json::Value;
use std::cell::RefCell;
use std::path::PathBuf;
use stellar_xdr::{
    AccountId, ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerHeaderHistoryEntry, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, PublicKey, ReadXdr, ScAddress, ScVal, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

const NETWORK: &str = "Test SDF Network ; September 2015";
const ACCOUNT: &str = "CCMQ4NMMKBOXXEYENL3MS2GSTEJHFYTCDF3LZXNUM3C45NUTLA72PUKN";
const RECIPIENT: &str = "GB6IN2X73PZP5OECYTMFJFWO6AJLQE4UIHAMSJQW3MHYHGILNADFKWU6";
const AMOUNT: u64 = 1_000_000;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/captured-testnet/target-capture-protocol30")
}

/// The unsigned envelope: transfer(ACCOUNT, RECIPIENT, AMOUNT) on testnet's native SAC.
fn envelope() -> String {
    envelope_for(ACCOUNT, RECIPIENT)
}

fn envelope_for(account_address: &str, recipient_address: &str) -> String {
    let network = ozpb_domain::NetworkId::from_passphrase(NETWORK);
    let sac = ozpb_source_rpc::native_asset_contract(&network).unwrap();
    let account = stellar_strkey::Contract::from_string(account_address).unwrap();
    let recipient = stellar_strkey::ed25519::PublicKey::from_string(recipient_address).unwrap();
    let call = InvokeContractArgs {
        contract_address: sac,
        function_name: "transfer".try_into().unwrap(),
        args: vec![
            ScVal::Address(ScAddress::Contract(ContractId(Hash(account.0)))),
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256(recipient.0)),
            ))),
            ScVal::I128(Int128Parts { hi: 0, lo: AMOUNT }),
        ]
        .try_into()
        .unwrap(),
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            // Simulation needs an existing source account; it is never charged or signed.
            source_account: MuxedAccount::Ed25519(Uint256(recipient.0)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(call),
                    auth: Default::default(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    })
    .to_xdr_base64(xdr_limits())
    .unwrap()
}

/// Replays the recorded `result` objects by method and records the requests made.
struct Replay {
    calls: RefCell<Vec<(String, Value)>>,
}

impl RpcTransport for Replay {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push((method.into(), params));
        let path = fixtures().join(format!("{method}.json"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        Ok(serde_json::from_str(&text).unwrap())
    }
}

#[test]
fn a_captured_native_transfer_response_set_binds_header_config_and_entries() {
    let transport = Replay {
        calls: RefCell::new(vec![]),
    };
    let capture = capture_native_target(&transport, NETWORK, &envelope())
        .expect("the verbatim testnet responses must capture");
    assert_eq!(capture.provenance, "rpc_reported");
    assert_eq!(capture.read_only_keys.len(), 1);
    assert_eq!(capture.read_write_keys.len(), 2);
    assert_eq!(capture.entries.len(), 3);
    let header =
        LedgerHeaderHistoryEntry::from_xdr_base64(&capture.header_xdr, xdr_limits()).unwrap();
    assert_eq!(header.header.ledger_seq, capture.observed_ledger);
    assert_eq!(header.header.ledger_version, 30);
    let calls = transport.calls.borrow();
    let methods: Vec<_> = calls.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        methods,
        [
            "getNetwork",
            "simulateTransaction",
            "getLedgerEntries",
            "getLedgers"
        ]
    );
    assert_eq!(calls[1].1["authMode"], "record");
    assert_eq!(calls[1].1["transaction"], envelope());
    assert_eq!(calls[3].1["startLedger"], capture.observed_ledger);
    // The live account runs the pinned account release.
    assert_eq!(
        capture.account_code_hash,
        ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()
    );
    // Input for the runtime's recorded-testnet test (scripts/test-captured-target.sh).
    if let Ok(dir) = std::env::var("OZPB_TARGET_CAPTURE_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::write(
            dir.join("capture.json"),
            serde_json::to_vec(&capture).unwrap(),
        )
        .unwrap();
        let call = serde_json::json!({
            "account": ACCOUNT,
            "recipient": RECIPIENT,
            "amount": AMOUNT.to_string(),
            "observed_ledger": capture.observed_ledger,
        });
        std::fs::write(dir.join("call.json"), call.to_string()).unwrap();
    }
}

/// Forwards to a live endpoint and stores each `result` as a fixture (close meta dropped).
#[cfg(feature = "http")]
struct Recorder(ozpb_source_rpc::HttpTransport);

#[cfg(feature = "http")]
impl RpcTransport for Recorder {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let result = self.0.call(method, params)?;
        let mut stored = result.clone();
        if let Some(ledgers) = stored.get_mut("ledgers").and_then(Value::as_array_mut) {
            for ledger in ledgers {
                ledger.as_object_mut().unwrap().remove("metadataXdr");
            }
        }
        std::fs::create_dir_all(fixtures()).unwrap();
        std::fs::write(
            fixtures().join(format!("{method}.json")),
            serde_json::to_string_pretty(&stored).unwrap() + "\n",
        )
        .unwrap();
        Ok(result)
    }
}

#[cfg(feature = "http")]
#[test]
#[ignore = "reads testnet RPC and rewrites fixtures; run deliberately"]
fn record_a_live_native_transfer_capture() {
    let url = std::env::var("OZPB_TESTNET_RPC")
        .unwrap_or_else(|_| "https://rpc.testnet.stellar.gateway.fm".into());
    let transport = Recorder(ozpb_source_rpc::HttpTransport::new(url));
    let capture = capture_native_target(&transport, NETWORK, &envelope()).unwrap();
    assert_eq!(capture.entries.len(), 3);
}

/// Older XDR remains decodable, but a captured job must not be relabelled for a newer host.
#[test]
fn historical_protocol29_capture_is_not_accepted_as_protocol30() {
    struct Historical;
    impl RpcTransport for Historical {
        fn call(&self, method: &str, _: Value) -> Result<Value, RpcError> {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/captured-testnet/target-capture")
                .join(format!("{method}.json"));
            Ok(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
        }
    }
    let error = capture_native_target(
        &Historical,
        NETWORK,
        &envelope_for(
            "CARDQAE4VYNTNB5JDTEIWVJYTZ5V6KPI5S4WJRTN2BOOFUT2AR5MQGIJ",
            "GCTSURZBB5ELTL3XMEDKQVLVAMKURVUJOAUXPE7DGSXSUCPEDPYDV37R",
        ),
    )
    .unwrap_err();
    assert!(error.to_string().contains("ledger header"), "{error}");
}
