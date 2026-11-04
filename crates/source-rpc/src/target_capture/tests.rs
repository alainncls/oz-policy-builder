use super::*;
use crate::{xdr_limits, RpcTransport};
use ozpb_domain::{sha256, NetworkId};
use ozpb_recorder_core::{fixtures, record, RecordOptions};
use serde_json::{json, Value};
use std::cell::RefCell;
use stellar_xdr::*;

const NETWORK: &str = "Test SDF Network ; September 2015";
const LEDGER: u32 = 1000;

struct Fixture {
    envelope: String,
    simulation: Value,
    entries: Value,
    header: Value,
    nonce_key: String,
    calls: RefCell<Vec<String>>,
}
impl RpcTransport for Fixture {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push(method.into());
        Ok(match method {
            "getNetwork" => json!({"passphrase": NETWORK, "protocolVersion": 30}),
            "simulateTransaction" => {
                assert_eq!(params["authMode"], "record");
                assert_eq!(params["transaction"], self.envelope);
                self.simulation.clone()
            }
            "getLedgerEntries" => {
                // The recorded authorization's fresh nonce key is never requested.
                assert!(!params["keys"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(self.nonce_key)));
                self.entries.clone()
            }
            "getLedgers" => {
                assert_eq!(params["startLedger"], LEDGER);
                assert_eq!(params["pagination"]["limit"], 1);
                self.header.clone()
            }
            _ => panic!("unexpected RPC method {method}"),
        })
    }
}
fn encode<T: WriteXdr>(v: &T) -> String {
    v.to_xdr_base64(xdr_limits()).unwrap()
}
fn fixture() -> Fixture {
    let network = NetworkId::from_passphrase(NETWORK);
    let native = sha256(
        &HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(network.0 .0),
            contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
        })
        .to_xdr(xdr_limits())
        .unwrap(),
    );
    let token = ScAddress::Contract(ContractId(Hash(native.0)));
    let account = ScAddress::Contract(ContractId(Hash([1; 32])));
    let recipient = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([3; 32])));
    let call = InvokeContractArgs {
        contract_address: token.clone(),
        function_name: "transfer".try_into().unwrap(),
        args: vec![
            ScVal::Address(account.clone()),
            ScVal::Address(ScAddress::Account(recipient.clone())),
            ScVal::I128(Int128Parts {
                hi: 0,
                lo: 1_000_000,
            }),
        ]
        .try_into()
        .unwrap(),
    };
    let mut envelope = TransactionEnvelope::from_xdr_base64(
        &record(&fixtures::executed_snapshot(), RecordOptions::default())
            .unwrap()
            .raw
            .envelope_xdr_base64,
        xdr_limits(),
    )
    .unwrap();
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        panic!()
    };
    v1.signatures = Default::default();
    v1.tx.operations = vec![Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(call.clone()),
            auth: Default::default(),
        }),
    }]
    .try_into()
    .unwrap();
    v1.tx.ext = TransactionExt::V0;
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: token.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::StellarAsset,
            storage: None,
        }),
    });
    let balance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: token,
        key: ScVal::Vec(Some(
            vec![
                ScVal::Symbol("Balance".try_into().unwrap()),
                ScVal::Address(account.clone()),
            ]
            .try_into()
            .unwrap(),
        )),
        durability: ContractDataDurability::Persistent,
        val: ScVal::I128(Int128Parts {
            hi: 0,
            lo: 100_000_000,
        }),
    });
    let classic = LedgerEntryData::Account(AccountEntry {
        account_id: recipient,
        balance: 100_000_000,
        ..Default::default()
    });
    let archival =
        LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(StateArchivalSettings {
            max_entry_ttl: 631200,
            min_temporary_ttl: 16,
            min_persistent_ttl: 4096,
            ..Default::default()
        }));
    let code = b"\0asm\x01\0\0\0".to_vec();
    let code_hash = Hash(sha256(&code).0);
    let account_instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: account.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(code_hash.clone()),
            storage: None,
        }),
    });
    let account_code = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: code_hash,
        code: code.try_into().unwrap(),
    });
    let nonce = LedgerKey::ContractData(LedgerKeyContractData {
        contract: account.clone(),
        key: ScVal::LedgerKeyNonce(ScNonceKey { nonce: 17 }),
        durability: ContractDataDurability::Temporary,
    });
    // The shape a real record-mode simulation reports (see target_capture_conformance.rs).
    let footprint = LedgerFootprint {
        read_only: vec![
            account_instance.to_key(),
            instance.to_key(),
            account_code.to_key(),
        ]
        .try_into()
        .unwrap(),
        read_write: vec![classic.to_key(), nonce.clone(), balance.to_key()]
            .try_into()
            .unwrap(),
    };
    let data = SorobanTransactionData {
        resources: SorobanResources {
            footprint,
            ..Default::default()
        },
        ..Default::default()
    };
    let auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account,
            nonce: 17,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(call),
            sub_invocations: Default::default(),
        },
    };
    let mut header = LedgerHeader {
        ledger_version: 30,
        ledger_seq: LEDGER,
        base_reserve: 5_000_000,
        ..Default::default()
    };
    header.scp_value.close_time = TimePoint(100_000);
    let hash = sha256(&header.to_xdr(xdr_limits()).unwrap());
    let header = LedgerHeaderHistoryEntry {
        hash: Hash(hash.0),
        header,
        ext: LedgerHeaderHistoryEntryExt::V0,
    };
    Fixture {
        envelope: encode(&envelope),
        simulation: json!({"latestLedger":LEDGER,"transactionData":encode(&data),"minResourceFee":data.resource_fee.to_string(),"results":[{"xdr":encode(&ScVal::Void),"auth":[encode(&auth)]}]}),
        entries: json!({"latestLedger":LEDGER,"entries":([instance,balance,classic,archival,account_instance,account_code].into_iter().map(|entry|json!({"key":encode(&entry.to_key()),"xdr":encode(&entry),"lastModifiedLedgerSeq":999,"liveUntilLedgerSeq":if matches!(entry,LedgerEntryData::ContractData(_)|LedgerEntryData::ContractCode(_)){Some(900000)}else{None}})).collect::<Vec<_>>())}),
        header: json!({"ledgers":[{"sequence":LEDGER,"hash":hash.to_hex(),"ledgerCloseTime":"100000","headerXdr":encode(&header)}]}),
        nonce_key: encode(&nonce),
        calls: RefCell::new(vec![]),
    }
}
#[test]
fn native_target_capture_binds_recorded_call_header_config_and_exact_entries() {
    let fixture = fixture();
    let capture = capture_native_target(&fixture, NETWORK, &fixture.envelope).unwrap();
    assert_eq!(capture.observed_ledger, LEDGER);
    assert_eq!(capture.provenance, "rpc_reported");
    assert_eq!(capture.entries.len(), 3);
    assert_eq!(capture.read_only_keys.len(), 1);
    assert_eq!(capture.read_write_keys.len(), 2);
    assert_eq!(
        capture.header_xdr,
        fixture.header["ledgers"][0]["headerXdr"]
    );
    assert_eq!(
        capture.recording_auth_xdr,
        fixture.simulation["results"][0]["auth"][0]
    );
    assert_eq!(
        capture.account_code_hash,
        sha256(b"\0asm\x01\0\0\0").to_hex()
    );
    // The network is checked once, before the simulation: nothing is requested between the
    // simulation and the entry read but the read.
    assert_eq!(
        *fixture.calls.borrow(),
        [
            "getNetwork",
            "simulateTransaction",
            "getLedgerEntries",
            "getLedgers"
        ]
    );
}
#[test]
fn native_target_capture_refuses_incoherence_archive_and_unrelated_recording() {
    type Mutation = fn(&mut Fixture);
    fn edit_header(f: &mut Fixture, change: fn(&mut LedgerHeaderHistoryEntry), rehash: bool) {
        let mut header = LedgerHeaderHistoryEntry::from_xdr_base64(
            f.header["ledgers"][0]["headerXdr"].as_str().unwrap(),
            xdr_limits(),
        )
        .unwrap();
        change(&mut header);
        let hash = sha256(&header.header.to_xdr(xdr_limits()).unwrap());
        if rehash {
            header.hash = Hash(hash.0);
        }
        f.header["ledgers"][0]["hash"] = json!(hash.to_hex());
        f.header["ledgers"][0]["headerXdr"] = json!(encode(&header));
    }
    const HEADER: &str = "the ledger header does not hash to, or describe, the captured ledger";
    let cases: [(Mutation, &str); 18] = [
        (
            |f| f.entries["latestLedger"] = json!(LEDGER + 1),
            "kept observing different ledgers",
        ),
        (
            |f| f.header["ledgers"][0]["hash"] = json!("ff".repeat(32)),
            HEADER,
        ),
        (
            |f| f.header["ledgers"][0]["sequence"] = json!(LEDGER + 1),
            HEADER,
        ),
        (
            |f| f.header["ledgers"][0]["ledgerCloseTime"] = json!("1"),
            HEADER,
        ),
        // Valid, re-hashed headers that describe something else.
        (
            |f| edit_header(f, |h| h.header.ledger_version = 28, true),
            HEADER,
        ),
        (
            |f| edit_header(f, |h| h.header.ledger_seq = LEDGER + 1, true),
            HEADER,
        ),
        // A changed header whose embedded hash is stale.
        (
            |f| edit_header(f, |h| h.header.base_reserve += 1, false),
            HEADER,
        ),
        (
            |f| f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER - 1),
            "is archived at the captured ledger",
        ),
        (
            |f| f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER),
            "expires at the captured ledger",
        ),
        (
            |f| {
                f.entries["entries"].as_array_mut().unwrap().remove(1);
            },
            "is missing from getLedgerEntries",
        ),
        (
            |f| f.simulation["results"][0]["auth"] = json!([]),
            "exactly one recorded authorization root",
        ),
        (
            |f| f.simulation["restorePreamble"] = valid_preamble(),
            "requires restoration",
        ),
        (
            |f| f.simulation["results"][0]["xdr"] = json!(encode(&ScVal::Bool(true))),
            "did not return void",
        ),
        (
            |f| {
                let mut auth = SorobanAuthorizationEntry::from_xdr_base64(
                    f.simulation["results"][0]["auth"][0].as_str().unwrap(),
                    xdr_limits(),
                )
                .unwrap();
                let child = auth.root_invocation.clone();
                auth.root_invocation.sub_invocations = vec![child].try_into().unwrap();
                f.simulation["results"][0]["auth"][0] = json!(encode(&auth));
            },
            "not exactly the account's transfer",
        ),
        (
            |f| f.entries["entries"][3]["liveUntilLedgerSeq"] = json!(LEDGER + 10),
            "state-archival configuration is inconsistent",
        ),
        (
            |f| {
                let archival = LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(
                    StateArchivalSettings {
                        max_entry_ttl: 631200,
                        min_temporary_ttl: 16,
                        min_persistent_ttl: 0,
                        ..Default::default()
                    },
                ));
                f.entries["entries"][3]["xdr"] = json!(encode(&archival));
            },
            "state-archival configuration is inconsistent",
        ),
        // Account code missing from the response.
        (
            |f| {
                f.entries["entries"].as_array_mut().unwrap().remove(5);
            },
            "is missing from getLedgerEntries",
        ),
        // The target footprint reads account storage beyond its instance, and RPC returns it.
        (
            |f| {
                let mut data = SorobanTransactionData::from_xdr_base64(
                    f.simulation["transactionData"].as_str().unwrap(),
                    xdr_limits(),
                )
                .unwrap();
                let LedgerKey::ContractData(instance) =
                    data.resources.footprint.read_only[0].clone()
                else {
                    panic!()
                };
                let signers = ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: instance.contract,
                    key: ScVal::Symbol("Signers".try_into().unwrap()),
                    durability: ContractDataDurability::Persistent,
                    val: ScVal::Void,
                };
                let entry = LedgerEntryData::ContractData(signers);
                let mut read_only = data.resources.footprint.read_only.to_vec();
                read_only.push(entry.to_key());
                data.resources.footprint.read_only = read_only.try_into().unwrap();
                f.simulation["transactionData"] = json!(encode(&data));
                f.entries["entries"].as_array_mut().unwrap().push(json!({
                    "key": encode(&entry.to_key()),
                    "xdr": encode(&entry),
                    "lastModifiedLedgerSeq": 999,
                    "liveUntilLedgerSeq": 900000,
                }));
            },
            "the target reads account storage",
        ),
    ];
    for (index, (mutate, reason)) in cases.into_iter().enumerate() {
        let mut fixture = fixture();
        mutate(&mut fixture);
        match capture_native_target(&fixture, NETWORK, &fixture.envelope) {
            Err(error) => assert!(
                error.to_string().contains(reason),
                "mutation {index}: {error}"
            ),
            Ok(_) => panic!("mutation {index} was accepted"),
        }
        assert!(fixture.calls.borrow().len() <= 10);
    }
}

#[test]
fn native_target_capture_refuses_unsupported_envelopes_before_any_rpc() {
    let fixture = fixture();
    let envelope = TransactionEnvelope::from_xdr_base64(&fixture.envelope, xdr_limits()).unwrap();
    let with_call = |mutate: fn(&mut InvokeContractArgs)| {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut changed else {
            panic!()
        };
        let mut operations = v1.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!()
        };
        let HostFunction::InvokeContract(call) = &mut op.host_function else {
            panic!()
        };
        mutate(call);
        v1.tx.operations = operations.try_into().unwrap();
        encode(&changed)
    };
    let signed = {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut changed else {
            panic!()
        };
        v1.signatures = vec![DecoratedSignature {
            hint: SignatureHint([0; 4]),
            signature: Signature(vec![1; 64].try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        encode(&changed)
    };
    const SHAPE: &str = "only a positive native-asset transfer";
    for (candidate, reason) in [
        (signed, "the envelope carries signatures"),
        (
            with_call(|call| {
                call.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])))
            }),
            SHAPE,
        ),
        (
            with_call(|call| call.function_name = "approve".try_into().unwrap()),
            SHAPE,
        ),
        (
            with_call(|call| {
                let mut args = call.args.to_vec();
                args[2] = ScVal::I128(Int128Parts { hi: 0, lo: 0 });
                call.args = args.try_into().unwrap();
            }),
            SHAPE,
        ),
    ] {
        match capture_native_target(&fixture, NETWORK, &candidate) {
            Err(error) => assert!(error.to_string().contains(reason), "{error}"),
            Ok(_) => panic!("an unsupported envelope was accepted"),
        }
        assert!(fixture.calls.borrow().is_empty());
    }
}

/// The caller's own envelope is refused locally under the input codes the shells map
/// (`E_RESOURCE_LIMIT`, `E_ENVELOPE_PARSE`, `E_UNSUPPORTED_ENVELOPE`), never as an endpoint
/// fault, and nothing is sent.
#[test]
fn native_target_capture_names_input_refusals_by_code() {
    let fixture = fixture();
    let envelope = TransactionEnvelope::from_xdr_base64(&fixture.envelope, xdr_limits()).unwrap();
    let edited = |edit: fn(&mut TransactionV1Envelope)| {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut changed else {
            panic!()
        };
        edit(v1);
        encode(&changed)
    };
    let signed = edited(|v1| {
        v1.signatures = vec![DecoratedSignature {
            hint: SignatureHint([0; 4]),
            signature: Signature(vec![1; 64].try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
    });
    let approve = edited(|v1| {
        let mut operations = v1.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!()
        };
        let HostFunction::InvokeContract(call) = &mut op.host_function else {
            panic!()
        };
        call.function_name = "approve".try_into().unwrap();
        v1.tx.operations = operations.try_into().unwrap();
    });
    let with_memo = edited(|v1| v1.tx.memo = Memo::Id(7));
    let (head, tail) = fixture.envelope.split_at(fixture.envelope.len() / 2);
    let spaced = format!("{head} {tail}");
    let oversized = "A".repeat(crate::MAX_XDR_BASE64_BYTES + 1);
    for (candidate, expected) in [
        (
            signed,
            "E_UNSUPPORTED_ENVELOPE: native target capture refused",
        ),
        (
            approve,
            "E_UNSUPPORTED_ENVELOPE: native target capture refused",
        ),
        (with_memo, "E_UNSUPPORTED_ENVELOPE: "),
        ("not-an-envelope".to_string(), "E_ENVELOPE_PARSE: "),
        (spaced, "E_ENVELOPE_PARSE: "),
        (oversized, "E_RESOURCE_LIMIT: "),
    ] {
        let error = capture_native_target(&fixture, NETWORK, &candidate)
            .expect_err("an unsupported envelope was accepted");
        assert!(error.to_string().starts_with(expected), "{error}");
        assert!(fixture.calls.borrow().is_empty(), "{error}");
    }
}

/// Answers the `nth` call of a method in place of the endpoint, or declines with `None`.
type FaultFn<'a> = dyn Fn(&str, usize) -> Option<Result<Value, RpcError>> + 'a;

/// A transport that answers through the fixture except where `fault` answers first.
struct Faulty<'a> {
    inner: &'a Fixture,
    fault: Box<FaultFn<'a>>,
    seen: RefCell<std::collections::BTreeMap<String, usize>>,
}
impl RpcTransport for Faulty<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let nth = {
            let mut seen = self.seen.borrow_mut();
            let count = seen.entry(method.to_string()).or_default();
            *count += 1;
            *count - 1
        };
        match (self.fault)(method, nth) {
            Some(reply) => reply,
            None => self.inner.call(method, params),
        }
    }
}

/// Once simulation has run, the endpoint holds the envelope and can put it in any later reply:
/// an error message, a reported network name, a response ID. No endpoint text reaches the
/// error, whichever request carried it.
#[test]
fn native_target_capture_withholds_endpoint_text() {
    let fixture = fixture();
    let secret = fixture.envelope.clone();
    type Fault = fn(&str) -> Result<Value, RpcError>;
    let echo: Fault = |s| Err(RpcError::Rpc(s.into()));
    let named: Fault = |s| Ok(json!({"passphrase": s, "protocolVersion": 30}));
    let gateway: Fault = |s| {
        Err(RpcError::Transport(format!(
            "HTTP 500 from the endpoint: {s}"
        )))
    };
    let foreign_id: Fault = |s| {
        Err(RpcError::Malformed(format!(
            "response id \"{s}\" does not match"
        )))
    };
    // (method, its nth call, the fault, whether the error must stay a network mismatch)
    let cases: Vec<(&str, usize, Fault, bool)> = vec![
        ("getNetwork", 0, echo, false),
        ("getNetwork", 0, named, true),
        ("simulateTransaction", 0, echo, false),
        ("simulateTransaction", 0, gateway, false),
        ("simulateTransaction", 0, foreign_id, false),
        ("getLedgerEntries", 0, echo, false),
        ("getLedgers", 0, echo, false),
        ("getLedgers", 0, gateway, false),
    ];
    for (method, nth, fault, mismatch) in cases {
        let secret = secret.clone();
        let transport = Faulty {
            inner: &fixture,
            fault: Box::new(move |called, seen| {
                (called == method && seen == nth).then(|| fault(&secret))
            }),
            seen: RefCell::new(Default::default()),
        };
        let error = capture_native_target(&transport, NETWORK, &fixture.envelope)
            .expect_err("an endpoint fault was accepted");
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(
                !text.contains(&fixture.envelope),
                "{method}#{nth} reached the error: {text}"
            );
        }
        // The category survives: a different network is still a network mismatch.
        assert_eq!(
            matches!(error, RpcError::NetworkMismatch { .. }),
            mismatch,
            "{method}#{nth}: {error}"
        );
    }
}

/// An envelope that does not decode is refused with one fixed description. The decoder's own
/// message names an input byte and its offset, which is envelope content.
#[test]
fn native_target_capture_parse_refusals_are_fixed_descriptions() {
    let fixture = fixture();
    let (head, tail) = fixture.envelope.split_at(fixture.envelope.len() / 2);
    for candidate in [
        // Not base64 at a distinctive byte.
        format!("{head}!{tail}"),
        // Base64 that is not a transaction envelope.
        "AAAA".to_string(),
        // A truncated envelope.
        head.chars().take(head.len() / 4 * 4).collect(),
    ] {
        let error = capture_native_target(&fixture, NETWORK, &candidate)
            .expect_err("an undecodable envelope was accepted");
        assert!(matches!(error, RpcError::EnvelopeParse(_)), "{error}");
        assert_eq!(
            error.to_string(),
            format!(
                "E_ENVELOPE_PARSE: {}",
                crate::preflight::ENVELOPE_DECODE_REFUSAL
            )
        );
        assert!(fixture.calls.borrow().is_empty());
    }
}

/// The simulation is classified as preflight classifies it: only a non-empty string error, with
/// no results or restoration and a ledger the endpoint read, is the target refusing the call;
/// a preamble, a success that restored archived entries, or an archived or expiring footprint
/// entry is archived target state. Everything else stays an endpoint answer (`E_RPC`). No
/// classification carries the endpoint's text, which could quote the envelope.
#[test]
fn native_target_capture_classifies_the_simulation_like_preflight() {
    #[derive(Debug, PartialEq)]
    enum Kind {
        Refused,
        Archived,
        Rpc,
    }
    type Mutation = Box<dyn Fn(&mut Fixture)>;
    let quoted = fixture().envelope;
    let failed = |error: Value| -> Mutation {
        Box::new(move |f: &mut Fixture| {
            f.simulation["error"] = error.clone();
            f.simulation.as_object_mut().unwrap().remove("results");
        })
    };
    let archived = |indices: Vec<u32>| -> Mutation {
        Box::new(move |f: &mut Fixture| {
            let mut data = SorobanTransactionData::from_xdr_base64(
                f.simulation["transactionData"].as_str().unwrap(),
                xdr_limits(),
            )
            .unwrap();
            data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                archived_soroban_entries: indices.clone().try_into().unwrap(),
            });
            f.simulation["transactionData"] = json!(encode(&data));
        })
    };
    // A success that restored entries is still malformed if its resource fee is not complete
    // and consistent. It must remain an endpoint failure, never an archival-state diagnosis.
    for fee in [
        None,
        Some(Value::Null),
        Some(json!(123)),
        Some(json!("not-a-fee")),
        Some(json!("-1")),
        Some(json!("18446744073709551616")),
        Some(json!("1")),
    ] {
        let mut f = fixture();
        archived(vec![2])(&mut f);
        if let Some(fee) = fee {
            f.simulation["minResourceFee"] = fee;
        } else {
            f.simulation
                .as_object_mut()
                .unwrap()
                .remove("minResourceFee");
        }
        let error = capture_native_target(&f, NETWORK, &f.envelope).unwrap_err();
        assert!(
            matches!(error, RpcError::Malformed(_) | RpcError::Rpc(_)),
            "{error}"
        );
    }
    let refusal = format!("HostError: Error(Contract, #10) balance is not sufficient: {quoted}");
    let preamble = |value: Value| -> Mutation {
        Box::new(move |f: &mut Fixture| f.simulation["restorePreamble"] = value.clone())
    };
    let mut wrong_fee = valid_preamble();
    wrong_fee["minResourceFee"] = json!("2");
    let cases: Vec<(&str, Mutation, Kind)> = vec![
        ("a failed simulation", failed(json!(refusal)), Kind::Refused),
        ("an empty error", failed(json!("")), Kind::Rpc),
        ("a null error", failed(Value::Null), Kind::Rpc),
        (
            "a non-string error",
            failed(json!({ "message": refusal })),
            Kind::Rpc,
        ),
        (
            "an error alongside results",
            Box::new(|f: &mut Fixture| f.simulation["error"] = json!("refused")),
            Kind::Rpc,
        ),
        (
            "an error alongside a restoration preamble",
            Box::new(move |f: &mut Fixture| {
                failed(json!("refused"))(f);
                f.simulation["restorePreamble"] = json!({ "transactionData": "AAAA" });
            }),
            Kind::Rpc,
        ),
        (
            "an error before the endpoint read its ledger",
            Box::new(move |f: &mut Fixture| {
                failed(json!("refused"))(f);
                f.simulation["latestLedger"] = json!(0);
            }),
            Kind::Rpc,
        ),
        (
            "a restoration preamble",
            preamble(valid_preamble()),
            Kind::Archived,
        ),
        // Preflight validates a preamble before reporting restoration; so does capture.
        (
            "an empty restoration preamble",
            preamble(json!({})),
            Kind::Rpc,
        ),
        (
            "a preamble with undecodable transaction data",
            preamble(json!({ "transactionData": quoted.clone(), "minResourceFee": "1" })),
            Kind::Rpc,
        ),
        (
            "a preamble whose fee is not its data's",
            preamble(wrong_fee),
            Kind::Rpc,
        ),
        (
            "a malformed restoration preamble",
            Box::new(|f: &mut Fixture| f.simulation["restorePreamble"] = json!("restore")),
            Kind::Rpc,
        ),
        (
            "a success that restored archived entries",
            archived(vec![2]),
            Kind::Archived,
        ),
        (
            "an archived index outside the footprint",
            archived(vec![9]),
            Kind::Rpc,
        ),
        (
            "an archived footprint entry",
            Box::new(|f: &mut Fixture| {
                f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER - 1)
            }),
            Kind::Archived,
        ),
        (
            // The reader judges archival at its own ledger: from a node behind or ahead of the
            // simulation that says nothing about the call at L, so it is retried as any ledger
            // mismatch, and a persistent one is an endpoint answer.
            "an entry archived at a ledger other than the simulation's",
            Box::new(|f: &mut Fixture| {
                f.entries["latestLedger"] = json!(LEDGER + 1);
                f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER);
            }),
            Kind::Rpc,
        ),
        (
            "a footprint entry expiring at the captured ledger",
            Box::new(|f: &mut Fixture| {
                f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER)
            }),
            Kind::Archived,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut fixture = fixture();
        mutate(&mut fixture);
        let error = capture_native_target(&fixture, NETWORK, &fixture.envelope)
            .expect_err("a refused simulation was accepted");
        let kind = match error {
            RpcError::TargetRefused(_) => Kind::Refused,
            RpcError::TargetArchived(_) => Kind::Archived,
            _ => Kind::Rpc,
        };
        assert_eq!(kind, expected, "{name}: {error}");
        // A refused or archived simulation is the call's outcome: nothing is read after it.
        if matches!(
            name,
            "a failed simulation"
                | "a restoration preamble"
                | "a success that restored archived entries"
        ) {
            assert_eq!(
                *fixture.calls.borrow(),
                ["getNetwork", "simulateTransaction"],
                "{name}"
            );
        }
        if name == "an entry archived at a ledger other than the simulation's" {
            assert!(
                error
                    .to_string()
                    .contains("kept observing different ledgers"),
                "{error}"
            );
            assert_eq!(
                fixture
                    .calls
                    .borrow()
                    .iter()
                    .filter(|m| *m == "simulateTransaction")
                    .count(),
                CAPTURE_ATTEMPTS,
                "retried as a ledger mismatch"
            );
        }
        let code = match kind {
            Kind::Refused => "E_TARGET_REFUSED: ",
            Kind::Archived => "E_TARGET_ARCHIVED: ",
            Kind::Rpc => "E_RPC: ",
        };
        assert!(error.to_string().starts_with(code), "{name}: {error}");
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(&fixture.envelope), "{name}: {text}");
            assert!(!text.contains("HostError"), "{name}: {text}");
        }
    }
}

/// A restoration preamble whose transaction data decodes and whose fee is that data's own, as
/// preflight requires before it reports restoration.
fn valid_preamble() -> Value {
    let data = SorobanTransactionData {
        resource_fee: 4321,
        ..Default::default()
    };
    json!({ "transactionData": encode(&data), "minResourceFee": "4321" })
}
