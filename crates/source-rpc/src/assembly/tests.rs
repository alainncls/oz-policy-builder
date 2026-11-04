use super::*;
use crate::xdr_limits;
use serde_json::{json, Value};
use std::cell::RefCell;

const NETWORK: &str = ozpb_domain::TESTNET_PASSPHRASE;

struct Rpc {
    responses: RefCell<Vec<(&'static str, Value)>>,
    calls: RefCell<Vec<(String, Value)>>,
}

impl RpcTransport for Rpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push((method.into(), params));
        let (expected, response) = self.responses.borrow_mut().remove(0);
        assert_eq!(method, expected);
        Ok(response)
    }
}

fn b64<T: WriteXdr>(value: &T) -> String {
    value.to_xdr_base64(xdr_limits()).unwrap()
}

fn fixture() -> (InstallAssemblyRequest, Rpc) {
    let payer = [7; 32];
    let account = ScAddress::Contract(ContractId(Hash([9; 32])));
    let invocation = InvokeContractArgs {
        contract_address: account.clone(),
        function_name: "add_context_rule".try_into().unwrap(),
        args: vec![ScVal::Void; 5].try_into().unwrap(),
    };
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account,
            nonce: 123,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invocation.clone()),
            sub_invocations: Default::default(),
        },
    };
    let id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer)));
    let ledger_key = LedgerKey::Account(LedgerKeyAccount {
        account_id: id.clone(),
    });
    let account_data = LedgerEntryData::Account(AccountEntry {
        account_id: id,
        balance: 50_000_000,
        seq_num: SequenceNumber(42),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: Default::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    });
    let data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: Default::default(),
                read_write: Default::default(),
            },
            instructions: 2000,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 1234,
    };
    let responses = vec![
        (
            "getNetwork",
            json!({"passphrase":NETWORK,"protocolVersion":29}),
        ),
        (
            "getLedgerEntries",
            json!({"latestLedger":100,"entries":[{
                "key":b64(&ledger_key),"xdr":b64(&account_data),"lastModifiedLedgerSeq":99
            }]}),
        ),
        (
            "getFeeStats",
            json!({"latestLedger":100,"sorobanInclusionFee":{"p90":"200"}}),
        ),
        (
            "simulateTransaction",
            json!({"latestLedger":101,"minResourceFee":"1234",
            "transactionData":b64(&data),"results":[{"xdr":b64(&ScVal::Void),"auth":[b64(&entry)]}]}),
        ),
    ];
    (
        InstallAssemblyRequest {
            invocation,
            fee_payer: format!("{}", stellar_strkey::ed25519::PublicKey(payer)),
            max_fee_stroops: 50_000,
            validity_ledgers: 20,
            authority_observed_ledger: 99,
        },
        Rpc {
            responses: RefCell::new(responses),
            calls: RefCell::new(vec![]),
        },
    )
}

#[test]
fn assembles_only_the_requested_install_without_signatures() {
    let (request, rpc) = fixture();
    let result = assemble_install_transaction(&rpc, NETWORK, &request).unwrap();
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(&result.envelope_xdr_base64, xdr_limits()).unwrap()
    else {
        panic!("v1 envelope")
    };
    assert!(envelope.signatures.is_empty());
    assert_eq!(envelope.tx.seq_num, SequenceNumber(43));
    assert_eq!(envelope.tx.fee, 1434);
    assert_eq!(envelope.tx.operations.len(), 1);
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        panic!("invoke")
    };
    assert_eq!(
        op.host_function,
        HostFunction::InvokeContract(request.invocation)
    );
    assert_eq!(op.auth.len(), 1);
    assert!(!crate::envelope_carries_signatures(&result.envelope_xdr_base64).unwrap());
    assert_eq!(result.simulation_ledger, 101);
    assert_eq!(result.sequence_read_ledger, 100);
    assert_eq!(result.restoration, AssemblyRestoration::None);
    assert_eq!(result.max_ledger, 120);
    assert_eq!(rpc.calls.borrow().last().unwrap().1["authMode"], "record");
}

#[test]
fn altered_auth_invocation_is_refused() {
    let (request, rpc) = fixture();
    let mut responses = rpc.responses.borrow_mut();
    let auth = responses[3].1["results"][0]["auth"][0].as_str().unwrap();
    let mut entry = SorobanAuthorizationEntry::from_xdr_base64(auth, xdr_limits()).unwrap();
    entry.root_invocation.function = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
        function_name: "remove_context_rule".try_into().unwrap(),
        ..request.invocation.clone()
    });
    responses[3].1["results"][0]["auth"][0] = b64(&entry).into();
    drop(responses);
    let error = assemble_install_transaction(&rpc, NETWORK, &request).unwrap_err();
    assert!(error.to_string().contains("authorization"), "{error}");
}

#[test]
fn fee_cap_and_sequence_overflow_are_refused() {
    let (mut request, rpc) = fixture();
    request.max_fee_stroops = 1000;
    assert!(assemble_install_transaction(&rpc, NETWORK, &request)
        .unwrap_err()
        .to_string()
        .contains("fee"));

    let (request, rpc) = fixture();
    let mut responses = rpc.responses.borrow_mut();
    let encoded = responses[1].1["entries"][0]["xdr"].as_str().unwrap();
    let LedgerEntryData::Account(mut account) =
        LedgerEntryData::from_xdr_base64(encoded, xdr_limits()).unwrap()
    else {
        unreachable!()
    };
    account.seq_num = SequenceNumber(i64::MAX);
    responses[1].1["entries"][0]["xdr"] = b64(&LedgerEntryData::Account(account)).into();
    drop(responses);
    assert!(assemble_install_transaction(&rpc, NETWORK, &request)
        .unwrap_err()
        .to_string()
        .contains("sequence"));
}

fn change_auth(rpc: &Rpc, f: impl FnOnce(&mut SorobanAuthorizationEntry)) {
    let mut responses = rpc.responses.borrow_mut();
    let encoded = responses[3].1["results"][0]["auth"][0].as_str().unwrap();
    let mut entry = SorobanAuthorizationEntry::from_xdr_base64(encoded, xdr_limits()).unwrap();
    f(&mut entry);
    responses[3].1["results"][0]["auth"][0] = b64(&entry).into();
}

#[test]
fn signed_wrong_account_and_nested_authorizations_are_refused() {
    for corruption in 0..5 {
        let (request, rpc) = fixture();
        change_auth(&rpc, |entry| match corruption {
            0 => {
                let SorobanCredentials::Address(c) = &mut entry.credentials else {
                    unreachable!()
                };
                c.signature = ScVal::Bytes(ScBytes(vec![1, 2].try_into().unwrap()));
            }
            1 => {
                let SorobanCredentials::Address(c) = &mut entry.credentials else {
                    unreachable!()
                };
                c.address = ScAddress::Contract(ContractId(Hash([8; 32])));
            }
            2 => entry.credentials = SorobanCredentials::SourceAccount,
            3 => {
                entry.root_invocation.sub_invocations =
                    vec![entry.root_invocation.clone()].try_into().unwrap()
            }
            _ => {
                let mut args = request.invocation.clone();
                args.args = vec![ScVal::U32(9); 5].try_into().unwrap();
                entry.root_invocation.function = SorobanAuthorizedFunction::ContractFn(args);
            }
        });
        assert!(
            assemble_install_transaction(&rpc, NETWORK, &request).is_err(),
            "corruption {corruption}"
        );
    }
}

#[test]
fn incomplete_or_conflicting_simulations_never_yield_an_envelope() {
    for corruption in 0..9 {
        let (request, rpc) = fixture();
        let mut responses = rpc.responses.borrow_mut();
        let sim = &mut responses[3].1;
        match corruption {
            0 => {
                sim.as_object_mut().unwrap().remove("results");
            }
            1 => sim["results"] = json!([]),
            2 => sim["results"][0]["auth"] = json!([]),
            3 => {
                sim["results"][0]["auth"] =
                    json!([sim["results"][0]["auth"][0], sim["results"][0]["auth"][0]])
            }
            4 => sim["minResourceFee"] = "999".into(),
            5 => sim["latestLedger"] = 98.into(),
            6 => sim["latestLedger"] = 120.into(),
            7 => sim["error"] = "PRIVATE-RPC-CONTENT".into(),
            _ => sim["transactionData"] = "invalid".into(),
        }
        drop(responses);
        let error = assemble_install_transaction(&rpc, NETWORK, &request)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE-RPC-CONTENT"));
    }
}

#[test]
fn source_account_identity_and_network_are_checked() {
    for corruption in 0..5 {
        let (request, rpc) = fixture();
        let mut responses = rpc.responses.borrow_mut();
        match corruption {
            0 => responses[0].1["passphrase"] = "PRIVATE-WRONG-NETWORK".into(),
            1 => responses[1].1["entries"] = json!([]),
            2 => {
                let wrong = LedgerKey::Account(LedgerKeyAccount {
                    account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([4; 32]))),
                });
                responses[1].1["entries"][0]["key"] = b64(&wrong).into();
            }
            3 => responses[1].1["entries"][0]["lastModifiedLedgerSeq"] = 101.into(),
            _ => responses[0].1["protocolVersion"] = (crate::MAX_SUPPORTED_PROTOCOL + 1).into(),
        }
        drop(responses);
        let error = assemble_install_transaction(&rpc, NETWORK, &request)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE-WRONG-NETWORK"));
        assert!(rpc
            .calls
            .borrow()
            .iter()
            .all(|(method, _)| method != "simulateTransaction"));
    }
}

#[test]
fn invalid_local_parameters_do_not_send_any_request() {
    for corruption in 0..5 {
        let (mut request, rpc) = fixture();
        match corruption {
            0 => request.validity_ledgers = 121,
            1 => request.validity_ledgers = 0,
            2 => request.fee_payer = "not-a-key".into(),
            3 => request.max_fee_stroops = 99,
            _ => request.invocation.function_name = "remove_context_rule".try_into().unwrap(),
        }
        assert!(assemble_install_transaction(&rpc, NETWORK, &request).is_err());
        assert!(rpc.calls.borrow().is_empty());
    }
}

fn restored_data() -> SorobanTransactionData {
    SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: Default::default(),
                read_write: vec![LedgerKey::ContractCode(LedgerKeyContractCode {
                    hash: Hash([1; 32]),
                })]
                .try_into()
                .unwrap(),
            },
            instructions: 0,
            disk_read_bytes: 500,
            write_bytes: 500,
        },
        resource_fee: 4321,
    }
}

#[test]
fn separate_restoration_returns_only_a_restore_transaction_and_its_fee() {
    let (request, rpc) = fixture();
    let mut invocation_data = restored_data();
    invocation_data.resource_fee = 1234;
    rpc.responses.borrow_mut()[3].1["transactionData"] = b64(&invocation_data).into();
    rpc.responses.borrow_mut()[3].1["restorePreamble"] = json!({
        "transactionData": b64(&restored_data()), "minResourceFee":"4321"
    });
    let output = assemble_install_transaction(&rpc, NETWORK, &request).unwrap();
    assert_eq!(output.restoration, AssemblyRestoration::SeparateTransaction);
    assert_eq!(output.fee_stroops, 4521);
    let TransactionEnvelope::Tx(e) =
        TransactionEnvelope::from_xdr_base64(&output.envelope_xdr_base64, xdr_limits()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(e.tx.operations.len(), 1);
    assert!(matches!(
        e.tx.operations[0].body,
        OperationBody::RestoreFootprint(_)
    ));
    assert_eq!(e.tx.ext, TransactionExt::V1(restored_data()));
    assert!(e.signatures.is_empty());
}

#[test]
fn the_next_open_ledger_must_fit_below_the_exclusive_maximum() {
    for restore in [false, true] {
        // latestLedger is already closed. Even a same-ledger simulation with a
        // one-ledger validity window leaves no possible inclusion ledger.
        for (validity, simulated, accepted) in [(1, 100, false), (2, 101, false), (2, 100, true)] {
            let (mut request, rpc) = fixture();
            request.validity_ledgers = validity;
            {
                let mut responses = rpc.responses.borrow_mut();
                responses[3].1["latestLedger"] = simulated.into();
                if restore {
                    let mut invocation_data = restored_data();
                    invocation_data.resource_fee = 1234;
                    responses[3].1["transactionData"] = b64(&invocation_data).into();
                    responses[3].1["restorePreamble"] = json!({
                        "transactionData": b64(&restored_data()), "minResourceFee":"4321"
                    });
                }
            }
            let result = assemble_install_transaction(&rpc, NETWORK, &request);
            if accepted {
                let output = result.unwrap();
                assert!(output.simulation_ledger + 1 < output.max_ledger);
                assert_eq!(
                    output.restoration == AssemblyRestoration::SeparateTransaction,
                    restore
                );
            } else {
                assert!(
                    result.unwrap_err().to_string().contains("expired"),
                    "validity={validity}, simulation={simulated}, restoration={restore}"
                );
            }
        }
    }
}

#[test]
fn automatic_restoration_is_labeled_and_its_indices_are_checked() {
    for indices in [vec![0], vec![0, 0], vec![1]] {
        let (request, rpc) = fixture();
        let mut data = restored_data();
        data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: indices.clone().try_into().unwrap(),
        });
        rpc.responses.borrow_mut()[3].1["transactionData"] = b64(&data).into();
        rpc.responses.borrow_mut()[3].1["minResourceFee"] = "4321".into();
        let output = assemble_install_transaction(&rpc, NETWORK, &request);
        if indices == [0] {
            let output = output.unwrap();
            assert_eq!(output.restoration, AssemblyRestoration::Automatic);
            assert_eq!(output.fee_stroops, 4521);
        } else {
            assert!(output.is_err());
        }
    }
}

#[test]
fn fee_overflow_and_expired_bounds_refuse_without_wrapping() {
    let (mut request, rpc) = fixture();
    request.max_fee_stroops = u32::MAX;
    let mut data = restored_data();
    data.resource_fee = i64::from(u32::MAX);
    rpc.responses.borrow_mut()[3].1["transactionData"] = b64(&data).into();
    rpc.responses.borrow_mut()[3].1["minResourceFee"] = u32::MAX.to_string().into();
    assert!(assemble_install_transaction(&rpc, NETWORK, &request)
        .unwrap_err()
        .to_string()
        .contains("overflow"));
    let (mut request, rpc) = fixture();
    request.validity_ledgers = 1;
    assert!(assemble_install_transaction(&rpc, NETWORK, &request)
        .unwrap_err()
        .to_string()
        .contains("expired"));
}

#[test]
fn transport_parser_diagnostics_are_not_returned_to_clients() {
    struct BrokenTransport;
    impl RpcTransport for BrokenTransport {
        fn call(&self, _: &str, _: Value) -> Result<Value, RpcError> {
            Err(RpcError::Malformed("PRIVATE-RESPONSE-ID-AND-URL".into()))
        }
    }
    let (request, _) = fixture();
    let error = assemble_install_transaction(&BrokenTransport, NETWORK, &request)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE-RESPONSE-ID-AND-URL"), "{error}");
    assert!(error.contains("withheld"));
}

#[test]
fn restoration_refuses_unrelated_classic_and_temporary_keys() {
    let valid_key = restored_data().resources.footprint.read_write[0].clone();
    let classic = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
    });
    let temporary = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
        key: ScVal::U32(1),
        durability: ContractDataDurability::Temporary,
    });
    let persistent = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
        key: ScVal::U32(1),
        durability: ContractDataDurability::Persistent,
    });
    // A legitimate invocation may contain classic or temporary entries, but those
    // entries can never be restored. Restoration must also belong to this invocation.
    for (key, in_invocation, allowed) in [
        (valid_key.clone(), true, true),
        (persistent, true, true),
        (valid_key, false, false),
        (classic, true, false),
        (temporary, true, false),
    ] {
        for automatic in [false, true] {
            if automatic && !in_invocation {
                continue; // automatic restoration already indexes its own footprint
            }
            let (request, rpc) = fixture();
            let mut restoration = restored_data();
            restoration.resources.footprint.read_write = vec![key.clone()].try_into().unwrap();
            let mut invocation = restoration.clone();
            if !in_invocation {
                invocation.resources.footprint.read_write = Default::default();
            }
            let mut responses = rpc.responses.borrow_mut();
            if automatic {
                invocation.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                    archived_soroban_entries: vec![0].try_into().unwrap(),
                });
            } else {
                responses[3].1["restorePreamble"] = json!({
                    "transactionData": b64(&restoration), "minResourceFee":"4321"
                });
            }
            invocation.resource_fee = 1234;
            responses[3].1["transactionData"] = b64(&invocation).into();
            drop(responses);
            let output = assemble_install_transaction(&rpc, NETWORK, &request);
            assert_eq!(
                output.is_ok(),
                allowed,
                "automatic={automatic}, in_invocation={in_invocation}, key={key:?}: {output:?}"
            );
        }
    }
}
