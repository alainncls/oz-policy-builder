//! Actual SDK-30 native SAC, pinned account Wasm and freshly generated policy over a capture.
//! The capture here is built locally from a real SAC deployment; it is not an RPC observation.
#[path = "support/captured_fixture.rs"]
mod captured_fixture;

use captured_fixture::{enc, job, job_from, job_with_balance, SENDER_BALANCE};
use ed25519_dalek::{Signer, SigningKey};
use ozpb_execution_runtime::{
    execute_captured, prepare_captured, CapturedTargetJob, DelegateSigner, SignRequest,
    SignatureResponse,
};
use soroban_sdk::xdr::{self, ReadXdr, WriteXdr};

struct Capability;
impl DelegateSigner for Capability {
    fn sign(&mut self, r: &SignRequest) -> Result<SignatureResponse, String> {
        let key = SigningKey::from_bytes(&[42; 32]);
        Ok(SignatureResponse {
            frame_type: "signature".into(),
            request_id: r.request_id.clone(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(key.sign(&hex::decode(&r.digest_hex).unwrap()).to_bytes()),
        })
    }
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_sac_executes_real_target_balances_and_policy_denial_rollback() {
    let prepared = prepare_captured(job()).unwrap();
    let report = execute_captured(&prepared, &mut Capability).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["passed"], true, "{value:#}");
    assert_eq!(value["complete"], false);
    assert_eq!(value["storage_mode"], "strict_snapshot_source");
    let cases = value["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let original = &cases[0];
    assert_eq!(original["case_id"], "target:original:0");
    assert_eq!(original["sender_delta"], "-1000000");
    assert_eq!(original["recipient_delta"], "1000000");
    assert_eq!(original["counter_before"], 0);
    assert_eq!(original["counter_after"], 1);
    // Both captured writable entries changed; exactly the two new nonces appeared.
    assert_eq!(original["written_keys"].as_array().unwrap().len(), 3);
    assert_eq!(original["created_keys"].as_array().unwrap().len(), 2);
    assert_eq!(original["captured_reads"].as_array().unwrap().len(), 3);
    assert!(original["undeclared_reads"].as_array().unwrap().is_empty());
    assert_eq!(cases[1]["case_id"], "target:argument-denial:0");
    assert_eq!(cases[1]["refusal_code"], 6);
    assert_eq!(cases[2]["case_id"], "target:empty-signers:0");
    assert_eq!(cases[2]["refusal_code"], 1);
    for case in &cases[1..] {
        assert_eq!(case["refusal_contract"], value["policy_address"]);
        assert_eq!(case["state_before_hash"], case["state_after_hash"]);
        assert_eq!(case["sender_delta"], "0");
        assert_eq!(case["recipient_delta"], "0");
        assert_eq!(case["counter_after"], 0);
        assert!(case["created_keys"].as_array().unwrap().is_empty());
    }
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_state_decides_the_target_outcome() {
    // The policy permits the call, but the captured sender cannot cover it: the target's own
    // refusal must fail the layer rather than read as a pass or as a policy denial.
    let prepared = prepare_captured(job_with_balance(999_999)).unwrap();
    let report = execute_captured(&prepared, &mut Capability).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["passed"], false);
    let original = &value["cases"][0];
    assert_eq!(original["permitted"], false);
    assert_eq!(original["agree"], false);
    assert!(original["refusal_code"].is_null());
    assert_eq!(original["state_before_hash"], original["state_after_hash"]);
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_prepare_refuses_modified_header_config_scope_and_incomplete_closure() {
    type Mutation = fn(&mut CapturedTargetJob);
    const HEADER: &str = "ledger header does not hash to or describe the job ledger";
    const CLOSURE: &str = "not exactly the native transfer closure";
    fn edit_header(j: &mut CapturedTargetJob, change: fn(&mut xdr::LedgerHeader), rehash: bool) {
        let mut header = xdr::LedgerHeaderHistoryEntry::from_xdr_base64(
            &j.capture.header_xdr,
            xdr::Limits::none(),
        )
        .unwrap();
        change(&mut header.header);
        if rehash {
            header.hash = xdr::Hash(
                ozpb_domain::sha256(&header.header.to_xdr(xdr::Limits::none()).unwrap()).0,
            );
        }
        j.capture.header_xdr = enc(&header);
    }
    fn edit_archival(j: &mut CapturedTargetJob, change: fn(&mut xdr::StateArchivalSettings)) {
        let mut data = xdr::LedgerEntryData::from_xdr_base64(
            &j.capture.state_archival.data_xdr,
            xdr::Limits::none(),
        )
        .unwrap();
        let xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) =
            &mut data
        else {
            panic!("state-archival entry")
        };
        change(settings);
        j.capture.state_archival.data_xdr = enc(&data);
    }
    let cases: [(Mutation, &str); 20] = [
        (
            |j| j.capture.observed_ledger += 1,
            "network or ledger differs",
        ),
        (
            |j| j.capture.network_id = "ff".repeat(32),
            "network or ledger differs",
        ),
        (
            |j| j.capture.header_xdr = "AAAAAA==".into(),
            "ledger header is not valid XDR",
        ),
        (
            |j| j.capture.state_archival.last_modified_ledger = u32::MAX,
            "state-archival configuration differs",
        ),
        (
            |j| {
                for entry in &mut j.capture.entries {
                    if entry.live_until_ledger.is_some() {
                        entry.live_until_ledger = Some(1);
                    }
                }
            },
            "not live",
        ),
        (
            // Live through L only: archived by the time any submission lands.
            |j| {
                let observed = j.capture.observed_ledger;
                for entry in &mut j.capture.entries {
                    if entry.live_until_ledger.is_some() {
                        entry.live_until_ledger = Some(observed);
                    }
                }
            },
            "not live",
        ),
        // Valid, re-hashed headers that describe a different ledger.
        (|j| edit_header(j, |h| h.ledger_version = 28, true), HEADER),
        (
            |j| edit_header(j, |h| h.scp_value.close_time.0 += 1, true),
            HEADER,
        ),
        (|j| edit_header(j, |h| h.base_reserve += 1, true), HEADER),
        // A stale embedded hash over a field no other check compares: only the hash refuses it.
        (|j| edit_header(j, |h| h.total_coins += 1, false), HEADER),
        (
            |j| edit_archival(j, |s| s.min_persistent_ttl += 1),
            "state-archival configuration differs",
        ),
        (
            |j| {
                for entry in &mut j.capture.entries {
                    let mut data =
                        xdr::LedgerEntryData::from_xdr_base64(&entry.data_xdr, xdr::Limits::none())
                            .unwrap();
                    if let xdr::LedgerEntryData::ContractData(d) = &mut data {
                        if let xdr::ScVal::ContractInstance(instance) = &mut d.val {
                            instance.executable = xdr::ContractExecutable::Wasm(xdr::Hash([7; 32]));
                        }
                    }
                    entry.data_xdr = enc(&data);
                }
            },
            "not the built-in asset contract",
        ),
        (|j| j.capture.read_write_keys.reverse(), CLOSURE),
        (|j| j.capture.entries.reverse(), CLOSURE),
        (|j| drop(j.capture.entries.pop()), CLOSURE),
        (
            |j| j.native.ledger.protocol_version = 26,
            "unsupported job schema or source protocol",
        ),
        (
            |j| j.capture.account_code_hash = "00".repeat(32),
            "pinned account Wasm",
        ),
        (
            |j| {
                let key = j.capture.read_only_keys[0].clone();
                j.capture.read_write_keys.push(key);
            },
            CLOSURE,
        ),
        (
            |j| {
                let mut call = xdr::InvokeContractArgs::from_xdr_base64(
                    &j.capture.invocation_xdr,
                    xdr::Limits::none(),
                )
                .unwrap();
                let mut args = call.args.to_vec();
                args[2] = xdr::ScVal::I128(xdr::Int128Parts {
                    hi: 0,
                    lo: 1_000_001,
                });
                call.args = args.try_into().unwrap();
                j.capture.invocation_xdr = enc(&call);
            },
            "not an exact-amount transfer",
        ),
        (
            |j| {
                let mut auth = xdr::SorobanAuthorizationEntry::from_xdr_base64(
                    &j.capture.recording_auth_xdr,
                    xdr::Limits::none(),
                )
                .unwrap();
                let child = auth.root_invocation.clone();
                auth.root_invocation.sub_invocations = vec![child].try_into().unwrap();
                j.capture.recording_auth_xdr = enc(&auth);
            },
            "recorded authorization root",
        ),
    ];
    let base = job();
    prepare_captured(base.clone()).unwrap();
    for (index, (mutate, reason)) in cases.into_iter().enumerate() {
        let mut input = base.clone();
        mutate(&mut input);
        match prepare_captured(input) {
            Err(error) => assert!(error.contains(reason), "mutation {index}: {error}"),
            Ok(_) => panic!("mutation {index} was accepted"),
        }
    }
}

#[test]
#[ignore = "requires source-built uncapped policy fixture; run scripts/test-captured-target.sh"]
fn captured_uncapped_rule_executes_without_a_counter() {
    // The generated policy defines no counter key: nothing may read it from the strict source.
    let prepared =
        prepare_captured(job_from("OZPB_CAPTURED_UNCAPPED_JOB", SENDER_BALANCE)).unwrap();
    let value =
        serde_json::to_value(execute_captured(&prepared, &mut Capability).unwrap()).unwrap();
    assert_eq!(value["passed"], true, "{value:#}");
    for case in value["cases"].as_array().unwrap() {
        assert!(case["counter_seed"].is_null());
        assert!(case["counter_before"].is_null());
        assert!(case["counter_after"].is_null());
        assert!(case["undeclared_reads"].as_array().unwrap().is_empty());
    }
    let original = &value["cases"][0];
    assert_eq!(original["sender_delta"], "-1000000");
    assert_eq!(original["written_keys"].as_array().unwrap().len(), 2);
}

#[test]
#[ignore = "requires source-built self-recipient policy fixture; run scripts/test-captured-target.sh"]
fn captured_state_overlapping_the_candidate_is_refused() {
    // Paying the delegate itself: its captured account entry collides with the candidate's
    // synthetic delegate account, which must be refused rather than overwritten.
    let error = prepare_captured(job_from("OZPB_CAPTURED_SELF_RECIPIENT_JOB", SENDER_BALANCE))
        .err()
        .expect("overlap must be refused");
    assert!(error.contains("overlaps candidate"), "{error}");
}

#[test]
#[ignore = "requires the recorded testnet capture and its generated policy; run scripts/test-captured-target.sh"]
fn captured_recorded_testnet_state_executes() {
    // The job's ledger parameters come from the capture's own header and configuration;
    // preparation still checks the header hash and every binding independently.
    let read = |var: &str| std::fs::read(std::env::var(var).unwrap()).unwrap();
    let mut native: ozpb_execution_runtime::NativeJob =
        serde_json::from_slice(&read("OZPB_TESTNET_NATIVE_JOB")).unwrap();
    let capture: ozpb_domain::TargetCapture =
        serde_json::from_slice(&read("OZPB_TESTNET_CAPTURE")).unwrap();
    let header =
        xdr::LedgerHeaderHistoryEntry::from_xdr_base64(&capture.header_xdr, xdr::Limits::none())
            .unwrap();
    let xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) =
        xdr::LedgerEntryData::from_xdr_base64(
            &capture.state_archival.data_xdr,
            xdr::Limits::none(),
        )
        .unwrap()
    else {
        panic!("state-archival entry")
    };
    native.ledger.sequence = capture.observed_ledger;
    native.ledger.timestamp = header.header.scp_value.close_time.0.to_string();
    native.ledger.base_reserve = header.header.base_reserve;
    native.ledger.min_temp_entry_ttl = settings.min_temporary_ttl;
    native.ledger.min_persistent_entry_ttl = settings.min_persistent_ttl;
    native.ledger.max_entry_ttl = settings.max_entry_ttl;
    let prepared = prepare_captured(CapturedTargetJob {
        schema: 1,
        native,
        capture,
    })
    .unwrap();
    let value =
        serde_json::to_value(execute_captured(&prepared, &mut Capability).unwrap()).unwrap();
    assert_eq!(value["passed"], true, "{value:#}");
    if let Ok(path) = std::env::var("OZPB_TESTNET_CAPTURED_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
}
