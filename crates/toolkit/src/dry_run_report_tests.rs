use super::*;
use ozpb_api_types::{DryRunBinding, VerifyOutput};
use ozpb_harness::{Outcome, UnmodeledPolicy};
use serde_json::json;
use std::collections::BTreeMap;

fn contract(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn account_address() -> String {
    contract(5)
}

fn policy() -> String {
    contract(40)
}

fn delegate() -> String {
    stellar_strkey::ed25519::PublicKey([6; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn testnet() -> String {
    NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
        .0
        .to_hex()
}

/// A preparation whose selected rule has a permitted original and `denials` argument denials.
fn preparation(denials: usize) -> DryRunOutput {
    let mut outcomes = vec![Outcome {
        label: "original transfer".into(),
        rule_index: 0,
        class: MutationClass::Original,
        expected: "permit".into(),
        actual: "permit".into(),
        agree: true,
    }];
    outcomes.extend((0..denials).map(|index| Outcome {
        label: format!("amount[2] = mutation {index}"),
        rule_index: 0,
        class: MutationClass::ArgEquality,
        expected: "deny".into(),
        actual: "deny(ArgMismatch)".into(),
        agree: true,
    }));
    let classes = BTreeSet::from([MutationClass::Original, MutationClass::ArgEquality]);
    let report = EvidenceReport {
        layer: "layer1-reference".into(),
        spec_hash: "aa".repeat(32),
        total: outcomes.len(),
        agreements: outcomes.len(),
        disagreements: 0,
        coverage: Vec::new(),
        coverage_by_rule: BTreeMap::new(),
        expected_classes: BTreeMap::from([(0, classes)]),
        outcomes,
        unmodeled_policies: Vec::<UnmodeledPolicy>::new(),
        disclaimer: "synthetic".into(),
    };
    let unavailable = |id| layer(id, Status::Unavailable, "not run");
    DryRunOutput {
        schema: "ozpb:dry-run:v1".into(),
        run_hash: "11".repeat(32),
        binding: DryRunBinding {
            spec_hash: "aa".repeat(32),
            binding_set_hash: "bb".repeat(32),
            registry_snapshot_root: "dd".repeat(32),
            account_address: account_address(),
            account_code_hash: OZ_SMART_ACCOUNT_WASM.to_hex(),
            network_id: testnet(),
            rule_index: 0,
            candidate_context_rule_id: 7,
            suite_hash: "33".repeat(32),
            policy_code_hashes: BTreeMap::from([(policy(), "cc".repeat(32))]),
        },
        artifact_verification: VerifyOutput {
            spec_conformance: "conforms".into(),
            source_reproduction: "reproduced".into(),
            offline_behavioral_conformance: "agrees".into(),
            wasm_reproduction: "reproduced".into(),
            current_network_preflight: "not run".into(),
            normalized_input_hash: "ee".repeat(32),
            models_all_policies: true,
            unmodeled_reviewed_policies: Vec::new(),
            matches: true,
        },
        reference_case_ledgers: Some(vec![1000; report.outcomes.len()]),
        reference_report: serde_json::to_value(report).unwrap(),
        layers: vec![
            DryRunLayer {
                cases: denials + 1,
                ..layer(
                    Layer::Reference,
                    Status::Passed,
                    "independent_reference_cases_agree",
                )
            },
            unavailable(Layer::AccountWasm),
            unavailable(Layer::CapturedTarget),
            unavailable(Layer::LiveEnforcement),
        ],
        complete: false,
        acceptance: None,
        disclaimer: "preparation".into(),
    }
}

fn expectation(preparation: &DryRunOutput) -> NativeExpectation {
    let binding = OfflineBinding {
        run_hash: preparation.run_hash.clone(),
        job_hash: "22".repeat(32),
        suite_hash: preparation.binding.suite_hash.clone(),
        state_hash: "44".repeat(32),
        source_network_id: testnet(),
        source_protocol_version: 29,
        source_ledger: 1000,
        account_address: account_address(),
        delegate_address: delegate(),
    };
    NativeExpectation {
        execution_network_id: offline_execution_network_id(&binding).unwrap(),
        binding,
        scope: NativeScope {
            delegate_address: delegate(),
            policy_address: policy(),
            policy_code_hash: "cc".repeat(32),
            target_contract: contract(9),
            max_calls: Some(12),
        },
        candidate_context_rule_id: 7,
        boundary_cases: reference(preparation).unwrap().outcomes.len(),
        case_ledgers: vec![1000; reference(preparation).unwrap().outcomes.len()],
        signing_expirations: ["case:0", "case:1", "control:signature_bit", "sequence:0"]
            .iter()
            .map(|id| (id.to_string(), 1064))
            .collect(),
        signature_expiration_ledgers: BTreeSet::from([1064]),
        signing_cases: ["case:0", "case:1", "control:signature_bit", "sequence:0"]
            .iter()
            .map(|id| id.to_string())
            .collect(),
    }
}

/// The worker report a correct run of `preparation` produces, as JSON.
fn worker_result(preparation: &DryRunOutput, expectation: &NativeExpectation) -> serde_json::Value {
    let reference = reference(preparation).unwrap();
    let cases: Vec<_> = reference
        .outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| {
            let permit = outcome.expected == "permit";
            json!({
                "case_id": format!("case:{index}"), "label": outcome.label, "class": outcome.class,
                "expected_permit": permit, "permitted": permit, "agree": true,
                "refusal_contract": if permit { None } else { Some(policy()) },
                "refusal_code": if permit { None } else { Some(6) },
                "state_before_hash": "a0".repeat(32),
                "state_after_hash": if permit { "a1".repeat(32) } else { "a0".repeat(32) },
                "state_changed": permit, "ledger": 1000,
                "counter_seed": 0, "counter_before": 0, "counter_after": if permit { 1 } else { 0 },
            })
        })
        .collect();
    let controls: Vec<_> = NATIVE_CONTROLS
        .iter()
        .map(|(name, stage)| {
            json!({"name": name, "passed": true, "refusal_stage": stage,
                   "state_before_hash": "c0".repeat(32), "state_after_hash": "c0".repeat(32)})
        })
        .collect();
    json!({
        "type": "result", "schema": 1, "binding": expectation.binding,
        "execution_network_id": expectation.execution_network_id,
        "account_code_hash": OZ_SMART_ACCOUNT_WASM.to_hex(),
        "policy_address": policy(), "policy_code_hash": "cc".repeat(32),
        "host_version": HOST_VERSION, "local_rule_id": 1, "candidate_context_rule_id": 7,
        "provenance": NATIVE_PROVENANCE, "cases": cases, "controls": controls,
        "stateful": {"successful_calls": 12, "counter_before": 0, "counter_after": 12,
                     "overflow_refused": true, "overflow_rolled_back": true,
                     "partial_rollback_refused": true, "partial_rollback_preserved_counter": true,
                     "passed": true},
        "required_classes": reference.required_classes, "passed": true, "complete": false,
    })
}

/// A clean exit after the signer answered every request `native` expects.
fn ran(native: &NativeExpectation, result: serde_json::Value) -> LayerRun {
    LayerRun::Ran {
        exit: WorkerExit::Success,
        result: Some(result),
        signed: native.signing_cases.clone(),
    }
}

fn not_requested() -> LayerRun {
    LayerRun::NotRun {
        unsupported: false,
        reason: "captured_target_not_requested".into(),
    }
}

fn assemble(preparation: &DryRunOutput, native: &NativeExpectation, run: LayerRun) -> DryRunOutput {
    assemble_dry_run_report(preparation, Some(native), &run, None, &not_requested())
}

fn layer_of(report: &DryRunOutput, id: Layer) -> &DryRunLayer {
    report.layers.iter().find(|layer| layer.id == id).unwrap()
}

fn acceptance(report: &DryRunOutput) -> &DryRunAcceptance {
    report
        .acceptance
        .as_ref()
        .expect("an assembled report carries acceptance")
}

#[test]
fn dry_run_acceptance_requires_original_permit_and_five_reverted_denials() {
    let prep = preparation(5);
    let native = expectation(&prep);
    let report = assemble(&prep, &native, ran(&native, worker_result(&prep, &native)));
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Passed, "{}", account.reason);
    assert_eq!(account.cases, 6);
    let execution = account.execution.as_ref().unwrap();
    assert_eq!(execution.execution_network_id, native.execution_network_id);
    assert!(execution.cases.iter().all(|case| case.agree));
    assert_eq!(
        acceptance(&report),
        &DryRunAcceptance {
            required_reverted_denials: 5,
            original_permitted: true,
            executed_layers: vec![DryRunLayerAcceptance {
                layer: Layer::AccountWasm,
                status: Status::Passed,
                original_permitted: true,
                reverted_denials: 5,
            }],
            meets_minimum: true,
        }
    );
    // Outside the wallet the live layer never runs, and nothing completes the report.
    let live = layer_of(&report, Layer::LiveEnforcement);
    assert_eq!(live.status, Status::Unavailable);
    assert_eq!(live.reason, "wallet_owner_consent_required");
    assert!(!report.complete);
    assert_eq!(
        layer_of(&report, Layer::CapturedTarget).status,
        Status::Unavailable
    );

    // Four reverted denials: the layer passes, the bar is not met.
    let prep = preparation(4);
    let native = expectation(&prep);
    let report = assemble(&prep, &native, ran(&native, worker_result(&prep, &native)));
    assert_eq!(layer_of(&report, Layer::AccountWasm).status, Status::Passed);
    assert_eq!(acceptance(&report).executed_layers[0].reverted_denials, 4);
    assert!(!acceptance(&report).meets_minimum);

    // The original refused: the case disagrees, so the layer fails and nothing counts.
    let prep = preparation(5);
    let native = expectation(&prep);
    let mut refused = worker_result(&prep, &native);
    let original = &mut refused["cases"][0];
    original["permitted"] = false.into();
    original["refusal_contract"] = policy().into();
    original["refusal_code"] = 6.into();
    original["state_after_hash"] = "a0".repeat(32).into();
    original["state_changed"] = false.into();
    original["counter_after"] = 0.into();
    let report = assemble(&prep, &native, ran(&native, refused));
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert_eq!(account.reason, "case_disagreement");
    assert!(!acceptance(&report).original_permitted);
    assert!(!acceptance(&report).meets_minimum);

    // A denial refused by a contract its class does not predict does not revert as required,
    // whatever the worker says about it.
    let mut misattributed = worker_result(&prep, &native);
    misattributed["cases"][3]["refusal_contract"] = account_address().into();
    misattributed["cases"][3]["refusal_code"] = 3016.into();
    let report = assemble(&prep, &native, ran(&native, misattributed));
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert!(!account.execution.as_ref().unwrap().cases[3].agree);
    assert!(!acceptance(&report).meets_minimum);

    // The reference layer must itself have passed.
    let mut unreferenced = preparation(5);
    unreferenced.layers[0].status = Status::Unsupported;
    let report = assemble(
        &unreferenced,
        &native,
        ran(&native, worker_result(&prep, &native)),
    );
    assert_eq!(layer_of(&report, Layer::AccountWasm).status, Status::Passed);
    assert!(!acceptance(&report).meets_minimum);

    // A layer that did not run stays missing, whatever the preparation claims about it.
    let mut claimed = preparation(5);
    claimed.layers[1].status = Status::Passed;
    claimed.layers[1].cases = 6;
    let report = assemble(
        &claimed,
        &native,
        LayerRun::NotRun {
            unsupported: false,
            reason: "native_worker_not_configured".into(),
        },
    );
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Unavailable);
    assert_eq!(account.reason, "native_worker_not_configured");
    assert!(account.execution.is_none());
    assert!(acceptance(&report).executed_layers.is_empty());
    assert!(!acceptance(&report).original_permitted);
    assert!(!acceptance(&report).meets_minimum);
}

#[test]
fn dry_run_report_refuses_worker_result_with_foreign_run_hash() {
    let prep = preparation(5);
    let native = expectation(&prep);
    // A complete, internally consistent report from another run: its own run hash and the
    // network ID that binding derives. Every case would agree.
    let mut foreign = worker_result(&prep, &native);
    let mut binding = native.binding.clone();
    binding.run_hash = "ff".repeat(32);
    foreign["execution_network_id"] = offline_execution_network_id(&binding).unwrap().into();
    foreign["binding"] = serde_json::to_value(&binding).unwrap();
    let report = assemble(&prep, &native, ran(&native, foreign));
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert_eq!(account.reason, "worker_binding_mismatch");
    assert!(account.execution.is_none(), "no case from it is accepted");
    assert_eq!(account.cases, 0);
    assert_eq!(acceptance(&report).executed_layers[0].reverted_denials, 0);
    assert!(!acceptance(&report).meets_minimum);

    // An expectation that is itself not the preparation's run is refused before the report.
    let mut stray = native.clone();
    stray.binding.run_hash = "ff".repeat(32);
    stray.execution_network_id = offline_execution_network_id(&stray.binding).unwrap();
    let mut matching = worker_result(&prep, &stray);
    matching["binding"]["run_hash"] = "ff".repeat(32).into();
    let report = assemble(&prep, &stray, ran(&stray, matching));
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert_eq!(account.reason, "expectation_not_bound_to_preparation");
    assert!(!acceptance(&report).meets_minimum);

    // So is one whose suite is not the prepared suite, with a worker report that matches it.
    let mut other_suite = native.clone();
    other_suite.binding.suite_hash = "ff".repeat(32);
    other_suite.execution_network_id = offline_execution_network_id(&other_suite.binding).unwrap();
    let report = assemble(
        &prep,
        &other_suite,
        ran(&other_suite, worker_result(&prep, &other_suite)),
    );
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert_eq!(account.reason, "expectation_not_bound_to_preparation");
}

#[test]
fn dry_run_report_fails_layer_on_nonzero_worker_exit() {
    let prep = preparation(5);
    let native = expectation(&prep);
    for (exit, reason) in [
        (WorkerExit::Code(1), "worker_exit_nonzero"),
        (WorkerExit::Signal, "worker_ended_by_signal"),
    ] {
        // A report that would pass on its own does not survive a failed exit.
        let report = assemble(
            &prep,
            &native,
            LayerRun::Ran {
                exit,
                result: Some(worker_result(&prep, &native)),
                signed: native.signing_cases.clone(),
            },
        );
        let account = layer_of(&report, Layer::AccountWasm);
        assert_eq!(account.status, Status::Failed, "{exit:?}");
        assert_eq!(account.reason, reason);
        assert_eq!(acceptance(&report).executed_layers[0].reverted_denials, 0);
        assert!(!acceptance(&report).original_permitted);
        assert!(!acceptance(&report).meets_minimum);
        // Without any report the exit still names the failure.
        let report = assemble(
            &prep,
            &native,
            LayerRun::Ran {
                exit,
                result: None,
                signed: BTreeSet::new(),
            },
        );
        assert_eq!(layer_of(&report, Layer::AccountWasm).reason, reason);
    }
    // A refused exchange is a failed layer with no evidence.
    let report = assemble(
        &prep,
        &native,
        LayerRun::Refused {
            reason: "worker_deadline_exceeded".into(),
        },
    );
    let account = layer_of(&report, Layer::AccountWasm);
    assert_eq!(account.status, Status::Failed);
    assert_eq!(account.reason, "worker_deadline_exceeded");
    assert!(!acceptance(&report).meets_minimum);
}

#[test]
fn offline_execution_network_id_matches_the_shared_domain_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/examples/native-domain-vector.json"
    ))
    .unwrap();
    let binding: OfflineBinding = serde_json::from_value(vector["binding"].clone()).unwrap();
    assert_eq!(
        offline_execution_network_id(&binding).unwrap(),
        vector["execution_network_id"].as_str().unwrap()
    );
    for change in [
        |b: &mut OfflineBinding| b.source_protocol_version = 26,
        |b: &mut OfflineBinding| b.source_ledger = 0,
        |b: &mut OfflineBinding| b.run_hash = "FF".repeat(32),
        |b: &mut OfflineBinding| b.delegate_address = contract(6),
    ] {
        let mut changed = binding.clone();
        change(&mut changed);
        assert!(offline_execution_network_id(&changed).is_err());
    }
    // The denylist names the source, public, test and future networks.
    let live = live_network_ids(&binding.source_network_id);
    assert!(live.contains(&testnet()));
    assert!(live.contains(
        &NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE)
            .0
            .to_hex()
    ));
}

#[test]
fn captured_layer_counts_its_two_denials_and_never_meets_the_bar_alone() {
    let prep = preparation(5);
    let native = expectation(&prep);
    let mut binding = native.binding.clone();
    binding.job_hash = "55".repeat(32);
    let captured = CapturedExpectation {
        execution_network_id: offline_execution_network_id(&binding).unwrap(),
        binding,
        capture_hash: "66".repeat(32),
        candidate_state_hash: "77".repeat(32),
        target_contract: contract(9),
        observed_ledger: 1000,
        amount: 1_000_000,
        counter_seed: Some(0),
        policy_address: policy(),
        policy_code_hash: "cc".repeat(32),
        candidate_context_rule_id: 7,
        signing_case_ids: ["target:original:0", "target:argument-denial:0"]
            .iter()
            .map(|id| id.to_string())
            .collect(),
        signature_expiration_ledgers: BTreeSet::from([1064]),
    };
    let case = |id: &str, class: &str, permit: bool, code: Option<u32>| {
        json!({
            "case_id": id, "label": id, "class": class, "expected_permit": permit,
            "permitted": permit, "agree": true,
            "refusal_contract": code.map(|_| policy()), "refusal_code": code, "host_error": null,
            "state_before_hash": "a0".repeat(32),
            "state_after_hash": if permit { "a1".repeat(32) } else { "a0".repeat(32) },
            "sender_delta": if permit { "-1000000" } else { "0" },
            "recipient_delta": if permit { "1000000" } else { "0" },
            "counter_seed": 0, "counter_before": 0, "counter_after": if permit { 1 } else { 0 },
            "captured_reads": [], "created_keys": [], "written_keys": [], "ttl_extended_keys": [],
            "undeclared_reads": [], "unexpected_changes": [],
        })
    };
    let result = json!({
        "type": "result", "schema": 1, "layer": "captured_target", "binding": captured.binding,
        "execution_network_id": captured.execution_network_id,
        "capture_hash": captured.capture_hash, "candidate_state_hash": captured.candidate_state_hash,
        "capture_provenance": "rpc_reported", "observed_ledger": 1000,
        "target_contract": contract(9), "account_code_hash": OZ_SMART_ACCOUNT_WASM.to_hex(),
        "policy_address": policy(), "policy_code_hash": "cc".repeat(32),
        "host_version": HOST_VERSION, "local_rule_id": 1, "candidate_context_rule_id": 7,
        "storage_mode": STORAGE_MODE, "provenance": CAPTURED_PROVENANCE,
        "cases": [
            case("target:original:0", "original", true, None),
            case("target:argument-denial:0", "arg_equality", false, Some(6)),
            case("target:empty-signers:0", "zero_signers", false, Some(1)),
        ],
        "passed": true, "complete": false,
    });
    let report = assemble_dry_run_report(
        &prep,
        Some(&native),
        &LayerRun::NotRun {
            unsupported: true,
            reason: "selected_rule_outside_native_scope".into(),
        },
        Some(&captured),
        &LayerRun::Ran {
            exit: WorkerExit::Success,
            result: Some(result.clone()),
            signed: captured.signing_case_ids.clone(),
        },
    );
    let layer = layer_of(&report, Layer::CapturedTarget);
    assert_eq!(layer.status, Status::Passed, "{}", layer.reason);
    assert!(layer.state_dependent);
    let accepted = acceptance(&report);
    assert_eq!(accepted.executed_layers.len(), 1);
    assert_eq!(accepted.executed_layers[0].reverted_denials, 2);
    assert!(accepted.original_permitted);
    assert!(!accepted.meets_minimum, "two denials are below the bar");

    for (index, field, value) in [
        (1, "state_before_hash", json!("")),
        (1, "state_after_hash", json!("")),
        (0, "counter_after", json!(0)),
        (0, "refusal_code", json!(6)),
    ] {
        let mut changed = result.clone();
        changed["cases"][index][field] = value;
        if field.starts_with("state_") {
            changed["cases"][index]["state_before_hash"] = json!("");
            changed["cases"][index]["state_after_hash"] = json!("");
        }
        let report = assemble_dry_run_report(
            &prep,
            Some(&native),
            &not_requested(),
            Some(&captured),
            &LayerRun::Ran {
                exit: WorkerExit::Success,
                result: Some(changed),
                signed: captured.signing_case_ids.clone(),
            },
        );
        assert_eq!(
            layer_of(&report, Layer::CapturedTarget).status,
            Status::Failed,
            "{field}"
        );
    }

    // Counter shape and seed come from the policy, including on the denial cases.
    for index in 0..3 {
        for seed in [None, Some(1)] {
            let mut changed = result.clone();
            changed["cases"][index]["counter_seed"] = json!(seed);
            changed["cases"][index]["counter_before"] = json!(seed);
            changed["cases"][index]["counter_after"] =
                json!(seed.map(|value| value + u32::from(index == 0)));
            let report = assemble_dry_run_report(
                &prep,
                Some(&native),
                &not_requested(),
                Some(&captured),
                &LayerRun::Ran {
                    exit: WorkerExit::Success,
                    result: Some(changed),
                    signed: captured.signing_case_ids.clone(),
                },
            );
            assert_eq!(
                layer_of(&report, Layer::CapturedTarget).status,
                Status::Failed
            );
        }
    }
    // Uncapped policies legitimately have no counter fields.
    let mut uncapped = captured.clone();
    uncapped.counter_seed = None;
    let mut uncounted = result.clone();
    for case in uncounted["cases"].as_array_mut().unwrap() {
        for field in ["counter_seed", "counter_before", "counter_after"] {
            case[field] = json!(null);
        }
    }
    let report = assemble_dry_run_report(
        &prep,
        Some(&native),
        &not_requested(),
        Some(&uncapped),
        &LayerRun::Ran {
            exit: WorkerExit::Success,
            result: Some(uncounted),
            signed: uncapped.signing_case_ids.clone(),
        },
    );
    assert_eq!(
        layer_of(&report, Layer::CapturedTarget).status,
        Status::Passed
    );

    // An original that moved another amount does not agree.
    let mut moved = result;
    moved["cases"][0]["sender_delta"] = "-999999".into();
    let report = assemble_dry_run_report(
        &prep,
        Some(&native),
        &not_requested(),
        Some(&captured),
        &LayerRun::Ran {
            exit: WorkerExit::Success,
            result: Some(moved),
            signed: captured.signing_case_ids.clone(),
        },
    );
    assert_eq!(
        layer_of(&report, Layer::CapturedTarget).reason,
        "case_disagreement"
    );
}

#[test]
fn dry_run_report_requires_exactly_the_expected_signatures() {
    let prep = preparation(5);
    let native = expectation(&prep);
    // A report the worker could produce without asking for a single signature, or after
    // skipping one, or after asking for one too many, is not evidence of authorization.
    let mut missing = native.signing_cases.clone();
    missing.remove("control:signature_bit");
    let mut extra = native.signing_cases.clone();
    extra.insert("case:5".into());
    for signed in [BTreeSet::new(), missing, extra] {
        let report = assemble(
            &prep,
            &native,
            LayerRun::Ran {
                exit: WorkerExit::Success,
                result: Some(worker_result(&prep, &native)),
                signed,
            },
        );
        let account = layer_of(&report, Layer::AccountWasm);
        assert_eq!(account.status, Status::Failed);
        assert_eq!(account.reason, "signatures_differ_from_expectation");
        assert!(account.execution.is_none());
        assert!(!acceptance(&report).meets_minimum);
    }
}

/// The synthetic example request: the public subscription spec reduced to its generated
/// policy, claiming the pinned account, with one binding.
fn example_request(mutate: impl FnOnce(&mut serde_json::Value)) -> DryRunInput {
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/examples/subscription-spec.json"
    ))
    .unwrap();
    spec["smart_account"]["observed_code_hash"] = OZ_SMART_ACCOUNT_WASM.to_hex().into();
    spec["rules"][0]["policies"]
        .as_array_mut()
        .unwrap()
        .retain(|policy| policy.get("generated").is_some());
    mutate(&mut spec);
    let network_id = spec["network_id"].clone();
    serde_json::from_value(json!({
        "candidate": {
            "spec": spec, "rule_index": 0,
            "binding_set": {
                "schema": "policy-binding-set/v1", "spec_hash": "00".repeat(32),
                "network_id": network_id,
                "bindings": [{
                    "rule_index": 0, "policy_index": 0, "contract_address": policy(),
                    "observed_wasm_hash": "cc".repeat(32),
                    "recognition": {"kind": "reviewed_registry"},
                    "resolution_reference": "synthetic scope test",
                }],
            },
            "signed_registry_snapshot": {}, "account_address": spec["smart_account"]["address"],
            "network_id": network_id, "rpc_source": "synthetic",
        },
        "artifact": {
            "spec": spec, "rule_index": 0, "claimed_generated_files": {},
            "claimed_wasm_base64": null, "claimed_build_manifest": null,
        },
        "candidate_context_rule_id": 7, "run_nonce": "11".repeat(32),
    }))
    .unwrap()
}

#[test]
fn native_scope_refuses_every_bound_the_worker_refuses() {
    let scope = native_scope(&example_request(|_| {})).expect("the example is in scope");
    assert_eq!(scope.max_calls, Some(12));
    // An unselected rule with nine calls: the worker derives every rule's suite first.
    let nine_calls = example_request(|spec| {
        let mut second = spec["rules"][0].clone();
        let call = second["allowed_calls"][0].clone();
        second["allowed_calls"] = (0..9)
            .map(|n| {
                let mut c = call.clone();
                c["fn"] = format!("transfer_{n}").into();
                c
            })
            .collect::<Vec<_>>()
            .into();
        spec["rules"].as_array_mut().unwrap().push(second);
    });
    assert!(native_scope(&nine_calls).is_err());
    // A call cap the worker's stateful sequence does not run.
    let large_cap = example_request(|spec| {
        spec["rules"][0]["state"] = json!([{"call_count_per_installation": {"max_calls": 513}}]);
    });
    assert!(native_scope(&large_cap).is_err());
}

#[test]
fn native_results_cannot_swap_valid_execution_ledgers_between_cases() {
    let mut prep = preparation(5);
    prep.reference_case_ledgers.as_mut().unwrap()[1] = 1001;
    let mut native = expectation(&prep);
    native.case_ledgers[1] = 1001;
    native.signature_expiration_ledgers.insert(1065);
    native.signing_expirations.insert("case:1".into(), 1065);
    let mut result = worker_result(&prep, &native);
    result["cases"][1]["ledger"] = json!(1001);
    assert_eq!(
        layer_of(
            &assemble(&prep, &native, ran(&native, result.clone())),
            Layer::AccountWasm
        )
        .status,
        Status::Passed
    );
    result["cases"][0]["ledger"] = json!(1001);
    result["cases"][1]["ledger"] = json!(1000);
    assert_eq!(
        layer_of(
            &assemble(&prep, &native, ran(&native, result)),
            Layer::AccountWasm
        )
        .status,
        Status::Failed
    );
}

#[test]
fn contract_delegates_are_outside_native_scope_before_any_key_is_read() {
    let request = example_request(|spec| {
        spec["rules"][0]["authorization"]["signers"][0]["delegated"]["address"] =
            json!(contract(6));
    });
    assert!(native_scope(&request).unwrap_err().contains("Ed25519"));
}

#[test]
fn native_refusals_match_shared_wallet_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/examples/native-refusal-vectors.json"
    ))
    .unwrap();
    for class in vectors["classes"].as_array().unwrap() {
        for enforcer in vectors["enforcers"].as_array().unwrap() {
            for code in vectors["codes"].as_array().unwrap() {
                let tuple = json!([class, enforcer, code]);
                let expected = vectors["allowed"].as_array().unwrap().contains(&tuple);
                assert_eq!(
                    predicted_refusal(
                        serde_json::from_value(class.clone()).unwrap(),
                        serde_json::from_value(enforcer.clone()).unwrap(),
                        code.as_u64().unwrap() as u32,
                    ),
                    expected,
                    "{tuple}"
                );
            }
        }
    }
}

#[test]
fn assembled_reports_preserve_case_ledgers_and_legacy_reports_remain_readable() {
    let prep = preparation(6);
    let native = expectation(&prep);
    let report = assemble(&prep, &native, ran(&native, worker_result(&prep, &native)));
    assert_eq!(report.reference_case_ledgers, prep.reference_case_ledgers);
    let mut json = serde_json::to_value(&prep).unwrap();
    json.as_object_mut()
        .unwrap()
        .remove("reference_case_ledgers");
    let legacy: DryRunOutput = serde_json::from_value(json).unwrap();
    assert!(legacy.reference_case_ledgers.is_none());
}

#[test]
fn assembled_native_reports_reject_mismatched_case_metadata_but_accept_legacy_absence() {
    let prep = preparation(5);
    let native = expectation(&prep);
    for ledgers in [vec![1001; 6], vec![1000; 5], vec![]] {
        let mut changed = prep.clone();
        changed.reference_case_ledgers = Some(ledgers);
        let report = assemble(
            &changed,
            &native,
            ran(&native, worker_result(&prep, &native)),
        );
        assert_eq!(layer_of(&report, Layer::AccountWasm).status, Status::Failed);
        assert_eq!(
            layer_of(&report, Layer::AccountWasm).reason,
            "expectation_not_bound_to_preparation"
        );
    }
    let mut legacy = prep.clone();
    legacy.reference_case_ledgers = None;
    let report = assemble(
        &legacy,
        &native,
        ran(&native, worker_result(&prep, &native)),
    );
    assert_eq!(layer_of(&report, Layer::AccountWasm).status, Status::Passed);
}
