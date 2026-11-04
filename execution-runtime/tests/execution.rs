use ozpb_execution_runtime::{
    execute, prepare, DelegateSigner, NativeJob, PreparedFrame, SignRequest, SignatureResponse,
};

struct NoCapability;
impl DelegateSigner for NoCapability {
    fn sign(&mut self, _: &SignRequest) -> Result<SignatureResponse, String> {
        Err("no registered delegate capability".into())
    }
}

/// The process test's public delegate seed, answering every request it is asked to sign.
struct Capability(ed25519_dalek::SigningKey);
impl DelegateSigner for Capability {
    fn sign(&mut self, request: &SignRequest) -> Result<SignatureResponse, String> {
        use ed25519_dalek::Signer;
        Ok(SignatureResponse {
            frame_type: "signature".into(),
            request_id: request.request_id.clone(),
            public_key_hex: hex::encode(self.0.verifying_key().to_bytes()),
            signature_hex: hex::encode(
                self.0
                    .sign(&hex::decode(&request.digest_hex).unwrap())
                    .to_bytes(),
            ),
        })
    }
}

fn fixture_job() -> NativeJob {
    serde_json::from_slice(&std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap())
        .unwrap()
}

/// Rebind a one-rule job as a two-rule specification: rule 0 composes the reviewed spending
/// limit with a generated policy, and rule 1 is the job's own generated-only rule, with its
/// binding moved to index 1. `selected` picks the rule the job asks the worker to run.
fn with_composed_rule_first(mut job: NativeJob, selected: usize) -> NativeJob {
    let candidate_index = job.request.candidate.rule_index;
    let spec = &mut job.request.candidate.spec;
    let candidate_rule = spec["rules"][candidate_index].clone();
    let mut composed = candidate_rule.clone();
    composed["policies"] = serde_json::json!([
        {"reviewed": {
            "kind": "oz:spending_limit",
            "capability": "4a7b750eeebc6ab1bd49f5d6597970214c78e7ce1fc08b7511a5bedbc66f3934",
            "params": {"spending_limit": {"limit": "500000000", "period_ledgers": 120960}}
        }},
        candidate_rule["policies"][0].clone(),
    ]);
    spec["rules"] = serde_json::json!([composed, candidate_rule]);
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    let spec_hash = validated.validate().unwrap().hash().to_hex();
    let bindings = &mut job.request.candidate.binding_set.bindings;
    let candidate_binding = bindings.remove(0);
    for (policy_index, byte) in [(0, 0x51u8), (1, 0x52)] {
        let mut composed_binding = candidate_binding.clone();
        composed_binding.rule_index = 0;
        composed_binding.policy_index = policy_index;
        composed_binding.contract_address = stellar_strkey::Contract([byte; 32])
            .to_string()
            .as_str()
            .to_owned();
        bindings.push(composed_binding);
    }
    let mut moved = candidate_binding;
    moved.rule_index = 1;
    bindings.push(moved);
    job.request.candidate.binding_set.spec_hash = spec_hash;
    job.request.candidate.rule_index = selected;
    job.request.artifact.spec = job.request.candidate.spec.clone();
    job.request.artifact.rule_index = selected;
    job
}

/// A synthetic job over the public example specification: its one rule reduced to the
/// generated policy, the pinned account claimed, a single delegated signer. Its Wasm is a bare
/// header, so it can only reach the refusals that precede the byte-hash checks.
fn synthetic_job() -> NativeJob {
    let mut spec: serde_json::Value =
        serde_json::from_str(include_str!("../../docs/examples/subscription-spec.json")).unwrap();
    spec["smart_account"]["observed_code_hash"] =
        ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM
            .to_hex()
            .into();
    let generated: Vec<_> = spec["rules"][0]["policies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p.get("generated").is_some())
        .cloned()
        .collect();
    spec["rules"][0]["policies"] = generated.into();
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    let spec_hash = validated.validate().unwrap().hash().to_hex();
    let network_id = spec["network_id"].clone();
    let wasm = "AGFzbQEAAAA=";
    serde_json::from_value(serde_json::json!({
        "schema": 1,
        "request": {
            "candidate": {
                "spec": spec, "rule_index": 0,
                "binding_set": {
                    "schema": "policy-binding-set/v1", "spec_hash": spec_hash,
                    "network_id": network_id,
                    "bindings": [{
                        "rule_index": 0, "policy_index": 0,
                        "contract_address": "CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6",
                        "observed_wasm_hash": "00".repeat(32),
                        "recognition": {"kind": "reviewed_registry"},
                        "resolution_reference": "synthetic selected-rule test",
                    }],
                },
                "signed_registry_snapshot": {},
                "account_address": spec["smart_account"]["address"],
                "network_id": network_id, "rpc_source": "synthetic-fixture",
            },
            "artifact": {
                "spec": spec, "rule_index": 0, "claimed_generated_files": {},
                "claimed_wasm_base64": wasm, "claimed_build_manifest": null,
            },
            "candidate_context_rule_id": 7, "run_nonce": "11".repeat(32),
        },
        "account_wasm_base64": wasm,
        "ledger": {
            "protocol_version": 30, "sequence": 1000, "timestamp": "100000",
            "base_reserve": 5000000, "min_temp_entry_ttl": 16,
            "min_persistent_entry_ttl": 4096, "max_entry_ttl": 631200,
        },
    }))
    .unwrap()
}

#[test]
fn native_prepare_refuses_selected_rule_with_composed_policy() {
    let composed = with_composed_rule_first(synthetic_job(), 0);
    let error = prepare(composed)
        .err()
        .expect("a composed selected rule must be refused");
    assert!(error.contains("unsupported policy composition"), "{error}");
    // Control: the same two-rule job selecting its generated-only rule gets past every scope
    // and composition check, and stops only at the synthetic Wasm.
    let error = prepare(with_composed_rule_first(synthetic_job(), 1))
        .err()
        .expect("the synthetic Wasm is not the pinned account");
    assert!(error.contains("byte hash mismatch"), "{error}");
    // A selected index past the last rule is refused, not clamped.
    let mut beyond = with_composed_rule_first(synthetic_job(), 1);
    beyond.request.candidate.rule_index = 2;
    beyond.request.artifact.rule_index = 2;
    let error = prepare(beyond).err().expect("out-of-range rule");
    assert!(error.contains("selected rule"), "{error}");
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn native_prepare_accepts_selected_rule_of_two_rule_spec() {
    let single = prepare(fixture_job()).unwrap();
    let single_cases = PreparedFrame::from_execution(&single)
        .unwrap()
        .boundary_cases;
    let job = with_composed_rule_first(fixture_job(), 1);
    let policy = job.request.candidate.binding_set.bindings[2]
        .contract_address
        .clone();
    let prepared = prepare(job).unwrap();
    let frame = PreparedFrame::from_execution(&prepared).unwrap();
    // Only the selected rule's derived cases, and only its policy, are prepared.
    assert_eq!(frame.boundary_cases, single_cases);
    assert_eq!(frame.policy_address, policy);
    let out = execute(
        &prepared,
        &mut Capability(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
    )
    .unwrap();
    assert!(out.passed, "{out:#?}");
    assert_eq!(out.cases.len(), single_cases);
    assert_eq!(out.policy_address, policy);
    // The composed rule of the same specification stays outside the native scope.
    let composed = with_composed_rule_first(fixture_job(), 0);
    assert!(matches!(prepare(composed), Err(e) if e.contains("unsupported policy composition")));
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn real_candidate_account_path_cannot_substitute_a_missing_delegate() {
    let job: NativeJob = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    let prepared = prepare(job).unwrap();
    assert!(execute(&prepared, &mut NoCapability).is_err());
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn worker_rejects_protocol_identity_and_expansion_mismatches_before_signing() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let job: NativeJob = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    for mutate in [
        |j: &mut NativeJob| j.ledger.protocol_version = 26,
        |j: &mut NativeJob| j.ledger.timestamp = "000100000".into(),
        |j: &mut NativeJob| j.request.candidate.network_id = "ff".repeat(32),
        |j: &mut NativeJob| j.request.artifact.rule_index = 1,
        |j: &mut NativeJob| {
            j.request.candidate.binding_set.bindings[0].observed_wasm_hash = "ff".repeat(32)
        },
    ] {
        let mut changed = job.clone();
        mutate(&mut changed);
        assert!(prepare(changed).is_err());
    }
    for account in [true, false] {
        let mut changed = job.clone();
        let encoded = if account {
            &mut changed.account_wasm_base64
        } else {
            changed
                .request
                .artifact
                .claimed_wasm_base64
                .as_mut()
                .unwrap()
        };
        let mut bytes = STANDARD.decode(&*encoded).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        *encoded = STANDARD.encode(bytes);
        assert!(matches!(prepare(changed), Err(e) if e.contains("byte hash mismatch")));
    }
    let mut unsupported = job.clone();
    let spec = &mut unsupported.request.candidate.spec;
    spec["rules"][0]["authorization"]["signers"].as_array_mut().unwrap().push(
        serde_json::json!({"delegated": {"address": stellar_strkey::ed25519::PublicKey([6;32]).to_string().as_str()}})
    );
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    unsupported.request.candidate.binding_set.spec_hash =
        validated.validate().unwrap().hash().to_hex();
    unsupported.request.artifact.spec = spec.clone();
    assert!(
        matches!(prepare(unsupported), Err(e) if e.contains("unsupported signer configuration"))
    );
    // Every rule's suite is derived before the selected rule's cases are kept, so an
    // unselected rule's expansion is bounded too.
    let mut expanded = job;
    let spec = &mut expanded.request.candidate.spec;
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
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    let validated = validated.validate().unwrap();
    expanded.request.candidate.binding_set.spec_hash = validated.hash().to_hex();
    expanded.request.artifact.spec = spec.clone();
    assert!(matches!(prepare(expanded), Err(e) if e.contains("unsupported native scope")));
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn real_candidate_account_path_runs_the_derived_suite_and_commits_state() {
    let prepared = prepare(fixture_job()).unwrap();
    let out = execute(
        &prepared,
        &mut Capability(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
    )
    .unwrap();
    assert!(out.passed, "{out:#?}");
    assert!(!out.complete);
    assert!(out.cases.len() > 15);
    assert!(out.cases.iter().any(|c| c.permitted && c.state_changed));
    assert!(out
        .cases
        .iter()
        .filter(|c| !c.permitted)
        .all(|c| !c.state_changed));
    let json = serde_json::to_value(&out).unwrap();
    let controls = json["controls"]
        .as_array()
        .expect("cryptographic controls are required");
    for name in [
        "signature_bit",
        "nonce_binding",
        "payload_binding",
        "context_rule_binding",
        "nonce_replay",
    ] {
        assert!(
            controls
                .iter()
                .any(|v| v["name"] == name && v["passed"] == true),
            "{name}"
        );
    }
    assert_eq!(json["stateful"]["successful_calls"], 12);
    assert_eq!(json["stateful"]["counter_before"], 0);
    assert_eq!(json["stateful"]["counter_after"], 12);
    assert_eq!(json["stateful"]["overflow_refused"], true);
    assert_eq!(json["stateful"]["overflow_rolled_back"], true);
    assert_eq!(json["stateful"]["partial_rollback_refused"], true);
    assert_eq!(json["stateful"]["partial_rollback_preserved_counter"], true);
    assert_eq!(json["stateful"]["passed"], true);
}
