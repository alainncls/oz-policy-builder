//! Candidate-bound coordination. Runtime evidence must be produced by execution,
//! never imported from a caller's assertion that a layer passed.

use super::{
    call_surface::prepare_call_surface_check, map_registry_err, to_value, verify_with_build_config,
    BuildConfig, RegistryTrust, EC,
};
use ozpb_api_types::{
    DryRunBinding, DryRunInput, DryRunLayer, DryRunLayerId as Layer, DryRunLayerStatus as Status,
    DryRunOutput, ToolError,
};
use ozpb_domain::{canonical_hash, domains, Hash32};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Run the supported deterministic prerequisites and name every missing runtime
/// layer. This function cannot authorize installation, sign or submit a transaction.
pub fn prepare_dry_run_with_build_config(
    input: &DryRunInput,
    trust: &RegistryTrust,
    build: &BuildConfig,
) -> Result<DryRunOutput, ToolError> {
    super::verification::refuse_artifact_reference(&input.artifact)?;
    if input.candidate.spec != input.artifact.spec
        || input.candidate.rule_index != input.artifact.rule_index
    {
        return Err(ToolError::new(
            EC::ESpecInvalid,
            "candidate and artifact must describe exactly the same spec and rule",
        ));
    }
    if !Hash32::from_hex(&input.run_nonce).is_ok_and(|nonce| nonce.to_hex() == input.run_nonce) {
        return Err(ToolError::new(
            EC::ESpecInvalid,
            "run_nonce must be canonical lowercase 32-byte hex",
        ));
    }
    // Canonicalization has independent depth and byte ceilings. Bound the entire
    // request before registry recognition, suite construction or artifact builds.
    let run_hash = hash(domains::DRY_RUN_REQUEST, input)?;
    let prepared = prepare_call_surface_check(&input.candidate, trust, build)?;
    let rule_index = input.candidate.rule_index;
    let suite: Vec<_> = ozpb_harness::build_suite(&prepared.spec)
        .into_iter()
        .filter(|case| case.rule_index == rule_index)
        .collect();
    let suite_hash = hash(domains::DRY_RUN_SUITE, &suite)?;
    let mut reference = ozpb_harness::run_layer1(&prepared.spec);
    reference
        .outcomes
        .retain(|outcome| outcome.rule_index == rule_index);
    reference
        .coverage_by_rule
        .retain(|index, _| *index == rule_index);
    reference
        .expected_classes
        .retain(|index, _| *index == rule_index);
    reference
        .unmodeled_policies
        .retain(|policy| policy.rule_index == rule_index);
    reference.coverage = reference
        .coverage_by_rule
        .get(&rule_index)
        .map(|coverage| {
            coverage
                .iter()
                .map(|(class, count)| (*class, *count))
                .collect()
        })
        .unwrap_or_default();
    if suite.len() != reference.outcomes.len()
        || suite
            .iter()
            .zip(&reference.outcomes)
            .any(|(case, outcome)| {
                case.rule_index != outcome.rule_index
                    || case.label != outcome.label
                    || case.class != outcome.class
                    || outcome.expected != if case.expect_permit { "permit" } else { "deny" }
            })
    {
        return Err(ToolError::new(
            EC::EInternal,
            "reference suite ordering mismatch",
        ));
    }
    let reference_case_ledgers = suite
        .iter()
        .map(|case| case.context.current_ledger.0)
        .collect();
    reference.total = reference.outcomes.len();
    reference.agreements = reference
        .outcomes
        .iter()
        .filter(|outcome| outcome.agree)
        .count();
    reference.disagreements = reference.total - reference.agreements;
    let (status, reason) = if reference.total == 0
        || !reference.all_agree()
        || !reference.missing_classes().is_empty()
    {
        (Status::Failed, "reference_disagreement_or_missing_coverage")
    } else if !reference.models_all_policies() {
        (
            Status::Unsupported,
            "reference_has_unmodeled_composed_policies",
        )
    } else {
        (Status::Passed, "independent_reference_cases_agree")
    };
    let artifact_verification = verify_with_build_config(&input.artifact, build)?;
    // A successful build must not extend a signed registry's validity window.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ToolError::new(EC::EInternal, "system clock precedes the Unix epoch"))?
        .as_secs()
        .try_into()
        .map_err(|_| ToolError::new(EC::EInternal, "trusted time exceeds i64"))?;
    prepared
        .registry
        .ensure_valid_at(now)
        .map_err(map_registry_err)?;

    let binding = DryRunBinding {
        spec_hash: prepared.spec.hash().to_hex(),
        binding_set_hash: hash(domains::POLICY_BINDING_SET, &input.candidate.binding_set)?,
        registry_snapshot_root: prepared.loaded_root.to_hex(),
        account_address: input.candidate.account_address.clone(),
        account_code_hash: prepared
            .spec
            .spec()
            .smart_account
            .observed_code_hash
            .to_hex(),
        network_id: input.candidate.network_id.clone(),
        rule_index,
        candidate_context_rule_id: input.candidate_context_rule_id,
        suite_hash,
        policy_code_hashes: input
            .candidate
            .binding_set
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.contract_address.clone(),
                    binding.observed_wasm_hash.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    };
    Ok(DryRunOutput {
        schema: "ozpb:dry-run:v1".into(),
        run_hash,
        binding,
        artifact_verification,
        reference_report: to_value(&reference)?,
        reference_case_ledgers: Some(reference_case_ledgers),
        layers: vec![
            DryRunLayer {
                id: Layer::Reference,
                status,
                reason: reason.into(),
                cases: reference.total,
                state_dependent: false,
                writes_committed: false,
                execution: None,
            },
            unavailable(Layer::AccountWasm, "account_execution_backend_unavailable"),
            unavailable(
                Layer::CapturedTarget,
                "captured_target_execution_unavailable",
            ),
            unavailable(
                Layer::LiveEnforcement,
                "wallet_authorized_candidate_preflight_unavailable",
            ),
        ],
        complete: false,
        acceptance: None,
        disclaimer: "Constraint-derived evidence is not proof about untested inputs. \
                     Runtime layers have not executed. This report does not authorize \
                     installation, establish ownership, or claim current deployed code."
            .into(),
    })
}

fn hash<T: serde::Serialize>(domain: &str, value: &T) -> Result<String, ToolError> {
    canonical_hash(domain, value)
        .map(|digest| digest.to_hex())
        .map_err(|_| ToolError::new(EC::ESpecInvalid, "dry-run input exceeds canonical bounds"))
}

fn unavailable(id: Layer, reason: &str) -> DryRunLayer {
    DryRunLayer {
        id,
        status: Status::Unavailable,
        reason: reason.into(),
        cases: 0,
        state_dependent: id == Layer::LiveEnforcement,
        writes_committed: false,
        execution: None,
    }
}
