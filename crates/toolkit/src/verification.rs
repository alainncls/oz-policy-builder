//! Reference-suite and artifact-verification operations.

use super::{from_value, generate_code_with_build_config, spec_error, to_value, EC};
use base64::Engine;
use ozpb_api_types::{
    GenerateCodeInput, ReferenceSuiteInput, ReferenceSuiteOutput, ToolError, VerifyInput,
    VerifyOutput,
};
use ozpb_harness::EvidenceReport;
use ozpb_policy_spec::PolicySpec;
use std::collections::BTreeMap;

/// Run the layer-1 reference suite over a validated policy specification.
pub fn reference_suite(input: &ReferenceSuiteInput) -> Result<ReferenceSuiteOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    let report = ozpb_harness::run_layer1(&validated);

    Ok(ReferenceSuiteOutput {
        total: report.total,
        disagreements: report.disagreements,
        all_agree: report.all_agree(),
        unmodeled_reviewed_policies: report
            .unmodeled_policies
            .iter()
            .map(|policy| format!("rule[{}]: {}", policy.rule_index, policy.kind))
            .collect(),
        coverage: report
            .coverage
            .iter()
            .map(|(class, count)| format!("{class:?}: {count}"))
            .collect(),
        missing_classes: report
            .missing_classes()
            .iter()
            .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
            .collect(),
        permit_only_classes: report
            .permit_only_classes()
            .iter()
            .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
            .collect(),
        report: to_value(&report)?,
    })
}

/// Emit the same layer-1 suite as replayable cases with the hash that names it
/// (`ozpb reference-suite --emit-cases`). The cases are not evaluated again here; the report
/// from [`reference_suite`] carries their layer-1 outcomes under the same labels.
pub fn reference_suite_cases(
    input: &ReferenceSuiteInput,
) -> Result<ozpb_harness::SuiteCases, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    ozpb_harness::emit_cases(&validated).map_err(|e| ToolError::new(EC::EInternal, e.to_string()))
}

/// Verification builds one rule's artifact, so its behavioral evidence must describe that
/// same rule even when the supplied spec contains other rules.
struct RuleBehavior {
    total: usize,
    disagreements: usize,
    missing_classes: Vec<String>,
    unmodeled_reviewed_policies: Vec<String>,
}

fn rule_behavior(report: &EvidenceReport, rule_index: usize) -> RuleBehavior {
    let outcomes: Vec<_> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.rule_index == rule_index)
        .collect();
    RuleBehavior {
        total: outcomes.len(),
        disagreements: outcomes.iter().filter(|outcome| !outcome.agree).count(),
        missing_classes: report
            .missing_classes()
            .into_iter()
            .filter(|(rule, _)| *rule == rule_index)
            .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
            .collect(),
        unmodeled_reviewed_policies: report
            .unmodeled_policies
            .iter()
            .filter(|policy| policy.rule_index == rule_index)
            .map(|policy| format!("rule[{}]: {}", policy.rule_index, policy.kind))
            .collect(),
    }
}

/// Refuse a `generated_artifact` reference. Only the MCP session that generated the artifact can
/// resolve one, and it replaces the reference with the bytes before calling here: evidence is
/// bound to what was checked, never to a name for it.
pub(crate) fn refuse_artifact_reference(input: &VerifyInput) -> Result<(), ToolError> {
    match input.generated_artifact {
        Some(_) => Err(ToolError::new(
            EC::ESpecInvalid,
            "generated_artifact is resolved only by the MCP session that generated it; send the \
             claimed files, Wasm and BuildManifest instead",
        )),
        None => Ok(()),
    }
}

/// Reproduce generated files and Wasm, and report each verification dimension separately.
pub fn verify_with_build_config(
    input: &VerifyInput,
    build_config: &super::BuildConfig,
) -> Result<VerifyOutput, ToolError> {
    refuse_artifact_reference(input)?;
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    let generated = generate_code_with_build_config(
        &GenerateCodeInput {
            spec: input.spec.clone(),
            rule_index: input.rule_index,
        },
        build_config,
    )?;

    // BuildManifest.source_hash covers every generated file except Cargo.lock. Compare the
    // complete path set and contents so a changed toolchain or manifest cannot pass as source
    // reproduction.
    let regenerated: BTreeMap<String, String> = generated
        .files
        .iter()
        .filter(|(path, _)| path.as_str() != "Cargo.lock")
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect();
    let source_matches = regenerated == input.claimed_generated_files;

    let claimed_wasm = input
        .claimed_wasm_base64
        .as_deref()
        .map(|encoded| base64::engine::general_purpose::STANDARD.decode(encoded));
    let reproduced_wasm = base64::engine::general_purpose::STANDARD
        .decode(&generated.wasm_base64)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))?;
    let wasm_matches =
        matches!(claimed_wasm.as_ref(), Some(Ok(claimed)) if claimed == &reproduced_wasm);
    let manifest_matches = input
        .claimed_build_manifest
        .as_ref()
        .is_some_and(|claimed| claimed == &generated.build_manifest);

    let report = ozpb_harness::run_layer1(&validated);
    let behavior = rule_behavior(&report, input.rule_index);
    let models_all_policies = behavior.unmodeled_reviewed_policies.is_empty();
    let behavior_ok = behavior.disagreements == 0 && behavior.missing_classes.is_empty();

    Ok(VerifyOutput {
        spec_conformance: "conforms (validated PolicySpec v1)".to_string(),
        source_reproduction: if source_matches {
            "reproduced: generated non-lock files are byte-identical".to_string()
        } else {
            "MISMATCH: generated non-lock files differ from regeneration".to_string()
        },
        offline_behavioral_conformance: if behavior.disagreements != 0 {
            format!("FAIL: {} permit/deny disagreements", behavior.disagreements)
        } else if !behavior.missing_classes.is_empty() {
            format!(
                "FAIL: missing boundary classes: {}",
                behavior.missing_classes.join(", ")
            )
        } else if models_all_policies {
            format!(
                "pass: {} constraint-derived cases all agree",
                behavior.total
            )
        } else {
            format!(
                "pass (scope+count only): {} cases agree; {} composed reviewed policies are \
                 enforced on-chain and not modeled here",
                behavior.total,
                behavior.unmodeled_reviewed_policies.len()
            )
        },
        wasm_reproduction: match (
            claimed_wasm.as_ref(),
            wasm_matches,
            &input.claimed_build_manifest,
            manifest_matches,
        ) {
            (None, _, _, _) => "not_verified: no claimed Wasm was supplied".to_string(),
            (Some(Err(error)), _, _, _) => {
                format!("INVALID: claimed Wasm is not valid base64: {error}")
            }
            (Some(Ok(_)), false, _, _) => {
                "MISMATCH: claimed Wasm differs from reproduction".to_string()
            }
            (Some(Ok(_)), true, None, _) => {
                "not_verified: no BuildManifest was supplied".to_string()
            }
            (Some(Ok(_)), true, Some(_), false) => {
                "MISMATCH: claimed BuildManifest differs from reproduction".to_string()
            }
            (Some(Ok(_)), true, Some(_), true) => {
                "reproduced: Wasm and BuildManifest are identical".to_string()
            }
        },
        current_network_preflight: "not_checked_here: state-dependent (wallet/live)".to_string(),
        normalized_input_hash: generated.normalized_input_hash,
        models_all_policies,
        unmodeled_reviewed_policies: behavior.unmodeled_reviewed_policies,
        matches: source_matches && behavior_ok && wasm_matches && manifest_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_config, wire_spec};
    use ozpb_policy_spec::PolicyRef;

    /// A reference names an artifact only the MCP session that generated it holds. Anywhere
    /// else it would be evidence bound to a name instead of to the bytes, so it is refused
    /// before anything is built.
    #[test]
    fn an_artifact_reference_is_refused_outside_the_session_that_generated_it() {
        let input = VerifyInput {
            spec: serde_json::to_value(wire_spec().spec()).unwrap(),
            rule_index: 0,
            claimed_generated_files: BTreeMap::new(),
            claimed_wasm_base64: None,
            claimed_build_manifest: None,
            generated_artifact: Some("ab".repeat(32)),
        };
        let error = verify_with_build_config(&input, &build_config()).unwrap_err();
        assert_eq!(error.code, EC::ESpecInvalid);
        assert!(
            error.message.contains("generated_artifact"),
            "{}",
            error.message
        );
    }

    #[test]
    fn reference_suite_reports_layer_one_evidence_and_coverage() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let output = reference_suite(&ReferenceSuiteInput { spec }).unwrap();
        let report: ozpb_harness::EvidenceReport =
            serde_json::from_value(output.report.clone()).unwrap();

        assert_eq!(report.layer, "layer1-reference-evaluator");
        assert!(output.total > 10);
        assert_eq!(output.total, report.total);
        assert_eq!(output.disagreements, report.disagreements);
        assert!(output.all_agree);
        assert!(!output.coverage.is_empty());
        assert_eq!(output.missing_classes.len(), report.missing_classes().len());
        assert!(!output.unmodeled_reviewed_policies.is_empty());
    }

    #[test]
    fn reference_suite_cases_emit_the_reported_suite_with_its_hash() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let input = ReferenceSuiteInput { spec };
        let output = reference_suite(&input).unwrap();
        let cases = reference_suite_cases(&input).unwrap();
        let report: ozpb_harness::EvidenceReport = serde_json::from_value(output.report).unwrap();
        assert_eq!(cases.spec_hash, report.spec_hash);
        assert_eq!(cases.total, output.total);
        assert_eq!(
            cases.cases.iter().map(|c| &c.label).collect::<Vec<_>>(),
            report.outcomes.iter().map(|o| &o.label).collect::<Vec<_>>()
        );
        assert_eq!(
            ozpb_harness::suite_hash(&cases.spec_hash, &cases.cases).unwrap(),
            cases.suite_hash
        );
        // An invalid spec is refused the same way the report refuses it.
        let error = reference_suite_cases(&ReferenceSuiteInput {
            spec: serde_json::json!({"schema": "policy-spec/v0"}),
        })
        .unwrap_err();
        assert!(!error.message.is_empty());
    }

    #[test]
    fn verification_reports_reproduction_without_claiming_live_preflight() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let build_config = build_config();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec.clone(),
                rule_index: 0,
            },
            &build_config,
        )
        .unwrap();
        let claimed_generated_files = generated
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        let output = verify_with_build_config(
            &VerifyInput {
                spec,
                rule_index: 0,
                claimed_generated_files,
                claimed_wasm_base64: Some(generated.wasm_base64),
                claimed_build_manifest: Some(generated.build_manifest),
                generated_artifact: None,
            },
            &build_config,
        )
        .unwrap();

        assert!(output.matches);
        assert!(output.source_reproduction.starts_with("reproduced"));
        assert!(output.wasm_reproduction.starts_with("reproduced"));
        assert!(output
            .current_network_preflight
            .starts_with("not_checked_here"));
        assert!(!output.models_all_policies);
        assert!(!output.unmodeled_reviewed_policies.is_empty());
    }

    #[test]
    fn verification_checks_every_non_lock_file_and_requires_the_manifest() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let build_config = build_config();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec.clone(),
                rule_index: 0,
            },
            &build_config,
        )
        .unwrap();
        let claimed_generated_files = generated
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        let base = VerifyInput {
            spec,
            rule_index: 0,
            claimed_generated_files,
            claimed_wasm_base64: Some(generated.wasm_base64),
            claimed_build_manifest: Some(generated.build_manifest),
            generated_artifact: None,
        };

        for path in ["Cargo.toml", "rust-toolchain.toml", "rustfmt.toml"] {
            let mut edited = base.clone();
            edited
                .claimed_generated_files
                .insert(path.to_string(), "changed".to_string());
            let output = verify_with_build_config(&edited, &build_config).unwrap();
            assert!(!output.matches, "{path} must be checked");
            assert!(output.source_reproduction.starts_with("MISMATCH"));
        }

        let mut missing_file = base.clone();
        missing_file.claimed_generated_files.remove("Cargo.toml");
        assert!(
            !verify_with_build_config(&missing_file, &build_config)
                .unwrap()
                .matches
        );
        let mut extra_file = base.clone();
        extra_file
            .claimed_generated_files
            .insert("src/extra.rs".to_string(), String::new());
        assert!(
            !verify_with_build_config(&extra_file, &build_config)
                .unwrap()
                .matches
        );

        let mut missing_manifest = base.clone();
        missing_manifest.claimed_build_manifest = None;
        let output = verify_with_build_config(&missing_manifest, &build_config).unwrap();
        assert!(!output.matches);
        assert!(output.wasm_reproduction.starts_with("not_verified"));

        let mut malformed_wasm = base.clone();
        malformed_wasm.claimed_wasm_base64 = Some("%%%".to_string());
        let output = verify_with_build_config(&malformed_wasm, &build_config).unwrap();
        assert!(!output.matches);
        assert!(output.source_reproduction.starts_with("reproduced"));
        assert!(output
            .wasm_reproduction
            .starts_with("INVALID: claimed Wasm is not valid base64"));

        let mut different_wasm = base;
        different_wasm.claimed_wasm_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode(b"different Wasm bytes"));
        let output = verify_with_build_config(&different_wasm, &build_config).unwrap();
        assert!(!output.matches);
        assert!(output.source_reproduction.starts_with("reproduced"));
        assert_eq!(
            output.wasm_reproduction,
            "MISMATCH: claimed Wasm differs from reproduction"
        );
    }

    #[test]
    fn verification_uses_only_the_artifacts_rule_for_behavior_and_policy_scope() {
        let mut spec = wire_spec().spec().clone();
        let reviewed_rule = spec.rules[0].clone();
        spec.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
        spec.rules.push(reviewed_rule);
        let validated = spec.validate().unwrap();
        let spec = serde_json::to_value(validated.spec()).unwrap();

        let report = ozpb_harness::run_layer1(&validated);
        assert!(!report.unmodeled_policies.is_empty());
        let selected = rule_behavior(&report, 0);
        assert!(selected.unmodeled_reviewed_policies.is_empty());
        assert!(selected.total < report.total);

        // A regression in another rule must not change this rule's artifact verdict.
        let mut other_rule_failed = report;
        let unrelated = other_rule_failed
            .outcomes
            .iter_mut()
            .find(|outcome| outcome.rule_index == 1)
            .unwrap();
        unrelated.agree = false;
        other_rule_failed.disagreements += 1;
        other_rule_failed.coverage_by_rule.remove(&1);
        let selected = rule_behavior(&other_rule_failed, 0);
        assert_eq!(selected.disagreements, 0);
        assert!(selected.missing_classes.is_empty());
        assert!(selected.unmodeled_reviewed_policies.is_empty());
        let unrelated = rule_behavior(&other_rule_failed, 1);
        assert_eq!(unrelated.disagreements, 1);
        assert!(!unrelated.missing_classes.is_empty());

        let build_config = build_config();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec.clone(),
                rule_index: 0,
            },
            &build_config,
        )
        .unwrap();
        let claimed_generated_files = generated
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        let output = verify_with_build_config(
            &VerifyInput {
                spec,
                rule_index: 0,
                claimed_generated_files,
                claimed_wasm_base64: Some(generated.wasm_base64),
                claimed_build_manifest: Some(generated.build_manifest),
                generated_artifact: None,
            },
            &build_config,
        )
        .unwrap();
        assert!(output.matches);
        assert!(output.models_all_policies);
        assert!(output.unmodeled_reviewed_policies.is_empty());
        assert!(output.offline_behavioral_conformance.starts_with("pass:"));
    }
}
