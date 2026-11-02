//! MCP wrappers for reference evidence and generated-artifact verification.
//!
//! The reference suite covers the pure evaluator layer only. Artifact verification
//! reproduces generated files and Wasm and reports its dimensions separately; neither
//! operation performs a live network preflight.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{
    DryRunInput, DryRunOutput, ErrorCode, ReferenceSuiteInput, ReferenceSuiteOutput, ToolError,
    VerifyInput, VerifyOutput,
};

use crate::{cancel, internal_tool_err, tool_err, PolicyBuilderServer};
use tokio_util::sync::CancellationToken;

#[tool_router(router = verification_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Prepare immutable candidate evidence without pretending runtime layers have executed.
    #[tool(
        name = "prepare_dry_run",
        description = "Recognize candidate bindings and reproduce its artifact, derive the \
                       selected-rule reference suite, and bind the complete request to a run \
                       hash. Account-Wasm, captured-target and live-enforcement execution are \
                       explicitly unavailable; complete is false. Resource-consuming, no \
                       network reads, signing or submission. This is not the full dry_run.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn prepare_dry_run(
        &self,
        Parameters(mut input): Parameters<DryRunInput>,
        ct: CancellationToken,
    ) -> Result<Json<DryRunOutput>, CallToolResult> {
        self.resolve_generated_artifact(&mut input.artifact)
            .map_err(tool_err)?;
        // Reserve shared work capacity and validate the operator's RPC source
        // before building, even though this preparation does not read that source.
        // Binding recognition reproduces each generated rule. Artifact verification
        // then builds the selected rule again and needs its own timeout allowance.
        let (trust, _source, _url, deadline, slot) = self.authority_setup(&input.candidate, 1)?;
        // The work is also stopped at the deadline; its slot is released when it ends.
        let work_ct = ct.child_token();
        let build = cancel::build_config(&self.build_config, &work_ct);
        let work = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            ozpb_toolkit::prepare_dry_run_with_build_config(&input, &trust, &build)
        });
        let output = tokio::time::timeout(deadline, work).await.map_err(|_| {
            work_ct.cancel();
            tool_err(ToolError::new(
                ErrorCode::EResourceLimit,
                "dry-run preparation exceeded its work deadline",
            ))
        });
        let output = cancel::unless_cancelled(&ct, output)?
            .map_err(internal_tool_err)?
            .map_err(tool_err)?;
        Ok(Json(output))
    }

    /// Run the pure reference evaluator over a constraint-derived permit/deny suite.
    #[tool(
        name = "reference_suite",
        description = "Evaluate a PolicySpec with the layer-1 reference suite and return \
                       labeled permit/deny evidence and coverage. Pure; does not run \
                       contract integration or live preflight."
    )]
    async fn reference_suite(
        &self,
        Parameters(input): Parameters<ReferenceSuiteInput>,
    ) -> Result<Json<ReferenceSuiteOutput>, CallToolResult> {
        let out = tokio::task::spawn_blocking(move || ozpb_toolkit::reference_suite(&input))
            .await
            .map_err(internal_tool_err)?
            .map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Reproduce the selected rule's generated artifact and report each dimension.
    #[tool(
        name = "verify",
        description = "Verify generated non-lock files, Wasm and BuildManifest against a \
                       PolicySpec rule, and report offline behavior separately. For an \
                       artifact generate_code built in this session, pass its \
                       build_manifest_hash as generated_artifact instead of the files. \
                       Resource-consuming; live preflight remains separate."
    )]
    async fn verify(
        &self,
        Parameters(mut input): Parameters<VerifyInput>,
        ct: CancellationToken,
    ) -> Result<Json<VerifyOutput>, CallToolResult> {
        self.resolve_generated_artifact(&mut input)
            .map_err(tool_err)?;
        let build = cancel::build_config(&self.build_config, &ct);
        let out = tokio::task::spawn_blocking(move || {
            ozpb_toolkit::verify_with_build_config(&input, &build)
        })
        .await
        .map_err(internal_tool_err)?;
        let out = cancel::unless_cancelled(&ct, out.map_err(tool_err))?;
        Ok(Json(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{hosted, refusal_code, subscription_spec};

    fn preparation() -> (PolicyBuilderServer, DryRunInput) {
        let mut server = hosted();
        server.registry_trust = Some(
            ozpb_toolkit::registry_trust_from_roots_json(
                include_str!("../../../docs/examples/registry-roots.json"),
                1,
            )
            .unwrap(),
        );
        server.rpc_sources = std::sync::Arc::new(std::collections::BTreeMap::from([(
            "wallet".into(),
            ozpb_toolkit::RpcSource {
                rpc_url: "https://rpc.allowed.example".into(),
                network_passphrase: ozpb_domain::TESTNET_PASSPHRASE.into(),
            },
        )]));
        let spec = subscription_spec();
        let input = DryRunInput {
            candidate: ozpb_api_types::CheckPolicyCallSurfaceInput {
                spec: spec.clone(),
                rule_index: 0,
                binding_set: ozpb_api_types::PolicyBindingSet {
                    schema: ozpb_api_types::POLICY_BINDING_SET_SCHEMA.into(),
                    spec_hash: "11".repeat(32),
                    network_id: spec["network_id"].as_str().unwrap().into(),
                    bindings: vec![],
                },
                signed_registry_snapshot: serde_json::json!({}),
                account_address: spec["smart_account"]["address"].as_str().unwrap().into(),
                network_id: spec["network_id"].as_str().unwrap().into(),
                rpc_source: "wallet".into(),
            },
            artifact: VerifyInput {
                spec,
                rule_index: 0,
                claimed_generated_files: Default::default(),
                claimed_wasm_base64: None,
                claimed_build_manifest: None,
                generated_artifact: None,
            },
            candidate_context_rule_id: 7,
            run_nonce: "22".repeat(32),
        };
        (server, input)
    }

    #[tokio::test]
    async fn actual_preparation_route_uses_shared_capacity_before_any_build() {
        let (server, input) = preparation();
        let slots = server.authority_slots.clone().unwrap();
        let _permit = slots.try_acquire_owned().unwrap();
        assert_eq!(
            refusal_code(
                server
                    .prepare_dry_run(Parameters(input), Default::default())
                    .await
            ),
            "E_RESOURCE_LIMIT",
        );
    }

    #[test]
    fn preparation_budget_includes_binding_reproduction_and_artifact_verification() {
        use ozpb_api_types::{PolicyBinding, PolicyRecognition};
        use std::time::Duration;

        let (mut server, mut input) = preparation();
        server.build_config.timeout = Duration::from_secs(500);
        // Two generated rules, including a repeated binding for one rule. The
        // selected artifact needs another build after binding reproduction.
        for rule_index in [0, 0, 2] {
            input.candidate.binding_set.bindings.push(PolicyBinding {
                rule_index,
                policy_index: 0,
                contract_address: "candidate".into(),
                observed_wasm_hash: "11".repeat(32),
                recognition: PolicyRecognition::VerifiedGeneratedManifest {
                    build_manifest: serde_json::json!({}),
                },
                resolution_reference: "test".into(),
            });
        }
        let (_, _, _, deadline, _) = server.authority_setup(&input.candidate, 1).unwrap();
        assert_eq!(deadline, Duration::from_secs(1800));
        let (_, _, _, authority_deadline, _) = server.authority_setup(&input.candidate, 0).unwrap();
        assert_eq!(authority_deadline, Duration::from_secs(1300));
    }

    #[tokio::test]
    async fn preparation_rejects_unconfigured_or_disallowed_candidate_sources() {
        let (mut server, mut input) = preparation();
        input.candidate.rpc_source = "unconfigured".into();
        assert_eq!(
            refusal_code(
                server
                    .prepare_dry_run(Parameters(input.clone()), Default::default())
                    .await
            ),
            "E_RPC",
        );
        input.candidate.rpc_source = "wallet".into();
        std::sync::Arc::make_mut(&mut server.rpc_sources)
            .get_mut("wallet")
            .unwrap()
            .rpc_url = "https://outside.example".into();
        assert_eq!(
            refusal_code(
                server
                    .prepare_dry_run(Parameters(input), Default::default())
                    .await
            ),
            "E_RPC",
        );
    }

    #[tokio::test]
    async fn hosted_verify_is_busy_while_every_build_slot_is_taken() {
        let server = hosted();
        let slots = server
            .build_config
            .slots
            .clone()
            .expect("hosted build slots");
        let _running = slots.try_take().expect("the free slot");
        let result = server
            .verify(
                Parameters(VerifyInput {
                    spec: subscription_spec(),
                    rule_index: 0,
                    claimed_generated_files: Default::default(),
                    claimed_wasm_base64: None,
                    claimed_build_manifest: None,
                    generated_artifact: None,
                }),
                Default::default(),
            )
            .await;
        assert_eq!(refusal_code(result), "E_BUILD_BUSY");
    }
}
