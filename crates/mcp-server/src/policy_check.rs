//! Live selected-rule prediction under the same operator budgets as authority reads.

use crate::{cancel, internal_tool_err, tool_err, PolicyBuilderServer};
use ozpb_api_types::{
    CheckAgainstPolicyInput, CheckAgainstPolicyOutput, ErrorCode, PolicyRecognition, ToolError,
};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use tokio_util::sync::CancellationToken;

#[tool_router(router=policy_check_tool_router,vis="pub(crate)")]
impl PolicyBuilderServer {
    /// Predict one recognized installed rule from one current endpoint observation.
    #[tool(
        name = "check_against_policy",
        description = "State-dependent prediction for one explicitly selected installed rule, through an operator-configured RPC source. Recognizes exact reviewed code or locally reproduced generated artifacts and reads rule, signers, policies, counters, configuration and TTLs at one reported ledger/hash. Candidate signer identities MUST successfully authenticate later; this tool does not verify signatures. A foreign candidate signer denies. Unknown implementations, unavailable/archived state and unmodeled authentication return unsupported. Results contain exact observations and require a fresh check plus enforce simulation of the actual authorization before signing. This is not an account safety or ownership verdict and never signs, restores or submits. May rebuild generated policies.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn check_against_policy(
        &self,
        Parameters(input): Parameters<CheckAgainstPolicyInput>,
        ct: CancellationToken,
    ) -> Result<Json<CheckAgainstPolicyOutput>, CallToolResult> {
        let trust = self.registry_trust.clone().ok_or_else(|| {
            tool_err(ToolError::new(
                ErrorCode::ERegistryEmpty,
                "no pinned registry trust configured",
            ))
        })?;
        let source = ozpb_toolkit::resolve_rpc_source(
            &self.rpc_sources,
            &input.rpc_source,
            &input.network_id,
        )
        .map_err(tool_err)?
        .clone();
        let rpc_url = self.authorized_rpc_url(&source.rpc_url).map_err(tool_err)?;
        let slot = match &self.authority_slots {
            Some(slots) => Some(slots.clone().try_acquire_owned().map_err(|_| {
                tool_err(ToolError::new(
                    ErrorCode::EResourceLimit,
                    "another live policy/authority read is running; retry shortly",
                ))
            })?),
            None => None,
        };
        let generated = input
            .binding_set
            .bindings
            .iter()
            .filter(|binding| {
                matches!(
                    binding.recognition,
                    PolicyRecognition::VerifiedGeneratedManifest { .. }
                )
            })
            .map(|binding| binding.rule_index)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let deadline = self
            .build_config
            .timeout
            .saturating_mul(u32::try_from(generated).unwrap_or(u32::MAX))
            .saturating_add(std::time::Duration::from_secs(300));
        let work_ct = ct.child_token();
        let build = cancel::build_config(&self.build_config, &work_ct);
        let reads = work_ct.clone();
        let work = tokio::task::spawn_blocking(move || {
            // Keep the slot until blocking work actually stops, including after caller timeout.
            let _slot = slot;
            let plan = match ozpb_toolkit::plan_policy_check_read(&input, &trust, &build) {
                Ok(plan) => plan,
                Err(error) => return ozpb_toolkit::policy_check_unavailable(error),
            };
            let capture = ozpb_source_rpc::capture_policy_state(
                &cancel::transport(rpc_url, &reads),
                &source.network_passphrase,
                &plan.account_address,
                plan.installed_context_rule_id,
                &plan.contract_addresses,
                &plan.additional_keys,
            )
            .map_err(|_| {
                ToolError::new(
                    ErrorCode::ERpc,
                    "policy state could not be acquired coherently; endpoint details withheld",
                )
            })?;
            ozpb_toolkit::finish_policy_check(&plan, &capture)
        });
        let waited = tokio::time::timeout(deadline, work).await.map_err(|_| {
            work_ct.cancel();
            tool_err(ToolError::new(
                ErrorCode::EResourceLimit,
                "live policy read exceeded its deadline",
            ))
        });
        Ok(Json(
            cancel::unless_cancelled(&ct, waited)?
                .map_err(internal_tool_err)?
                .map_err(tool_err)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{http_session_factory, tests::refusal_code, RpcEndpointPolicy};
    use serde_json::json;

    fn request() -> CheckAgainstPolicyInput {
        // Deliberately invalid spec: if the route reaches planning it must stop before I/O.
        serde_json::from_value(json!({
            "spec": {},
            "binding_set": {"schema": "policy-binding-set/v1", "spec_hash": "00", "network_id": "00", "bindings": []},
            "signed_registry_snapshot": {}, "rule_index": 0, "installed_context_rule_id": 42,
            "account_address": "unused", "network_id": ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE).0.to_hex(),
            "rpc_source": "testnet", "candidate_signers": [], "invocation": {}
        })).unwrap()
    }

    fn factory(endpoint: &str) -> impl Fn() -> Result<PolicyBuilderServer, std::io::Error> {
        let root = ozpb_registry::dev::dev_root_verifying_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let trust = ozpb_toolkit::registry_trust_from_roots_json(
            &json!({"threshold": 1, "keys": {"legacy": root}}).to_string(),
            1,
        )
        .unwrap();
        let sources = std::collections::BTreeMap::from([(
            "testnet".into(),
            ozpb_toolkit::RpcSource {
                rpc_url: endpoint.into(),
                network_passphrase: ozpb_domain::TESTNET_PASSPHRASE.into(),
            },
        )]);
        http_session_factory(
            Some(trust),
            RpcEndpointPolicy::from_csv("https://rpc.allowed.example").unwrap(),
            std::sync::Arc::new(sources),
            crate::tests::hosted().build_config,
            crate::tool_limits::ToolLimitConfig::parse(60, None).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn actual_policy_route_refuses_an_operator_source_outside_hosted_allowlist() {
        let server = factory("https://rpc.other.example")().unwrap();
        assert_eq!(
            refusal_code(
                server
                    .check_against_policy(Parameters(request()), Default::default())
                    .await
            ),
            "E_RPC"
        );
    }

    #[tokio::test]
    async fn actual_policy_route_uses_shared_authority_capacity_across_sessions() {
        let sessions = factory("https://rpc.allowed.example");
        let first = sessions().unwrap();
        let second = sessions().unwrap();
        let running = first
            .authority_slots
            .as_ref()
            .unwrap()
            .clone()
            .try_acquire_owned()
            .unwrap();
        drop(first);
        assert_eq!(
            refusal_code(
                second
                    .check_against_policy(Parameters(request()), Default::default())
                    .await
            ),
            "E_RESOURCE_LIMIT"
        );
        drop(running);
        // The control reaches the malformed spec, proving the busy result was the slot.
        assert_eq!(
            refusal_code(
                second
                    .check_against_policy(Parameters(request()), Default::default())
                    .await
            ),
            "E_SPEC_INVALID"
        );
        assert_eq!(
            second.authority_slots.as_ref().unwrap().available_permits(),
            1
        );
    }
}
