//! Network-read wrapper for capturing one native SAC transfer's target state.
//!
//! The endpoint is the operator's: the request names a configured source, and a hosted server
//! additionally requires that source's URL on its allowlist and runs one such read at a time,
//! sharing the limit authority reads use, since every one of them spends the operator's RPC
//! source. The envelope is confidential input and never comes back in a result or an error.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{CaptureTargetInput, CaptureTargetOutput, ErrorCode, ToolError};
use tokio_util::sync::CancellationToken;

use crate::{cancel, internal_tool_err, tool_err, PolicyBuilderServer};

/// At most eight requests (the first network check, then up to two attempts of simulation,
/// network check and entry read, the last also reading the header) at the transport's 30 s per
/// request.
const CAPTURE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

#[tool_router(router = capture_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Capture the target state one native SAC transfer reads and writes, for the native
    /// worker's captured-target layer.
    #[tool(
        name = "capture_target",
        description = "Read-only, state-dependent network read through an operator-configured \
                       RPC source (the request names the source and network; it never carries \
                       a URL). Takes one unsigned envelope with no authorization entries whose \
                       only call is a native Stellar Asset Contract transfer(contract account, \
                       existing G recipient, positive amount) on that network, and returns its \
                       target capture: the ledger header, state-archival configuration, the \
                       call, the account's executed Wasm hash and every footprint entry at one \
                       ledger, provenance rpc_reported (an endpoint's answer, not an inclusion \
                       proof). The record-mode simulation it uses is acquisition only, never \
                       evidence that a policy permits the call. Any other target, function or \
                       envelope shape is refused (E_UNSUPPORTED_ENVELOPE). The envelope is \
                       confidential input: it reaches the configured RPC endpoint and this \
                       conversation, and no result or error echoes it; the capture repeats its \
                       call (account, recipient, amount) and is equally confidential. Prefer \
                       the CLI or a local stdio server. The output is the capture the native \
                       worker's captured-target modes read; this tool does not run the \
                       captured-target layer, signs nothing and submits nothing.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn capture_target(
        &self,
        Parameters(input): Parameters<CaptureTargetInput>,
        ct: CancellationToken,
    ) -> Result<Json<CaptureTargetOutput>, CallToolResult> {
        // Resolved first, so an unknown name or another network fails before any slot or read.
        let source = ozpb_toolkit::resolve_capture_rpc_source(
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
                    "another read through an operator RPC source is running on this server; \
                     retry shortly",
                ))
            })?),
            None => None,
        };
        let work_ct = ct.child_token();
        let reads = work_ct.clone();
        let work = tokio::task::spawn_blocking(move || {
            // Held until the blocking read stops, including after the caller stops waiting.
            let _slot = slot;
            ozpb_toolkit::capture_target_output(ozpb_source_rpc::capture_native_target(
                &cancel::transport(rpc_url, &reads),
                &source.network_passphrase,
                &input.envelope_xdr_base64,
            ))
        });
        let waited = tokio::time::timeout(CAPTURE_DEADLINE, work)
            .await
            .map_err(|_| {
                work_ct.cancel();
                tool_err(ToolError::new(
                    ErrorCode::EResourceLimit,
                    format!(
                        "the target capture did not finish within {} s",
                        CAPTURE_DEADLINE.as_secs()
                    ),
                ))
            });
        let output = cancel::unless_cancelled(&ct, waited)?
            .map_err(internal_tool_err)?
            .map_err(tool_err)?;
        Ok(Json(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::refusal_code;
    use crate::{http_session_factory, RpcEndpointPolicy};

    fn request() -> CaptureTargetInput {
        CaptureTargetInput {
            network_id: ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
                .0
                .to_hex(),
            rpc_source: "testnet".into(),
            // Malformed on purpose: a route that got past its limits refuses it locally.
            envelope_xdr_base64: "not-an-envelope".into(),
        }
    }

    /// Hosted sessions whose operator source `testnet` is `endpoint`.
    fn sessions(endpoint: &str) -> impl Fn() -> Result<PolicyBuilderServer, std::io::Error> {
        let sources = std::collections::BTreeMap::from([(
            "testnet".into(),
            ozpb_toolkit::RpcSource {
                rpc_url: endpoint.into(),
                network_passphrase: ozpb_domain::TESTNET_PASSPHRASE.into(),
            },
        )]);
        http_session_factory(
            None,
            RpcEndpointPolicy::from_csv("https://rpc.allowed.example").unwrap(),
            std::sync::Arc::new(sources),
            crate::tests::hosted().build_config,
            crate::tool_limits::ToolLimitConfig::parse(60, None).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn hosted_capture_refuses_an_operator_source_outside_the_allowlist() {
        let server = sessions("https://rpc.other.example")().unwrap();
        assert_eq!(
            refusal_code(
                server
                    .capture_target(Parameters(request()), Default::default())
                    .await
            ),
            "E_RPC"
        );
    }

    #[tokio::test]
    async fn hosted_capture_shares_the_one_operation_limit_across_sessions() {
        let sessions = sessions("https://rpc.allowed.example");
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
                    .capture_target(Parameters(request()), Default::default())
                    .await
            ),
            "E_RESOURCE_LIMIT"
        );
        drop(running);
        // The control reaches the envelope check, proving the busy result was the slot, and
        // gives the slot back.
        assert_eq!(
            refusal_code(
                second
                    .capture_target(Parameters(request()), Default::default())
                    .await
            ),
            "E_ENVELOPE_PARSE"
        );
        assert_eq!(
            second.authority_slots.as_ref().unwrap().available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn a_request_names_a_configured_source_for_its_own_network() {
        let server = sessions("https://rpc.allowed.example")().unwrap();
        let mut unknown = request();
        unknown.rpc_source = "unconfigured".into();
        assert_eq!(
            refusal_code(
                server
                    .capture_target(Parameters(unknown), Default::default())
                    .await
            ),
            "E_RPC"
        );
        let mut other_network = request();
        other_network.network_id = "00".repeat(32);
        assert_eq!(
            refusal_code(
                server
                    .capture_target(Parameters(other_network), Default::default())
                    .await
            ),
            "E_NETWORK_MISMATCH"
        );
    }
}
