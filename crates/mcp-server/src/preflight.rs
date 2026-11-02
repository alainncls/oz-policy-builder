//! Network-read wrapper for one authorization-enforcing transaction simulation.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{ErrorCode, PreflightTransactionInput, PreflightTransactionOutput, ToolError};
use tokio_util::sync::CancellationToken;

use crate::{cancel, internal_tool_err, rpc_tool_err, tool_err, PolicyBuilderServer};

/// Why a hosted server takes no signed material. The server never holds anything that can
/// authorize on a user's account (architecture §6.2), and confidential simulation belongs on
/// local or self-hosted processing (§6.5). A signed entry is stronger than confidential: whoever
/// receives it can use it until it expires.
const HOSTED_SIGNED_REFUSAL: &str = "this hosted server refuses envelopes that carry \
    transaction signatures or signed authorization entries: they are live authorizations, \
    which anyone holding them can submit until they expire. Run preflight through the CLI or \
    a local stdio server against an RPC endpoint you trust";

#[tool_router(router = preflight_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Simulate one exact envelope with RPC authorization enforcement. The endpoint's
    /// result is a state-dependent trial, not a durable policy or installation verdict.
    #[tool(
        name = "preflight_transaction",
        description = "Simulate one exact envelope, including any intended authorization \
                       entries, through Stellar RPC with authorization enforced. \
                       Returns the endpoint-reported outcome \
                       (simulated_success, simulation_failed, restoration_required, or \
                       declared_resources_insufficient naming each footprint list that is not \
                       exactly the simulated one and each disk-read or write limit below the \
                       use) and ledger for that exact envelope. below_endpoint_estimate is \
                       advice: declared instructions or resource fee below the endpoint's \
                       padded estimate, which never changes the outcome. State-dependent; \
                       writes are discarded. Does not identify an installed policy or submit a \
                       transaction. \
                       Signed authorization entries are live authorizations: anyone who sees \
                       the envelope can submit them until their signatureExpirationLedger, and \
                       simulation does not consume their nonce. The envelope reaches the RPC \
                       endpoint and this conversation; prefer testnet or a short expiration and \
                       a trusted endpoint. A hosted server refuses signed envelopes; use the CLI \
                       or a local stdio server."
    )]
    async fn preflight_transaction(
        &self,
        Parameters(input): Parameters<PreflightTransactionInput>,
        ct: CancellationToken,
    ) -> Result<Json<PreflightTransactionOutput>, CallToolResult> {
        let rpc_url = self.authorized_rpc_url(&input.rpc_url).map_err(tool_err)?;
        // Only a hosted server has an endpoint policy; a stdio server runs in the caller's own
        // trust domain, like the CLI.
        if self.rpc_policy.is_some()
            && ozpb_source_rpc::envelope_carries_signatures(&input.envelope_xdr_base64)
                .map_err(|error| tool_err(rpc_tool_err(error)))?
        {
            return Err(tool_err(ToolError::new(
                ErrorCode::EUnsupportedEnvelope,
                HOSTED_SIGNED_REFUSAL,
            )));
        }
        let request = ct.clone();
        let observation = tokio::task::spawn_blocking(move || {
            let transport = cancel::transport(rpc_url, &request);
            ozpb_source_rpc::preflight_transaction(
                &transport,
                &input.network_passphrase,
                &input.envelope_xdr_base64,
            )
            .map_err(rpc_tool_err)
        })
        .await
        .map_err(internal_tool_err)?;
        let observation = cancel::unless_cancelled(&ct, observation.map_err(tool_err))?;
        Ok(Json(ozpb_toolkit::preflight_transaction_output(
            observation,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RpcEndpointPolicy;

    #[tokio::test]
    async fn hosted_preflight_rejects_an_endpoint_outside_the_allowlist() {
        let policy = RpcEndpointPolicy::from_csv("https://rpc.allowed.example")
            .expect("valid operator allowlist");
        let server = PolicyBuilderServer::new(
            None,
            Some(policy),
            Default::default(),
            ozpb_toolkit::BuildConfig::default(),
        );
        let error = server
            .preflight_transaction(
                Parameters(PreflightTransactionInput {
                    rpc_url: "https://rpc.unapproved.example".to_string(),
                    network_passphrase: "Test SDF Network ; September 2015".to_string(),
                    envelope_xdr_base64: "not-base64".to_string(),
                }),
                Default::default(),
            )
            .await;
        let error = match error {
            Ok(_) => panic!("hosted endpoint policy must run before RPC acquisition"),
            Err(error) => error,
        };
        let wire = serde_json::to_value(error).expect("tool error JSON");
        assert_eq!(wire["structuredContent"]["code"], "E_RPC", "{wire}");
        assert!(
            wire["structuredContent"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("allowlist")),
            "{wire}"
        );
    }

    /// The example invocation with one transaction signature added.
    fn signed_envelope() -> String {
        use stellar_xdr::{
            DecoratedSignature, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
            WriteXdr,
        };
        let bundle: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/examples/import-bundle.json"))
                .expect("example bundle JSON");
        let mut envelope = TransactionEnvelope::from_xdr_base64(
            bundle["envelope_xdr_base64"]
                .as_str()
                .expect("example envelope"),
            Limits::none(),
        )
        .expect("example envelope XDR");
        let TransactionEnvelope::Tx(v1) = &mut envelope else {
            panic!("the example envelope is a v1 transaction");
        };
        v1.signatures = vec![DecoratedSignature {
            hint: SignatureHint([1; 4]),
            signature: Signature(vec![7; 64].try_into().expect("signature bytes")),
        }]
        .try_into()
        .expect("one signature");
        envelope
            .to_xdr_base64(Limits::none())
            .expect("signed envelope XDR")
    }

    #[tokio::test]
    async fn hosted_preflight_refuses_signed_material_before_any_request() {
        let policy = RpcEndpointPolicy::from_csv("https://rpc.allowed.example")
            .expect("valid operator allowlist");
        let server = PolicyBuilderServer::new(
            None,
            Some(policy),
            Default::default(),
            ozpb_toolkit::BuildConfig::default(),
        );
        let result = server
            .preflight_transaction(
                Parameters(PreflightTransactionInput {
                    rpc_url: "https://rpc.allowed.example".to_string(),
                    network_passphrase: "Test SDF Network ; September 2015".to_string(),
                    envelope_xdr_base64: signed_envelope(),
                }),
                Default::default(),
            )
            .await;
        let error = match result {
            Ok(_) => panic!("a hosted server must not accept signed material"),
            Err(error) => error,
        };
        let wire = serde_json::to_value(error).expect("tool error JSON");
        assert_eq!(
            wire["structuredContent"]["code"], "E_UNSUPPORTED_ENVELOPE",
            "{wire}"
        );
        let message = wire["structuredContent"]["message"].as_str().unwrap_or("");
        assert!(message.contains("live authorizations"), "{wire}");
        assert!(message.contains("stdio"), "{wire}");
    }
}
