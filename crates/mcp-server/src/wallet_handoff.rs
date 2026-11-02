//! Same-machine, draft-only wallet transport. Never holds the wallet's full session bearer.
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ozpb_api_types::{
    ConnectWalletInput, ConnectWalletOutput, ErrorCode, SendWalletProposalInput,
    SendWalletProposalOutput, ToolError, WalletHandoffConnection, WalletHandoffReceipt,
};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use serde_json::{json, Value};

use crate::{internal_tool_err, tool_err, PolicyBuilderServer};

fn refusal() -> ToolError {
    ToolError::new(ErrorCode::ERpc, "local wallet bridge unavailable; open the wallet, connect Claude and use a fresh pairing code")
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) struct WalletBridge {
    origin: String,
    client: ureq::Agent,
    capability: Option<String>,
    connection: Option<WalletHandoffConnection>,
}
impl WalletBridge {
    fn new(origin: &str) -> anyhow::Result<Self> {
        let url = url::Url::parse(origin)?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!("OZPB_WALLET_HANDOFF_URL must be a literal http://127.0.0.1:PORT origin");
        }
        Ok(Self {
            origin: url.as_str().trim_end_matches('/').to_owned(),
            client: ureq::AgentBuilder::new()
                .redirects(0)
                .try_proxy_from_env(false)
                .timeout(Duration::from_secs(5))
                .build(),
            capability: None,
            connection: None,
        })
    }
    fn post(
        &self,
        path: &str,
        payload: Value,
        capability: Option<&str>,
    ) -> Result<Value, ToolError> {
        let request = self.client.post(&format!("{}{path}", self.origin));
        let request = if let Some(cap) = capability {
            request.set("authorization", &format!("Bearer {cap}"))
        } else {
            request
        };
        let response = request.send_json(payload).map_err(|_| refusal())?;
        if response.status() != 200 {
            return Err(refusal());
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| refusal())?;
        if bytes.len() > 32768 {
            return Err(refusal());
        }
        serde_json::from_slice(&bytes).map_err(|_| refusal())
    }
    fn connect(&mut self, code: &str) -> Result<ConnectWalletOutput, ToolError> {
        // A failed attempt to select another wallet must not leave the previous
        // connection's draft-delivery authority usable by accident.
        self.capability = None;
        self.connection = None;
        if !code.strip_prefix("ozpb-pair-").is_some_and(hex) {
            return Err(refusal());
        }
        let value = self.post("/agent/connect", json!({"pairingCode":code}), None)?;
        if value.as_object().is_none_or(|map| map.len() != 2) {
            return Err(refusal());
        }
        let capability = value["capability"]
            .as_str()
            .filter(|v| hex(v))
            .ok_or_else(refusal)?
            .to_owned();
        let connection: WalletHandoffConnection =
            serde_json::from_value(value["connection"].clone()).map_err(|_| refusal())?;
        if !hex(&connection.connection_id)
            || !connection.account.starts_with('C')
            || connection.account.len() != 56
            || !connection.delegate.starts_with('G')
            || connection.delegate.len() != 56
            || connection.network_id
                != ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
                    .0
                    .to_hex()
            || connection.expires_in_seconds == 0
            || connection.expires_in_seconds > 1800
            || connection.limits.max_calls != 10000
            || connection.limits.max_validity_ledgers != 17280
            || !connection.limits.exact_native_transfer_only
        {
            return Err(refusal());
        }
        self.capability = Some(capability);
        self.connection = Some(connection.clone());
        Ok(ConnectWalletOutput { connection })
    }
    fn send(&self, proposal: &str) -> Result<SendWalletProposalOutput, ToolError> {
        if proposal.len() > 16384 || proposal.is_empty() {
            return Err(refusal());
        }
        let capability = self.capability.as_deref().ok_or_else(refusal)?;
        let connection = self.connection.as_ref().ok_or_else(refusal)?;
        let delivery_id = ozpb_domain::sha256(proposal.as_bytes()).to_hex();
        let value = self.post(
            "/agent/proposal",
            json!({"deliveryId":delivery_id,"proposal":proposal}),
            Some(capability),
        )?;
        let receipt: WalletHandoffReceipt = serde_json::from_value(value).map_err(|_| refusal())?;
        if receipt.delivery_id != delivery_id
            || receipt.connection_id != connection.connection_id
            || receipt.account != connection.account
            || receipt.delegate != connection.delegate
            || !["pending", "claimed", "dismissed", "expired"].contains(&receipt.status.as_str())
        {
            return Err(refusal());
        }
        Ok(SendWalletProposalOutput {
            receipt,
            wallet_review_required: true,
        })
    }
}
pub(crate) fn configured_bridge() -> anyhow::Result<Option<Arc<Mutex<WalletBridge>>>> {
    std::env::var("OZPB_WALLET_HANDOFF_URL")
        .ok()
        .map(|url| WalletBridge::new(&url).map(|bridge| Arc::new(Mutex::new(bridge))))
        .transpose()
}

#[tool_router(router = wallet_handoff_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    #[tool(
        name = "connect_wallet",
        description = "Pair with the user's same-machine testnet wallet using the one-time code its Connect Claude button shows. Returns public account, delegate and limits. No signing or installation authority. Unavailable on hosted MCP."
    )]
    async fn connect_wallet(
        &self,
        Parameters(input): Parameters<ConnectWalletInput>,
    ) -> Result<Json<ConnectWalletOutput>, CallToolResult> {
        let bridge = self
            .wallet_bridge
            .clone()
            .ok_or_else(|| tool_err(refusal()))?;
        let result = tokio::task::spawn_blocking(move || {
            bridge
                .lock()
                .map_err(|_| refusal())?
                .connect(&input.pairing_code)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(result))
    }
    #[tool(
        name = "send_wallet_proposal",
        description = "Only after the user's explicit final permission-card confirmation: send existing ozpb-grant-proposal/v1 JSON to the paired local testnet wallet as an unverified draft. Does not deploy, sign, install or approve. The wallet user must review it. Retries of identical bytes are idempotent; do not change bytes to retry an expired/rejected proposal without new confirmation."
    )]
    async fn send_wallet_proposal(
        &self,
        Parameters(input): Parameters<SendWalletProposalInput>,
    ) -> Result<Json<SendWalletProposalOutput>, CallToolResult> {
        let bridge = self
            .wallet_bridge
            .clone()
            .ok_or_else(|| tool_err(refusal()))?;
        let result = tokio::task::spawn_blocking(move || {
            bridge
                .lock()
                .map_err(|_| refusal())?
                .send(&input.proposal_json)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_operator_configured_literal_loopback_origins_are_accepted() {
        assert!(WalletBridge::new("http://127.0.0.1:4317").is_ok());
        for url in [
            "https://127.0.0.1:4317",
            "http://localhost:4317",
            "http://10.0.0.1:4317",
            "http://127.0.0.1:4317/path",
            "http://user@127.0.0.1:4317",
            "http://127.0.0.1:4317/?secret=x",
        ] {
            assert!(WalletBridge::new(url).is_err(), "{url}");
        }
    }
}
