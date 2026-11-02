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

const MANUAL: &str = "the manual install skill, /oz-policy-builder:policy-builder-install, \
                      which only the user can start";
const NEW_CARD: &str = "then show the complete card again and wait for `confirm` before sending";

#[derive(Clone, Copy, Debug)]
enum Route {
    Connect,
    Proposal,
}
impl Route {
    fn path(self) -> &'static str {
        match self {
            Route::Connect => "/agent/connect",
            Route::Proposal => "/agent/proposal",
        }
    }
}

fn unavailable(message: String) -> ToolError {
    ToolError::new(ErrorCode::EWalletUnavailable, message)
}
fn not_configured() -> ToolError {
    unavailable(format!(
        "This MCP server has no local wallet bridge: only a stdio server on the user's own \
         computer can reach their wallet, and a hosted server never can. Offer {MANUAL}."
    ))
}
fn not_understood() -> ToolError {
    unavailable(format!(
        "The wallet's reply was not understood (another wallet version, or another program on \
         its port); nothing is confirmed as delivered. Ask the user to check the wallet, or \
         offer {MANUAL}."
    ))
}
fn unreachable(route: Route) -> ToolError {
    unavailable(match route {
        Route::Connect => format!(
            "The wallet did not answer on this computer. Ask the user to open the wallet's \
             Policy Builder page and select Connect Claude for a fresh code, or offer {MANUAL}."
        ),
        Route::Proposal => format!(
            "The wallet did not answer, so the proposal may or may not have arrived. Retry the \
             identical proposal once. If it still does not answer, the wallet may have restarted, \
             which ends the connection: ask the user to select Connect Claude for a fresh code, \
             or offer {MANUAL}."
        ),
    })
}
fn pairing_required(message: String) -> ToolError {
    ToolError::new(ErrorCode::EWalletPairingRequired, message)
}
fn not_a_code() -> ToolError {
    pairing_required(
        "That is not a wallet pairing code. Ask the user to select Connect Claude in the wallet \
         and paste the one-time code it shows (it starts with ozpb-pair-)."
            .into(),
    )
}
fn not_connected() -> ToolError {
    pairing_required(format!(
        "No wallet is connected in this session. Ask the user to select Connect Claude in the \
         wallet and give you its one-time code, check that the connection's account and \
         delegate match the grant, {NEW_CARD}."
    ))
}
fn proposal_refused(message: String) -> ToolError {
    ToolError::new(ErrorCode::EWalletProposalRefused, message)
}
fn too_large() -> ToolError {
    proposal_refused(
        "The proposal is empty or larger than 16 KiB. Do not reconnect: build it exactly as \
         references/wallet-proposal.md describes."
            .into(),
    )
}

/// What a wallet refusal means for the agent. Only a closed `reason` that belongs to the route
/// and status is read; no other reply text reaches the tool result.
fn refusal(route: Route, status: u16, body: &[u8]) -> ToolError {
    let reply: Option<Value> = serde_json::from_slice(body).ok();
    let reason = reply
        .as_ref()
        .and_then(|value| value.get("reason"))
        .and_then(Value::as_str);
    match (route, status, reason) {
        (_, 409, Some("busy")) | (_, 429, Some("capacity")) => ToolError::new(
            ErrorCode::EWalletBusy,
            "The wallet is busy with another action. Wait a few seconds and retry once with \
             identical input. If it is still busy, ask the user to finish what the wallet is \
             doing.",
        ),
        (Route::Connect, 422, Some("pairing_refused")) => pairing_required(
            "The wallet did not accept that pairing code: it is wrong, already used or older \
             than five minutes. Ask the user to select Connect Claude again and paste the new code."
                .into(),
        ),
        (Route::Proposal, 422, Some("connection_unavailable")) => pairing_required(format!(
            "The wallet connection has ended: thirty minutes passed since pairing, the user \
             disconnected or connected again, or the wallet restarted. Ask the user to select \
             Connect Claude for a fresh code, check that the new connection's account and \
             delegate match the grant, {NEW_CARD}."
        )),
        (Route::Proposal, 422, Some("delivery_limit")) => pairing_required(format!(
            "This connection has already received eight proposals, its limit. Ask the user to \
             select Reconnect Claude for a fresh code, {NEW_CARD}."
        )),
        (Route::Proposal, 422, Some("draft_pending")) => ToolError::new(
            ErrorCode::EWalletDraftPending,
            format!(
                "A different, earlier proposal from this session is still waiting in the wallet, \
                 and nothing was sent. If this grant replaces it, ask the user to select Dismiss \
                 proposal in the wallet (on a wallet page reopened since pairing: Disconnect \
                 Claude, then Connect Claude for a fresh code), {NEW_CARD}."
            ),
        ),
        (Route::Proposal, 422, Some("proposal_invalid")) => proposal_refused(format!(
            "The wallet refused the proposal: it is malformed, not for the connected account on \
             testnet, or outside what the wallet supports (one exact native-XLM transfer). Do not \
             reconnect. Check it against references/wallet-proposal.md and the confirmed tool \
             outputs; if the grant itself is unsupported, offer {MANUAL}."
        )),
        (Route::Proposal, 422, Some("delegate_mismatch")) => proposal_refused(format!(
            "The grant's delegate is not the connected wallet's automation delegate. Do not \
             reconnect. Explain this to the user; with their agreement, build the grant again for \
             the delegate connect_wallet returned (a new card and confirmation follow), or \
             offer {MANUAL}."
        )),
        (Route::Proposal, 422, Some("call_limit")) => proposal_refused(format!(
            "The grant allows more than 512 calls, the most the wallet's execution checks \
             support. Do not reconnect. Ask the user for a cap of at most 512 (a new card and \
             confirmation follow), or offer {MANUAL}."
        )),
        _ => not_understood(),
    }
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn strkey(value: &str, version: u8) -> bool {
    value.len() == 56
        && value.as_bytes()[0] == version
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}
fn read_bounded(reader: impl Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(32769).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 32768).then_some(bytes)
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
        route: Route,
        payload: Value,
        capability: Option<&str>,
    ) -> Result<Value, ToolError> {
        let request = self
            .client
            .post(&format!("{}{}", self.origin, route.path()));
        let request = if let Some(cap) = capability {
            request.set("authorization", &format!("Bearer {cap}"))
        } else {
            request
        };
        let response = match request.send_json(payload) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                let body = read_bounded(response.into_reader()).unwrap_or_default();
                return Err(refusal(route, status, &body));
            }
            Err(ureq::Error::Transport(_)) => return Err(unreachable(route)),
        };
        // Redirects are not followed, so a 3xx arrives here.
        if response.status() != 200 {
            return Err(not_understood());
        }
        let bytes = read_bounded(response.into_reader()).ok_or_else(not_understood)?;
        serde_json::from_slice(&bytes).map_err(|_| not_understood())
    }
    fn connect(&mut self, code: &str) -> Result<ConnectWalletOutput, ToolError> {
        // A failed attempt to select another wallet must not leave the previous
        // connection's draft-delivery authority usable by accident.
        self.capability = None;
        self.connection = None;
        if !code.strip_prefix("ozpb-pair-").is_some_and(hex) {
            return Err(not_a_code());
        }
        let value = self.post(Route::Connect, json!({"pairingCode":code}), None)?;
        if value.as_object().is_none_or(|map| map.len() != 2) {
            return Err(not_understood());
        }
        let capability = value["capability"]
            .as_str()
            .filter(|v| hex(v))
            .ok_or_else(not_understood)?
            .to_owned();
        let connection: WalletHandoffConnection =
            serde_json::from_value(value["connection"].clone()).map_err(|_| not_understood())?;
        // Only an address's alphabet reaches the tool result, never other reply text.
        if !hex(&connection.connection_id)
            || !strkey(&connection.account, b'C')
            || !strkey(&connection.delegate, b'G')
            || connection.network_id
                != ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
                    .0
                    .to_hex()
            || connection.expires_in_seconds == 0
            || connection.expires_in_seconds > 1800
            || connection.limits.max_calls != 512
            || connection.limits.max_validity_ledgers != 17280
            || !connection.limits.exact_native_transfer_only
        {
            return Err(not_understood());
        }
        self.capability = Some(capability);
        self.connection = Some(connection.clone());
        Ok(ConnectWalletOutput { connection })
    }
    fn send(&self, proposal: &str) -> Result<SendWalletProposalOutput, ToolError> {
        if proposal.len() > 16384 || proposal.is_empty() {
            return Err(too_large());
        }
        let capability = self.capability.as_deref().ok_or_else(not_connected)?;
        let connection = self.connection.as_ref().ok_or_else(not_connected)?;
        let delivery_id = ozpb_domain::sha256(proposal.as_bytes()).to_hex();
        let value = self.post(
            Route::Proposal,
            json!({"deliveryId":delivery_id,"proposal":proposal}),
            Some(capability),
        )?;
        let receipt: WalletHandoffReceipt =
            serde_json::from_value(value).map_err(|_| not_understood())?;
        if receipt.delivery_id != delivery_id
            || receipt.connection_id != connection.connection_id
            || receipt.account != connection.account
            || receipt.delegate != connection.delegate
            || !["pending", "claimed", "dismissed", "expired"].contains(&receipt.status.as_str())
        {
            return Err(not_understood());
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
            .ok_or_else(|| tool_err(not_configured()))?;
        let result = tokio::task::spawn_blocking(move || {
            bridge
                .lock()
                .map_err(|_| not_understood())?
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
            .ok_or_else(|| tool_err(not_configured()))?;
        let result = tokio::task::spawn_blocking(move || {
            bridge
                .lock()
                .map_err(|_| not_understood())?
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
    use ozpb_api_types::ErrorCode::*;

    fn reply(reason: &str) -> Vec<u8> {
        json!({ "error": "agent request refused", "reason": reason })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn each_wallet_reason_maps_to_what_the_agent_can_do() {
        for (route, status, reason, code) in [
            (
                Route::Connect,
                422,
                "pairing_refused",
                EWalletPairingRequired,
            ),
            (Route::Connect, 409, "busy", EWalletBusy),
            (Route::Connect, 429, "capacity", EWalletBusy),
            (Route::Proposal, 409, "busy", EWalletBusy),
            (Route::Proposal, 429, "capacity", EWalletBusy),
            (
                Route::Proposal,
                422,
                "connection_unavailable",
                EWalletPairingRequired,
            ),
            (
                Route::Proposal,
                422,
                "delivery_limit",
                EWalletPairingRequired,
            ),
            (Route::Proposal, 422, "draft_pending", EWalletDraftPending),
            (
                Route::Proposal,
                422,
                "proposal_invalid",
                EWalletProposalRefused,
            ),
            (
                Route::Proposal,
                422,
                "delegate_mismatch",
                EWalletProposalRefused,
            ),
            (Route::Proposal, 422, "call_limit", EWalletProposalRefused),
        ] {
            assert_eq!(
                refusal(route, status, &reply(reason)).code,
                code,
                "{reason}"
            );
        }
    }

    #[test]
    fn anything_else_is_an_unavailable_wallet_and_no_reply_text_is_echoed() {
        let canary = "PRIVATE-WALLET-CANARY";
        for (route, status, body) in [
            // A reason that does not belong to the route, or to the status.
            (Route::Connect, 422, reply("draft_pending")),
            (Route::Connect, 422, reply("connection_unavailable")),
            (Route::Proposal, 422, reply("pairing_refused")),
            (Route::Proposal, 409, reply("draft_pending")),
            (Route::Proposal, 422, reply("request_invalid")),
            (Route::Proposal, 422, reply("unavailable")),
            (Route::Proposal, 422, reply(canary)),
            (
                Route::Proposal,
                422,
                b"{\"error\":\"wallet action unavailable\"}".to_vec(),
            ),
            (Route::Proposal, 422, canary.as_bytes().to_vec()),
            (Route::Proposal, 403, reply("busy")),
            (Route::Proposal, 400, reply("busy")),
            (Route::Proposal, 500, reply("busy")),
            (Route::Proposal, 307, reply("busy")),
        ] {
            let error = refusal(route, status, &body);
            assert_eq!(error.code, EWalletUnavailable, "{status} {body:?}");
            assert!(!error.to_string().contains(canary));
        }
    }

    #[test]
    fn content_refusals_say_not_to_reconnect_and_differ_by_reason() {
        let messages: Vec<String> = ["proposal_invalid", "delegate_mismatch", "call_limit"]
            .iter()
            .map(|reason| refusal(Route::Proposal, 422, &reply(reason)).message)
            .collect();
        for message in &messages {
            assert!(message.contains("Do not reconnect"), "{message}");
        }
        assert_eq!(
            messages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }
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
