//! Local wallet draft delivery, never signing or installation authority.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectWalletInput {
    pub pairing_code: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendWalletProposalInput {
    /// Existing ozpb-grant-proposal/v1 JSON, at most 16 KiB. Only after final confirmation.
    pub proposal_json: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletHandoffLimits {
    pub max_validity_ledgers: u32,
    pub max_calls: u32,
    pub exact_native_transfer_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletHandoffConnection {
    pub connection_id: String,
    pub account: String,
    pub delegate: String,
    pub network_id: String,
    pub expires_in_seconds: u32,
    pub limits: WalletHandoffLimits,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectWalletOutput {
    pub connection: WalletHandoffConnection,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletHandoffReceipt {
    pub delivery_id: String,
    pub status: String,
    pub account: String,
    pub delegate: String,
    pub connection_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendWalletProposalOutput {
    pub receipt: WalletHandoffReceipt,
    /// Delivery is not wallet verification, approval, deployment or installation.
    pub wallet_review_required: bool,
}
