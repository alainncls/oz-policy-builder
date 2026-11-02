//! Bound evidence for a candidate grant. Missing execution is never a passed layer.

use crate::{CheckPolicyCallSurfaceInput, VerifyInput, VerifyOutput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunInput {
    /// Exact candidate identities and operator RPC source name. This is input to
    /// recognition, not a caller-provided authority verdict or ledger observation.
    pub candidate: CheckPolicyCallSurfaceInput,
    /// Claimed source, Wasm and manifest for exactly the candidate's spec and rule.
    pub artifact: VerifyInput,
    /// Proposed chain ID, independent of the spec index. A later live execution
    /// must read and check the actual NextId; this field is not proof of that ID.
    pub candidate_context_rule_id: u32,
    /// Canonical lowercase 32-byte hex nonce to distinguish otherwise identical runs.
    pub run_nonce: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DryRunLayerId {
    Reference,
    AccountWasm,
    CapturedTarget,
    LiveEnforcement,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DryRunLayerStatus {
    Passed,
    Failed,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunLayer {
    pub id: DryRunLayerId,
    pub status: DryRunLayerStatus,
    /// Stable explanation of the actual evidence or missing prerequisite.
    pub reason: String,
    pub cases: usize,
    pub state_dependent: bool,
    /// Writes committed to a live network. No layer here commits one. An offline layer's
    /// permitted calls commit only fresh synthetic local state, which its `execution`
    /// provenance states.
    pub writes_committed: bool,
    /// Present only on a layer this run executed, once the worker's report was bound to the
    /// preparation: the identities it ran under and every case, each re-checked against the
    /// preparation's expectation. Never present in a preparation, and never on a layer whose
    /// report was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<DryRunLayerExecution>,
}

/// One executed layer's bound evidence. The offline binding equals the one derived from the
/// preparation; `execution_network_id` is re-derived from it, never a live network.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunLayerExecution {
    pub run_hash: String,
    pub job_hash: String,
    pub suite_hash: String,
    pub state_hash: String,
    pub source_network_id: String,
    pub source_ledger: u32,
    /// Counterfactual network the layer executed in, derived from the binding above.
    pub execution_network_id: String,
    pub delegate_address: String,
    pub policy_address: String,
    pub policy_code_hash: String,
    pub host_version: String,
    pub provenance: String,
    pub cases: Vec<DryRunCaseResult>,
    /// Signature, nonce, payload, rule-binding and replay controls (account-Wasm layer only).
    pub controls: Vec<DryRunControlResult>,
    /// The call-cap sequence, when the selected rule has a cap (account-Wasm layer only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateful: Option<DryRunStatefulResult>,
}

/// The contract that raised an attributed refusal, by its role in the candidate grant.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DryRunEnforcer {
    Account,
    Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunCaseResult {
    pub case_id: String,
    pub label: String,
    /// The reference case's mutation class in snake case, e.g. `arg_equality`.
    pub class: String,
    /// The preparation's expectation for this case, not the worker's.
    pub expected_permit: bool,
    pub permitted: bool,
    pub refused_by: Option<DryRunEnforcer>,
    pub refusal_code: Option<u32>,
    /// Local state was identical before and after the call.
    pub state_unchanged: bool,
    /// Recomputed by the coordinator: the outcome equals the expectation, and a refusal is the
    /// error its class predicts, raised by the contract that owns that error, with state
    /// unchanged. The worker's own verdict is necessary, never sufficient.
    pub agree: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunControlResult {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunStatefulResult {
    pub max_calls: u32,
    pub successful_calls: u32,
    pub passed: bool,
}

/// Whether the executed evidence meets the permit/deny bar: the original call permitted, and
/// enough derived denials reverted in executed Wasm. Counted only from layers that passed.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunAcceptance {
    /// Fewest derived denials one executed layer must revert.
    pub required_reverted_denials: usize,
    /// At least one layer executed, and every executed layer passed and permitted the original.
    pub original_permitted: bool,
    /// One entry per layer this run executed, in layer order.
    pub executed_layers: Vec<DryRunLayerAcceptance>,
    /// The reference layer passed, `original_permitted` holds, and one executed layer
    /// reverted at least `required_reverted_denials` derived denials.
    pub meets_minimum: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunLayerAcceptance {
    pub layer: DryRunLayerId,
    pub status: DryRunLayerStatus,
    /// The layer passed and permitted its original call.
    pub original_permitted: bool,
    /// Derived denials this layer refused with the predicted error and unchanged state; zero
    /// unless the layer passed.
    pub reverted_denials: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunBinding {
    pub spec_hash: String,
    pub binding_set_hash: String,
    pub registry_snapshot_root: String,
    pub account_address: String,
    /// Registry-recognized spec identity, not a live code observation.
    pub account_code_hash: String,
    pub network_id: String,
    pub rule_index: usize,
    pub candidate_context_rule_id: u32,
    pub suite_hash: String,
    /// Exact contract-address → reproduced/recognized Wasm hash for every binding.
    /// This is not proof of the current contents of those deployed addresses.
    pub policy_code_hashes: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunOutput {
    pub schema: String,
    /// Canonical hash of the full typed request, including artifact claims and nonce.
    pub run_hash: String,
    pub binding: DryRunBinding,
    pub artifact_verification: VerifyOutput,
    /// Selected-rule reference evidence only, with explicit model gaps.
    pub reference_report: serde_json::Value,
    /// Synthetic ledger for each selected reference outcome, in the same order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_case_ledgers: Option<Vec<u32>>,
    /// Always the four named layers in their declared order.
    pub layers: Vec<DryRunLayer>,
    /// False until every required runtime layer is actually executed and checked.
    /// This is never an account-safety or transaction-authorization verdict.
    pub complete: bool,
    /// Filled only by a coordinator that executed layers; absent from a preparation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<DryRunAcceptance>,
    pub disclaimer: String,
}
