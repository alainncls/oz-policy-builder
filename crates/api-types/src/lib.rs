//! MCP wire contract (architecture §4.6, §4.11).
//!
//! This crate IS the interface: the MCP server's `Parameters<T>`/`Json<T>` types come
//! from here, so the generated JSON Schemas and the implementation cannot drift. Every
//! tool has structured input and output; every failure is a stable machine-readable
//! code. No domain logic lives here.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One list, four derivations: the enum, the published [`ErrorCode::ALL`] vocabulary, the
/// Serde/JSON-Schema spelling and [`ErrorCode::as_str`] all come from the arms below, so a
/// code cannot exist without appearing in the vocabulary a caller publishes or in the
/// round-trip test that walks it, and cannot be spelled one way on the wire and another in
/// `as_str`.
/// Before this was a macro, `as_str` was an exhaustive match the compiler kept honest while
/// `ALL` was a hand-written array nothing tied to the variants — and two codes were missing
/// from it, which silently narrowed the one test that iterates it.
macro_rules! error_codes {
    ($( $(#[$attr:meta])* $variant:ident => $wire:literal, )+) => {
        /// Stable machine-readable error codes surfaced to agents (architecture §4.6). Kept
        /// in one place so the whole toolkit shares one vocabulary; new codes are appended,
        /// never renumbered.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[non_exhaustive]
        pub enum ErrorCode {
            $(
                $(#[$attr])*
                // The literal, not a transliteration of the identifier: with `rename_all`,
                // Serde and the schema derived the spelling from the Rust name while
                // `as_str` read it from here, so a variant whose name does not transliterate
                // to its intended code could disagree with itself.
                #[serde(rename = $wire)]
                #[schemars(rename = $wire)]
                $variant,
            )+
        }

        impl ErrorCode {
            /// Complete stable-code vocabulary — every variant, by construction. Tests
            /// serialize every entry; callers can publish it without maintaining a second
            /// list.
            pub const ALL: &'static [Self] = &[$( Self::$variant, )+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }
        }
    };
}

error_codes! {
    // recorder
    ETxNotFound => "E_TX_NOT_FOUND",
    ERetentionExpired => "E_RETENTION_EXPIRED",
    EEnvelopeParse => "E_ENVELOPE_PARSE",
    EUnsupportedEnvelope => "E_UNSUPPORTED_ENVELOPE",
    ENoSorobanOp => "E_NO_SOROBAN_OP",
    EOperationSelection => "E_OPERATION_SELECTION",
    ETxFailed => "E_TX_FAILED",
    EUnsupportedMetaVersion => "E_UNSUPPORTED_META_VERSION",
    EMetaParse => "E_META_PARSE",
    EResultMismatch => "E_RESULT_MISMATCH",
    EUnsupportedAddress => "E_UNSUPPORTED_ADDRESS",
    EAuthParse => "E_AUTH_PARSE",
    EImportParse => "E_IMPORT_PARSE",
    EResourceLimit => "E_RESOURCE_LIMIT",
    // synthesizer
    ENoEvidence => "E_NO_EVIDENCE",
    EEvidenceTrust => "E_EVIDENCE_TRUST",
    /// A supplied recording's decoded views are not what the recorder derives from its
    /// own raw evidence (or its schema/version is not current).
    EEvidenceIncoherent => "E_EVIDENCE_INCOHERENT",
    ENetworkMismatch => "E_NETWORK_MISMATCH",
    EAuthorizerNotFound => "E_AUTHORIZER_NOT_FOUND",
    EUnsupportedPattern => "E_UNSUPPORTED_PATTERN",
    EAmbiguousArgSemantics => "E_AMBIGUOUS_ARG_SEMANTICS",
    EUnregisteredPolicy => "E_UNREGISTERED_POLICY",
    ENeedsDecision => "E_NEEDS_DECISION",
    // spec / codegen
    ESpecInvalid => "E_SPEC_INVALID",
    ECodegen => "E_CODEGEN",
    EBuildFailed => "E_BUILD_FAILED",
    EBuildTimeout => "E_BUILD_TIMEOUT",
    EBuildResourceLimit => "E_BUILD_RESOURCE_LIMIT",
    /// The builder could not be started or configured at all — a misconfigured
    /// `stellar` binary path, an unusable build cache, a rejected operator setting.
    /// Distinct from `EBuildFailed` so an operator fault is never reported to an agent
    /// as "your spec does not compile".
    EBuildUnavailable => "E_BUILD_UNAVAILABLE",
    /// Every build slot on a hosted server is in use. Retryable by design: the same request
    /// can succeed once a running build finishes.
    EBuildBusy => "E_BUILD_BUSY",
    /// The caller cancelled the request (or its session ended) and the server stopped the
    /// work: a build was terminated or a read stopped before its next RPC call. MCP sends the
    /// cancelling client no response, so this is the outcome's name, not a wire answer to it.
    ECancelled => "E_CANCELLED",
    // registry
    ERegistrySignature => "E_REGISTRY_SIGNATURE",
    ERegistryRollback => "E_REGISTRY_ROLLBACK",
    ERegistryNetwork => "E_REGISTRY_NETWORK",
    ERegistryExpired => "E_REGISTRY_EXPIRED",
    ERegistryValidity => "E_REGISTRY_VALIDITY",
    ERegistryTransparency => "E_REGISTRY_TRANSPARENCY",
    ERegistryRevoked => "E_REGISTRY_REVOKED",
    EIncompatibleAccount => "E_INCOMPATIBLE_ACCOUNT",
    EUnregisteredVerifier => "E_UNREGISTERED_VERIFIER",
    ETargetAdapterUnsupported => "E_TARGET_ADAPTER_UNSUPPORTED",
    EUnregisteredTemplate => "E_UNREGISTERED_TEMPLATE",
    ERegistryEmpty => "E_REGISTRY_EMPTY",
    // policy recognition / authority surface
    EPolicyBindingInvalid => "E_POLICY_BINDING_INVALID",
    EAccountRuleEnumerationUnsupported => "E_ACCOUNT_RULE_ENUMERATION_UNSUPPORTED",
    EIncompleteAccountState => "E_INCOMPLETE_ACCOUNT_STATE",
    EUnsafeCallSurface => "E_UNSAFE_CALL_SURFACE",
    EUnsafeManagementSurface => "E_UNSAFE_MANAGEMENT_SURFACE",
    /// A rule that can change the account has a shape the authority check cannot describe
    /// (a policy-guarded owner rule, a nested-account signer, an unrecognized verifier).
    EUnsupportedAuthority => "E_UNSUPPORTED_AUTHORITY",
    /// A restricted (delegate) key can already change the account on its own.
    EDelegateHasAuthority => "E_DELEGATE_HAS_AUTHORITY",
    /// A restricted key already has another usable rule on the new rule's target, so a
    /// stateful limit would not hold.
    EDelegateGrantOverlap => "E_DELEGATE_GRANT_OVERLAP",
    EScanBudgetExceeded => "E_SCAN_BUDGET_EXCEEDED",
    // target capture
    /// The record-mode simulation of a supported capture failed: the target refused the call
    /// (for example an insufficient balance or a missing recipient), or the endpoint's
    /// simulator failed, which its withheld text cannot distinguish. Not a transport fault.
    ETargetRefused => "E_TARGET_REFUSED",
    /// The captured call's state is archived: a restoration preamble, a simulation that restored
    /// archived entries, or a footprint entry archived or expiring at the captured ledger.
    /// Capture never performs a restoration.
    ETargetArchived => "E_TARGET_ARCHIVED",
    // rpc / transport
    ERpc => "E_RPC",
    // catch-all internal
    EInternal => "E_INTERNAL",
}

/// Uniform structured error returned by every tool on failure.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    /// Present when a tool fails with several findings (e.g. spec validation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ToolError {
            code,
            message: message.into(),
            details: vec![],
        }
    }
    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        for d in &self.details {
            write!(f, "\n  - {d}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ToolError {}

// ---------------------------------------------------------------------------------------
// Tool inputs/outputs. Domain artifacts (RecordingBundle, PolicySpec, …) are carried as
// JSON values so this wire crate stays free of domain dependencies; the server
// (de)serializes them against the real types.
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordTransactionInput {
    /// Transaction hash (64 hex chars).
    pub tx_hash: String,
    /// Name of an RPC source the server's operator configured. Omit both this and `rpc_url`
    /// when the server has exactly one source: it is used.
    #[serde(default)]
    pub rpc_source: Option<String>,
    /// Another RPC endpoint URL instead of a configured source; requires
    /// `network_passphrase`. On the hosted service this must be an allowlisted endpoint.
    #[serde(default)]
    pub rpc_url: Option<String>,
    /// Network passphrase (e.g. "Test SDF Network ; September 2015"). Taken from the source
    /// when one is used; if given as well, it must be that source's network.
    #[serde(default)]
    pub network_passphrase: Option<String>,
    #[serde(default)]
    pub operation_index: Option<u32>,
    #[serde(default)]
    pub allow_failed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordSimulationInput {
    /// Unsigned transaction envelope, base64 XDR. Confidential input (§6.5).
    pub envelope_xdr_base64: String,
    /// As for `record_transaction`: a configured source by name, or the only one when omitted.
    #[serde(default)]
    pub rpc_source: Option<String>,
    /// As for `record_transaction`: another endpoint, with `network_passphrase`.
    #[serde(default)]
    pub rpc_url: Option<String>,
    #[serde(default)]
    pub network_passphrase: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecordOutput {
    /// The RecordingBundle as JSON.
    pub bundle: serde_json::Value,
    /// Full recording hash (hex).
    pub recording_hash: String,
    pub trust: String,
    /// Human-readable notes (e.g. unattributed events).
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SynthesizeInput {
    /// One or more RecordingBundles as JSON.
    pub bundles: Vec<serde_json::Value>,
    /// The selected smart-account authorizer (strkey).
    ///
    /// Omit it and synthesis derives it from the recordings, but only when they leave no
    /// choice to make: exactly one authorizing address that runs observed Wasm. Two such
    /// addresses is a decision about whose account is being constrained, and a caller who
    /// did not state it has not made it — so that is an error naming the candidates rather
    /// than a pick.
    #[serde(default)]
    pub selected_authorizer: Option<String>,
    /// The account compatibility record as JSON (SmartAccountRecord).
    ///
    /// Omit it and synthesis builds it from the same recordings: the address is the selected
    /// authorizer and the code hash is the one observed for it. Nothing is invented — an
    /// account whose code the recordings never observed is still `E_INCOMPATIBLE_ACCOUNT`.
    #[serde(default)]
    pub account: Option<serde_json::Value>,
    /// Signed capability-registry snapshot. Its signature, network, validity window, and
    /// rollback version are verified against the server/CLI-configured trusted root; the
    /// request cannot select its own trust root.
    ///
    /// Omit it to use the snapshot the operator configured. Supplying one is still allowed and
    /// still verified against the configured root — a request can bring a newer snapshot, never
    /// a different root.
    #[serde(default)]
    pub signed_registry_snapshot: Option<serde_json::Value>,
    /// The user decisions (UserDecisions) as JSON.
    ///
    /// Required, and deliberately: the signer set, the lifetime and the call cap are what the
    /// grant *is*. A default here would mean the toolkit chose how much authority to hand out.
    pub decisions: serde_json::Value,
    /// Reviewed spending-limit wasm hash (hex), if composing it.
    ///
    /// [`PINNED_SPENDING_LIMIT`] selects the pinned reviewed policy by name instead of by 64
    /// hex characters. It stays an opt-in rather than becoming a default: composing a reviewed
    /// third-party contract into a grant is a decision, and the tool should not make it because
    /// a spending limit appeared in the decisions.
    #[serde(default)]
    pub spending_limit_capability: Option<String>,
    /// Audited template pack to render from. Defaults to [`DEFAULT_TEMPLATE_FAMILY`], the only
    /// family this milestone registers.
    #[serde(default = "default_template_family")]
    pub template_family: String,
}

/// The one template family registered in this milestone.
pub const DEFAULT_TEMPLATE_FAMILY: &str = "policy-templates/scope@1";

/// Accepted in place of a hex hash in [`SynthesizeInput::spending_limit_capability`] to select
/// the pinned reviewed spending-limit policy.
pub const PINNED_SPENDING_LIMIT: &str = "pinned";

fn default_template_family() -> String {
    DEFAULT_TEMPLATE_FAMILY.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SynthesizeOutput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    /// Canonical spec hash (hex).
    pub spec_hash: String,
    /// Per-constraint reasoning for display.
    pub rationale: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluateSpecInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    /// The evaluation context (EvalContext) as JSON.
    pub context: serde_json::Value,
    /// The candidate invocation (Invocation) as JSON.
    pub invocation: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EvaluateSpecOutput {
    /// "permit", "deny", or "indeterminate". The last verdict is fail-closed: at least one
    /// composed reviewed policy is outside the Phase 1 evaluator's model.
    pub verdict: String,
    /// Present on deny or indeterminate: the machine-readable reason. The wire name is retained
    /// for compatibility even though an indeterminate reason is not a denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateCodeInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    pub rule_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GenerateCodeOutput {
    pub crate_name: String,
    /// Relative path → file contents (Cargo.toml, src/lib.rs, src/contract.rs, …).
    pub files: std::collections::BTreeMap<String, String>,
    /// Pre-build normalized codegen input hash (hex). NOT the wasm hash (§4.10).
    pub normalized_input_hash: String,
    /// Pinned build inputs recorded for the BuildManifest.
    pub soroban_sdk_version: String,
    pub stellar_accounts_version: String,
    /// Built Wasm bytes. This is base64 to keep the JSON/MCP artifact self-contained.
    pub wasm_base64: String,
    pub wasm_hash: String,
    /// BuildManifest binding the spec/codegen/source/lock/toolchain/Wasm artifact chain.
    pub build_manifest: serde_json::Value,
    pub build_manifest_hash: String,
}

// --- import_recording ------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportRecordingInput {
    pub network_passphrase: String,
    /// Raw transaction envelope, base64 XDR.
    pub envelope_xdr_base64: String,
    #[serde(default)]
    pub result_meta_xdr_base64: Option<String>,
    /// Raw `TransactionResult` XDR; checked against `successful` when recording. Without
    /// it the import is labeled `incomplete` and cannot drive synthesis.
    #[serde(default)]
    pub result_xdr_base64: Option<String>,
    #[serde(default)]
    pub ledger: Option<u32>,
    #[serde(default)]
    pub created_at_unix: Option<i64>,
    /// Supplier claim that the transaction succeeded (verified against
    /// `result_xdr_base64` when recording).
    pub successful: bool,
}

#[cfg(test)]
pub(crate) mod test_support;

/// Wire types for evaluation, verification, live checks, and install intent.
pub mod policy_operations;
pub use policy_operations::*;
mod install_assembly;
pub use install_assembly::*;
pub mod dry_run;
pub use dry_run::*;
pub mod target_capture;
pub use target_capture::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::no_build_settings_on_the_wire;

    /// `ALL` is generated from the same arms as the enum and `as_str`, so walking it walks
    /// every declared code — which is what makes this table exhaustive rather than
    /// exhaustive-looking. A count assertion is deliberately absent: it would pass a
    /// substitution and only catch a deletion.
    #[test]
    fn error_codes_round_trip() {
        let mut serialized = std::collections::BTreeSet::new();
        for &code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert!(serialized.insert(json.clone()), "duplicate code {code:?}");
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
        // The two codes whose absence from a hand-written ALL is what motivated generating
        // it; named explicitly so a regression is a failing assertion, not a silent gap.
        for code in [ErrorCode::EResultMismatch, ErrorCode::EEvidenceIncoherent] {
            assert!(
                ErrorCode::ALL.contains(&code),
                "{code:?} must be part of the published vocabulary"
            );
        }
    }

    /// The wire spelling has three consumers — `as_str`, Serde, and the JSON Schema an agent
    /// reads — and a code is only stable if all three agree. Serde equality is asserted above;
    /// this asserts the schema's enumeration is exactly the vocabulary, so a variant whose
    /// Rust identifier does not transliterate to its intended code cannot slip through with a
    /// correct `as_str` and a wrong schema.
    #[test]
    fn the_published_schema_enumerates_exactly_the_vocabulary() {
        let schema = serde_json::to_value(schemars::schema_for!(ErrorCode))
            .expect("the error-code schema must serialize");
        // Documented variants become their own `const` branch rather than joining the flat
        // `enum`, so gather from wherever the generator put them: the property is the set of
        // codes a client can see, not the shape it is expressed in.
        fn collect(value: &serde_json::Value, found: &mut std::collections::BTreeSet<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        match (key.as_str(), child) {
                            ("const", serde_json::Value::String(code)) => {
                                found.insert(code.clone());
                            }
                            ("enum", serde_json::Value::Array(codes)) => {
                                found.extend(
                                    codes.iter().filter_map(|c| c.as_str().map(str::to_string)),
                                );
                            }
                            _ => collect(child, found),
                        }
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        collect(item, found);
                    }
                }
                _ => {}
            }
        }
        let mut listed = std::collections::BTreeSet::new();
        collect(&schema, &mut listed);
        assert!(
            !listed.is_empty(),
            "the schema must enumerate its codes somewhere: {schema}"
        );
        let expected: std::collections::BTreeSet<String> = ErrorCode::ALL
            .iter()
            .map(|code| code.as_str().to_string())
            .collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn tool_error_displays_with_details() {
        let e = ToolError::new(ErrorCode::ESpecInvalid, "spec invalid")
            .with_details(vec!["rule 0: no signers".into()]);
        let s = format!("{e}");
        assert!(s.contains("E_SPEC_INVALID"));
        assert!(s.contains("rule 0"));
    }

    #[test]
    fn the_wire_contract_carries_no_build_configuration() {
        no_build_settings_on_the_wire(
            "GenerateCodeInput",
            schemars::schema_for!(GenerateCodeInput),
        );
    }

    #[test]
    fn dtos_have_schemas() {
        // schemars must be able to generate a schema for every input type (this is what
        // the MCP server exposes; if it panics, the wire contract is broken).
        let _ = schemars::schema_for!(RecordTransactionInput);
        let _ = schemars::schema_for!(RecordSimulationInput);
        let _ = schemars::schema_for!(RecordOutput);
        let _ = schemars::schema_for!(SynthesizeInput);
        let _ = schemars::schema_for!(SynthesizeOutput);
        let _ = schemars::schema_for!(EvaluateSpecInput);
        let _ = schemars::schema_for!(EvaluateSpecOutput);
        let _ = schemars::schema_for!(GenerateCodeInput);
        let _ = schemars::schema_for!(GenerateCodeOutput);
        let _ = schemars::schema_for!(ImportRecordingInput);
    }

    #[test]
    fn request_dtos_reject_unknown_fields() {
        let value = serde_json::json!({
            "network_passphrase": "network",
            "tx_hash": "0".repeat(64),
            "rpc_url": "https://rpc.example",
            "unexpected": true
        });
        assert!(serde_json::from_value::<RecordTransactionInput>(value).is_err());
    }
}

mod installed_grant;
pub use installed_grant::*;
