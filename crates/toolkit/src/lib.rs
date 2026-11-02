//! Toolkit facade: turns the pure cores into the operations the MCP server and CLI
//! expose, translating domain results into the `api-types` wire contract (stable error
//! codes, JSON-carried artifacts). This is a thin orchestration layer — no policy logic
//! lives here; it delegates to the cores and never reaches a network (acquisition is the
//! caller's job, keeping this crate pure and testable).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use base64::Engine;
use ozpb_api_types::ErrorCode as EC;
use ozpb_api_types::{
    EvaluateSpecInput, EvaluateSpecOutput, GenerateCodeInput, GenerateCodeOutput, RecordOutput,
    SynthesizeInput, SynthesizeOutput, ToolError,
};
use ozpb_codegen::{generate, Pins};
use ozpb_domain::Hash32;
use ozpb_evaluator::{evaluate, EvalContext, Invocation, Verdict};
use ozpb_policy_spec::{PolicyRef, PolicySpec, RuleSpec};
use ozpb_recorder_core::{
    record, EvidenceSnapshot, ObservedExecutable, RecordOptions, RecordingBundle,
};
use ozpb_registry::{Registry, RegistryCheckpoint, RegistryError, RootPolicy, SignedSnapshot};
use ozpb_synthesizer::{synthesize, SynthesisInput, UserDecisions};
use std::collections::BTreeMap;

mod verification;
pub use verification::{reference_suite, reference_suite_cases, verify_with_build_config};
mod dry_run;
pub use dry_run::prepare_dry_run_with_build_config;
mod authority_text;
pub mod dry_run_report;
#[cfg(test)]
mod dry_run_tests;
pub use authority_text::render_authority_text;
mod call_surface;
pub use call_surface::{
    check_observed_call_surface_with_build_config, CallSurfaceObservation, ObservedCallSurfaceCheck,
};
mod call_surface_live;
pub use call_surface_live::{
    finish_call_surface_check, plan_call_surface_read, resolve_rpc_source, rpc_sources_from_json,
    scan_tool_error, CallSurfaceReadPlan, RpcSource,
};
mod installed_grant;
pub use installed_grant::check_installed_grant_from_scan;
mod install_intent;
pub use install_intent::{plan_install_intent_read, prepare_install_intent_from_scan};
mod install_assembly;
pub use install_assembly::{install_assembly_output, install_assembly_request};
mod preflight;
pub use preflight::preflight_transaction_output;
mod target_capture;
pub use target_capture::{capture_target_output, resolve_capture_rpc_source};
mod policy_check;
pub use policy_check::{
    finish_policy_check, plan_policy_check_read, policy_check_unavailable, PolicyCheckReadPlan,
};

/// Build configuration, re-exported so the shells configure the builder through this facade
/// rather than depending on `ozpb-build-runner` directly. Operator-side only — the wire
/// contract carries no build settings (see [`ENV_BUILD_TIMEOUT_SECS`] and friends).
///
/// `Builder` is deliberately NOT re-exported: a facade consumer cannot name the hermetic stub,
/// which emits unattestable wasm. For the same reason the building tools have no
/// default-config convenience wrapper — every one of them takes an explicit `&BuildConfig`, so
/// a caller cannot silently bypass operator configuration by picking the shorter name.
pub use ozpb_build_runner::{
    BuildCancel, BuildConfig, BuildSlots, ENV_BUILD_CACHE_DIR, ENV_BUILD_JOBS,
    ENV_BUILD_TIMEOUT_SECS, ENV_BUILD_WORKER_LAUNCHER, ENV_STELLAR_BINARY,
};

/// The two names a shell needs to read an import document itself, re-exported for the same
/// reason as the build configuration above: reading a file is the shell's job — this crate
/// touches no I/O — but the ceiling it must stop at, and the refusal it reports on reaching it,
/// belong to the operation in this facade. Without these a shell would either depend on the
/// adapter directly or hand-write the bound and its error code.
///
/// `ImportedBundle` and `import_json` are deliberately not re-exported: importing *through* the
/// facade is [`import_recording`], and a second path to a snapshot is what that operation
/// exists to prevent.
pub use ozpb_source_bundle::{ImportError, MAX_IMPORT_JSON_BYTES};

#[derive(Clone, Debug)]
pub struct RegistryTrust {
    pub root_policy: RootPolicy,
    /// Persisted anti-rollback floor. Hosted deployments keep this in durable config/state;
    /// local callers pin it alongside the root key and signed snapshot.
    pub minimum_version: u64,
    pub checkpoint: Option<RegistryCheckpoint>,
    /// The signed snapshot to use when a request omits one. Verified against `root_policy`
    /// exactly like a request-supplied snapshot: configuring it decides *which* snapshot is the
    /// default, never whether it is checked.
    pub configured_snapshot: Option<serde_json::Value>,
}

/// The authorizing addresses in these recordings that run observed Wasm, each with the code
/// hash observed for it.
///
/// Both halves of the pair have to come from the recordings for a derived account record to be
/// worth anything. An authorizer with no observed executable is not a candidate: the toolkit
/// would have to fetch its code to say what it runs, and synthesis is pure. A built-in Stellar
/// Asset contract is not a candidate either — it has no Wasm hash, so no registry entry can
/// recognise it as an account implementation.
fn smart_account_candidates(bundles: &[RecordingBundle]) -> BTreeMap<String, Hash32> {
    let mut candidates = BTreeMap::new();
    for bundle in bundles {
        for authorization in &bundle.authorizations {
            let Some(observation) = bundle.contract_executables.get(&authorization.authorizer)
            else {
                continue;
            };
            if let ObservedExecutable::Wasm { code_hash } = observation.executable {
                candidates.insert(authorization.authorizer.clone(), code_hash);
            }
        }
    }
    candidates
}

/// Which account these recordings are about, when the caller did not say.
///
/// Only answered when the recordings leave nothing to choose. Two candidate accounts is a
/// decision about whose authority is being constrained, and picking one — the first, the
/// lexicographically smallest, the one in the newest bundle — would be the toolkit making that
/// decision quietly. So the error names them and stops.
fn derive_selected_authorizer(bundles: &[RecordingBundle]) -> Result<String, ToolError> {
    let candidates = smart_account_candidates(bundles);
    let mut addresses = candidates.keys();
    match (addresses.next(), addresses.next()) {
        (Some(only), None) => Ok(only.clone()),
        (None, _) => Err(ToolError::new(
            EC::EAuthorizerNotFound,
            "no authorization by a contract running observed Wasm in the supplied recordings, \
             so there is no account to synthesize for: pass `selected_authorizer` if the \
             recordings do carry one",
        )),
        (Some(first), Some(second)) => {
            let all: Vec<&str> = candidates.keys().map(String::as_str).collect();
            let _ = (first, second);
            Err(ToolError::new(
                EC::EAuthorizerNotFound,
                format!(
                    "the recordings carry {} authorizing accounts, so which one this policy is \
                     for is a decision rather than a lookup — pass `selected_authorizer`: {}",
                    all.len(),
                    all.join(", ")
                ),
            ))
        }
    }
}

/// Build the account record from the recordings themselves.
///
/// `registry_resolution` is left empty on purpose: synthesis overwrites it with the entry that
/// actually resolved, and a derived record must not arrive asserting a resolution nothing has
/// checked yet.
fn derive_account_record(
    bundles: &[RecordingBundle],
    selected_authorizer: &str,
) -> Result<ozpb_policy_spec::SmartAccountRecord, ToolError> {
    let candidates = smart_account_candidates(bundles);
    let observed_code_hash = candidates
        .get(selected_authorizer)
        .copied()
        .ok_or_else(|| {
            // `E_INCOMPATIBLE_ACCOUNT`, not `E_AUTHORIZER_NOT_FOUND`: the caller named an
            // account and it is present, so the authorizer was found. What cannot be
            // established is what code it runs — the same thing `registry.resolve_account`
            // reports when the explicit path hands over a code hash no entry recognises. One
            // question, one code, whichever way the record arrived.
            ToolError::new(
                EC::EIncompatibleAccount,
                format!(
                    "the recordings observed no Wasm code hash for {selected_authorizer}, so \
                 what it runs is unknown and no registry entry can recognise it: pass \
                 `account` explicitly if you have the observation"
                ),
            )
        })?;
    Ok(ozpb_policy_spec::SmartAccountRecord {
        address: selected_authorizer.to_string(),
        observed_code_hash,
        registry_resolution: String::new(),
    })
}

/// Turn an acquired evidence snapshot into a RecordingBundle output. Acquisition (RPC or
/// import) happens in the shell; this stays pure.
pub fn record_snapshot(
    snapshot: &EvidenceSnapshot,
    options: RecordOptions,
) -> Result<RecordOutput, ToolError> {
    let bundle = record(snapshot, options).map_err(|e| map_record_err(&e))?;
    let recording_hash = bundle
        .recording_hash()
        .map_err(|e| ToolError::new(EC::EInternal, e.to_string()))?;
    Ok(RecordOutput {
        trust: bundle.trust.as_str().to_string(),
        notes: bundle.evidence_notes.clone(),
        recording_hash: recording_hash.to_hex(),
        bundle: to_value(&bundle)?,
    })
}

/// Import a raw-XDR evidence bundle and record it, as one operation.
///
/// The halves are not separable by a caller on purpose. `import_json` parses the document and
/// labels it for what its transaction result proves, but only [`record`] decodes the envelope
/// and result meta the document *names* — so a caller that stopped after parsing would report
/// a successful import of evidence that cannot be recorded at all. Both shells import through
/// here, so neither can forget the second half or perform it in the wrong order.
///
/// Errors keep the code of the stage that produced them — import codes for the document,
/// recorder codes for the evidence it named — instead of being flattened into one import
/// failure that tells an agent nothing about which half to fix.
pub fn import_recording(json: &str, options: RecordOptions) -> Result<RecordOutput, ToolError> {
    let snapshot = ozpb_source_bundle::import_json(json).map_err(|e| map_import_err(&e))?;
    record_snapshot(&snapshot, options)
}

pub fn synthesize_policy(
    input: &SynthesizeInput,
    registry_trust: &RegistryTrust,
) -> Result<SynthesizeOutput, ToolError> {
    let mut bundles: Vec<RecordingBundle> = input
        .bundles
        .iter()
        .map(from_value)
        .collect::<Result<_, _>>()?;
    if bundles.is_empty() {
        return Err(ToolError::new(
            EC::ENoEvidence,
            "no recording bundles supplied",
        ));
    }
    // JSON supplied to this boundary is caller-controlled, even when it was originally emitted
    // by `record_snapshot`. Two consequences, handled in order:
    //
    // 1. Every decoded view must be re-derived from the bundle's own raw evidence before it
    //    can drive synthesis — a serialized bundle's identity (its hash) proves nothing about
    //    raw/decoded coherence.
    // 2. A serialized `rpc_reported` / `trusted_indexer` label is descriptive provenance, not
    //    an authenticated receipt. Weaken it to `self_supplied`; a future hosted acquisition
    //    service may add a separately verified receipt instead. The weakening only ever
    //    lowers a label — `incomplete` evidence stays `incomplete`, because a bundle that
    //    was missing evidence when it was recorded is still missing it here.
    //
    // Wire trust remains an acquisition claim, so this boundary caps it at self_supplied.
    // V2 also rechecks execution against preserved transaction-result XDR and refuses
    // executed evidence without that XDR unless its label remains incomplete.
    // Internal coherence still does not prove ledger inclusion.
    for (index, bundle) in bundles.iter().enumerate() {
        bundle.verify().map_err(|error| {
            let mapped = map_record_err(&error);
            ToolError::new(
                mapped.code,
                format!("recording bundle {index}: {}", mapped.message),
            )
        })?;
    }
    for bundle in &mut bundles {
        bundle.trust = bundle.trust.downgraded_to_self_supplied();
    }
    let selected_authorizer = match &input.selected_authorizer {
        Some(address) => address.clone(),
        None => derive_selected_authorizer(&bundles)?,
    };
    let mut account: ozpb_policy_spec::SmartAccountRecord = match &input.account {
        Some(value) => from_value(value)?,
        None => derive_account_record(&bundles, &selected_authorizer)?,
    };
    let decisions: UserDecisions = from_value(&input.decisions)?;
    let snapshot_value = input
        .signed_registry_snapshot
        .as_ref()
        .or(registry_trust.configured_snapshot.as_ref())
        .ok_or_else(|| {
            ToolError::new(
                EC::ERegistryEmpty,
                "no signed registry snapshot: supply `signed_registry_snapshot`, or configure \
                 one for this deployment",
            )
        })?;
    let signed_registry: SignedSnapshot = from_value(snapshot_value)?;
    let network = bundles[0].network_id;
    let mut registry = match registry_trust.checkpoint.clone() {
        Some(checkpoint) => Registry::with_pinned_roots_for_network_at_checkpoint(
            registry_trust.root_policy.clone(),
            network,
            checkpoint,
        ),
        None => Registry::with_pinned_roots_for_network_at_version(
            registry_trust.root_policy.clone(),
            network,
            registry_trust.minimum_version,
        ),
    }
    .map_err(map_registry_err)?;
    let registry_snapshot = registry.load(&signed_registry).map_err(map_registry_err)?;

    let account_capability = registry
        .resolve_account(&account.observed_code_hash)
        .map_err(map_registry_err)?;
    account.registry_resolution = format!(
        "{} (registry entry {})",
        account_capability.release,
        account.observed_code_hash.to_hex()
    );

    let template = registry
        .resolve_template(&input.template_family)
        .map_err(map_registry_err)?;
    let template_capability_schema = template.capability_schema;
    let declared_constraint_kinds = &template.constraint_kinds;
    let declared_signer_predicates = &template.signer_predicates;
    let spending_limit_capability = match &input.spending_limit_capability {
        Some(h) => {
            // `pinned` names the reviewed policy this milestone pins, so a caller opts in
            // without transcribing 64 hex characters. It resolves to a hash and then takes the
            // identical registry path: naming it shorter must not mean checking it less.
            let hash = if h == ozpb_api_types::PINNED_SPENDING_LIMIT {
                ozpb_domain::pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM
            } else {
                parse_hash(h)?
            };
            let capability = registry.resolve_policy(&hash).map_err(map_registry_err)?;
            if capability.kind != "oz:spending_limit" {
                return Err(ToolError::new(
                    EC::EUnregisteredPolicy,
                    format!(
                        "policy {} is registered as '{}', not oz:spending_limit",
                        hash.to_hex(),
                        capability.kind
                    ),
                ));
            }
            Some(hash)
        }
        None => None,
    };

    let mut adapters = BTreeMap::new();
    for bundle in &bundles {
        let mut pending: Vec<_> = bundle
            .authorizations
            .iter()
            .filter(|auth| auth.authorizer == selected_authorizer)
            .map(|auth| &auth.root)
            .collect();
        while let Some(node) = pending.pop() {
            pending.extend(&node.sub_invocations);
            let ozpb_recorder_core::AuthorizedCall::Contract { contract, .. } = &node.call else {
                continue;
            };
            let Some(observation) = bundle.contract_executables.get(contract) else {
                continue;
            };
            if let ObservedExecutable::Wasm { code_hash } = observation.executable {
                if let Some(semantics) = registry
                    .resolve_target_adapter(&code_hash)
                    .map_err(map_registry_err)?
                {
                    adapters.insert(
                        code_hash,
                        ozpb_synthesizer::adapters::Adapter::from_semantics(code_hash, semantics),
                    );
                }
            }
        }
    }
    let syn_input = SynthesisInput {
        bundles,
        selected_authorizer: selected_authorizer.clone(),
        account,
        registry_snapshot,
        spending_limit_capability,
        template_family: input.template_family.clone(),
        template_capability_schema,
        // The signature binds the governance assertion to this exact observed code hash.
        // Recording observations remain self-supplied, not chain attestations.
        adapters: adapters.into_values().collect(),
    };

    let out = synthesize(&syn_input, &decisions).map_err(map_synth_errs)?;
    within_declared_capabilities(
        out.spec.rules.iter().enumerate(),
        &input.template_family,
        declared_constraint_kinds,
        declared_signer_predicates,
    )?;
    // Validate immediately: the wire always carries a spec that passed validation.
    let validated = out
        .spec
        .clone()
        .validate()
        .map_err(|errs| spec_error(&errs))?;
    Ok(SynthesizeOutput {
        spec: to_value(&out.spec)?,
        spec_hash: validated.hash().to_hex(),
        rationale: out.rationale,
    })
}

/// Parse a pinned ed25519 registry root from configuration. This is deliberately separate
/// from `SynthesizeInput`: a request must never be able to choose the key that authenticates
/// its own registry snapshot.
pub fn parse_registry_root_hex(value: &str) -> Result<[u8; 32], ToolError> {
    hex::decode(value)
        .map_err(|_| ToolError::new(EC::ERegistrySignature, "registry root is not valid hex"))?
        .try_into()
        .map_err(|_| {
            ToolError::new(
                EC::ERegistrySignature,
                "registry root must be exactly 32 bytes",
            )
        })
}

pub fn registry_trust_from_config(
    root_hex: &str,
    minimum_version: u64,
) -> Result<RegistryTrust, ToolError> {
    Ok(RegistryTrust {
        root_policy: RootPolicy {
            threshold: 1,
            keys: std::collections::BTreeMap::from([(
                "legacy".to_string(),
                parse_registry_root_hex(root_hex)?,
            )]),
        },
        minimum_version,
        checkpoint: None,
        configured_snapshot: None,
    })
}

/// Parse a production threshold-root policy from JSON:
/// `{ "threshold": 2, "keys": { "ops-a": "<32-byte hex>", ... } }`.
pub fn registry_trust_from_roots_json(
    roots_json: &str,
    minimum_version: u64,
) -> Result<RegistryTrust, ToolError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RootConfig {
        threshold: u32,
        keys: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        checkpoint: Option<RegistryCheckpoint>,
    }
    let config: RootConfig = serde_json::from_str(roots_json).map_err(|error| {
        ToolError::new(
            EC::ERegistrySignature,
            format!("invalid registry roots JSON: {error}"),
        )
    })?;
    let keys = config
        .keys
        .into_iter()
        .map(|(id, encoded)| parse_registry_root_hex(&encoded).map(|key| (id, key)))
        .collect::<Result<_, _>>()?;
    let root_policy = RootPolicy {
        threshold: config.threshold,
        keys,
    };
    Registry::with_pinned_roots(root_policy.clone()).map_err(map_registry_err)?;
    if config
        .checkpoint
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.version < minimum_version)
    {
        return Err(ToolError::new(
            EC::ERegistryRollback,
            "registry checkpoint is older than the configured minimum version",
        ));
    }
    Ok(RegistryTrust {
        root_policy,
        minimum_version,
        checkpoint: config.checkpoint,
        configured_snapshot: None,
    })
}

pub fn evaluate_spec(input: &EvaluateSpecInput) -> Result<EvaluateSpecOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errs| spec_error(&errs))?;
    let context: EvalContext = from_value(&input.context)?;
    let invocation: Invocation = from_value(&input.invocation)?;
    Ok(match evaluate(&validated, &context, &invocation) {
        Verdict::Permit => EvaluateSpecOutput {
            verdict: "permit".to_string(),
            deny_reason: None,
        },
        Verdict::Deny(reason) => EvaluateSpecOutput {
            verdict: "deny".to_string(),
            deny_reason: Some(format!("{reason:?}")),
        },
        Verdict::Indeterminate(reason) => EvaluateSpecOutput {
            verdict: "indeterminate".to_string(),
            deny_reason: Some(format!("{reason:?}")),
        },
    })
}

pub fn generate_code_with_build_config(
    input: &GenerateCodeInput,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<GenerateCodeOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    // A serialized spec is caller-controlled text, and this is the boundary that seals its
    // claims into the hashed BuildManifest chain. `self_supplied` is the only label a wire
    // spec can carry legitimately, and each departure is refused for its own reason: a
    // stronger label (rpc_reported, trusted_indexer) is an acquisition claim this boundary
    // cannot authenticate — and none this toolkit emitted, because `synthesize_policy`
    // downgrades bundle trust for the same reason — while `incomplete` marks evidence the
    // recorder ruled out of synthesis, so no legitimate pipeline produced a spec citing it.
    // Refuse rather than downgrade: silently rewriting the label would change the spec hash
    // the caller reviewed.
    for (index, recording) in spec.evidence.recordings.iter().enumerate() {
        if recording.trust == ozpb_domain::TrustLevel::self_supplied() {
            continue;
        }
        let reason = if recording.trust == ozpb_domain::TrustLevel::incomplete() {
            format!(
                "evidence.recordings[{index}] is labelled 'incomplete'; evidence the \
                 recorder ruled out of synthesis cannot justify a build"
            )
        } else {
            format!(
                "evidence.recordings[{index}] claims acquisition trust '{}' across the \
                 JSON tool boundary; a supplied spec cannot authenticate acquisition \
                 context, so only 'self_supplied' can be sealed into a build",
                recording.trust.as_str()
            )
        };
        return Err(ToolError::new(EC::ESpecInvalid, reason));
    }
    let validated = spec.validate().map_err(|errs| spec_error(&errs))?;
    let pins = Pins::default();
    let g = generate(&validated, input.rule_index, &pins)
        .map_err(|e| ToolError::new(EC::ECodegen, e.to_string()))?;
    let rule = validated
        .spec()
        .rules
        .get(input.rule_index)
        .ok_or_else(|| ToolError::new(EC::ECodegen, "rule index out of range"))?;
    let template_family = rule
        .policies
        .iter()
        .find_map(|policy| match policy {
            PolicyRef::Generated {
                template_family, ..
            } => Some(template_family.as_str()),
            PolicyRef::Reviewed { .. } => None,
        })
        .ok_or_else(|| ToolError::new(EC::ECodegen, "rule has no generated policy"))?;
    let artifact = ozpb_build_runner::build(
        &ozpb_build_runner::BuildRequest {
            generated: &g,
            spec_hash: validated.hash(),
            registry_snapshot: validated.spec().registry_snapshot,
            rule_index: input.rule_index,
            template_family,
            pins: &pins,
        },
        build_config,
    )
    .map_err(map_build_err)?;
    Ok(GenerateCodeOutput {
        crate_name: g.crate_name,
        files: g.files,
        normalized_input_hash: g.normalized_input_hash.to_hex(),
        soroban_sdk_version: pins.soroban_sdk,
        stellar_accounts_version: pins.stellar_accounts,
        wasm_base64: base64::engine::general_purpose::STANDARD.encode(&artifact.wasm),
        wasm_hash: artifact.manifest.wasm_hash.to_hex(),
        build_manifest: to_value(&artifact.manifest)?,
        build_manifest_hash: artifact.manifest_hash.to_hex(),
    })
}

#[cfg(test)]
pub(crate) mod test_support;

// --- helpers ---------------------------------------------------------------------------

fn to_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::new(EC::EInternal, e.to_string()))
}

fn from_value<T: serde::de::DeserializeOwned>(v: &serde_json::Value) -> Result<T, ToolError> {
    serde_json::from_value(v.clone())
        .map_err(|e| ToolError::new(EC::ESpecInvalid, format!("malformed input JSON: {e}")))
}

fn parse_hash(hex: &str) -> Result<Hash32, ToolError> {
    Hash32::from_hex(hex).map_err(|e| ToolError::new(EC::ESpecInvalid, e.to_string()))
}

fn spec_error(errs: &[ozpb_policy_spec::SpecError]) -> ToolError {
    ToolError::new(EC::ESpecInvalid, "PolicySpec failed validation")
        .with_details(errs.iter().map(|e| e.to_string()).collect())
}

/// Refuse rules that use constraints or predicates the resolved template does not declare.
///
/// The registry entry for a template family records which predicate and constraint kinds a
/// reviewed instantiation implements. Until now nothing read those lists: they were an
/// assertion inside a signed document that no code checked, so the snapshot could describe a
/// vocabulary narrower or wider than the template's without any gate noticing — which is how
/// two entries came to name things that are not constraints or predicates at all.
///
/// Against the dev snapshot this repository ships it cannot fire, because that entry declares
/// both types' full vocabularies and synthesis emits nothing outside them. That is a property
/// of the shipped fixture, not of this function: `signed_registry_snapshot` is a caller input,
/// so any narrower production entry can refuse here — which is what the check is for. Its
/// standing job is to be the tripwire when a new `Constraint` variant, or the first
/// adapter-derived constraint, reaches a spec before the reviewed template claims to implement
/// it. `Constraint::kind_name` is generated from the same exhaustive list as `Constraint::KINDS`,
/// so the variant is a compile error in `ozpb-policy-spec` rather than a silent admission here.
///
/// Two things it does NOT cover, so the guarantee is not read wider than it is. `rule.state`
/// carries `StateSpec`, for which `TemplateCapability` declares no vocabulary at all — adding
/// one is a snapshot-shape change, and until then removing the (mis-filed)
/// `call_count_per_installation` entry left state capabilities undeclared rather than
/// unchecked, since nothing checked them before either. And `generate_code` / `verify` take a
/// caller-supplied spec and are handed no snapshot, so neither can run this; closing that path
/// means making the snapshot a required input to those operations, which breaks the wire
/// contract and, for `verify`, belongs to a later milestone regardless.
fn within_declared_capabilities<'a>(
    rules: impl IntoIterator<Item = (usize, &'a RuleSpec)>,
    resolved_family: &str,
    declared_constraint_kinds: &[String],
    declared_signer_predicates: &[String],
) -> Result<(), ToolError> {
    let mut undeclared: Vec<String> = Vec::new();
    for (rule_index, rule) in rules {
        let predicate = rule.authorization.kind.kind_name();
        if !declared_signer_predicates.iter().any(|d| d == predicate) {
            undeclared.push(format!(
                "rules[{rule_index:02}] signer predicate '{predicate}'"
            ));
        }
        // The tuple index, not just the function name: `allowed_calls` is a disjunction of
        // complete tuples, so one rule can hold several entries for the same function, and a
        // detail naming only the function would collapse two distinct offending tuples into
        // one line under the dedup below. Both indexes are zero-padded so the sort orders them
        // numerically rather than putting `rules[10]` before `rules[2]`.
        for (call_index, call) in rule.allowed_calls.iter().enumerate() {
            for arg in &call.args {
                let kind = arg.constraint.kind_name();
                if !declared_constraint_kinds.iter().any(|d| d == kind) {
                    undeclared.push(format!(
                        "rules[{rule_index:02}]/allowed_calls[{call_index:02}] {}/arg {} \
                         constraint kind '{kind}'",
                        call.fn_name, arg.index
                    ));
                }
            }
        }
    }
    if undeclared.is_empty() {
        return Ok(());
    }
    undeclared.sort();
    undeclared.dedup();
    // Deliberately NOT `EUnregisteredTemplate`: that code means "no audited family by this
    // name", and an agent reading it would tell the user their family is unregistered or their
    // snapshot is stale. Here the family resolved fine and declares less than the spec uses,
    // and the remedy is the opposite — narrow the spec, or update the template entry. The
    // message leads with the family so the distinction survives even where the code is coarse.
    Err(ToolError::new(
        EC::EUnsupportedPattern,
        format!(
            "template family '{resolved_family}' is registered but does not declare every \
             capability this spec uses"
        ),
    )
    .with_details(undeclared))
}

fn map_record_err(e: &ozpb_recorder_core::RecordError) -> ToolError {
    use ozpb_recorder_core::RecordError as R;
    let code = match e {
        R::EnvelopeParse(_) => EC::EEnvelopeParse,
        R::UnsupportedEnvelope(_) => EC::EUnsupportedEnvelope,
        R::NoSorobanOp => EC::ENoSorobanOp,
        R::OperationSelection(_) => EC::EOperationSelection,
        R::TxFailed => EC::ETxFailed,
        R::UnsupportedMetaVersion(_) => EC::EUnsupportedMetaVersion,
        R::MetaParse(_) => EC::EMetaParse,
        R::ResultMismatch(_) => EC::EResultMismatch,
        R::EvidenceIncoherent(_) => EC::EEvidenceIncoherent,
        R::UnsupportedAddress(_) => EC::EUnsupportedAddress,
        R::AuthParse(_) => EC::EAuthParse,
        R::ResourceLimit(_) => EC::EResourceLimit,
        R::Internal(_) => EC::EInternal,
    };
    ToolError::new(code, e.to_string())
}

/// Per variant, not one code for the enum: an oversized document is a resource refusal, and an
/// agent told its JSON was malformed would go looking for a syntax error in a document that is
/// merely too big.
///
/// The code is stripped from the message it is paired with. `ImportError` opens its `Display`
/// with the code — the property a caller relies on when it reads a bare error string — but
/// `ToolError` prepends the code again when it renders, so passing the string through verbatim
/// produced `E_IMPORT_PARSE: E_IMPORT_PARSE: …`. Stripping is safe precisely because the two are
/// asserted equal below.
fn map_import_err(e: &ozpb_source_bundle::ImportError) -> ToolError {
    use ozpb_source_bundle::ImportError as I;
    let code = match e {
        I::Parse(_) => EC::EImportParse,
        I::TooLarge { .. } => EC::EResourceLimit,
    };
    let rendered = e.to_string();
    let message = rendered
        .strip_prefix(&format!("{}: ", code.as_str()))
        .unwrap_or(&rendered);
    ToolError::new(code, message)
}

fn map_synth_errs(errs: Vec<ozpb_synthesizer::SynthError>) -> ToolError {
    use ozpb_synthesizer::SynthError as S;
    let code = match errs.first() {
        Some(S::NoEvidence) => EC::ENoEvidence,
        Some(S::EvidenceTrust(_, _)) => EC::EEvidenceTrust,
        Some(S::FailedExecution(_)) => EC::ETxFailed,
        Some(S::NetworkMismatch) => EC::ENetworkMismatch,
        Some(S::AuthorizerNotFound(_)) => EC::EAuthorizerNotFound,
        Some(S::IncompatibleAccount(_)) => EC::EIncompatibleAccount,
        Some(S::UnsupportedPattern(_)) => EC::EUnsupportedPattern,
        Some(S::AmbiguousArgSemantics { .. }) => EC::EAmbiguousArgSemantics,
        Some(S::UnregisteredPolicy(_)) => EC::EUnregisteredPolicy,
        Some(S::NeedsDecision(_)) => EC::ENeedsDecision,
        Some(S::InvalidDecision(_)) => EC::ESpecInvalid,
        Some(S::Internal(_)) | None => EC::EInternal,
    };
    ToolError::new(code, "synthesis failed")
        .with_details(errs.iter().map(|e| e.to_string()).collect())
}

fn map_registry_err(error: RegistryError) -> ToolError {
    let code = match &error {
        RegistryError::Signature
        | RegistryError::RootPolicy(_)
        | RegistryError::Schema(_)
        | RegistryError::Parse(_) => EC::ERegistrySignature,
        RegistryError::Rollback { .. } => EC::ERegistryRollback,
        RegistryError::Transparency(_) => EC::ERegistryTransparency,
        RegistryError::Revoked { .. } => EC::ERegistryRevoked,
        RegistryError::Network { .. } => EC::ERegistryNetwork,
        RegistryError::NotYetValid { .. } | RegistryError::Expired { .. } => EC::ERegistryExpired,
        RegistryError::Validity { .. } => EC::ERegistryValidity,
        RegistryError::UnknownPolicy(_) => EC::EUnregisteredPolicy,
        RegistryError::UnknownAccount(_) | RegistryError::AccountAuthorityUnsupported(_) => {
            EC::EIncompatibleAccount
        }
        RegistryError::AccountRuleEnumerationUnsupported { .. } => {
            EC::EAccountRuleEnumerationUnsupported
        }
        RegistryError::UnknownVerifier(_) | RegistryError::VerifierCapabilityIncomplete(_) => {
            EC::EUnregisteredVerifier
        }
        RegistryError::TargetAdapterUnsupported(_) => EC::ETargetAdapterUnsupported,
        RegistryError::UnknownTemplate(_) => EC::EUnregisteredTemplate,
        RegistryError::NotLoaded => EC::ERegistryEmpty,
        RegistryError::Internal(_) => EC::EInternal,
    };
    ToolError::new(code, error.to_string())
}

fn map_build_err(error: ozpb_build_runner::BuildError) -> ToolError {
    let code = match error {
        ozpb_build_runner::BuildError::Timeout => EC::EBuildTimeout,
        ozpb_build_runner::BuildError::ResourceLimit(_) => EC::EBuildResourceLimit,
        // Operator faults (unusable builder path, unusable cache) are not the caller's spec.
        ozpb_build_runner::BuildError::Unavailable(_) => EC::EBuildUnavailable,
        ozpb_build_runner::BuildError::Busy => EC::EBuildBusy,
        ozpb_build_runner::BuildError::Cancelled => EC::ECancelled,
        ozpb_build_runner::BuildError::Input(_)
        | ozpb_build_runner::BuildError::Failed(_)
        | ozpb_build_runner::BuildError::Internal(_) => EC::EBuildFailed,
    };
    ToolError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use ozpb_policy_spec::SignerSpec;
    use ozpb_recorder_core::fixtures::{executed_snapshot, imported_snapshot};
    use ozpb_registry::dev as registry_dev;
    use ozpb_synthesizer::fixtures as fx;

    /// The registry's small-order root rejection has to reach the boundary an operator actually
    /// configures — a roots JSON file — not just the Rust constructor. `registry_trust_from_roots_json`
    /// validates the policy through `Registry::with_pinned_roots` before returning trust, so a
    /// weak governance key is refused at startup rather than at first load.
    ///
    /// This also pins where the refusal lands on the wire: there is no `E_REGISTRY_ROOT_POLICY`
    /// error code, so it arrives as `E_REGISTRY_SIGNATURE` carrying the root-policy message. A
    /// root-policy *configuration* fault reported under a *signature* code is worth knowing
    /// about; the test records today's behavior rather than asserting a code that exists.
    #[test]
    fn a_small_order_governance_root_is_refused_at_the_operator_boundary() {
        // The compressed Edwards identity: the audit's forgery root.
        let identity = format!("01{}", "00".repeat(31));
        let roots_json = format!(r#"{{"threshold":1,"keys":{{"governance":"{identity}"}}}}"#);
        let error = registry_trust_from_roots_json(&roots_json, 0)
            .expect_err("a small-order governance root must not configure registry trust");
        // Semantic content first: the refusal must name the offending signer id and the reason,
        // which is what an operator reading a startup failure needs.
        assert!(
            error.message.contains("governance") && error.message.contains("small-order"),
            "the refusal must name the key and the reason, got: {}",
            error.message
        );
        // Deliberate tripwires for the code/message mismatch described above, not incidental
        // string coupling: the wire code says "signature" while the message says
        // "E_REGISTRY_ROOT_POLICY". Both assertions are expected to be revisited together when
        // the error vocabulary gains a root-policy code — that is the point of pinning them.
        assert_eq!(error.code, EC::ERegistrySignature);
        assert!(
            error.message.contains("E_REGISTRY_ROOT_POLICY"),
            "the message still carries the root-policy label, got: {}",
            error.message
        );

        // Control: the same JSON shape with a sound root configures trust, so the assertion
        // above is detecting the weak key and not a malformed file.
        let sound = hex::encode(registry_dev::dev_root_verifying_bytes());
        let roots_json = format!(r#"{{"threshold":1,"keys":{{"governance":"{sound}"}}}}"#);
        let trust = registry_trust_from_roots_json(&roots_json, 0)
            .expect("a sound root must configure registry trust");
        assert_eq!(trust.root_policy.threshold, 1);
    }

    #[test]
    fn build_errors_map_to_distinct_wire_codes_per_cause() {
        use ozpb_build_runner::BuildError;
        for (error, expected) in [
            (BuildError::Timeout, EC::EBuildTimeout),
            (
                BuildError::ResourceLimit("too big".to_string()),
                EC::EBuildResourceLimit,
            ),
            (
                BuildError::Unavailable("no such builder".to_string()),
                EC::EBuildUnavailable,
            ),
            (
                BuildError::Failed("compile error".to_string()),
                EC::EBuildFailed,
            ),
            // Transient, unlike every other build error, so it has a code a caller can retry on.
            (BuildError::Busy, EC::EBuildBusy),
            (BuildError::Cancelled, EC::ECancelled),
        ] {
            assert_eq!(map_build_err(error.clone()).code, expected, "{error}");
        }
    }

    #[test]
    fn account_authority_registry_errors_keep_their_architecture_codes() {
        for (error, expected) in [
            (
                RegistryError::AccountAuthorityUnsupported("00".repeat(32)),
                EC::EIncompatibleAccount,
            ),
            (
                RegistryError::AccountRuleEnumerationUnsupported {
                    wasm_hash: "00".repeat(32),
                    method: "onchain_list".to_string(),
                },
                EC::EAccountRuleEnumerationUnsupported,
            ),
        ] {
            let message = error.to_string();
            let mapped = map_registry_err(error);
            assert_eq!(mapped.code, expected, "{message}");
            assert!(message.starts_with(expected.as_str()), "{message}");
        }
    }

    #[test]
    fn a_misconfigured_builder_is_not_reported_as_a_spec_that_will_not_compile() {
        let spec = wire_spec();
        let input = GenerateCodeInput {
            spec: to_value(spec.spec()).unwrap(),
            rule_index: 0,
        };
        let misconfigured = ozpb_build_runner::BuildConfig {
            stellar_binary: std::path::PathBuf::from("/nonexistent/ozpb-not-a-builder"),
            ..ozpb_build_runner::BuildConfig::default()
        };
        let error = generate_code_with_build_config(&input, &misconfigured).unwrap_err();
        assert_eq!(
            error.code,
            EC::EBuildUnavailable,
            "an operator's broken builder path must not read as ESpecInvalid/EBuildFailed \
             to an agent: {}",
            error.message
        );
    }

    /// A structured error carries a code *and* a message, and an agent reads both. When a
    /// message opens with an `E_…` prefix, that prefix is a claim about which failure this
    /// is, so it must be the code the caller receives — otherwise the two halves of one
    /// error name different failures. Messages that carry no `E_` prefix (the catch-all
    /// `internal:`, uniform across the workspace's error enums) are outside the property by
    /// construction rather than by exemption.
    #[test]
    fn a_recorder_errors_message_prefix_names_the_code_the_caller_gets() {
        use ozpb_recorder_core::RecordError as R;
        // One per variant. A new variant fails the exhaustive match below until it is named,
        // which is the prompt to add it here too.
        let all = vec![
            R::EnvelopeParse("x".into()),
            R::UnsupportedEnvelope("x".into()),
            R::NoSorobanOp,
            R::OperationSelection(2),
            R::TxFailed,
            R::UnsupportedMetaVersion(0),
            R::MetaParse("x".into()),
            R::ResultMismatch("x".into()),
            R::EvidenceIncoherent("x".into()),
            R::UnsupportedAddress("x".into()),
            R::AuthParse("x".into()),
            R::ResourceLimit("x".into()),
            R::Internal("x".into()),
        ];
        for error in &all {
            match error {
                R::EnvelopeParse(_)
                | R::UnsupportedEnvelope(_)
                | R::NoSorobanOp
                | R::OperationSelection(_)
                | R::TxFailed
                | R::UnsupportedMetaVersion(_)
                | R::MetaParse(_)
                | R::ResultMismatch(_)
                | R::EvidenceIncoherent(_)
                | R::UnsupportedAddress(_)
                | R::AuthParse(_)
                | R::ResourceLimit(_)
                | R::Internal(_) => {}
            }
            let message = error.to_string();
            let Some(prefix) = message.split(':').next().filter(|p| p.starts_with("E_")) else {
                continue;
            };
            let code = map_record_err(error).code;
            assert_eq!(
                prefix,
                code.as_str(),
                "message prefix and wire code name different failures: {message}"
            );
        }
    }

    /// The facade's import runs both halves, and each half keeps its own code.
    ///
    /// A document can be well-formed and still name evidence that does not decode — the
    /// envelope is not looked at until the recorder sees it. So the envelope failure below is
    /// exactly what a caller who stopped after parsing would have reported as a successful
    /// import, and it must arrive under the recorder's code: an agent told `E_IMPORT_PARSE`
    /// would go and fix its JSON, which is not what is wrong.
    #[test]
    fn the_atomic_import_runs_both_halves_and_each_keeps_its_code() {
        let document =
            |bundle: &ozpb_source_bundle::ImportedBundle| to_value(bundle).unwrap().to_string();
        let names_an_undecodable_envelope = ozpb_source_bundle::ImportedBundle {
            network_passphrase: ozpb_domain::TESTNET_PASSPHRASE.to_string(),
            envelope_xdr_base64: "AAAA".to_string(),
            result_meta_xdr_base64: None,
            result_xdr_base64: None,
            ledger: None,
            created_at_unix: None,
            successful: true,
        };
        assert_eq!(
            import_recording(
                &document(&names_an_undecodable_envelope),
                RecordOptions::default()
            )
            .unwrap_err()
            .code,
            EC::EEnvelopeParse,
            "the recording half ran, and named its own failure"
        );
        assert_eq!(
            import_recording("{", RecordOptions::default())
                .unwrap_err()
                .code,
            EC::EImportParse,
            "and the parsing half still names its own"
        );
    }

    /// The same property for the import boundary's errors, which reach a caller through the
    /// same structured channel.
    #[test]
    fn an_import_errors_message_prefix_names_the_code_the_caller_gets() {
        use ozpb_source_bundle::ImportError as I;
        // One per variant; the exhaustive match stops compiling when the enum grows.
        let all = vec![I::Parse("x".into()), I::TooLarge { bytes: 2, max: 1 }];
        for error in &all {
            match error {
                I::Parse(_) | I::TooLarge { .. } => {}
            }
            let message = error.to_string();
            let prefix = message
                .split(':')
                .next()
                .filter(|prefix| prefix.starts_with("E_"))
                .expect("every import error opens its message with its code");
            let mapped = map_import_err(error);
            assert_eq!(
                prefix,
                mapped.code.as_str(),
                "message prefix and wire code name different failures: {message}"
            );
            // And the caller reads the code once. ToolError renders "{code}: {message}", so a
            // message that still carried its own prefix would arrive doubled.
            assert!(
                !mapped.message.starts_with("E_"),
                "the mapped message repeats the code: {}",
                mapped
            );
        }
    }

    #[test]
    fn generate_refuses_trust_labels_the_wire_cannot_authenticate() {
        // A serialized spec is caller-controlled text: a `rpc_reported` label in it is an
        // unverifiable claim, and generate_code would seal that claim into the hashed
        // BuildManifest chain. The boundary must refuse it the way synthesize_policy
        // downgrades bundle trust — nothing legitimately produced by this toolkit carries
        // anything but self_supplied across the wire.
        let mut spec = serde_json::to_value(wire_spec().spec()).unwrap();
        spec["evidence"]["recordings"][0]["trust"] = serde_json::json!("rpc_reported");
        let error = generate_code_with_build_config(
            &GenerateCodeInput {
                spec,
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap_err();
        assert_eq!(error.code, EC::ESpecInvalid);
        assert!(
            error.message.contains("trust"),
            "the refusal must name the unauthenticated claim: {}",
            error.message
        );
    }

    #[test]
    fn generate_refuses_incomplete_evidence_for_its_own_reason() {
        // `incomplete` is not a forged strength claim — it is evidence the recorder ruled
        // out of synthesis, which no legitimate pipeline ever cites in a spec. The refusal
        // must say that, not accuse it of claiming acquisition context.
        let mut spec = serde_json::to_value(wire_spec().spec()).unwrap();
        spec["evidence"]["recordings"][0]["trust"] = serde_json::json!("incomplete");
        let error = generate_code_with_build_config(
            &GenerateCodeInput {
                spec,
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap_err();
        assert_eq!(error.code, EC::ESpecInvalid);
        assert!(
            error.message.contains("ruled out of synthesis"),
            "the refusal must state the incomplete-specific reason: {}",
            error.message
        );
    }

    #[test]
    fn recorder_resource_limits_have_a_stable_wire_code() {
        let error = map_record_err(&ozpb_recorder_core::RecordError::ResourceLimit(
            "oversized evidence".to_string(),
        ));
        assert_eq!(error.code, EC::EResourceLimit);
    }

    #[test]
    fn record_then_synthesize_then_generate_end_to_end() {
        // The full Phase 1 pipeline through the wire types.
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(rec.trust, "rpc_reported");

        let syn_input = SynthesizeInput {
            bundles: vec![rec.bundle.clone()],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let syn = synthesize_policy(&syn_input, &registry_trust()).unwrap();
        assert!(!syn.spec_hash.is_empty());

        let gen = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: syn.spec.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        assert!(gen.files.contains_key("src/lib.rs"));
        assert_eq!(gen.stellar_accounts_version, "0.8.0");

        // The generated scope permits, but the full spec also composes a reviewed
        // spending-limit policy that the Phase 1 evaluator deliberately does not simulate.
        let ctx = serde_json::json!({
            "smart_account": fx::golden_account_strkey(),
            "current_ledger": 100,
            "authenticated_signers": [{"delegated":{"address": fx::golden_delegate_strkey()}}],
            "rule_live_signers": [{"delegated":{"address": fx::golden_delegate_strkey()}}],
            "call_count_so_far": 0
        });
        let inv = serde_json::json!({
            "contract": fx::golden_token_strkey(),
            "fn_name": "transfer",
            "args": [
                {"address": fx::golden_account_strkey()},
                {"address": fx::golden_merchant_strkey()},
                {"i128": 500000000i64}
            ]
        });
        let out = evaluate_spec(&EvaluateSpecInput {
            spec: syn.spec.clone(),
            context: ctx,
            invocation: inv,
        })
        .unwrap();
        assert_eq!(out.verdict, "indeterminate");
        assert_eq!(
            out.deny_reason.as_deref(),
            Some("ReviewedPoliciesUnmodeled")
        );
    }

    #[test]
    fn generated_artifact_includes_wasm_and_a_binding_manifest() {
        let input = GenerateCodeInput {
            spec: serde_json::to_value(wire_spec().spec()).unwrap(),
            rule_index: 0,
        };
        let config = build_config();
        let generated = generate_code_with_build_config(&input, &config).unwrap();

        assert!(!generated.wasm_base64.is_empty());
        assert_eq!(
            generated.build_manifest["wasm_hash"],
            serde_json::json!(generated.wasm_hash)
        );
        assert!(!generated.build_manifest_hash.is_empty());
    }

    #[test]
    fn synthesis_errors_map_to_stable_codes() {
        let mut d = fx::golden_decisions();
        d.delegate_signers.clear();
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(d).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::ENeedsDecision);
    }

    /// A caller that drops the acknowledgement, as tool callers often drop fields, gets a
    /// question rather than an uncapped grant: absent reads as not acknowledged.
    #[test]
    fn an_uncapped_decision_without_the_acknowledgement_needs_a_decision() {
        let mut decisions = serde_json::to_value(fx::golden_decisions()).unwrap();
        let fields = decisions.as_object_mut().unwrap();
        assert_eq!(
            fields.remove("unlimited_calls_acknowledged"),
            Some(serde_json::Value::Bool(false))
        );
        fields.insert("max_calls".into(), serde_json::Value::Null);
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions,
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::ENeedsDecision);
        assert!(
            err.details.iter().any(|detail| detail.contains("call cap")),
            "{:?}",
            err.details
        );
    }

    #[test]
    fn synthesis_rejects_untrusted_registry_evidence() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let mut input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        input.signed_registry_snapshot.as_mut().unwrap()["snapshot"]["version"] =
            serde_json::json!(999);
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::ERegistrySignature);

        input.signed_registry_snapshot = Some(signed_registry_json());
        let attacker_trust = RegistryTrust {
            root_policy: RootPolicy {
                threshold: 1,
                keys: std::collections::BTreeMap::from([(
                    "legacy".to_string(),
                    ozpb_domain::sha256(b"attacker registry root").0,
                )]),
            },
            minimum_version: 1,
            checkpoint: None,
            configured_snapshot: None,
        };
        let err = synthesize_policy(&input, &attacker_trust).unwrap_err();
        assert_eq!(err.code, EC::ERegistrySignature);

        input.signed_registry_snapshot = Some(signed_registry_json());
        let rollback_floor = RegistryTrust {
            root_policy: RootPolicy {
                threshold: 1,
                keys: std::collections::BTreeMap::from([(
                    "legacy".to_string(),
                    registry_dev::dev_root_verifying_bytes(),
                )]),
            },
            minimum_version: 2,
            checkpoint: None,
            configured_snapshot: None,
        };
        let err = synthesize_policy(&input, &rollback_floor).unwrap_err();
        assert_eq!(err.code, EC::ERegistryRollback);
    }

    /// Every field the MCP surface made optional, exercised against the one it replaced.
    ///
    /// The assertion is on the spec *hash*, not on "it returned something": these fields feed
    /// the canonical artifact, so an omitted field that produced a subtly different account
    /// record or template family would still synthesize — and would hand a reviewer a different
    /// policy than the explicit call does. Equal hashes are the only statement worth making.
    mod omitted_inputs_are_derived {
        use super::*;

        fn explicit() -> SynthesizeInput {
            let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
            SynthesizeInput {
                bundles: vec![rec.bundle],
                selected_authorizer: Some(fx::golden_account_strkey()),
                account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
                signed_registry_snapshot: Some(signed_registry_json()),
                decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
                spending_limit_capability: Some(
                    fx::golden_input()
                        .spending_limit_capability
                        .unwrap()
                        .to_hex(),
                ),
                template_family: ozpb_api_types::DEFAULT_TEMPLATE_FAMILY.to_string(),
            }
        }

        fn spec_hash(input: &SynthesizeInput, trust: &RegistryTrust) -> String {
            synthesize_policy(input, trust).unwrap().spec_hash
        }

        #[test]
        fn authorizer_and_account_come_from_the_recording() {
            let baseline = spec_hash(&explicit(), &registry_trust());
            let mut derived = explicit();
            derived.selected_authorizer = None;
            derived.account = None;
            assert_eq!(spec_hash(&derived, &registry_trust()), baseline);
        }

        #[test]
        fn the_pinned_sentinel_resolves_to_the_pinned_hash() {
            let baseline = spec_hash(&explicit(), &registry_trust());
            let mut sentinel = explicit();
            sentinel.spending_limit_capability =
                Some(ozpb_api_types::PINNED_SPENDING_LIMIT.to_string());
            assert_eq!(spec_hash(&sentinel, &registry_trust()), baseline);
        }

        #[test]
        fn the_template_family_defaults_to_the_only_registered_one() {
            let json = serde_json::to_value(explicit()).unwrap();
            let mut object = json.as_object().unwrap().clone();
            object.remove("template_family");
            let without: SynthesizeInput =
                serde_json::from_value(serde_json::Value::Object(object)).unwrap();
            assert_eq!(
                without.template_family,
                ozpb_api_types::DEFAULT_TEMPLATE_FAMILY
            );
            assert_eq!(
                spec_hash(&without, &registry_trust()),
                spec_hash(&explicit(), &registry_trust())
            );
        }

        /// A configured snapshot decides the default, not whether it is checked — so a request
        /// that omits one gets the same artifact, and the attacker-root test elsewhere in this
        /// file still refuses a snapshot signed by anyone else.
        #[test]
        fn the_configured_snapshot_is_used_when_the_request_omits_one() {
            let mut trust = registry_trust();
            trust.configured_snapshot = Some(signed_registry_json());
            let mut omitted = explicit();
            omitted.signed_registry_snapshot = None;
            assert_eq!(
                spec_hash(&omitted, &trust),
                spec_hash(&explicit(), &registry_trust())
            );
        }

        #[test]
        fn omitting_the_snapshot_with_none_configured_is_refused() {
            let mut omitted = explicit();
            omitted.signed_registry_snapshot = None;
            let err = synthesize_policy(&omitted, &registry_trust()).unwrap_err();
            assert_eq!(err.code, EC::ERegistryEmpty);
        }

        /// Two candidate accounts is a decision, and the toolkit does not get to make it.
        ///
        /// Aimed at the derivation function rather than at `synthesize_policy`, because a
        /// two-authorizer bundle cannot be reached through the boundary by editing one: every
        /// decoded view is re-derived from the raw XDR at admission, so a hand-added
        /// authorization is `E_EVIDENCE_INCOHERENT` long before derivation runs. Producing a
        /// genuinely coherent two-account recording needs an envelope with two such
        /// authorizations, which is a fixture this milestone does not carry.
        #[test]
        fn a_second_authorizing_account_is_refused_rather_than_picked() {
            let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
            let mut bundle: RecordingBundle = serde_json::from_value(rec.bundle).unwrap();

            let second = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWGO".to_string();
            let mut extra = bundle.authorizations[0].clone();
            extra.authorizer = second.clone();
            bundle.authorizations.push(extra);
            let observed = bundle
                .contract_executables
                .get(&fx::golden_account_strkey())
                .expect("the fixture observes the account's code")
                .clone();
            bundle.contract_executables.insert(second.clone(), observed);

            let bundles = vec![bundle];
            assert_eq!(smart_account_candidates(&bundles).len(), 2);
            let err = derive_selected_authorizer(&bundles).unwrap_err();
            assert_eq!(err.code, EC::EAuthorizerNotFound);
            assert!(
                err.message.contains(&second) && err.message.contains(&fx::golden_account_strkey()),
                "the error has to name the candidates so the caller can choose: {}",
                err.message
            );
        }

        /// A named account whose code the recordings never observed is an incompatibility, not
        /// a missing authorizer — the distinction `SynthesizeInput::account` documents, and the
        /// code the explicit path already returns for the same question.
        #[test]
        fn a_named_account_with_no_observed_code_is_incompatible() {
            let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
            let mut bundle: RecordingBundle = serde_json::from_value(rec.bundle).unwrap();
            let named = bundle.authorizations[0].authorizer.clone();
            bundle.contract_executables.clear();
            let err = derive_account_record(&[bundle], &named).unwrap_err();
            assert_eq!(err.code, EC::EIncompatibleAccount);
        }

        /// A recording whose only authorizer is a classic account has no account to synthesize
        /// for — the case behind the funding transfer in the demo, which records fine and
        /// cannot be synthesized from.
        #[test]
        fn no_authorizing_contract_is_refused() {
            let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
            let mut bundle: RecordingBundle = serde_json::from_value(rec.bundle).unwrap();
            bundle.contract_executables.clear();
            let err = derive_selected_authorizer(&[bundle]).unwrap_err();
            assert_eq!(err.code, EC::EAuthorizerNotFound);
        }
    }

    #[test]
    fn synthesis_resolves_every_security_capability_from_the_registry() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let base = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        let mut unknown_account = base.clone();
        unknown_account.account.as_mut().unwrap()["observed_code_hash"] =
            serde_json::json!(ozpb_domain::sha256(b"unknown-account").to_hex());
        let err = synthesize_policy(&unknown_account, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EIncompatibleAccount);

        let mut unknown_policy = base.clone();
        unknown_policy.spending_limit_capability =
            Some(ozpb_domain::sha256(b"unknown-policy").to_hex());
        let err = synthesize_policy(&unknown_policy, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnregisteredPolicy);

        let mut unknown_template = base.clone();
        unknown_template.template_family = "policy-templates/unknown@1".to_string();
        let err = synthesize_policy(&unknown_template, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnregisteredTemplate);

        let mut decisions = fx::golden_decisions();
        decisions.delegate_signers = vec![SignerSpec::External {
            verifier: fx::golden_token_strkey(),
            verifier_code_hash: ozpb_domain::sha256(b"unknown-verifier"),
            key_hex: "00".repeat(32),
        }];
        let mut unsupported_external = base;
        unsupported_external.decisions = serde_json::to_value(decisions).unwrap();
        let err = synthesize_policy(&unsupported_external, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnsupportedPattern);
        assert!(err
            .details
            .iter()
            .any(|detail| detail.contains("external verifiers are unavailable in Phase 1")));
    }

    /// A spec may only use capabilities the resolved template family declares.
    ///
    /// The registry's `constraint_kinds` and `signer_predicates` were, until now, an assertion
    /// inside a signed document that no code read. This asserts they are read, and it does so
    /// the only way that can fail today: by narrowing the snapshot rather than widening the
    /// spec, because synthesis emits exactly what the corrected lists already cover. Take the
    /// dev snapshot, drop `eq_address` from the template's declared constraints, re-sign it
    /// with the dev key, and synthesize the golden spec — whose first argument is `SELF`, an
    /// `eq_address`. It must refuse.
    ///
    /// Narrowing the snapshot is also what the check is *for*: the failure it guards against is
    /// the reviewed template and the signed description of it drifting apart, in either
    /// direction.
    #[test]
    fn a_spec_may_not_use_capabilities_the_template_does_not_declare() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let mut narrowed_snapshot = ozpb_registry::dev::dev_snapshot(
            ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            1,
        );
        let template = narrowed_snapshot
            .templates
            .get_mut("policy-templates/scope@1")
            .expect("the dev snapshot declares the scope template");
        template
            .constraint_kinds
            .retain(|kind| kind != "eq_address");
        let re_signed =
            ozpb_registry::sign_snapshot(&registry_dev::dev_signing_key(), narrowed_snapshot)
                .expect("re-signing the dev snapshot");

        let input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(serde_json::to_value(&re_signed).unwrap()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnsupportedPattern);
        assert!(
            err.message.contains("policy-templates/scope@1"),
            "the refusal must name the family that resolved: {}",
            err.message
        );
        assert!(
            err.details
                .iter()
                .any(|detail| detail.contains("'eq_address'")),
            "the refusal must name the undeclared kind: {:?}",
            err.details
        );
    }

    /// The boundary's trust handling must be a downgrade, not an assignment. An executed
    /// import with no transaction result is recorded `incomplete` — and crossing the wire
    /// must not promote it to a level the synthesis gate accepts. Runs the whole wire path
    /// (record -> JSON bundle -> synthesize), because the in-process label was never the
    /// exposed surface; the control case is the same evidence *with* its result, which must
    /// still synthesize.
    #[test]
    fn a_wire_bundle_may_only_have_its_trust_lowered_at_the_synthesis_boundary() {
        let synthesis_input = |bundle: serde_json::Value| SynthesizeInput {
            bundles: vec![bundle],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        // Control: the identical import that ships its transaction result is `self_supplied`
        // and synthesizes. Without this, the assertion below could pass for any reason.
        let complete = record_snapshot(&imported_snapshot(true), RecordOptions::default()).unwrap();
        assert_eq!(complete.trust, "self_supplied");
        assert!(
            synthesize_policy(&synthesis_input(complete.bundle), &registry_trust()).is_ok(),
            "an import with its transaction result must remain synthesizable"
        );

        // The finding: the same evidence minus the result is `incomplete` and must stay
        // `incomplete` across the boundary.
        let incomplete =
            record_snapshot(&imported_snapshot(false), RecordOptions::default()).unwrap();
        assert_eq!(incomplete.trust, "incomplete");
        assert_eq!(
            incomplete.bundle["trust"],
            serde_json::json!("incomplete"),
            "the wire bundle must carry the label the recorder derived"
        );
        let error =
            synthesize_policy(&synthesis_input(incomplete.bundle), &registry_trust()).unwrap_err();
        assert_eq!(
            error.code,
            EC::EEvidenceTrust,
            "incomplete evidence must not be promoted to self_supplied at the boundary: {}",
            error.message
        );
    }

    #[test]
    fn incoherent_bundles_are_rejected_at_the_synthesis_boundary() {
        // The audit reproduction at the wire: leave the raw evidence untouched, edit the
        // decoded rule synthesis would consume. The bundle still hashes; the boundary
        // must still refuse it.
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let mut forged = rec.bundle.clone();
        forged["authorizations"][0]["root"]["call"]["contract"]["fn_name"] =
            serde_json::json!("drain_everything");
        assert_ne!(forged, rec.bundle, "the mutation must land");
        let input = SynthesizeInput {
            bundles: vec![forged],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(
            err.code,
            EC::EEvidenceIncoherent,
            "an edited decoded view with untouched raw evidence must be refused: {}",
            err.message
        );
    }

    #[test]
    fn caller_supplied_provenance_labels_are_downgraded_before_synthesis() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(rec.bundle["trust"], serde_json::json!("rpc_reported"));

        let mut forged = rec.bundle;
        forged["trust"] = serde_json::json!("trusted_indexer");
        let input = SynthesizeInput {
            bundles: vec![forged],
            selected_authorizer: Some(fx::golden_account_strkey()),
            account: Some(serde_json::to_value(&fx::golden_input().account).unwrap()),
            signed_registry_snapshot: Some(signed_registry_json()),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let output = synthesize_policy(&input, &registry_trust()).unwrap();

        assert_eq!(
            output.spec["evidence"]["recordings"][0]["trust"],
            serde_json::json!("self_supplied"),
            "an unauthenticated wire label must not survive as trusted provenance"
        );
    }
}

#[cfg(test)]
mod target_adapter_tests;
