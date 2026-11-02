//! rmcp stdio MCP server (architecture §4.6, §4.11).
//!
//! A thin shell over `ozpb_toolkit` for policy operations and `ozpb_source_rpc` for
//! network observations, with wire types from `ozpb_api_types`. Recording and exact-envelope
//! preflight read the selected RPC endpoint; generation and verification may build Wasm.
//! No domain logic or transaction submission lives here.
//!
//! Deployment and signing are deliberately NOT capabilities of this server.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{CallToolResult, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};

use ozpb_api_types::{
    EvaluateSpecInput, EvaluateSpecOutput, GenerateCodeInput, GenerateCodeOutput,
    ImportRecordingInput, RecordOutput, RecordSimulationInput, RecordTransactionInput,
    SynthesizeInput, SynthesizeOutput, ToolError,
};
use ozpb_recorder_core::RecordOptions;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

mod authority;
mod cancel;
mod capture;
mod http;
mod policy_check;
mod preflight;
mod tool_limits;
mod verification;

#[derive(Clone)]
struct RpcEndpointPolicy {
    allowed: Arc<BTreeSet<String>>,
}

impl RpcEndpointPolicy {
    fn from_csv(csv: &str) -> anyhow::Result<Self> {
        let mut allowed = BTreeSet::new();
        for candidate in csv.split(',').map(str::trim).filter(|url| !url.is_empty()) {
            allowed.insert(Self::normalize(candidate)?);
        }
        if allowed.is_empty() {
            anyhow::bail!("OZPB_RPC_ALLOWLIST must contain at least one HTTPS endpoint");
        }
        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }

    fn normalize(candidate: &str) -> anyhow::Result<String> {
        let url = url::Url::parse(candidate)
            .map_err(|error| anyhow::anyhow!("invalid RPC URL '{candidate}': {error}"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            anyhow::bail!(
                "hosted RPC endpoints must be absolute HTTPS URLs without credentials or fragments"
            );
        }
        Ok(url.to_string())
    }

    fn authorize(&self, requested: &str) -> Result<String, ToolError> {
        let normalized = Self::normalize(requested)
            .map_err(|error| ToolError::new(ozpb_api_types::ErrorCode::ERpc, error.to_string()))?;
        if !self.allowed.contains(&normalized) {
            return Err(ToolError::new(
                ozpb_api_types::ErrorCode::ERpc,
                "RPC endpoint is not in the hosted server allowlist",
            ));
        }
        Ok(normalized)
    }
}

/// How many artifacts one session remembers for `generated_artifact` references.
const KEPT_ARTIFACTS: usize = 8;

/// What `generate_code` built in this session, so `verify` and `prepare_dry_run` can name an
/// artifact by its `build_manifest_hash` instead of carrying a crate and its Wasm — tens of
/// thousands of characters — back through the conversation. The oldest is forgotten first.
#[derive(Default)]
struct GeneratedArtifacts(std::collections::VecDeque<GenerateCodeOutput>);

impl GeneratedArtifacts {
    fn keep(&mut self, artifact: GenerateCodeOutput) {
        self.0
            .retain(|kept| kept.build_manifest_hash != artifact.build_manifest_hash);
        if self.0.len() == KEPT_ARTIFACTS {
            self.0.pop_front();
        }
        self.0.push_back(artifact);
    }

    fn find(&self, build_manifest_hash: &str) -> Option<&GenerateCodeOutput> {
        self.0
            .iter()
            .find(|kept| kept.build_manifest_hash == build_manifest_hash)
    }
}

#[derive(Clone)]
struct PolicyBuilderServer {
    tool_router: ToolRouter<Self>,
    registry_trust: Option<ozpb_toolkit::RegistryTrust>,
    rpc_policy: Option<RpcEndpointPolicy>,
    /// Operator-named RPC sources for state reads that must not take a URL from the client
    /// (`OZPB_RPC_SOURCES_JSON`). Empty when the operator configured none.
    rpc_sources: Arc<std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>>,
    /// Slots for authority reads (which may build and always read the network) on a hosted
    /// server. Held by the blocking work itself, so a caller who gives up does not free the
    /// slot while the work still runs. `None` on stdio: one user, their own machine.
    authority_slots: Option<Arc<tokio::sync::Semaphore>>,
    /// Operator-side build settings. Unlike `rpc_policy` this is not optional: every
    /// transport needs a builder, and the wire contract carries no build fields — a
    /// caller-chosen timeout would be resource exhaustion and a caller-chosen builder path
    /// arbitrary execution.
    build_config: ozpb_toolkit::BuildConfig,
    tool_quotas: Option<tool_limits::ToolQuotas>,
    /// This session's generated artifacts. Per session on a hosted server too: one client
    /// cannot name another's.
    generated: Arc<std::sync::Mutex<GeneratedArtifacts>>,
}

impl PolicyBuilderServer {
    fn new(
        registry_trust: Option<ozpb_toolkit::RegistryTrust>,
        rpc_policy: Option<RpcEndpointPolicy>,
        rpc_sources: Arc<std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>>,
        build_config: ozpb_toolkit::BuildConfig,
    ) -> Self {
        Self {
            tool_router: Self::tool_router()
                + Self::verification_tool_router()
                + Self::preflight_tool_router()
                + Self::authority_tool_router()
                + Self::policy_check_tool_router()
                + Self::capture_tool_router(),
            authority_slots: rpc_policy
                .as_ref()
                .map(|_| Arc::new(tokio::sync::Semaphore::new(1))),
            registry_trust,
            rpc_policy,
            rpc_sources,
            build_config,
            tool_quotas: None,
            generated: Default::default(),
        }
    }

    fn authorized_rpc_url(&self, requested: &str) -> Result<String, ToolError> {
        match &self.rpc_policy {
            Some(policy) => policy.authorize(requested),
            None => Ok(requested.to_string()),
        }
    }

    /// Replace a `generated_artifact` reference with the files, Wasm and BuildManifest this
    /// session's `generate_code` built, so everything downstream — reproduction, the dry-run
    /// hash — sees exactly the request a client sending the bytes would have made.
    fn resolve_generated_artifact(
        &self,
        input: &mut ozpb_api_types::VerifyInput,
    ) -> Result<(), ToolError> {
        let Some(reference) = input.generated_artifact.take() else {
            return Ok(());
        };
        let refuse =
            |message: String| ToolError::new(ozpb_api_types::ErrorCode::ESpecInvalid, message);
        if !input.claimed_generated_files.is_empty()
            || input.claimed_wasm_base64.is_some()
            || input.claimed_build_manifest.is_some()
        {
            return Err(refuse(
                "give generated_artifact or the claimed files, Wasm and BuildManifest, not both"
                    .to_string(),
            ));
        }
        if reference.len() != 64
            || !reference
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refuse(
                "generated_artifact is the build_manifest_hash generate_code returned".to_string(),
            ));
        }
        // Nothing panics while the lock is held, so a poisoned store is still consistent.
        let kept = self
            .generated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let artifact = kept.find(&reference).ok_or_else(|| {
            refuse(format!(
                "no artifact with build_manifest_hash {reference} was generated in this session \
                 (it keeps the last {KEPT_ARTIFACTS}); call generate_code again, or send the \
                 claimed files, Wasm and BuildManifest"
            ))
        })?;
        input.claimed_generated_files = artifact
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        input.claimed_wasm_base64 = Some(artifact.wasm_base64.clone());
        input.claimed_build_manifest = Some(artifact.build_manifest.clone());
        Ok(())
    }

    /// Where a recording tool reads, and for which network: a configured source by name, the
    /// only configured source when nothing is named, or a caller URL with its passphrase. An
    /// agent should never have to ask its user for an endpoint the operator already chose.
    fn record_endpoint(
        &self,
        rpc_source: Option<&str>,
        rpc_url: Option<&str>,
        network_passphrase: Option<&str>,
    ) -> Result<(String, String), ToolError> {
        let refuse = |message: String| ToolError::new(ozpb_api_types::ErrorCode::ERpc, message);
        let source = match (rpc_source, rpc_url) {
            (Some(_), Some(_)) => {
                return Err(refuse(
                    "name a configured rpc_source or give an rpc_url, not both".to_string(),
                ))
            }
            (None, Some(url)) => {
                let passphrase = network_passphrase.ok_or_else(|| {
                    refuse("an rpc_url needs the network_passphrase it serves".to_string())
                })?;
                return Ok((self.authorized_rpc_url(url)?, passphrase.to_string()));
            }
            // Like the other source-reading tools, an unknown name does not list the
            // operator's names to a client that guessed one.
            (Some(name), None) => self.rpc_sources.get(name).ok_or_else(|| {
                refuse(format!(
                    "no RPC source named {name:?} is configured on this server"
                ))
            })?,
            (None, None) => {
                let mut sources = self.rpc_sources.values();
                match (sources.next(), sources.next()) {
                    (Some(only), None) => only,
                    (None, _) => {
                        return Err(refuse(
                            "this server has no configured RPC source; give an rpc_url and \
                             its network_passphrase"
                                .to_string(),
                        ))
                    }
                    (Some(_), Some(_)) => {
                        let names: Vec<_> = self
                            .rpc_sources
                            .keys()
                            .map(|name| format!("{name:?}"))
                            .collect();
                        return Err(refuse(format!(
                            "this server configures several RPC sources; name one as \
                             rpc_source: [{}]",
                            names.join(", ")
                        )));
                    }
                }
            }
        };
        if network_passphrase.is_some_and(|stated| stated != source.network_passphrase) {
            return Err(ToolError::new(
                ozpb_api_types::ErrorCode::ENetworkMismatch,
                "the RPC source serves another network than the stated network_passphrase",
            ));
        }
        Ok((
            self.authorized_rpc_url(&source.rpc_url)?,
            source.network_passphrase.clone(),
        ))
    }
}

/// Construct hosted resources once, then clone them into each rmcp session. Creating a new
/// server inside the closure would give every client its own authority-work budget.
fn http_session_factory(
    registry_trust: Option<ozpb_toolkit::RegistryTrust>,
    rpc_policy: RpcEndpointPolicy,
    rpc_sources: Arc<std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>>,
    build_config: ozpb_toolkit::BuildConfig,
    limits: tool_limits::ToolLimitConfig,
) -> anyhow::Result<impl Fn() -> Result<PolicyBuilderServer, std::io::Error>> {
    let mut server =
        PolicyBuilderServer::new(registry_trust, Some(rpc_policy), rpc_sources, build_config);
    server.tool_quotas = Some(tool_limits::ToolQuotas::new(
        server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned()),
        limits,
    )?);
    Ok(move || {
        let mut session = server.clone();
        session.generated = Default::default();
        Ok(session)
    })
}

/// Map a toolkit ToolError into an rmcp tool-execution error carrying the structured
/// payload (stable code + message + details) as JSON data — the agent-recoverable
/// channel (§4.6).
fn tool_err(e: ToolError) -> CallToolResult {
    let data = serde_json::to_value(&e).unwrap_or_else(|_| {
        serde_json::json!({
            "code": "E_INTERNAL",
            "message": "could not serialize tool error"
        })
    });
    CallToolResult::structured_error(data)
}

fn internal_tool_err(error: impl std::fmt::Display) -> CallToolResult {
    tool_err(ToolError::new(
        ozpb_api_types::ErrorCode::EInternal,
        error.to_string(),
    ))
}

fn rpc_tool_err(error: ozpb_source_rpc::RpcError) -> ToolError {
    let code = match error {
        ozpb_source_rpc::RpcError::NotFound(_) => ozpb_api_types::ErrorCode::ETxNotFound,
        ozpb_source_rpc::RpcError::NetworkMismatch { .. } => {
            ozpb_api_types::ErrorCode::ENetworkMismatch
        }
        ozpb_source_rpc::RpcError::EnvelopeTooLarge(_) => ozpb_api_types::ErrorCode::EResourceLimit,
        ozpb_source_rpc::RpcError::EnvelopeParse(_) => ozpb_api_types::ErrorCode::EEnvelopeParse,
        ozpb_source_rpc::RpcError::UnsupportedEnvelope(_) => {
            ozpb_api_types::ErrorCode::EUnsupportedEnvelope
        }
        _ => ozpb_api_types::ErrorCode::ERpc,
    };
    ToolError::new(code, error.to_string())
}

#[tool_router(router = tool_router)]
impl PolicyBuilderServer {
    /// Record an executed on-chain transaction (by hash) into an authorization
    /// fingerprint. NETWORK READ. Retention is short — outside it, use import.
    #[tool(
        name = "record_transaction",
        description = "Record an executed Stellar transaction (by hash, via Stellar RPC) \
                       into a RecordingBundle: the authorization tree, token movements, \
                       and dual hashes. Network read. Reads through the server's configured \
                       RPC source when there is one; do not ask the user for an endpoint."
    )]
    async fn record_transaction(
        &self,
        Parameters(input): Parameters<RecordTransactionInput>,
        ct: CancellationToken,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let (rpc_url, network_passphrase) = self
            .record_endpoint(
                input.rpc_source.as_deref(),
                input.rpc_url.as_deref(),
                input.network_passphrase.as_deref(),
            )
            .map_err(tool_err)?;
        let request = ct.clone();
        let out = tokio::task::spawn_blocking(move || {
            let transport = cancel::transport(rpc_url, &request);
            let snapshot =
                ozpb_source_rpc::get_transaction(&transport, &network_passphrase, &input.tx_hash)
                    .map_err(rpc_tool_err)?;
            let options = RecordOptions {
                operation_index: input.operation_index,
                allow_failed: input.allow_failed,
            };
            ozpb_toolkit::record_snapshot(&snapshot, options)
        })
        .await
        .map_err(internal_tool_err)?;
        let out = cancel::unless_cancelled(&ct, out.map_err(tool_err))?;
        Ok(Json(out))
    }

    /// Record a locally simulated (unsigned) transaction via RPC record mode. NETWORK
    /// READ. The envelope may encode private intent — confidential input (§6.5).
    #[tool(
        name = "record_simulation",
        description = "Record an unsigned transaction envelope via simulateTransaction in \
                       record mode into a RecordingBundle. Network read through the server's \
                       configured RPC source when there is one; the envelope is confidential \
                       input."
    )]
    async fn record_simulation(
        &self,
        Parameters(input): Parameters<RecordSimulationInput>,
        ct: CancellationToken,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let (rpc_url, network_passphrase) = self
            .record_endpoint(
                input.rpc_source.as_deref(),
                input.rpc_url.as_deref(),
                input.network_passphrase.as_deref(),
            )
            .map_err(tool_err)?;
        let request = ct.clone();
        let out = tokio::task::spawn_blocking(move || {
            let transport = cancel::transport(rpc_url, &request);
            let snapshot = ozpb_source_rpc::simulate_transaction(
                &transport,
                &network_passphrase,
                &input.envelope_xdr_base64,
            )
            .map_err(rpc_tool_err)?;
            ozpb_toolkit::record_snapshot(&snapshot, RecordOptions::default())
        })
        .await
        .map_err(internal_tool_err)?;
        let out = cancel::unless_cancelled(&ct, out.map_err(tool_err))?;
        Ok(Json(out))
    }

    /// Synthesize a minimum-permission PolicySpec from recordings + explicit user
    /// decisions. PURE and deterministic. Exact-by-default; widening only via decisions.
    #[tool(
        name = "synthesize_policy",
        description = "Synthesize a minimum-permission PolicySpec from RecordingBundle(s) \
                       plus explicit user decisions (signer set, lifetime, widenings). \
                       Pure, deterministic, exact-by-default, fail-closed."
    )]
    async fn synthesize_policy(
        &self,
        Parameters(input): Parameters<SynthesizeInput>,
    ) -> Result<Json<SynthesizeOutput>, CallToolResult> {
        let trust = self.registry_trust.as_ref().ok_or_else(|| {
            tool_err(ToolError::new(
                ozpb_api_types::ErrorCode::ERegistryEmpty,
                "synthesize_policy is disabled until OZPB_REGISTRY_ROOTS_JSON and \
                 OZPB_REGISTRY_MIN_VERSION are configured",
            ))
        })?;
        let out = ozpb_toolkit::synthesize_policy(&input, trust).map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Evaluate a candidate invocation against a PolicySpec using the independent
    /// reference evaluator. PURE. Lets an agent pre-flight an action safely.
    #[tool(
        name = "evaluate_spec",
        description = "Evaluate whether a candidate invocation would be permitted under a \
                       PolicySpec, using the independent reference evaluator. Pure; \
                       returns permit or deny + machine-readable reason."
    )]
    async fn evaluate_spec(
        &self,
        Parameters(input): Parameters<EvaluateSpecInput>,
    ) -> Result<Json<EvaluateSpecOutput>, CallToolResult> {
        let out = ozpb_toolkit::evaluate_spec(&input).map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Generate and reproducibly build the immutable Stellar smart-contract policy artifact. Resource
    /// consuming, deterministic, and non-deploying — code-first, deploy-second (§6.2).
    #[tool(
        name = "generate_code",
        description = "Generate and build the deterministic, immutable Stellar smart-contract policy \
                       artifact for a PolicySpec rule: locked Rust source, Wasm, and a \
                       binding BuildManifest. Resource-consuming; never deploys or signs."
    )]
    async fn generate_code(
        &self,
        Parameters(input): Parameters<GenerateCodeInput>,
        ct: CancellationToken,
    ) -> Result<Json<GenerateCodeOutput>, CallToolResult> {
        let build = cancel::build_config(&self.build_config, &ct);
        let out = tokio::task::spawn_blocking(move || {
            ozpb_toolkit::generate_code_with_build_config(&input, &build)
        })
        .await
        .map_err(internal_tool_err)?;
        let out = cancel::unless_cancelled(&ct, out.map_err(tool_err))?;
        self.generated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keep(out.clone());
        Ok(Json(out))
    }

    /// Import a raw-XDR evidence bundle (offline) into a RecordingBundle. PURE. For
    /// transactions outside RPC retention; `self_supplied` trust at most — `incomplete`
    /// without the transaction result XDR.
    #[tool(
        name = "import_recording",
        description = "Record from a self-contained raw-XDR evidence bundle (offline). \
                       Pure; carries self_supplied trust (internally consistent but not \
                       network-verified) when the transaction result XDR is supplied and \
                       agrees with the claimed outcome, incomplete without it."
    )]
    async fn import_recording(
        &self,
        Parameters(input): Parameters<ImportRecordingInput>,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let bundle_json = serde_json::json!({
            "network_passphrase": input.network_passphrase,
            "envelope_xdr_base64": input.envelope_xdr_base64,
            "result_meta_xdr_base64": input.result_meta_xdr_base64,
            "result_xdr_base64": input.result_xdr_base64,
            "ledger": input.ledger,
            "created_at_unix": input.created_at_unix,
            "successful": input.successful,
        })
        .to_string();
        let out = ozpb_toolkit::import_recording(&bundle_json, RecordOptions::default())
            .map_err(tool_err)?;
        Ok(Json(out))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PolicyBuilderServer {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Unknown methods keep the router's ordinary error; they do not spend another tool's budget.
        if self.tool_router.has_route(&request.name)
            && self
                .tool_quotas
                .as_ref()
                .is_some_and(|quotas| !quotas.admit(&request.name))
        {
            return Ok(tool_err(ToolError::new(
                ozpb_api_types::ErrorCode::EResourceLimit,
                "tool request quota exceeded; retry after the current 60-second window",
            )));
        }
        let call = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(call).await
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "OZ Accounts Policy Builder. Record a Stellar transaction, synthesize a \
             minimum-permission OpenZeppelin smart-account policy, evaluate it, run the layer-1 \
             reference suite, generate reviewable Rust, verify generated artifacts offline, and \
             optionally simulate one exact envelope with preflight_transaction. Once the \
             policies are deployed and bound, check_policy_call_surface reads, through an \
             operator-configured source, who can change the account or reset them; it is \
             advisory and never says an account is safe — the user's wallet decides. \
             prepare_install_intent runs that check itself and returns the exact \
             add_context_rule arguments only when nothing is refused and nothing is \
             unresolved. check_against_policy predicts one recognized installed rule, \
             conditional on candidate identities authenticating later; repeat the check and \
             enforce-simulate the actual authorization before signing. capture_target reads, \
             through an operator-configured source, the target state of one unsigned native \
             asset transfer for the native worker's captured-target layer; it does not run \
             that layer. Pure tools are deterministic; record_transaction, record_simulation, \
             preflight_transaction, check_policy_call_surface, prepare_install_intent, \
             check_against_policy and capture_target read Stellar RPC, and their results \
             depend on ledger state. Fail-closed: this \
             server never deploys, signs, submits, or holds keys — code-first, deploy-second. \
             Signed authorization entries given to preflight_transaction stay live \
             authorizations until they expire. Widening a grant beyond exactly what was \
             observed requires explicit user decisions.",
        )
    }
}

/// Transport is stdio by default (Claude Code, one process in the user's trust domain);
/// `--http <addr>` serves the same handler over streamable HTTP — the transport a hosted,
/// self-hostable endpoint uses (§4.6). The handler is transport-agnostic: both paths wrap
/// the identical `PolicyBuilderServer`.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry_trust = configured_registry_trust()?;
    // Parsed before the transport branch so stdio and HTTP are configured identically, and
    // fail-closed: a rejected setting stops startup rather than silently using a default.
    let build_config = ozpb_toolkit::BuildConfig::from_env()?;
    let rpc_sources = Arc::new(configured_rpc_sources()?);
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--http") => {
            let addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
            http::serve(&addr, registry_trust, rpc_sources, build_config).await
        }
        _ => {
            let service = PolicyBuilderServer::new(registry_trust, None, rpc_sources, build_config)
                .serve(rmcp::transport::stdio())
                .await?;
            service.waiting().await?;
            Ok(())
        }
    }
}

/// A configured source the allowlist does not cover would fail every request that names it;
/// a hosted server refuses to start instead, so the operator sees the mismatch, not clients.
fn require_allowlisted_sources(
    policy: &RpcEndpointPolicy,
    sources: &std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>,
) -> anyhow::Result<()> {
    for (name, source) in sources {
        policy
            .authorize(&source.rpc_url)
            .map_err(|_| anyhow::anyhow!("RPC source {name:?} is not on OZPB_RPC_ALLOWLIST"))?;
    }
    Ok(())
}

/// The operator's named RPC sources, from `OZPB_RPC_SOURCES_JSON`; none when unset.
fn configured_rpc_sources(
) -> anyhow::Result<std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>> {
    match std::env::var("OZPB_RPC_SOURCES_JSON") {
        Ok(json) => Ok(ozpb_toolkit::rpc_sources_from_json(&json).map_err(anyhow::Error::from)?),
        Err(std::env::VarError::NotPresent) => Ok(Default::default()),
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

fn configured_registry_trust() -> anyhow::Result<Option<ozpb_toolkit::RegistryTrust>> {
    let roots = std::env::var("OZPB_REGISTRY_ROOTS_JSON");
    let minimum = std::env::var("OZPB_REGISTRY_MIN_VERSION");
    match (roots, minimum) {
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => Ok(None),
        (Ok(roots), Ok(minimum)) => {
            let minimum = minimum
                .parse::<u64>()
                .map_err(|error| anyhow::anyhow!("invalid OZPB_REGISTRY_MIN_VERSION: {error}"))?;
            let mut trust = ozpb_toolkit::registry_trust_from_roots_json(&roots, minimum)
                .map_err(anyhow::Error::from)?;
            // The snapshot a request may omit. Configured separately from the roots because it
            // is data rather than trust: it is verified against those roots either way, so what
            // this decides is which snapshot is the default, never whether it is checked.
            trust.configured_snapshot = match std::env::var("OZPB_REGISTRY_SNAPSHOT_JSON") {
                Ok(raw) => Some(serde_json::from_str(&raw).map_err(|error| {
                    anyhow::anyhow!("invalid OZPB_REGISTRY_SNAPSHOT_JSON: {error}")
                })?),
                Err(std::env::VarError::NotPresent) => None,
                Err(error) => return Err(anyhow::Error::new(error)),
            };
            Ok(Some(trust))
        }
        (Err(error), _) if !matches!(error, std::env::VarError::NotPresent) => {
            Err(anyhow::Error::new(error))
        }
        (_, Err(error)) if !matches!(error, std::env::VarError::NotPresent) => {
            Err(anyhow::Error::new(error))
        }
        _ => Err(anyhow::anyhow!(
            "OZPB_REGISTRY_ROOTS_JSON and OZPB_REGISTRY_MIN_VERSION must be configured together"
        )),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A hosted server configured as `--http` configures it, with one build slot. Its builder
    /// path does not exist, so a call that got past the slot fails fast instead of compiling.
    pub(crate) fn hosted() -> PolicyBuilderServer {
        let policy = RpcEndpointPolicy::from_csv("https://rpc.allowed.example")
            .expect("valid operator allowlist");
        let build = ozpb_toolkit::BuildConfig {
            stellar_binary: std::path::PathBuf::from("/nonexistent/ozpb-not-a-builder"),
            jobs: 1,
            ..ozpb_toolkit::BuildConfig::default()
        };
        let limits = http::hosted_limits(|_| Ok(None), build, 1).expect("default hosted limits");
        PolicyBuilderServer::new(None, Some(policy), Default::default(), limits.build_config)
    }

    pub(crate) fn subscription_spec() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../docs/examples/subscription-spec.json"
        ))
        .expect("example spec JSON")
    }

    /// The structured code of a refused tool call.
    pub(crate) fn refusal_code<T>(result: Result<T, CallToolResult>) -> String {
        let Err(error) = result else {
            panic!("expected the call to be refused");
        };
        let wire = serde_json::to_value(error).expect("tool error JSON");
        wire["structuredContent"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn artifact(hash: &str) -> GenerateCodeOutput {
        GenerateCodeOutput {
            crate_name: "policy".into(),
            files: std::collections::BTreeMap::from([
                ("Cargo.lock".into(), "lock".into()),
                ("src/lib.rs".into(), "source".into()),
            ]),
            normalized_input_hash: "11".repeat(32),
            soroban_sdk_version: "sdk".into(),
            stellar_accounts_version: "accounts".into(),
            wasm_base64: "AGFzbQ==".into(),
            wasm_hash: "22".repeat(32),
            build_manifest: serde_json::json!({"manifest": hash}),
            build_manifest_hash: hash.into(),
        }
    }

    fn reference(hash: &str) -> ozpb_api_types::VerifyInput {
        ozpb_api_types::VerifyInput {
            spec: subscription_spec(),
            rule_index: 0,
            claimed_generated_files: Default::default(),
            claimed_wasm_base64: None,
            claimed_build_manifest: None,
            generated_artifact: Some(hash.into()),
        }
    }

    /// The reference becomes exactly the claim a client would have sent: every file but the
    /// lockfile, the Wasm and the manifest, with the reference itself gone.
    #[test]
    fn a_generated_artifact_reference_becomes_its_files_wasm_and_manifest() {
        let server = hosted();
        let hash = "ab".repeat(32);
        server.generated.lock().unwrap().keep(artifact(&hash));
        let mut input = reference(&hash);
        server.resolve_generated_artifact(&mut input).unwrap();
        assert_eq!(input.generated_artifact, None);
        assert_eq!(
            input.claimed_generated_files,
            std::collections::BTreeMap::from([("src/lib.rs".into(), "source".into())])
        );
        assert_eq!(input.claimed_wasm_base64.as_deref(), Some("AGFzbQ=="));
        assert_eq!(
            input.claimed_build_manifest,
            Some(serde_json::json!({"manifest": hash}))
        );
    }

    #[test]
    fn an_unknown_mixed_or_malformed_reference_is_refused() {
        let server = hosted();
        let kept = "ab".repeat(32);
        server.generated.lock().unwrap().keep(artifact(&kept));
        let mut mixed = reference(&kept);
        mixed.claimed_wasm_base64 = Some("AGFzbQ==".into());
        for (mut input, says) in [
            (reference(&"cd".repeat(32)), "generate_code again"),
            (mixed, "not both"),
            (reference("not-a-hash"), "build_manifest_hash"),
        ] {
            let error = server.resolve_generated_artifact(&mut input).unwrap_err();
            assert!(error.message.contains(says), "{}", error.message);
        }
    }

    /// Bounded: the oldest artifact is forgotten first, and regenerating one keeps one copy.
    #[test]
    fn the_session_keeps_only_its_latest_artifacts() {
        let mut kept = GeneratedArtifacts::default();
        for i in 0..=KEPT_ARTIFACTS {
            kept.keep(artifact(&format!("{i:064x}")));
        }
        kept.keep(artifact(&format!("{:064x}", KEPT_ARTIFACTS)));
        assert_eq!(kept.0.len(), KEPT_ARTIFACTS);
        assert!(kept.find(&format!("{:064x}", 0)).is_none());
        assert!(kept.find(&format!("{:064x}", 1)).is_some());
    }

    /// A hosted server serves many clients; one session cannot name another's artifact.
    #[test]
    fn hosted_sessions_do_not_share_generated_artifacts() {
        let sessions = http_session_factory(
            None,
            RpcEndpointPolicy::from_csv("https://rpc.allowed.example").unwrap(),
            Default::default(),
            hosted().build_config,
            tool_limits::ToolLimitConfig::parse(60, None).unwrap(),
        )
        .unwrap();
        let (first, second) = (sessions().unwrap(), sessions().unwrap());
        let hash = "ab".repeat(32);
        first.generated.lock().unwrap().keep(artifact(&hash));
        assert!(second
            .resolve_generated_artifact(&mut reference(&hash))
            .is_err());
        assert!(first
            .resolve_generated_artifact(&mut reference(&hash))
            .is_ok());
    }

    #[tokio::test]
    async fn hosted_generate_code_is_busy_while_every_build_slot_is_taken() {
        let server = hosted();
        let slots = server
            .build_config
            .slots
            .clone()
            .expect("hosted build slots");
        let input = || GenerateCodeInput {
            spec: subscription_spec(),
            rule_index: 0,
        };
        let running = slots.try_take().expect("the free slot");
        assert_eq!(
            refusal_code(
                server
                    .generate_code(Parameters(input()), Default::default())
                    .await
            ),
            "E_BUILD_BUSY"
        );
        drop(running);
        // Control: with the slot free the call reaches the builder, whose path does not exist,
        // and gives the slot back.
        assert_eq!(
            refusal_code(
                server
                    .generate_code(Parameters(input()), Default::default())
                    .await
            ),
            "E_BUILD_UNAVAILABLE"
        );
        assert_eq!(slots.available(), 1);
    }

    #[test]
    fn hosted_sessions_share_authority_capacity_until_work_releases_it() {
        let factory = http_session_factory(
            None,
            RpcEndpointPolicy::from_csv("https://rpc.example").unwrap(),
            Default::default(),
            hosted().build_config,
            tool_limits::ToolLimitConfig::parse(60, None).unwrap(),
        )
        .unwrap();
        let first = factory().unwrap();
        let second = factory().unwrap();
        let running_work = first
            .authority_slots
            .as_ref()
            .unwrap()
            .clone()
            .try_acquire_owned()
            .unwrap();
        // Disconnecting the first session must not free capacity still held by its work.
        drop(first);
        let slots = second.authority_slots.as_ref().unwrap();
        assert!(matches!(
            slots.try_acquire(),
            Err(tokio::sync::TryAcquireError::NoPermits)
        ));
        assert!(second
            .build_config
            .slots
            .as_ref()
            .unwrap()
            .try_take()
            .is_some());
        drop(running_work);
        assert!(slots.try_acquire().is_ok());
    }

    #[test]
    fn every_hosted_session_draws_on_the_same_build_slots() {
        let factory = http_session_factory(
            None,
            RpcEndpointPolicy::from_csv("https://rpc.example").unwrap(),
            Default::default(),
            hosted().build_config,
            tool_limits::ToolLimitConfig::parse(60, None).unwrap(),
        )
        .unwrap();
        let first = factory().unwrap();
        let second = factory().unwrap();
        let taken = first
            .build_config
            .slots
            .as_ref()
            .and_then(|slots| slots.try_take());
        assert!(taken.is_some());
        drop(first);
        assert_eq!(
            second
                .build_config
                .slots
                .as_ref()
                .map(|slots| slots.available()),
            Some(0),
            "a second session saw a free slot while the first held the only one"
        );
        assert!(second
            .authority_slots
            .as_ref()
            .unwrap()
            .try_acquire()
            .is_ok());
    }

    #[test]
    fn a_stdio_server_has_no_build_limit() {
        let server = PolicyBuilderServer::new(
            None,
            None,
            Default::default(),
            ozpb_toolkit::BuildConfig::default(),
        );
        assert!(server.build_config.slots.is_none());
        assert!(server.authority_slots.is_none());
    }

    #[test]
    fn rpc_allowlist_blocks_ssrf_vectors() {
        let policy = RpcEndpointPolicy::from_csv(
            "https://rpc.testnet.stellar.gateway.fm, https://stellar.example/rpc",
        )
        .unwrap();
        // Exact allowlisted HTTPS endpoints are authorized.
        assert!(policy
            .authorize("https://rpc.testnet.stellar.gateway.fm")
            .is_ok());
        // A host not on the allowlist is refused — including the cloud metadata endpoint,
        // the classic SSRF target.
        assert!(policy.authorize("https://evil.example/rpc").is_err());
        assert!(policy
            .authorize("https://169.254.169.254/latest/meta-data")
            .is_err());
        // Non-HTTPS, credentialed, fragment, or non-web schemes never normalize.
        assert!(policy
            .authorize("http://rpc.testnet.stellar.gateway.fm")
            .is_err());
        // Credentials are refused even against an allowlisted host — the allowlist is not a
        // substitute for stripping them.
        assert!(policy
            .authorize("https://user:pass@stellar.example/rpc")
            .is_err());
        assert!(policy
            .authorize("https://rpc.testnet.stellar.gateway.fm#frag")
            .is_err());
        assert!(policy.authorize("file:///etc/passwd").is_err());
    }

    #[test]
    fn every_configured_rpc_source_must_be_allowlisted_on_a_hosted_server() {
        let policy = RpcEndpointPolicy::from_csv("https://rpc.example").unwrap();
        let sources = |url: &str| {
            ozpb_toolkit::rpc_sources_from_json(
                &serde_json::json!({"testnet": {
                    "rpc_url": url,
                    "network_passphrase": "Test SDF Network ; September 2015"
                }})
                .to_string(),
            )
            .unwrap()
        };
        assert!(require_allowlisted_sources(&policy, &sources("https://rpc.example")).is_ok());
        assert!(require_allowlisted_sources(&policy, &sources("https://other.example")).is_err());
    }

    #[test]
    fn rpc_allowlist_must_be_nonempty_and_https() {
        assert!(RpcEndpointPolicy::from_csv("").is_err());
        assert!(RpcEndpointPolicy::from_csv("   ,  ").is_err());
        assert!(RpcEndpointPolicy::from_csv("http://insecure.example").is_err());
    }
}
