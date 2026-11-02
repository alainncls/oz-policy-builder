//! Bounded generated-policy builder and BuildManifest artifact binding.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_codegen::{GeneratedCrate, Pins};
use ozpb_domain::{domains, sha256, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use stellar_xdr::{Limited, Limits, ReadXdr, ScMetaEntry};
use wait_timeout::ChildExt;

pub mod worker;

pub const BUILD_MANIFEST_SCHEMA: &str = "build-manifest/v1";

#[derive(Clone, Debug)]
pub struct BuildRequest<'a> {
    pub generated: &'a GeneratedCrate,
    pub spec_hash: Hash32,
    pub registry_snapshot: Hash32,
    pub rule_index: usize,
    pub template_family: &'a str,
    pub pins: &'a Pins,
}

/// What the builder asserts about the tools that produced the Wasm.
///
/// Every version here is also written *into* the Wasm by those tools, as SEP-46 `contractmetav0`
/// entries: `rsver` and `rssdkver` by the SDK at compile time, `cliver` appended by
/// `stellar contract build`. The platform's spellings are the more precise ones — they carry the
/// build's git revision where ours carry a bare version — so this struct is a claim and not the
/// record of last resort, and [`reconcile_declared_toolchain`] holds it to what the artifact says
/// about itself before any of it is recorded.
///
/// **Replace this with the standard once there is a released one to replace it with.** In shape it
/// is a private spelling of **SEP-55 — Contract Build Verification** (Draft, version 0.4.1,
/// updated 2025-03-12): an assertion by the builder about how an artifact was produced. The
/// rebuild route is **SEP-58 — Contract Build Reproducibility for Verification** (Draft, version
/// 0.6.0, updated 2026-07-15), keyed on a required `source_sha256` over the bytes of a source
/// archive with an optional `source_uri` — a vocabulary still moving, since those two replaced
/// `source_repo`/`source_rev`/`tarball_url`/`tarball_sha256` in v0.4.0, and since on 16 July its
/// author was still establishing whether `--meta` has to be passed at verification time. An
/// implementation exists and no released `stellar-cli` carries it: `build --backend docker` and
/// `contract build verify` come from the `feat/reproducible-builds-via-docker` branch of
/// `stellar-cli#2525`. Our case is also outside what the SEP covers — a generated contract has no
/// source archive at all — and that question is on our agenda for `stellar-protocol#1923`.
///
/// The signal to replace it, then, is not a date: **SEP-58 leaving Draft and its support shipping
/// in a released `stellar-cli`.** Until both hold there is nothing to conform to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainIdentity {
    pub rustc_version: String,
    pub stellar_cli_version: String,
    pub builder: String,
}

/// The `builder` each [`Builder`] stamps into the manifest it produces.
///
/// Constants rather than literals at the two sites, because the reconciliation in [`manifest_for`]
/// keys its one exemption on [`BUILDER_STUB`]: a second spelling of that name is a second way for
/// a real build to be exempted by accident. Both directions fail closed — a further real builder
/// that stamps neither name is reconciled, and a renamed stub loses its exemption loudly.
///
/// Which is why the fixtures name them too. A test that spelled the exemption key out by hand would
/// keep passing through a rename of the constant while production stopped agreeing with it, so the
/// one guard against the exemption drifting would be the first thing to stop watching it.
const BUILDER_LOCAL: &str = "local-unattested";
const BUILDER_STUB: &str = "stub-hermetic";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    pub spec_hash: Hash32,
    /// Carried from the spec, which recorded the snapshot synthesis resolved against — the
    /// build does not re-resolve it. What this manifest attests is that this wasm was built
    /// from this spec; whether the spec's registry and capability references resolve against
    /// a signed snapshot is proven at synthesis (Tranche 1) and by the verification
    /// operations that resolve bindings against pinned roots (Tranche 2), never by the
    /// build step.
    pub registry_snapshot: Hash32,
    pub rule_index: u32,
    pub template_family: String,
    pub normalized_input_hash: Hash32,
    pub source_hash: Hash32,
    pub lockfile_hash: Hash32,
    pub wasm_hash: Hash32,
    pub wasm_size: u64,
    pub soroban_sdk_version: String,
    pub stellar_accounts_version: String,
    pub toolchain: ToolchainIdentity,
    pub build_args: Vec<String>,
}

impl BuildManifest {
    pub fn hash(&self) -> Result<Hash32, BuildError> {
        ozpb_domain::canonical_hash(domains::BUILD_MANIFEST, self)
            .map_err(|error| BuildError::Internal(error.to_string()))
    }
}

/// Selects how a generated crate becomes Wasm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Builder {
    /// Shell out to the pinned `stellar contract build` (production and the end-to-end
    /// test). This is the only builder that produces trustworthy, attestable Wasm.
    #[default]
    Local,
    /// A hermetic, deterministic stand-in that produces placeholder Wasm as a pure function
    /// of the generated source — WITHOUT invoking any toolchain. It exists so the toolkit's
    /// verify / binding / manifest logic can be tested without a local `stellar` install (and
    /// without cargo-lock contention under `cargo test`). It is NOT a real build; its manifest
    /// toolchain identity says `stub-hermetic` so it can never be mistaken for one.
    Stub,
}

/// Operator-configuration keys. Build configuration is **operator-side only** — never
/// request-supplied: a caller-chosen timeout is resource exhaustion and a caller-chosen
/// builder path is arbitrary execution. The CLI exposes the same keys as flags via clap's
/// `env`, so both shells read one vocabulary.
pub const ENV_BUILD_TIMEOUT_SECS: &str = "OZPB_BUILD_TIMEOUT_SECS";
pub const ENV_BUILD_CACHE_DIR: &str = "OZPB_BUILD_CACHE_DIR";
pub const ENV_BUILD_JOBS: &str = "OZPB_BUILD_JOBS";
pub const ENV_STELLAR_BINARY: &str = "OZPB_STELLAR_BINARY";
pub const ENV_BUILD_WORKER_LAUNCHER: &str = "OZPB_BUILD_WORKER_LAUNCHER";

/// How long the toolchain identity probes (`rustc --version`, `<stellar> --version`) may
/// take. Bounded for the same reason the build is: an operator-supplied binary that never
/// returns must not hang the request.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Sanity ceilings on operator input. Without them a typo fails *open*: `u64::MAX` seconds is
/// no bound at all, and a five-digit job count is a fork bomb with extra steps.
const MAX_CONFIGURABLE_TIMEOUT_SECS: u64 = 3_600;
const MAX_CONFIGURABLE_JOBS: u32 = 256;

#[derive(Clone, Debug)]
pub struct BuildConfig {
    /// Fixed operator-owned launcher for disposable builds. Never supplied by an MCP request.
    pub worker_launcher: Option<PathBuf>,
    pub stellar_binary: PathBuf,
    pub timeout: Duration,
    /// Production workers keep this true and pre-populate their dependency cache. This
    /// prevents a generated build from becoming an unbounded network/registry operation.
    /// Deliberately **not** operator-configurable: it is an egress control, not a knob.
    pub cargo_offline: bool,
    /// Operator-owned compilation cache. `None` resolves to a shared default rather than a
    /// per-build directory — see [`resolve_target_dir`].
    pub target_dir: Option<PathBuf>,
    /// Compiler parallelism (`CARGO_BUILD_JOBS`). Does not affect output bytes; cargo builds
    /// are deterministic for identical inputs regardless of job count.
    pub jobs: u32,
    /// Which builder to use. Defaults to the real `Local` subprocess build. Deliberately
    /// **not** reachable from operator configuration: `Stub` emits unattestable wasm.
    pub builder: Builder,
    /// How many builds may run at once through every clone of this configuration. `None`, the
    /// default, leaves it unbounded: the CLI runs one build per process, and a stdio server
    /// serves one caller. A hosted server sets it, because each of its sessions holds a clone.
    pub slots: Option<BuildSlots>,
    /// The requesting caller's cancellation. `None`, the default, builds until completion or
    /// timeout. Set per request on a clone of the operator's configuration, never shared.
    pub cancel: Option<BuildCancel>,
}

/// A fail-fast bound on concurrent builds. Clones share one count, so every holder of a cloned
/// [`BuildConfig`] draws from the same slots.
#[derive(Clone, Debug)]
pub struct BuildSlots {
    limit: u32,
    in_use: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

/// One taken slot, released when dropped.
#[derive(Debug)]
pub struct BuildSlot {
    in_use: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl BuildSlots {
    /// `limit` builds at once. Zero would refuse every build, so it is refused instead.
    pub fn new(limit: u32) -> Result<Self, BuildError> {
        if limit == 0 {
            return Err(BuildError::Input(
                "concurrent build limit must be positive".to_string(),
            ));
        }
        Ok(Self {
            limit,
            in_use: std::sync::Arc::default(),
        })
    }

    /// Take a slot if one is free. Never waits: a caller queued behind a running build would
    /// spend its own timeout on cargo's build-directory lock.
    pub fn try_take(&self) -> Option<BuildSlot> {
        use std::sync::atomic::Ordering;
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < self.limit).then_some(taken + 1)
            })
            .ok()
            .map(|_| BuildSlot {
                in_use: self.in_use.clone(),
            })
    }

    /// Slots not currently taken.
    pub fn available(&self) -> u32 {
        self.limit
            .saturating_sub(self.in_use.load(std::sync::atomic::Ordering::Acquire))
    }
}

impl Drop for BuildSlot {
    fn drop(&mut self) {
        self.in_use
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// How often a running build checks [`BuildCancel`]. Only a build that has a cancel hook polls;
/// without one the build waits on its timeout alone, as it always has.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// The caller's cancellation, polled while a build runs. A hosted server sets one per request
/// so that a client's cancellation (or its session ending) stops the build and frees its slot
/// instead of compiling on for the rest of the timeout. A predicate rather than a token type,
/// so this crate stays independent of the server's async runtime.
#[derive(Clone)]
pub struct BuildCancel(std::sync::Arc<dyn Fn() -> bool + Send + Sync>);

impl BuildCancel {
    pub fn new(is_cancelled: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(is_cancelled))
    }

    pub fn is_cancelled(&self) -> bool {
        (self.0)()
    }
}

impl std::fmt::Debug for BuildCancel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BuildCancel")
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            worker_launcher: None,
            stellar_binary: PathBuf::from("stellar"),
            // A real bound now that the timeout reaches the whole process group. A cold
            // dependency tree does not fit in the old 120s on ordinary hardware.
            timeout: Duration::from_secs(600),
            cargo_offline: true,
            target_dir: None,
            jobs: default_jobs(),
            builder: Builder::Local,
            slots: None,
            cancel: None,
        }
    }
}

fn default_jobs() -> u32 {
    std::thread::available_parallelism()
        .map(|available| {
            u32::try_from(available.get())
                .unwrap_or(1)
                .saturating_sub(1)
                .max(1)
        })
        .unwrap_or(1)
}

impl BuildConfig {
    /// Read operator configuration from the process environment.
    pub fn from_env() -> Result<Self, BuildError> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// Environment-independent form, so tests need no global mutation. Unrecognized keys are
    /// ignored; in particular there is no key that selects [`Builder::Stub`].
    pub fn from_env_with<F>(get: F) -> Result<Self, BuildError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config = Self::default();
        if let Some(raw) = get(ENV_BUILD_TIMEOUT_SECS) {
            config.timeout = Duration::from_secs(parse_u64(ENV_BUILD_TIMEOUT_SECS, &raw)?);
        }
        if let Some(raw) = get(ENV_BUILD_JOBS) {
            config.jobs = u32::try_from(parse_u64(ENV_BUILD_JOBS, &raw)?).unwrap_or(u32::MAX);
        }
        if let Some(raw) = get(ENV_BUILD_CACHE_DIR) {
            config.target_dir = Some(PathBuf::from(raw));
        }
        if let Some(raw) = get(ENV_STELLAR_BINARY) {
            config.stellar_binary = PathBuf::from(raw);
        }
        if let Some(raw) = get(ENV_BUILD_WORKER_LAUNCHER) {
            config.worker_launcher = Some(PathBuf::from(raw));
        }
        config.validated()
    }

    /// Enforce the operator-input invariants.
    ///
    /// Every construction path ends here — the environment reader above and the CLI's flag
    /// parser both — so a value accepted through a flag can never be one the env var would
    /// reject. Duplicating the checks per path is how the two drift apart, and an operator who
    /// finds that `--build-timeout-secs` accepts what `OZPB_BUILD_TIMEOUT_SECS` refuses has no
    /// way to tell which is authoritative.
    ///
    /// Both ends fail closed: zero disables the bound it configures, and an absurd value is no
    /// bound at all.
    pub fn validated(self) -> Result<Self, BuildError> {
        if let Some(launcher) = &self.worker_launcher {
            worker::validate_launcher(launcher)?;
        }
        let seconds = self.timeout.as_secs();
        if seconds == 0 || seconds > MAX_CONFIGURABLE_TIMEOUT_SECS {
            return Err(BuildError::Input(format!(
                "build timeout must be 1..={MAX_CONFIGURABLE_TIMEOUT_SECS} seconds, got {seconds}"
            )));
        }
        if self.jobs == 0 || self.jobs > MAX_CONFIGURABLE_JOBS {
            return Err(BuildError::Input(format!(
                "build jobs must be 1..={MAX_CONFIGURABLE_JOBS}, got {}",
                self.jobs
            )));
        }
        if self
            .target_dir
            .as_ref()
            .is_some_and(|dir| dir.as_os_str().is_empty())
        {
            return Err(BuildError::Input(
                "build cache directory must not be empty".to_string(),
            ));
        }
        if self.stellar_binary.as_os_str().is_empty() {
            return Err(BuildError::Input(
                "builder path must not be empty".to_string(),
            ));
        }
        Ok(self)
    }
}

/// Parse an integer, reporting the key. Range is enforced by [`BuildConfig::validated`], so
/// the env and flag paths cannot disagree about the bounds.
fn parse_u64(key: &str, raw: &str) -> Result<u64, BuildError> {
    raw.trim()
        .parse::<u64>()
        .map_err(|error| BuildError::Input(format!("invalid {key}: {error}")))
}

/// Where cargo's build cache lives for this build.
///
/// `None` resolves to one shared location, **not** a directory inside the per-build
/// workspace. A fresh target directory means every request recompiles `soroban-sdk` and
/// `stellar-accounts` from scratch, which is what made the timeout unreachable in practice.
/// The OS may clean the shared location; that costs one slow build.
///
/// The path is **per-uid**, and [`prepare_cache_dir`] checks its ownership and mode before
/// any build uses it. A shared, predictably named cache is otherwise a poisoning target: a
/// local actor who creates it first could point it at another directory (arbitrary write) or
/// plant dependency artifacts that cargo links into the policy wasm — and since `verify`
/// reproduces through the same cache, the reproduction would agree with the poisoned build.
///
/// The `workspace` argument is deliberately unused — it must not influence the cache.
pub fn resolve_target_dir(config: &BuildConfig, _workspace: &Path) -> PathBuf {
    config.target_dir.clone().unwrap_or_else(|| {
        #[cfg(unix)]
        let name = format!("ozpb-build-cache-{}", nix::unistd::getuid());
        #[cfg(not(unix))]
        let name = "ozpb-build-cache".to_string();
        std::env::temp_dir().join(name)
    })
}

/// Create the build cache if absent, and refuse to use one we do not exclusively own.
///
/// Fails closed on: a symlink (following it would write through to the target), a
/// non-directory, an entry owned by another uid, one that is group- or world-**writable** (the
/// poisoning vector — group *read* is not, so an ordinary `contracts/target` at 0755 is
/// accepted), or one the owner cannot write to and enter. An operator-configured directory gets
/// the same treatment as the default: the risk is a property of sharing a persistent path, not
/// of who chose it.
pub fn prepare_cache_dir(path: &Path) -> Result<(), BuildError> {
    let unusable = |reason: &str| {
        // The path itself stays out of the message: it reaches MCP clients (§6.5).
        BuildError::Unavailable(format!("build cache is unusable: {reason}"))
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(unusable(
                        "it is a symlink; following it could write outside the cache",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(unusable("it exists but is not a directory"));
                }
                if metadata.uid() != nix::unistd::getuid().as_raw() {
                    return Err(unusable("it is owned by another user"));
                }
                // Only *write* access matters: poisoning means planting an artifact, and a
                // group-readable directory (an ordinary `contracts/target` at 0755) is not a
                // route to that. Rejecting read access too would refuse legitimate
                // developer-owned caches, which is how a check gets disabled rather than fixed.
                let mode = metadata.permissions().mode();
                if mode & 0o022 != 0 {
                    return Err(unusable(
                        "it is group- or world-writable, so its artifacts are not trustworthy",
                    ));
                }
                // Owner write+execute, checked here rather than left to cargo: a read-only
                // cache (0o555) is an operator misconfiguration, and discovering it later
                // surfaces as EBuildFailed — i.e. as though the caller's spec were at fault.
                if mode & 0o300 != 0o300 {
                    return Err(unusable("the owner cannot write to and enter it"));
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| unusable(&format!("parent is unusable: {error}")))?;
                }
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(|error| unusable(&format!("could not create it: {error}")))
            }
            Err(error) => Err(unusable(&format!("could not inspect it: {error}"))),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path).map_err(|error| unusable(&format!("{error}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildArtifact {
    pub manifest: BuildManifest,
    pub manifest_hash: Hash32,
    pub wasm: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("E_BUILD_INPUT: {0}")]
    Input(String),
    #[error("E_BUILD_FAILED: {0}")]
    Failed(String),
    #[error("E_BUILD_TIMEOUT: builder exceeded its time limit")]
    Timeout,
    #[error("E_BUILD_RESOURCE_LIMIT: {0}")]
    ResourceLimit(String),
    /// The builder could not be started or configured, or the artifact it produced contradicts
    /// the toolchain the manifest would attest to ([`reconcile_declared_toolchain`]) — an operator
    /// fault, not a property of the generated crate. Kept separate from [`BuildError::Failed`] so
    /// it never reaches an agent as "your spec does not compile": a build environment whose tools
    /// are not the ones it reports is nothing the caller's spec can fix.
    #[error("E_BUILD_UNAVAILABLE: {0}")]
    Unavailable(String),
    /// Every build slot is taken. Retryable by design: the same request can succeed once a
    /// running build finishes.
    #[error("E_BUILD_BUSY: every build slot on this server is in use; retry when a running build finishes")]
    Busy,
    /// The caller cancelled the request; the build was stopped and produced nothing.
    #[error("E_CANCELLED: the request was cancelled and its build stopped")]
    Cancelled,
    #[error("internal: {0}")]
    Internal(String),
}

/// Bind a built artifact to the inputs that produced it.
///
/// This is the only place a toolchain claim becomes a record, so it is where the claim is checked:
/// [`reconcile_declared_toolchain`] refuses the build when the Wasm's own SEP-46 metadata
/// contradicts what `toolchain` asserts. [`Builder::Stub`] is exempt, and only because its
/// placeholder Wasm is not a module and carries no metadata to reconcile against.
pub fn manifest_for(
    request: &BuildRequest<'_>,
    wasm: &[u8],
    toolchain: ToolchainIdentity,
) -> Result<BuildManifest, BuildError> {
    validate_generated(request.generated)?;
    if wasm.is_empty() {
        return Err(BuildError::Input("builder produced empty Wasm".to_string()));
    }
    if wasm.len() > MAX_WASM_BYTES {
        return Err(BuildError::ResourceLimit(format!(
            "Wasm is {} bytes; maximum is {MAX_WASM_BYTES}",
            wasm.len()
        )));
    }
    let source_files: BTreeMap<&String, &String> = request
        .generated
        .files
        .iter()
        .filter(|(path, _)| path.as_str() != "Cargo.lock")
        .collect();
    let source_hash = ozpb_domain::canonical_hash(domains::GENERATED_SOURCE, &source_files)
        .map_err(|error| BuildError::Internal(error.to_string()))?;
    let lockfile = request
        .generated
        .files
        .get("Cargo.lock")
        .ok_or_else(|| BuildError::Input("generated crate has no Cargo.lock".to_string()))?;
    if toolchain.builder != BUILDER_STUB {
        reconcile_declared_toolchain(&toolchain, &request.pins.soroban_sdk, wasm)?;
    }
    Ok(BuildManifest {
        schema: BUILD_MANIFEST_SCHEMA.to_string(),
        spec_hash: request.spec_hash,
        registry_snapshot: request.registry_snapshot,
        rule_index: request
            .rule_index
            .try_into()
            .map_err(|_| BuildError::Input("rule index exceeds u32".to_string()))?,
        template_family: request.template_family.to_string(),
        normalized_input_hash: request.generated.normalized_input_hash,
        source_hash,
        // These two stay plain SHA-256 over raw bytes, deliberately, while every hash over a
        // *structure* in this crate now carries a domain.
        //
        // `wasm_hash` is not ours to define: it is the contract code hash the network computes
        // and the capability registry matches against. Domain-separating it would produce a
        // value that identifies nothing on chain.
        //
        // `lockfile_hash` is the digest of one file exactly as it sits on disk, so a reader
        // checks it with `sha256sum Cargo.lock`. Wrapping it would cost that affordance and buy
        // nothing: there is no structure here whose encoding it could be confused with.
        lockfile_hash: sha256(lockfile.as_bytes()),
        wasm_hash: sha256(wasm),
        wasm_size: wasm
            .len()
            .try_into()
            .map_err(|_| BuildError::ResourceLimit("Wasm size exceeds u64".to_string()))?,
        soroban_sdk_version: request.pins.soroban_sdk.clone(),
        stellar_accounts_version: request.pins.stellar_accounts.clone(),
        toolchain,
        build_args: BUILD_ARGS.iter().map(ToString::to_string).collect(),
    })
}

const MAX_FILES: usize = 16;
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_WASM_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 64 * 1024;
/// Cap on a recorded toolchain version string. It is hashed into the BuildManifest, so it is
/// attestation content, not a log line.
const MAX_VERSION_BYTES: usize = 256;
const BUILD_ARGS: &[&str] = &[
    "contract",
    "build",
    "--locked",
    "--optimize=false",
    "--quiet",
];

// ---------------------------------------------------------------------------------------
// Reconciling the manifest's toolchain claim against the artifact's own metadata
// ---------------------------------------------------------------------------------------

/// The Wasm custom section SEP-46 carries contract metadata in.
///
/// A build emits **two** of them rather than one extended section — the SDK writes `rsver` and
/// `rssdkver` at compile time, then `stellar contract build` appends `cliver` — so every
/// occurrence has to be read. A reader stopping at the first finds the compiler, never the CLI.
const WASM_META_SECTION: &str = "contractmetav0";

/// Wasm's fixed preamble: the magic `\0asm` and format version 1.
const WASM_PREAMBLE: [u8; 8] = *b"\0asm\x01\0\0\0";

/// Ceiling on the metadata entries read out of one Wasm. A bound on a length field that arrives
/// from a subprocess's output, not a schema limit — real artifacts carry four.
const MAX_WASM_META_ENTRIES: usize = 256;

/// A LEB128-encoded `u32`, as the Wasm binary format writes section and name lengths, with the
/// bytes it did not consume. Bounded at the five bytes a `u32` can need: unbounded, a padded
/// encoding would be allowed to run to the end of the module.
fn read_uleb128(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut value: u64 = 0;
    for (index, byte) in bytes.iter().take(5).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            let value = usize::try_from(u32::try_from(value).ok()?).ok()?;
            return Some((value, bytes.get(index + 1..)?));
        }
    }
    None
}

/// The SEP-46 metadata the toolchain wrote into `wasm`, as key -> value.
///
/// The section walk is hand-rolled rather than delegated to a Wasm parser: what is needed is a
/// walk over section headers, and the payload is XDR this workspace already decodes with its
/// pinned `stellar-xdr`. Every length is checked against the bytes actually remaining, so a
/// truncated or malformed module is an error — the alternative is an empty map, and an empty map
/// would make [`reconcile_declared_toolchain`] pass by finding nothing to disagree with.
///
/// A key that occurs twice is an error for the same reason, whether the two occurrences sit in one
/// section or one each. Reading into a map would otherwise resolve them by last-wins, and last is
/// a fact about this walk rather than about the wasm: a verifier walking the sections in another
/// order would reconcile the other value and reach the opposite verdict about identical bytes. That
/// is precisely the disagreement this check exists to surface, so it cannot be collapsed on the way
/// in — including when the two values are equal, since deciding which duplicates are harmless is a
/// judgement a gate should not be making about metadata it is here to distrust.
fn wasm_contract_meta(wasm: &[u8]) -> Result<BTreeMap<String, String>, BuildError> {
    let unreadable = |why: &str| {
        BuildError::Unavailable(format!(
            "the built wasm cannot be read for its {WASM_META_SECTION} metadata, so the \
             manifest's toolchain claim cannot be checked against it: {why}"
        ))
    };
    let mut rest = wasm
        .strip_prefix(&WASM_PREAMBLE)
        .ok_or_else(|| unreadable("it does not begin with the wasm magic and format version 1"))?;
    let mut meta = BTreeMap::new();
    while let Some((section_id, tail)) = rest.split_first() {
        let (size, tail) =
            read_uleb128(tail).ok_or_else(|| unreadable("unreadable section length"))?;
        if size > tail.len() {
            return Err(unreadable(
                "a section claims more bytes than the module has",
            ));
        }
        let (body, tail) = tail.split_at(size);
        rest = tail;
        // Only custom sections (id 0) carry a name; the rest cannot be this one.
        if *section_id != 0 {
            continue;
        }
        let (name_len, body) = read_uleb128(body)
            .ok_or_else(|| unreadable("unreadable custom-section name length"))?;
        if name_len > body.len() {
            return Err(unreadable("a custom section's name overruns the section"));
        }
        let (name, payload) = body.split_at(name_len);
        if name != WASM_META_SECTION.as_bytes() {
            continue;
        }
        let limits = Limits {
            // A `SCMetaEntry` is a union of one struct of two strings; nothing here recurses.
            depth: 8,
            len: payload.len(),
        };
        let mut reader = Limited::new(payload, limits);
        for entry in ScMetaEntry::read_xdr_iter(&mut reader) {
            if meta.len() >= MAX_WASM_META_ENTRIES {
                return Err(unreadable(&format!(
                    "more than {MAX_WASM_META_ENTRIES} metadata entries, which is this reader's \
                     own ceiling — `MAX_WASM_META_ENTRIES` in `ozpb-build-runner` — on how much of \
                     the builder's output it will accumulate, and not a limit the format places on \
                     a contract. Raise it there if a legitimate artifact has outgrown it"
                )));
            }
            match entry.map_err(|error| {
                unreadable(&format!(
                    "{WASM_META_SECTION} is not decodable XDR: {error}"
                ))
            })? {
                ScMetaEntry::ScMetaV0(entry) => {
                    let key = entry.key.to_utf8_string_lossy();
                    let value = entry.val.to_utf8_string_lossy();
                    if let Some(first) = meta.get(&key) {
                        return Err(unreadable(&format!(
                            "it states `{key}` twice, as {first:?} and as {value:?}. A key with \
                             two occurrences has no one value, so which of them is reconciled \
                             would be a property of this reader's walk order rather than of the \
                             artifact — and a verifier walking the sections differently would \
                             reach the opposite verdict about the same bytes"
                        )));
                    }
                    meta.insert(key, value);
                }
            }
        }
    }
    Ok(meta)
}

/// A tool's version and, where the value states one, the git revision it was built at.
///
/// Two spellings meet here and reduce to the same pair, which is what makes them comparable. A
/// `--version` line leads with the program name and parenthesizes the revision
/// (`stellar 27.0.0 (5a7c…)`); a `contractmetav0` value spells it `<version>#<revision>`
/// (`cliver: 27.0.0#5a7c…`) or as a bare version (`rsver: 1.91.1`).
#[derive(Debug, PartialEq, Eq)]
struct ToolIdentity<'a> {
    version: &'a str,
    revision: Option<&'a str>,
}

/// The identity inside a `--version` line, or inside a bare pinned version.
///
/// The version is the first token beginning with a digit, which skips the program name and is not
/// confused by the parenthesized revision. Returns `None` when there is no such token at all,
/// because a claim this cannot read is a claim that must not be compared and silently agreed with.
fn declared_identity(value: &str) -> Option<ToolIdentity<'_>> {
    let version = value
        .split_whitespace()
        .find(|token| token.starts_with(|first: char| first.is_ascii_digit()))?;
    let revision = value
        .split_once('(')
        .and_then(|(_, after)| after.split_once(')'))
        .and_then(|(inside, _)| inside.split_whitespace().next());
    Some(ToolIdentity { version, revision })
}

fn metadata_identity(value: &str) -> ToolIdentity<'_> {
    match value.split_once('#') {
        Some((version, revision)) => ToolIdentity {
            version,
            revision: Some(revision),
        },
        None => ToolIdentity {
            version: value,
            revision: None,
        },
    }
}

/// One field of the manifest's toolchain claim, beside the `contractmetav0` key the toolchain
/// writes the same fact under.
struct ToolchainClaim<'a> {
    /// Named as an operator reads it in the manifest JSON, so a divergence points at the line.
    field: &'a str,
    declared: &'a str,
    key: &'a str,
    /// Whether both spellings state the build's git revision at full length. Only `cliver` does:
    /// `rustc --version` abbreviates its commit and `rsver` omits it entirely, and the SDK version
    /// is a pin with no revision on our side at all. Recorded per claim rather than inferred from
    /// the values, so a release that stopped printing its revision fails here instead of quietly
    /// demoting the check to a version comparison.
    revision_is_stated: bool,
}

/// Hold the manifest's toolchain claim to what the artifact says about itself.
///
/// The manifest asserts which tools produced the Wasm; those tools wrote the same facts into the
/// Wasm. Where the two disagree the build is refused, naming the manifest field, the metadata
/// key and both values — the operator has to be able to tell which side is wrong. Absent metadata
/// is a refusal too: this exists precisely for the case of a claim with nothing behind it, so
/// finding nothing must never read as agreement.
fn reconcile_declared_toolchain(
    toolchain: &ToolchainIdentity,
    soroban_sdk_version: &str,
    wasm: &[u8],
) -> Result<(), BuildError> {
    let meta = wasm_contract_meta(wasm)?;
    for claim in [
        ToolchainClaim {
            field: "toolchain.rustc_version",
            declared: &toolchain.rustc_version,
            key: "rsver",
            revision_is_stated: false,
        },
        ToolchainClaim {
            field: "toolchain.stellar_cli_version",
            declared: &toolchain.stellar_cli_version,
            key: "cliver",
            revision_is_stated: true,
        },
        ToolchainClaim {
            field: "soroban_sdk_version",
            declared: soroban_sdk_version,
            key: "rssdkver",
            revision_is_stated: false,
        },
    ] {
        let contradiction = |what: &str, declared: &str, observed: &str| {
            BuildError::Unavailable(format!(
                "the built wasm contradicts the manifest: `{}` declares {what} {declared}, and \
                 the wasm's own `{}` says {observed}. The artifact was not produced by the tools \
                 the manifest attests to, so it must not be recorded as though it were.",
                claim.field, claim.key
            ))
        };
        let missing = |why: &str| {
            BuildError::Unavailable(format!(
                "the built wasm does not state {why}, so `{}` cannot be checked against the \
                 artifact and would be recorded on the builder's word alone.",
                claim.field
            ))
        };

        let observed = meta
            .get(claim.key)
            .map(|value| metadata_identity(value))
            .ok_or_else(|| missing(&format!("a `{}` in its {WASM_META_SECTION}", claim.key)))?;
        let declared = declared_identity(claim.declared).ok_or_else(|| {
            BuildError::Unavailable(format!(
                "`{}` is {:?}, which states no version, so there is nothing to reconcile against \
                 the wasm's `{}` of {}.",
                claim.field, claim.declared, claim.key, observed.version
            ))
        })?;

        if declared.version != observed.version {
            return Err(contradiction("version", declared.version, observed.version));
        }
        if claim.revision_is_stated {
            let (Some(declared_revision), Some(observed_revision)) =
                (declared.revision, observed.revision)
            else {
                return Err(BuildError::Unavailable(format!(
                    "the build's git revision is stated on only one side, so `{}` cannot be fully \
                     checked: it gives {:?} and the wasm's `{}` gives {:?}. Both halves of a \
                     `<version>#<revision>` are inside the hashed bytes, so agreement on the \
                     version alone does not identify the build.",
                    claim.field, declared.revision, claim.key, observed.revision
                )));
            };
            if declared_revision != observed_revision {
                return Err(contradiction(
                    "revision",
                    declared_revision,
                    observed_revision,
                ));
            }
        }
    }
    Ok(())
}

/// Build a generated crate into a manifest-bound artifact using the configured [`Builder`].
/// Production and the end-to-end test use [`Builder::Local`]; hermetic tests use
/// [`Builder::Stub`]. Every caller routes through here — `build_local` is private — so the
/// builder is a single injectable seam and no build runs outside [`BuildConfig::slots`].
pub fn build(
    request: &BuildRequest<'_>,
    config: &BuildConfig,
) -> Result<BuildArtifact, BuildError> {
    // Taken before anything else and held for the whole build. This runs on the caller's
    // thread, so the slot outlives whatever asked for the build: a server that answered the
    // request with a stream, or a client that disconnected, cannot release it early.
    let slot = match &config.slots {
        Some(slots) => Some(slots.try_take().ok_or(BuildError::Busy)?),
        None => None,
    };
    if config.worker_launcher.is_some() {
        return match worker::build(request, config) {
            Ok(result) => result,
            Err(()) => {
                // A timed-out or crashed launcher cannot prove that its container is gone.
                // Retain capacity until the operator verifies cleanup and restarts the API.
                // The runtime deadline still applies independently of this process.
                if let Some(slot) = slot {
                    std::mem::forget(slot);
                }
                Err(BuildError::Unavailable(
                    "worker cleanup is unconfirmed; operator cleanup and restart required".into(),
                ))
            }
        };
    }
    match config.builder {
        Builder::Local => build_local(request, config),
        Builder::Stub => build_stub(request),
    }
}

/// Deterministic, subprocess-free placeholder build (see [`Builder::Stub`]). The Wasm is a
/// pure function of the generated source, so regenerating the same spec reproduces
/// byte-identical Wasm — which is exactly what the toolkit's verify/binding checks compare —
/// while any source change yields different Wasm. It begins with the real Wasm magic so
/// magic-byte assertions hold, and is bound into a manifest exactly like a real build.
fn build_stub(request: &BuildRequest<'_>) -> Result<BuildArtifact, BuildError> {
    validate_generated(request.generated)?;
    let digest =
        ozpb_domain::canonical_hash(domains::GENERATED_CRATE_FILES, &request.generated.files)
            .map_err(|error| BuildError::Internal(error.to_string()))?;
    let mut wasm = b"\0asm-ozpb-stub\0".to_vec();
    wasm.extend_from_slice(digest.to_string().as_bytes());
    let toolchain = ToolchainIdentity {
        rustc_version: "stub".to_string(),
        stellar_cli_version: "stub".to_string(),
        builder: BUILDER_STUB.to_string(),
    };
    let manifest = manifest_for(request, &wasm, toolchain)?;
    let manifest_hash = manifest.hash()?;
    Ok(BuildArtifact {
        manifest,
        manifest_hash,
        wasm,
    })
}

/// Build a generated crate using fixed arguments in an isolated temporary directory. The
/// process receives no request-selected command or arguments; the output is bounded and
/// cryptographically bound into the returned manifest. `local-unattested` is deliberately
/// honest: trust requires local reproduction or a separately trusted build attestation.
fn build_local(
    request: &BuildRequest<'_>,
    config: &BuildConfig,
) -> Result<BuildArtifact, BuildError> {
    validate_generated(request.generated)?;
    let workspace = tempfile::Builder::new()
        .prefix("ozpb-build-")
        .tempdir()
        .map_err(|error| BuildError::Internal(error.to_string()))?;
    write_generated(workspace.path(), request.generated)?;
    let output_dir = workspace.path().join("out");
    std::fs::create_dir(&output_dir).map_err(|error| BuildError::Internal(error.to_string()))?;
    let target_dir = resolve_target_dir(config, workspace.path());
    prepare_cache_dir(&target_dir)?;
    let manifest_path = workspace.path().join("Cargo.toml");

    let command = build_command(
        config,
        workspace.path(),
        &manifest_path,
        &output_dir,
        &target_dir,
    );
    let output = run_bounded_until(command, config.timeout, config.cancel.as_ref())?;
    if !output.status.success() {
        return Err(BuildError::Failed(format!(
            "stellar contract build exited with {}; output: {}",
            output.status,
            String::from_utf8_lossy(&output.combined)
        )));
    }

    let expected_name = format!("{}.wasm", request.generated.crate_name.replace('-', "_"));
    let wasm_path = output_dir.join(expected_name);
    let metadata = std::fs::symlink_metadata(&wasm_path)
        .map_err(|_| BuildError::Failed("builder did not produce the expected Wasm".to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_WASM_BYTES as u64 {
        return Err(BuildError::ResourceLimit(
            "builder output is not a regular bounded Wasm file".to_string(),
        ));
    }
    let wasm =
        std::fs::read(&wasm_path).map_err(|error| BuildError::Internal(error.to_string()))?;
    let toolchain = ToolchainIdentity {
        // Both probes run from the build workspace, so they report the tools that actually
        // produced this Wasm rather than whatever the caller's directory resolves to.
        rustc_version: command_version(
            Path::new("rustc"),
            workspace.path(),
            VERSION_PROBE_TIMEOUT,
        )?,
        stellar_cli_version: command_version(
            &config.stellar_binary,
            workspace.path(),
            VERSION_PROBE_TIMEOUT,
        )?,
        // `local-unattested` names what this is, for the reason in this function's doc comment:
        // a claim a consumer can check only by re-running our own CLI. The ecosystem's answers
        // are SEP-55's attestation signed by the CI that performed the build, and SEP-58's
        // rebuild against a digest-pinned image; either would replace this string with something
        // a third party can verify without us. Both are Draft and the implementation is in no
        // released `stellar-cli`, so the signal to replace it is SEP-58 leaving Draft with
        // support in a release — see the note on `ToolchainIdentity` for the specifics.
        //
        // Meanwhile the versions beside it are not taken on trust: `manifest_for` reconciles
        // them against the `contractmetav0` the toolchain wrote into the wasm.
        builder: BUILDER_LOCAL.to_string(),
    };
    let manifest = manifest_for(request, &wasm, toolchain)?;
    let manifest_hash = manifest.hash()?;
    Ok(BuildArtifact {
        manifest,
        manifest_hash,
        wasm,
    })
}

fn validate_generated(generated: &GeneratedCrate) -> Result<(), BuildError> {
    if generated.files.len() > MAX_FILES {
        return Err(BuildError::ResourceLimit(format!(
            "generated crate has {} files; maximum is {MAX_FILES}",
            generated.files.len()
        )));
    }
    // The files a submitted crate must carry, spelled out rather than derived: this is the
    // boundary where a caller-supplied crate is checked, and the point of a boundary is to name
    // what it requires.
    //
    // `src/contract.rs` is required alongside the crate root, not optional. The root is a header
    // and a `pub mod contract;` declaration, so a crate that carries only the root passes every
    // other check here and then fails in the compiler with an unresolved module — validation
    // reporting clean on an input it cannot build.
    //
    // `rust-toolchain.toml` is required for a different and sharper reason: it is what decides
    // the compiler. `clear_inherited_toolchain_selection` removes every inherited compiler
    // selector precisely so that "the pin travelling with the source decides", and with no pin in
    // the source there is nothing left to decide — rustup falls back to whatever channel happens
    // to be the default on the machine. The build would succeed and the manifest would attest
    // that this source produced this wasm, while the same source on another machine produced a
    // different one. That is the defect the clearing exists to prevent, reached by leaving a file
    // out instead of by setting an environment variable.
    //
    // `rustfmt.toml` is deliberately absent from this list. It is shipped for a reviewer running
    // the library's own fmt gate and reaches no compiler, so a crate without it builds to the
    // same bytes.
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "src/lib.rs",
        "src/contract.rs",
    ] {
        if !generated.files.contains_key(required) {
            return Err(BuildError::Input(format!(
                "generated crate must contain Cargo.toml, Cargo.lock, rust-toolchain.toml, \
                 src/lib.rs and src/contract.rs; {required} is missing"
            )));
        }
    }
    let total = generated
        .files
        .iter()
        .try_fold(0usize, |total, (path, body)| {
            validate_relative_path(path)?;
            total.checked_add(body.len()).ok_or_else(|| {
                BuildError::ResourceLimit("generated source size overflow".to_string())
            })
        })?;
    if total > MAX_SOURCE_BYTES {
        return Err(BuildError::ResourceLimit(format!(
            "generated crate is {total} bytes; maximum is {MAX_SOURCE_BYTES}"
        )));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), BuildError> {
    if path.is_empty()
        || path.len() > 256
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BuildError::Input(format!(
            "unsafe generated file path: {path}"
        )));
    }
    Ok(())
}

fn write_generated(root: &Path, generated: &GeneratedCrate) -> Result<(), BuildError> {
    for (relative, body) in &generated.files {
        let path = root.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| BuildError::Input(format!("file has no parent: {relative}")))?;
        std::fs::create_dir_all(parent).map_err(|error| BuildError::Internal(error.to_string()))?;
        std::fs::write(path, body).map_err(|error| BuildError::Internal(error.to_string()))?;
    }
    Ok(())
}

#[derive(Debug)]
struct ProcessOutput {
    status: std::process::ExitStatus,
    /// Standard output alone. The toolchain identity probes read this, so a warning on
    /// stderr can never contaminate a value that lands in the BuildManifest.
    stdout: Vec<u8>,
    /// stdout followed by as much stderr as the shared log budget allows — the diagnostic
    /// the caller sees when a build fails.
    combined: Vec<u8>,
}

/// SIGKILL the builder's whole process group.
///
/// `stellar contract build` spawns `cargo`, which spawns `rustc` workers. Killing only the
/// direct child leaves those grandchildren running, so a timed-out build leaks compilers and
/// keeps our pipe ends open. The child is made a process-group leader before spawn, so the
/// group is exactly the build and never our own process.
#[cfg(unix)]
fn terminate_process_group(child: &std::process::Child) -> Result<(), BuildError> {
    use nix::errno::Errno;
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    let raw = i32::try_from(child.id())
        .map_err(|_| BuildError::Internal("builder pid is out of range".to_string()))?;
    match killpg(Pid::from_raw(raw), Signal::SIGKILL) {
        // ESRCH: the group already exited between the timeout and the signal.
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(errno) => Err(BuildError::Internal(format!(
            "could not terminate builder process group: {errno}"
        ))),
    }
}

/// Non-unix fallback: only the direct child is reachable without job objects, which is
/// container-era work. Recorded honestly rather than silently claiming containment.
#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) -> Result<(), BuildError> {
    child
        .kill()
        .map_err(|error| BuildError::Internal(error.to_string()))
}

fn run_bounded(command: Command, timeout: Duration) -> Result<ProcessOutput, BuildError> {
    run_bounded_until(command, timeout, None)
}

/// Wait for `child` until it exits, `timeout` passes, or `cancel` reports cancellation.
/// `Ok(None)` means it is still running and must be terminated; the flag says whether
/// cancellation, rather than the timeout, ended the wait.
fn wait_until(
    child: &mut std::process::Child,
    timeout: Duration,
    cancel: Option<&BuildCancel>,
) -> (std::io::Result<Option<std::process::ExitStatus>>, bool) {
    let Some(cancel) = cancel else {
        return (child.wait_timeout(timeout), false);
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return (Ok(None), true);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return (Ok(None), false);
        }
        match child.wait_timeout(remaining.min(CANCEL_POLL)) {
            Ok(None) => {}
            other => return (other, false),
        }
    }
}

fn run_bounded_until(
    mut command: Command,
    timeout: Duration,
    cancel: Option<&BuildCancel>,
) -> Result<ProcessOutput, BuildError> {
    // Must happen before spawn: it makes the child its own process-group leader so the
    // timeout can reach its descendants without ever signalling our own group.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        // The builder path stays out of the message: it reaches MCP clients (§6.5).
        .map_err(|error| {
            BuildError::Unavailable(format!("could not start the configured builder: {error}"))
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BuildError::Internal("builder stdout was not captured".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BuildError::Internal("builder stderr was not captured".to_string()))?;
    // Results come back over channels, not `JoinHandle::join`, so the wait for them can be
    // bounded — see the collection comment below.
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = stdout_tx.send(read_bounded(stdout));
    });
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = stderr_tx.send(read_bounded(stderr));
    });

    let (waited, cancelled) = wait_until(&mut child, timeout, cancel);
    // Terminate on timeout, on cancellation AND on a wait error: `wait_timeout` can fail before observing the
    // child (it allocates a self-pipe), and leaving the group alive there would block the
    // caller for the build's natural lifetime with nothing bounding it.
    let kill_result = if matches!(waited, Ok(None) | Err(_)) {
        #[cfg(unix)]
        let result = terminate_process_group(&child);
        #[cfg(not(unix))]
        let result = terminate_process_group(&mut child);
        let _ = child.wait();
        result
    } else {
        Ok(())
    };

    // Collect the readers with their own bound rather than an unconditional `join()`.
    //
    // The readers hold the pipe read ends. Killing the process group normally closes the
    // write ends, so this returns at once — but a descendant that left the group (its own
    // `setsid`/`setpgid`, or a wrapper script started under job control) survives `killpg`
    // and keeps a write end open. An unconditional join would then block for *that*
    // process's lifetime, turning a bounded build into an unbounded request and pinning a
    // blocking thread per event. So: wait a short grace period, and if a reader is still
    // stuck, abandon it (bounded leak) rather than hang the caller.
    let stdout_bytes = collect_reader(stdout_rx, "stdout")?;
    let stderr_bytes = collect_reader(stderr_rx, "stderr")?;
    // Propagated only after the readers are dealt with, so a kill failure (e.g. EPERM on a
    // setuid descendant) cannot skip the collection and leak descriptors.
    kill_result?;

    let status = match waited.map_err(|error| BuildError::Internal(error.to_string()))? {
        Some(status) => status,
        None if cancelled => return Err(BuildError::Cancelled),
        None => return Err(BuildError::Timeout),
    };
    let mut combined = stdout_bytes.clone();
    let remaining = MAX_LOG_BYTES.saturating_sub(combined.len());
    combined.extend_from_slice(&stderr_bytes[..stderr_bytes.len().min(remaining)]);
    Ok(ProcessOutput {
        status,
        stdout: stdout_bytes,
        combined,
    })
}

/// How long to wait for a reader thread after the process group is gone. Normally the pipe is
/// already at EOF and this returns immediately; the bound only matters when a descendant
/// escaped the group and still holds a write end.
const READER_GRACE: Duration = Duration::from_secs(5);

/// Take a reader's output, or give up on it. Giving up abandons the thread and its pipe end —
/// a bounded leak, and strictly better than blocking the caller for an escaped descendant's
/// lifetime. Log output is diagnostic, never trust-bearing, so losing it is safe.
fn collect_reader(
    receiver: std::sync::mpsc::Receiver<Result<Vec<u8>, BuildError>>,
    stream: &str,
) -> Result<Vec<u8>, BuildError> {
    match receiver.recv_timeout(READER_GRACE) {
        Ok(result) => result,
        // Disconnected: the thread died without sending, which only a panic can cause.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(BuildError::Internal(format!(
            "builder {stream} reader panicked"
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(format!(
            "[{stream} unavailable: a builder descendant outlived its process group]"
        )
        .into_bytes()),
    }
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, BuildError> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let count = reader
            .read(&mut chunk)
            .map_err(|error| BuildError::Internal(error.to_string()))?;
        if count == 0 {
            break;
        }
        let remaining = MAX_LOG_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..count.min(remaining)]);
    }
    Ok(kept)
}

/// Assemble the builder invocation.
///
/// Separated from [`build_local`] so a test can inspect the command that would run. The
/// environment this hands to the builder is part of what determines the Wasm bytes, and until it
/// was inspectable the only coverage was of a probe that runs beside the build rather than of the
/// build itself.
fn build_command(
    config: &BuildConfig,
    workspace: &Path,
    manifest_path: &Path,
    output_dir: &Path,
    target_dir: &Path,
) -> Command {
    let mut command = Command::new(&config.stellar_binary);
    sanitize_build_environment(&mut command);
    command
        .args(BUILD_ARGS)
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--out-dir")
        .arg(output_dir)
        .current_dir(workspace)
        .env("CARGO_BUILD_JOBS", config.jobs.to_string())
        .env("CARGO_TARGET_DIR", target_dir)
        .env(
            "CARGO_NET_OFFLINE",
            if config.cargo_offline {
                "true"
            } else {
                "false"
            },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    clear_inherited_toolchain_selection(&mut command);
    command
}

/// Every inherited variable that can change which compiler runs or what it emits.
///
/// Grouped by how they do it. The first group substitutes the compiler outright; the second
/// leaves the compiler alone and changes its output, which is the more insidious of the two,
/// because the version probe would keep reporting the pinned compiler truthfully while the bytes
/// came from different flags.
///
/// Each was confirmed by measurement rather than taken from documentation: the substitutions with
/// a stand-in `rustc` that announces itself, and the flag variables by hashing the artifact with
/// and without them set — every one moved the bytes at an unchanged compiler.
const INHERITED_COMPILER_SELECTORS: &[&str] = &[
    // Substitute the compiler.
    "RUSTUP_TOOLCHAIN",
    "RUSTC",
    "CARGO_BUILD_RUSTC",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    // Change what it emits.
    "RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    // Per-target form of the above. The triple is the one the generated crate declares, uppercased
    // with dashes turned into underscores — the naming rule was confirmed against the host triple.
    "CARGO_TARGET_WASM32V1_NONE_RUSTFLAGS",
    // Decides what is built at all. The builder passes the target explicitly, so removing an
    // inherited value cannot break the build; leaving it would let a caller's environment choose.
    "CARGO_BUILD_TARGET",
];

/// Drop the environment variables that select a compiler, so the generated crate's own
/// `rust-toolchain.toml` is what governs.
///
/// `RUSTUP_TOOLCHAIN` takes precedence over an override file, and cargo exports it to child
/// processes — so running `ozpb` from any cargo subprocess silently defeated the pin the
/// generated crate carries: both the build and the probe would use the ambient channel while the
/// crate declared another, and nothing would report the difference.
///
/// Clearing that one and `RUSTC` is not enough, and the shape of what was missing is worth
/// recording. Cargo accepts a second spelling for most of its configuration — `CARGO_BUILD_RUSTC`
/// for `build.rustc`, and likewise for the wrappers and flags — and those spellings are invisible
/// to a `rustc --version` probe, because the probe runs `rustc` directly and never consults
/// Cargo's configuration at all. An inherited `CARGO_BUILD_RUSTC` therefore built the Wasm with
/// one compiler while the manifest attested to another, which is exactly the defect the pin
/// exists to remove, reached through a name nobody had thought of.
///
/// [`INHERITED_COMPILER_SELECTORS`] carries the full set with the reasoning for each.
///
/// Inherited toolchain selection is not honoured on purpose: the manifest attests that *this*
/// source compiled to *this* Wasm, and that claim is only reproducible if the pin travelling with
/// the source decides the compiler.
///
/// Deliberately **not** cleared. `RUSTDOCFLAGS` reaches rustdoc only and never the Wasm.
/// `RUSTUP_HOME` and `CARGO_HOME` relocate installations rather than substitute a compiler;
/// removing them would break a legitimate non-default setup, and their failure mode is a loud
/// "toolchain not found" rather than a quietly different artifact. `CARGO` names the cargo binary
/// for build scripts and does not redirect which cargo the builder invokes — selecting a binary by
/// `PATH` is a separate problem, and one that clearing the environment cannot solve.
fn clear_inherited_toolchain_selection(command: &mut Command) {
    for name in INHERITED_COMPILER_SELECTORS {
        command.env_remove(name);
    }
}

/// Start builders and version probes with an allowlisted environment.
///
/// Generated Rust invokes third-party build scripts. Even with network access disabled, an
/// inherited environment would expose CI tokens, cloud credentials, signing material, and every
/// unrelated application secret to those processes. The allowlist contains only what rustup and
/// Cargo need to locate the pinned tools/cache plus platform temporary/certificate settings. It
/// deliberately excludes proxy variables and all compiler selectors.
fn sanitize_build_environment(command: &mut Command) {
    let original_home = std::env::var_os("HOME");
    let cargo_home = std::env::var_os("CARGO_HOME").or_else(|| {
        original_home
            .as_ref()
            .map(|home| Path::new(home).join(".cargo").into())
    });
    let rustup_home = std::env::var_os("RUSTUP_HOME").or_else(|| {
        original_home
            .as_ref()
            .map(|home| Path::new(home).join(".rustup").into())
    });

    command.env_clear();
    for name in [
        "PATH",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NIX_SSL_CERT_FILE",
        "SYSTEMROOT",
        "SystemRoot",
        "COMSPEC",
        "ComSpec",
        "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(value) = cargo_home {
        command.env("CARGO_HOME", value);
    }
    if let Some(value) = rustup_home {
        command.env("RUSTUP_HOME", value);
    }
}

/// Probe a build tool's version, **from the directory the build itself runs in**.
///
/// `from` is not optional, because getting it wrong makes the attestation lie. `rustc` is a
/// rustup shim: it resolves which real compiler to invoke by walking up from its working
/// directory looking for `rust-toolchain.toml`. The build runs with `current_dir(workspace)`,
/// where the generated crate pins a channel, so a probe run from anywhere else can report a
/// different compiler than the one that produced the Wasm — and that string is hashed into the
/// manifest identity, so the same Wasm would attest to different compilers depending on the
/// caller's working directory.
fn command_version(binary: &Path, from: &Path, timeout: Duration) -> Result<String, BuildError> {
    let mut command = Command::new(binary);
    sanitize_build_environment(&mut command);
    command
        .arg("--version")
        .current_dir(from)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    clear_inherited_toolchain_selection(&mut command);
    // Routed through run_bounded so the probe inherits the same time bound and
    // process-group containment as the build itself. A probe that never returns is an
    // operator fault, so it must not surface as `Timeout` — that would tell the agent its
    // *spec* timed out and invite it to shrink a spec that was fine.
    let output = run_bounded(command, timeout).map_err(|error| match error {
        BuildError::Timeout => BuildError::Unavailable("toolchain probe did not return".into()),
        other => other,
    })?;
    // First line only, and bounded: this value lands in the BuildManifest and is hashed into
    // its identity, so a chatty or hostile binary must not be able to write 64 KiB of
    // arbitrary bytes into the attestation record.
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !output.status.success() || version.is_empty() || version.len() > MAX_VERSION_BYTES {
        // The binary path stays out of the message: it reaches MCP clients (§6.5).
        return Err(BuildError::Unavailable(
            "toolchain version probe failed or returned an unusable version".to_string(),
        ));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::sha256;
    use std::collections::BTreeMap;

    /// A generated crate with the file set the emitter actually produces.
    ///
    /// `src/contract.rs` carries the varying part, because that is where the emitter puts it: the
    /// crate root is a header and a `pub mod contract;`. A helper that varied only the root would
    /// be exercising the one file whose content does not depend on the rule.
    fn generated(source: &str) -> GeneratedCrate {
        GeneratedCrate {
            crate_name: "generated-test-r0".to_string(),
            files: BTreeMap::from([
                ("Cargo.lock".to_string(), "lock-v1".to_string()),
                ("Cargo.toml".to_string(), "manifest-v1".to_string()),
                (
                    "src/lib.rs".to_string(),
                    "#![no_std]\n\npub mod contract;\n".to_string(),
                ),
                ("src/contract.rs".to_string(), source.to_string()),
                (
                    "rust-toolchain.toml".to_string(),
                    "[toolchain]\nchannel = \"1.91.1\"\n".to_string(),
                ),
            ]),
            normalized_input_hash: sha256(b"normalized"),
        }
    }

    /// A crate missing any file the build needs is refused at the boundary, not by rustc.
    ///
    /// Two of these were found by leaving them out and watching what happened next, and the two
    /// failure modes are different in kind.
    ///
    /// Without `src/contract.rs` the build fails in the compiler with an unresolved module — the
    /// crate root has been a header and a `pub mod contract;` since the split. Validation that
    /// reports clean on an input it cannot build is worse than no validation, because a caller
    /// reads the compiler error as a defect in their spec.
    ///
    /// Without `rust-toolchain.toml` the build **succeeds**, which is why this one matters more.
    /// `clear_inherited_toolchain_selection` strips every inherited compiler selector so that the
    /// pin travelling with the source decides the compiler; with no pin, rustup falls back to the
    /// machine's default channel and the manifest attests a wasm that another machine will not
    /// reproduce. A silent divergence in the artifact the whole pipeline exists to make
    /// verifiable.
    ///
    /// Each is asserted with the others present, so the refusal names one file rather than
    /// whichever the loop reaches first, and the complete crate is built at the end so the
    /// refusals are known to be about the file removed.
    #[test]
    fn a_generated_crate_missing_a_required_file_is_refused() {
        let pins = Pins::default();
        for required in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/lib.rs",
            "src/contract.rs",
        ] {
            let mut incomplete = generated("the contract");
            incomplete.files.remove(required);
            let request = BuildRequest {
                generated: &incomplete,
                spec_hash: sha256(b"spec"),
                registry_snapshot: sha256(b"registry"),
                rule_index: 0,
                template_family: "policy-templates/scope@1",
                pins: &pins,
            };
            match build_stub(&request) {
                Err(BuildError::Input(message)) => assert!(
                    message.contains(&format!("{required} is missing")),
                    "the refusal must name the missing file, so a caller knows which one: \
                     {message}"
                ),
                other => panic!("a crate with no {required} must be refused: {other:?}"),
            }
        }

        // Non-vacuity: the complete crate builds through the stub, so each refusal above is about
        // the file that was removed and not about the fixture.
        let complete = generated("the contract");
        let request = BuildRequest {
            generated: &complete,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        assert!(
            build_stub(&request).is_ok(),
            "the complete crate must pass, or the refusals above prove nothing"
        );
    }

    /// Every file `validate_generated` requires is one the emitter actually produces.
    ///
    /// A required file the emitter never emits would refuse every crate the tool itself generates
    /// — a boundary that rejects its own output. Read from `generate` rather than restated, so the
    /// two lists cannot be brought into disagreement by editing one of them.
    #[test]
    fn every_required_file_is_one_the_emitter_emits() {
        let generated = ozpb_codegen::generate(
            &ozpb_synthesizer::fixtures::golden_spec(),
            0,
            &ozpb_codegen::Pins::default(),
        )
        .expect("the golden spec generates");
        for required in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/lib.rs",
            "src/contract.rs",
        ] {
            assert!(
                generated.files.contains_key(required),
                "validate_generated requires {required}, which the emitter does not emit; the \
                 boundary would refuse the tool's own output"
            );
        }
    }

    #[test]
    fn manifest_hash_binds_source_wasm_lockfile_and_pipeline_inputs() {
        let pins = Pins::default();
        let first_generated = generated("source-a");
        let request = BuildRequest {
            generated: &first_generated,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        // The stub's builder name, because the wasm here is two placeholder byte strings and the
        // subject is what the manifest hash binds. Under the real builder's name `manifest_for`
        // reconciles the versions against the wasm's own metadata, which placeholders do not
        // carry — `only_the_stub_builders_placeholder_wasm_is_exempt` asserts that boundary.
        let toolchain = ToolchainIdentity {
            rustc_version: "stub".to_string(),
            stellar_cli_version: "stub".to_string(),
            builder: BUILDER_STUB.to_string(),
        };
        let first = manifest_for(&request, b"wasm-a", toolchain.clone()).unwrap();

        let second_generated = generated("source-b");
        let second_request = BuildRequest {
            generated: &second_generated,
            ..request
        };
        let source_changed = manifest_for(&second_request, b"wasm-a", toolchain.clone()).unwrap();
        let wasm_changed = manifest_for(&request, b"wasm-b", toolchain).unwrap();

        assert_ne!(first.hash().unwrap(), source_changed.hash().unwrap());
        assert_ne!(first.hash().unwrap(), wasm_changed.hash().unwrap());
    }

    #[test]
    fn unsafe_generated_paths_are_rejected_before_any_process_starts() {
        let pins = Pins::default();
        let mut hostile = generated("source");
        hostile
            .files
            .insert("../outside.rs".to_string(), "attack".to_string());
        let request = BuildRequest {
            generated: &hostile,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        assert!(matches!(
            manifest_for(
                &request,
                b"wasm",
                ToolchainIdentity {
                    rustc_version: "rustc-test".to_string(),
                    stellar_cli_version: "stellar-test".to_string(),
                    builder: BUILDER_LOCAL.to_string(),
                }
            ),
            Err(BuildError::Input(_))
        ));
    }

    // --- the manifest's toolchain claim, against the artifact's own metadata ---------------

    /// The revisions the pinned releases were built at. Both are recorded elsewhere in the tree —
    /// the CLI's in `nightly-live.yml`, read by `scripts/recorded-build-inputs.sh` — and repeated
    /// here as fixture values, because what these tests need is two *distinguishable* revisions,
    /// not the current pins.
    const CLI_REVISION: &str = "5a7c5fe76530bf4248477ac812fc757146b98cc4";
    const SDK_REVISION: &str = "48d506712f964094d14176e2f0b02afcd1054567";

    /// Minimal LEB128, as the wasm binary format writes section and name lengths.
    fn uleb128(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// An XDR `string<>`: a four-byte length, the bytes, then zero padding to a four-byte
    /// boundary.
    fn xdr_string(value: &str) -> Vec<u8> {
        let mut out = (value.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(value.as_bytes());
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    /// A wasm module carrying each group of `sections` as its own `contractmetav0` section.
    ///
    /// Encoded by hand rather than through the types the reader decodes with. Sharing an encoder
    /// would make the two sides agree by construction: a reader that mis-parses the section would
    /// be handed bytes mis-written the same way and pass regardless.
    fn wasm_with_meta(sections: &[&[(&str, &str)]]) -> Vec<u8> {
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        for entries in sections {
            let mut payload = Vec::new();
            for (key, value) in *entries {
                payload.extend_from_slice(&0u32.to_be_bytes()); // SC_META_V0
                payload.extend(xdr_string(key));
                payload.extend(xdr_string(value));
            }
            let mut body = uleb128("contractmetav0".len());
            body.extend_from_slice(b"contractmetav0");
            body.extend(payload);
            wasm.push(0); // custom-section id
            wasm.extend(uleb128(body.len()));
            wasm.extend(body);
        }
        wasm
    }

    /// The metadata a real build writes, in the **two** sections it writes them in: `rsver` and
    /// `rssdkver` by the SDK at compile time, `cliver` appended afterwards by
    /// `stellar contract build`. Measured on the golden policy, which carries exactly this shape.
    pub(crate) fn honest_wasm() -> Vec<u8> {
        let sdk = format!("28.0.0#{SDK_REVISION}");
        let cli = format!("27.0.0#{CLI_REVISION}");
        wasm_with_meta(&[
            &[("rsver", "1.91.1"), ("rssdkver", &sdk)],
            &[("cliver", &cli)],
        ])
    }

    /// What a build on the pinned toolchain probes for itself: whole `--version` lines, exactly
    /// as `command_version` returns them, against the pinned `Pins::default().soroban_sdk`.
    pub(crate) fn honest_toolchain() -> ToolchainIdentity {
        ToolchainIdentity {
            rustc_version: "rustc 1.91.1 (ed61e7d7e 2025-11-07)".to_string(),
            stellar_cli_version: format!("stellar 27.0.0 ({CLI_REVISION})"),
            builder: BUILDER_LOCAL.to_string(),
        }
    }

    fn manifest_from(
        wasm: &[u8],
        toolchain: ToolchainIdentity,
    ) -> Result<BuildManifest, BuildError> {
        let pins = Pins::default();
        let crate_files = generated("source");
        let request = BuildRequest {
            generated: &crate_files,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        manifest_for(&request, wasm, toolchain)
    }

    /// The control for every refusal below: a claim the artifact confirms is recorded.
    ///
    /// Without it, a reconciliation that refused every build would satisfy all of them.
    #[test]
    fn a_toolchain_claim_the_artifact_confirms_is_recorded() {
        let manifest = manifest_from(&honest_wasm(), honest_toolchain())
            .expect("metadata that agrees with the claim must still be recorded");
        assert_eq!(manifest.toolchain, honest_toolchain());
    }

    /// `BuildManifest` asserts which tools produced the wasm — and the toolchain writes the same
    /// facts *into* the wasm, as SEP-46 `contractmetav0` entries. So the assertion is checkable,
    /// and an assertion that can be checked and is not is worth no more than the builder's word.
    ///
    /// The seam is `manifest_for`, because that is the only place a claim becomes a record: both
    /// builders reach it and `build_local` has no other way to produce a `BuildArtifact`. A check
    /// wired into `build_local` alone could be deleted with every test still green.
    ///
    /// Not a hypothetical divergence. `the_build_command_carries_no_inherited_compiler_selection`
    /// below exists because `CARGO_BUILD_RUSTC` changes the compiler cargo invokes while leaving
    /// the probe reporting the pinned one — that gate inspects the command before the build, this
    /// one inspects the artifact after it.
    #[test]
    fn a_manifest_that_misstates_the_cli_that_built_the_wasm_is_refused() {
        let mut claimed = honest_toolchain();
        claimed.stellar_cli_version = format!("stellar 27.1.0 ({CLI_REVISION})");
        let message = manifest_from(&honest_wasm(), claimed)
            .expect_err(
                "the wasm's cliver says 27.0.0 and the manifest claims 27.1.0; recording that \
                 attests to a build that did not happen",
            )
            .to_string();
        for expected in ["stellar_cli_version", "cliver", "27.1.0", "27.0.0"] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from {message:?}: a divergence has to name the field, the \
                 metadata key and both values, or the operator cannot tell which side is wrong"
            );
        }
    }

    #[test]
    fn a_manifest_that_misstates_the_compiler_is_refused() {
        let mut claimed = honest_toolchain();
        claimed.rustc_version = "rustc 1.90.0 (0000000000 2025-01-01)".to_string();
        let message = manifest_from(&honest_wasm(), claimed)
            .expect_err("a compiler the wasm does not name must not be recorded")
            .to_string();
        for expected in ["rustc_version", "rsver", "1.90.0", "1.91.1"] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from {message:?}"
            );
        }
    }

    /// The SDK version is the one field with no probe behind it: it is copied from the pins the
    /// crate was generated against, so the wasm is the only witness of what actually compiled in.
    #[test]
    fn a_wasm_built_against_a_different_sdk_than_the_pins_is_refused() {
        let sdk = format!("26.0.0#{SDK_REVISION}");
        let cli = format!("27.0.0#{CLI_REVISION}");
        let disagrees = wasm_with_meta(&[
            &[("rsver", "1.91.1"), ("rssdkver", &sdk)],
            &[("cliver", &cli)],
        ]);
        let message = manifest_from(&disagrees, honest_toolchain())
            .expect_err("a wasm built against an unpinned SDK must not be recorded as pinned")
            .to_string();
        for expected in ["soroban_sdk_version", "rssdkver", "26.0.0", "28.0.0"] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from {message:?}"
            );
        }
    }

    /// The half of the platform's metadata ours does not have.
    ///
    /// `cliver` records `<version>#<revision>` and both halves land inside the hashed bytes, so a
    /// CLI built from a fork, a branch or a dirty tree reports the same version, a different
    /// revision, and produces a different wasm — `scripts/verify-pinned-upstream.sh` says as much
    /// about reproducing an upstream hash. Comparing versions alone would wave it through,
    /// which would leave this check weaker than the metadata it reads.
    #[test]
    fn a_cli_at_the_pinned_version_built_from_another_revision_is_refused() {
        const OTHER: &str = "0123456789abcdef0123456789abcdef01234567";
        let mut claimed = honest_toolchain();
        claimed.stellar_cli_version = format!("stellar 27.0.0 ({OTHER})");
        let message = manifest_from(&honest_wasm(), claimed)
            .expect_err("same version, different build: the artifact is not the pinned one")
            .to_string();
        for expected in ["stellar_cli_version", "cliver", OTHER, CLI_REVISION] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from {message:?}"
            );
        }
    }

    /// A revision on one side only, in both directions.
    ///
    /// This is the shape a future release could take by simply printing less, and the tempting
    /// response — compare the revision when both sides happen to state one — would silently demote
    /// the check above to a version comparison on the day that happened. So it is a refusal: which
    /// halves are compared is declared per claim, and a claim that cannot be met has to say so.
    #[test]
    fn a_revision_stated_on_only_one_side_is_refused_rather_than_skipped() {
        let sdk = format!("28.0.0#{SDK_REVISION}");
        let wasm_without_revision = wasm_with_meta(&[
            &[("rsver", "1.91.1"), ("rssdkver", &sdk)],
            &[("cliver", "27.0.0")],
        ]);
        let message = manifest_from(&wasm_without_revision, honest_toolchain())
            .expect_err("a cliver with no revision leaves the pinned build unidentified")
            .to_string();
        assert!(
            message.contains("stellar_cli_version") && message.contains("cliver"),
            "{message:?}"
        );

        let mut claimed = honest_toolchain();
        claimed.stellar_cli_version = "stellar 27.0.0".to_string();
        let message = manifest_from(&honest_wasm(), claimed)
            .expect_err("a probe that reports no revision cannot confirm the wasm's")
            .to_string();
        assert!(
            message.contains("stellar_cli_version") && message.contains("cliver"),
            "{message:?}"
        );
    }

    /// A reconciliation that passes when it finds nothing is not a reconciliation — it is the
    /// original claim with a gate's name on it. Four ways the metadata can be missing, and none of
    /// them may read as agreement.
    #[test]
    fn a_wasm_that_does_not_carry_the_metadata_cannot_be_attested() {
        let rsver_only = wasm_with_meta(&[&[("rsver", "1.91.1")]]);
        let cases: [(&str, Vec<u8>); 4] = [
            ("no metadata section at all", wasm_with_meta(&[])),
            ("only what the SDK writes, no cliver", rsver_only),
            ("not a wasm module", b"\0asm-ozpb-stub\0digest".to_vec()),
            ("a truncated section", {
                let mut truncated = honest_wasm();
                truncated.truncate(truncated.len() - 8);
                truncated
            }),
        ];
        for (label, wasm) in cases {
            assert!(
                manifest_from(&wasm, honest_toolchain()).is_err(),
                "{label}: a toolchain claim was recorded with nothing to check it against"
            );
        }
    }

    /// A key the wasm states twice is refused, not resolved.
    ///
    /// The whole point of the reconciliation is to catch a contradiction between the manifest and
    /// the artifact, so a contradiction *inside* the artifact must not be quietly collapsed on the
    /// way in. Reading the metadata into a map made that the default: the last occurrence won, and
    /// which occurrence is last is a fact about the walk order, not about the wasm. Another
    /// verifier walking the sections differently would read the other value and reach the opposite
    /// verdict about the same bytes.
    ///
    /// Every case below is a wasm whose *later* occurrence is the one that agrees with the
    /// manifest, which is exactly the shape last-wins waves through, plus one where both
    /// occurrences agree — a repeated key has no one value even when the values match, and letting
    /// that through would mean deciding, per key, which duplicates are harmless.
    ///
    /// The duplicates are written into the encoded section bytes by `wasm_with_meta`, not injected
    /// into a decoded map, because what has to be caught is what a file can actually contain: a
    /// build writes two `contractmetav0` sections, so the same key arriving twice needs no
    /// tampering at all.
    #[test]
    fn a_key_the_wasm_states_twice_is_refused_rather_than_resolved_by_walk_order() {
        let sdk = format!("28.0.0#{SDK_REVISION}");
        let cli = format!("27.0.0#{CLI_REVISION}");
        let cases: [(&str, Vec<u8>, [&str; 3]); 4] = [
            (
                "twice in one section, the agreeing value last",
                wasm_with_meta(&[
                    &[("rsver", "1.90.0"), ("rsver", "1.91.1"), ("rssdkver", &sdk)],
                    &[("cliver", &cli)],
                ]),
                ["rsver", "1.90.0", "1.91.1"],
            ),
            (
                "once per section, the agreeing value in the later one",
                wasm_with_meta(&[
                    &[("rsver", "1.90.0"), ("rssdkver", &sdk)],
                    &[("cliver", &cli), ("rsver", "1.91.1")],
                ]),
                ["rsver", "1.90.0", "1.91.1"],
            ),
            (
                "twice with the same value, which is still no single value",
                wasm_with_meta(&[
                    &[("rsver", "1.91.1"), ("rssdkver", &sdk)],
                    &[("cliver", &cli), ("rsver", "1.91.1")],
                ]),
                ["rsver", "1.91.1", "1.91.1"],
            ),
            (
                "the agreeing value first, so last-wins reports the wrong fault",
                wasm_with_meta(&[
                    &[("rsver", "1.91.1"), ("rssdkver", &sdk)],
                    &[("cliver", &cli), ("rsver", "1.90.0")],
                ]),
                ["rsver", "1.91.1", "1.90.0"],
            ),
        ];
        for (label, wasm, expected) in cases {
            let message = manifest_from(&wasm, honest_toolchain())
                .expect_err(&format!(
                    "{label}: a wasm stating one key twice was attested against whichever \
                     occurrence the walk happened to keep"
                ))
                .to_string();
            assert!(
                message.contains("twice"),
                "{label}: {message:?} reports something other than the duplication, so an \
                 operator is sent to reconcile a value the wasm does not state alone"
            );
            for named in expected {
                assert!(
                    message.contains(named),
                    "{label}: {named:?} missing from {message:?}: the refusal has to name the \
                     repeated key and both of the values it was given"
                );
            }
        }
    }

    /// The stub builder is the single exemption, and it is exempt because its placeholder wasm is
    /// not a wasm module and has no metadata to reconcile against — not because a build may skip
    /// the check. The same bytes under the real builder's name must be refused, or the exemption
    /// is a hole anything can be pushed through.
    #[test]
    fn only_the_stub_builders_placeholder_wasm_is_exempt() {
        let pins = Pins::default();
        let crate_files = generated("source");
        let request = BuildRequest {
            generated: &crate_files,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        let stub = build_stub(&request).expect("the hermetic stub must still build");
        assert_eq!(stub.manifest.toolchain.builder, BUILDER_STUB);

        let mut posing_as_real = stub.manifest.toolchain.clone();
        posing_as_real.builder = BUILDER_LOCAL.to_string();
        assert!(
            manifest_for(&request, &stub.wasm, posing_as_real).is_err(),
            "the stub's placeholder wasm was attested as a real build: the exemption is keyed on \
             the builder name, so it must not survive that name changing"
        );
    }

    /// A stub build under `slots`, so the bound is exercised without a toolchain.
    fn build_with_slots(slots: &BuildSlots) -> Result<BuildArtifact, BuildError> {
        let pins = Pins::default();
        let crate_files = generated("source");
        let request = BuildRequest {
            generated: &crate_files,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        let config = BuildConfig {
            builder: Builder::Stub,
            slots: Some(slots.clone()),
            ..BuildConfig::default()
        };
        build(&request, &config)
    }

    #[test]
    fn a_build_is_refused_as_busy_while_every_slot_is_taken() {
        let slots = BuildSlots::new(1).expect("one slot");
        let running = slots.try_take().expect("a free slot");
        assert!(
            matches!(build_with_slots(&slots), Err(BuildError::Busy)),
            "a build ran with every slot taken"
        );
        drop(running);
        build_with_slots(&slots).expect("a free slot admits the build");
        assert_eq!(slots.available(), 1, "a finished build gives its slot back");
    }

    /// The slot is held while the builder runs, not just checked on the way in. The builder is
    /// a script that marks that it started and then waits, so the slot is observed while a real
    /// subprocess build is in progress, after any early release would already have happened.
    #[test]
    #[cfg(unix)]
    fn a_running_build_holds_its_slot_until_the_builder_exits() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let script = fixture_script(
            dir.path(),
            &format!(": > {}\n/bin/sleep 2\nexit 1", started.display()),
        );
        let slots = BuildSlots::new(1).expect("one slot");
        let config = BuildConfig {
            stellar_binary: script,
            target_dir: Some(dir.path().join("cache")),
            slots: Some(slots.clone()),
            ..BuildConfig::default()
        };
        let builder = std::thread::spawn(move || {
            let pins = Pins::default();
            let crate_files = generated("source");
            let request = BuildRequest {
                generated: &crate_files,
                spec_hash: sha256(b"spec"),
                registry_snapshot: sha256(b"registry"),
                rule_index: 0,
                template_family: "policy-templates/scope@1",
                pins: &pins,
            };
            build(&request, &config)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the fake builder never started"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            slots.available(),
            0,
            "the slot was released while the builder was still running"
        );
        let result = builder.join().expect("build thread");
        assert!(
            matches!(result, Err(BuildError::Failed(_))),
            "the fake builder exits 1: {result:?}"
        );
        assert_eq!(
            slots.available(),
            1,
            "the slot came back when the build ended"
        );
    }

    #[test]
    fn clones_of_a_configuration_share_one_set_of_slots() {
        let config = BuildConfig {
            slots: Some(BuildSlots::new(1).expect("one slot")),
            ..BuildConfig::default()
        };
        let session = config.clone();
        let taken = config.slots.as_ref().and_then(BuildSlots::try_take);
        assert!(taken.is_some());
        assert!(
            session
                .slots
                .as_ref()
                .and_then(BuildSlots::try_take)
                .is_none(),
            "a clone had its own slots, so a per-session limit would be no limit"
        );
        drop(taken);
        assert_eq!(session.slots.as_ref().map(BuildSlots::available), Some(1));
    }

    #[test]
    fn a_zero_slot_limit_is_refused() {
        assert!(matches!(BuildSlots::new(0), Err(BuildError::Input(_))));
    }

    #[test]
    #[ignore = "requires the pinned Rust target, stellar-cli, and cached contract dependencies"]
    fn pinned_golden_contract_builds_to_a_manifest_bound_wasm() {
        let generated = GeneratedCrate {
            crate_name: "generated-sub-transfer-r0".to_string(),
            files: BTreeMap::from([
                (
                    "Cargo.lock".to_string(),
                    include_str!("../../../contracts/golden-transfer-policy/Cargo.lock")
                        .to_string(),
                ),
                (
                    "Cargo.toml".to_string(),
                    include_str!("../../../contracts/golden-transfer-policy/Cargo.toml")
                        .to_string(),
                ),
                (
                    "src/lib.rs".to_string(),
                    include_str!("../../../contracts/golden-transfer-policy/src/lib.rs")
                        .to_string(),
                ),
                // The contract module. The crate root is a header and a `pub mod contract;`, so
                // without this the build cannot resolve the module and the test fails in the
                // compiler rather than on anything it means to assert.
                (
                    "src/contract.rs".to_string(),
                    include_str!("../../../contracts/golden-transfer-policy/src/contract.rs")
                        .to_string(),
                ),
                (
                    "rust-toolchain.toml".to_string(),
                    include_str!("../../../contracts/golden-transfer-policy/rust-toolchain.toml")
                        .to_string(),
                ),
            ]),
            normalized_input_hash: sha256(b"golden-normalized-input"),
        };
        let pins = Pins::default();
        let request = BuildRequest {
            generated: &generated,
            spec_hash: sha256(b"golden-spec"),
            registry_snapshot: sha256(b"golden-registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        let config = BuildConfig {
            target_dir: Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/target")),
            ..BuildConfig::default()
        };
        let artifact = build_local(&request, &config).unwrap();
        assert_eq!(&artifact.wasm[..4], b"\0asm");
        assert_eq!(artifact.manifest.wasm_hash, sha256(&artifact.wasm));
        assert_eq!(artifact.manifest_hash, artifact.manifest.hash().unwrap());
    }

    /// The boundary shapes, as spec inputs. Shared by the two tests below so the case list
    /// exists once: `i128::MIN` / `i128::MAX` literals, a zero-argument tuple, an
    /// unconstrained argument, and the longest legal Soroban symbol.
    fn boundary_cases() -> Vec<(
        &'static str,
        Vec<ozpb_policy_spec::AllowedCall>,
        Vec<ozpb_policy_spec::StateSpec>,
    )> {
        use ozpb_policy_spec::{AllowedCall, ArgConstraint, Constraint, StateSpec};

        fn call(fn_name: &str, constraints: Vec<Constraint>) -> AllowedCall {
            AllowedCall {
                fn_name: fn_name.to_string(),
                args: constraints
                    .into_iter()
                    .enumerate()
                    .map(|(index, constraint)| ArgConstraint {
                        index: index as u32,
                        // Widening constraints may not claim ObservedExact provenance. And
                        // `AnyValue` — which two of these cases use — is the maximal widening,
                        // so validation demands it be acknowledged as high blast radius; a
                        // lower label is a contradiction the artifact must not carry. `High`
                        // is honest for every widening here, and a bounded widening accepts
                        // any declared radius, so one label serves all four cases.
                        provenance: if constraint.is_widening() {
                            ozpb_domain::Provenance::UserWidened {
                                intent: "boundary compile test".to_string(),
                                blast_radius: ozpb_domain::BlastRadius::High,
                            }
                        } else {
                            ozpb_domain::Provenance::ObservedExact
                        },
                        constraint,
                    })
                    .collect(),
                justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
            }
        }

        let cases: Vec<(&str, Vec<AllowedCall>, Vec<StateSpec>)> = vec![
            (
                "i128 boundaries",
                vec![call(
                    "transfer",
                    vec![
                        Constraint::EqI128 {
                            value: i128::MIN.to_string(),
                        },
                        Constraint::LeI128 {
                            max: i128::MAX.to_string(),
                        },
                    ],
                )],
                vec![StateSpec::CallCountPerInstallation { max_calls: 12 }],
            ),
            (
                "zero-arg tuple, longest symbol, no state",
                vec![call(&"a".repeat(32), vec![])],
                vec![],
            ),
            (
                // `max_calls` boundaries: 1 is the minimum validation accepts (0 is
                // rejected), u32::MAX the maximum a `u32` literal can carry.
                "unconstrained argument, single-use cap",
                vec![call("swap", vec![Constraint::AnyValue])],
                vec![StateSpec::CallCountPerInstallation { max_calls: 1 }],
            ),
            (
                "maximum per-installation cap",
                vec![call("swap", vec![Constraint::AnyValue])],
                vec![StateSpec::CallCountPerInstallation {
                    max_calls: u32::MAX,
                }],
            ),
        ];

        cases
    }

    /// One boundary case, validated. Everything up to codegen is pure, which is the half that
    /// can run anywhere.
    fn boundary_spec(
        label: &str,
        calls: Vec<ozpb_policy_spec::AllowedCall>,
        state: Vec<ozpb_policy_spec::StateSpec>,
    ) -> ozpb_policy_spec::ValidatedSpec {
        let mut spec = ozpb_synthesizer::fixtures::golden_spec().spec().clone();
        let rule = &mut spec.rules[0];
        // These cases exercise generated-source compilation, not the semantics of the golden
        // fixture's reviewed spending-limit composition. Keeping that policy while replacing
        // the transfer tuple would make validation correctly reject the fixture before any
        // boundary shape reached rustc.
        rule.policies
            .retain(|policy| matches!(policy, ozpb_policy_spec::PolicyRef::Generated { .. }));
        rule.allowed_calls = calls;
        rule.state = state;
        spec.validate()
            .unwrap_or_else(|e| panic!("{label} did not validate: {e:?}"))
    }

    /// Every boundary shape validates and reaches generated source. No toolchain, so this runs
    /// wherever the suite runs — which is the point: the case list's own conformance to the
    /// spec schema is not evidence that has to wait for a scheduled job.
    ///
    /// It exists because it was missing. When validation began demanding a high-blast-radius
    /// acknowledgement for `AnyValue`, the sibling fixtures in `codegen` were updated with the
    /// rule and this crate's were not — and nothing said so, because the only test reading them
    /// is `#[ignore]`d and runs nightly. The pull request merged green; the red arrived the next
    /// morning in a job whose header lists three plausible external causes for a failure.
    #[test]
    fn boundary_specs_validate_and_generate() {
        let pins = Pins::default();
        for (label, calls, state) in boundary_cases() {
            let spec = boundary_spec(label, calls, state);
            ozpb_codegen::generate(&spec, 0, &pins)
                .unwrap_or_else(|e| panic!("{label} did not generate: {e}"));
        }
    }

    /// The real-compile half of codegen's "always compilable" property. Codegen itself cannot
    /// dev-depend on this crate (build-runner depends on codegen, so the types would be
    /// duplicated), so the boundary shapes a parse check cannot fully vouch for are compiled
    /// here — with the real toolchain, which is why this half is `#[ignore]`d.
    #[test]
    #[ignore = "requires the pinned Rust target, stellar-cli, and cached contract dependencies"]
    fn boundary_specs_compile_to_wasm() {
        let pins = Pins::default();
        let config = BuildConfig {
            target_dir: Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/target")),
            ..BuildConfig::default()
        };
        for (label, calls, state) in boundary_cases() {
            let spec = boundary_spec(label, calls, state);
            let generated = ozpb_codegen::generate(&spec, 0, &pins)
                .unwrap_or_else(|e| panic!("{label} did not generate: {e}"));
            let request = BuildRequest {
                generated: &generated,
                spec_hash: spec.hash(),
                registry_snapshot: spec.spec().registry_snapshot,
                rule_index: 0,
                template_family: "policy-templates/scope@1",
                pins: &pins,
            };
            let artifact = build_local(&request, &config)
                .unwrap_or_else(|e| panic!("{label} did not compile: {e}"));
            assert_eq!(&artifact.wasm[..4], b"\0asm", "{label}");
        }
    }

    // --- process containment (the timeout must actually bound the build) -------------------

    /// `stellar contract build` spawns `cargo`, which spawns `rustc` workers. A bound that
    /// only reaches the direct child is not a bound at all, so these fixtures stand in for
    /// that shape: a script that backgrounds a long-lived grandchild and waits on it.
    #[cfg(unix)]
    fn fixture_script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fixture.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    fn piped(program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    #[cfg(unix)]
    fn pid_is_alive(pid: &str) -> bool {
        Command::new("kill")
            .args(["-0", pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// The process-level tests spawn children and observe process/descriptor state, so they
    /// must not run concurrently with each other: a sibling's transient pipes would show up
    /// as descriptor growth, and machine load would race the timeout against fixture startup.
    /// Not gated on Unix: the process-group tests below are Unix-only, but the toolchain probe
    /// test is not, and it needs the same serialization. Gating the helper and not its caller is
    /// what broke the Windows build of this test target.
    static PROCESS_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serialized() -> std::sync::MutexGuard<'static, ()> {
        PROCESS_TESTS.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    #[cfg(unix)]
    fn timeout_kills_the_whole_process_group_not_just_the_child() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("grandchild.pid");
        let script = fixture_script(
            dir.path(),
            &format!(
                "sleep 30 &\necho $! > {0}.tmp && mv {0}.tmp {0}\nwait",
                pidfile.display()
            ),
        );

        // Generous headroom so the fixture certainly reaches `echo` even under load; the
        // 30s sleep guarantees the timeout is what ends the build.
        assert_eq!(
            run_bounded(piped(&script), Duration::from_secs(2)).unwrap_err(),
            BuildError::Timeout
        );

        let pid = std::fs::read_to_string(&pidfile)
            .expect("fixture did not record its grandchild pid before the timeout")
            .trim()
            .to_string();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while pid_is_alive(&pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !pid_is_alive(&pid),
            "grandchild pid {pid} survived the build timeout; the bound reached only the \
             direct child, so orphaned compilers accumulate per timed-out build"
        );
    }

    #[test]
    #[cfg(unix)]
    fn repeated_timeouts_do_not_leak_reader_threads_or_pipe_descriptors() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        // The grandchild inherits the pipes, so a reader thread that is never joined keeps
        // its descriptor alive for the grandchild's whole lifetime.
        let script = fixture_script(dir.path(), "sleep 30 &\nwait");
        let open_descriptors = || std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0);
        assert!(
            open_descriptors() > 0,
            "/dev/fd is unreadable here, so this test cannot observe descriptor growth and \
             would pass vacuously"
        );

        // One warm-up timeout so first-run allocations are not counted as growth.
        let _ = run_bounded(piped(&script), Duration::from_millis(400));
        let before = open_descriptors();
        const ROUNDS: usize = 6;
        for _ in 0..ROUNDS {
            assert_eq!(
                run_bounded(piped(&script), Duration::from_millis(400)).unwrap_err(),
                BuildError::Timeout
            );
        }
        let after = open_descriptors();
        // A leak is two descriptors per round (both pipe read ends), so 12 here against a
        // slack of 4 for unrelated churn.
        assert!(
            after <= before + 4,
            "open descriptors grew {before} -> {after} across {ROUNDS} timeouts; the timeout \
             path returned without joining its reader threads, leaking each one's pipe end"
        );
    }

    #[test]
    #[cfg(unix)]
    fn cancellation_kills_the_whole_process_group_and_reports_cancelled() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("grandchild.pid");
        let script = fixture_script(
            dir.path(),
            &format!(
                "sleep 30 &\necho $! > {0}.tmp && mv {0}.tmp {0}\nwait",
                pidfile.display()
            ),
        );
        // The caller cancels as soon as the build has started its grandchild, long before the
        // 30s timeout could end it.
        let started_grandchild = pidfile.clone();
        let cancel = BuildCancel::new(move || started_grandchild.exists());
        let started = std::time::Instant::now();
        assert_eq!(
            run_bounded_until(piped(&script), Duration::from_secs(30), Some(&cancel)).unwrap_err(),
            BuildError::Cancelled
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "cancellation waited {:?}; the build ran on toward its timeout",
            started.elapsed()
        );
        let pid = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .to_string();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while pid_is_alive(&pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !pid_is_alive(&pid),
            "grandchild pid {pid} survived cancellation; only the direct child was stopped"
        );
    }

    #[test]
    #[cfg(unix)]
    fn an_uncancelled_build_with_a_cancel_hook_completes_normally() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(dir.path(), "sleep 0.3\necho done");
        let cancel = BuildCancel::new(|| false);
        let output =
            run_bounded_until(piped(&script), Duration::from_secs(10), Some(&cancel)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done\n");
    }

    #[test]
    fn a_missing_builder_binary_is_unavailable_not_a_failed_build() {
        let pins = Pins::default();
        let crate_files = generated("source");
        let request = BuildRequest {
            generated: &crate_files,
            spec_hash: sha256(b"spec"),
            registry_snapshot: sha256(b"registry"),
            rule_index: 0,
            template_family: "policy-templates/scope@1",
            pins: &pins,
        };
        let config = BuildConfig {
            stellar_binary: PathBuf::from("/nonexistent/ozpb-not-a-builder"),
            ..BuildConfig::default()
        };
        assert!(
            matches!(
                build_local(&request, &config),
                Err(BuildError::Unavailable(_))
            ),
            "an unusable builder path is an operator fault; reporting it as a build failure \
             tells the agent its spec does not compile"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_descendant_that_escapes_the_process_group_does_not_hang_the_request() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        // `setsid` puts the grandchild in its own session, so `killpg` cannot reach it — and
        // it keeps the inherited stdout write end open for its whole life. An unconditional
        // join would block here for the grandchild's lifetime; the bound must win instead.
        let script = fixture_script(
            dir.path(),
            "python3 -c 'import os,time; os.setsid(); time.sleep(60)' &\nwait",
        );
        let started = std::time::Instant::now();
        let result = run_bounded(piped(&script), Duration::from_secs(1));
        let elapsed = started.elapsed();

        assert_eq!(result.unwrap_err(), BuildError::Timeout);
        assert!(
            elapsed < Duration::from_secs(30),
            "run_bounded took {elapsed:?}: an escaped descendant held a pipe open and the \
             collection waited on it, so the timeout no longer bounds the request"
        );
    }

    /// The **build command** must carry no inherited compiler selection.
    ///
    /// The probe test below covers the probe. This covers the build, and the two are not the same
    /// path: a variable Cargo reads but `rustc` does not — `CARGO_BUILD_RUSTC` is the example that
    /// prompted this — changes the compiler the build uses while leaving the probe reporting the
    /// pinned one, so the manifest attests to a compiler that did not produce the Wasm. Inspecting
    /// the assembled command catches that without needing a toolchain to run it.
    #[test]
    fn the_build_command_carries_no_inherited_compiler_selection() {
        let dir = tempfile::tempdir().unwrap();
        let command = build_command(
            &BuildConfig::default(),
            dir.path(),
            &dir.path().join("Cargo.toml"),
            &dir.path().join("out"),
            &dir.path().join("target"),
        );

        let explicitly_carried: std::collections::BTreeSet<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_some())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();

        // Spelled out again rather than iterating `INHERITED_COMPILER_SELECTORS`. Sharing the list
        // would make this test agree with the implementation by construction: delete a name from
        // the constant and both sides forget it together, which is the failure most worth
        // catching. Duplication is the point — a name removed from the constant fails here.
        for name in [
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "CARGO_BUILD_RUSTC",
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_WASM32V1_NONE_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
        ] {
            assert!(
                !explicitly_carried.contains(name),
                "the sanitized build command explicitly carries {name}, which can change the \
                 compiler or its output while the version probe keeps reporting the pinned one"
            );
        }
        for forbidden in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "OZPB_HTTP_BEARER_TOKEN",
            "HTTP_PROXY",
            "HTTPS_PROXY",
        ] {
            assert!(
                !command
                    .get_envs()
                    .any(|(name, value)| name == forbidden && value.is_some()),
                "the sanitized build environment explicitly carries {forbidden}"
            );
        }
    }

    #[test]
    fn sanitized_builder_environment_does_not_expose_an_inherited_secret() {
        let _guard = serialized();
        const SECRET: &str = "OZPB_TEST_BUILD_SECRET";
        let previous = std::env::var_os(SECRET);
        std::env::set_var(SECRET, "must-not-reach-generated-code");
        let mut command = Command::new("env");
        sanitize_build_environment(&mut command);
        let output = command.output().unwrap();
        match previous {
            Some(value) => std::env::set_var(SECRET, value),
            None => std::env::remove_var(SECRET),
        }
        assert!(output.status.success());
        let environment = String::from_utf8_lossy(&output.stdout);
        assert!(!environment.contains(SECRET), "{environment}");
        assert!(!environment.contains("must-not-reach-generated-code"));
    }

    /// The recorded `rustc` version must come from the compiler the build would use, not from
    /// whatever the caller's directory resolves to.
    ///
    /// `rustc` is a rustup shim: it picks a real compiler by walking up from its working directory
    /// for `rust-toolchain.toml`. A generated crate pins a channel and the build runs inside that
    /// crate, so a probe run from elsewhere can attest to a compiler that never ran. Not
    /// hypothetical — with a machine default of 1.97.1 against a pin of 1.91.1, one Wasm produced
    /// two different manifest hashes depending only on the caller's directory.
    ///
    /// The assertion is deliberately negative. Pinning a channel and checking the probe reports
    /// it proves nothing here: the test process already runs inside this repository, whose own
    /// pin is that same channel, so it passes whether or not the directory is honoured. Pinning
    /// an *unresolvable* toolchain instead separates the two cases with no dependency on the
    /// ambient channel and no network access.
    #[test]
    fn the_version_probe_resolves_rustc_from_the_directory_it_is_given() {
        let _guard = serialized();
        // Without a rustup shim, `rust-toolchain.toml` means nothing and there is no property to
        // test; asserting anyway would only report the environment.
        if command_version(Path::new("rustup"), Path::new("."), VERSION_PROBE_TIMEOUT).is_err() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"ozpb-no-such-toolchain\"\n",
        )
        .unwrap();

        let probed = command_version(Path::new("rustc"), dir.path(), VERSION_PROBE_TIMEOUT);
        assert!(
            probed.is_err(),
            "probe returned {probed:?} from a directory pinning an unresolvable toolchain, so it \
             ignored the directory and read the ambient channel; the manifest would attest to a \
             compiler that did not build the Wasm"
        );

        // And an inherited selection must not win either. `RUSTUP_TOOLCHAIN` outranks an override
        // file and cargo exports it, so without clearing it every `ozpb` run started from a cargo
        // subprocess would ignore the pin the generated crate carries. Restored before asserting
        // so a failure here cannot leak into another test.
        let previous = std::env::var_os("RUSTUP_TOOLCHAIN");
        std::env::set_var("RUSTUP_TOOLCHAIN", workspace_channel_for_test());
        let with_inherited = command_version(Path::new("rustc"), dir.path(), VERSION_PROBE_TIMEOUT);
        match previous {
            Some(value) => std::env::set_var("RUSTUP_TOOLCHAIN", value),
            None => std::env::remove_var("RUSTUP_TOOLCHAIN"),
        }
        assert!(
            with_inherited.is_err(),
            "probe returned {with_inherited:?} with RUSTUP_TOOLCHAIN inherited, so an ambient \
             selection overrides the pin travelling with the generated source"
        );
    }

    /// A channel that is certainly installed: the one this workspace is built with.
    fn workspace_channel_for_test() -> String {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml"),
        )
        .expect("reading the workspace toolchain file");
        text.lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("channel")?
                    .trim_start()
                    .strip_prefix('=')
                    .map(|value| value.trim().trim_matches('"').to_string())
            })
            .expect("a declared channel")
    }

    #[test]
    #[cfg(unix)]
    fn the_toolchain_version_probe_is_bounded() {
        let _guard = serialized();
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(dir.path(), "sleep 30");
        let started = std::time::Instant::now();
        let result = command_version(&script, dir.path(), Duration::from_millis(400));
        assert!(
            result.is_err(),
            "a toolchain probe that never returns must fail, not succeed"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "command_version took {:?}; an unbounded probe hangs the whole build",
            started.elapsed()
        );
    }

    // --- target-dir resolution (the shipped path must not be cold on every build) ----------

    #[test]
    fn the_default_target_dir_is_shared_across_builds_not_per_build() {
        let config = BuildConfig::default();
        let first = resolve_target_dir(&config, Path::new("/nonexistent/workspace-a"));
        let second = resolve_target_dir(&config, Path::new("/nonexistent/workspace-b"));
        assert_eq!(
            first, second,
            "the default cache must be shared, or every build recompiles the whole \
             dependency tree from scratch inside the timeout"
        );
        assert!(
            !first.starts_with("/nonexistent/workspace-a"),
            "the default must not live inside the per-build workspace: {first:?}"
        );
    }

    // The default cache is shared and persistent, so its path is predictable and it outlives
    // any single build. That makes it a target: a local actor who wins the create race can
    // point it at a directory of their choosing (arbitrary write) or plant poisoned
    // dependency artifacts that cargo then links into the policy wasm — and because `verify`
    // reproduces through the *same* cache, the reproduction would agree with the poisoned
    // build. So the default path is per-uid and its ownership/mode are checked before use.

    #[test]
    #[cfg(unix)]
    fn the_default_cache_path_is_per_uid() {
        let path = resolve_target_dir(&BuildConfig::default(), Path::new("/nonexistent"));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.ends_with(&format!("-{}", nix::unistd::getuid())),
            "a cache path shared between users invites poisoning: {name}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_cache_directory_that_is_a_symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let planted = dir.path().join("cache");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let error = prepare_cache_dir(&planted).unwrap_err();
        assert!(
            matches!(error, BuildError::Unavailable(_)),
            "a symlinked cache must fail closed, got {error:?}"
        );
        assert!(
            !victim.join("CACHEDIR.TAG").exists(),
            "nothing may be written through the symlink"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_group_or_world_writable_cache_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for (mode, must_fail) in [
            (0o777, true),
            (0o775, true),  // group-writable
            (0o757, true),  // other-writable
            (0o755, false), // ordinary developer-owned target dir: readable, not writable
            (0o700, false),
        ] {
            let cache = dir.path().join(format!("cache-{mode:o}"));
            std::fs::create_dir(&cache).unwrap();
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(mode)).unwrap();
            let refused = matches!(prepare_cache_dir(&cache), Err(BuildError::Unavailable(_)));
            assert_eq!(
                refused, must_fail,
                "mode {mode:o}: refused={refused}, expected refused={must_fail}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_cache_directory_the_owner_cannot_use_is_refused_up_front() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Read-only (0o555) and non-enterable (0o600) are operator misconfigurations. Left to
        // cargo they surface as EBuildFailed, i.e. as though the caller's spec were at fault.
        for mode in [0o555, 0o600] {
            let cache = dir.path().join(format!("cache-{mode:o}"));
            std::fs::create_dir(&cache).unwrap();
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(mode)).unwrap();
            let refused = matches!(prepare_cache_dir(&cache), Err(BuildError::Unavailable(_)));
            // Restore before the tempdir is cleaned, or teardown cannot remove it.
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                refused,
                "mode {mode:o} must be refused as unusable by its owner"
            );
        }
    }

    #[test]
    fn flag_and_environment_configuration_agree_on_what_is_valid() {
        // The two operator paths must accept and reject exactly the same values; otherwise an
        // operator cannot tell which is authoritative. This asserts the shared validator is
        // actually shared, by driving it the way each path does.
        for (seconds, jobs, valid) in [
            (600u64, 4u32, true),
            (1, 1, true),
            (MAX_CONFIGURABLE_TIMEOUT_SECS, MAX_CONFIGURABLE_JOBS, true),
            (0, 4, false),
            (MAX_CONFIGURABLE_TIMEOUT_SECS + 1, 4, false),
            (600, 0, false),
            (600, MAX_CONFIGURABLE_JOBS + 1, false),
        ] {
            // The env path.
            let env: BTreeMap<&str, String> = BTreeMap::from([
                (ENV_BUILD_TIMEOUT_SECS, seconds.to_string()),
                (ENV_BUILD_JOBS, jobs.to_string()),
            ]);
            let from_env = BuildConfig::from_env_with(|key| env.get(key).cloned()).is_ok();
            // The flag path assigns fields directly, then validates.
            let from_flags = BuildConfig {
                timeout: Duration::from_secs(seconds),
                jobs,
                ..BuildConfig::default()
            }
            .validated()
            .is_ok();
            assert_eq!(
                from_env, valid,
                "env path disagreed for timeout={seconds} jobs={jobs}"
            );
            assert_eq!(
                from_flags, from_env,
                "flag and env paths disagreed for timeout={seconds} jobs={jobs}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_private_cache_directory_is_accepted_and_created_privately() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("nested").join("cache");
        prepare_cache_dir(&cache).expect("a fresh private cache must be accepted");
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "the cache must be created private, got {mode:o}"
        );
        // Idempotent: the second build reuses it.
        prepare_cache_dir(&cache).expect("an existing private cache must be reused");
    }

    #[test]
    fn a_configured_target_dir_overrides_the_default() {
        let config = BuildConfig {
            target_dir: Some(PathBuf::from("/operator/cache")),
            ..BuildConfig::default()
        };
        assert_eq!(
            resolve_target_dir(&config, Path::new("/nonexistent/workspace")),
            PathBuf::from("/operator/cache")
        );
    }

    // --- operator configuration (never request-supplied, never the stub builder) -----------

    #[test]
    fn operator_config_can_never_select_the_stub_builder() {
        // Every key an operator could plausibly try, including ones we do not define.
        let hostile: BTreeMap<&str, &str> = BTreeMap::from([
            ("OZPB_BUILD_BUILDER", "stub"),
            ("OZPB_BUILDER", "Stub"),
            ("OZPB_BUILD_STUB", "1"),
            (ENV_BUILD_TIMEOUT_SECS, "30"),
        ]);
        let config =
            BuildConfig::from_env_with(|key| hostile.get(key).map(|value| value.to_string()))
                .unwrap();
        assert_eq!(
            config.builder,
            Builder::Local,
            "operator configuration must never be able to serve unattestable stub wasm"
        );
    }

    #[test]
    fn operator_config_reads_the_documented_keys_and_rejects_nonsense() {
        let good: BTreeMap<&str, &str> = BTreeMap::from([
            (ENV_BUILD_TIMEOUT_SECS, "300"),
            (ENV_BUILD_CACHE_DIR, "/operator/cache"),
            (ENV_BUILD_JOBS, "3"),
            (ENV_STELLAR_BINARY, "/opt/bin/stellar"),
        ]);
        let config =
            BuildConfig::from_env_with(|key| good.get(key).map(|value| value.to_string())).unwrap();
        assert_eq!(config.timeout, Duration::from_secs(300));
        assert_eq!(config.target_dir, Some(PathBuf::from("/operator/cache")));
        assert_eq!(config.jobs, 3);
        assert_eq!(config.stellar_binary, PathBuf::from("/opt/bin/stellar"));

        for (key, value) in [
            (ENV_BUILD_TIMEOUT_SECS, "0"),
            (ENV_BUILD_TIMEOUT_SECS, "not-a-number"),
            (ENV_BUILD_JOBS, "0"),
            // Ceilings: an absurd value is no bound at all, so it must fail closed too.
            (ENV_BUILD_TIMEOUT_SECS, "18446744073709551615"),
            (ENV_BUILD_JOBS, "100000"),
        ] {
            let bad: BTreeMap<&str, &str> = BTreeMap::from([(key, value)]);
            assert!(
                BuildConfig::from_env_with(|k| bad.get(k).map(|v| v.to_string())).is_err(),
                "{key}={value} must fail closed at startup, not silently fall back"
            );
        }
    }

    #[test]
    fn an_empty_environment_yields_the_defaults() {
        let config = BuildConfig::from_env_with(|_| None).unwrap();
        assert_eq!(config.builder, Builder::Local);
        assert_eq!(config.timeout, BuildConfig::default().timeout);
        assert!(config.cargo_offline);
    }
}
