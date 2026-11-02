//! Bounded file-job protocol. Only a trusted launcher can confirm disposable-job teardown.

use super::*;
use base64::Engine;
use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

const JOB_SCHEMA: &str = "build-worker-job/v1";
const RESULT_SCHEMA: &str = "build-worker-result/v1";
const CONTAINED_SCHEMA: &str = "contained-build-result/v1";
const MAX_JOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
#[cfg(not(test))]
const LAUNCHER_GRACE: Duration = Duration::from_secs(90);
// Exercise the identical timeout path without waiting for production startup/probe grace.
#[cfg(test)]
const LAUNCHER_GRACE: Duration = Duration::from_secs(1);
/// How long a cancelled launcher has to remove its job and confirm it: the bounded container
/// removal and existence check in `deployment/worker-launcher.py` take at most 25 s.
#[cfg(not(test))]
const CANCEL_CONFIRMATION: Duration = Duration::from_secs(45);
#[cfg(test)]
const CANCEL_CONFIRMATION: Duration = Duration::from_secs(2);

/// What a launcher writes first, once its SIGTERM handler is installed. A signal that arrives
/// before then kills it, which leaves its job's removal unconfirmed and its slot retained until
/// an operator restart, so a cancellation waits for this line however long startup takes.
const LAUNCHER_READY: &[u8] = b"ready\n";

/// Ask a running launcher to stop (SIGTERM to the launcher alone, which removes its job and
/// frames that removal) once it has reported `ready`, and wait for it to exit. `None` if it is
/// not ready by `deadline` or does not exit in time.
fn request_launcher_stop(
    child: &mut std::process::Child,
    ready: &AtomicBool,
    deadline: std::time::Instant,
) -> Option<std::process::ExitStatus> {
    // It may also finish on its own before it is ready to be signalled.
    while !ready.load(Ordering::Acquire) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        if let Some(status) = child.wait_timeout(left.min(CANCEL_POLL)).ok()? {
            return Some(status);
        }
    }
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        let pid = i32::try_from(child.id()).ok()?;
        kill(Pid::from_raw(pid), Signal::SIGTERM).ok()?;
    }
    #[cfg(not(unix))]
    {
        // No graceful stop without a signal: nothing can confirm the job is gone.
        return None;
    }
    child.wait_timeout(CANCEL_CONFIRMATION).ok().flatten()
}
const FILES: [&str; 6] = [
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "src/contract.rs",
    "src/lib.rs",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobFile {
    path: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    schema: String,
    crate_name: String,
    files: Vec<JobFile>,
    timeout_seconds: u64,
    jobs: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerArtifact {
    wasm_base64: String,
    wasm_hash: Hash32,
    toolchain: ToolchainIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    schema: String,
    artifact: Option<WorkerArtifact>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainedResult {
    schema: String,
    job_hash: Hash32,
    containment: String,
    result: Option<WorkerResult>,
}

fn unavailable() -> BuildError {
    BuildError::Unavailable("disposable worker returned an invalid artifact".into())
}

/// Validate an operator executable, without exposing its path to an MCP caller.
pub(crate) fn validate_launcher(path: &Path) -> Result<(), BuildError> {
    let invalid = || {
        BuildError::Unavailable(
            "worker launcher must be an absolute, protected executable file".into(),
        )
    };
    if !path.is_absolute() {
        return Err(invalid());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = nix::unistd::getuid().as_raw();
        let protected = |metadata: &std::fs::Metadata| {
            (metadata.uid() == uid || metadata.uid() == 0)
                && metadata.permissions().mode() & 0o022 == 0
        };
        if !protected(&metadata) || metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid());
        }
        for parent in path.ancestors().skip(1) {
            // Reject every symlink ancestor. Comparing only the original and final
            // paths misses writable intermediate targets in a chain of symlinks.
            let metadata = std::fs::symlink_metadata(parent).map_err(|_| invalid())?;
            if metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            // A root-owned sticky temporary directory protects an owned private child.
            let sticky_root = metadata.uid() == 0 && metadata.permissions().mode() & 0o1000 != 0;
            if !metadata.is_dir() || (!protected(&metadata) && !sticky_root) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    Err(BuildError::Unavailable(
        "disposable worker launch requires a Unix host".into(),
    ))
}

fn validate_job(job: &Job) -> Result<GeneratedCrate, BuildError> {
    if job.schema != JOB_SCHEMA
        || job.crate_name.is_empty()
        || job.crate_name.len() > 128
        || !job
            .crate_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || !(1..=MAX_CONFIGURABLE_TIMEOUT_SECS).contains(&job.timeout_seconds)
        || !(1..=MAX_CONFIGURABLE_JOBS).contains(&job.jobs)
        || job.files.len() != FILES.len()
    {
        return Err(BuildError::Input("invalid disposable build job".into()));
    }
    let mut files = BTreeMap::new();
    let mut size = 0usize;
    for file in &job.files {
        if !FILES.contains(&file.path.as_str()) || files.contains_key(&file.path) {
            return Err(BuildError::Input(
                "worker requires exactly the generated file set".into(),
            ));
        }
        size = size
            .checked_add(file.body.len())
            .ok_or_else(|| BuildError::Input("worker source exceeds its limit".into()))?;
        if size > MAX_SOURCE_BYTES {
            return Err(BuildError::ResourceLimit(
                "worker source exceeds its limit".into(),
            ));
        }
        files.insert(file.path.clone(), file.body.clone());
    }
    Ok(GeneratedCrate {
        crate_name: job.crate_name.clone(),
        files,
        normalized_input_hash: sha256(b"worker-input"),
    })
}

/// The outer error means a launcher started but did not prove containment ended.
pub(crate) fn build(
    request: &BuildRequest<'_>,
    config: &BuildConfig,
) -> Result<Result<BuildArtifact, BuildError>, ()> {
    let job = Job {
        schema: JOB_SCHEMA.into(),
        crate_name: request.generated.crate_name.clone(),
        files: request
            .generated
            .files
            .iter()
            .map(|(path, body)| JobFile {
                path: path.clone(),
                body: body.clone(),
            })
            .collect(),
        timeout_seconds: config.timeout.as_secs(),
        jobs: config.jobs,
    };
    let prepared = (|| {
        validate_job(&job)?;
        let pins = Pins::default();
        if request.pins.rust_channel != pins.rust_channel
            || request.pins.soroban_sdk != pins.soroban_sdk
            || request.pins.stellar_accounts != pins.stellar_accounts
        {
            return Err(BuildError::Input(
                "worker requires the configured pinned toolchain".into(),
            ));
        }
        let path = config.worker_launcher.as_ref().ok_or_else(unavailable)?;
        validate_launcher(path)?;
        let data = serde_json::to_vec(&job).map_err(|_| unavailable())?;
        if data.len() > MAX_JOB_BYTES {
            return Err(BuildError::ResourceLimit(
                "worker job exceeds its limit".into(),
            ));
        }
        let mut input = tempfile::tempfile().map_err(|_| unavailable())?;
        input.write_all(&data).map_err(|_| unavailable())?;
        input.rewind().map_err(|_| unavailable())?;
        Ok((path, data, input))
    })();
    let (path, data, input) = match prepared {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    let mut command = Command::new(path);
    command
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin");
    // Rootless runtime discovery only. Never inherit API authentication, RPC or proxy secrets.
    for key in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let deadline = std::time::Instant::now() + config.timeout + LAUNCHER_GRACE;
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return Ok(Err(BuildError::Unavailable(
                "worker launcher could not start".into(),
            )))
        }
    };
    let stdout = child.stdout.take().ok_or(())?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let ready = Arc::new(AtomicBool::new(false));
    let announced = Arc::clone(&ready);
    std::thread::spawn(move || {
        let mut stdout = stdout.take((LAUNCHER_READY.len() + MAX_RESPONSE_BYTES + 1) as u64);
        let mut line = [0; LAUNCHER_READY.len()];
        let read = stdout.read_exact(&mut line).and_then(|()| {
            if line != LAUNCHER_READY {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            announced.store(true, Ordering::Release);
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let _ = sender.send(read);
    });
    // The runtime owns the actual job deadline. This adds bounded startup, probes and cleanup.
    let (status, cancelled) = wait_until(
        &mut child,
        deadline.saturating_duration_since(std::time::Instant::now()),
        config.cancel.as_ref(),
    );
    let status = match status {
        Ok(Some(status)) => status,
        // Cancelled: ask the launcher to remove its job. Killing it would leave the container's
        // fate unknown, so only its own confirmation, through the normal frame, can release
        // capacity; a launcher that does not confirm in time is treated as a dead one.
        Ok(None) if cancelled => match request_launcher_stop(&mut child, &ready, deadline) {
            Some(status) => status,
            None => {
                #[cfg(unix)]
                let _ = terminate_process_group(&child);
                #[cfg(not(unix))]
                let _ = terminate_process_group(&mut child);
                let _ = child.kill();
                let _ = child.wait();
                return Err(());
            }
        },
        _ => {
            #[cfg(unix)]
            let _ = terminate_process_group(&child);
            #[cfg(not(unix))]
            let _ = terminate_process_group(&mut child);
            let _ = child.kill();
            let _ = child.wait();
            return Err(());
        }
    };
    let bytes = receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if !status.success() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    let frame: ContainedResult = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if frame.schema != CONTAINED_SCHEMA
        || frame.job_hash != sha256(&data)
        || frame.containment != "removed"
    {
        return Err(());
    }
    // After trusted confirmation, malformed compiler output is an ordinary failed job.
    Ok((|| {
        let result = frame.result.ok_or_else(|| {
            if cancelled {
                BuildError::Cancelled
            } else {
                BuildError::Failed("disposable compilation failed".into())
            }
        })?;
        if result.schema != RESULT_SCHEMA {
            return Err(unavailable());
        }
        let artifact = result
            .artifact
            .ok_or_else(|| BuildError::Failed("disposable compilation failed".into()))?;
        if artifact.toolchain.builder != BUILDER_LOCAL
            || artifact.toolchain.rustc_version.len() > MAX_VERSION_BYTES
            || artifact.toolchain.stellar_cli_version.len() > MAX_VERSION_BYTES
            || declared_identity(&artifact.toolchain.rustc_version)
                .is_none_or(|identity| identity.version != request.pins.rust_channel)
        {
            return Err(unavailable());
        }
        let wasm = base64::engine::general_purpose::STANDARD
            .decode(artifact.wasm_base64)
            .map_err(|_| unavailable())?;
        if wasm.len() > MAX_WASM_BYTES || sha256(&wasm) != artifact.wasm_hash {
            return Err(unavailable());
        }
        let manifest =
            manifest_for(request, &wasm, artifact.toolchain).map_err(|_| unavailable())?;
        let manifest_hash = manifest.hash().map_err(|_| unavailable())?;
        Ok(BuildArtifact {
            manifest,
            manifest_hash,
            wasm,
        })
    })())
}

/// Execute one job inside an already isolated container. This does not create isolation.
/// Errors contain no compiler output, request text, paths or credentials.
pub fn serve_one(mut input: impl Read, mut output: impl Write) -> Result<(), BuildError> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > MAX_JOB_BYTES {
        return Err(BuildError::Input("worker job exceeds its limit".into()));
    }
    let job: Job = serde_json::from_slice(&bytes)
        .map_err(|_| BuildError::Input("invalid disposable build job".into()))?;
    let generated = validate_job(&job)?;
    let pins = Pins::default();
    let request = BuildRequest {
        generated: &generated,
        spec_hash: sha256(&bytes),
        registry_snapshot: sha256(b"worker"),
        rule_index: 0,
        template_family: "worker",
        pins: &pins,
    };
    let config = BuildConfig {
        timeout: Duration::from_secs(job.timeout_seconds),
        jobs: job.jobs,
        target_dir: Some(std::env::temp_dir().join("target")),
        ..BuildConfig::default()
    };
    let result = WorkerResult {
        schema: RESULT_SCHEMA.into(),
        artifact: build_local(&request, &config)
            .ok()
            .map(|artifact| WorkerArtifact {
                wasm_hash: sha256(&artifact.wasm),
                wasm_base64: base64::engine::general_purpose::STANDARD.encode(artifact.wasm),
                toolchain: artifact.manifest.toolchain,
            }),
    };
    let response = serde_json::to_vec(&result).map_err(|_| unavailable())?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(unavailable());
    }
    output.write_all(&response).map_err(|_| unavailable())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn generated() -> GeneratedCrate {
        GeneratedCrate {
            crate_name: "fixture-policy".into(),
            files: FILES
                .iter()
                .map(|path| (path.to_string(), "fixture".into()))
                .collect(),
            normalized_input_hash: sha256(b"fixture"),
        }
    }

    fn run(generated: &GeneratedCrate, config: &BuildConfig) -> Result<BuildArtifact, BuildError> {
        super::super::build(
            &BuildRequest {
                generated,
                spec_hash: sha256(b"spec"),
                registry_snapshot: sha256(b"registry"),
                rule_index: 0,
                template_family: "fixture",
                pins: &Pins::default(),
            },
            config,
        )
    }

    /// Reports the launcher ready, as `deployment/worker-launcher.py` does on startup.
    const ANNOUNCE: &str = r"import sys
sys.stdout.write('ready\n')
sys.stdout.flush()
";

    /// A launcher that announces itself ready before running `body`.
    fn launcher(body: &str) -> (tempfile::TempDir, BuildConfig, BuildSlots) {
        script(&format!("{ANNOUNCE}{body}"))
    }

    /// A launcher that runs `body` alone, which writes its own ready line, or never does.
    fn script(body: &str) -> (tempfile::TempDir, BuildConfig, BuildSlots) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().canonicalize().unwrap().join("launcher");
        std::fs::write(&path, format!("#!/usr/bin/python3\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let slots = BuildSlots::new(1).unwrap();
        let config = BuildConfig {
            worker_launcher: Some(path),
            slots: Some(slots.clone()),
            timeout: Duration::from_secs(10),
            ..BuildConfig::default()
        };
        (directory, config, slots)
    }

    const CONFIRMED_FAILURE: &str = r#"import hashlib,json,sys
data=sys.stdin.buffer.read()
print(json.dumps({'schema':'contained-build-result/v1','job_hash':hashlib.sha256(data).hexdigest(),'containment':'removed','result':None}))"#;

    #[test]
    fn confirmed_compilation_failure_releases_capacity() {
        let (_directory, config, slots) = launcher(CONFIRMED_FAILURE);
        assert!(matches!(
            run(&generated(), &config),
            Err(BuildError::Failed(_))
        ));
        assert_eq!(slots.available(), 1);
        assert!(matches!(
            run(&generated(), &config),
            Err(BuildError::Failed(_))
        ));
    }

    #[test]
    fn malformed_launcher_frame_poisons_capacity_and_redacts_its_contents() {
        let (_directory, config, slots) = launcher("print('SOURCE-SECRET-CANARY')");
        let error = run(&generated(), &config).unwrap_err();
        assert!(!error.to_string().contains("SOURCE-SECRET-CANARY"));
        assert!(error.to_string().contains("cleanup is unconfirmed"));
        assert_eq!(slots.available(), 0);
        assert_eq!(run(&generated(), &config), Err(BuildError::Busy));
    }

    #[test]
    fn launcher_death_cannot_claim_cleanup() {
        let (_directory, config, slots) =
            launcher("import os,signal\nos.kill(os.getpid(),signal.SIGKILL)");
        assert!(run(&generated(), &config).is_err());
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn launcher_timeout_retains_capacity_until_operator_restart() {
        let (_directory, mut config, slots) = launcher("import time\ntime.sleep(30)");
        config.timeout = Duration::from_secs(1);
        let start = std::time::Instant::now();
        assert!(run(&generated(), &config).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(slots.available(), 0);
    }

    /// A launcher that, like `deployment/worker-launcher.py`, reports ready once its SIGTERM
    /// handler is installed and answers SIGTERM by removing its job and confirming that removal
    /// with no result. Run it with `script`.
    const CANCELLABLE: &str = r#"import hashlib,json,signal,sys,time
data=sys.stdin.buffer.read()
def stop(*_):
    print(json.dumps({'schema':'contained-build-result/v1','job_hash':hashlib.sha256(data).hexdigest(),'containment':'removed','result':None}))
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
sys.stdout.write('ready\n')
sys.stdout.flush()
time.sleep(30)"#;

    fn cancelled_after(delay: Duration) -> BuildCancel {
        let start = std::time::Instant::now();
        BuildCancel::new(move || start.elapsed() >= delay)
    }

    #[test]
    fn cancelled_build_with_confirmed_cleanup_releases_capacity() {
        let (_directory, mut config, slots) = script(CANCELLABLE);
        config.timeout = Duration::from_secs(30);
        config.cancel = Some(cancelled_after(Duration::from_millis(300)));
        let start = std::time::Instant::now();
        assert_eq!(run(&generated(), &config), Err(BuildError::Cancelled));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(slots.available(), 1, "the launcher confirmed removal");
    }

    #[test]
    fn an_immediate_cancellation_waits_for_a_slow_launcher_to_report_ready() {
        // Takes three seconds to install its handler, like an interpreter on a loaded host; a
        // SIGTERM before then would kill it and strand the slot.
        let slow = CANCELLABLE.replace(
            "import hashlib",
            "import time\ntime.sleep(3)\nimport hashlib",
        );
        let (_directory, mut config, slots) = script(&slow);
        config.timeout = Duration::from_secs(30);
        config.cancel = Some(BuildCancel::new(|| true));
        assert_eq!(run(&generated(), &config), Err(BuildError::Cancelled));
        assert_eq!(
            slots.available(),
            1,
            "the launcher lived to confirm removal"
        );
    }

    #[test]
    fn a_launcher_that_never_reports_ready_cannot_release_capacity() {
        let (_directory, config, slots) = script(CONFIRMED_FAILURE);
        assert!(run(&generated(), &config).is_err());
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn a_cancelled_launcher_that_is_never_ready_retains_capacity() {
        let (_directory, mut config, slots) = script("import time\ntime.sleep(30)");
        config.timeout = Duration::from_secs(1);
        config.cancel = Some(BuildCancel::new(|| true));
        let start = std::time::Instant::now();
        assert!(run(&generated(), &config).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn cancelled_build_without_confirmed_cleanup_retains_capacity() {
        // Ignores SIGTERM, so nothing confirms that its job is gone.
        let (_directory, mut config, slots) = launcher(
            "import signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)",
        );
        config.timeout = Duration::from_secs(30);
        config.cancel = Some(cancelled_after(Duration::from_millis(300)));
        let start = std::time::Instant::now();
        assert!(run(&generated(), &config).is_err());
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn excess_launcher_output_is_bounded_and_retains_capacity() {
        let (_directory, config, slots) =
            launcher("import sys\nsys.stdout.write('x' * (5 * 1024 * 1024))");
        assert!(run(&generated(), &config).is_err());
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn input_rejection_before_launch_does_not_lose_a_slot() {
        let (_directory, config, slots) = launcher("raise RuntimeError('must not run')");
        let mut input = generated();
        input.files.remove("rustfmt.toml");
        input.files.insert("../../secret".into(), "body".into());
        assert!(matches!(run(&input, &config), Err(BuildError::Input(_))));
        assert_eq!(slots.available(), 1);
    }

    #[test]
    fn launcher_cannot_exempt_real_artifacts_as_stub_builds() {
        let body = CONFIRMED_FAILURE.replace("'result':None", "'result':{'schema':'build-worker-result/v1','artifact':{'wasm_base64':'AGFzbQEAAAA=','wasm_hash':'0000000000000000000000000000000000000000000000000000000000000000','toolchain':{'builder':'stub-hermetic','rustc_version':'stub','stellar_cli_version':'stub'}}}");
        let (_directory, config, slots) = launcher(&body);
        assert!(matches!(
            run(&generated(), &config),
            Err(BuildError::Unavailable(_))
        ));
        assert_eq!(slots.available(), 1, "trusted launcher did confirm cleanup");
    }

    fn artifact_launcher(wasm: &[u8], toolchain: ToolchainIdentity, digest: Hash32) -> String {
        let result = serde_json::to_string(&WorkerResult {
            schema: RESULT_SCHEMA.into(),
            artifact: Some(WorkerArtifact {
                wasm_base64: base64::engine::general_purpose::STANDARD.encode(wasm),
                wasm_hash: digest,
                toolchain,
            }),
        })
        .unwrap();
        let quoted = serde_json::to_string(&result).unwrap();
        CONFIRMED_FAILURE.replace("'result':None", &format!("'result':json.loads({quoted})"))
    }

    #[test]
    fn valid_worker_artifact_reconstructs_the_api_manifest_and_releases_capacity() {
        let wasm = crate::tests::honest_wasm();
        let tools = crate::tests::honest_toolchain();
        let body = artifact_launcher(&wasm, tools.clone(), sha256(&wasm));
        let (_directory, config, slots) = launcher(&body);
        let generated = generated();
        let artifact = run(&generated, &config).unwrap();
        assert_eq!(artifact.wasm, wasm);
        let manifest = &artifact.manifest;
        assert_eq!(manifest.schema, BUILD_MANIFEST_SCHEMA);
        assert_eq!(manifest.spec_hash, sha256(b"spec"));
        assert_eq!(manifest.registry_snapshot, sha256(b"registry"));
        assert_eq!(manifest.rule_index, 0);
        assert_eq!(manifest.template_family, "fixture");
        assert_eq!(
            manifest.normalized_input_hash,
            generated.normalized_input_hash
        );
        assert_eq!(manifest.lockfile_hash, sha256(b"fixture"));
        assert_eq!(manifest.wasm_hash, sha256(&wasm));
        assert_eq!(manifest.wasm_size, wasm.len() as u64);
        assert_eq!(manifest.toolchain, tools);
        assert_eq!(manifest.soroban_sdk_version, Pins::default().soroban_sdk);
        assert_eq!(artifact.manifest_hash, manifest.hash().unwrap());
        assert_eq!(slots.available(), 1);
        assert_eq!(run(&generated, &config).unwrap(), artifact);
    }

    #[test]
    fn bad_digest_and_metadata_claims_release_capacity_after_confirmed_cleanup() {
        let wasm = crate::tests::honest_wasm();
        for corrupt_digest in [true, false] {
            let mut tools = crate::tests::honest_toolchain();
            let digest = if corrupt_digest {
                sha256(b"wrong artifact")
            } else {
                tools.stellar_cli_version = "stellar 99.0.0 (0000000000)".into();
                sha256(&wasm)
            };
            let body = artifact_launcher(&wasm, tools, digest);
            let (_directory, config, slots) = launcher(&body);
            assert!(matches!(
                run(&generated(), &config),
                Err(BuildError::Unavailable(_))
            ));
            assert_eq!(slots.available(), 1);
            assert!(matches!(
                run(&generated(), &config),
                Err(BuildError::Unavailable(_))
            ));
        }
    }

    #[test]
    fn a_response_for_a_different_job_cannot_release_capacity() {
        let body = CONFIRMED_FAILURE.replace("hashlib.sha256(data).hexdigest()", "'0'*64");
        let (_directory, config, slots) = launcher(&body);
        assert!(run(&generated(), &config).is_err());
        assert_eq!(slots.available(), 0);
    }

    #[test]
    fn duplicate_missing_extra_and_oversized_files_are_rejected_by_worker() {
        let mut job = Job {
            schema: JOB_SCHEMA.into(),
            crate_name: "fixture".into(),
            files: generated()
                .files
                .into_iter()
                .map(|(path, body)| JobFile { path, body })
                .collect(),
            timeout_seconds: 1,
            jobs: 1,
        };
        assert!(validate_job(&job).is_ok());
        job.files[0].path = job.files[1].path.clone();
        assert!(validate_job(&job).is_err());
        job.files[0].path = "build.rs".into();
        assert!(validate_job(&job).is_err());
        job.files[0].path = "Cargo.lock".into();
        job.files[0].body = "x".repeat(MAX_SOURCE_BYTES + 1);
        assert!(validate_job(&job).is_err());
        job.files.pop();
        assert!(validate_job(&job).is_err());
    }

    #[test]
    fn unprotected_and_symlink_launchers_fail_configuration() {
        let (directory, config, _) = launcher(CONFIRMED_FAILURE);
        let path = config.worker_launcher.as_ref().unwrap();
        assert!(config.clone().validated().is_ok());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(config.clone().validated().is_err());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(path, &link).unwrap();
        assert!(BuildConfig {
            worker_launcher: Some(link),
            ..config
        }
        .validated()
        .is_err());
    }

    #[test]
    fn a_writable_parent_cannot_redirect_a_launcher_through_a_symlink() {
        let (directory, config, _) = launcher(CONFIRMED_FAILURE);
        let unprotected = directory.path().join("unprotected");
        std::fs::create_dir(&unprotected).unwrap();
        std::fs::set_permissions(&unprotected, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(directory.path(), unprotected.join("alias")).unwrap();
        assert!(BuildConfig {
            worker_launcher: Some(unprotected.join("alias/launcher")),
            ..config
        }
        .validated()
        .is_err());
    }

    #[test]
    fn intermediate_symlink_targets_cannot_hide_a_writable_parent() {
        let (directory, config, _) = launcher(CONFIRMED_FAILURE);
        let root = directory.path().canonicalize().unwrap();
        let unprotected = root.join("unprotected");
        std::fs::create_dir(&unprotected).unwrap();
        std::fs::set_permissions(&unprotected, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&root, unprotected.join("relay")).unwrap();
        std::os::unix::fs::symlink(unprotected.join("relay"), root.join("alias")).unwrap();
        assert!(BuildConfig {
            worker_launcher: Some(root.join("alias/launcher")),
            ..config
        }
        .validated()
        .is_err());
    }
}
