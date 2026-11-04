//! `ozpb dry-run`: prepare a candidate, run the operator's native worker for the account-Wasm
//! layer and, when asked, the captured-target layer, and print one four-layer report.
//!
//! This is the one CLI command that holds a key. The spec delegate's key is read from a 0600
//! file and signs only offline-domain requests (see `signer`); the worker never receives it. The
//! live-enforcement layer is not run here: it needs the wallet owner's consent and signature,
//! so the report always names it `unavailable`. Exit status zero means the report meets the
//! permit/deny bar in its `acceptance` block; any other report is printed and exits nonzero.

mod key;
mod signer;
mod worker;

use crate::{print_json, read_json, BuildConfigArgs};
use anyhow::{anyhow, bail, Context, Result};
use key::DelegateKey;
use ozpb_api_types::{DryRunInput, DryRunOutput};
use ozpb_domain::TargetCapture;
use ozpb_toolkit::dry_run_report::{
    assemble_dry_run_report, captured_expectation, captured_job, check_native_prepared,
    check_source_ledger, native_expectation, native_job, native_scope, CapturedExpectation,
    LayerRun, NativeExpectation, NativeJob, SourceLedger, WorkerExit,
};
use signer::OfflineSigner;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use worker::{Mode, Outcome, Worker};

#[derive(clap::Args, Debug)]
pub struct DryRunArgs {
    /// DryRunInput JSON, the same request `prepare-dry-run` takes.
    #[arg(long)]
    request: PathBuf,
    /// Out-of-band root policy JSON for the signed registry snapshot.
    #[arg(long, env = "OZPB_REGISTRY_ROOTS_FILE")]
    registry_roots: PathBuf,
    /// Persisted minimum accepted snapshot version (anti-rollback floor).
    #[arg(long, env = "OZPB_REGISTRY_MIN_VERSION")]
    registry_min_version: u64,
    /// JSON map of source name to {rpc_url, network_passphrase}. The request names a source.
    #[arg(long, env = "OZPB_RPC_SOURCES_FILE")]
    rpc_sources: PathBuf,
    /// Absolute path of the operator's native execution worker (`ozpb-execution-runtime`). It
    /// must be trusted: it runs unsandboxed as you and can read anything you can, the key file
    /// included. It must be writable only by you or root. It runs with fixed arguments, an
    /// environment holding only PATH and LANG, a 120 s deadline per run and its own process
    /// group.
    #[arg(long, env = "OZPB_NATIVE_WORKER")]
    native_worker: PathBuf,
    /// File holding the spec delegate's Stellar secret seed (`S…`): a regular file owned by
    /// you with mode 0600. The key is read only from this file, never from an argument or the
    /// environment, and signs only requests for this run's derived offline network.
    #[arg(long)]
    delegate_key_file: PathBuf,
    /// The pinned smart-account Wasm the worker installs. Its SHA-256 must be the pin.
    #[arg(long)]
    account_wasm: PathBuf,
    /// Source ledger JSON: {protocol_version: 30, sequence, timestamp (decimal string),
    /// base_reserve, min_temp_entry_ttl, min_persistent_entry_ttl, max_entry_ttl}.
    #[arg(long)]
    source_ledger: PathBuf,
    /// Also run the captured-target layer: a CaptureTargetInput JSON (network_id, rpc_source,
    /// confidential unsigned envelope) captured through the named operator source.
    #[arg(long)]
    capture_request: Option<PathBuf>,
    #[command(flatten)]
    build: BuildConfigArgs,
}

fn resolve_capture_source(
    sources: &std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>,
    capture: &ozpb_api_types::CaptureTargetInput,
    candidate_network: &str,
) -> Result<ozpb_toolkit::RpcSource> {
    if capture.network_id != candidate_network {
        bail!("the capture request names another network than the candidate");
    }
    Ok(
        ozpb_toolkit::resolve_capture_rpc_source(
            sources,
            &capture.rpc_source,
            &capture.network_id,
        )?
        .clone(),
    )
}

pub fn run(args: DryRunArgs) -> Result<()> {
    let input: DryRunInput = serde_json::from_value(read_json(&args.request)?)
        .with_context(|| format!("parsing {}", args.request.display()))?;
    let roots = std::fs::read_to_string(&args.registry_roots)
        .with_context(|| format!("reading {}", args.registry_roots.display()))?;
    let trust = ozpb_toolkit::registry_trust_from_roots_json(&roots, args.registry_min_version)?;
    let sources = std::fs::read_to_string(&args.rpc_sources)
        .with_context(|| format!("reading {}", args.rpc_sources.display()))?;
    let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;
    ozpb_toolkit::resolve_rpc_source(
        &sources,
        &input.candidate.rpc_source,
        &input.candidate.network_id,
    )?;
    let worker = Worker::new(&args.native_worker).map_err(anyhow::Error::msg)?;
    let account_wasm = std::fs::read(&args.account_wasm)
        .with_context(|| format!("reading {}", args.account_wasm.display()))?;
    if ozpb_domain::sha256(&account_wasm) != ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM {
        bail!(
            "{} is not the pinned smart-account Wasm",
            args.account_wasm.display()
        );
    }
    let ledger: SourceLedger = serde_json::from_value(read_json(&args.source_ledger)?)
        .with_context(|| format!("parsing {}", args.source_ledger.display()))?;
    check_source_ledger(&ledger).map_err(anyhow::Error::msg)?;
    // A capture request is read and its source resolved before any build or execution, so a
    // bad one costs nothing. The envelope it carries is confidential and is never printed.
    let capture_input = args
        .capture_request
        .as_deref()
        .map(crate::capture::read_request)
        .transpose()?;
    let capture_source = capture_input
        .as_ref()
        .map(|capture| resolve_capture_source(&sources, capture, &input.candidate.network_id))
        .transpose()?;
    let preparation =
        ozpb_toolkit::prepare_dry_run_with_build_config(&input, &trust, &args.build.resolve()?)?;
    let capture = capture_input.zip(capture_source).map(|(capture, source)| {
        move || -> Result<TargetCapture, String> {
            let captured = ozpb_source_rpc::capture_native_target(
                &ozpb_source_rpc::HttpTransport::new(source.rpc_url.clone()),
                &source.network_passphrase,
                &capture.envelope_xdr_base64,
            );
            ozpb_toolkit::capture_target_output(captured)
                .map(|output| output.0)
                .map_err(|error| error.message)
        }
    });
    let report = execute_layers(
        &preparation,
        &worker,
        native_job(&input, &account_wasm, ledger),
        &account_wasm,
        &args.delegate_key_file,
        capture
            .as_ref()
            .map(|c| c as &dyn Fn() -> Result<TargetCapture, String>),
    )?;
    print_json(&report)?;
    let accepted = report
        .acceptance
        .as_ref()
        .is_some_and(|acceptance| acceptance.meets_minimum);
    if !accepted {
        bail!(
            "the dry-run report does not meet the permit/deny bar; read its `acceptance` block \
             and layer reasons"
        );
    }
    Ok(())
}

/// Run the runtime layers for one preparation and assemble the report. The delegate key is read
/// only once the run's offline binding is derived, and dropped (best-effort zeroized) before
/// assembly.
fn execute_layers(
    preparation: &DryRunOutput,
    worker: &Worker,
    job: NativeJob,
    account_wasm: &[u8],
    key_file: &Path,
    capture: Option<&dyn Fn() -> Result<TargetCapture, String>>,
) -> Result<DryRunOutput> {
    let not_requested = LayerRun::NotRun {
        unsupported: false,
        reason: "captured_target_not_requested".into(),
    };
    if let Err(reason) = native_scope(&job.request) {
        eprintln!("ozpb dry-run: the selected rule is outside the native worker's scope: {reason}");
        let unsupported = LayerRun::NotRun {
            unsupported: true,
            reason: "selected_rule_outside_native_scope".into(),
        };
        let captured = if capture.is_some() {
            unsupported.clone()
        } else {
            not_requested
        };
        return Ok(assemble_dry_run_report(
            preparation,
            None,
            &unsupported,
            None,
            &captured,
        ));
    }
    let native = native_expectation(preparation, &job)
        .map_err(|reason| anyhow!("cannot derive this run's offline binding: {reason}"))?;
    let key = DelegateKey::read(key_file, &native.scope.delegate_address)?;
    let account = run_account_layer(worker, &job, &native, &key);
    let (captured_expectation, captured) = match capture {
        None => (None, not_requested),
        Some(capture) => run_captured_layer(
            worker,
            &job.request,
            preparation,
            account_wasm,
            capture,
            &key,
        ),
    };
    drop(key);
    Ok(assemble_dry_run_report(
        preparation,
        Some(&native),
        &account,
        captured_expectation.as_ref(),
        &captured,
    ))
}

fn never_sign(_: &serde_json::Value) -> Result<serde_json::Value, &'static str> {
    Err("a preparation run asks for no signature")
}

/// Worker stderr or endpoint error text as the operator sees it: control characters other than
/// newlines (terminal escape sequences among them) and bidirectional marks, embeddings,
/// overrides and isolates are replaced, so the text can neither rewrite the operator's screen
/// nor reorder what it shows.
fn printable(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .map(|c| {
            let bidi = matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            );
            if c == '\n' || !(c.is_control() || bidi) {
                c
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

fn report_stderr(label: &str, stderr: &[u8]) {
    if !stderr.is_empty() {
        eprintln!(
            "ozpb dry-run: {label} worker stderr (first {} bytes): {}",
            stderr.len(),
            printable(stderr).trim_end()
        );
    }
}

fn layer_run(label: &str, outcome: Outcome, stderr: &[u8], signed: BTreeSet<String>) -> LayerRun {
    match outcome {
        Outcome::Refused(reason) => {
            report_stderr(label, stderr);
            LayerRun::Refused {
                reason: reason.into(),
            }
        }
        Outcome::Exited { exit, result, .. } => {
            if exit != WorkerExit::Success {
                report_stderr(label, stderr);
            }
            LayerRun::Ran {
                exit,
                result,
                signed,
            }
        }
    }
}

/// The trusted `--prepare` run's frame, or why the layer stops before any signature.
fn retained_preparation(
    label: &str,
    outcome: Outcome,
    stderr: &[u8],
) -> Result<serde_json::Value, LayerRun> {
    match outcome {
        Outcome::Exited {
            exit: WorkerExit::Success,
            prepared: Some(frame),
            result: None,
        } => Ok(frame),
        Outcome::Refused(reason) => {
            report_stderr(label, stderr);
            Err(LayerRun::Refused {
                reason: reason.into(),
            })
        }
        Outcome::Exited { .. } => {
            report_stderr(label, stderr);
            Err(LayerRun::Refused {
                reason: "worker_preparation_refused".into(),
            })
        }
    }
}

fn run_account_layer(
    worker: &Worker,
    job: &NativeJob,
    native: &NativeExpectation,
    key: &DelegateKey,
) -> LayerRun {
    let Ok(line) = serde_json::to_vec(job) else {
        return LayerRun::Refused {
            reason: "job_encoding_failed".into(),
        };
    };
    let (outcome, stderr) = worker.run(
        Mode::Prepare,
        &line,
        &mut |frame| check_native_prepared(frame, native).map(|_| ()),
        &mut never_sign,
    );
    let retained = match retained_preparation("account-Wasm preparation", outcome, &stderr) {
        Ok(frame) => frame,
        Err(run) => return run,
    };
    let Ok(mut signer) = OfflineSigner::new(
        key,
        &native.binding,
        &native.execution_network_id,
        native.signing_case_ids(),
        native.signing_expirations.clone(),
    ) else {
        return LayerRun::Refused {
            reason: "signer_refused_binding".into(),
        };
    };
    let (outcome, stderr) = worker.run(
        Mode::Execute,
        &line,
        &mut |frame| {
            if *frame == retained {
                Ok(())
            } else {
                Err("the executing worker's preparation differs from the retained one")
            }
        },
        &mut |request| signer.sign(request),
    );
    layer_run("account-Wasm", outcome, &stderr, signer.signed_cases())
}

fn run_captured_layer(
    worker: &Worker,
    input: &DryRunInput,
    preparation: &DryRunOutput,
    account_wasm: &[u8],
    capture: &dyn Fn() -> Result<TargetCapture, String>,
    key: &DelegateKey,
) -> (Option<CapturedExpectation>, LayerRun) {
    let capture = match capture() {
        Ok(capture) => capture,
        Err(message) => {
            // Requested and not run: a failed layer, so the report cannot meet the bar on the
            // other layers alone.
            eprintln!(
                "ozpb dry-run: target capture did not complete: {}",
                printable(message.as_bytes())
            );
            return (
                None,
                LayerRun::Refused {
                    reason: "target_capture_failed".into(),
                },
            );
        }
    };
    let job = match captured_job(input, account_wasm, &capture) {
        Ok(job) => job,
        Err(reason) => {
            eprintln!("ozpb dry-run: the capture cannot form a captured-target job: {reason}");
            return (
                None,
                LayerRun::Refused {
                    reason: "captured_job_refused".into(),
                },
            );
        }
    };
    let Ok(line) = serde_json::to_vec(&job) else {
        return (
            None,
            LayerRun::Refused {
                reason: "job_encoding_failed".into(),
            },
        );
    };
    let mut expectation = None;
    let (outcome, stderr) = worker.run(
        Mode::PrepareCaptured,
        &line,
        &mut |frame| {
            expectation = Some(captured_expectation(preparation, &job, frame)?);
            Ok(())
        },
        &mut never_sign,
    );
    let retained = match retained_preparation("captured-target preparation", outcome, &stderr) {
        Ok(frame) => frame,
        Err(run) => return (None, run),
    };
    let Some(expectation) = expectation else {
        return (
            None,
            LayerRun::Refused {
                reason: "worker_preparation_refused".into(),
            },
        );
    };
    let Ok(mut signer) = OfflineSigner::new(
        key,
        &expectation.binding,
        &expectation.execution_network_id,
        expectation.signing_case_ids.clone(),
        expectation
            .signing_case_ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    expectation
                        .observed_ledger
                        .saturating_add(ozpb_toolkit::dry_run_report::SIGNATURE_WINDOW),
                )
            })
            .collect(),
    ) else {
        return (
            Some(expectation),
            LayerRun::Refused {
                reason: "signer_refused_binding".into(),
            },
        );
    };
    let (outcome, stderr) = worker.run(
        Mode::ExecuteCaptured,
        &line,
        &mut |frame| {
            if *frame == retained {
                Ok(())
            } else {
                Err("the executing worker's preparation differs from the retained one")
            }
        },
        &mut |request| signer.sign(request),
    );
    let signed = signer.signed_cases();
    (
        Some(expectation),
        layer_run("captured-target", outcome, &stderr, signed),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::key::tests::{address, key_file, seed_strkey};
    use super::key::KeyFileError;
    use super::signer::tests::{binding, delegate_key, request};
    use super::*;

    #[test]
    fn capture_source_errors_never_echo_confidential_request_fields() {
        let secret = "CONFIDENTIAL_CAPTURE_ENVELOPE";
        let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
            .0
            .to_hex();
        let sources = ozpb_toolkit::rpc_sources_from_json(
            r#"{"testnet":{"rpc_url":"https://example.invalid","network_passphrase":"Test SDF Network ; September 2015"}}"#,
        ).unwrap();
        let mut capture = ozpb_api_types::CaptureTargetInput {
            network_id: network.clone(),
            rpc_source: "testnet".into(),
            envelope_xdr_base64: secret.into(),
        };
        assert!(resolve_capture_source(&sources, &capture, &network).is_ok());
        capture.rpc_source = secret.into();
        let error = resolve_capture_source(&sources, &capture, &network).unwrap_err();
        assert!(error.to_string().contains("request details withheld"));
        assert!(!format!("{error:#}").contains(secret));
        capture.network_id = secret.into();
        let error = resolve_capture_source(&sources, &capture, &network).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the capture request names another network than the candidate"
        );
    }

    #[test]
    fn key_never_appears_in_output_or_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [42u8; 32];
        let secrets = [
            seed_strkey(seed),
            hex::encode(seed),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, seed),
        ];
        let mut seen = Vec::new();

        // What the signer hands back to the worker, and its own and the key's debug output.
        let key = delegate_key(dir.path());
        let binding = binding(key.address());
        let network = ozpb_toolkit::dry_run_report::offline_execution_network_id(&binding).unwrap();
        let mut signer = OfflineSigner::new(
            &key,
            &binding,
            &network,
            ["case:0", "case:1"].iter().map(|c| c.to_string()).collect(),
            ["case:0", "case:1"]
                .iter()
                .map(|c| (c.to_string(), 1064))
                .collect(),
        )
        .unwrap();
        for (id, case) in [(1, "case:0"), (2, "case:1")] {
            seen.push(
                signer
                    .sign(&request(&binding, &network, id, case))
                    .unwrap()
                    .to_string(),
            );
        }
        seen.push(format!("{key:?}"));
        seen.push(format!("{signer:?}"));
        // A refused request's error.
        seen.push(
            signer
                .sign(&request(&binding, &binding.source_network_id, 3, "case:0"))
                .unwrap_err()
                .to_string(),
        );

        // Every refusal of the key file, including one that read the key and found another
        // delegate's.
        let secret = seed_strkey(seed);
        let refusals: Vec<KeyFileError> = vec![
            DelegateKey::read(
                &key_file(dir.path(), "open.key", &secret, 0o644),
                &address(seed),
            )
            .unwrap_err(),
            DelegateKey::read(
                &key_file(dir.path(), "other.key", &secret, 0o600),
                &address([7; 32]),
            )
            .unwrap_err(),
            DelegateKey::read(
                &key_file(dir.path(), "bad.key", &format!("{secret}x"), 0o600),
                &address(seed),
            )
            .unwrap_err(),
        ];
        for refusal in &refusals {
            seen.push(refusal.to_string());
            seen.push(format!("{refusal:?}"));
            // As the CLI reports it.
            seen.push(format!("{:?}", anyhow::Error::from(refusal.clone())));
        }

        // The evidence: a report assembled after the key was used.
        let preparation: DryRunOutput = serde_json::from_value(serde_json::json!({
            "schema": "ozpb:dry-run:v1", "run_hash": binding.run_hash,
            "binding": {
                "spec_hash": "aa".repeat(32), "binding_set_hash": "bb".repeat(32),
                "registry_snapshot_root": "dd".repeat(32), "account_address": binding.account_address,
                "account_code_hash": ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex(),
                "network_id": binding.source_network_id, "rule_index": 0,
                "candidate_context_rule_id": 7, "suite_hash": binding.suite_hash,
                "policy_code_hashes": {},
            },
            "artifact_verification": {
                "spec_conformance": "", "source_reproduction": "", "offline_behavioral_conformance": "",
                "wasm_reproduction": "", "current_network_preflight": "", "normalized_input_hash": "",
                "models_all_policies": true, "unmodeled_reviewed_policies": [], "matches": true,
            },
            "reference_report": {}, "layers": [], "complete": false, "disclaimer": "",
        }))
        .unwrap();
        let report = assemble_dry_run_report(
            &preparation,
            None,
            &LayerRun::Refused {
                reason: "signing_request_refused".into(),
            },
            None,
            &LayerRun::NotRun {
                unsupported: false,
                reason: "captured_target_not_requested".into(),
            },
        );
        seen.push(serde_json::to_string(&report).unwrap());
        drop(signer);
        drop(key);

        // The public address is expected throughout; no form of the secret is.
        assert!(seen.iter().any(|text| text.contains(&address(seed))));
        for text in &seen {
            for secret in &secrets {
                assert!(!text.contains(secret.as_str()), "secret in: {text}");
            }
        }
    }

    fn minimal_preparation(binding: &ozpb_toolkit::dry_run_report::OfflineBinding) -> DryRunOutput {
        serde_json::from_value(serde_json::json!({
            "schema": "ozpb:dry-run:v1", "run_hash": binding.run_hash,
            "binding": {
                "spec_hash": "aa".repeat(32), "binding_set_hash": "bb".repeat(32),
                "registry_snapshot_root": "dd".repeat(32), "account_address": binding.account_address,
                "account_code_hash": ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex(),
                "network_id": binding.source_network_id, "rule_index": 0,
                "candidate_context_rule_id": 7, "suite_hash": binding.suite_hash,
                "policy_code_hashes": {},
            },
            "artifact_verification": {
                "spec_conformance": "", "source_reproduction": "", "offline_behavioral_conformance": "",
                "wasm_reproduction": "", "current_network_preflight": "", "normalized_input_hash": "",
                "models_all_policies": true, "unmodeled_reviewed_policies": [], "matches": true,
            },
            "reference_report": {}, "layers": [], "complete": false, "disclaimer": "",
        }))
        .unwrap()
    }

    #[test]
    fn a_requested_capture_that_fails_fails_the_layer() {
        let dir = tempfile::tempdir().unwrap();
        let key = delegate_key(dir.path());
        let binding = binding(key.address());
        let input: DryRunInput = serde_json::from_value(serde_json::json!({
            "candidate": {
                "spec": {}, "rule_index": 0,
                "binding_set": {"schema": "policy-binding-set/v1", "spec_hash": "00".repeat(32),
                                "network_id": binding.source_network_id, "bindings": []},
                "signed_registry_snapshot": {}, "account_address": binding.account_address,
                "network_id": binding.source_network_id, "rpc_source": "testnet",
            },
            "artifact": {"spec": {}, "rule_index": 0, "claimed_generated_files": {}},
            "candidate_context_rule_id": 7, "run_nonce": "11".repeat(32),
        }))
        .unwrap();
        let worker = Worker::new(Path::new("/bin/sh")).unwrap();
        let unreachable = || -> Result<TargetCapture, String> {
            Err("E_RPC: the endpoint did not answer".into())
        };
        let (expectation, run) = run_captured_layer(
            &worker,
            &input,
            &minimal_preparation(&binding),
            &[],
            &unreachable,
            &key,
        );
        assert!(expectation.is_none());
        // Asked for and not run is a failed layer, so it blocks acceptance, not a missing one.
        assert!(
            matches!(&run, LayerRun::Refused { reason } if reason == "target_capture_failed"),
            "{run:?}"
        );
    }

    #[test]
    fn worker_stderr_is_printed_without_control_characters() {
        let shown = printable(b"refused\x1b[2J\x1b[1;1Hacceptance met\x07\r\nnext line\n");
        assert!(
            !shown.chars().any(|c| c.is_control() && c != '\n'),
            "{shown:?}"
        );
        assert!(shown.contains("refused") && shown.contains("next line"));
        // Bidirectional overrides and isolates cannot reorder what the operator reads either.
        let shown = printable(
            "ok \u{202E}deliaf\u{202C} \u{2066}x\u{2069}\u{200F}\u{200E}\u{061C}".as_bytes(),
        );
        assert!(
            !shown.chars().any(|c| matches!(c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')),
            "{shown:?}"
        );
        assert!(shown.contains("deliaf"));
    }
}
