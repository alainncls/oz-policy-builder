//! `ozpb dry-run` with the captured-target layer, capturing through the CLI's own capture path
//! from a local endpoint that replays the recorded testnet responses. Run through
//! scripts/test-cli-dry-run.sh, which prepares the fixture, the delegate key file and private
//! copies of the CLI and the native worker.

#[path = "../../../tests/support/target_capture_rpc.rs"]
mod target_capture_rpc;

use std::path::PathBuf;
use std::process::Command;
use target_capture_rpc::{envelope, methods, sources, ReplayEndpoint};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by scripts/test-cli-dry-run.sh"))
}

#[test]
#[ignore = "requires the fixture scripts/test-cli-dry-run.sh prepares"]
fn dry_run_runs_the_captured_layer_through_a_replayed_capture() {
    let work = PathBuf::from(var("OZPB_DRY_RUN_E2E_WORK"));
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples");
    let endpoint = ReplayEndpoint::recorded();
    std::fs::write(work.join("rpc-sources.json"), sources(&endpoint.url)).unwrap();
    let envelope = envelope();
    let network_id = ozpb_domain::NetworkId::from_passphrase(target_capture_rpc::NETWORK)
        .0
        .to_hex();
    std::fs::write(
        work.join("capture-request.json"),
        serde_json::json!({
            "network_id": network_id, "rpc_source": "testnet", "envelope_xdr_base64": envelope,
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(var("OZPB_DRY_RUN_E2E_CLI"))
        .arg("dry-run")
        .arg("--request")
        .arg(work.join("request.json"))
        .arg("--registry-roots")
        .arg(examples.join("registry-roots.json"))
        .args(["--registry-min-version", "3"])
        .arg("--rpc-sources")
        .arg(work.join("rpc-sources.json"))
        .arg("--native-worker")
        .arg(var("OZPB_DRY_RUN_E2E_WORKER"))
        .arg("--delegate-key-file")
        .arg(work.join("delegate.key"))
        .arg("--account-wasm")
        .arg(work.join("pinned-account.wasm"))
        .arg("--source-ledger")
        .arg(work.join("ledger.json"))
        .arg("--capture-request")
        .arg(work.join("capture-request.json"))
        .env_remove("OZPB_RPC_SOURCES_FILE")
        .env_remove("OZPB_REGISTRY_ROOTS_FILE")
        .env_remove("OZPB_REGISTRY_MIN_VERSION")
        .env_remove("OZPB_NATIVE_WORKER")
        .output()
        .expect("run the CLI");
    // Kept for the script's search for the delegate secret.
    std::fs::write(work.join("dry-run.stdout"), &output.stdout).unwrap();
    std::fs::write(work.join("dry-run.stderr"), &output.stderr).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    // Exactly one capture's reads reached the endpoint; preparation contacted it not at all.
    assert_eq!(
        methods(&endpoint.finish()),
        [
            "getNetwork",
            "simulateTransaction",
            "getLedgerEntries",
            "getLedgers"
        ]
    );
    // The envelope is confidential input and is echoed nowhere.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&envelope) && !stderr.contains(&envelope));

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let layer = |id: &str| {
        report["layers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|layer| layer["id"] == id)
            .unwrap()
            .clone()
    };
    let account = layer("account_wasm");
    let captured = layer("captured_target");
    assert_eq!(account["status"], "passed", "{}", account["reason"]);
    assert_eq!(captured["status"], "passed", "{}", captured["reason"]);
    assert_eq!(captured["state_dependent"], true);
    let cases = captured["execution"]["cases"].as_array().unwrap();
    let ids: Vec<_> = cases.iter().map(|case| case["case_id"].clone()).collect();
    assert_eq!(
        ids,
        [
            "target:original:0",
            "target:argument-denial:0",
            "target:empty-signers:0"
        ]
    );
    assert!(cases.iter().all(|case| case["agree"] == true));
    // Each layer runs in its own derived offline network, never the source network.
    let networks: Vec<_> = [&account, &captured]
        .iter()
        .map(|layer| layer["execution"]["execution_network_id"].clone())
        .collect();
    assert_ne!(networks[0], networks[1]);
    assert!(networks.iter().all(|id| *id != network_id.as_str()));
    let live = layer("live_enforcement");
    assert_eq!(live["status"], "unavailable");
    assert_eq!(live["reason"], "wallet_owner_consent_required");
    assert_eq!(report["complete"], false);
    let acceptance = &report["acceptance"];
    assert_eq!(acceptance["meets_minimum"], true, "{acceptance:#}");
    let executed = acceptance["executed_layers"].as_array().unwrap();
    assert_eq!(executed.len(), 2);
    assert_eq!(executed[1]["layer"], "captured_target");
    assert_eq!(executed[1]["reverted_denials"], 2);
    assert!(executed[0]["reverted_denials"].as_u64().unwrap() >= 5);
}
