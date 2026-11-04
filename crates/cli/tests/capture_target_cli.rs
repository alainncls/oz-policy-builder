//! `ozpb capture-target` through a local RPC endpoint replaying recorded testnet responses.

#[path = "../../../tests/support/preflight_rpc.rs"]
mod preflight_rpc;
#[path = "../../../tests/support/target_capture_rpc.rs"]
mod target_capture_rpc;

use serde_json::json;
use std::process::{Command, Output};
use target_capture_rpc::{envelope, envelope_with, methods, sources, ReplayEndpoint, Reply};

fn testnet_id() -> String {
    ozpb_domain::NetworkId::from_passphrase(target_capture_rpc::NETWORK)
        .0
        .to_hex()
}

/// Run `capture-target` with `request` against a source file naming `url` as `testnet`.
fn capture(url: &str, request: &serde_json::Value) -> Output {
    capture_raw(url, request.to_string().as_bytes())
}

fn capture_raw(url: &str, request: &[u8]) -> Output {
    let directory = tempfile::tempdir().expect("temporary directory");
    let request_file = directory.path().join("capture-request.json");
    std::fs::write(&request_file, request).expect("write request");
    let sources_file = directory.path().join("rpc-sources.json");
    std::fs::write(&sources_file, sources(url)).expect("write sources");
    Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .arg("capture-target")
        .arg("--request")
        .arg(&request_file)
        .arg("--rpc-sources")
        .arg(&sources_file)
        .env_remove("OZPB_RPC_SOURCES_FILE")
        .output()
        .expect("run CLI")
}

fn request(envelope: &str) -> serde_json::Value {
    json!({
        "network_id": testnet_id(),
        "rpc_source": "testnet",
        "envelope_xdr_base64": envelope,
    })
}

/// Neither stream carries the envelope.
fn assert_not_echoed(output: &Output, envelope: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(envelope), "stdout echoed the envelope");
    assert!(!stderr.contains(envelope), "stderr echoed the envelope");
}

#[test]
fn capture_target_replays_recorded_testnet_fixture() {
    let endpoint = ReplayEndpoint::recorded();
    let envelope = envelope();
    let output = capture(&endpoint.url, &request(&envelope));
    let requests = endpoint.finish();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_not_echoed(&output, &envelope);

    // The printed document is exactly the capture the execution runtime reads.
    let capture: ozpb_domain::TargetCapture =
        serde_json::from_slice(&output.stdout).expect("a TargetCapture document");
    assert_eq!(capture.schema, 1);
    assert_eq!(capture.provenance, "rpc_reported");
    assert_eq!(capture.network_id, testnet_id());
    assert_eq!(capture.read_only_keys.len(), 1);
    assert_eq!(capture.read_write_keys.len(), 2);
    assert_eq!(capture.entries.len(), 3);
    assert_eq!(
        capture.account_code_hash,
        ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()
    );
    assert_eq!(
        capture.observed_ledger,
        target_capture_rpc::recorded("getLedgers")["ledgers"][0]["sequence"]
            .as_u64()
            .unwrap() as u32
    );
    assert_eq!(
        methods(&requests),
        [
            "getNetwork",
            "simulateTransaction",
            "getLedgerEntries",
            "getLedgers"
        ]
    );
    assert_eq!(requests[1]["params"]["authMode"], "record");
    assert_eq!(requests[1]["params"]["transaction"], envelope);
}

/// Each refusal happens before any connection to the configured source.
#[test]
fn refusals_name_their_code_before_the_network() {
    let unsupported = envelope_with(|call| call.function_name = "approve".try_into().unwrap());
    let other_contract = envelope_with(|call| {
        call.contract_address =
            stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([9; 32])))
    });
    let mut unknown_source = request(&envelope());
    unknown_source["rpc_source"] = json!("unconfigured");
    let mut other_network = request(&envelope());
    other_network["network_id"] = json!(ozpb_domain::NetworkId::from_passphrase(
        "Public Global Stellar Network ; September 2015"
    )
    .0
    .to_hex());
    for (name, request, code) in [
        (
            "unsupported function",
            request(&unsupported),
            "E_UNSUPPORTED_ENVELOPE: ",
        ),
        (
            "non-native contract",
            request(&other_contract),
            "E_UNSUPPORTED_ENVELOPE: ",
        ),
        ("unconfigured source", unknown_source, "E_RPC: "),
        ("other network", other_network, "E_NETWORK_MISMATCH: "),
        (
            "malformed envelope",
            request("not-an-envelope"),
            "E_ENVELOPE_PARSE: ",
        ),
        (
            "oversized envelope",
            request(&"A".repeat(ozpb_source_rpc::MAX_XDR_BASE64_BYTES + 1)),
            "E_RESOURCE_LIMIT: ",
        ),
    ] {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let output = capture(&endpoint.url, &request);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{name}: {stderr}");
        assert!(output.stdout.is_empty(), "{name}: printed a capture");
        assert!(stderr.contains(code), "{name}: {stderr}");
        // One code, as the preflight command prints it, not the code and then the message's.
        assert!(
            !stderr.contains(&format!("{code}{code}")),
            "{name}: {stderr}"
        );
        assert_eq!(endpoint.connections(), 0, "{name}: reached the network");
        if let Some(envelope) = request["envelope_xdr_base64"].as_str() {
            assert_not_echoed(&output, envelope);
        }
    }
}

/// After simulation the endpoint holds the envelope and could put it in any later reply; no
/// endpoint text reaches the output.
#[test]
fn an_endpoint_echoing_the_envelope_never_reaches_the_output() {
    let envelope = envelope();
    let echoed = envelope.clone();
    let endpoint = ReplayEndpoint::bind(move |method, _| match method {
        "simulateTransaction" => Reply::Error(json!({"code": -32000, "message": echoed.clone()})),
        other => Reply::Result(target_capture_rpc::recorded(other)),
    });
    let output = capture(&endpoint.url, &request(&envelope));
    endpoint.finish();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("Error: E_RPC: rpc error: "), "{stderr}");
    assert!(!stderr.contains("E_RPC: E_RPC: "), "{stderr}");
    assert!(stderr.contains("withheld"), "{stderr}");
    assert_not_echoed(&output, &envelope);
}

/// A request file that is not a request is refused without quoting it.
#[test]
fn a_malformed_request_file_is_refused_without_quoting_it() {
    let envelope = envelope();
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let output = capture_raw(
        &endpoint.url,
        format!("{{\"envelope_xdr_base64\": \"{envelope}\", \"{envelope}\": 1}}").as_bytes(),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("invalid shape; confidential details withheld"),
        "{stderr}"
    );
    assert_not_echoed(&output, &envelope);
    assert_eq!(endpoint.connections(), 0);
}

#[test]
fn capture_target_is_a_documented_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(["capture-target", "--help"])
        .output()
        .expect("run CLI");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{help}");
    for flag in ["--request", "--rpc-sources"] {
        assert!(help.contains(flag), "{help}");
    }
    assert!(!help.contains("--rpc-url"), "{help}");
}

/// A simulation the target refused, or whose footprint needs restoration, is named by its own
/// code, so a caller can tell the call's outcome from an endpoint fault. The endpoint's words,
/// which could quote the envelope, still never reach the output.
#[test]
fn a_target_refusal_or_archived_footprint_has_its_own_code() {
    // Since protocol 23 an endpoint restores archived entries inside the simulated call and
    // lists them in the transaction data rather than sending a preamble.
    let restored = |simulation: &mut serde_json::Value| {
        use stellar_xdr::{Limits, ReadXdr, WriteXdr};
        let mut data = stellar_xdr::SorobanTransactionData::from_xdr_base64(
            simulation["transactionData"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap();
        data.ext = stellar_xdr::SorobanTransactionDataExt::V1(stellar_xdr::SorobanResourcesExtV0 {
            archived_soroban_entries: vec![0].try_into().unwrap(),
        });
        simulation["transactionData"] = json!(data.to_xdr_base64(Limits::none()).unwrap());
    };
    for (field, code) in [
        ("error", "E_TARGET_REFUSED"),
        ("restorePreamble", "E_TARGET_ARCHIVED"),
        ("archived", "E_TARGET_ARCHIVED"),
    ] {
        let envelope = envelope();
        let echoed = envelope.clone();
        let endpoint = ReplayEndpoint::bind(move |method, _| match method {
            "simulateTransaction" => {
                let mut simulation = target_capture_rpc::recorded(method);
                let quoted = format!("balance is not sufficient: {echoed}");
                match field {
                    // A failed simulation reports its error and no results.
                    "error" => {
                        simulation["error"] = json!(quoted);
                        simulation.as_object_mut().unwrap().remove("results");
                    }
                    // A well-formed preamble: transaction data whose fee is its own.
                    "restorePreamble" => {
                        use stellar_xdr::{Limits, WriteXdr};
                        let data = stellar_xdr::SorobanTransactionData {
                            resource_fee: 4321,
                            ..Default::default()
                        };
                        simulation["restorePreamble"] = json!({
                            "transactionData": data.to_xdr_base64(Limits::none()).unwrap(),
                            "minResourceFee": "4321",
                        })
                    }
                    _ => restored(&mut simulation),
                }
                Reply::Result(simulation)
            }
            other => Reply::Result(target_capture_rpc::recorded(other)),
        });
        let output = capture(&endpoint.url, &request(&envelope));
        let requests = endpoint.finish();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{field}: {stderr}");
        assert!(output.stdout.is_empty(), "{field}: printed a capture");
        assert!(
            stderr.starts_with(&format!("Error: {code}: ")),
            "{field}: {stderr}"
        );
        assert!(!stderr.contains("E_RPC"), "{field}: {stderr}");
        assert!(
            !stderr.contains("balance is not sufficient"),
            "{field}: {stderr}"
        );
        assert_not_echoed(&output, &envelope);
        assert_eq!(
            methods(&requests),
            ["getNetwork", "simulateTransaction"],
            "{field}"
        );
    }
}

#[test]
fn a_confidential_envelope_copied_into_the_source_name_is_not_echoed() {
    let secret = envelope();
    let mut input = request(&secret);
    input["rpc_source"] = json!(secret);
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let output = capture(&endpoint.url, &input);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("E_RPC"));
    assert_not_echoed(&output, &secret);
    assert_eq!(endpoint.connections(), 0);
}

#[test]
fn syntax_locations_survive_without_echoing_confidential_input() {
    let secret = envelope();
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let output = capture_raw(&endpoint.url, format!("{{\"{secret}\":").as_bytes());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("line 1"));
    assert_not_echoed(&output, &secret);
    assert_eq!(endpoint.connections(), 0);
}
