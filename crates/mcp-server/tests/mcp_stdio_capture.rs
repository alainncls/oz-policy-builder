//! The `capture_target` tool at the stdio protocol boundary, against a local endpoint replaying
//! recorded testnet responses through an operator-configured source.

mod common;
use common::*;
#[path = "../../../tests/support/preflight_rpc.rs"]
mod preflight_rpc;
#[path = "../../../tests/support/target_capture_rpc.rs"]
mod target_capture_rpc;

use serde_json::json;
use target_capture_rpc::{envelope, envelope_with, methods, sources, ReplayEndpoint, Reply};

fn testnet_id() -> String {
    ozpb_domain::NetworkId::from_passphrase(target_capture_rpc::NETWORK)
        .0
        .to_hex()
}

fn arguments(envelope: &str) -> serde_json::Value {
    json!({
        "network_id": testnet_id(),
        "rpc_source": "testnet",
        "envelope_xdr_base64": envelope,
    })
}

/// One `capture_target` call on a server whose operator source `testnet` is `url`.
fn capture_call(url: &str, arguments: serde_json::Value) -> serde_json::Value {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "capture_target", "arguments": arguments}
            }),
        ],
        &[("OZPB_RPC_SOURCES_JSON", sources(url))],
    );
    by_id(&responses, 2).clone()
}

#[test]
fn capture_target_replays_recorded_testnet_fixture() {
    let endpoint = ReplayEndpoint::recorded();
    let envelope = envelope();
    let call = capture_call(&endpoint.url, arguments(&envelope));
    let requests = endpoint.finish();
    assert_ne!(call["result"]["isError"], true, "{call}");
    assert!(
        !call.to_string().contains(&envelope),
        "the response echoed the envelope"
    );
    // The structured result is exactly the capture the execution runtime reads.
    let capture: ozpb_domain::TargetCapture =
        serde_json::from_value(call["result"]["structuredContent"].clone())
            .expect("a TargetCapture document");
    assert_eq!(capture.provenance, "rpc_reported");
    assert_eq!(capture.network_id, testnet_id());
    assert_eq!(capture.entries.len(), 3);
    assert_eq!(
        capture.account_code_hash,
        ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()
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

#[test]
fn capture_target_is_listed_with_its_schemas_and_limits() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let tools = by_id(&responses, 2)["result"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "capture_target")
        .expect("capture_target must be advertised");
    let input = &tool["inputSchema"];
    let mut required: Vec<&str> = input["required"]
        .as_array()
        .expect("required input fields")
        .iter()
        .filter_map(|field| field.as_str())
        .collect();
    required.sort_unstable();
    assert_eq!(
        required,
        ["envelope_xdr_base64", "network_id", "rpc_source"],
        "{tool}"
    );
    assert!(input["properties"].get("rpc_url").is_none(), "{tool}");
    // The output schema describes the domain TargetCapture field for field.
    let output = &tool["outputSchema"];
    let mut properties: Vec<&String> = output["properties"]
        .as_object()
        .expect("output properties")
        .keys()
        .collect();
    properties.sort_unstable();
    assert_eq!(
        properties,
        [
            "account_code_hash",
            "entries",
            "header_xdr",
            "invocation_xdr",
            "network_id",
            "observed_ledger",
            "provenance",
            "read_only_keys",
            "read_write_keys",
            "recording_auth_xdr",
            "schema",
            "state_archival"
        ],
        "{tool}"
    );
    assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
    assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
    let description = tool["description"].as_str().unwrap();
    for claim in [
        "operator-configured RPC source",
        "unsigned",
        "confidential",
        "acquisition only",
        "rpc_reported",
        "native Stellar Asset Contract transfer",
        "does not run the captured-target layer",
        // Over MCP the envelope passes through the conversation, and the capture repeats its
        // call: neither is private to the endpoint.
        "this conversation",
        "equally confidential",
        "local stdio server",
    ] {
        assert!(description.contains(claim), "{claim}: {description}");
    }
}

#[test]
fn refusals_name_their_code_before_the_network() {
    let unsupported = envelope_with(|call| call.function_name = "approve".try_into().unwrap());
    let mut unknown_source = arguments(&envelope());
    unknown_source["rpc_source"] = json!("unconfigured");
    for (name, arguments, code) in [
        (
            "unsupported target",
            arguments(&unsupported),
            "E_UNSUPPORTED_ENVELOPE",
        ),
        ("unconfigured source", unknown_source, "E_RPC"),
        (
            "malformed envelope",
            arguments("not-an-envelope"),
            "E_ENVELOPE_PARSE",
        ),
    ] {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let call = capture_call(&endpoint.url, arguments.clone());
        assert_eq!(call["result"]["isError"], true, "{name}: {call}");
        assert_eq!(
            call["result"]["structuredContent"]["code"], code,
            "{name}: {call}"
        );
        assert_eq!(endpoint.connections(), 0, "{name}: reached the network");
        let envelope = arguments["envelope_xdr_base64"].as_str().unwrap();
        assert!(!call.to_string().contains(envelope), "{name}: echoed");
    }
}

#[test]
fn an_endpoint_echoing_the_envelope_never_reaches_the_response() {
    // The network is checked once, before the simulation, so an endpoint can name the envelope
    // as its network only if it saw the envelope earlier; after the simulation it holds it and
    // can quote it in the entry read's error.
    for (echo_at, code) in [
        ("getNetwork", "E_NETWORK_MISMATCH"),
        ("getLedgerEntries", "E_RPC"),
    ] {
        let envelope = envelope();
        let echoed = envelope.clone();
        let endpoint = ReplayEndpoint::bind(move |method, _| match method {
            "getNetwork" if method == echo_at => {
                Reply::Result(json!({"passphrase": echoed.clone(), "protocolVersion": 29}))
            }
            other if other == echo_at => {
                Reply::Error(json!({"code": -32000, "message": echoed.clone()}))
            }
            other => Reply::Result(target_capture_rpc::recorded(other)),
        });
        let call = capture_call(&endpoint.url, arguments(&envelope));
        endpoint.finish();
        assert_eq!(call["result"]["isError"], true, "{echo_at}: {call}");
        // The category survives without the endpoint's words.
        assert_eq!(
            call["result"]["structuredContent"]["code"], code,
            "{echo_at}: {call}"
        );
        assert!(!call.to_string().contains(&envelope), "{echo_at}: {call}");
    }
}

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
        let call = capture_call(&endpoint.url, arguments(&envelope));
        endpoint.finish();
        assert_eq!(call["result"]["isError"], true, "{field}: {call}");
        assert_eq!(
            call["result"]["structuredContent"]["code"], code,
            "{field}: {call}"
        );
        assert!(!call.to_string().contains(&envelope), "{field}: echoed");
        assert!(
            !call.to_string().contains("balance is not sufficient"),
            "{field}: {call}"
        );
    }
}

#[test]
fn malformed_capture_arguments_do_not_echo_any_request_field() {
    let secret = envelope();
    let mut unknown = arguments(&secret);
    unknown[&secret] = json!(true);
    let mut wrong_type = arguments(&secret);
    wrong_type["rpc_source"] = json!({&secret: secret});
    let mut copied_source = arguments(&secret);
    copied_source["rpc_source"] = json!(secret);
    let mut copied_network = arguments(&secret);
    copied_network["network_id"] = json!(secret);
    for (input, code) in [
        (unknown, None),
        (wrong_type, None),
        (copied_source, Some("E_RPC")),
        (copied_network, Some("E_NETWORK_MISMATCH")),
    ] {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let call = capture_call(&endpoint.url, input);
        if let Some(code) = code {
            assert_eq!(call["result"]["isError"], true, "{call}");
            assert_eq!(call["result"]["structuredContent"]["code"], code, "{call}");
        } else {
            assert_eq!(call["result"]["isError"], true, "{call}");
            assert_eq!(
                call["result"]["content"],
                json!([{"type": "text", "text": "failed to deserialize parameters: invalid capture-target request; confidential details withheld"}]),
                "{call}"
            );
        }
        assert!(
            !call.to_string().contains(&secret),
            "response echoed confidential input"
        );
        assert_eq!(endpoint.connections(), 0);
    }
}
