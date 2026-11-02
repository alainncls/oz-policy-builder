//! The recording tools read through the operator's configured RPC source by default.
//!
//! They used to require an `rpc_url` and a network passphrase on every call, so an agent asked
//! the user to pick an endpoint before it could record anything — a question the user should
//! never have to answer when the server already names its source. The URL form stays for a
//! client that wants another endpoint (subject to the hosted allowlist).

mod common;
use common::*;
#[path = "../../../tests/support/target_capture_rpc.rs"]
mod target_capture_rpc;

use serde_json::{json, Value};
use target_capture_rpc::{methods, recorded, sources, ReplayEndpoint, Reply};

const TX_HASH: &str = "ab00000000000000000000000000000000000000000000000000000000000000";

/// Answers the network check and reports the transaction as not found: a refusal that only a
/// read of the configured source can produce.
fn endpoint() -> ReplayEndpoint {
    ReplayEndpoint::bind(|method, _| match method {
        "getTransaction" => Reply::Result(json!({"status": "NOT_FOUND"})),
        other => Reply::Result(recorded(other)),
    })
}

fn call(name: &str, arguments: Value, env: &[(&str, String)]) -> Value {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            }),
        ],
        env,
    );
    by_id(&responses, 2)["result"].clone()
}

fn code(result: &Value) -> &str {
    result["structuredContent"]["code"]
        .as_str()
        .unwrap_or_default()
}

#[test]
fn a_hash_alone_is_recorded_through_the_only_configured_source() {
    let endpoint = endpoint();
    let result = call(
        "record_transaction",
        json!({"tx_hash": TX_HASH}),
        &[("OZPB_RPC_SOURCES_JSON", sources(&endpoint.url))],
    );
    let requests = endpoint.finish();
    assert_eq!(code(&result), "E_TX_NOT_FOUND", "{result}");
    assert!(
        methods(&requests).contains(&"getTransaction".to_string()),
        "{requests:?}"
    );
}

#[test]
fn a_named_source_is_used_with_its_own_network() {
    let endpoint = endpoint();
    let result = call(
        "record_transaction",
        json!({"tx_hash": TX_HASH, "rpc_source": "testnet"}),
        &[("OZPB_RPC_SOURCES_JSON", sources(&endpoint.url))],
    );
    endpoint.finish();
    assert_eq!(code(&result), "E_TX_NOT_FOUND", "{result}");
}

#[test]
fn a_simulation_also_defaults_to_the_configured_source() {
    let endpoint = endpoint();
    call(
        "record_simulation",
        json!({"envelope_xdr_base64": target_capture_rpc::envelope()}),
        &[("OZPB_RPC_SOURCES_JSON", sources(&endpoint.url))],
    );
    let requests = endpoint.finish();
    assert!(
        methods(&requests).contains(&"simulateTransaction".to_string()),
        "{requests:?}"
    );
}

#[test]
fn a_source_cannot_disagree_with_the_stated_network() {
    let endpoint = endpoint();
    let result = call(
        "record_transaction",
        json!({"tx_hash": TX_HASH, "rpc_source": "testnet",
               "network_passphrase": "Public Global Stellar Network ; September 2015"}),
        &[("OZPB_RPC_SOURCES_JSON", sources(&endpoint.url))],
    );
    let requests = endpoint.finish();
    assert_eq!(code(&result), "E_NETWORK_MISMATCH", "{result}");
    assert!(
        requests.is_empty(),
        "nothing is read for a contradictory request"
    );
}

#[test]
fn ambiguous_or_unresolvable_endpoints_are_refused_before_any_read() {
    let endpoint = endpoint();
    let configured = [("OZPB_RPC_SOURCES_JSON", sources(&endpoint.url))];
    let two = [(
        "OZPB_RPC_SOURCES_JSON",
        json!({
            "a": {"rpc_url": endpoint.url, "network_passphrase": target_capture_rpc::NETWORK},
            "b": {"rpc_url": endpoint.url, "network_passphrase": target_capture_rpc::NETWORK},
        })
        .to_string(),
    )];
    for (arguments, env, says) in [
        // Both forms at once.
        (
            json!({"tx_hash": TX_HASH, "rpc_source": "testnet", "rpc_url": endpoint.url,
                   "network_passphrase": target_capture_rpc::NETWORK}),
            &configured[..],
            "not both",
        ),
        // A name the operator did not configure. Like the other source-reading tools, the
        // refusal does not list the operator's names to a client that guessed one.
        (
            json!({"tx_hash": TX_HASH, "rpc_source": "mainnet"}),
            &configured[..],
            "\"mainnet\"",
        ),
        // Several sources and none named: the refusal lists them.
        (json!({"tx_hash": TX_HASH}), &two[..], "\"a\""),
        // No source configured and no URL.
        (json!({"tx_hash": TX_HASH}), &[][..], "rpc_url"),
        // A URL needs its network stated.
        (
            json!({"tx_hash": TX_HASH, "rpc_url": endpoint.url}),
            &configured[..],
            "network_passphrase",
        ),
    ] {
        let result = call("record_transaction", arguments.clone(), env);
        assert_eq!(result["isError"], true, "{arguments}: {result}");
        let message = result["structuredContent"]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(message.contains(says), "{arguments}: {message}");
        if arguments["rpc_source"] == "mainnet" {
            assert!(!message.contains("testnet"), "{message}");
        }
    }
    assert!(
        endpoint.finish().is_empty(),
        "no refused request reaches the endpoint"
    );
}
