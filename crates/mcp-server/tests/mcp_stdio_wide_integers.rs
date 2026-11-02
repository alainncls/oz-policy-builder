//! Wide integers at the boundary a JavaScript client reads.
//!
//! Claude Code parses every tool result and every argument it sends as JavaScript numbers, which
//! are exact only up to 2^53. A recorded authorization nonce is a random 64-bit value, so almost
//! every real one is beyond that: the agent saw `6413110240810737672` as `6413110240810738000`,
//! passed the recording back, and `synthesize_policy` rightly refused it as incoherent evidence.
//! The fixtures every other suite uses carry nonce 12345, which is why nothing caught it.

mod common;

use common::{by_id, initialize, initialized, run_session_with_env};
use ozpb_recorder_core::fixtures as rec;
use ozpb_recorder_core::{record, EvidenceSnapshot, RecordOptions};
use stellar_xdr::{Limits, WriteXdr};

/// A nonce of the size the network actually issues, beyond JavaScript's exact range.
const NONCE: i64 = 6_413_110_240_810_737_672;

/// The largest magnitude a JavaScript number carries exactly.
const JS_EXACT: u64 = (1 << 53) - 1;

fn envelope_base64() -> String {
    rec::envelope_with(vec![rec::auth_entry(rec::address_credentials(NONCE))])
        .to_xdr_base64(Limits::none())
        .unwrap()
}

fn recording() -> serde_json::Value {
    let snapshot = EvidenceSnapshot::from_rpc_transaction(
        ozpb_domain::TESTNET_PASSPHRASE,
        envelope_base64(),
        Some(rec::meta_v3().to_xdr_base64(Limits::none()).unwrap()),
        4_200_100,
        1_780_000_000,
        true,
    )
    .with_rpc_result(rec::transaction_result_base64(true))
    .with_contract_executables(rec::observed_executables());
    serde_json::to_value(record(&snapshot, RecordOptions::default()).unwrap()).unwrap()
}

/// What a JavaScript client hands back after `JSON.parse` and `JSON.stringify`: every number
/// passes through an f64.
fn through_javascript(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => {
            let f = n.as_f64().unwrap();
            if (-(2f64.powi(63))..2f64.powi(63)).contains(&f) {
                Value::from(f as i64)
            } else if (0f64..2f64.powi(64)).contains(&f) {
                Value::from(f as u64)
            } else {
                Value::from(f)
            }
        }
        Value::Array(items) => Value::Array(items.iter().map(through_javascript).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), through_javascript(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Paths of every number a JavaScript client would round.
fn inexact_numbers(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
    use serde_json::Value;
    match value {
        Value::Number(n) => {
            let exact = n
                .as_i64()
                .map(|v| v.unsigned_abs() <= JS_EXACT)
                .or_else(|| n.as_u64().map(|v| v <= JS_EXACT))
                .unwrap_or(true);
            if !exact {
                found.push(format!("{path} = {n}"));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                inexact_numbers(item, &format!("{path}[{i}]"), found);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                inexact_numbers(v, &format!("{path}.{k}"), found);
            }
        }
        _ => {}
    }
}

fn configured_trust() -> Vec<(&'static str, String)> {
    let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    let snapshot = ozpb_registry::dev::dev_snapshot(network, 1);
    let signed =
        ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap();
    let root_hex: String = ozpb_registry::dev::dev_signing_key()
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    vec![
        (
            "OZPB_REGISTRY_ROOTS_JSON",
            serde_json::json!({"threshold": 1, "keys": {"legacy": root_hex}}).to_string(),
        ),
        ("OZPB_REGISTRY_MIN_VERSION", "1".to_string()),
        (
            "OZPB_REGISTRY_SNAPSHOT_JSON",
            serde_json::to_string(&signed).unwrap(),
        ),
    ]
}

#[test]
fn a_recording_returns_no_number_a_javascript_client_would_round() {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "import_recording", "arguments": {
                    "network_passphrase": ozpb_domain::TESTNET_PASSPHRASE,
                    "envelope_xdr_base64": envelope_base64(),
                    "result_meta_xdr_base64": rec::meta_v3().to_xdr_base64(Limits::none()).unwrap(),
                    "result_xdr_base64": rec::transaction_result_base64(true),
                    "ledger": 4_200_100,
                    "successful": true,
                }}
            }),
        ],
        &[],
    );
    let result = &by_id(&responses, 2)["result"];
    assert!(result["isError"] != serde_json::json!(true), "{result}");
    let mut found = Vec::new();
    inexact_numbers(
        &result["structuredContent"],
        "structuredContent",
        &mut found,
    );
    for (i, item) in result["content"].as_array().unwrap().iter().enumerate() {
        if let Some(text) = item["text"].as_str() {
            if let Ok(parsed) = serde_json::from_str(text) {
                inexact_numbers(&parsed, &format!("content[{i}]"), &mut found);
            }
        }
    }
    assert!(
        found.is_empty(),
        "a JavaScript client rounds these: {found:?}"
    );
    assert_eq!(
        result["structuredContent"]["bundle"]["authorizations"][0]["credential"]["address"]
            ["nonce"],
        serde_json::json!(NONCE.to_string()),
        "the nonce has to arrive exactly"
    );
}

#[test]
fn a_recording_passed_back_by_a_javascript_client_still_synthesizes() {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "synthesize_policy", "arguments": {
                    "bundles": [through_javascript(&recording())],
                    "decisions": serde_json::to_value(
                        ozpb_synthesizer::fixtures::golden_decisions()).unwrap(),
                    "spending_limit_capability": "pinned",
                }}
            }),
        ],
        &configured_trust(),
    );
    let result = &by_id(&responses, 2)["result"];
    assert!(
        result["isError"] != serde_json::json!(true),
        "the recording must survive the client that carries it: {result}"
    );
    assert_eq!(
        result["structuredContent"]["spec_hash"]
            .as_str()
            .map(str::len),
        Some(64),
        "{result}"
    );
}

/// A recording written before this change carried its nonce as a number; a client that kept
/// it exactly (or a file read from disk) must still be accepted.
#[test]
fn a_numeric_nonce_is_still_accepted() {
    let mut bundle = recording();
    let nonce = &mut bundle["authorizations"][0]["credential"]["address"]["nonce"];
    *nonce = serde_json::json!(NONCE);
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "synthesize_policy", "arguments": {
                    "bundles": [bundle],
                    "decisions": serde_json::to_value(
                        ozpb_synthesizer::fixtures::golden_decisions()).unwrap(),
                    "spending_limit_capability": "pinned",
                }}
            }),
        ],
        &configured_trust(),
    );
    let result = &by_id(&responses, 2)["result"];
    assert!(result["isError"] != serde_json::json!(true), "{result}");
}
