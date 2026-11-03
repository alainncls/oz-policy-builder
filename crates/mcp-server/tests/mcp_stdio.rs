//! Automated MCP protocol test: spawn the built stdio server and exercise the real
//! JSON-RPC handshake + tool calls end to end. Hermetic — only the pure tools (no
//! network) are called. Closes the "MCP wiring untested" gap.
//!
//! The shared harness is in `common/`.

mod common;
use common::*;

#[test]
fn initialize_and_list_tools() {
    let resp = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    // initialize succeeded with server info.
    let init = by_id(&resp, 1);
    assert!(init["result"]["serverInfo"].is_object(), "init: {init}");
    // Every tool is listed, each with an output schema.
    let tools = by_id(&resp, 2)["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for tool in MVP_TOOLS {
        assert!(names.contains(tool), "missing tool {tool}; have {names:?}");
    }
    // Exact count so a newly-added or dropped tool can't silently drift from the contract.
    // The core, verification, preflight, authority, policy-check and capture routers define the
    // served tool set.
    assert_eq!(
        tools.len(),
        MVP_TOOLS.len()
            + VERIFICATION_TOOLS.len()
            + PREFLIGHT_TOOLS.len()
            + AUTHORITY_TOOLS.len()
            + POLICY_CHECK_TOOLS.len()
            + CAPTURE_TOOLS.len()
            + WALLET_HANDOFF_TOOLS.len(),
        "tool set drifted; have {names:?}"
    );
    assert!(
        tools.iter().all(|t| t.get("outputSchema").is_some()),
        "every tool must advertise an output schema"
    );
}

#[test]
fn tools_call_evaluate_spec_is_indeterminate_for_unmodeled_reviewed_policy() {
    // Derive the concrete addresses from the committed spec so the test never drifts:
    // account (SELF), the token (rule contract), the delegate signer, and the exact
    // recipient/amount from the allowed-call tuple.
    let spec = subscription_spec();
    let rule = &spec["rules"][0];
    let account = spec["smart_account"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let token = rule["context"]["contract"].as_str().unwrap().to_string();
    let delegate = rule["authorization"]["signers"][0]["delegated"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let args = &rule["allowed_calls"][0]["args"];
    let merchant = args[1]["c"]["eq_address"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    let amount: i64 = args[2]["c"]["eq_i128"]["value"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let ctx = serde_json::json!({
        "smart_account": account,
        "current_ledger": 100,
        "authenticated_signers": [{"delegated": {"address": delegate}}],
        "rule_live_signers": [{"delegated": {"address": delegate}}],
        "call_count_so_far": 0
    });
    let inv = serde_json::json!({
        "contract": token,
        "fn_name": "transfer",
        "args": [
            {"address": account},        // from = SELF
            {"address": merchant},
            {"i128": amount}
        ]
    });
    let resp = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "evaluate_spec", "arguments": {
                "spec": subscription_spec(), "context": ctx, "invocation": inv}}
        }),
    ]);
    let sc = &by_id(&resp, 2)["result"]["structuredContent"];
    assert_eq!(
        sc["verdict"],
        serde_json::json!("indeterminate"),
        "got response {:?}",
        by_id(&resp, 2)
    );
}

#[test]
fn malformed_tool_input_yields_a_machine_readable_error() {
    // generate_code with a spec that fails validation → the tool returns an error carrying
    // the structured ToolError payload (stable code).
    let resp = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "generate_code",
                       "arguments": {"spec": {"$schema": "policy-spec/v1"}, "rule_index": 0}}
        }),
    ]);
    let call = by_id(&resp, 2);
    assert_eq!(call["result"]["isError"], true, "got {call}");
    assert_eq!(
        call["result"]["structuredContent"]["code"], "E_SPEC_INVALID",
        "got {call}"
    );
    assert!(
        call.get("error").is_none(),
        "tool failures are not protocol errors"
    );
}

#[test]
fn unknown_request_fields_fail_closed_as_tool_errors() {
    let resp = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "record_transaction", "arguments": {
                "network_passphrase": "network",
                "tx_hash": "0".repeat(64),
                "rpc_url": "https://rpc.example",
                "unexpected": "must not be ignored"
            }}
        }),
    ]);
    let call = by_id(&resp, 2);
    assert_eq!(call["result"]["isError"], true, "got {call}");
}
