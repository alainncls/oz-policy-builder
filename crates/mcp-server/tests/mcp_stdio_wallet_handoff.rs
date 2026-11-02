mod common;
use common::{by_id, initialize, initialized, run_session};
use serde_json::json;

#[test]
fn wallet_handoff_is_unavailable_without_an_operator_configured_local_bridge() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        json!({"jsonrpc":"2.0", "id":2,
        "method":"tools/call", "params":{"name":"connect_wallet", "arguments":{
            "pairing_code":format!("ozpb-pair-{}", "a".repeat(64))}}}),
    ]);
    let result = &by_id(&responses, 2)["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result.to_string().contains("local wallet bridge"),
        "{result}"
    );
}
