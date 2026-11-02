//! Shared harness for the stdio protocol tests, plus the served tool set as data.
//!
//! Integration test files are separate crates and cannot `use` each other, so the harness lives
//! here and each test binary compiles its own copy. That is also why the module is
//! `#![allow(dead_code)]`: every binary uses a subset of it, and without the allow the unused
//! remainder would be a warning — fatal under the `-D warnings` gate.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// The MVP tool set: recording, synthesis, evaluation, codegen.
pub const MVP_TOOLS: &[&str] = &[
    "record_transaction",
    "record_simulation",
    "import_recording",
    "synthesize_policy",
    "evaluate_spec",
    "generate_code",
];

/// Layer-1 reference evidence and generated-artifact verification tools.
pub const VERIFICATION_TOOLS: &[&str] = &["reference_suite", "verify", "prepare_dry_run"];

/// Exact-envelope network simulation, separate from the complete dry-run.
pub const PREFLIGHT_TOOLS: &[&str] = &["preflight_transaction"];

/// Advisory account-authority reads through operator-configured RPC sources.
pub const AUTHORITY_TOOLS: &[&str] = &[
    "check_policy_call_surface",
    "prepare_install_intent",
    "assemble_install_transaction",
];
pub const POLICY_CHECK_TOOLS: &[&str] = &["check_against_policy"];

/// Read-only target-state capture through an operator-configured RPC source.
pub const CAPTURE_TOOLS: &[&str] = &["capture_target"];

/// Drive the server over stdio with a batch of newline-delimited JSON-RPC requests,
/// close stdin (which ends the transport and exits the server), and return the parsed
/// responses keyed by id.
pub fn run_session(requests: &[serde_json::Value]) -> Vec<serde_json::Value> {
    run_session_with_env(requests, &[])
}

/// The same session, with operator configuration in the environment.
///
/// Separate from [`run_session`] rather than a default argument to it, because the difference is
/// the point: several tools are refused until the deployment is configured, and a suite that
/// always configured them could not tell a working tool from a disabled one.
pub fn run_session_with_env(
    requests: &[serde_json::Value],
    env: &[(&str, String)],
) -> Vec<serde_json::Value> {
    let bin = env!("CARGO_BIN_EXE_ozpb-mcp-server");
    let mut command = Command::new(bin);
    // A test states the operator configuration it needs; an exported one must not leak in.
    command.env_remove("OZPB_RPC_SOURCES_JSON");
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp server");

    {
        let mut stdin = child.stdin.take().unwrap();
        for r in requests {
            writeln!(stdin, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        // Dropping stdin closes it → server sees EOF and shuts down.
    }

    let out = child.stdout.take().unwrap();
    let mut responses = Vec::new();
    for line in BufReader::new(out).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            responses.push(v);
        }
    }
    let _ = child.wait();
    responses
}

pub fn initialize() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "itest", "version": "0"}}
    })
}

pub fn initialized() -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
}

pub fn by_id(responses: &[serde_json::Value], id: i64) -> &serde_json::Value {
    responses
        .iter()
        .find(|r| r.get("id").and_then(|v| v.as_i64()) == Some(id))
        .unwrap_or_else(|| panic!("no response with id {id}; got {responses:?}"))
}

pub fn subscription_spec() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/subscription-spec.json");
    let text = std::fs::read_to_string(&path).expect("read example spec");
    serde_json::from_str(&text).unwrap()
}
