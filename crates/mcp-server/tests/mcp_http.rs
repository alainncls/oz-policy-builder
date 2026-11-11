//! The hosted transport end to end: the real binary in `--http` mode, spoken to over a socket.
//!
//! The guard's unit tests drive it in front of a stand-in service. This drives the served
//! router — the guard in front of rmcp — so a regression that left `/v1/mcp` unguarded, or a
//! body the guard re-wraps that rmcp can no longer read, fails here.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A test-only bearer value, long enough for the startup check.
const TOKEN: &str = "test-bearer-0123456789abcdef0123456789";

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"itest","version":"0"}}}"#;

struct Server {
    child: Child,
    addr: String,
    /// Held open for the server's lifetime: a closed pipe would make its next write to stderr
    /// fail, and `eprintln!` panics on that.
    _stderr: BufReader<std::process::ChildStderr>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command_at(listen: &str, env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ozpb-mcp-server"));
    command.args(["--http", listen]);
    // Only what the test sets: an operator's own variables must not change the verdict.
    for name in [
        "OZPB_HTTP_BEARER_TOKEN",
        "OZPB_HTTP_ALLOWED_HOSTS",
        "OZPB_RPC_ALLOWLIST",
        "OZPB_RPC_SOURCES_JSON",
        "OZPB_HTTP_REQUESTS_PER_MINUTE",
        "OZPB_HTTP_MAX_CONCURRENCY",
        "OZPB_HTTP_MAX_BODY_BYTES",
        "OZPB_BUILD_JOBS",
        "OZPB_BUILD_TIMEOUT_SECS",
        "OZPB_BUILD_CACHE_DIR",
        "OZPB_STELLAR_BINARY",
        "OZPB_REGISTRY_ROOTS_JSON",
        "OZPB_REGISTRY_MIN_VERSION",
        "OZPB_REGISTRY_SNAPSHOT_JSON",
    ] {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    command
}

/// Start the server with a quota of `per_minute` and wait for the address it bound.
fn start(per_minute: &str, max_body_bytes: &str) -> Server {
    start_at(
        "127.0.0.1:0",
        &[
            ("OZPB_HTTP_REQUESTS_PER_MINUTE", per_minute),
            ("OZPB_HTTP_MAX_BODY_BYTES", max_body_bytes),
        ],
    )
}

fn start_at(listen: &str, extra: &[(&str, &str)]) -> Server {
    let mut env = vec![
        ("OZPB_HTTP_BEARER_TOKEN", TOKEN),
        ("OZPB_RPC_ALLOWLIST", "https://rpc.example"),
        ("OZPB_BUILD_JOBS", "1"),
    ];
    env.extend_from_slice(extra);
    let mut child = command_at(listen, &env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the HTTP server");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr"));
    let mut line = String::new();
    stderr.read_line(&mut line).expect("startup line");
    let addr = line
        .trim()
        .strip_prefix("ozpb MCP streamable-HTTP endpoint on http://")
        .and_then(|rest| rest.strip_suffix("/v1/mcp"))
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"))
        .to_string();
    Server {
        child,
        addr,
        _stderr: stderr,
    }
}

/// POST `body` to `/v1/mcp` and return the response status code.
fn post(server: &Server, bearer: Option<&str>, body: &str) -> u16 {
    post_as(server, &server.addr, bearer, body)
}

/// The same, naming `host` in the request's `Host` header, as an ingress forwarding it would.
fn post_as(server: &Server, host: &str, bearer: Option<&str>, body: &str) -> u16 {
    // A wildcard bind is reached on loopback.
    let target = server.addr.replace("0.0.0.0", "127.0.0.1");
    let mut stream = TcpStream::connect(&target).expect("connect");
    let timeout = Some(Duration::from_secs(10));
    stream.set_read_timeout(timeout).expect("read timeout");
    stream.set_write_timeout(timeout).expect("write timeout");
    let authorization = bearer
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    // One write, so a server that answers 401 or 429 without reading the body has the whole
    // request in its buffer rather than a half-sent one it resets.
    let request = format!(
        "POST /v1/mcp HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n{authorization}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        host,
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).expect("status line");
    let head = String::from_utf8_lossy(&head);
    head.strip_prefix("HTTP/1.1 ")
        .and_then(|code| code.trim().parse().ok())
        .unwrap_or_else(|| panic!("unexpected status line: {head:?}"))
}

/// Run a server that must refuse to start, and return what it printed. A regression that let it
/// start fails here after a deadline instead of hanging the suite.
fn refused_startup(env: &[(&str, &str)]) -> String {
    refused_startup_at("127.0.0.1:0", env)
}

fn refused_startup_at(listen: &str, env: &[(&str, &str)]) -> String {
    let mut child = command_at(listen, env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the HTTP server");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("poll the server") {
            assert!(!status.success(), "the server exited successfully");
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .expect("stderr")
                .read_to_string(&mut stderr)
                .expect("stderr text");
            return stderr;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the server started instead of refusing: {env:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_served_endpoint_authenticates_bounds_bodies_and_refuses_requests_over_the_quota() {
    let server = start("3", "4096");
    assert_eq!(post(&server, None, INITIALIZE), 401, "no token");
    assert_eq!(post(&server, Some("wrong"), INITIALIZE), 401, "wrong token");
    // rmcp answers a real handshake through the guard: the re-wrapped body is still readable.
    assert_eq!(post(&server, Some(TOKEN), INITIALIZE), 200, "first request");
    let oversized = format!(r#"{{"pad":"{}"}}"#, "x".repeat(4096));
    assert_eq!(
        post(&server, Some(TOKEN), &oversized),
        413,
        "oversized body"
    );
    assert_eq!(post(&server, Some(TOKEN), INITIALIZE), 200, "third request");
    // Three requests were admitted — the refusals before authentication spent nothing — so
    // the fourth is over the quota.
    assert_eq!(
        post(&server, Some(TOKEN), INITIALIZE),
        429,
        "over the quota"
    );
}

#[test]
fn hosted_mode_refuses_a_configured_source_outside_the_allowlist() {
    let sources = serde_json::json!({"testnet": {
        "rpc_url": "https://other.example",
        "network_passphrase": "Test SDF Network ; September 2015"
    }})
    .to_string();
    let stderr = refused_startup(&[
        ("OZPB_HTTP_BEARER_TOKEN", TOKEN),
        ("OZPB_RPC_ALLOWLIST", "https://rpc.example"),
        ("OZPB_BUILD_JOBS", "1"),
        ("OZPB_RPC_SOURCES_JSON", &sources),
    ]);
    assert!(stderr.contains("is not on OZPB_RPC_ALLOWLIST"), "{stderr}");
}

#[test]
fn hosted_mode_refuses_to_start_on_a_missing_token_or_a_zero_limit() {
    let stderr = refused_startup(&[]);
    assert!(
        stderr.contains("OZPB_HTTP_BEARER_TOKEN is required"),
        "{stderr}"
    );

    for name in [
        "OZPB_HTTP_REQUESTS_PER_MINUTE",
        "OZPB_HTTP_MAX_CONCURRENCY",
        "OZPB_HTTP_MAX_BODY_BYTES",
    ] {
        let stderr = refused_startup(&[
            ("OZPB_HTTP_BEARER_TOKEN", TOKEN),
            ("OZPB_RPC_ALLOWLIST", "https://rpc.example"),
            ("OZPB_BUILD_JOBS", "1"),
            (name, "0"),
        ]);
        assert!(
            stderr.contains(&format!("{name} must be positive")),
            "{name}: {stderr}"
        );
    }
}

#[test]
fn a_routable_listener_needs_the_ingress_hosts_and_answers_only_those() {
    let stderr = refused_startup_at(
        "0.0.0.0:0",
        &[
            ("OZPB_HTTP_BEARER_TOKEN", TOKEN),
            ("OZPB_RPC_ALLOWLIST", "https://rpc.example"),
            ("OZPB_BUILD_JOBS", "1"),
        ],
    );
    assert!(stderr.contains("OZPB_HTTP_ALLOWED_HOSTS"), "{stderr}");

    let server = start_at(
        "0.0.0.0:0",
        &[("OZPB_HTTP_ALLOWED_HOSTS", "mcp.example.test")],
    );
    assert_eq!(
        post_as(&server, "mcp.example.test", None, INITIALIZE),
        401,
        "no token"
    );
    assert_eq!(
        post_as(&server, "mcp.example.test", Some(TOKEN), INITIALIZE),
        200,
        "the named host"
    );
    assert_eq!(
        post_as(&server, "other.example.test", Some(TOKEN), INITIALIZE),
        403,
        "a host the ingress does not forward"
    );
}
