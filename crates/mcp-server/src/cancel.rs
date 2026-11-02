//! A client's `notifications/cancelled`, or the end of its session, stops the work its request
//! started. rmcp only cancels the request's token; the blocking work behind a tool has to look
//! at it. Builds poll it and terminate their process group (a disposable worker is asked to
//! remove its job), and network reads make no further RPC call once it is set. A call already
//! in flight still ends on its own transport timeout.

use ozpb_api_types::{ErrorCode, ToolError};
use ozpb_source_rpc::{HttpTransport, RpcError, RpcTransport};
use rmcp::model::CallToolResult;
use tokio_util::sync::CancellationToken;

/// The operator's build configuration for one request, with that request's cancellation.
pub(crate) fn build_config(
    base: &ozpb_toolkit::BuildConfig,
    ct: &CancellationToken,
) -> ozpb_toolkit::BuildConfig {
    let ct = ct.clone();
    ozpb_toolkit::BuildConfig {
        cancel: Some(ozpb_toolkit::BuildCancel::new(move || ct.is_cancelled())),
        ..base.clone()
    }
}

/// An RPC transport that refuses every call once its request is cancelled.
pub(crate) struct Cancellable<T> {
    inner: T,
    ct: CancellationToken,
}

impl<T: RpcTransport> RpcTransport for Cancellable<T> {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        if self.ct.is_cancelled() {
            return Err(RpcError::Transport("request cancelled".into()));
        }
        self.inner.call(method, params)
    }
}

/// The HTTP transport for one request's reads.
pub(crate) fn transport(url: String, ct: &CancellationToken) -> Cancellable<HttpTransport> {
    Cancellable {
        inner: HttpTransport::new(url),
        ct: ct.clone(),
    }
}

/// Whatever the stopped work returned, a cancelled request's result is this. rmcp sends no
/// response to the client that cancelled (as MCP specifies); the code names the outcome for the
/// server's own handling and for a request cancelled by its session ending.
pub(crate) fn refusal() -> CallToolResult {
    crate::tool_err(ToolError::new(
        ErrorCode::ECancelled,
        "the request was cancelled; its work was stopped",
    ))
}

/// `result`, unless the request was cancelled while it was produced.
pub(crate) fn unless_cancelled<T>(
    ct: &CancellationToken,
    result: Result<T, CallToolResult>,
) -> Result<T, CallToolResult> {
    if ct.is_cancelled() {
        return Err(refusal());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Answers `getNetwork` like a testnet endpoint, refuses everything else, and records each
    /// method it was asked for. `on_first` runs once, after the first call is answered.
    struct Endpoint {
        calls: RefCell<Vec<String>>,
        on_first: Box<dyn Fn()>,
    }

    impl RpcTransport for Endpoint {
        fn call(&self, method: &str, _: serde_json::Value) -> Result<serde_json::Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            if self.calls.borrow().len() == 1 {
                (self.on_first)();
            }
            match method {
                "getNetwork" => Ok(serde_json::json!({
                    "passphrase": ozpb_domain::TESTNET_PASSPHRASE,
                    "protocolVersion": ozpb_recorder_core::MAX_ACQUISITION_PROTOCOL,
                })),
                _ => Err(RpcError::Rpc("fixture answers getNetwork only".into())),
            }
        }
    }

    fn scan(transport: &impl RpcTransport) {
        let _ = ozpb_source_rpc::scan_authority_state(
            transport,
            ozpb_domain::TESTNET_PASSPHRASE,
            "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526",
            &[],
            &[],
            Default::default(),
        );
    }

    #[test]
    fn cancelled_authority_read_issues_no_further_rpc_call() {
        // Control: uncancelled, the scan goes on past `getNetwork` to read ledger entries, so
        // a single call below is the cancellation's doing and not the fixture's.
        let ct = CancellationToken::new();
        let uncancelled = Cancellable {
            inner: Endpoint {
                calls: RefCell::default(),
                on_first: Box::new(|| {}),
            },
            ct: ct.clone(),
        };
        scan(&uncancelled);
        assert!(uncancelled.inner.calls.borrow().len() > 1);

        // The client cancels while the first call is being answered.
        let ct = CancellationToken::new();
        let cancel = ct.clone();
        let cancelled = Cancellable {
            inner: Endpoint {
                calls: RefCell::default(),
                on_first: Box::new(move || cancel.cancel()),
            },
            ct,
        };
        scan(&cancelled);
        assert_eq!(*cancelled.inner.calls.borrow(), vec!["getNetwork"]);
    }

    #[test]
    fn a_cancelled_request_answers_e_cancelled_whatever_its_work_returned() {
        let ct = CancellationToken::new();
        assert_eq!(
            unless_cancelled(&ct, Ok::<_, CallToolResult>(1)).ok(),
            Some(1)
        );
        ct.cancel();
        let refused = unless_cancelled(&ct, Ok::<_, CallToolResult>(1)).unwrap_err();
        let wire = serde_json::to_value(refused).unwrap();
        assert_eq!(wire["structuredContent"]["code"], "E_CANCELLED");
    }

    /// A builder that backgrounds a long-lived grandchild, records its pid and waits, the way
    /// `stellar contract build` waits on cargo and rustc.
    #[cfg(unix)]
    fn slow_builder(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let pidfile = dir.join("grandchild.pid");
        let builder = dir.join("stellar");
        std::fs::write(
            &builder,
            format!(
                "#!/bin/sh\n/bin/sleep 30 &\necho $! > {0}.tmp && /bin/mv {0}.tmp {0}\nwait\n",
                pidfile.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&builder, std::fs::Permissions::from_mode(0o755)).unwrap();
        (builder, pidfile)
    }

    #[cfg(unix)]
    fn alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// The real MCP dispatch on an in-memory transport: a client starts `generate_code`, sees
    /// the build running, and sends `notifications/cancelled` for it.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_generate_code_kills_worker_group_and_frees_build_slot() {
        use rmcp::ServiceExt;
        use serde_json::{json, Value};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = std::env::temp_dir().join(format!(
            "ozpb-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (builder, pidfile) = slow_builder(&dir);
        let mut server = crate::tests::hosted();
        server.build_config.stellar_binary = builder;
        server.build_config.target_dir = Some(dir.join("target"));
        server.build_config.timeout = std::time::Duration::from_secs(120);
        let slots = server
            .build_config
            .slots
            .clone()
            .expect("hosted build slots");

        let (server_io, client_io) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(async move {
            server
                .serve(server_io)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        type Lines = tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>;
        async fn next_response(lines: &mut Lines, id: u64) -> Value {
            loop {
                let line =
                    tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
                        .await
                        .expect("a response in time")
                        .unwrap()
                        .expect("an open transport");
                let message: Value = serde_json::from_str(&line).unwrap();
                if message["id"] == id {
                    return message;
                }
            }
        }
        fn send(message: Value) -> String {
            format!("{message}\n")
        }
        let (read, mut write) = tokio::io::split(client_io);
        let mut lines: Lines = BufReader::new(read).lines();
        let initialize = json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-03-26", "capabilities":{}, "clientInfo":{"name":"cancel-test","version":"1"}}});
        write.write_all(send(initialize).as_bytes()).await.unwrap();
        next_response(&mut lines, 1).await;
        write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let generate = json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{
            "name":"generate_code",
            "arguments":{"spec":crate::tests::subscription_spec(),"rule_index":0}}});
        write.write_all(send(generate).as_bytes()).await.unwrap();

        let started = std::time::Instant::now();
        while !pidfile.exists() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the build never started its grandchild"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            slots.available(),
            0,
            "the running build holds the only slot"
        );
        let cancelled = json!({"jsonrpc":"2.0", "method":"notifications/cancelled",
            "params":{"requestId":2, "reason":"user stopped"}});
        write.write_all(send(cancelled).as_bytes()).await.unwrap();

        while slots.available() == 0 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the build ran on toward its 120 s timeout and kept its slot"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // MCP sends no response to a cancelled request: the next answer is the ping's.
        write
            .write_all(send(json!({"jsonrpc":"2.0", "id":3, "method":"ping"})).as_bytes())
            .await
            .unwrap();
        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
                .await
                .expect("a response in time")
                .unwrap()
                .expect("an open transport");
            let message: Value = serde_json::from_str(&line).unwrap();
            assert_ne!(message["id"], 2, "a cancelled call was answered: {message}");
            if message["id"] == 3 {
                break;
            }
        }
        let pid = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .to_string();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while alive(&pid) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            !alive(&pid),
            "the builder's grandchild {pid} survived cancellation"
        );

        write.shutdown().await.unwrap();
        drop(write);
        drop(lines);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_build_config_keeps_the_operator_settings_and_shares_the_slots() {
        let slots = ozpb_toolkit::BuildSlots::new(1).unwrap();
        let base = ozpb_toolkit::BuildConfig {
            jobs: 3,
            slots: Some(slots.clone()),
            ..ozpb_toolkit::BuildConfig::default()
        };
        let ct = CancellationToken::new();
        let request = build_config(&base, &ct);
        assert_eq!(request.jobs, 3);
        let taken = request.slots.as_ref().unwrap().try_take();
        assert_eq!(
            slots.available(),
            0,
            "a request config must draw from the shared slots"
        );
        drop(taken);
        let cancel = request.cancel.unwrap();
        assert!(!cancel.is_cancelled());
        ct.cancel();
        assert!(cancel.is_cancelled());
        assert!(
            base.cancel.is_none(),
            "the operator's configuration is never cancelled"
        );
    }
}
