//! Per-tool fixed-window admission shared across hosted sessions, before dispatch.
use crate::http::RequestQuota;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Tools that build or read an RPC endpoint, limited to at most 4 calls a minute by default.
const HEAVY: [&str; 11] = [
    "generate_code",
    "verify",
    "prepare_dry_run",
    "record_transaction",
    "record_simulation",
    "preflight_transaction",
    "check_policy_call_surface",
    "prepare_install_intent",
    "assemble_install_transaction",
    "check_against_policy",
    "capture_target",
];
/// Pure tools: bounded by their own size limits and the ordinary per-tool default.
#[cfg(test)]
const PURE: [&str; 4] = [
    "synthesize_policy",
    "evaluate_spec",
    "import_recording",
    "reference_suite",
];

#[derive(Clone)]
pub(crate) struct ToolLimitConfig {
    pub(crate) default_per_minute: u32,
    overrides: BTreeMap<String, u32>,
}
impl ToolLimitConfig {
    pub(crate) fn parse(default_per_minute: u32, json: Option<&str>) -> anyhow::Result<Self> {
        let overrides: BTreeMap<String, u32> = json
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| {
                anyhow::anyhow!(
                    "OZPB_HTTP_TOOL_LIMITS_JSON must map tool names to positive integer limits"
                )
            })?
            .unwrap_or_default();
        if default_per_minute == 0 || overrides.values().any(|limit| *limit == 0) {
            anyhow::bail!("per-tool request limits must be positive");
        }
        Ok(Self {
            default_per_minute,
            overrides,
        })
    }
    fn limit(&self, name: &str) -> u32 {
        self.overrides.get(name).copied().unwrap_or_else(|| {
            if HEAVY.contains(&name) {
                self.default_per_minute.min(4)
            } else {
                self.default_per_minute
            }
        })
    }
}

#[derive(Clone)]
pub(crate) struct ToolQuotas {
    quotas: Arc<BTreeMap<String, RequestQuota>>,
}
impl ToolQuotas {
    pub(crate) fn new(
        names: impl IntoIterator<Item = String>,
        config: ToolLimitConfig,
    ) -> anyhow::Result<Self> {
        let quotas: BTreeMap<_, _> = names
            .into_iter()
            .map(|name| {
                let quota = RequestQuota::per_minute(config.limit(&name));
                (name, quota)
            })
            .collect();
        if config
            .overrides
            .keys()
            .any(|name| !quotas.contains_key(name))
        {
            anyhow::bail!("OZPB_HTTP_TOOL_LIMITS_JSON contains an unknown tool name");
        }
        Ok(Self {
            quotas: Arc::new(quotas),
        })
    }
    pub(crate) fn admit(&self, name: &str) -> bool {
        self.quotas.get(name).is_some_and(RequestQuota::admit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotas_are_independent_and_clones_share_counts() {
        let quotas = ToolQuotas::new(
            ["generate_code".into(), "reference_suite".into()],
            ToolLimitConfig::parse(60, Some(r#"{"generate_code":1}"#)).unwrap(),
        )
        .unwrap();
        assert!(quotas.admit("generate_code"));
        assert!(!quotas.clone().admit("generate_code"));
        assert!(quotas.admit("reference_suite"));
        assert!(!quotas.admit("unknown"));
    }
    /// Every tool is classified, so a new one cannot silently get the light default.
    #[test]
    fn every_routed_tool_is_classified_heavy_or_pure() {
        let routed: std::collections::BTreeSet<String> = crate::tests::hosted()
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        let classified: std::collections::BTreeSet<String> = HEAVY
            .iter()
            .chain(PURE.iter())
            .map(|name| name.to_string())
            .collect();
        assert_eq!(routed, classified);
        assert!(HEAVY.iter().all(|name| !PURE.contains(name)));
    }

    #[test]
    fn malformed_limits_and_unknown_overrides_refuse_startup() {
        for json in [
            "null",
            "[]",
            r#"{"generate_code":0}"#,
            r#"{"generate_code":-1}"#,
            r#"{"generate_code":1.5}"#,
            r#"{"generate_code":"1"}"#,
        ] {
            assert!(ToolLimitConfig::parse(60, Some(json)).is_err(), "{json}");
        }
        assert!(ToolQuotas::new(
            ["generate_code".into()],
            ToolLimitConfig::parse(60, Some(r#"{"typo":1}"#)).unwrap()
        )
        .is_err());
        let config = ToolLimitConfig::parse(2, None).unwrap();
        assert_eq!(config.limit("generate_code"), 2);
        assert_eq!(config.limit("reference_suite"), 2);
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use crate::{http_session_factory, PolicyBuilderServer, RpcEndpointPolicy};
    use rmcp::ServiceExt;
    use serde_json::{json, Value};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// Real MCP handshake/dispatch on an in-memory transport, through the same hosted
    /// session factory as HTTP. Each request waits for its own response before the next.
    async fn session(server: PolicyBuilderServer, calls: Vec<Value>) -> Vec<Value> {
        let (server_io, client_io) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            server
                .serve(server_io)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let (read, mut write) = tokio::io::split(client_io);
        let mut read = BufReader::new(read);
        let mut messages = vec![
            json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-03-26", "capabilities":{}, "clientInfo":{"name":"quota-test","version":"1"}}}),
        ];
        messages.extend(calls);
        let mut results = Vec::new();
        for message in messages {
            write
                .write_all(format!("{message}\n").as_bytes())
                .await
                .unwrap();
            loop {
                let mut line = String::new();
                let length = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read.read_line(&mut line),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(length > 0);
                let response: Value = serde_json::from_str(&line).unwrap();
                if response.get("id") == message.get("id") {
                    if message["id"] == 1 {
                        write
                            .write_all(
                                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
                            )
                            .await
                            .unwrap();
                    } else {
                        results.push(response);
                    }
                    break;
                }
            }
        }
        write.shutdown().await.unwrap();
        drop(write);
        drop(read);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        results
    }

    #[tokio::test]
    async fn tool_quota_refuses_generate_code_after_limit_while_reference_suite_still_served() {
        // This valid request reaches the configured missing builder and spends its budget;
        // failed attempts are intentionally not refunded.
        let config = crate::tests::hosted().build_config;
        let factory = http_session_factory(
            None,
            RpcEndpointPolicy::from_csv("https://rpc.allowed.example").unwrap(),
            Default::default(),
            config,
            ToolLimitConfig::parse(60, Some(r#"{"generate_code":1}"#)).unwrap(),
        )
        .unwrap();
        let spec = crate::tests::subscription_spec();
        let generate = |id| {
            json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{
            "name":"generate_code", "arguments":{"spec":spec,"rule_index":0}}})
        };
        let first = session(factory().unwrap(), vec![generate(2)]).await;
        assert_eq!(
            first[0]["result"]["structuredContent"]["code"], "E_BUILD_UNAVAILABLE",
            "{}",
            first[0]
        );
        let second = session(
            factory().unwrap(),
            vec![
                generate(2),
                json!({"jsonrpc":"2.0", "id":3,
            "method":"tools/call", "params":{"name":"reference_suite","arguments":{"spec":spec}}}),
            ],
        )
        .await;
        assert_eq!(
            second[0]["result"]["structuredContent"]["code"],
            "E_RESOURCE_LIMIT"
        );
        assert_eq!(second[1]["result"]["isError"], false, "{}", second[1]);
        assert!(second[1]["result"]["structuredContent"]["report"]["spec_hash"].is_string());
    }
}
