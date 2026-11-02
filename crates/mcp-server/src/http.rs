//! Streamable-HTTP transport: the same `PolicyBuilderServer` stdio serves, behind the guard a
//! hosted, self-hostable endpoint needs (architecture §4.6, §4.11).
//!
//! Every request passes bearer authentication, then a global request quota, then a request-body
//! bound, in that order: an unauthenticated request spends no quota and its body is never read.

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{http_session_factory, require_allowlisted_sources, RpcEndpointPolicy};

/// Requests admitted per fixed window, across every client. Per-client limits belong to the
/// reverse proxy in front of the server, which is the only component that knows the client.
pub(crate) struct RequestQuota {
    limit: u32,
    window: Duration,
    /// Start of the current window and the requests admitted in it.
    state: Mutex<(Instant, u32)>,
}

impl RequestQuota {
    pub(crate) fn per_minute(limit: u32) -> Self {
        Self::starting_at(limit, Instant::now())
    }

    fn starting_at(limit: u32, start: Instant) -> Self {
        Self {
            limit,
            window: Duration::from_secs(60),
            state: Mutex::new((start, 0)),
        }
    }

    pub(crate) fn admit(&self) -> bool {
        self.admit_at(Instant::now())
    }

    /// A fixed window: at most `limit` in one window, so at most twice that across a window
    /// boundary. A poisoned lock refuses rather than admits.
    fn admit_at(&self, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if now.saturating_duration_since(state.0) >= self.window {
            *state = (now, 0);
        }
        if state.1 >= self.limit {
            return false;
        }
        state.1 += 1;
        true
    }
}

/// What the guard checks, shared by every request the router serves.
#[derive(Clone)]
pub(crate) struct HttpSecurity {
    bearer: Arc<str>,
    quota: Arc<RequestQuota>,
    max_body_bytes: usize,
}

impl HttpSecurity {
    pub(crate) fn new(bearer: &str, quota: RequestQuota, max_body_bytes: usize) -> Self {
        Self {
            bearer: Arc::from(bearer),
            quota: Arc::new(quota),
            max_body_bytes,
        }
    }
}

async fn enforce_http_security(
    State(security): State<HttpSecurity>,
    request: Request,
    next: Next,
) -> Response {
    let expected = format!("Bearer {}", security.bearer);
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()));
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    }
    if !security.quota.admit() {
        return (StatusCode::TOO_MANY_REQUESTS, "request quota exceeded").into_response();
    }
    // rmcp reads the body itself with an unbounded collect, and axum's `DefaultBodyLimit` only
    // configures axum's own extractors, so the bound is applied here. rmcp buffers the whole
    // body anyway; buffering it here first is bounded by the same limit.
    let (parts, body) = request.into_parts();
    let limited = http_body_util::Limited::new(body, security.max_body_bytes);
    let bytes: Bytes = match http_body_util::BodyExt::collect(limited).await {
        Ok(collected) => collected.to_bytes(),
        Err(error) if error.is::<http_body_util::LengthLimitError>() => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the limit",
            )
                .into_response();
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "unreadable request body").into_response(),
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Where the MCP service is mounted. Versioned so a breaking transport change can be served
/// beside the old one.
pub(crate) const MCP_PATH: &str = "/v1/mcp";

/// Put every route of `routes` behind the guard. `serve` and the tests both build the MCP route
/// with `nest_service(MCP_PATH, …)` and pass it here, so the tests exercise the served layering.
pub(crate) fn guard(routes: axum::Router, security: HttpSecurity) -> axum::Router {
    routes.layer(middleware::from_fn_with_state(
        security,
        enforce_http_security,
    ))
}

/// A positive integer setting, or `default` when unset. Zero and garbage stop startup rather
/// than silently disabling the bound.
pub(crate) fn parse_positive(name: &str, value: Option<&str>, default: u32) -> anyhow::Result<u32> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u32>()
        .map_err(|error| anyhow::anyhow!("invalid {name}: {error}"))?;
    if parsed == 0 {
        anyhow::bail!("{name} must be positive");
    }
    Ok(parsed)
}

/// One environment variable: `None` when unset, an error when set but not Unicode, so a
/// mangled value stops startup rather than silently falling back to a default.
fn env_var(name: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

/// The limits a hosted server enforces, as `serve` uses them.
pub(crate) struct HostedLimits {
    pub(crate) requests_per_minute: u32,
    pub(crate) max_body_bytes: usize,
    pub(crate) tool_limits: crate::tool_limits::ToolLimitConfig,
    /// The operator's build configuration plus one set of build slots. rmcp builds a handler
    /// per session and each holds a clone; clones share the slots, so the limit holds across
    /// sessions rather than per session.
    pub(crate) build_config: ozpb_toolkit::BuildConfig,
}

/// Read and check the hosted limits. `get` is the environment, so tests need no process-wide
/// mutation; `available_cpus` is the machine's parallelism.
pub(crate) fn hosted_limits<F>(
    get: F,
    build_config: ozpb_toolkit::BuildConfig,
    available_cpus: usize,
) -> anyhow::Result<HostedLimits>
where
    F: Fn(&str) -> anyhow::Result<Option<String>>,
{
    let positive = |name: &str, default: u32| -> anyhow::Result<u32> {
        parse_positive(name, get(name)?.as_deref(), default)
    };
    let requests_per_minute = positive("OZPB_HTTP_REQUESTS_PER_MINUTE", 60)?;
    let tool_limits = crate::tool_limits::ToolLimitConfig::parse(
        positive("OZPB_HTTP_TOOL_REQUESTS_PER_MINUTE", 60)?,
        // Empty means no overrides: the compose file passes the variable through unset as "".
        get("OZPB_HTTP_TOOL_LIMITS_JSON")?
            .as_deref()
            .filter(|json| !json.trim().is_empty()),
    )?;
    // Builds are CPU- and memory-heavy. The build slots and Cargo's worker count form one
    // resource budget; validating their product prevents four simultaneous builds from each
    // starting an almost-machine-wide compile. Operators can trade build concurrency for
    // per-build parallelism explicitly. With the one shared build cache, cargo's lock
    // serializes compiles anyway, so more than one slot queues builds rather than overlapping
    // them.
    let max_concurrency = positive("OZPB_HTTP_MAX_CONCURRENCY", 1)?;
    let build_workers = usize::try_from(build_config.jobs).unwrap_or(usize::MAX);
    let requested_workers = usize::try_from(max_concurrency)
        .unwrap_or(usize::MAX)
        .checked_mul(build_workers)
        .ok_or_else(|| anyhow::anyhow!("HTTP/build concurrency budget overflows"))?;
    if requested_workers > available_cpus {
        anyhow::bail!(
            "OZPB_HTTP_MAX_CONCURRENCY ({max_concurrency}) × OZPB_BUILD_JOBS ({build_workers}) \
             exceeds available parallelism ({available_cpus})"
        );
    }
    let max_body_bytes = positive("OZPB_HTTP_MAX_BODY_BYTES", 1_048_576)? as usize;
    if max_body_bytes > 24 * 1024 * 1024 {
        anyhow::bail!("OZPB_HTTP_MAX_BODY_BYTES must not exceed 25165824");
    }
    Ok(HostedLimits {
        requests_per_minute,
        max_body_bytes,
        tool_limits,
        build_config: ozpb_toolkit::BuildConfig {
            slots: Some(ozpb_toolkit::BuildSlots::new(max_concurrency)?),
            ..build_config
        },
    })
}

/// Serve the MCP handler over streamable HTTP. Refuses to start without a bearer token, an RPC
/// allowlist, and limits that fit the machine.
pub(crate) async fn serve(
    addr: &str,
    registry_trust: Option<ozpb_toolkit::RegistryTrust>,
    rpc_sources: Arc<std::collections::BTreeMap<String, ozpb_toolkit::RpcSource>>,
    build_config: ozpb_toolkit::BuildConfig,
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService,
    };

    let socket = require_loopback_bind(addr)?;
    let bearer = std::env::var("OZPB_HTTP_BEARER_TOKEN")
        .map_err(|_| anyhow::anyhow!("OZPB_HTTP_BEARER_TOKEN is required for HTTP mode"))?;
    if bearer.len() < 32 {
        anyhow::bail!("OZPB_HTTP_BEARER_TOKEN must contain at least 32 bytes");
    }
    let rpc_allowlist = std::env::var("OZPB_RPC_ALLOWLIST")
        .map_err(|_| anyhow::anyhow!("OZPB_RPC_ALLOWLIST is required for HTTP mode"))?;
    let rpc_policy = RpcEndpointPolicy::from_csv(&rpc_allowlist)?;
    require_allowlisted_sources(&rpc_policy, &rpc_sources)?;
    let available_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let limits = hosted_limits(env_var, build_config, available_cpus)?;
    let security = HttpSecurity::new(
        &bearer,
        RequestQuota::per_minute(limits.requests_per_minute),
        limits.max_body_bytes,
    );
    let build_config = limits.build_config;

    let ct = tokio_util::sync::CancellationToken::new();
    let service = StreamableHttpService::new(
        http_session_factory(
            registry_trust,
            rpc_policy,
            rpc_sources,
            build_config,
            limits.tool_limits,
        )?,
        LocalSessionManager::default().into(),
        Default::default(),
    );
    let router = guard(
        axum::Router::new().nest_service(MCP_PATH, service),
        security,
    );
    let listener = tokio::net::TcpListener::bind(socket).await?;
    // The bound address, not the requested one, so port 0 reports the port it was given.
    eprintln!(
        "ozpb MCP streamable-HTTP endpoint on http://{}{MCP_PATH}",
        listener.local_addr()?
    );
    let ct2 = ct.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct2.cancel();
        })
        .await?;
    Ok(())
}

/// Parse a bind address and require it to be loopback. Public exposure must go through a
/// TLS-terminating, authenticating reverse proxy; the server itself never binds a routable
/// interface. Extracted so the guard is unit-testable without starting a listener.
pub(crate) fn require_loopback_bind(addr: &str) -> anyhow::Result<std::net::SocketAddr> {
    let socket: std::net::SocketAddr = addr
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid HTTP listen address '{addr}': {error}"))?;
    if !socket.ip().is_loopback() {
        anyhow::bail!(
            "HTTP listener must bind to loopback; terminate TLS at an authenticated reverse proxy"
        );
    }
    Ok(socket)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max = left.len().max(right.len());
    for index in 0..max {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// A test-only bearer value, long enough for the startup check.
    const TOKEN: &str = "test-bearer-0123456789abcdef0123456789";

    /// The guard in front of a stand-in service that answers 200 with the length of the body it
    /// received.
    fn guarded(limit: u32, max_body_bytes: usize) -> axum::Router {
        guard(
            axum::Router::new().nest_service(
                MCP_PATH,
                axum::routing::any(|body: Bytes| async move { body.len().to_string() }),
            ),
            HttpSecurity::new(TOKEN, RequestQuota::per_minute(limit), max_body_bytes),
        )
    }

    /// The status, and the body length the stand-in reports.
    async fn post_reading(
        router: &axum::Router,
        bearer: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, String) {
        let mut request = Request::post(MCP_PATH);
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("infallible router");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("response body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn post(router: &axum::Router, bearer: Option<&str>, body: Vec<u8>) -> StatusCode {
        let mut request = Request::post(MCP_PATH);
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("infallible router")
            .status()
    }

    #[tokio::test]
    async fn requests_over_the_quota_are_refused_with_429() {
        let router = guarded(2, 1024);
        assert_eq!(post(&router, Some(TOKEN), vec![]).await, StatusCode::OK);
        assert_eq!(post(&router, Some(TOKEN), vec![]).await, StatusCode::OK);
        assert_eq!(
            post(&router, Some(TOKEN), vec![]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_refused_without_spending_the_quota() {
        let router = guarded(1, 1024);
        assert_eq!(post(&router, None, vec![]).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            post(&router, Some("not-the-token"), vec![]).await,
            StatusCode::UNAUTHORIZED
        );
        // The one admitted request is still available after two refusals.
        assert_eq!(post(&router, Some(TOKEN), vec![]).await, StatusCode::OK);
        assert_eq!(
            post(&router, Some(TOKEN), vec![]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn a_body_over_the_bound_is_refused_and_one_within_it_arrives_whole() {
        let router = guarded(10, 16);
        assert_eq!(
            post_reading(&router, Some(TOKEN), vec![b'x'; 16]).await,
            (StatusCode::OK, "16".to_string()),
            "a body at the bound must reach the service intact"
        );
        assert_eq!(
            post(&router, Some(TOKEN), vec![b'x'; 17]).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // The bound applies after authentication: an unauthenticated oversized body is a 401.
        assert_eq!(
            post(&router, None, vec![b'x'; 17]).await,
            StatusCode::UNAUTHORIZED
        );
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> anyhow::Result<Option<String>> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        move |name| {
            Ok(pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone()))
        }
    }

    fn one_job() -> ozpb_toolkit::BuildConfig {
        ozpb_toolkit::BuildConfig {
            jobs: 1,
            ..ozpb_toolkit::BuildConfig::default()
        }
    }

    #[test]
    fn hosted_limits_default_to_one_build_slot_and_the_documented_bounds() {
        let limits = hosted_limits(env(&[]), one_job(), 4).expect("defaults fit");
        assert_eq!(limits.requests_per_minute, 60);
        assert_eq!(limits.max_body_bytes, 1_048_576);
        let slots = limits
            .build_config
            .slots
            .expect("a hosted server bounds its builds");
        assert_eq!(slots.available(), 1);
    }

    #[test]
    fn an_empty_tool_override_means_none_and_a_bad_one_stops_startup() {
        // The compose file passes an unset override through as "".
        for empty in ["", "  "] {
            let limits = hosted_limits(
                env(&[
                    ("OZPB_HTTP_TOOL_LIMITS_JSON", empty),
                    ("OZPB_HTTP_TOOL_REQUESTS_PER_MINUTE", "9"),
                ]),
                one_job(),
                4,
            )
            .expect("an empty override is no override");
            assert_eq!(limits.tool_limits.default_per_minute, 9);
        }
        assert!(hosted_limits(
            env(&[("OZPB_HTTP_TOOL_LIMITS_JSON", "{\"generate_code\":0}")]),
            one_job(),
            4
        )
        .is_err());
    }

    #[test]
    fn the_build_slots_are_the_configured_concurrency() {
        let limits = hosted_limits(
            env(&[
                ("OZPB_HTTP_MAX_CONCURRENCY", "3"),
                ("OZPB_HTTP_REQUESTS_PER_MINUTE", "7"),
                ("OZPB_HTTP_MAX_BODY_BYTES", "2048"),
            ]),
            one_job(),
            4,
        )
        .expect("three one-job builds fit four CPUs");
        assert_eq!(limits.requests_per_minute, 7);
        assert_eq!(limits.max_body_bytes, 2048);
        assert_eq!(
            limits.build_config.slots.map(|slots| slots.available()),
            Some(3)
        );
    }

    #[test]
    fn hosted_limits_that_do_not_fit_the_machine_stop_startup() {
        let two_jobs = ozpb_toolkit::BuildConfig {
            jobs: 2,
            ..ozpb_toolkit::BuildConfig::default()
        };
        let error = hosted_limits(env(&[("OZPB_HTTP_MAX_CONCURRENCY", "3")]), two_jobs, 4)
            .err()
            .expect("3 builds × 2 jobs exceed 4 CPUs");
        assert!(
            error.to_string().contains("exceeds available parallelism"),
            "{error}"
        );
        let error = hosted_limits(
            env(&[("OZPB_HTTP_MAX_BODY_BYTES", "25165825")]),
            one_job(),
            4,
        )
        .err()
        .expect("a body bound over 24 MiB");
        assert!(error.to_string().contains("must not exceed"), "{error}");
        let error = hosted_limits(env(&[("OZPB_HTTP_MAX_CONCURRENCY", "0")]), one_job(), 4)
            .err()
            .expect("zero build slots");
        assert!(error.to_string().contains("must be positive"), "{error}");
    }

    #[test]
    fn the_quota_admits_again_once_its_window_has_passed() {
        let start = Instant::now();
        let quota = RequestQuota::starting_at(2, start);
        assert!(quota.admit_at(start));
        assert!(quota.admit_at(start + Duration::from_secs(1)));
        assert!(!quota.admit_at(start + Duration::from_secs(59)));
        // A new window starts the count again, and is itself bounded.
        assert!(quota.admit_at(start + Duration::from_secs(60)));
        assert!(quota.admit_at(start + Duration::from_secs(61)));
        assert!(!quota.admit_at(start + Duration::from_secs(62)));
    }

    #[test]
    fn a_zero_or_malformed_limit_stops_startup() {
        assert_eq!(parse_positive("LIMIT", None, 60).unwrap(), 60);
        assert_eq!(parse_positive("LIMIT", Some("5"), 60).unwrap(), 5);
        for bad in ["0", "-1", "ten", ""] {
            let error = parse_positive("LIMIT", Some(bad), 60).expect_err(bad);
            assert!(error.to_string().contains("LIMIT"), "{bad}: {error}");
        }
    }

    #[test]
    fn loopback_bind_is_required() {
        // Loopback binds (v4 and v6) are accepted.
        assert!(require_loopback_bind("127.0.0.1:8080").is_ok());
        assert!(require_loopback_bind("[::1]:8080").is_ok());
        // Routable interfaces are refused — no accidental public exposure.
        assert!(require_loopback_bind("0.0.0.0:8080").is_err());
        assert!(require_loopback_bind("192.168.1.10:8080").is_err());
        assert!(require_loopback_bind("203.0.113.5:8080").is_err());
        // Garbage is a parse error, not a bind.
        assert!(require_loopback_bind("not-an-addr").is_err());
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(
            b"Bearer secret-token",
            b"Bearer secret-token"
        ));
        // Same length, differing content.
        assert!(!constant_time_eq(
            b"Bearer secret-token",
            b"Bearer wrong-token!"
        ));
        // Different length.
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
