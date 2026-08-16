//! HTTP entrypoint for the Olopa ingest server.
//!
//! Responsibilities:
//! - initialize logging/tracing,
//! - construct and start the ingest runtime worker,
//! - expose health and ingest APIs over Axum,
//! - handle graceful shutdown and worker drain.

mod config;
mod durability;
mod telemetry;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{parse_auth_tokens, AuthConfig, AuthTokenScope, ServerConfig};
use crate::telemetry::{
    AckResponse, IngestBatchRequest, IngestDataSummaryResponse, IngestRuntime, IngestStatsResponse,
    ReadinessResponse, RecentIngestResponse,
};

/// Shared application state injected into route handlers.
#[derive(Clone)]
struct AppState {
    /// Background ingest runtime used by API handlers.
    runtime: Arc<IngestRuntime>,
    /// API authn/authz state.
    auth: Arc<AuthState>,
    /// Per-tenant/host token buckets for admission control.
    rate_limiter: Arc<RateLimiter>,
}

/// Command line overrides for ingest server runtime configuration.
#[derive(Debug, Parser)]
#[command(
    name = "olopa-ingest",
    about = "Olopa ingest API server",
    after_help = "Examples:\n  olopa-ingest --host 0.0.0.0 --port 8000\n  olopa-ingest --ingest-surreal-url http://127.0.0.1:8000/sql --ingest-clickhouse-url http://127.0.0.1:8123/\n  olopa-ingest --print-effective-config"
)]
struct Cli {
    /// Override bind host (fallback: SERVER_HOST env).
    #[arg(long)]
    host: Option<String>,
    /// Override bind port (fallback: SERVER_PORT env).
    #[arg(long)]
    port: Option<u16>,
    /// Override `RUST_LOG` filter string for this process.
    #[arg(long)]
    log_filter: Option<String>,
    /// Override INGEST_API_TOKENS in `token[:tenant-a|tenant-b]` format.
    #[arg(long)]
    ingest_api_tokens: Option<String>,

    /// Override ingest queue max size.
    #[arg(long)]
    queue_maxsize: Option<usize>,
    /// Override flush interval in milliseconds.
    #[arg(long)]
    flush_interval_ms: Option<u64>,
    /// Override flush max rows threshold.
    #[arg(long)]
    flush_max_rows: Option<usize>,
    /// Override default retry-after milliseconds.
    #[arg(long)]
    default_retry_after_ms: Option<u32>,
    /// Override suggested batch payload size in bytes.
    #[arg(long)]
    suggested_batch_bytes: Option<u32>,
    /// Override in-memory recent events retention cap.
    #[arg(long)]
    recent_events_max: Option<usize>,
    /// Override local JSONL persistence path.
    #[arg(long)]
    ingest_persist_jsonl_path: Option<String>,

    /// Override ClickHouse HTTP endpoint.
    #[arg(long)]
    ingest_clickhouse_url: Option<String>,
    /// Override ClickHouse insert SQL (`... FORMAT JSONEachRow`).
    #[arg(long)]
    ingest_clickhouse_insert_sql: Option<String>,
    /// Override ClickHouse basic auth username.
    #[arg(long)]
    ingest_clickhouse_user: Option<String>,
    /// Override ClickHouse basic auth password.
    #[arg(long)]
    ingest_clickhouse_password: Option<String>,
    /// Override ClickHouse HTTP timeout in milliseconds.
    #[arg(long)]
    ingest_clickhouse_timeout_ms: Option<u64>,
    /// Disable ClickHouse sink regardless of env/CLI URL.
    #[arg(long, action = ArgAction::SetTrue)]
    disable_clickhouse: bool,

    /// Override SurrealDB HTTP SQL endpoint.
    #[arg(long)]
    ingest_surreal_url: Option<String>,
    /// Override SurrealDB namespace.
    #[arg(long)]
    ingest_surreal_namespace: Option<String>,
    /// Override SurrealDB database.
    #[arg(long)]
    ingest_surreal_database: Option<String>,
    /// Override SurrealDB target table.
    #[arg(long)]
    ingest_surreal_table: Option<String>,
    /// Override SurrealDB basic auth username.
    #[arg(long)]
    ingest_surreal_user: Option<String>,
    /// Override SurrealDB basic auth password.
    #[arg(long)]
    ingest_surreal_password: Option<String>,
    /// Override SurrealDB bearer token.
    #[arg(long)]
    ingest_surreal_token: Option<String>,
    /// Override SurrealDB timeout in milliseconds.
    #[arg(long)]
    ingest_surreal_timeout_ms: Option<u64>,
    /// Disable SurrealDB sink regardless of env/CLI URL.
    #[arg(long, action = ArgAction::SetTrue)]
    disable_surreal: bool,

    /// Print resolved effective config JSON and exit.
    #[arg(long, action = ArgAction::SetTrue)]
    print_effective_config: bool,
}

/// Redacted effective server config snapshot for CLI inspection.
#[derive(Debug, Serialize)]
struct EffectiveServerConfig {
    host: String,
    port: u16,
    auth_enabled: bool,
    auth_token_count: usize,
    production_mode: bool,
    cors_allowed_origins: Vec<String>,
    max_request_body_bytes: usize,
    rate_limit_per_second: u32,
    rate_limit_burst: u32,
    rate_limit_max_keys: usize,
    ingest: EffectiveIngestConfig,
}

/// Redacted ingest runtime config snapshot for CLI inspection.
#[derive(Debug, Serialize)]
struct EffectiveIngestConfig {
    queue_maxsize: usize,
    flush_interval_ms: u64,
    flush_max_rows: usize,
    default_retry_after_ms: u32,
    suggested_batch_bytes: u32,
    recent_events_max: usize,
    dedupe_max_entries: usize,
    wal_path: String,
    dedupe_path: String,
    flush_workers: usize,
    wal_compact_after_commits: usize,
    sink_retry_max_attempts: u32,
    sink_retry_initial_ms: u64,
    sink_retry_max_ms: u64,
    circuit_failure_threshold: u32,
    circuit_open_ms: u64,
    dead_letter_path: String,
    persist_jsonl_path: String,
    clickhouse_enabled: bool,
    clickhouse_url: Option<String>,
    clickhouse_insert_sql: String,
    clickhouse_basic_auth: bool,
    clickhouse_timeout_ms: u64,
    surreal_enabled: bool,
    surreal_url: Option<String>,
    surreal_namespace: String,
    surreal_database: String,
    surreal_table: String,
    surreal_auth_mode: &'static str,
    surreal_timeout_ms: u64,
}

impl EffectiveServerConfig {
    fn from_config(cfg: &ServerConfig) -> Self {
        let surreal_auth_mode = if cfg.ingest.surreal_token.is_some() {
            "token"
        } else if cfg.ingest.surreal_user.is_some() {
            "basic"
        } else {
            "none"
        };
        Self {
            host: cfg.host.clone(),
            port: cfg.port,
            auth_enabled: cfg.auth.enabled(),
            auth_token_count: cfg.auth.tokens.len(),
            production_mode: cfg.production_mode,
            cors_allowed_origins: cfg.cors_allowed_origins.clone(),
            max_request_body_bytes: cfg.max_request_body_bytes,
            rate_limit_per_second: cfg.rate_limit_per_second,
            rate_limit_burst: cfg.rate_limit_burst,
            rate_limit_max_keys: cfg.rate_limit_max_keys,
            ingest: EffectiveIngestConfig {
                queue_maxsize: cfg.ingest.queue_maxsize,
                flush_interval_ms: cfg.ingest.flush_interval_ms,
                flush_max_rows: cfg.ingest.flush_max_rows,
                default_retry_after_ms: cfg.ingest.default_retry_after_ms,
                suggested_batch_bytes: cfg.ingest.suggested_batch_bytes,
                recent_events_max: cfg.ingest.recent_events_max,
                dedupe_max_entries: cfg.ingest.dedupe_max_entries,
                wal_path: cfg.ingest.wal_path.clone(),
                dedupe_path: cfg.ingest.dedupe_path.clone(),
                flush_workers: cfg.ingest.flush_workers,
                wal_compact_after_commits: cfg.ingest.wal_compact_after_commits,
                sink_retry_max_attempts: cfg.ingest.sink_retry_max_attempts,
                sink_retry_initial_ms: cfg.ingest.sink_retry_initial_ms,
                sink_retry_max_ms: cfg.ingest.sink_retry_max_ms,
                circuit_failure_threshold: cfg.ingest.circuit_failure_threshold,
                circuit_open_ms: cfg.ingest.circuit_open_ms,
                dead_letter_path: cfg.ingest.dead_letter_path.clone(),
                persist_jsonl_path: cfg.ingest.persist_jsonl_path.clone(),
                clickhouse_enabled: cfg.ingest.clickhouse_url.is_some(),
                clickhouse_url: cfg.ingest.clickhouse_url.clone(),
                clickhouse_insert_sql: cfg.ingest.clickhouse_insert_sql.clone(),
                clickhouse_basic_auth: cfg.ingest.clickhouse_user.is_some(),
                clickhouse_timeout_ms: cfg.ingest.clickhouse_timeout_ms,
                surreal_enabled: cfg.ingest.surreal_url.is_some(),
                surreal_url: cfg.ingest.surreal_url.clone(),
                surreal_namespace: cfg.ingest.surreal_namespace.clone(),
                surreal_database: cfg.ingest.surreal_database.clone(),
                surreal_table: cfg.ingest.surreal_table.clone(),
                surreal_auth_mode,
                surreal_timeout_ms: cfg.ingest.surreal_timeout_ms,
            },
        }
    }
}

fn apply_cli_overrides(cfg: &mut ServerConfig, cli: &Cli) {
    if let Some(v) = cli.host.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        cfg.host = v.to_string();
    }
    if let Some(v) = cli.port {
        cfg.port = v;
    }
    if let Some(v) = cli
        .ingest_api_tokens
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.auth.tokens = parse_auth_tokens(v);
    }

    if let Some(v) = cli.queue_maxsize {
        cfg.ingest.queue_maxsize = v;
    }
    if let Some(v) = cli.flush_interval_ms {
        cfg.ingest.flush_interval_ms = v;
    }
    if let Some(v) = cli.flush_max_rows {
        cfg.ingest.flush_max_rows = v;
    }
    if let Some(v) = cli.default_retry_after_ms {
        cfg.ingest.default_retry_after_ms = v;
    }
    if let Some(v) = cli.suggested_batch_bytes {
        cfg.ingest.suggested_batch_bytes = v;
    }
    if let Some(v) = cli.recent_events_max {
        cfg.ingest.recent_events_max = v;
    }
    if let Some(v) = cli
        .ingest_persist_jsonl_path
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.persist_jsonl_path = v.to_string();
    }

    if let Some(v) = cli
        .ingest_clickhouse_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.clickhouse_url = Some(v.to_string());
    }
    if let Some(v) = cli
        .ingest_clickhouse_insert_sql
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.clickhouse_insert_sql = v.to_string();
    }
    if let Some(v) = cli
        .ingest_clickhouse_user
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.clickhouse_user = Some(v.to_string());
    }
    if let Some(v) = cli
        .ingest_clickhouse_password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.clickhouse_password = Some(v.to_string());
    }
    if let Some(v) = cli.ingest_clickhouse_timeout_ms {
        cfg.ingest.clickhouse_timeout_ms = v;
    }
    if cli.disable_clickhouse {
        cfg.ingest.clickhouse_url = None;
    }

    if let Some(v) = cli
        .ingest_surreal_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_url = Some(v.to_string());
    }
    if let Some(v) = cli
        .ingest_surreal_namespace
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_namespace = v.to_string();
    }
    if let Some(v) = cli
        .ingest_surreal_database
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_database = v.to_string();
    }
    if let Some(v) = cli
        .ingest_surreal_table
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_table = v.to_string();
    }
    if let Some(v) = cli
        .ingest_surreal_user
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_user = Some(v.to_string());
    }
    if let Some(v) = cli
        .ingest_surreal_password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_password = Some(v.to_string());
    }
    if let Some(v) = cli
        .ingest_surreal_token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cfg.ingest.surreal_token = Some(v.to_string());
    }
    if let Some(v) = cli.ingest_surreal_timeout_ms {
        cfg.ingest.surreal_timeout_ms = v;
    }
    if cli.disable_surreal {
        cfg.ingest.surreal_url = None;
    }
}

/// Lightweight health-check response body.
#[derive(Serialize)]
struct HealthResponse {
    /// Static health status string.
    status: &'static str,
}

/// Query params for recent ingest rows endpoint.
#[derive(Debug, Deserialize)]
struct RecentRowsQuery {
    /// Maximum number of rows to return.
    limit: Option<usize>,
    /// Optional tenant filter.
    tenant_id: Option<String>,
}

/// Tenant selector for scoped read endpoints.
#[derive(Debug, Deserialize)]
struct TenantQuery {
    /// Optional tenant filter.
    tenant_id: Option<String>,
}

/// Uniform API error body for auth/tenant failures.
#[derive(Debug, Serialize)]
struct ApiErrorResponse {
    error: &'static str,
    message: String,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiErrorResponse>)>;

/// Per-request principal scope resolved from bearer/api-key token.
#[derive(Clone, Debug)]
enum AuthPrincipal {
    Global,
    TenantSet(HashSet<String>),
}

/// Shared auth state loaded from configuration at startup.
#[derive(Clone, Debug)]
struct AuthState {
    enabled: bool,
    tokens: std::collections::HashMap<String, AuthPrincipal>,
}

struct RateBucket {
    tokens: f64,
    updated_at: Instant,
}

struct RateLimiter {
    rate_per_second: f64,
    burst: f64,
    max_keys: usize,
    buckets: Mutex<HashMap<(String, String), RateBucket>>,
}

impl RateLimiter {
    fn new(rate_per_second: u32, burst: u32, max_keys: usize) -> Self {
        Self {
            rate_per_second: rate_per_second as f64,
            burst: burst as f64,
            max_keys: max_keys.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, tenant_id: &str, host_id: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (tenant_id.to_string(), host_id.to_string());
        if !buckets.contains_key(&key) && buckets.len() >= self.max_keys {
            if let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.updated_at)
                .map(|(key, _)| key.clone())
            {
                buckets.remove(&oldest);
            }
        }
        let bucket = buckets.entry(key).or_insert(RateBucket {
            tokens: self.burst,
            updated_at: now,
        });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
        bucket.updated_at = now;
        if bucket.tokens < 1.0 {
            false
        } else {
            bucket.tokens -= 1.0;
            true
        }
    }
}

impl AuthState {
    fn from_config(cfg: &AuthConfig) -> Self {
        let mut tokens = std::collections::HashMap::new();
        for (token, scope) in &cfg.tokens {
            let principal = match scope {
                AuthTokenScope::Global => AuthPrincipal::Global,
                AuthTokenScope::TenantSet(tenants) => AuthPrincipal::TenantSet(tenants.clone()),
            };
            tokens.insert(token.clone(), principal);
        }
        Self {
            enabled: cfg.enabled(),
            tokens,
        }
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthPrincipal, (StatusCode, Json<ApiErrorResponse>)> {
        if !self.enabled {
            // Auth disabled keeps existing open-by-default behavior.
            return Ok(AuthPrincipal::Global);
        }

        let Some(token) = extract_api_token(headers) else {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "missing_token",
                "missing API token; use Authorization: Bearer <token> or x-api-key",
            ));
        };

        self.tokens.get(token).cloned().ok_or_else(|| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "provided API token is not recognized",
            )
        })
    }
}

/// Boot the server and run until shutdown signal is received.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_filter.as_deref());

    let mut cfg = ServerConfig::from_env();
    apply_cli_overrides(&mut cfg, &cli);
    if cli.print_effective_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&EffectiveServerConfig::from_config(&cfg))
                .context("serialize effective ingest config")?
        );
        return Ok(());
    }
    cfg.validate().map_err(anyhow::Error::msg)?;
    if cfg.ingest.surreal_url.is_some() {
        info!(
            jsonl_path = %cfg.ingest.persist_jsonl_path,
            surreal_namespace = %cfg.ingest.surreal_namespace,
            surreal_database = %cfg.ingest.surreal_database,
            surreal_table = %cfg.ingest.surreal_table,
            clickhouse_enabled = cfg.ingest.clickhouse_url.is_some(),
            recent_events_max = cfg.ingest.recent_events_max,
            "ingest persistence configured: surreal_http (fallback: clickhouse_http/jsonl)"
        );
    } else if cfg.ingest.clickhouse_url.is_some() {
        info!(
            jsonl_path = %cfg.ingest.persist_jsonl_path,
            recent_events_max = cfg.ingest.recent_events_max,
            "ingest persistence configured: clickhouse_http with jsonl fallback"
        );
    } else {
        info!(
            jsonl_path = %cfg.ingest.persist_jsonl_path,
            recent_events_max = cfg.ingest.recent_events_max,
            "ingest persistence configured: jsonl"
        );
    }
    let runtime = Arc::new(IngestRuntime::try_new(cfg.ingest.clone()).map_err(anyhow::Error::msg)?);
    runtime.start_worker().await;

    let state = AppState {
        runtime: Arc::clone(&runtime),
        auth: Arc::new(AuthState::from_config(&cfg.auth)),
        rate_limiter: Arc::new(RateLimiter::new(
            cfg.rate_limit_per_second,
            cfg.rate_limit_burst,
            cfg.rate_limit_max_keys,
        )),
    };

    let app = build_app(state, &cfg)?;

    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .with_context(|| format!("invalid bind addr {}:{}", cfg.host, cfg.port))?;
    info!(%addr, "olopa-ingest listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed binding server socket on {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server terminated with error")?;

    runtime.shutdown().await;
    Ok(())
}

fn build_app(state: AppState, cfg: &ServerConfig) -> anyhow::Result<Router> {
    let cors = build_cors_layer(&cfg.cors_allowed_origins)?;
    Ok(Router::new()
        .route("/", get(root_ok))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/ingest/batches", post(ingest_batch))
        .route("/api/v1/ingest/stats", get(ingest_stats))
        .route("/api/v1/ingest/recent", get(ingest_recent))
        .route("/api/v1/ingest/summary", get(ingest_summary))
        .with_state(state)
        .layer(DefaultBodyLimit::max(cfg.max_request_body_bytes))
        .layer(TraceLayer::new_for_http())
        .layer(cors))
}

/// Configure process-wide tracing subscriber with optional CLI override.
///
/// Uses CLI `--log-filter` first, then `RUST_LOG`, and finally a default.
fn init_tracing(log_filter_override: Option<&str>) {
    let env_filter = log_filter_override
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| tracing_subscriber::EnvFilter::try_new(v).ok())
        .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| "info,tower_http=info".into());
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Liveness/readiness endpoint.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let response = state.runtime.readiness().await;
    let status = if response.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(response))
}

async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<([(HeaderName, HeaderValue); 1], String), (StatusCode, Json<ApiErrorResponse>)> {
    let principal = state.auth.authenticate(&headers)?;
    if !matches!(principal, AuthPrincipal::Global) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "metrics endpoint requires a global-scope token",
        ));
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        state.runtime.prometheus_metrics(),
    ))
}

/// Minimal root endpoint for simple load balancer probes.
async fn root_ok() -> &'static str {
    "Ok"
}

/// Ingest endpoint: accepts one normalized batch and returns ack/backpressure hints.
async fn ingest_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IngestBatchRequest>,
) -> ApiResult<AckResponse> {
    let principal = state.auth.authenticate(&headers)?;
    ensure_tenant_allowed(&principal, &body.tenant_id)?;
    if !state.rate_limiter.allow(&body.tenant_id, &body.host_id) {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "tenant/host ingest rate exceeded",
        ));
    }
    let runtime = Arc::clone(&state.runtime);
    let ack = tokio::task::spawn_blocking(move || runtime.ack_batch(body))
        .await
        .map_err(|err| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "acceptance_worker_failed",
                format!("durable acceptance worker failed: {err}"),
            )
        })?;
    Ok(Json(ack))
}

fn build_cors_layer(origins: &[String]) -> anyhow::Result<CorsLayer> {
    let allowed = origins
        .iter()
        .map(|origin| {
            if origin.trim() == "*" {
                anyhow::bail!("wildcard CORS origin is not allowed; configure explicit origins");
            }
            let parsed = reqwest::Url::parse(origin)
                .with_context(|| format!("invalid CORS origin URL '{origin}'"))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                anyhow::bail!(
                    "CORS origin must be an http(s) scheme, host, and optional port only: '{origin}'"
                );
            }
            origin
                .parse::<HeaderValue>()
                .with_context(|| format!("invalid CORS origin '{origin}'"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-api-key"),
        ]);
    Ok(if allowed.is_empty() {
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(allowed))
    })
}

/// Stats endpoint for queue depth and flush counters.
async fn ingest_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<IngestStatsResponse> {
    let principal = state.auth.authenticate(&headers)?;
    if !matches!(principal, AuthPrincipal::Global) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "stats endpoint requires a global-scope token",
        ));
    }
    Ok(Json(state.runtime.stats()))
}

/// Read latest flushed rows retained by server memory index.
async fn ingest_recent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RecentRowsQuery>,
) -> ApiResult<RecentIngestResponse> {
    let principal = state.auth.authenticate(&headers)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 5_000);
    let tenant = resolve_tenant_filter(&principal, query.tenant_id.as_deref())?;
    let response = match tenant {
        Some(tenant_id) => {
            state
                .runtime
                .recent_rows_for_tenant(limit, &tenant_id)
                .await
        }
        None => state.runtime.recent_rows(limit).await,
    };
    Ok(Json(response))
}

/// Read aggregate ingest counters derived from flushed rows.
async fn ingest_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TenantQuery>,
) -> ApiResult<IngestDataSummaryResponse> {
    let principal = state.auth.authenticate(&headers)?;
    let tenant = resolve_tenant_filter(&principal, query.tenant_id.as_deref())?;
    let response = match tenant {
        Some(tenant_id) => state.runtime.data_summary_for_tenant(&tenant_id).await,
        None => state.runtime.data_summary().await,
    };
    Ok(Json(response))
}

fn api_error(
    status: StatusCode,
    error: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        status,
        Json(ApiErrorResponse {
            error,
            message: message.into(),
        }),
    )
}

fn ensure_tenant_allowed(
    principal: &AuthPrincipal,
    tenant_id: &str,
) -> Result<(), (StatusCode, Json<ApiErrorResponse>)> {
    let tenant = tenant_id.trim();
    if tenant.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_tenant",
            "tenant_id must be non-empty",
        ));
    }

    match principal {
        AuthPrincipal::Global => Ok(()),
        AuthPrincipal::TenantSet(allowed) => {
            if allowed.contains(tenant) {
                Ok(())
            } else {
                Err(api_error(
                    StatusCode::FORBIDDEN,
                    "tenant_forbidden",
                    format!("token is not authorized for tenant '{tenant}'"),
                ))
            }
        }
    }
}

fn resolve_tenant_filter(
    principal: &AuthPrincipal,
    requested_tenant: Option<&str>,
) -> Result<Option<String>, (StatusCode, Json<ApiErrorResponse>)> {
    let requested = requested_tenant
        .map(str::trim)
        .filter(|tenant| !tenant.is_empty());

    match principal {
        AuthPrincipal::Global => Ok(requested.map(|tenant| tenant.to_string())),
        AuthPrincipal::TenantSet(allowed) => match requested {
            Some(tenant) => {
                if allowed.contains(tenant) {
                    Ok(Some(tenant.to_string()))
                } else {
                    Err(api_error(
                        StatusCode::FORBIDDEN,
                        "tenant_forbidden",
                        format!("token is not authorized for tenant '{tenant}'"),
                    ))
                }
            }
            None => {
                if allowed.len() == 1 {
                    Ok(allowed.iter().next().cloned())
                } else {
                    Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "tenant_required",
                        "tenant_id query parameter is required for multi-tenant scoped tokens",
                    ))
                }
            }
        },
    }
}

fn extract_api_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(authz_value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = authz_value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token);
            }
        }
        if let Some(token) = authz_value.strip_prefix("bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }

    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Wait for SIGINT/SIGTERM and drive graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            let _ = term.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use tower::ServiceExt;

    #[test]
    fn extracts_bearer_and_x_api_key_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        assert_eq!(extract_api_token(&headers), Some("secret-token"));

        headers.clear();
        headers.insert("x-api-key", HeaderValue::from_static("key-123"));
        assert_eq!(extract_api_token(&headers), Some("key-123"));
    }

    #[test]
    fn tenant_scope_requires_explicit_tenant_when_multiple_allowed() {
        let principal = AuthPrincipal::TenantSet(
            ["acme".to_string(), "globex".to_string()]
                .into_iter()
                .collect(),
        );
        let result = resolve_tenant_filter(&principal, None);
        assert!(
            result.is_err(),
            "multi-tenant scope should require tenant_id"
        );
    }

    #[test]
    fn tenant_scope_accepts_single_tenant_without_query() {
        let principal = AuthPrincipal::TenantSet(["acme".to_string()].into_iter().collect());
        let resolved = resolve_tenant_filter(&principal, None).expect("resolve tenant");
        assert_eq!(resolved.as_deref(), Some("acme"));
    }

    #[test]
    fn tenant_host_rate_limiter_enforces_burst_and_refills() {
        let limiter = RateLimiter::new(1_000, 2, 8);
        assert!(limiter.allow("acme", "host"));
        assert!(limiter.allow("acme", "host"));
        assert!(!limiter.allow("acme", "host"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(limiter.allow("acme", "host"));
        assert!(limiter.allow("acme", "other-host"));
    }

    #[test]
    fn cors_configuration_is_restricted_and_rejects_invalid_origins() {
        assert!(build_cors_layer(&[]).is_ok());
        assert!(build_cors_layer(&["https://console.example".to_string()]).is_ok());
        assert!(build_cors_layer(&["*".to_string()]).is_err());
        assert!(build_cors_layer(&["console.example".to_string()]).is_err());
        assert!(build_cors_layer(&["https://console.example/path".to_string()]).is_err());
        assert!(build_cors_layer(&["bad\norigin".to_string()]).is_err());
    }

    #[tokio::test]
    async fn http_boundary_rejects_oversized_and_malformed_json() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("olopa-ingest-http-{nonce}"));
        let mut cfg = ServerConfig::from_env();
        cfg.auth = AuthConfig::default();
        cfg.max_request_body_bytes = 64;
        cfg.ingest.flush_workers = 1;
        cfg.ingest.wal_path = base.with_extension("wal").to_string_lossy().into_owned();
        cfg.ingest.dedupe_path = base.with_extension("dedupe").to_string_lossy().into_owned();
        cfg.ingest.persist_jsonl_path = base.with_extension("jsonl").to_string_lossy().into_owned();
        cfg.ingest.dead_letter_path = base.with_extension("dlq").to_string_lossy().into_owned();
        let runtime = Arc::new(IngestRuntime::try_new(cfg.ingest.clone()).expect("runtime"));
        runtime.start_worker().await;
        let state = AppState {
            runtime: Arc::clone(&runtime),
            auth: Arc::new(AuthState::from_config(&cfg.auth)),
            rate_limiter: Arc::new(RateLimiter::new(10, 10, 10)),
        };
        let app = build_app(state, &cfg).expect("router");

        let oversized = app
            .clone()
            .oneshot(
                axum::http::Request::post("/api/v1/ingest/batches")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("x".repeat(65)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let malformed = app
            .oneshot(
                axum::http::Request::post("/api/v1/ingest/batches")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{bad json"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(malformed.status().is_client_error());
        runtime.shutdown().await;
    }
}
