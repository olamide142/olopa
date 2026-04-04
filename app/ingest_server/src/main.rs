//! HTTP entrypoint for the Olopa ingest server.
//!
//! Responsibilities:
//! - initialize logging/tracing,
//! - construct and start the ingest runtime worker,
//! - expose health and ingest APIs over Axum,
//! - handle graceful shutdown and worker drain.

mod config;
mod telemetry;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{AuthConfig, AuthTokenScope, ServerConfig};
use crate::telemetry::{
    AckResponse, IngestBatchRequest, IngestDataSummaryResponse, IngestRuntime, IngestStatsResponse,
    RecentIngestResponse,
};

/// Shared application state injected into route handlers.
#[derive(Clone)]
struct AppState {
    /// Background ingest runtime used by API handlers.
    runtime: Arc<IngestRuntime>,
    /// API authn/authz state.
    auth: Arc<AuthState>,
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
    init_tracing();

    let cfg = ServerConfig::from_env();
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
    let runtime = Arc::new(IngestRuntime::new(cfg.ingest.clone()));
    runtime.start_worker().await;

    let state = AppState {
        runtime: Arc::clone(&runtime),
        auth: Arc::new(AuthState::from_config(&cfg.auth)),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/ingest/batches", post(ingest_batch))
        .route("/api/v1/ingest/stats", get(ingest_stats))
        .route("/api/v1/ingest/recent", get(ingest_recent))
        .route("/api/v1/ingest/summary", get(ingest_summary))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .with_context(|| format!("invalid bind addr {}:{}", cfg.host, cfg.port))?;
    info!(%addr, "olopa-server listening");

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

/// Configure process-wide tracing subscriber.
///
/// Uses `RUST_LOG` when present, otherwise defaults to `info`.
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Liveness/readiness endpoint.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Ingest endpoint: accepts one normalized batch and returns ack/backpressure hints.
async fn ingest_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IngestBatchRequest>,
) -> ApiResult<AckResponse> {
    let principal = state.auth.authenticate(&headers)?;
    ensure_tenant_allowed(&principal, &body.tenant_id)?;
    Ok(Json(state.runtime.ack_batch(body)))
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
    use axum::http::HeaderValue;

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
}
