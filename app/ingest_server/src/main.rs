//! HTTP entrypoint for the Olopa ingest server.
//!
//! Responsibilities:
//! - initialize logging/tracing,
//! - construct and start the ingest runtime worker,
//! - expose health and ingest APIs over Axum,
//! - handle graceful shutdown and worker drain.

mod config;
mod telemetry;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ServerConfig;
use crate::telemetry::{
    AckResponse, IngestBatchRequest, IngestDataSummaryResponse, IngestRuntime, IngestStatsResponse,
    RecentIngestResponse,
};

/// Shared application state injected into route handlers.
#[derive(Clone)]
struct AppState {
    /// Background ingest runtime used by API handlers.
    runtime: Arc<IngestRuntime>,
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
}

/// Boot the server and run until shutdown signal is received.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = ServerConfig::from_env();
    if cfg.ingest.clickhouse_url.is_some() {
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
    Json(body): Json<IngestBatchRequest>,
) -> Json<AckResponse> {
    Json(state.runtime.ack_batch(body))
}

/// Stats endpoint for queue depth and flush counters.
async fn ingest_stats(State(state): State<AppState>) -> Json<IngestStatsResponse> {
    Json(state.runtime.stats())
}

/// Read latest flushed rows retained by server memory index.
async fn ingest_recent(
    State(state): State<AppState>,
    Query(query): Query<RecentRowsQuery>,
) -> Json<RecentIngestResponse> {
    let limit = query.limit.unwrap_or(100).clamp(1, 5_000);
    Json(state.runtime.recent_rows(limit).await)
}

/// Read aggregate ingest counters derived from flushed rows.
async fn ingest_summary(State(state): State<AppState>) -> Json<IngestDataSummaryResponse> {
    Json(state.runtime.data_summary().await)
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
