//! Environment-driven configuration for the ingest API server.
//!
//! This module intentionally keeps parsing logic small and explicit:
//! - every runtime knob has a strongly typed field,
//! - defaults are centralized in `IngestConfig::default()`,
//! - environment overrides are handled in `ServerConfig::from_env()`.

use std::env;

/// Top-level HTTP server configuration.
///
/// `host` and `port` define the bind socket while `ingest`
/// configures queueing/flush/persistence behavior for telemetry ingestion.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Interface or address to bind the HTTP server to.
    pub host: String,
    /// TCP port for the API listener.
    pub port: u16,
    /// Ingest pipeline tuning and persistence settings.
    pub ingest: IngestConfig,
}

/// Configuration for the asynchronous ingest runtime.
#[derive(Clone, Debug)]
pub struct IngestConfig {
    /// Maximum number of queued batches waiting for background flush.
    pub queue_maxsize: usize,
    /// Time-driven flush interval for pending rows.
    pub flush_interval_ms: u64,
    /// Row threshold that triggers immediate flush.
    pub flush_max_rows: usize,
    /// Suggested retry delay returned to senders on backpressure.
    pub default_retry_after_ms: u32,
    /// Suggested payload size returned to senders for adaptive batching.
    pub suggested_batch_bytes: u32,
    /// Maximum number of recent rows kept in memory for inspection APIs.
    pub recent_events_max: usize,
    /// Durable local fallback sink for flattened events.
    pub persist_jsonl_path: String,
    /// Optional ClickHouse HTTP endpoint.
    ///
    /// Example: `http://127.0.0.1:8123/`
    pub clickhouse_url: Option<String>,
    /// SQL query used for ClickHouse inserts via `query=` URL parameter.
    ///
    /// Expected to end with `FORMAT JSONEachRow`.
    pub clickhouse_insert_sql: String,
    /// Optional ClickHouse username for basic auth.
    pub clickhouse_user: Option<String>,
    /// Optional ClickHouse password for basic auth.
    pub clickhouse_password: Option<String>,
    /// Request timeout for ClickHouse insert HTTP calls.
    pub clickhouse_timeout_ms: u64,
}

impl Default for IngestConfig {
    /// Baseline ingest defaults for local and dev usage.
    ///
    /// Production deployments should override these through environment
    /// variables (especially queue sizing and persistence endpoints).
    fn default() -> Self {
        Self {
            queue_maxsize: 2_000,
            flush_interval_ms: 250,
            flush_max_rows: 10_000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 5_000,
            persist_jsonl_path: "/tmp/olopa/ingest/events.jsonl".to_string(),
            clickhouse_url: None,
            clickhouse_insert_sql: "INSERT INTO olopa.events_raw FORMAT JSONEachRow".to_string(),
            clickhouse_user: None,
            clickhouse_password: None,
            clickhouse_timeout_ms: 2_000,
        }
    }
}

impl ServerConfig {
    /// Load server configuration from environment variables.
    ///
    /// Unknown or malformed numeric values fall back to defaults so the
    /// process can still boot with safe baseline behavior.
    pub fn from_env() -> Self {
        let ingest_defaults = IngestConfig::default();
        Self {
            host: env_or("SERVER_HOST", "0.0.0.0"),
            port: env_parse_or("SERVER_PORT", 8000u16),
            ingest: IngestConfig {
                queue_maxsize: env_parse_or("INGEST_QUEUE_MAXSIZE", ingest_defaults.queue_maxsize),
                flush_interval_ms: env_parse_or(
                    "INGEST_FLUSH_INTERVAL_MS",
                    ingest_defaults.flush_interval_ms,
                ),
                flush_max_rows: env_parse_or(
                    "INGEST_FLUSH_MAX_ROWS",
                    ingest_defaults.flush_max_rows,
                ),
                default_retry_after_ms: env_parse_or(
                    "INGEST_DEFAULT_RETRY_AFTER_MS",
                    ingest_defaults.default_retry_after_ms,
                ),
                suggested_batch_bytes: env_parse_or(
                    "INGEST_SUGGESTED_BATCH_BYTES",
                    ingest_defaults.suggested_batch_bytes,
                ),
                recent_events_max: env_parse_or(
                    "INGEST_RECENT_EVENTS_MAX",
                    ingest_defaults.recent_events_max,
                ),
                persist_jsonl_path: env_or(
                    "INGEST_PERSIST_JSONL_PATH",
                    &ingest_defaults.persist_jsonl_path,
                ),
                clickhouse_url: env_opt("INGEST_CLICKHOUSE_URL"),
                clickhouse_insert_sql: env_or(
                    "INGEST_CLICKHOUSE_INSERT_SQL",
                    &ingest_defaults.clickhouse_insert_sql,
                ),
                clickhouse_user: env_opt("INGEST_CLICKHOUSE_USER"),
                clickhouse_password: env_opt("INGEST_CLICKHOUSE_PASSWORD"),
                clickhouse_timeout_ms: env_parse_or(
                    "INGEST_CLICKHOUSE_TIMEOUT_MS",
                    ingest_defaults.clickhouse_timeout_ms,
                ),
            },
        }
    }
}

/// Read a non-empty string environment value, or return default.
fn env_or(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

/// Parse an environment variable into a typed value with default fallback.
fn env_parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    match env::var(key) {
        Ok(v) => v.parse::<T>().unwrap_or(default),
        Err(_) => default,
    }
}

/// Read an optional non-empty string environment variable.
fn env_opt(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}
