//! Environment-driven configuration for the ingest API server.
//!
//! This module intentionally keeps parsing logic small and explicit:
//! - every runtime knob has a strongly typed field,
//! - defaults are centralized in `IngestConfig::default()`,
//! - environment overrides are handled in `ServerConfig::from_env()`.

use std::collections::{HashMap, HashSet};
use std::env;

use serde::Serialize;

/// Top-level HTTP server configuration.
///
/// `host` and `port` define the bind socket while `ingest`
/// configures queueing/flush/persistence behavior for telemetry ingestion.
#[derive(Clone, Debug, Serialize)]
pub struct ServerConfig {
    /// Interface or address to bind the HTTP server to.
    pub host: String,
    /// TCP port for the API listener.
    pub port: u16,
    /// API authentication/authorization settings.
    pub auth: AuthConfig,
    /// Refuse unsafe development defaults when enabled.
    pub production_mode: bool,
    /// Browser origins allowed to call the API. Empty disables cross-origin access.
    pub cors_allowed_origins: Vec<String>,
    /// Maximum decoded HTTP request body size.
    pub max_request_body_bytes: usize,
    /// Sustained accepted requests per second for one tenant/host pair.
    pub rate_limit_per_second: u32,
    /// Maximum token-bucket burst for one tenant/host pair.
    pub rate_limit_burst: u32,
    /// Maximum tenant/host rate buckets retained in memory.
    pub rate_limit_max_keys: usize,
    /// Ingest pipeline tuning and persistence settings.
    pub ingest: IngestConfig,
}

/// Token-based auth configuration for ingest HTTP APIs.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuthConfig {
    /// Map from API token to tenant scope.
    pub tokens: HashMap<String, AuthTokenScope>,
}

/// Authorization scope granted to one API token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum AuthTokenScope {
    /// Full access to all tenants and operational endpoints.
    Global,
    /// Access restricted to one or more tenant ids.
    TenantSet(HashSet<String>),
}

impl AuthConfig {
    /// Auth is enabled when at least one token is configured.
    pub fn enabled(&self) -> bool {
        !self.tokens.is_empty()
    }
}

/// Configuration for the asynchronous ingest runtime.
#[derive(Clone, Debug, Serialize)]
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
    /// Maximum accepted `(tenant, host, batch_id)` keys retained for retry deduplication.
    /// Set to zero to disable idempotency tracking.
    pub dedupe_max_entries: usize,
    /// Fsynced write-ahead log used before acknowledging batches.
    pub wal_path: String,
    /// Atomically replaced persistent idempotency snapshot.
    pub dedupe_path: String,
    /// Commit count between WAL compaction attempts.
    pub wal_compact_after_commits: usize,
    /// Number of independently partitioned flush workers.
    pub flush_workers: usize,
    /// Maximum sink attempts before falling back or dead-lettering.
    pub sink_retry_max_attempts: u32,
    /// Initial exponential sink retry delay.
    pub sink_retry_initial_ms: u64,
    /// Upper bound for exponential sink retry delay.
    pub sink_retry_max_ms: u64,
    /// Consecutive failures that open one sink circuit.
    pub circuit_failure_threshold: u32,
    /// Time an open sink circuit rejects calls before a half-open probe.
    pub circuit_open_ms: u64,
    /// Durable local destination for batches that no sink can persist.
    pub dead_letter_path: String,
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
    /// Optional SurrealDB HTTP SQL endpoint.
    ///
    /// Example: `http://127.0.0.1:8000/sql`
    pub surreal_url: Option<String>,
    /// SurrealDB namespace header value (`NS`).
    pub surreal_namespace: String,
    /// SurrealDB database header value (`DB`).
    pub surreal_database: String,
    /// SurrealDB table used for flattened ingest rows.
    pub surreal_table: String,
    /// Optional SurrealDB username for basic auth.
    pub surreal_user: Option<String>,
    /// Optional SurrealDB password for basic auth.
    pub surreal_password: Option<String>,
    /// Optional SurrealDB bearer token auth.
    pub surreal_token: Option<String>,
    /// Request timeout for SurrealDB HTTP calls.
    pub surreal_timeout_ms: u64,
    /// Enable near-real-time stream correlation engine on ingest.
    pub correlation_enabled: bool,
    /// Optional file path to initial runtime IR rules JSON.
    pub correlation_rules_path: Option<String>,
    /// Maximum multi-source window buckets per shard in the correlation engine.
    pub correlation_window_max_entries: usize,
    /// Maximum correlated alerts retained in memory for inspection.
    pub correlation_alerts_max: usize,
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
            dedupe_max_entries: 100_000,
            wal_path: "/tmp/olopa/ingest/acceptance.wal".to_string(),
            dedupe_path: "/tmp/olopa/ingest/dedupe.json".to_string(),
            wal_compact_after_commits: 1_000,
            flush_workers: 4,
            sink_retry_max_attempts: 4,
            sink_retry_initial_ms: 100,
            sink_retry_max_ms: 5_000,
            circuit_failure_threshold: 5,
            circuit_open_ms: 30_000,
            dead_letter_path: "/tmp/olopa/ingest/dead-letter.jsonl".to_string(),
            persist_jsonl_path: "/tmp/olopa/ingest/events.jsonl".to_string(),
            clickhouse_url: None,
            clickhouse_insert_sql: "INSERT INTO olopa.events_raw FORMAT JSONEachRow".to_string(),
            clickhouse_user: None,
            clickhouse_password: None,
            clickhouse_timeout_ms: 2_000,
            surreal_url: None,
            surreal_namespace: "olopa".to_string(),
            surreal_database: "events".to_string(),
            surreal_table: "events_raw".to_string(),
            surreal_user: None,
            surreal_password: None,
            surreal_token: None,
            surreal_timeout_ms: 2_000,
            correlation_enabled: true,
            correlation_rules_path: None,
            correlation_window_max_entries: 10_000,
            correlation_alerts_max: 5_000,
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
        let auth_tokens = env_opt("INGEST_API_TOKENS")
            .map(|raw| parse_auth_tokens(&raw))
            .unwrap_or_default();
        Self {
            host: env_or("SERVER_HOST", "0.0.0.0"),
            port: env_parse_or("SERVER_PORT", 8000u16),
            production_mode: env_bool("INGEST_PRODUCTION_MODE", false)
                || env_opt("INGEST_ENV").is_some_and(|value| {
                    matches!(value.to_ascii_lowercase().as_str(), "prod" | "production")
                }),
            cors_allowed_origins: env_list("INGEST_CORS_ALLOWED_ORIGINS"),
            max_request_body_bytes: env_parse_or(
                "INGEST_MAX_REQUEST_BODY_BYTES",
                8 * 1024 * 1024usize,
            ),
            rate_limit_per_second: env_parse_or("INGEST_RATE_LIMIT_PER_SECOND", 200u32),
            rate_limit_burst: env_parse_or("INGEST_RATE_LIMIT_BURST", 400u32),
            rate_limit_max_keys: env_parse_or("INGEST_RATE_LIMIT_MAX_KEYS", 100_000usize),
            auth: AuthConfig {
                tokens: auth_tokens,
            }, 
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
                dedupe_max_entries: env_parse_or(
                    "INGEST_DEDUPE_MAX_ENTRIES",
                    ingest_defaults.dedupe_max_entries,
                ),
                wal_path: env_or("INGEST_WAL_PATH", &ingest_defaults.wal_path),
                dedupe_path: env_or("INGEST_DEDUPE_PATH", &ingest_defaults.dedupe_path),
                wal_compact_after_commits: env_parse_or(
                    "INGEST_WAL_COMPACT_AFTER_COMMITS",
                    ingest_defaults.wal_compact_after_commits,
                ),
                flush_workers: env_parse_or("INGEST_FLUSH_WORKERS", ingest_defaults.flush_workers),
                sink_retry_max_attempts: env_parse_or(
                    "INGEST_SINK_RETRY_MAX_ATTEMPTS",
                    ingest_defaults.sink_retry_max_attempts,
                ),
                sink_retry_initial_ms: env_parse_or(
                    "INGEST_SINK_RETRY_INITIAL_MS",
                    ingest_defaults.sink_retry_initial_ms,
                ),
                sink_retry_max_ms: env_parse_or(
                    "INGEST_SINK_RETRY_MAX_MS",
                    ingest_defaults.sink_retry_max_ms,
                ),
                circuit_failure_threshold: env_parse_or(
                    "INGEST_CIRCUIT_FAILURE_THRESHOLD",
                    ingest_defaults.circuit_failure_threshold,
                ),
                circuit_open_ms: env_parse_or(
                    "INGEST_CIRCUIT_OPEN_MS",
                    ingest_defaults.circuit_open_ms,
                ),
                dead_letter_path: env_or(
                    "INGEST_DEAD_LETTER_PATH",
                    &ingest_defaults.dead_letter_path,
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
                surreal_url: env_opt("INGEST_SURREAL_URL"),
                surreal_namespace: env_or(
                    "INGEST_SURREAL_NAMESPACE",
                    &ingest_defaults.surreal_namespace,
                ),
                surreal_database: env_or(
                    "INGEST_SURREAL_DATABASE",
                    &ingest_defaults.surreal_database,
                ),
                surreal_table: env_or("INGEST_SURREAL_TABLE", &ingest_defaults.surreal_table),
                surreal_user: env_opt("INGEST_SURREAL_USER"),
                surreal_password: env_opt("INGEST_SURREAL_PASSWORD"),
                surreal_token: env_opt("INGEST_SURREAL_TOKEN"),
                surreal_timeout_ms: env_parse_or(
                    "INGEST_SURREAL_TIMEOUT_MS",
                    ingest_defaults.surreal_timeout_ms,
                ),
                correlation_enabled: env_bool("INGEST_CORRELATION_ENABLED", true),
                correlation_rules_path: env_opt("INGEST_CORRELATION_RULES_PATH"),
                correlation_window_max_entries: env_parse_or(
                    "INGEST_CORRELATION_WINDOW_MAX_ENTRIES",
                    ingest_defaults.correlation_window_max_entries,
                ),
                correlation_alerts_max: env_parse_or(
                    "INGEST_CORRELATION_ALERTS_MAX",
                    ingest_defaults.correlation_alerts_max,
                ),
            },
        }
    }

    /// Reject configurations that would silently remove production safety guarantees.
    pub fn validate(&self) -> Result<(), String> {
        if self.production_mode && !self.auth.enabled() {
            return Err(
                "production mode requires INGEST_API_TOKENS; unauthenticated startup refused"
                    .to_string(),
            );
        }
        if self.max_request_body_bytes == 0 {
            return Err("INGEST_MAX_REQUEST_BODY_BYTES must be greater than zero".to_string());
        }
        if self.rate_limit_per_second == 0 || self.rate_limit_burst == 0 {
            return Err("ingest rate limit and burst must be greater than zero".to_string());
        }
        if self.rate_limit_max_keys == 0 {
            return Err("INGEST_RATE_LIMIT_MAX_KEYS must be greater than zero".to_string());
        }
        if self.ingest.queue_maxsize == 0
            || self.ingest.flush_workers == 0
            || self.ingest.sink_retry_max_attempts == 0
        {
            return Err(
                "queue size, flush workers, and sink retry attempts must be non-zero".to_string(),
            );
        }
        if self.ingest.wal_path.trim().is_empty() || self.ingest.dedupe_path.trim().is_empty() {
            return Err("durable WAL and dedupe paths must be configured".to_string());
        }
        let durable_paths = [
            self.ingest.wal_path.as_str(),
            self.ingest.dedupe_path.as_str(),
            self.ingest.persist_jsonl_path.as_str(),
            self.ingest.dead_letter_path.as_str(),
        ];
        for (index, path) in durable_paths.iter().enumerate() {
            if durable_paths[index + 1..].contains(path) {
                return Err(
                    "WAL, dedupe, JSONL, and dead-letter paths must be distinct".to_string()
                );
            }
        }
        Ok(())
    }
}

/// Parse `INGEST_API_TOKENS` as comma-separated token scope declarations.
///
/// Supported forms:
/// - `token-a` -> global scope
/// - `token-b:tenant-alpha` -> one tenant
/// - `token-c:tenant-a|tenant-b` -> multi-tenant scoped token
/// - `token-d:*` -> global scope
pub(crate) fn parse_auth_tokens(raw: &str) -> HashMap<String, AuthTokenScope> {
    let mut out = HashMap::new();
    for entry in raw.split(',') {
        let part = entry.trim();
        if part.is_empty() {
            continue;
        }

        let (token, scope) = match part.split_once(':') {
            Some((token, scope)) => (token.trim(), parse_auth_scope(scope)),
            None => (part, AuthTokenScope::Global),
        };
        if token.is_empty() {
            continue;
        }
        out.insert(token.to_string(), scope);
    }
    out
}

fn parse_auth_scope(raw: &str) -> AuthTokenScope {
    let scope_raw = raw.trim();
    if scope_raw.is_empty() || scope_raw == "*" {
        return AuthTokenScope::Global;
    }

    let mut tenants = HashSet::new();
    for tenant in scope_raw.split('|') {
        let tenant = tenant.trim();
        if tenant.is_empty() {
            continue;
        }
        if tenant == "*" {
            return AuthTokenScope::Global;
        }
        tenants.insert(tenant.to_string());
    }

    if tenants.is_empty() {
        AuthTokenScope::Global
    } else {
        AuthTokenScope::TenantSet(tenants)
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

fn env_bool(key: &str, default: bool) -> bool {
    env_opt(key)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn env_list(key: &str) -> Vec<String> {
    env_opt(key)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_auth_token_scopes_from_env_string() {
        let parsed = parse_auth_tokens("global-token, tenant-token:acme|globex, wildcard:*");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed.get("global-token"), Some(&AuthTokenScope::Global));
        assert_eq!(parsed.get("wildcard"), Some(&AuthTokenScope::Global));
        match parsed.get("tenant-token") {
            Some(AuthTokenScope::TenantSet(tenants)) => {
                assert!(tenants.contains("acme"));
                assert!(tenants.contains("globex"));
                assert_eq!(tenants.len(), 2);
            }
            other => panic!("unexpected tenant-token scope: {other:?}"),
        }
    }

    #[test]
    fn auth_is_enabled_only_when_tokens_present() {
        let disabled = AuthConfig::default();
        assert!(!disabled.enabled());

        let mut enabled = AuthConfig::default();
        enabled
            .tokens
            .insert("t".to_string(), AuthTokenScope::Global);
        assert!(enabled.enabled());
    }

    #[test]
    fn production_configuration_requires_authentication() {
        let mut cfg = ServerConfig::from_env();
        cfg.production_mode = true;
        cfg.auth = AuthConfig::default();
        assert!(cfg.validate().is_err());

        cfg.auth
            .tokens
            .insert("secret".to_string(), AuthTokenScope::Global);
        assert!(cfg.validate().is_ok());
    }
}
