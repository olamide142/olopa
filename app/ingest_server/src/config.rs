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
            },
        }
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
}
