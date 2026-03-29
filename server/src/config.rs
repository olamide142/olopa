use std::env;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub ingest: IngestConfig,
}

#[derive(Clone, Debug)]
pub struct IngestConfig {
    pub queue_maxsize: usize,
    pub flush_interval_ms: u64,
    pub flush_max_rows: usize,
    pub default_retry_after_ms: u32,
    pub suggested_batch_bytes: u32,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            queue_maxsize: 2_000,
            flush_interval_ms: 250,
            flush_max_rows: 10_000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
        }
    }
}

impl ServerConfig {
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
            },
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

fn env_parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    match env::var(key) {
        Ok(v) => v.parse::<T>().unwrap_or(default),
        Err(_) => default,
    }
}
