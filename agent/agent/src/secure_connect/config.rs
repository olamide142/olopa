use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct SecureConnectConfig {
    pub control_url: String,
    pub tenant_id: String,
    pub host_id: String,
    pub user_id: Option<String>,
    pub enrollment_token: Option<String>,
    pub api_token: Option<String>,
    pub identity_pem: Option<PathBuf>,
    pub interface: String,
    pub status_path: PathBuf,
    pub state_path: PathBuf,
    pub heartbeat_interval: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
    pub policy_ttl: Duration,
    pub kill_switch: bool,
    pub mtu: u16,
}

impl SecureConnectConfig {
    pub fn from_env() -> Result<Option<Self>> {
        if !env_flag("OLOPA_SC_ENABLED") {
            return Ok(None);
        }

        let control_url = required("OLOPA_SC_CONTROL_URL")?
            .trim_end_matches('/')
            .to_string();
        if !(control_url.starts_with("https://")
            || (env_flag("OLOPA_SC_ALLOW_INSECURE_HTTP") && control_url.starts_with("http://")))
        {
            bail!(
                "OLOPA_SC_CONTROL_URL must use https (set OLOPA_SC_ALLOW_INSECURE_HTTP=1 only for local development)"
            );
        }

        let interface = env_non_empty("OLOPA_SC_INTERFACE").unwrap_or_else(|| "olopa0".to_string());
        if interface.len() > 15
            || interface.is_empty()
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            bail!("invalid OLOPA_SC_INTERFACE '{interface}'");
        }

        let heartbeat_ms = env_parse("OLOPA_SC_HEARTBEAT_MS", 15_000u64)?.max(1_000);
        let retry_min_ms = env_parse("OLOPA_SC_RETRY_MIN_MS", 500u64)?.max(100);
        let retry_max_ms = env_parse("OLOPA_SC_RETRY_MAX_MS", 30_000u64)?.max(retry_min_ms);
        let policy_ttl_secs = env_parse("OLOPA_SC_POLICY_TTL_SECS", 300u64)?.max(10);
        let mtu = env_parse("OLOPA_SC_MTU", 1_420u16)?;
        if !(576..=9_000).contains(&mtu) {
            bail!("OLOPA_SC_MTU must be between 576 and 9000");
        }

        let identity_pem = env_non_empty("OLOPA_SC_MTLS_IDENTITY_PEM").map(PathBuf::from);
        if identity_pem.is_none() && !env_flag("OLOPA_SC_ALLOW_UNBOUND_ENROLLMENT") {
            bail!(
                "OLOPA_SC_MTLS_IDENTITY_PEM is required (set OLOPA_SC_ALLOW_UNBOUND_ENROLLMENT=1 only for local development)"
            );
        }

        Ok(Some(Self {
            control_url,
            tenant_id: env_non_empty("OLOPA_SC_TENANT_ID")
                .or_else(|| env_non_empty("OLOPA_INGEST_TENANT_ID"))
                .unwrap_or_else(|| "default".to_string()),
            host_id: env_non_empty("OLOPA_SC_HOST_ID")
                .or_else(|| env_non_empty("OLOPA_INGEST_HOST_ID"))
                .or_else(|| env_non_empty("HOSTNAME"))
                .unwrap_or_else(|| "agent-local".to_string()),
            user_id: env_non_empty("OLOPA_SC_USER_ID"),
            enrollment_token: env_non_empty("OLOPA_SC_ENROLLMENT_TOKEN"),
            api_token: env_non_empty("OLOPA_SC_API_TOKEN"),
            identity_pem,
            interface,
            status_path: env_non_empty("OLOPA_SC_STATUS_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/secure-connect.json")),
            state_path: env_non_empty("OLOPA_SC_STATE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/olopa/secure-connect-state.json")),
            heartbeat_interval: Duration::from_millis(heartbeat_ms),
            retry_min: Duration::from_millis(retry_min_ms),
            retry_max: Duration::from_millis(retry_max_ms),
            policy_ttl: Duration::from_secs(policy_ttl_secs),
            kill_switch: !matches!(
                env_non_empty("OLOPA_SC_KILL_SWITCH")
                    .unwrap_or_else(|| "on".to_string())
                    .to_ascii_lowercase()
                    .as_str(),
                "0" | "false" | "off" | "no"
            ),
            mtu,
        }))
    }
}

fn required(key: &str) -> Result<String> {
    env_non_empty(key).with_context(|| format!("{key} is required when Secure Connect is enabled"))
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn env_flag(key: &str) -> bool {
    env_non_empty(key).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_parse<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_non_empty(key) {
        Some(value) => value
            .parse::<T>()
            .map_err(|err| anyhow::anyhow!("invalid {key}='{value}': {err}")),
        None => Ok(default),
    }
}
