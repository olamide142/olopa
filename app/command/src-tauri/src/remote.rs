//! HTTP access to the ingest server and control plane.
//!
//! Requests are made from Rust rather than the webview: the desktop app then
//! needs no CORS allowances on either server, and the operator's credential
//! never has to be handed to page JavaScript.

use crate::settings::Settings;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Ingest,
    Control,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpReply {
    pub ok: bool,
    pub status: u16,
    pub latency_ms: u64,
    pub body: Option<Value>,
    /// Populated when the request failed or the body was not JSON.
    pub error: Option<String>,
}

fn base_for(settings: &Settings, target: Target) -> String {
    match target {
        Target::Ingest => settings.ingest_base_url.trim_end_matches('/').to_string(),
        Target::Control => settings.control_base_url.trim_end_matches('/').to_string(),
    }
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| format!("http client: {err}"))
}

/// Issue a request, returning transport failures as data rather than errors so
/// every panel can render "backend offline" without a try/catch.
pub async fn request(
    settings: &Settings,
    target: Target,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> HttpReply {
    let url = format!("{}{}", base_for(settings, target), path);
    let started = std::time::Instant::now();

    let client = match client() {
        Ok(client) => client,
        Err(err) => {
            return HttpReply {
                ok: false,
                status: 0,
                latency_ms: 0,
                body: None,
                error: Some(err),
            }
        }
    };

    let mut builder = match method {
        "POST" => client.post(&url),
        _ => client.get(&url),
    };
    for (name, value) in settings.auth_headers() {
        builder = builder.header(name, value);
    }
    if let Some(body) = body {
        builder = builder.json(&body);
    }

    match builder.send().await {
        Err(err) => HttpReply {
            ok: false,
            status: 0,
            latency_ms: started.elapsed().as_millis() as u64,
            body: None,
            error: Some(format!("{url} unreachable: {err}")),
        },
        Ok(response) => {
            let status = response.status();
            let latency_ms = started.elapsed().as_millis() as u64;
            let text = response.text().await.unwrap_or_default();
            let parsed = serde_json::from_str::<Value>(&text).ok();
            let error = if status.is_success() {
                parsed.is_none().then(|| "response body was not JSON".to_string())
            } else {
                Some(describe_error(&parsed, status.as_u16(), &text))
            };
            HttpReply {
                ok: status.is_success() && error.is_none(),
                status: status.as_u16(),
                latency_ms,
                body: parsed,
                error,
            }
        }
    }
}

/// Flatten FastAPI's `detail`, which is a string, a coded object, or a list.
fn describe_error(parsed: &Option<Value>, status: u16, raw: &str) -> String {
    let Some(detail) = parsed.as_ref().and_then(|body| body.get("detail")) else {
        let trimmed = raw.trim();
        return if trimmed.is_empty() {
            format!("HTTP {status}")
        } else {
            format!("HTTP {status}: {}", trimmed.chars().take(300).collect::<String>())
        };
    };
    match detail {
        Value::String(message) => message.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.get("msg").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("; "),
        Value::Object(map) => map
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("request rejected")
            .to_string(),
        other => other.to_string(),
    }
}
