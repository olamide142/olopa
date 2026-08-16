use super::config::SecureConnectConfig;
use super::posture::PostureFacts;
use super::{ControlAction, SessionState, TunnelProfile};
use anyhow::{bail, Context, Result};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::time::Duration;

#[derive(Clone)]
pub struct OrchestratorClient {
    client: Client,
    base_url: String,
    api_token: Option<String>,
    tenant_id: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollmentRequest<'a> {
    pub enrollment_token: &'a str,
    pub tenant_id: &'a str,
    pub host_id: &'a str,
    pub user_id: Option<&'a str>,
    pub device_fingerprint: &'a str,
    pub wireguard_public_key: &'a str,
    pub posture: &'a PostureFacts,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnrollmentResponse {
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct SessionStartRequest<'a> {
    pub tenant_id: &'a str,
    pub device_id: &'a str,
    pub host_id: &'a str,
    pub wireguard_public_key: &'a str,
    pub posture: &'a PostureFacts,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionStartResponse {
    pub session_id: String,
    #[serde(default)]
    pub state: Option<SessionState>,
    pub profile: TunnelProfile,
    #[serde(default)]
    pub command_nonce: u64,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest<'a> {
    pub tenant_id: &'a str,
    pub device_id: &'a str,
    pub session_id: &'a str,
    pub state: SessionState,
    pub posture: &'a PostureFacts,
    pub profile_version: u64,
    pub last_command_nonce: u64,
    pub last_handshake_unix: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct HeartbeatResponse {
    #[serde(default)]
    pub desired_state: Option<SessionState>,
    #[serde(default)]
    pub action: ControlAction,
    #[serde(default)]
    pub profile: Option<TunnelProfile>,
    #[serde(default)]
    pub command_nonce: u64,
}

#[derive(Debug, Serialize)]
pub struct RekeyRequest<'a> {
    pub tenant_id: &'a str,
    pub device_id: &'a str,
    pub wireguard_public_key: &'a str,
    pub last_command_nonce: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RekeyResponse {
    pub profile: TunnelProfile,
    #[serde(default)]
    pub command_nonce: u64,
}

impl OrchestratorClient {
    pub fn new(config: &SecureConnectConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .https_only(!config.control_url.starts_with("http://"))
            .timeout(Duration::from_secs(10));
        if let Some(path) = &config.identity_pem {
            let pem = fs::read(path)
                .with_context(|| format!("read Secure Connect mTLS identity {}", path.display()))?;
            let identity = reqwest::Identity::from_pem(&pem)
                .context("parse Secure Connect mTLS PEM identity")?;
            builder = builder.identity(identity);
        }
        Ok(Self {
            client: builder
                .build()
                .context("build Secure Connect HTTP client")?,
            base_url: config.control_url.clone(),
            api_token: config.api_token.clone(),
            tenant_id: config.tenant_id.clone(),
        })
    }

    pub async fn enroll(&self, request: &EnrollmentRequest<'_>) -> Result<EnrollmentResponse> {
        self.send_json(self.client.post(self.url("enroll")).json(request))
            .await
    }

    pub async fn start_session(
        &self,
        request: &SessionStartRequest<'_>,
    ) -> Result<SessionStartResponse> {
        self.send_json(self.client.post(self.url("sessions/start")).json(request))
            .await
    }

    pub async fn heartbeat(
        &self,
        session_id: &str,
        request: &HeartbeatRequest<'_>,
    ) -> Result<HeartbeatResponse> {
        self.send_json(
            self.client
                .post(self.url(&format!("sessions/{session_id}/heartbeat")))
                .json(request),
        )
        .await
    }

    pub async fn rekey(
        &self,
        session_id: &str,
        request: &RekeyRequest<'_>,
    ) -> Result<RekeyResponse> {
        self.send_json(
            self.client
                .post(self.url(&format!("sessions/{session_id}/rekey")))
                .json(request),
        )
        .await
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/api/v1/secure-connect/{suffix}", self.base_url)
    }

    fn authenticated(&self, request: RequestBuilder) -> RequestBuilder {
        let request = request.header("x-olopa-tenant-id", &self.tenant_id);
        match &self.api_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    async fn send_json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = self
            .authenticated(request)
            .send()
            .await
            .context("Secure Connect control request failed")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            bail!(
                "Secure Connect control request rejected status={} retryable={} body={}",
                status,
                retryable,
                truncate(&body, 512)
            );
        }
        response
            .json::<T>()
            .await
            .context("decode Secure Connect control response")
    }
}

fn truncate(value: &str, max: usize) -> &str {
    value.get(..value.len().min(max)).unwrap_or(value)
}
