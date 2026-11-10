//! The fwdonor HTTP API as seen by a client.
//!
//! Source: fwdonor `src/http.rs` (routes), `src/uploads.rs` (upload
//! sessions) and `src/error.rs` (error bodies). Every error response is
//! `{"error": <code>, "message": <text>}`, with an optional `Retry-After`
//! header in seconds.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::policy::Policy;

/// Longest wait between retries, `Retry-After` included (as on the page).
pub const MAX_BACKOFF: Duration = Duration::from_secs(20);

/// Hashes one `/api/known` request may carry.
pub const MAX_KNOWN_HASHES: usize = 1000;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Most requests are small; a 4 MiB chunk over a slow link gets longer (the
/// proxy in front of the server allows 120 s per request).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CHUNK_TIMEOUT: Duration = Duration::from_secs(150);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

/// Error code this client gives a success response it cannot parse.
const UNEXPECTED_RESPONSE: &str = "unexpected_response";

/// A failed request: no response at all, or the server's JSON error.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// `None`: the request never got a response (connection refused,
    /// timeout).
    pub status: Option<StatusCode>,
    /// The `error` code of the server's JSON body.
    pub code: Option<String>,
    /// User-facing description.
    pub message: String,
    /// The server's `Retry-After`, in seconds.
    pub retry_after: Option<u64>,
}

impl ApiError {
    fn no_response(error: &reqwest::Error) -> Self {
        Self {
            status: None,
            code: None,
            message: describe(error),
            retry_after: None,
        }
    }

    /// Worth retrying as is: the server is away, busy, limiting or paused.
    pub fn is_transient(&self) -> bool {
        match self.status {
            None => true,
            Some(status) => {
                status.is_server_error()
                    || status == StatusCode::REQUEST_TIMEOUT
                    || status == StatusCode::TOO_MANY_REQUESTS
            }
        }
    }

    /// The proxy answered instead of fwdonor: it is (re)starting.
    pub fn is_server_down(&self) -> bool {
        match self.status {
            None => true,
            Some(status) => self.code.is_none() && matches!(status.as_u16(), 502..=504),
        }
    }

    /// Whether the server's error code is `code`.
    pub fn is(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }

    /// The server does not know the resource (for an upload: it restarted).
    pub fn is_not_found(&self) -> bool {
        self.status == Some(StatusCode::NOT_FOUND)
    }

    /// This address is banned for a while (repeated server-side rejections).
    pub fn is_banned(&self) -> bool {
        self.status == Some(StatusCode::FORBIDDEN) && self.is("limited")
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            None => write!(f, "{}", self.message),
            Some(status) => write!(f, "{} ({})", self.message, status.as_u16()),
        }
    }
}

impl std::error::Error for ApiError {}

/// 1, 2, 4, 8, 16, 20, 20… seconds, or the server's `Retry-After`; at most
/// [`MAX_BACKOFF`] either way.
pub fn backoff(attempt: u32, retry_after: Option<u64>) -> Duration {
    let wait = match retry_after {
        Some(secs) => Duration::from_secs(secs.max(1)),
        None => Duration::from_secs(1 << attempt.min(5)),
    };
    wait.min(MAX_BACKOFF)
}

/// `GET /api/policy`: what the server accepts, and from whom.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyResponse {
    /// The zrax revision this client must have to upload: its own while the
    /// server still accepts it, otherwise the server's.
    pub zrax_rev: String,
    /// The server's own zrax revision.
    #[serde(default)]
    pub zrax_latest: Option<String>,
    /// Largest file the server takes, in bytes.
    pub max_file_bytes: u64,
    /// Smallest file the server takes, in bytes.
    pub min_file_bytes: u64,
    /// Donations are paused; uploads are refused with `paused`.
    pub paused: bool,
    /// The accept rule's lists and threshold.
    pub policy: Policy,
    /// Uploads at once the server allows this client (older servers don't
    /// say).
    #[serde(default)]
    pub max_parallel: Option<usize>,
    /// The server took our import token: more at once, no proof of work.
    #[serde(default)]
    pub import: bool,
}

/// `GET /api/challenge`: a proof-of-work challenge.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    /// Unpadded URL-safe base64 token; single-use.
    pub token: String,
    /// Leading zero bits a solution needs.
    pub bits: u8,
}

/// A hash the server knows: posted (with when), waiting for its post
/// (`queued`), or else being received or posted right now.
#[derive(Debug, Clone, Deserialize)]
pub struct Known {
    /// When it was posted, in Unix seconds.
    #[serde(default)]
    pub posted_at: Option<u64>,
    /// The post date as text.
    #[serde(default)]
    pub date: Option<String>,
    /// Received and kept; waiting for its post (the background lane).
    #[serde(default)]
    pub queued: bool,
}

#[derive(Deserialize)]
struct KnownResponse {
    known: HashMap<String, Known>,
}

/// `POST /api/uploads`: open an upload session.
#[derive(Debug, Serialize)]
pub struct InitRequest<'a> {
    /// File name without directories.
    pub name: &'a str,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 of the file, lowercase hex.
    pub sha256: &'a str,
    /// Donor name.
    pub username: &'a str,
    /// The proof-of-work token (empty with an import token).
    pub token: &'a str,
    /// The proof-of-work solution.
    pub nonce: u64,
    /// The client's zrax revision.
    pub zrax_rev: &'a str,
    /// `web`, or `background`: post it whenever no web donation is waiting.
    pub lane: &'a str,
    /// The client classifies with a zrax build of its own, so the server
    /// does not require `zrax_rev` to be one it accepts; its own verdict
    /// decides. Left out of the request when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub own_classifier: bool,
}

/// An open upload session.
#[derive(Debug, Clone, Deserialize)]
pub struct InitResponse {
    /// Session id (24 hex characters).
    pub id: String,
    /// Bytes per chunk; the last chunk holds the remainder.
    pub chunk_size: u64,
    /// Number of chunks.
    pub chunks: u64,
}

/// State of an upload session: `receiving`, `verifying`, `rejected`,
/// `queued`, `posting`, `posted` or `failed`.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    /// The state name.
    pub state: String,
    /// Why, for rejected and failed uploads.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One ISA's share of the collection.
#[derive(Debug, Clone, Deserialize)]
pub struct IsaStats {
    /// zrax `Isa` serde name.
    pub isa: String,
    /// Human ISA name.
    pub name: String,
    /// Images with this primary ISA.
    pub files: u64,
    /// Their total size in bytes.
    pub bytes: u64,
    /// Whether zrax's raw-code model can recognize this ISA.
    #[serde(default)]
    pub raw: bool,
}

/// `GET /api/stats`: the collection as the current zrax classifies it.
#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    /// Images donated.
    pub files: u64,
    /// Their total size in bytes.
    pub bytes: u64,
    /// Distinct donor names.
    #[serde(default)]
    pub donors: u64,
    /// Per-ISA counts; every raw-model ISA appears, with zeros if none was
    /// donated.
    #[serde(default)]
    pub isas: Vec<IsaStats>,
}

/// A connection to one fwdonor server.
#[derive(Clone)]
pub struct Api {
    http: Client,
    base: String,
}

/// Why no [`Api`] could be built.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The import token cannot go into an HTTP header.
    #[error("Invalid import token; it may only hold printable ASCII")]
    InvalidImportToken,
    /// The HTTP client could not be set up (TLS backend, resolver).
    #[error("HTTP client setup failed: {0}")]
    Http(#[from] reqwest::Error),
}

impl Api {
    /// `import_token` goes with every request (`Authorization: Bearer`).
    ///
    /// # Errors
    ///
    /// [`BuildError`] for a token that is not header-safe, or when the HTTP
    /// client cannot be created.
    pub fn new(
        base: &str,
        user_agent: &str,
        import_token: Option<&str>,
    ) -> Result<Self, BuildError> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = import_token {
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| BuildError::InvalidImportToken)?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        let http = Client::builder()
            .user_agent(user_agent)
            .default_headers(headers)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, request: RequestBuilder) -> Result<reqwest::Response, ApiError> {
        #[derive(Deserialize)]
        struct ErrorBody {
            error: String,
            message: String,
        }

        let response = request
            .send()
            .await
            .map_err(|error| ApiError::no_response(&error))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok());
        let text = response.text().await.unwrap_or_default();
        Err(match serde_json::from_str::<ErrorBody>(&text) {
            Ok(body) => ApiError {
                status: Some(status),
                code: Some(body.error),
                message: body.message,
                retry_after,
            },
            Err(_) => ApiError {
                status: Some(status),
                code: None,
                message: status
                    .canonical_reason()
                    .unwrap_or("HTTP error")
                    .to_lowercase(),
                retry_after,
            },
        })
    }

    async fn json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T, ApiError> {
        let response = self.send(request).await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| ApiError::no_response(&error))?;
        serde_json::from_str(&text).map_err(|error| ApiError {
            status: Some(status),
            code: Some(UNEXPECTED_RESPONSE.into()),
            message: format!("unexpected response from the server: {error}"),
            retry_after: None,
        })
    }

    /// The server's policy for a client at zrax revision `rev`.
    ///
    /// # Errors
    ///
    /// [`ApiError`]; `import_token` (401) when the import token is wrong.
    pub async fn policy(&self, rev: &str) -> Result<PolicyResponse, ApiError> {
        // Revisions are hex commit ids: nothing to escape.
        let url = self.url(&format!("/api/policy?rev={rev}"));
        self.json(self.http.get(url).timeout(REQUEST_TIMEOUT)).await
    }

    /// A fresh proof-of-work challenge.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn challenge(&self) -> Result<Challenge, ApiError> {
        let url = self.url("/api/challenge");
        self.json(self.http.get(url).timeout(REQUEST_TIMEOUT)).await
    }

    /// Which of these hashes (at most [`MAX_KNOWN_HASHES`]) the server
    /// already has or is receiving right now.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn known(&self, sha256: &[&str]) -> Result<HashMap<String, Known>, ApiError> {
        let body = serde_json::json!({ "sha256": sha256 });
        let request = self
            .http
            .post(self.url("/api/known"))
            .json(&body)
            .timeout(REQUEST_TIMEOUT);
        let response: KnownResponse = self.json(request).await?;
        Ok(response.known)
    }

    /// Open an upload session.
    ///
    /// # Errors
    ///
    /// [`ApiError`]: `duplicate`, `stale_client`, `pow`, `size`, `busy`,
    /// `limited`, `paused` or `import_token`.
    pub async fn init(&self, request: &InitRequest<'_>) -> Result<InitResponse, ApiError> {
        let request = self
            .http
            .post(self.url("/api/uploads"))
            .json(request)
            .timeout(REQUEST_TIMEOUT);
        self.json(request).await
    }

    /// Send chunk `index` of session `id`.
    ///
    /// # Errors
    ///
    /// [`ApiError`]: `state` or 404 when the server lost the session, 400
    /// for a chunk that arrived cut short.
    pub async fn put_chunk(&self, id: &str, index: u64, data: Bytes) -> Result<(), ApiError> {
        let request = self
            .http
            .put(self.url(&format!("/api/uploads/{id}/{index}")))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .timeout(CHUNK_TIMEOUT);
        self.send(request).await.map(|_| ())
    }

    /// Declare session `id` fully sent; the server starts verifying.
    ///
    /// # Errors
    ///
    /// [`ApiError`]: `incomplete` when chunks are missing.
    pub async fn complete(&self, id: &str) -> Result<Status, ApiError> {
        let url = self.url(&format!("/api/uploads/{id}/complete"));
        self.json(self.http.post(url).timeout(REQUEST_TIMEOUT))
            .await
    }

    /// The state of session `id`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn status(&self, id: &str) -> Result<Status, ApiError> {
        let url = self.url(&format!("/api/uploads/{id}"));
        self.json(self.http.get(url).timeout(REQUEST_TIMEOUT)).await
    }

    /// Cancel session `id` while it is still receiving.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn cancel(&self, id: &str) -> Result<(), ApiError> {
        let url = self.url(&format!("/api/uploads/{id}"));
        self.send(self.http.delete(url).timeout(CANCEL_TIMEOUT))
            .await
            .map(|_| ())
    }

    /// The collection's statistics.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn stats(&self) -> Result<Stats, ApiError> {
        let url = self.url("/api/stats");
        self.json(self.http.get(url).timeout(REQUEST_TIMEOUT)).await
    }
}

/// reqwest's error plus its causes (e.g. "connection refused").
fn describe(error: &reqwest::Error) -> String {
    let mut text = if error.is_timeout() {
        "timed out".to_string()
    } else {
        error.to_string()
    };
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_error(status: Option<u16>, code: Option<&str>) -> ApiError {
        ApiError {
            status: status.map(|s| StatusCode::from_u16(s).expect("valid status code")),
            code: code.map(str::to_string),
            message: String::new(),
            retry_after: None,
        }
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_and_honors_retry_after() {
        let secs: Vec<u64> = (0..8).map(|a| backoff(a, None).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 20, 20, 20]);
        assert_eq!(backoff(0, Some(5)), Duration::from_secs(5));
        assert_eq!(backoff(0, Some(600)), MAX_BACKOFF);
        assert_eq!(backoff(3, Some(0)), Duration::from_secs(1));
    }

    #[test]
    fn classifies_errors() {
        assert!(api_error(None, None).is_transient());
        assert!(api_error(None, None).is_server_down());
        assert!(api_error(Some(502), None).is_server_down());
        assert!(!api_error(Some(503), Some("paused")).is_server_down());
        assert!(api_error(Some(503), Some("paused")).is_transient());
        assert!(api_error(Some(429), Some("limited")).is_transient());
        assert!(api_error(Some(403), Some("limited")).is_banned());
        assert!(!api_error(Some(403), Some("pow")).is_banned());
        assert!(!api_error(Some(409), Some("duplicate")).is_transient());
        assert!(!api_error(Some(404), Some("not_found")).is_transient());
        assert!(api_error(Some(404), Some("not_found")).is_not_found());
    }

    #[test]
    fn policy_tolerates_fields_added_by_newer_servers() {
        let body = r#"{
            "zrax_rev": "abc", "max_file_bytes": 536870912, "min_file_bytes": 24,
            "paused": false, "chunk_bytes": 4194304, "pow_bits": 20, "future_field": 1,
            "policy": { "min_guess_confidence": 0.5, "allow": ["uimage"], "deny": [],
                        "future_list": [] }
        }"#;
        let policy: PolicyResponse = serde_json::from_str(body).expect("tolerant parse");
        assert_eq!(policy.policy.allow, ["uimage"]);
        assert_eq!(policy.max_parallel, None);
        assert!(!policy.import);
    }
}
