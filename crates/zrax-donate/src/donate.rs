//! One file's way to the server: lookup, proof of work, chunked upload and
//! the wait for the server's own verdict.
//!
//! Source: fwdonor `src/bin/fwdonate/main.rs` (`donate`, `upload_once`,
//! `admit`, `send_chunks`, `complete`, `await_verified`, `after_restart`).
//! The retry rules are the command-line client's: transient failures are
//! retried without limit, at most [`MAX_BACKOFF`] apart, so a server restart
//! or a pause only delays a donation. What ends the waiting is the caller's
//! [`CancellationToken`].

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zrax::types::DetectionPayload;

use crate::api::{
    backoff, Api, ApiError, BuildError, InitRequest, InitResponse, PolicyResponse, Stats, Status,
    MAX_BACKOFF,
};
use crate::donor::DonorName;
use crate::events::{Event, EventSender, Outcome, Stage};
use crate::policy::{self, Verdict};
use crate::pow;

/// The public donation server.
pub const DEFAULT_SERVER: &str = "https://fwdonor.zr.ax";

/// The server's lane for clients that do not wait for the Telegram post: a
/// file is done once the server has verified and kept it.
const BACKGROUND_LANE: &str = "background";

/// Uploads at once when the server does not say (its per-address limit).
const DEFAULT_MAX_PARALLEL: usize = 4;

/// Times a file is sent again after the server took it but could not keep it.
const SERVER_FAILURE_ATTEMPTS: u32 = 3;

/// Times one chunk is sent again after the server saw it cut short.
const DAMAGED_CHUNK_ATTEMPTS: u32 = 3;

/// Largest chunk size accepted from the server. Chunks are read into
/// memory, so the server's number must not size an arbitrary allocation.
const MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;

/// Verification takes about half a second: ask soon, then less often.
const FIRST_POLL: Duration = Duration::from_millis(250);
const SLOWEST_POLL: Duration = Duration::from_secs(2);

/// Name sent for a path without a final component.
const FALLBACK_FILE_NAME: &str = "firmware.bin";

/// Who the client is and which server it talks to.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server base URL, e.g. [`DEFAULT_SERVER`].
    pub server: String,
    /// The zrax commit this client was built from (full hex id). The server
    /// refuses uploads from a revision it does not accept.
    pub zrax_rev: String,
    /// `User-Agent`, e.g. `fwdonate/0.1.0`.
    pub user_agent: String,
    /// The server's import token: more uploads at once, no proof of work.
    pub import_token: Option<String>,
    /// Whether the client classifies with a zrax build of its own rather
    /// than the server's revision (the desktop workbench). The server then
    /// takes uploads whatever `zrax_rev` is and decides on its own
    /// classification; a file it rejects is reported as rejected and is not
    /// held against the sender. `fwdonate`, which is built from the
    /// server's revision, leaves this false.
    pub own_classifier: bool,
}

/// Why no session could be opened.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The HTTP client could not be built.
    #[error(transparent)]
    Build(#[from] BuildError),
    /// The policy request failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The server does not accept this client's zrax revision.
    #[error("Unsupported zrax revision {ours}; the server requires {required}")]
    StaleClient {
        /// The revision this client was built from.
        ours: String,
        /// The revision the server asks for.
        required: String,
    },
    /// The server did not take the import token.
    #[error("Invalid import token; the server does not accept it")]
    ImportTokenRefused,
}

/// A file the accept rule let through, identified by its SHA-256.
#[derive(Debug, Clone)]
pub struct Candidate {
    path: PathBuf,
    name: String,
    size: u64,
    sha256: [u8; 32],
    sha256_hex: String,
}

impl Candidate {
    /// Describe the file at `path`, whose current contents are `data`. The
    /// upload reads the file again and is abandoned if it changed.
    pub fn new(path: impl Into<PathBuf>, data: &[u8]) -> Self {
        let path = path.into();
        let name = path.file_name().map_or_else(
            || FALLBACK_FILE_NAME.to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let sha256: [u8; 32] = Sha256::digest(data).into();
        Self {
            path,
            name,
            size: data.len() as u64,
            sha256,
            sha256_hex: hex::encode(sha256),
        }
    }

    /// Where the file is read from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of the file, lowercase hex.
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

/// A server's policy plus the client state that outlives one file: the
/// upload slots and whether the server stopped accepting this client.
pub struct Session {
    api: Api,
    policy: PolicyResponse,
    zrax_rev: String,
    own_classifier: bool,
    zrax_label: String,
    /// A slot is held from the proof of work until the file is verified
    /// (the server holds the address's slot that long too).
    slots: Arc<Semaphore>,
    /// Set when nothing more can be donated in this session, with the
    /// reason.
    halted: Mutex<Option<String>>,
}

impl Session {
    /// Whether this build's zrax revision is one the server runs or still
    /// accepts. When it is not (only possible with
    /// [`ClientConfig::own_classifier`]), the server may classify a file
    /// differently from this client.
    pub fn is_server_revision(&self) -> bool {
        self.policy.zrax_rev == self.zrax_rev
    }

    /// Fetch the server's policy and check that it accepts this client.
    /// One request, no retries: the caller decides when to try again.
    ///
    /// # Errors
    ///
    /// [`ConnectError`]; in particular [`ConnectError::StaleClient`] when
    /// the server requires another zrax revision.
    pub async fn connect(config: ClientConfig) -> Result<Self, ConnectError> {
        let api = Api::new(
            &config.server,
            &config.user_agent,
            config.import_token.as_deref(),
        )?;
        let policy = match api.policy(&config.zrax_rev).await {
            Ok(policy) => policy,
            Err(error) if error.is("import_token") => return Err(ConnectError::ImportTokenRefused),
            Err(error) => return Err(error.into()),
        };
        if config.import_token.is_some() && !policy.import {
            return Err(ConnectError::ImportTokenRefused);
        }
        // A client with its own classifier is not tied to the server's
        // revision: the server classifies every upload itself.
        if !config.own_classifier && policy.zrax_rev != config.zrax_rev {
            return Err(ConnectError::StaleClient {
                ours: config.zrax_rev,
                required: policy.zrax_rev,
            });
        }
        let max_parallel = policy.max_parallel.unwrap_or(DEFAULT_MAX_PARALLEL).max(1);
        Ok(Self {
            api,
            zrax_label: policy::zrax_label(&config.zrax_rev),
            zrax_rev: config.zrax_rev,
            own_classifier: config.own_classifier,
            policy,
            slots: Arc::new(Semaphore::new(max_parallel)),
            halted: Mutex::new(None),
        })
    }

    /// The policy the server published when the session was opened.
    pub fn policy(&self) -> &PolicyResponse {
        &self.policy
    }

    /// The label accepted files name their classifier with.
    pub fn zrax_label(&self) -> &str {
        &self.zrax_label
    }

    /// Why this session donates nothing more, if it was stopped: the server
    /// no longer accepts the revision, the token, or the address.
    pub fn halted(&self) -> Option<String> {
        self.halted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the server would take a file of `size` bytes that zrax
    /// classified as `payload`. Run this before offering a donation: a file
    /// the server rejects counts against the uploader's address.
    pub fn assess(&self, size: u64, payload: &DetectionPayload) -> Verdict {
        if size > self.policy.max_file_bytes {
            return Verdict::Rejected {
                reason: format!(
                    "too large ({}, the limit is {})",
                    format_size(size),
                    format_size(self.policy.max_file_bytes)
                ),
            };
        }
        if size < self.policy.min_file_bytes {
            return Verdict::Rejected {
                reason: "too small".into(),
            };
        }
        policy::judge(payload, &self.policy.policy, &self.zrax_label)
    }

    /// The collection's statistics.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn stats(&self) -> Result<Stats, ApiError> {
        self.api.stats().await
    }

    /// Donate one file and report how it ended. Transient failures are
    /// retried until `cancel` is cancelled; a half-sent upload is then
    /// cancelled on the server too. Events may be dropped unread.
    pub async fn donate(
        &self,
        candidate: &Candidate,
        donor: &DonorName,
        events: &EventSender,
        cancel: &CancellationToken,
    ) -> Outcome {
        let attempt = Attempt {
            session: self,
            candidate,
            donor,
            events,
            cancel,
            receiving: Mutex::new(None),
        };
        tokio::select! {
            outcome = attempt.run() => outcome,
            () = cancel.cancelled() => {
                attempt.cancel_receiving().await;
                Outcome::Stopped("cancelled".into())
            }
        }
    }

    /// Stop taking new files: nothing more can be donated in this session.
    fn halt(&self, reason: String) -> Flow {
        let mut halted = self.halted.lock().unwrap_or_else(PoisonError::into_inner);
        let reason = halted.get_or_insert(reason).clone();
        Flow::Done(Outcome::Stopped(reason))
    }
}

/// How one attempt at a file ended, when not with a final outcome.
enum Flow {
    Done(Outcome),
    /// The server lost the upload (it restarted): send the file again.
    Restart(String),
    /// The server took the file but could not keep it.
    ServerFailed(String),
}

type Step<T> = Result<T, Flow>;

fn failed(error: &ApiError) -> Flow {
    Flow::Done(Outcome::Failed(error.to_string()))
}

/// One call of [`Session::donate`].
struct Attempt<'a> {
    session: &'a Session,
    candidate: &'a Candidate,
    donor: &'a DonorName,
    events: &'a EventSender,
    cancel: &'a CancellationToken,
    /// The upload session that is still receiving data, to cancel it on the
    /// server when the donation is cancelled.
    receiving: Mutex<Option<String>>,
}

impl Attempt<'_> {
    fn stage(&self, stage: Stage) {
        // A closed receiver only means nobody is watching.
        let _ = self.events.send(Event::Stage(stage));
    }

    fn notice(&self, text: String) {
        let _ = self.events.send(Event::Notice(text));
    }

    fn set_receiving(&self, id: Option<String>) {
        *self
            .receiving
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = id;
    }

    async fn cancel_receiving(&self) {
        let id = self
            .receiving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(id) = id {
            // Best effort: the server expires idle uploads by itself.
            let _ = self.session.api.cancel(&id).await;
        }
    }

    /// Say why we wait, then back off before retrying a transient failure.
    async fn wait(&self, error: &ApiError, attempt: u32) {
        let why = if error.is_server_down() {
            "the server isn't answering (it is probably restarting)".to_string()
        } else if error.is("paused") {
            "donations are paused".to_string()
        } else {
            error.message.clone()
        };
        self.notice(format!(
            "waiting: {why}; retrying every {} s at most",
            MAX_BACKOFF.as_secs()
        ));
        tokio::time::sleep(backoff(attempt, error.retry_after)).await;
    }

    /// Retry `request` through transient failures; other errors come back.
    async fn persist<T, F, Fut>(&self, mut request: F) -> Result<T, ApiError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        let mut attempt = 0;
        loop {
            match request().await {
                Ok(value) => return Ok(value),
                Err(error) if error.is_transient() => {
                    self.wait(&error, attempt).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn run(&self) -> Outcome {
        if let Some(reason) = self.session.halted() {
            return Outcome::Stopped(reason);
        }
        self.stage(Stage::Lookup);
        match self.lookup().await {
            Ok(None) => {}
            Ok(Some(outcome)) => return outcome,
            Err(error) => return Outcome::Failed(error.to_string()),
        }

        let mut server_failures = 0;
        loop {
            self.stage(Stage::Waiting);
            let slot = self.session.slots.acquire().await;
            if let Some(reason) = self.session.halted() {
                return Outcome::Stopped(reason);
            }
            let result = self.upload_once().await;
            drop(slot);
            match result {
                Ok(outcome) | Err(Flow::Done(outcome)) => return outcome,
                Err(Flow::Restart(why)) => self.notice(format!("{why}; sending it again")),
                Err(Flow::ServerFailed(why)) => {
                    server_failures += 1;
                    if server_failures >= SERVER_FAILURE_ATTEMPTS {
                        return Outcome::Failed(format!("the server could not post it: {why}"));
                    }
                    self.notice(format!(
                        "the server could not post it ({why}); trying again"
                    ));
                    tokio::time::sleep(MAX_BACKOFF).await;
                }
            }
        }
    }

    /// Ask whether the server already has the file. `None`: it does not.
    async fn lookup(&self) -> Result<Option<Outcome>, ApiError> {
        let sha256 = [self.candidate.sha256_hex.as_str()];
        let known = self.persist(|| self.session.api.known(&sha256)).await?;
        let Some(entry) = known.get(&self.candidate.sha256_hex) else {
            return Ok(None);
        };
        let why = match (&entry.date, entry.posted_at, entry.queued) {
            (Some(date), _, _) => format!("already donated ({date})"),
            (None, Some(_), _) => "already donated".to_string(),
            (None, None, true) => "already donated; waiting for its post".to_string(),
            (None, None, false) => "already on its way to the server".to_string(),
        };
        Ok(Some(Outcome::Known(why)))
    }

    async fn upload_once(&self) -> Step<Outcome> {
        let upload = self.admit().await?;
        self.set_receiving(Some(upload.id.clone()));
        let sent = self.send_chunks(&upload).await;
        let status = match sent {
            Ok(()) => self.complete(&upload.id).await,
            Err(flow) => Err(flow),
        };
        self.set_receiving(None);
        let status = status?;
        self.stage(Stage::Verifying);
        self.await_verified(&upload.id, status).await
    }

    /// Proof of work (unless with the import token) and upload admission.
    async fn admit(&self) -> Step<InitResponse> {
        let candidate = self.candidate;
        let mut attempt = 0;
        let mut may_retry_at_once = true;
        loop {
            let (token, nonce) = self.prove_work().await?;
            let request = InitRequest {
                name: &candidate.name,
                size: candidate.size,
                sha256: &candidate.sha256_hex,
                username: self.donor.as_str(),
                token: &token,
                nonce,
                zrax_rev: &self.session.zrax_rev,
                lane: BACKGROUND_LANE,
                own_classifier: self.session.own_classifier,
            };
            match self.session.api.init(&request).await {
                Ok(upload) => return Ok(upload),
                Err(e) if e.is("duplicate") => return Err(Flow::Done(Outcome::Known(e.message))),
                Err(e) if e.is("stale_client") => {
                    let reason = "the server no longer accepts this zrax revision; update the app";
                    return Err(self.session.halt(reason.to_string()));
                }
                Err(e) if e.is("import_token") => {
                    return Err(self
                        .session
                        .halt(format!("{} (was it replaced?)", e.message)));
                }
                Err(e) if e.is_banned() => {
                    return Err(self.session.halt(format!(
                        "the server refuses uploads from this address for now ({})",
                        e.message
                    )));
                }
                Err(e) if e.is("size") => return Err(Flow::Done(Outcome::Skipped(e.message))),
                // The challenge may have expired while we waited, or the
                // server restarted with a new key: once right away.
                Err(e) if e.is("pow") && may_retry_at_once => may_retry_at_once = false,
                Err(e) if e.is_transient() || e.is("pow") => {
                    self.wait(&e, attempt).await;
                    attempt += 1;
                }
                Err(e) => return Err(failed(&e)),
            }
        }
    }

    /// A challenge token and its solution; empty with the import token,
    /// which stands in for the proof of work.
    async fn prove_work(&self) -> Step<(String, u64)> {
        if self.session.policy.import {
            return Ok((String::new(), 0));
        }
        self.stage(Stage::ProofOfWork);
        let challenge = self
            .persist(|| self.session.api.challenge())
            .await
            .map_err(|error| failed(&error))?;
        let token = challenge.token.clone();
        let sha256 = self.candidate.sha256;
        let cancel = self.cancel.clone();
        let solved = tokio::task::spawn_blocking(move || {
            pow::solve(&token, &sha256, challenge.bits, &cancel)
        })
        .await;
        let nonce = match solved {
            Ok(Ok(nonce)) => nonce,
            Ok(Err(error)) => return Err(proof_failed(&error)),
            Err(error) => return Err(proof_failed(&error)),
        };
        Ok((challenge.token, nonce))
    }

    /// Give up on an upload that is still receiving.
    async fn abandon(&self, id: &str, why: String) -> Flow {
        let _ = self.session.api.cancel(id).await;
        Flow::Done(Outcome::Failed(why))
    }

    async fn send_chunks(&self, upload: &InitResponse) -> Step<()> {
        let candidate = self.candidate;
        if upload.chunk_size == 0 || upload.chunk_size > MAX_CHUNK_BYTES {
            let why = format!(
                "Invalid chunk size from the server ({} B)",
                upload.chunk_size
            );
            return Err(self.abandon(&upload.id, why).await);
        }
        let mut file = match tokio::fs::File::open(&candidate.path).await {
            Ok(file) => file,
            Err(error) => {
                return Err(self
                    .abandon(&upload.id, format!("read failed: {error}"))
                    .await)
            }
        };
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        self.stage(Stage::Uploading {
            sent,
            total: candidate.size,
        });
        for index in 0..upload.chunks {
            let remaining = candidate.size.saturating_sub(sent);
            // Bounded by MAX_CHUNK_BYTES, so it fits in usize.
            let len = usize::try_from(upload.chunk_size.min(remaining)).unwrap_or(0);
            let mut chunk = vec![0u8; len];
            if let Err(error) = file.read_exact(&mut chunk).await {
                return Err(self
                    .abandon(&upload.id, format!("read failed: {error}"))
                    .await);
            }
            hasher.update(&chunk);
            self.put_chunk(upload, index, Bytes::from(chunk)).await?;
            sent += len as u64;
            self.stage(Stage::Uploading {
                sent,
                total: candidate.size,
            });
        }
        // The server verifies the hash and counts a mismatch against this
        // address, so never complete a file that changed since it was checked.
        if hex::encode(hasher.finalize()) != candidate.sha256_hex {
            let why =
                "the file changed since it was checked; donate it again to send the new version";
            return Err(self.abandon(&upload.id, why.to_string()).await);
        }
        Ok(())
    }

    async fn put_chunk(&self, upload: &InitResponse, index: u64, data: Bytes) -> Step<()> {
        let mut attempt = 0;
        let mut damaged = 0;
        loop {
            match self
                .session
                .api
                .put_chunk(&upload.id, index, data.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) if e.is_not_found() || e.is("state") => {
                    return Err(self.after_restart().await)
                }
                Err(e) if e.is_transient() => {
                    self.wait(&e, attempt).await;
                    attempt += 1;
                }
                // A chunk that arrived cut short: send it again, a few times.
                Err(e)
                    if e.status == Some(StatusCode::BAD_REQUEST)
                        && damaged < DAMAGED_CHUNK_ATTEMPTS =>
                {
                    damaged += 1;
                    tokio::time::sleep(backoff(damaged, None)).await;
                }
                Err(e) => return Err(self.abandon(&upload.id, e.to_string()).await),
            }
        }
    }

    async fn complete(&self, id: &str) -> Step<Status> {
        let mut attempt = 0;
        loop {
            match self.session.api.complete(id).await {
                Ok(status) => return Ok(status),
                Err(e) if e.is_not_found() => return Err(self.after_restart().await),
                Err(e) if e.is("incomplete") => {
                    return Err(Flow::Restart("the server is missing parts of it".into()))
                }
                Err(e) if e.is_transient() => {
                    self.wait(&e, attempt).await;
                    attempt += 1;
                }
                Err(e) => return Err(failed(&e)),
            }
        }
    }

    /// Follow verification until the server has kept the file. It is posted
    /// later, whenever no web donation is waiting.
    async fn await_verified(&self, id: &str, mut status: Status) -> Step<Outcome> {
        let mut poll = FIRST_POLL;
        loop {
            match status.state.as_str() {
                "queued" | "posting" | "posted" => return Ok(Outcome::Donated),
                "rejected" => return Ok(Outcome::Rejected(status.reason.unwrap_or_default())),
                "failed" => return Err(Flow::ServerFailed(status.reason.unwrap_or_default())),
                "receiving" => return Err(Flow::Restart("the server restarted".into())),
                _ => {}
            }
            tokio::time::sleep(poll).await;
            poll = next_poll(poll);
            let mut attempt = 0;
            status = loop {
                match self.session.api.status(id).await {
                    Ok(status) => break status,
                    Err(e) if e.is_not_found() => return Err(self.after_restart().await),
                    Err(e) if e.is_transient() => {
                        self.wait(&e, attempt).await;
                        attempt += 1;
                    }
                    Err(e) => return Err(failed(&e)),
                }
            };
        }
    }

    /// The server no longer knows the upload: did it keep the file before it
    /// restarted, is the file still on its way, or must it be sent again?
    async fn after_restart(&self) -> Flow {
        let sha256 = [self.candidate.sha256_hex.as_str()];
        let mut attempt = 0;
        loop {
            let known = match self.persist(|| self.session.api.known(&sha256)).await {
                Ok(known) => known,
                Err(error) => return failed(&error),
            };
            match known.get(&self.candidate.sha256_hex) {
                // Posted, or verified and kept before the restart.
                Some(entry) if entry.posted_at.is_some() || entry.queued => {
                    return Flow::Done(Outcome::Donated)
                }
                // Still being received or posted: ask again.
                Some(_) => {
                    tokio::time::sleep(backoff(attempt, None)).await;
                    attempt += 1;
                }
                None => return Flow::Restart("the server lost the upload (it restarted)".into()),
            }
        }
    }
}

fn proof_failed(error: &dyn std::fmt::Display) -> Flow {
    Flow::Done(Outcome::Failed(format!("proof of work failed: {error}")))
}

fn next_poll(poll: Duration) -> Duration {
    (poll * 3 / 2).min(SLOWEST_POLL)
}

/// `512 B`, `1.5 MiB`: binary units, one decimal above bytes.
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    // Display only: f64 holds every size below 8 PiB exactly enough for one
    // decimal.
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polls_soon_then_less_often() {
        let polls: Vec<u128> =
            std::iter::successors(Some(FIRST_POLL), |poll| Some(next_poll(*poll)))
                .take(7)
                .map(|poll| poll.as_millis())
                .collect();
        assert_eq!(polls, [250, 375, 562, 843, 1265, 1898, 2000]);
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(3 * 1024 * 1024 / 2), "1.5 MiB");
        assert_eq!(format_size(512 * 1024 * 1024), "512.0 MiB");
    }

    #[test]
    fn candidates_carry_the_base_name_and_hash() {
        let candidate = Candidate::new("/some/dir/image.bin", b"abc");
        assert_eq!(candidate.name, "image.bin");
        assert_eq!(candidate.size(), 3);
        assert_eq!(
            candidate.sha256_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Candidate::new("/", b"").name, FALLBACK_FILE_NAME);
    }
}
