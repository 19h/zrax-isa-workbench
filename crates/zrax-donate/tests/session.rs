//! `Session` against an in-process stand-in for the fwdonor server: the
//! happy path with proof of work and chunking, known files, refused
//! revisions, retried admission, a lost upload, a changed file and
//! cancellation.
//!
//! The stand-in implements the routes of fwdonor `src/http.rs` from their
//! documented shapes. It checks the proof of work with this crate's hash
//! functions, which the shared vector in `src/pow.rs` ties to the server's.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::unbounded_channel;
use zrax_donate::{
    pow, CancellationToken, Candidate, ClientConfig, ConnectError, DonorName, Event, Outcome,
    Session, Stage,
};

const REV: &str = "1111111111111111111111111111111111111111";
const OTHER_REV: &str = "2222222222222222222222222222222222222222";
const CHUNK_BYTES: usize = 1024;
const POW_BITS: u8 = 8;
/// A file of two full chunks and a remainder.
const FILE_BYTES: usize = 2 * CHUNK_BYTES + 100;

/// One upload session on the stand-in server.
#[derive(Default)]
struct Upload {
    size: usize,
    sha256: String,
    chunks: HashMap<u64, Vec<u8>>,
    state: String,
    cancelled: bool,
}

/// Scripted server behavior and what it observed.
#[derive(Default)]
struct Server {
    /// The revision `/api/policy` asks clients to have.
    required_rev: String,
    known: HashMap<String, Value>,
    uploads: HashMap<String, Upload>,
    /// Error responses `POST /api/uploads` gives before it admits.
    admission_errors: Vec<(StatusCode, &'static str)>,
    /// Forget the first upload when its second chunk arrives (a restart).
    lose_first_upload: bool,
    /// Never answer chunk requests (to cancel mid-upload).
    stall_chunks: bool,
    /// State a completed, intact upload ends in.
    verified_state: &'static str,
    admissions: u32,
    /// Admission requests that declared a classifier of their own.
    own_classifier_admissions: u32,
    challenges_issued: u32,
}

type Shared = Arc<Mutex<Server>>;

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(json!({ "error": code, "message": format!("mock {code}") })),
    )
        .into_response()
}

async fn policy(
    State(server): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let server = server.lock().unwrap();
    assert!(query.contains_key("rev"), "the client states its revision");
    Json(json!({
        "zrax_rev": server.required_rev,
        "zrax_latest": server.required_rev,
        "max_file_bytes": 1 << 20,
        "min_file_bytes": 24,
        "chunk_bytes": CHUNK_BYTES,
        "pow_bits": POW_BITS,
        "max_parallel": 2,
        "import": false,
        "paused": false,
        "policy": { "min_guess_confidence": 0.5, "allow": [], "deny": [] },
    }))
}

async fn known(State(server): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let server = server.lock().unwrap();
    let mut found = serde_json::Map::new();
    for hash in body["sha256"].as_array().unwrap() {
        let hash = hash.as_str().unwrap();
        if let Some(entry) = server.known.get(hash) {
            found.insert(hash.to_string(), entry.clone());
        }
    }
    Json(json!({ "known": found }))
}

async fn challenge(State(server): State<Shared>) -> Json<Value> {
    let mut server = server.lock().unwrap();
    server.challenges_issued += 1;
    // 41 token bytes, like the server's; distinct per challenge.
    let token = [u8::try_from(server.challenges_issued).unwrap(); 41];
    Json(json!({ "token": URL_SAFE_NO_PAD.encode(token), "bits": POW_BITS, "expires": 0 }))
}

async fn init(State(server): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut server = server.lock().unwrap();
    if !server.admission_errors.is_empty() {
        let (status, code) = server.admission_errors.remove(0);
        return error(status, code);
    }
    // As fwdonor: a client that classifies with its own zrax is admitted
    // whatever its revision; the server's verdict decides.
    let own_classifier = body["own_classifier"] == true;
    server.own_classifier_admissions += u32::from(own_classifier);
    if !own_classifier && body["zrax_rev"] != server.required_rev {
        return error(StatusCode::CONFLICT, "stale_client");
    }
    assert_eq!(body["lane"], "background");
    assert_eq!(body["username"], "tester");
    let sha256 = body["sha256"].as_str().unwrap().to_string();
    let file_sha256: [u8; 32] = hex::decode(&sha256).unwrap().try_into().unwrap();
    let token = URL_SAFE_NO_PAD
        .decode(body["token"].as_str().unwrap())
        .unwrap();
    let work = pow::work_hash(
        &pow::seed(&token, &file_sha256),
        body["nonce"].as_u64().unwrap(),
    );
    if pow::leading_zero_bits(&work) < u32::from(POW_BITS) {
        return error(StatusCode::FORBIDDEN, "pow");
    }
    server.admissions += 1;
    let id = format!("{:024x}", server.admissions);
    let size = usize::try_from(body["size"].as_u64().unwrap()).unwrap();
    let upload = Upload {
        size,
        sha256,
        state: "receiving".into(),
        ..Upload::default()
    };
    server.uploads.insert(id.clone(), upload);
    let created =
        json!({ "id": id, "chunk_size": CHUNK_BYTES, "chunks": size.div_ceil(CHUNK_BYTES) });
    (StatusCode::CREATED, Json(created)).into_response()
}

async fn chunk(
    State(server): State<Shared>,
    Path((id, index)): Path<(String, u64)>,
    body: Bytes,
) -> Response {
    let stall = server.lock().unwrap().stall_chunks;
    if stall {
        std::future::pending::<()>().await;
    }
    let mut server = server.lock().unwrap();
    if server.lose_first_upload && index == 1 {
        server.lose_first_upload = false;
        server.uploads.remove(&id);
    }
    let Some(upload) = server.uploads.get_mut(&id) else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    upload.chunks.insert(index, body.to_vec());
    StatusCode::NO_CONTENT.into_response()
}

async fn complete(State(server): State<Shared>, Path(id): Path<String>) -> Response {
    let mut server = server.lock().unwrap();
    let verified_state = server.verified_state;
    let Some(upload) = server.uploads.get_mut(&id) else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let mut data = Vec::new();
    for index in 0..upload.size.div_ceil(CHUNK_BYTES) as u64 {
        let Some(part) = upload.chunks.get(&index) else {
            return error(StatusCode::CONFLICT, "incomplete");
        };
        data.extend_from_slice(part);
    }
    assert_eq!(
        hex::encode(Sha256::digest(&data)),
        upload.sha256,
        "the client never completes a changed file"
    );
    upload.state = verified_state.into();
    // The first answer is still "verifying", so the client has to poll.
    (StatusCode::ACCEPTED, Json(json!({ "state": "verifying" }))).into_response()
}

async fn status(State(server): State<Shared>, Path(id): Path<String>) -> Response {
    let server = server.lock().unwrap();
    match server.uploads.get(&id) {
        Some(upload) => {
            Json(json!({ "state": upload.state, "reason": "mock reason" })).into_response()
        }
        None => error(StatusCode::NOT_FOUND, "not_found"),
    }
}

async fn cancel(State(server): State<Shared>, Path(id): Path<String>) -> StatusCode {
    if let Some(upload) = server.lock().unwrap().uploads.get_mut(&id) {
        upload.cancelled = true;
    }
    StatusCode::NO_CONTENT
}

/// Start the stand-in server; returns its base URL and shared state.
async fn serve(configure: impl FnOnce(&mut Server)) -> (String, Shared) {
    let mut server = Server {
        required_rev: REV.into(),
        verified_state: "queued",
        ..Server::default()
    };
    configure(&mut server);
    let shared = Arc::new(Mutex::new(server));
    let router = Router::new()
        .route("/api/policy", get(policy))
        .route("/api/known", post(known))
        .route("/api/challenge", get(challenge))
        .route("/api/uploads", post(init))
        .route("/api/uploads/{id}/{index}", put(chunk))
        .route("/api/uploads/{id}/complete", post(complete))
        .route("/api/uploads/{id}", get(status).delete(cancel))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{address}"), shared)
}

fn config(server: &str, own_classifier: bool) -> ClientConfig {
    ClientConfig {
        server: server.to_string(),
        zrax_rev: REV.to_string(),
        user_agent: "zrax-donate-test".to_string(),
        import_token: None,
        own_classifier,
    }
}

async fn connect(server: &str) -> Result<Session, ConnectError> {
    Session::connect(config(server, false)).await
}

/// A file of [`FILE_BYTES`] deterministic bytes in a fresh directory.
fn firmware_file() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image.bin");
    let data: Vec<u8> = (0..FILE_BYTES).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    (directory, path, data)
}

/// Donate `candidate` and collect every event it reported.
async fn donate(session: &Session, candidate: &Candidate) -> (Outcome, Vec<Event>) {
    let (sender, mut receiver) = unbounded_channel();
    let donor = DonorName::parse("tester").unwrap();
    let outcome = session
        .donate(candidate, &donor, &sender, &CancellationToken::new())
        .await;
    drop(sender);
    let mut events = Vec::new();
    while let Some(event) = receiver.recv().await {
        events.push(event);
    }
    (outcome, events)
}

#[tokio::test]
async fn a_new_file_is_proved_chunked_and_donated_once_verified() {
    let (url, server) = serve(|_| {}).await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, events) = donate(&session, &Candidate::new(&path, &data)).await;

    assert_eq!(outcome, Outcome::Donated);
    let server = server.lock().unwrap();
    let upload = server.uploads.values().next().unwrap();
    assert_eq!(upload.chunks.len(), 3);
    assert_eq!(upload.chunks[&2].len(), 100);
    let total = FILE_BYTES as u64;
    let uploaded: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            Event::Stage(Stage::Uploading { sent, total: of }) if *of == total => Some(*sent),
            _ => None,
        })
        .collect();
    assert_eq!(uploaded, [0, 1024, 2048, total]);
    assert!(events.contains(&Event::Stage(Stage::ProofOfWork)));
    assert_eq!(events.last(), Some(&Event::Stage(Stage::Verifying)));
}

#[tokio::test]
async fn a_known_file_is_not_sent() {
    let (_directory, path, data) = firmware_file();
    let candidate = Candidate::new(&path, &data);
    let sha256 = candidate.sha256_hex().to_string();
    let (url, server) = serve(|server| {
        server
            .known
            .insert(sha256, json!({ "posted_at": 1, "date": "2026-11-01" }));
    })
    .await;
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &candidate).await;

    assert_eq!(
        outcome,
        Outcome::Known("already donated (2026-11-01)".into())
    );
    assert_eq!(server.lock().unwrap().admissions, 0);
}

#[tokio::test]
async fn a_server_that_requires_another_revision_refuses_the_session() {
    let (url, _) = serve(|server| server.required_rev = OTHER_REV.into()).await;
    match connect(&url).await {
        Err(ConnectError::StaleClient { ours, required }) => {
            assert_eq!(ours, REV);
            assert_eq!(required, OTHER_REV);
        }
        other => panic!("expected StaleClient, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn a_client_with_its_own_classifier_donates_whatever_its_revision() {
    let (url, server) = serve(|server| server.required_rev = OTHER_REV.into()).await;
    let (_directory, path, data) = firmware_file();
    let session = Session::connect(config(&url, true)).await.unwrap();
    assert!(!session.is_server_revision());
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;

    assert_eq!(outcome, Outcome::Donated);
    assert_eq!(server.lock().unwrap().own_classifier_admissions, 1);
}

#[tokio::test]
async fn a_client_on_the_servers_revision_does_not_declare_its_own_classifier() {
    let (url, server) = serve(|_| {}).await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    assert!(session.is_server_revision());
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;

    assert_eq!(outcome, Outcome::Donated);
    assert_eq!(server.lock().unwrap().own_classifier_admissions, 0);
}

#[tokio::test]
async fn a_revision_refused_at_admission_halts_the_session() {
    let (url, _) = serve(|server| {
        server
            .admission_errors
            .push((StatusCode::CONFLICT, "stale_client"));
    })
    .await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;

    let Outcome::Stopped(reason) = outcome else {
        panic!("expected Stopped, got {outcome:?}");
    };
    assert!(reason.contains("no longer accepts this zrax revision"));
    assert_eq!(session.halted(), Some(reason.clone()));
    // Nothing else is attempted in a halted session.
    let (again, _) = donate(&session, &Candidate::new(&path, &data)).await;
    assert_eq!(again, Outcome::Stopped(reason));
}

#[tokio::test]
async fn a_refused_proof_is_solved_again_with_a_new_challenge() {
    let (url, server) = serve(|server| {
        server.admission_errors.push((StatusCode::FORBIDDEN, "pow"));
    })
    .await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;

    assert_eq!(outcome, Outcome::Donated);
    assert_eq!(server.lock().unwrap().challenges_issued, 2);
}

#[tokio::test]
async fn a_duplicate_reported_at_admission_counts_as_known() {
    let (url, _) = serve(|server| {
        server
            .admission_errors
            .push((StatusCode::CONFLICT, "duplicate"));
    })
    .await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;
    assert_eq!(outcome, Outcome::Known("mock duplicate".into()));
}

#[tokio::test]
async fn an_upload_the_server_lost_is_sent_again_from_the_start() {
    let (url, server) = serve(|server| server.lose_first_upload = true).await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, events) = donate(&session, &Candidate::new(&path, &data)).await;

    assert_eq!(outcome, Outcome::Donated);
    assert_eq!(server.lock().unwrap().admissions, 2);
    let resent =
        Event::Notice("the server lost the upload (it restarted); sending it again".into());
    assert!(events.contains(&resent), "{events:?}");
}

#[tokio::test]
async fn a_rejection_by_the_server_is_reported_with_its_reason() {
    let (url, _) = serve(|server| server.verified_state = "rejected").await;
    let (_directory, path, data) = firmware_file();
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &Candidate::new(&path, &data)).await;
    assert_eq!(outcome, Outcome::Rejected("mock reason".into()));
}

#[tokio::test]
async fn a_file_that_changed_since_it_was_checked_is_abandoned() {
    let (url, server) = serve(|_| {}).await;
    let (_directory, path, data) = firmware_file();
    let candidate = Candidate::new(&path, &data);
    let mut changed = data.clone();
    changed[0] ^= 0xFF;
    std::fs::write(&path, &changed).unwrap();
    let session = connect(&url).await.unwrap();
    let (outcome, _) = donate(&session, &candidate).await;

    let Outcome::Failed(reason) = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert!(reason.starts_with("the file changed since it was checked"));
    let server = server.lock().unwrap();
    let upload = server.uploads.values().next().unwrap();
    assert!(upload.cancelled);
    assert_eq!(upload.state, "receiving", "never completed");
}

#[tokio::test]
async fn cancelling_mid_upload_stops_and_cancels_the_upload_on_the_server() {
    let (url, server) = serve(|server| server.stall_chunks = true).await;
    let (_directory, path, data) = firmware_file();
    let candidate = Candidate::new(&path, &data);
    let session = connect(&url).await.unwrap();
    let (sender, mut receiver) = unbounded_channel();
    let donor = DonorName::parse("tester").unwrap();
    let cancel = CancellationToken::new();

    let donation = session.donate(&candidate, &donor, &sender, &cancel);
    let cancel_once_uploading = async {
        while let Some(event) = receiver.recv().await {
            if matches!(event, Event::Stage(Stage::Uploading { .. })) {
                cancel.cancel();
            }
        }
    };
    let outcome = tokio::select! {
        outcome = donation => outcome,
        () = cancel_once_uploading => unreachable!("the sender outlives the donation"),
    };

    assert_eq!(outcome, Outcome::Stopped("cancelled".into()));
    let server = server.lock().unwrap();
    assert!(server.uploads.values().next().unwrap().cancelled);
}

#[tokio::test]
async fn files_outside_the_size_limits_are_rejected_before_classification() {
    let (url, _) = serve(|_| {}).await;
    let session = connect(&url).await.unwrap();
    let payload = zrax::detect_bytes(&elf_header()).unwrap();
    let too_large = session.assess(2 << 20, &payload);
    let too_small = session.assess(8, &payload);
    let accepted = session.assess(64, &payload);

    let reason = |verdict| match verdict {
        zrax_donate::policy::Verdict::Rejected { reason } => reason,
        zrax_donate::policy::Verdict::Accepted(_) => panic!("expected a rejection"),
    };
    assert_eq!(
        reason(too_large),
        "too large (2.0 MiB, the limit is 1.0 MiB)"
    );
    assert_eq!(reason(too_small), "too small");
    assert!(accepted.is_accepted());
}

/// A minimal little-endian ELF64 header for AArch64: `e_ident`, `e_type`
/// (`ET_EXEC`), `e_machine` (183), `e_version`, and `e_ehsize` (64).
fn elf_header() -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2; // EI_CLASS: ELFCLASS64
    header[5] = 1; // EI_DATA: little-endian
    header[6] = 1; // EI_VERSION
    header[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type
    header[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine
    header[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    header
}
