//! Firmware donation: the bridge between the workbench and the fwdonor
//! client (`zrax-donate`).
//!
//! Donation is always available: every analyzed file from disk shows
//! whether it can be donated, and no file is sent without an explicit
//! click. What the application does on its own, once a file has been
//! analyzed, is fetch the server's policy (one request naming this build's
//! zrax revision), so it can tell which files the server would take.
//!
//! The application is not tied to the server's zrax revision. It tells the
//! server that it classifies with a zrax of its own; the server then
//! classifies every upload itself and accepts or rejects it on that
//! verdict. The local check with the server's published rule only decides
//! whether to offer a file, so that files the server would plainly refuse
//! are not uploaded for nothing.
//!
//! The client is tokio-based. It runs on a small runtime owned here; its
//! results come back to the interface through gpui tasks.

use std::collections::HashSet;
use std::sync::Arc;

use gpui::{Context, SharedString};
use tokio::sync::mpsc::unbounded_channel;
use zrax_donate::api::Stats;
use zrax_donate::policy::Verdict;
use zrax_donate::{
    CancellationToken, Candidate, ClientConfig, ConnectError, DonorName, Event, Outcome, Session,
    Stage, DEFAULT_SERVER,
};

use crate::model::entry::{Entry, EntryId, Source, Status};

/// The zrax commit this binary was built from; empty when unknown.
const BUILD_REVISION: &str = env!("ZRAX_GIT_REV");
/// Environment variable naming another donation server (for a local
/// `fwdonor serve` during development).
const SERVER_VARIABLE: &str = "ZRAX_DONATE_SERVER";

/// Worker threads of the client's runtime: uploads wait on the network.
const RUNTIME_THREADS: usize = 2;

/// What a donor is told before the first upload. Every statement is about
/// what the server does with a donated file.
pub const DISCLOSURE: &str = "Donating uploads this file to the zrax firmware collection \
(fwdonor.zr.ax). The server classifies it again, posts it with its file name and your donor \
name to the zrax firmware group on Telegram, keeps a permanent copy, and lists it for public \
download. Only donate images you have the right to share.";

/// Whether the application can donate, and to whom.
pub enum Connection {
    /// This build cannot donate; the text says why.
    Unavailable(SharedString),
    /// The server has not been asked yet.
    Idle,
    /// The policy request is under way.
    Connecting,
    /// The server accepts this build.
    Ready(Arc<Session>),
    /// The server could not be reached or refused this build.
    Failed(SharedString),
}

/// What the file view shows about donating the selected file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferState {
    /// Nothing: the user declined for this file, or the entry is not a
    /// file from disk that has been analyzed.
    Hidden,
    /// The server would take the file: offer to donate it.
    Offer,
    /// One line saying why the file cannot be donated right now, or how
    /// its donation is going.
    Note {
        /// The line.
        text: String,
        /// Whether asking the server again may change the answer.
        can_retry: bool,
    },
}

/// One file the user chose to donate.
pub struct Donation {
    /// The entry being donated.
    pub entry: EntryId,
    /// Its file name.
    pub name: SharedString,
    /// Its size in bytes.
    pub size: u64,
    /// Where the upload is; `None` before the first report.
    pub stage: Option<Stage>,
    /// Why the client is waiting, when it is.
    pub notice: Option<SharedString>,
    /// How it ended; `None` while under way.
    pub outcome: Option<Outcome>,
    cancel: CancellationToken,
}

impl Donation {
    /// One line describing the state: the outcome, or the stage.
    pub fn status_text(&self) -> String {
        if let Some(outcome) = &self.outcome {
            return if outcome.detail().is_empty() {
                outcome.label().to_string()
            } else {
                format!("{} · {}", outcome.label(), outcome.detail())
            };
        }
        match &self.stage {
            None => "starting".to_string(),
            Some(Stage::Waiting) => "waiting for an upload slot".to_string(),
            Some(Stage::Lookup) => "checking whether the server has it".to_string(),
            Some(Stage::ProofOfWork) => "solving the proof of work".to_string(),
            Some(Stage::Uploading { sent, total }) => format!(
                "uploading {} of {}",
                crate::format::size(*sent),
                crate::format::size(*total)
            ),
            Some(Stage::Verifying) => "the server is verifying it".to_string(),
        }
    }

    /// Upload progress as a fraction, while uploading.
    pub fn progress(&self) -> Option<f32> {
        match (&self.outcome, &self.stage) {
            (None, Some(Stage::Uploading { sent, total })) if *total > 0 => {
                // A ratio for a progress bar.
                #[allow(clippy::cast_precision_loss)]
                let fraction = *sent as f32 / *total as f32;
                Some(fraction)
            }
            _ => None,
        }
    }
}

/// A file ready to be donated, detached from the session.
pub struct DonationRequest {
    entry: EntryId,
    name: SharedString,
    size: u64,
    path: std::path::PathBuf,
    engine: zrax::workbench::Engine,
    donor: DonorName,
}

/// Why this build cannot talk to a donation server at all: the server
/// has to be told which zrax revision is asking.
fn build_blocker() -> Option<&'static str> {
    BUILD_REVISION
        .is_empty()
        .then_some("this build does not know which zrax revision it was built from")
}

fn describe(error: &ConnectError) -> String {
    match error {
        ConnectError::StaleClient { ours, required } => {
            let short = |revision: &str| revision.get(..7).unwrap_or(revision).to_string();
            format!(
                "the server accepts zrax {} and not this build's {}",
                short(required),
                short(ours)
            )
        }
        other => other.to_string(),
    }
}

/// The donation state of one window.
pub struct Donations {
    runtime: Option<tokio::runtime::Runtime>,
    connection: Connection,
    server: String,
    /// The donor name as typed; validated when a donation starts.
    donor: String,
    items: Vec<Donation>,
    /// Entries the user answered "not this file" for.
    declined: HashSet<EntryId>,
    stats: Option<Stats>,
}

impl Donations {
    /// Donation state for a new window. Does not contact the server.
    pub fn new() -> Self {
        let server = std::env::var(SERVER_VARIABLE).unwrap_or_else(|_| DEFAULT_SERVER.to_string());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(RUNTIME_THREADS)
            .enable_all()
            .thread_name("zrax-donate")
            .build();
        let (runtime, connection) = match (build_blocker(), runtime) {
            (Some(blocker), runtime) => (runtime.ok(), Connection::Unavailable(blocker.into())),
            (None, Ok(runtime)) => (Some(runtime), Connection::Idle),
            (None, Err(error)) => (
                None,
                Connection::Unavailable(
                    format!("the upload runtime failed to start: {error}").into(),
                ),
            ),
        };
        Self {
            runtime,
            connection,
            server,
            donor: String::new(),
            items: Vec::new(),
            declined: HashSet::new(),
            stats: None,
        }
    }

    /// Whether and to whom the application can donate.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The server's base URL.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The short revision this build reports to the server.
    pub fn build_revision() -> &'static str {
        BUILD_REVISION.get(..7).unwrap_or(BUILD_REVISION)
    }

    /// Every donation of this session, oldest first.
    pub fn donations(&self) -> &[Donation] {
        &self.items
    }

    /// The donation of `entry`, if the user started one.
    pub fn donation(&self, entry: EntryId) -> Option<&Donation> {
        self.items.iter().find(|donation| donation.entry == entry)
    }

    /// The collection's statistics, once fetched.
    pub fn stats(&self) -> Option<&Stats> {
        self.stats.as_ref()
    }

    /// Set the donor name as typed.
    pub fn set_donor(&mut self, donor: &str, cx: &mut Context<Self>) {
        self.donor = donor.to_string();
        cx.notify();
    }

    /// The name donations are credited to: the typed one when the server
    /// would keep it, otherwise an error to show next to the field.
    pub fn donor_name(&self) -> Result<DonorName, zrax_donate::InvalidDonorName> {
        if self.donor.trim().is_empty() {
            Ok(DonorName::anonymous())
        } else {
            DonorName::parse(&self.donor)
        }
    }

    /// Fetch the server's policy unless that already happened or cannot.
    pub fn connect(&mut self, cx: &mut Context<Self>) {
        let is_startable = matches!(self.connection, Connection::Idle | Connection::Failed(_));
        let Some(runtime) = self.runtime.as_ref().filter(|_| is_startable) else {
            return;
        };
        self.connection = Connection::Connecting;
        let config = ClientConfig {
            server: self.server.clone(),
            zrax_rev: BUILD_REVISION.to_string(),
            user_agent: format!("zrax-desktop/{}", env!("CARGO_PKG_VERSION")),
            import_token: None,
            // The desktop classifies with the zrax it was built with; the
            // server classifies every upload itself and its verdict decides.
            own_classifier: true,
        };
        let connecting = runtime.spawn(async move {
            let session = Session::connect(config).await?;
            // Statistics are a courtesy; a failure only leaves them out.
            let stats = session.stats().await.ok();
            Ok::<_, ConnectError>((session, stats))
        });
        cx.spawn(async move |donations, cx| {
            let result = connecting.await;
            let _ = donations.update(cx, |donations, cx| {
                donations.connection = match result {
                    Ok(Ok((session, stats))) => {
                        donations.stats = stats;
                        Connection::Ready(Arc::new(session))
                    }
                    Ok(Err(error)) => Connection::Failed(describe(&error).into()),
                    Err(error) => Connection::Failed(error.to_string().into()),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Whether the server would take `entry`, by its own rule. `None` while
    /// that cannot be known: no connection, or no classification yet.
    pub fn verdict(&self, entry: &Entry) -> Option<Verdict> {
        let Connection::Ready(session) = &self.connection else {
            return None;
        };
        // Only files from disk are donated: the server names a donation
        // after its file, and an extracted member is not what was added.
        let is_donatable_kind = entry.depth == 0 && matches!(entry.source, Source::File(_));
        if !is_donatable_kind || entry.status != Status::Done {
            return None;
        }
        Some(session.assess(entry.size, entry.payload()?))
    }

    /// What the file view shows about donating `entry`.
    pub fn offer_state(&self, entry: &Entry) -> OfferState {
        // Extracted members and files still being analyzed are never
        // offered.
        let is_candidate = entry.depth == 0
            && matches!(entry.source, Source::File(_))
            && entry.status == Status::Done;
        if !is_candidate || self.declined.contains(&entry.id) {
            return OfferState::Hidden;
        }
        let note = |text: String, can_retry: bool| OfferState::Note { text, can_retry };
        if let Some(donation) = self.donation(entry.id) {
            return note(format!("donation: {}", donation.status_text()), false);
        }
        match &self.connection {
            Connection::Unavailable(reason) => note(format!("cannot donate: {reason}"), false),
            Connection::Failed(reason) => note(format!("cannot donate yet: {reason}"), true),
            Connection::Idle | Connection::Connecting => note(
                "asking the donation server what it accepts…".to_string(),
                false,
            ),
            Connection::Ready(_) => match self.verdict(entry) {
                Some(Verdict::Accepted(_)) => OfferState::Offer,
                Some(Verdict::Rejected { reason }) => note(
                    format!("the donation server would not take this file: {reason}"),
                    false,
                ),
                None => OfferState::Hidden,
            },
        }
    }

    /// Answer "not this file" for `entry`.
    pub fn decline(&mut self, entry: EntryId, cx: &mut Context<Self>) {
        self.declined.insert(entry);
        cx.notify();
    }

    /// Stop the donation of `entry`; a half-sent upload is cancelled on the
    /// server too.
    pub fn cancel(&mut self, entry: EntryId) {
        if let Some(donation) = self.donation(entry) {
            donation.cancel.cancel();
        }
    }

    fn donation_mut(&mut self, entry: EntryId) -> Option<&mut Donation> {
        self.items
            .iter_mut()
            .find(|donation| donation.entry == entry)
    }

    /// What is needed to donate `entry`, if it can be donated right now:
    /// the server would take the file, the donor name is valid, and no
    /// donation of it is under way.
    pub fn request_for(&self, entry: &Entry) -> Option<DonationRequest> {
        let is_accepted = self
            .verdict(entry)
            .is_some_and(|verdict| verdict.is_accepted());
        let is_under_way = self
            .donation(entry.id)
            .is_some_and(|donation| donation.outcome.is_none());
        if !is_accepted || is_under_way {
            return None;
        }
        Some(DonationRequest {
            entry: entry.id,
            name: entry.name.clone(),
            size: entry.size,
            path: entry.path()?.to_path_buf(),
            engine: entry.analysis.as_ref()?.engine.clone(),
            donor: self.donor_name().ok()?,
        })
    }

    /// Start the donation described by `request`: hash the file, then hand
    /// it to the client.
    pub fn donate(&mut self, request: DonationRequest, cx: &mut Context<Self>) {
        let (Connection::Ready(session), Some(runtime)) = (&self.connection, &self.runtime) else {
            return;
        };
        let DonationRequest {
            entry: entry_id,
            name,
            size,
            path,
            engine,
            donor,
        } = request;

        let cancel = CancellationToken::new();
        let (events, mut event_receiver) = unbounded_channel();
        let upload = runtime.spawn({
            let (session, cancel) = (session.clone(), cancel.clone());
            async move {
                // Hashing up to 512 MiB: off the async workers.
                let hashing =
                    tokio::task::spawn_blocking(move || Candidate::new(path, engine.data()));
                let candidate = match hashing.await {
                    Ok(candidate) => candidate,
                    Err(error) => return Outcome::Failed(format!("hashing failed: {error}")),
                };
                session.donate(&candidate, &donor, &events, &cancel).await
            }
        });

        self.items.retain(|donation| donation.entry != entry_id);
        self.items.push(Donation {
            entry: entry_id,
            name,
            size,
            stage: None,
            notice: None,
            outcome: None,
            cancel,
        });
        cx.spawn(async move |donations, cx| {
            while let Some(event) = event_receiver.recv().await {
                let updated = donations.update(cx, |donations, cx| {
                    if let Some(donation) = donations.donation_mut(entry_id) {
                        match event {
                            Event::Stage(stage) => {
                                donation.stage = Some(stage);
                                donation.notice = None;
                            }
                            Event::Notice(text) => donation.notice = Some(text.into()),
                        }
                    }
                    cx.notify();
                });
                if updated.is_err() {
                    return;
                }
            }
            // The sender is dropped when the upload task ends.
            let outcome = upload.await.unwrap_or_else(|error| {
                Outcome::Failed(format!("the upload task failed: {error}"))
            });
            let _ = donations.update(cx, |donations, cx| {
                if let Some(donation) = donations.donation_mut(entry_id) {
                    donation.outcome = Some(outcome);
                    donation.notice = None;
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}

impl Drop for Donations {
    fn drop(&mut self) {
        for donation in &self.items {
            donation.cancel.cancel();
        }
        // Dropping a runtime blocks until its tasks finish; uploads may be
        // waiting out a retry. Let it wind down on its own threads instead.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn donation(stage: Option<Stage>, outcome: Option<Outcome>) -> Donation {
        Donation {
            entry: EntryId(1),
            name: "image.bin".into(),
            size: 2048,
            stage,
            notice: None,
            outcome,
            cancel: CancellationToken::new(),
        }
    }

    #[test]
    fn status_text_follows_stage_then_outcome() {
        assert_eq!(donation(None, None).status_text(), "starting");
        let uploading = donation(
            Some(Stage::Uploading {
                sent: 1024,
                total: 2048,
            }),
            None,
        );
        assert_eq!(uploading.status_text(), "uploading 1.0 KiB of 2.0 KiB");
        assert_eq!(uploading.progress(), Some(0.5));
        let donated = donation(Some(Stage::Verifying), Some(Outcome::Donated));
        assert_eq!(donated.status_text(), "donated");
        assert_eq!(donated.progress(), None);
        let rejected = donation(None, Some(Outcome::Rejected("no ISA found in raw".into())));
        assert_eq!(rejected.status_text(), "rejected · no ISA found in raw");
    }

    #[test]
    fn an_empty_donor_name_is_anonymous_and_an_invalid_one_is_an_error() {
        let mut donations = Donations::new();
        assert_eq!(donations.donor_name().unwrap().as_str(), "anonymous");
        donations.donor = "some_name".into();
        assert_eq!(donations.donor_name().unwrap().as_str(), "some_name");
        donations.donor = "has space".into();
        assert!(donations.donor_name().is_err());
    }
}
