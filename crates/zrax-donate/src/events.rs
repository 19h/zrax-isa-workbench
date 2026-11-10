//! What a donation reports while it runs and how it ends.

use tokio::sync::mpsc::UnboundedSender;

/// Where one file is on its way to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for one of the upload slots the server allows this client.
    Waiting,
    /// Asking the server whether it already has the file.
    Lookup,
    /// Solving the proof of work for this file.
    ProofOfWork,
    /// Sending chunks; both counts are bytes.
    Uploading {
        /// Bytes the server has acknowledged.
        sent: u64,
        /// File size.
        total: u64,
    },
    /// Uploaded; the server is classifying the file itself.
    Verifying,
}

/// A progress report for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The file reached a new stage, or made progress within it.
    Stage(Stage),
    /// The client is waiting to retry; the text says why.
    Notice(String),
}

/// Receives the events of one donation. A closed receiver is not an error:
/// the donation continues unobserved.
pub type EventSender = UnboundedSender<Event>;

/// How a donation ended. Texts are user-facing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The server verified the file and kept it. It is posted later.
    Donated,
    /// The server already has the file, or is receiving it.
    Known(String),
    /// The server's own classification refused the file.
    Rejected(String),
    /// The file could not be read or sent, or the server could not keep it.
    Failed(String),
    /// The file is outside the server's limits and was not sent.
    Skipped(String),
    /// Not sent: cancelled, or the server stopped accepting this client.
    Stopped(String),
}

impl Outcome {
    /// The one-word state, as `fwdonate` prints it.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Donated => "donated",
            Outcome::Known(_) => "known",
            Outcome::Rejected(_) => "rejected",
            Outcome::Failed(_) => "failed",
            Outcome::Skipped(_) => "skipped",
            Outcome::Stopped(_) => "stopped",
        }
    }

    /// The reason that goes with the state; empty for [`Outcome::Donated`].
    pub fn detail(&self) -> &str {
        match self {
            Outcome::Donated => "",
            Outcome::Known(why)
            | Outcome::Rejected(why)
            | Outcome::Failed(why)
            | Outcome::Skipped(why)
            | Outcome::Stopped(why) => why,
        }
    }
}
