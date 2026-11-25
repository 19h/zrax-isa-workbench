//! One file in the session: where its bytes come from and what analysis
//! has established about it.

use std::path::PathBuf;
use std::sync::Arc;

use gpui::SharedString;
use zrax::inspection::Subfile;
use zrax::types::{DetectionPayload, Isa};
use zrax::workbench::Engine;

use crate::{format, names};

/// Identifies an entry for the lifetime of the session. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId(pub u64);

/// Where an entry's bytes come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A file on disk, read when analysis starts and re-read on demand.
    File(PathBuf),
    /// Bytes that exist only in this session: an extracted member, a
    /// decrypted payload, a certificate opened as a file.
    Memory(Arc<[u8]>),
}

/// How an entry came into the session. Together with the parent it
/// identifies a derived entry, so opening the same member twice selects the
/// existing entry instead of extracting it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A file the user added.
    Added,
    /// Member `index` of the parent's member list.
    Subfile(usize),
    /// DER bytes of the certificate stored at this byte offset in the parent.
    Certificate(u64),
}

/// How far analysis of an entry has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Waiting for a free analysis slot.
    Queued,
    /// Being read and classified.
    Analyzing,
    /// Analysis finished; the entry may still have no ISA.
    Done,
    /// The file could not be read or classified.
    Failed,
}

impl Status {
    /// The word shown in badges and counts.
    pub fn label(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Analyzing => "analyzing",
            Status::Done => "done",
            Status::Failed => "failed",
        }
    }

    /// The glyph in front of a file-list row.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Queued => "[ ]",
            Status::Analyzing => "[*]",
            Status::Done => "[+]",
            Status::Failed => "[-]",
        }
    }
}

/// Everything one analysis pass produced.
#[derive(Debug)]
pub struct Analysis {
    /// The resident bytes and the engine over them.
    pub engine: Engine,
    /// The classification; `None` for an opaque component.
    pub payload: Option<DetectionPayload>,
    /// Why there is no payload, when classification failed.
    pub error: Option<String>,
    /// Entropy per profile bin, in bits per byte.
    pub profile: Arc<[f32]>,
    /// Mean of `profile`; `None` for an empty file.
    pub mean_entropy: Option<f32>,
    /// Members that can be opened as files of their own.
    pub subfiles: Vec<Subfile>,
    /// Why members could not be listed, when the container is malformed.
    pub subfile_error: Option<String>,
    /// Wall-clock time of the pass, in milliseconds.
    pub elapsed_ms: f64,
}

/// A file in the session.
#[derive(Debug)]
pub struct Entry {
    /// Session-unique identifier.
    pub id: EntryId,
    /// Display name: the file name, or the member label.
    pub name: SharedString,
    /// Where the bytes come from.
    pub source: Source,
    /// Size in bytes.
    pub size: u64,
    /// Analysis progress.
    pub status: Status,
    /// The finished analysis.
    pub analysis: Option<Analysis>,
    /// Why analysis failed before producing anything (unreadable file).
    pub error: Option<String>,
    /// The entry this one was extracted from.
    pub parent: Option<EntryId>,
    /// How the entry came into the session.
    pub origin: Origin,
    /// Nesting depth; 0 for a file the user added.
    pub depth: usize,
    /// An opaque component: bytes are inspected, the code model is not run.
    pub opaque: bool,
    /// The byte offset the entropy and hex views are looking at.
    pub cursor: u64,
}

impl Entry {
    /// The classification, when analysis produced one.
    pub fn payload(&self) -> Option<&DetectionPayload> {
        self.analysis.as_ref()?.payload.as_ref()
    }

    /// The message to show for an entry without a classification.
    pub fn error_message(&self) -> Option<&str> {
        self.error
            .as_deref()
            .or_else(|| self.analysis.as_ref()?.error.as_deref())
    }

    /// The path on disk, for a file the user added.
    pub fn path(&self) -> Option<&std::path::Path> {
        match &self.source {
            Source::File(path) => Some(path),
            Source::Memory(_) => None,
        }
    }

    /// The second line of a file-list row and the status bar's summary:
    /// `arm · 32-bit little · usb dfu file`, or the state while there is no
    /// classification.
    pub fn summary(&self) -> String {
        match self.payload() {
            Some(payload) => {
                let primary = &payload.primary;
                format!(
                    "{} · {}-bit {} · {}",
                    architecture_label(payload),
                    primary.bitwidth,
                    format::endianness_short(primary.endianness),
                    names::format_name(payload.format.format).to_lowercase(),
                )
            }
            None => match self.status {
                Status::Failed => self
                    .error_message()
                    .unwrap_or("classification failed")
                    .to_string(),
                status => status.label().to_string(),
            },
        }
    }
}

/// The compact architecture tag the browser shows: the ISA's JSON ID
/// without underscores (`aarch64`), `x86_64` as it is, and the lowercased
/// display name for a machine value without an ID.
pub fn architecture_id(isa: Isa) -> String {
    match isa {
        Isa::Unknown(_) => names::isa_name(isa).to_lowercase(),
        Isa::X86_64 => names::isa_id(isa),
        _ => names::isa_id(isa).replace('_', ""),
    }
}

/// The architecture tag of a whole payload: the distinct tags of its
/// slices joined with ` + ` when it has several, else the primary's.
pub fn architecture_label(payload: &DetectionPayload) -> String {
    if payload.slices.len() <= 1 {
        return architecture_id(payload.primary.isa);
    }
    let mut tags: Vec<String> = Vec::new();
    for slice in &payload.slices {
        let tag = architecture_id(slice.isa);
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags.join(" + ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_tags_drop_underscores_except_for_x86_64() {
        assert_eq!(architecture_id(Isa::AArch64), "aarch64");
        assert_eq!(architecture_id(Isa::X86_64), "x86_64");
        assert_eq!(architecture_id(Isa::Arm), "arm");
        assert_eq!(architecture_id(Isa::Unknown(0x2A)), "unknown (0x2a)");
    }

    #[test]
    fn status_words_and_glyphs() {
        assert_eq!(Status::Done.label(), "done");
        assert_eq!(Status::Failed.label(), "failed");
        assert_eq!(Status::Analyzing.glyph(), "[*]");
    }
}
