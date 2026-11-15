//! One structured account of an input for a consumer that must decide how
//! its bytes are loaded: the classification or the reason there is none, how
//! much of the input the code model's reading explains, the boot marker a
//! raw image starts or ends with, and a container's members and load
//! sections with their file ranges and destination addresses.
//!
//! [`crate::detect_report`] builds it. The classification goes through the
//! decision path of [`crate::detect_payload`]; nothing here adds evidence.
//! The report carries, as fields, facts that the payload holds only as notes
//! and metadata strings, and keeps the candidates of an input the classifier
//! refuses.

use serde::Serialize;

use crate::error::{ClassifierError, Result};
use crate::formats::{
    self,
    container::{Container, Target, MAX_COMPONENTS},
    MAX_PAYLOAD,
};
use crate::heuristics;
use crate::inspection;
use crate::types::{DetectionPayload, Endianness, FileFormat, Isa, IsaCandidate};

/// Everything [`crate::detect_report`] establishes about one input.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionReport {
    /// The classification, or why there is none.
    pub outcome: Outcome,
    /// The code-model reading behind the outcome. `None` when a recognized
    /// format answered without the code model reading the input as a whole.
    pub reading: Option<CodeReading>,
    /// The boot marker of a raw image. Its presence does not depend on
    /// whether it changed the answer.
    pub boot_marker: Option<BootMarker>,
    /// Members and load sections, when the input is a container that parses.
    pub layout: Option<Layout>,
}

/// A classification or a refusal.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The payload [`crate::detect_payload`] returns for the same input.
    Decided(Box<DetectionPayload>),
    /// The classifier names no ISA.
    Abstained(Abstention),
}

/// Why an input has no classification, and what the code model saw.
#[derive(Debug, Clone, Serialize)]
pub struct Abstention {
    /// The kind of refusal.
    pub reason: AbstainReason,
    /// The classifier's error text.
    pub message: String,
    /// Ranked candidates of the stored bytes' reading, for raw input. Their
    /// `confidence` is a share of the evidence, not a probability, and none
    /// of them passed the decision rules.
    pub candidates: Vec<IsaCandidate>,
}

/// The kinds of refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstainReason {
    /// Fewer bytes than one model window needs.
    TooSmall,
    /// No family reaches the decision threshold.
    Inconclusive,
    /// A family leads, but too few windows of a large input hold its code.
    SparseCode,
    /// A recognized format does not parse, so nothing is read as raw code.
    Format,
}

impl AbstainReason {
    /// The reason an error of the classifier stands for.
    pub fn of(error: &ClassifierError) -> Self {
        match error {
            ClassifierError::FileTooSmall { .. } => Self::TooSmall,
            ClassifierError::HeuristicInconclusive { .. } => Self::Inconclusive,
            ClassifierError::HeuristicSparseCode { .. } => Self::SparseCode,
            _ => Self::Format,
        }
    }
}

/// How much of an input one code-model reading explains. Windows are the
/// model's 1 KiB scan windows of the bytes it read: the stored bytes, the
/// transformed bytes when `transform` is set, or a codec wrapper's decoded
/// bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CodeReading {
    /// Model family the reading favours. A family is named here even when
    /// the decision rules then refuse it.
    pub family: Option<&'static str>,
    /// Windows scanned that were not padding.
    pub informative_windows: usize,
    /// Code windows won by `family`.
    pub family_windows: usize,
    /// Code windows won by any family.
    pub code_windows: usize,
    /// Bytes in `family`'s code windows, as a share (0-1) of the informative
    /// bytes scanned.
    pub code_share: f64,
    /// Most bytes the scan scores, spread over the non-padding windows.
    pub budget: usize,
    /// Transform that put the stored bytes in execution order.
    pub transform: Option<String>,
    /// Readings of the input that were tried, the stored order included.
    pub trials: usize,
    /// Decided by the second, wider scan of an input whose code is sparse.
    pub rescanned: bool,
}

impl CodeReading {
    /// The account of `reading`, one of `trials` readings of the input.
    pub fn of(reading: &heuristics::Reading, trials: usize) -> Self {
        Self {
            family: reading.family,
            informative_windows: reading.informative_windows,
            family_windows: reading.code_windows,
            code_windows: reading.all_code_windows,
            code_share: reading.code_share,
            budget: reading.budget,
            transform: None,
            trials,
            rescanned: false,
        }
    }

    /// The same reading, made after `transform`.
    #[must_use]
    pub fn after(mut self, transform: String) -> Self {
        self.transform = Some(transform);
        self
    }

    /// The same reading, made by the wider scan of sparse code.
    #[must_use]
    pub fn rescanned(mut self) -> Self {
        self.rescanned = true;
        self
    }
}

/// The structures an architecture defines for the core that starts an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMarkerKind {
    /// A Cortex-M vector table at offset 0.
    CortexMVectorTable,
    /// An x86 reset vector 16 B below the end of a power-of-two image.
    X86ResetVector,
    /// An STM8 interrupt vector table at offset 0.
    Stm8VectorTable,
}

/// A boot marker found in a raw image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BootMarker {
    /// Which structure it is.
    pub kind: BootMarkerKind,
    /// The ISA of the core the structure belongs to.
    pub isa: Isa,
}

/// An architecture a format field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeclaredTarget {
    /// Architecture named by the format.
    pub isa: Isa,
    /// Register width in bits.
    pub bits: u8,
    /// Code byte order, when the format determines it.
    pub endianness: Option<Endianness>,
}

impl From<Target> for DeclaredTarget {
    fn from(target: Target) -> Self {
        Self {
            isa: target.isa,
            bits: target.bits,
            endianness: target.endianness,
        }
    }
}

/// What a container member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    /// An embedded image that is classified on its own.
    Child,
    /// Bytes the container loads into target memory.
    Section,
}

/// One member of a container. Offsets and stored sizes are bytes of the
/// input; `size` is what [`member_bytes`] returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    /// Position in the enumeration; the index [`member_bytes`] takes.
    pub index: usize,
    /// Child or load section.
    pub kind: MemberKind,
    /// Component role, section name or member path; untrusted text.
    pub label: String,
    /// File offset of the stored bytes.
    pub offset: u64,
    /// Stored size in the file, in bytes.
    pub stored_size: u64,
    /// Size of the extracted bytes, after any decoder.
    pub size: u64,
    /// Destination address of a load section, in the units the container's
    /// notes state (bytes unless stated).
    pub address: Option<u64>,
    /// Codec or transform that produced the extracted bytes.
    pub transform: Option<&'static str>,
    /// Ciphertext, configuration or metadata that is never read as code.
    pub opaque: bool,
    /// Architecture the container names for this member.
    pub target: Option<DeclaredTarget>,
    /// Whether [`member_bytes`] can return the member (at most 64 MiB).
    pub available: bool,
}

/// The members and load sections of a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// Reported file format.
    pub format: FileFormat,
    /// Layout name within the format.
    pub variant: String,
    /// Architecture the container itself names.
    pub target: Option<DeclaredTarget>,
    /// Entry point, in the units the container's notes state.
    pub entry: Option<u64>,
    /// The whole content is encrypted or metadata only.
    pub opaque: bool,
    /// Children in stream order, then load sections in stream order.
    pub members: Vec<Member>,
    /// Members beyond the enumeration limit, which are not listed.
    pub omitted: usize,
}

/// The container an input is, when its format has members or load sections.
fn container(data: &[u8]) -> Result<Option<Container<'_>>> {
    if let Some(found) = inspection::container(data)? {
        return Ok(Some(found));
    }
    let detected = formats::detect_format(data);
    formats::parse_container_model(data, &detected).transpose()
}

fn members(c: &Container<'_>) -> Vec<Member> {
    let children = c.children.iter().map(|child| Member {
        index: 0,
        kind: MemberKind::Child,
        label: child.label.clone(),
        offset: child.offset as u64,
        stored_size: child.stored_size as u64,
        size: child.data.len() as u64,
        address: None,
        transform: child.transform,
        opaque: c.opaque || child.opaque,
        target: child.target.map(DeclaredTarget::from),
        available: child.data.len() <= MAX_PAYLOAD,
    });
    let sections = c.sections.iter().map(|section| Member {
        index: 0,
        kind: MemberKind::Section,
        label: section.label.clone(),
        offset: section.offset as u64,
        stored_size: section.stored_size as u64,
        size: section.data.len() as u64,
        address: Some(section.address),
        transform: section.transform,
        opaque: c.opaque,
        target: None,
        available: section.data.len() <= MAX_PAYLOAD,
    });
    children
        .chain(sections)
        .enumerate()
        .map(|(index, member)| Member { index, ..member })
        .collect()
}

/// The layout of a container input: `None` for an input that is not a
/// container or whose structure does not parse.
pub fn layout(data: &[u8]) -> Option<Layout> {
    let c = container(data).ok()??;
    let mut listed = members(&c);
    let omitted = listed.len().saturating_sub(MAX_COMPONENTS);
    listed.truncate(MAX_COMPONENTS);
    Some(Layout {
        format: c.format,
        variant: c.variant.clone(),
        target: c.target.map(DeclaredTarget::from),
        entry: c.entry,
        opaque: c.opaque,
        members: listed,
        omitted,
    })
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::InspectionError {
        message: message.into(),
    }
}

/// The extracted bytes of one member, in their own coordinate system
/// starting at zero. `index` is a [`Member::index`] of [`layout`] for these
/// exact input bytes. Output is bounded to 64 MiB.
///
/// # Errors
///
/// The format's parse error, [`ClassifierError::InspectionError`] for an
/// input without members or an index outside them, or
/// [`ClassifierError::PayloadLimit`] for a member over the bound.
pub fn member_bytes(data: &[u8], index: usize) -> Result<Vec<u8>> {
    if index >= MAX_COMPONENTS {
        return Err(error("Invalid member index"));
    }
    let c = container(data)?.ok_or_else(|| error("Missing container members"))?;
    let child_count = c.children.len();
    let contents = if index < child_count {
        c.children.into_iter().nth(index).map(|child| child.data)
    } else {
        c.sections
            .into_iter()
            .nth(index - child_count)
            .map(|section| section.data)
    }
    .ok_or_else(|| error("Invalid member index"))?;
    if contents.len() > MAX_PAYLOAD {
        return Err(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD });
    }
    Ok(contents.into_owned())
}
