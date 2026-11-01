//! Container member inspection using the same validated byte extraction as
//! classification. Stored coordinates describe the parent; extracted bytes
//! form a new file with their own coordinate system starting at zero.

use crate::error::{ClassifierError, Result};
use crate::formats::{
    self,
    container::{Child, Container, MAX_COMPONENTS},
    DetectedFormat, MAX_PAYLOAD,
};
use crate::types::FileFormat;
use serde::Serialize;

mod regions;

pub use regions::{enclosing, regions, Region, RegionKind};

/// A member available for opening in an independent workbench.
#[derive(Debug, Serialize)]
pub struct Subfile {
    /// Stable index within the current input's member enumeration.
    pub index: usize,
    /// Component role or archive path; untrusted text.
    pub label: String,
    /// Byte offset of the stored data in the immediate parent file.
    pub offset: usize,
    /// Byte size in the immediate parent file.
    pub stored_size: usize,
    /// Extracted byte size after any decoder transform.
    pub size: usize,
    /// Transform already applied to the extracted data.
    pub transform: Option<&'static str>,
    /// Ciphertext, configuration or metadata: inspect bytes without ISA analysis.
    pub opaque: bool,
    /// Whether extraction fits the per-member inspection limit.
    pub available: bool,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::InspectionError {
        message: message.into(),
    }
}

fn container(data: &[u8]) -> Result<Option<Container<'_>>> {
    match formats::detect_format(data) {
        DetectedFormat::Container {
            kind: formats::container::Kind::Archive(layout),
        } => formats::archives::inspect_container(data, layout).map(Some),
        DetectedFormat::Container { kind } => formats::container::parse(data, kind).map(Some),
        DetectedFormat::Ar { .. } => {
            let mut c = Container::new(FileFormat::Archive, "ar archive", "ar");
            for member in formats::ar::parse_members(data)?
                .into_iter()
                .take(MAX_COMPONENTS)
            {
                c.children
                    .push(Child::stored(member.name, member.offset, member.data));
            }
            Ok(Some(c))
        }
        _ => Ok(None),
    }
}

/// List extracted children followed by load sections. A non-container has
/// no subfiles. Opaque components are listed for byte inspection only.
///
/// # Errors
///
/// The detected format's parse error when its structure is invalid.
pub fn subfiles(data: &[u8]) -> Result<Vec<Subfile>> {
    let Some(c) = container(data)? else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for child in &c.children {
        files.push(Subfile {
            index: files.len(),
            label: child.label.clone(),
            offset: child.offset,
            stored_size: child.stored_size,
            size: child.data.len(),
            transform: child.transform,
            opaque: c.opaque || child.opaque,
            available: child.data.len() <= MAX_PAYLOAD,
        });
    }
    for section in &c.sections {
        files.push(Subfile {
            index: files.len(),
            label: section.label.clone(),
            offset: section.offset,
            stored_size: section.stored_size,
            size: section.data.len(),
            transform: section.transform,
            opaque: c.opaque,
            available: section.data.len() <= MAX_PAYLOAD,
        });
    }
    files.truncate(MAX_COMPONENTS);
    Ok(files)
}

/// Extract one member's decoded bytes, independently of its parent offsets.
/// The index is the one returned by [`subfiles`] for these exact input bytes.
/// Output is bounded to 64 MiB. Parsing and decoding use their existing
/// container limits; no parent memory gaps are materialized.
///
/// # Errors
///
/// A format parse error, [`ClassifierError::InspectionError`] for a missing
/// member, or [`ClassifierError::PayloadLimit`] for oversized output.
pub fn extract_subfile(data: &[u8], index: usize) -> Result<Vec<u8>> {
    if index >= MAX_COMPONENTS {
        return Err(error("Invalid subfile index"));
    }
    let c = container(data)?.ok_or_else(|| error("Missing container subfiles"))?;
    let contents = if index < c.children.len() {
        c.children.into_iter().nth(index).map(|child| child.data)
    } else {
        c.sections
            .into_iter()
            .nth(index - c.children.len())
            .map(|section| section.data)
    }
    .ok_or_else(|| error("Invalid subfile index"))?;
    if contents.len() > MAX_PAYLOAD {
        return Err(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD });
    }
    Ok(contents.into_owned())
}
