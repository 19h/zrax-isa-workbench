//! ASAM PDX packages: ODX documents and their data files in one ZIP
//! archive. An ODX-F document's `EXTERN-FLASHDATA` element names its data
//! file by a `DATAFILE` path (odxtools 11.7.0 `externflashdata.py`); the
//! file is a member of the package. The ASAM schemas are not public, so
//! matching that path to a member name exactly, or else ignoring ASCII
//! case, is this module's reading of odxtools, not a published rule.

use super::*;
use crate::formats::automotive::{self, ExternalFlashData, FlashCoding};

/// A data file that one of the package's ODX documents names.
pub(super) struct DataFile {
    /// The ODX member that names the file.
    document: String,
    /// What the document says about the file.
    flash: ExternalFlashData,
}

impl DataFile {
    /// Does the member called `name` hold this data file?
    pub(super) fn is_named(&self, name: &str) -> bool {
        name == self.flash.file || name.eq_ignore_ascii_case(&self.flash.file)
    }
}

/// The data files the ODX members of a PDX-shaped archive name, at most
/// [`MAX_COMPONENTS`]. The documents are read with their own extraction
/// budget, and members that fail to decode are left for the member walk
/// to report.
pub(super) fn data_files(data: &[u8], entries: &[Entry<'_>], records: &[Local]) -> Vec<DataFile> {
    if !is_pdx(entries) {
        return Vec::new();
    }
    let mut members = Members::default();
    let mut tally = Tally::default();
    let mut files = Vec::new();
    for (entry, record) in entries.iter().zip(records) {
        if entry.is_directory() || entry.is_encrypted() || !is_odx_name(&entry.name) {
            continue;
        }
        let Some(contents) = verified_contents(data, entry, record, &mut members, &mut tally)
        else {
            continue;
        };
        let referenced = automotive::external_flash_data(&contents.data);
        files.extend(referenced.into_iter().map(|flash| DataFile {
            document: entry.name.clone(),
            flash,
        }));
        if files.len() >= MAX_COMPONENTS {
            files.truncate(MAX_COMPONENTS);
            break;
        }
    }
    files
}

/// What a data file's coding means for its member, as a note.
fn coding_text(coding: FlashCoding) -> &'static str {
    match coding {
        FlashCoding::Binary => "binary flash data, classified as code",
        FlashCoding::IntelHex => "Intel HEX records",
        FlashCoding::MotorolaS => "Motorola S-records",
        FlashCoding::Opaque => "encrypted, compressed or user-defined data; not analyzed",
    }
}

/// List the member `child`, which holds `file`, in the coding its document
/// states: binary data goes straight to the code model, hex records to
/// their own parsers, and encrypted, compressed or user-defined data stays
/// opaque. It is listed whether or not it is a recognized format.
pub(super) fn list_data_file<'a>(
    c: &mut Container<'a>,
    members: &mut Members,
    child: Child<'a>,
    file: &DataFile,
) {
    let child = match file.flash.coding {
        FlashCoding::Binary => child.as_code(),
        FlashCoding::IntelHex | FlashCoding::MotorolaS => child.if_recognized(),
        FlashCoding::Opaque => Child {
            opaque: true,
            ..child
        },
    };
    members.list(c, child);
}

/// One note per data file: the member that holds it and its coding, or
/// that no member of the package holds it.
pub(super) fn push_notes(c: &mut Container<'_>, files: &[DataFile], entries: &[Entry<'_>]) {
    for file in files {
        let member = entries
            .iter()
            .find(|entry| !entry.is_directory() && file.is_named(&entry.name));
        let note = match member {
            Some(entry) => format!(
                "{}: data file of {} in {}; {}",
                entry.name,
                file.flash.label,
                file.document,
                coding_text(file.flash.coding)
            ),
            None => format!(
                "{} in {}: data file {} is not in the package",
                file.flash.label, file.document, file.flash.file
            ),
        };
        c.notes.push(note);
    }
}
