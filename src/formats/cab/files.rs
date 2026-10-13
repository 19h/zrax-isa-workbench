//! The files of a cabinet as children: each file whose bytes this cabinet
//! holds is cut from its folder's uncompressed bytes and listed, labeled by
//! its name, when it is a recognized format.
//!
//! Folders are decoded in folder order, each at most as far as its last
//! extractable file and at most [`MAX_PAYLOAD`] bytes, until
//! [`MAX_EXTRACTED`] bytes are decoded for the cabinet; listing stops at
//! [`MAX_COMPONENTS`] children. Files that continue into another cabinet,
//! files of a folder that began in the previous cabinet, and files that a
//! limit leaves out are named in notes.

use super::folder::{self, Chain, Contents};
use super::header::{Continuation, FileEntry, Folder, FolderIndex, ATTRIBUTE_EXEC};
use super::*;
use crate::formats::container::{MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::fmt;

/// Bytes at the start of a file that are checked for a recognized format
/// before the whole file is checked and listed.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// File names shown in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// File names for a note: the first [`NOTE_NAMES`] are kept, the rest only
/// counted, so the note stays small for any cabinet.
#[derive(Debug, Default)]
struct NameList {
    shown: Vec<String>,
    total: usize,
}

impl NameList {
    fn push(&mut self, name: &str) {
        if self.shown.len() < NOTE_NAMES {
            self.shown.push(format!("`{name}`"));
        }
        self.total += 1;
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl fmt::Display for NameList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.shown.join(", "))?;
        let hidden = self.total - self.shown.len();
        if hidden > 0 {
            write!(f, " and {hidden} more")?;
        }
        Ok(())
    }
}

/// What the listing found and what it left out.
#[derive(Debug, Default)]
struct Census {
    /// Files read and checked for a recognized format.
    examined: usize,
    /// Files listed as children.
    listed: usize,
    /// Files of 0 B.
    empty: usize,
    /// Decoded bytes so far, counted against [`MAX_EXTRACTED`].
    extracted: usize,
    /// Files that begin in the previous cabinet or continue in the next.
    from_previous: NameList,
    to_next: NameList,
    /// Files of a folder that began in the previous cabinet.
    in_continued_folder: NameList,
    /// Files whose range ends past their folder's data in this cabinet.
    past_folder: NameList,
    /// Files that a limit kept from being decoded.
    over_limit: NameList,
    /// Files not examined because [`MAX_COMPONENTS`] were listed.
    unexamined: usize,
    /// Notes for folders whose files were not extracted.
    failures: Vec<String>,
    /// Files marked to run after extraction (`_A_EXEC`).
    run_after_extraction: NameList,
    /// Names in an unknown code page.
    code_page_names: usize,
}

/// List the cabinet's files in folder order, then table order.
pub(super) fn list<'a>(
    header: &Header<'_>,
    folders: &[Folder],
    chains: &[Chain<'a>],
    entries: &[FileEntry],
    continuation: &Continuation,
    c: &mut Container<'a>,
) {
    let mut census = Census::default();
    for entry in entries {
        if entry.attributes & ATTRIBUTE_EXEC != 0 {
            census.run_after_extraction.push(&entry.name);
        }
        if entry.name_in_code_page {
            census.code_page_names += 1;
        }
        if matches!(
            entry.folder,
            FolderIndex::FromPrevious | FolderIndex::PreviousAndNext
        ) {
            census.from_previous.push(&entry.name);
        }
        if matches!(
            entry.folder,
            FolderIndex::ToNext | FolderIndex::PreviousAndNext
        ) {
            census.to_next.push(&entry.name);
        }
    }
    // Each file's folder index was checked against the folder count.
    let mut members: Vec<Vec<&FileEntry>> = vec![Vec::new(); folders.len()];
    for entry in entries {
        if let FolderIndex::Folder(index) = entry.folder {
            if let Some(folder) = members.get_mut(index) {
                folder.push(entry);
            }
        }
    }
    for (index, ((folder, chain), members)) in folders.iter().zip(chains).zip(&members).enumerate()
    {
        list_folder(index, folder, chain, members, continuation, &mut census, c);
    }
    census.report(header, c);
}

/// List the files of one folder.
fn list_folder<'a>(
    index: usize,
    folder: &Folder,
    chain: &Chain<'a>,
    members: &[&FileEntry],
    continuation: &Continuation,
    census: &mut Census,
    c: &mut Container<'a>,
) {
    let mut extractable = Vec::new();
    for &entry in members {
        if entry.size == 0 {
            census.empty += 1;
        } else if continuation.starts_before(index) {
            census.in_continued_folder.push(&entry.name);
        } else if entry.end() > chain.uncompressed {
            census.past_folder.push(&entry.name);
        } else if entry.size > MAX_PAYLOAD {
            census.over_limit.push(&entry.name);
        } else {
            extractable.push(entry);
        }
    }
    let Some(wanted) = extractable.iter().map(|entry| entry.end()).max() else {
        return;
    };
    let budget = MAX_EXTRACTED.saturating_sub(census.extracted);
    let contents = match folder::decode(folder, chain, wanted.min(MAX_PAYLOAD).min(budget)) {
        Ok(contents) => contents,
        Err(problem) => {
            census.failures.push(format!(
                "Folder {index} ({}): {problem}; {} not extracted",
                folder.compression,
                count(extractable.len(), "file was", "files were")
            ));
            return;
        }
    };
    if let Contents::Decoded { data, .. } = &contents {
        census.extracted += data.len();
    }
    for entry in extractable {
        if c.children.len() >= MAX_COMPONENTS {
            census.unexamined += 1;
            continue;
        }
        let start = entry.folder_offset;
        let end = entry.end();
        let child = match &contents {
            Contents::Decoded { data, transform } => {
                let Some(bytes) = data.get(start..end) else {
                    census.over_limit.push(&entry.name);
                    continue;
                };
                census.examined += 1;
                if !is_recognized(bytes) {
                    continue;
                }
                let extent = chain.extent(start, end);
                Child::decoded(
                    entry.name.clone(),
                    extent.offset,
                    extent.size,
                    Cow::Owned(bytes.to_vec()),
                    transform,
                )
            }
            Contents::Stored => {
                let prefix = chain.stored_bytes(start, end.min(start + RECOGNITION_PREFIX));
                census.examined += 1;
                if !container::is_recognized(&prefix.bytes) {
                    continue;
                }
                let stored = chain.stored_bytes(start, end);
                if let Cow::Owned(bytes) = &stored.bytes {
                    if census.extracted + bytes.len() > MAX_EXTRACTED {
                        census.over_limit.push(&entry.name);
                        continue;
                    }
                    census.extracted += bytes.len();
                }
                if !container::is_recognized(&stored.bytes) {
                    continue;
                }
                stored.into_child(entry.name.clone())
            }
        };
        c.children.push(child.if_recognized());
        census.listed += 1;
    }
}

/// Whether the first bytes, and then all of them, are a recognized format.
/// The prefix check keeps unrecognized files from going through every
/// detector in full.
fn is_recognized(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
    container::is_recognized(prefix) && container::is_recognized(bytes)
}

impl Census {
    fn report(self, header: &Header<'_>, c: &mut Container<'_>) {
        c.notes.push(format!(
            "{} of {} examined {} in a recognized format and listed",
            self.listed,
            self.examined,
            if self.examined == 1 {
                "file is"
            } else {
                "files are"
            }
        ));
        if self.empty > 0 {
            c.notes.push(format!(
                "{} not examined",
                count(self.empty, "empty file is", "empty files are")
            ));
        }
        if !self.from_previous.is_empty() {
            let previous = header
                .previous
                .as_ref()
                .map_or_else(String::new, |n| format!(" `{}`", n.cabinet));
            c.notes.push(format!(
                "Files that begin in the previous cabinet{previous} are not joined: {}",
                self.from_previous
            ));
        }
        if !self.to_next.is_empty() {
            let next = header
                .next
                .as_ref()
                .map_or_else(String::new, |n| format!(" `{}`", n.cabinet));
            c.notes.push(format!(
                "Files that continue in the next cabinet{next} are not joined: {}",
                self.to_next
            ));
        }
        if !self.in_continued_folder.is_empty() {
            c.notes.push(format!(
                "Folder 0 began in the previous cabinet, so its files were not extracted: {}",
                self.in_continued_folder
            ));
        }
        if !self.past_folder.is_empty() {
            c.notes.push(format!(
                "Files that extend past their folder's data were not extracted: {}",
                self.past_folder
            ));
        }
        c.notes.extend(self.failures);
        if !self.over_limit.is_empty() {
            c.notes.push(format!(
                "Files over the extraction limits ({} MiB per folder or file, {} MiB per cabinet) \
                 were not decoded or classified: {}",
                MAX_PAYLOAD >> 20,
                MAX_EXTRACTED >> 20,
                self.over_limit
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "File listing stopped at {MAX_COMPONENTS} files; {} not examined",
                count(self.unexamined, "further file was", "further files were")
            ));
        }
        if !self.run_after_extraction.is_empty() {
            c.notes.push(format!(
                "Files marked to run after extraction (_A_EXEC): {}",
                self.run_after_extraction
            ));
        }
        if self.code_page_names > 0 {
            c.notes.push(format!(
                "{} in an unspecified code page (no _A_NAME_IS_UTF); bytes that are not UTF-8 are \
                 shown as replacement characters",
                count(self.code_page_names, "file name is", "file names are")
            ));
        }
        c.push_metadata("cab_files_listed", "Files listed", self.listed as u64);
        c.push_metadata(
            "cab_decoded_size",
            "Decoded folder bytes (B)",
            self.extracted as u64,
        );
    }
}
