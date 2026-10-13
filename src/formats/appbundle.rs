//! Application bundles that package a program's files for a runtime:
//! `PyInstaller` archives (`CArchive`, also called PKG), Electron ASAR archives
//! and .NET single-file bundles.
//!
//! Primary sources (pins and file lists in `docs/appbundle.md`):
//! - `PyInstaller` v6.22.3 (`ecd7993d`): `bootloader/src/pyi_archive.h`
//!   (`ARCHIVE_COOKIE`, `TOC_ENTRY`, the `ARCHIVE_ITEM_*` type codes),
//!   `bootloader/src/pyi_archive.c` (`pyi_archive_open`, the back-to-front
//!   cookie search, zlib extraction), `PyInstaller/archive/readers.py`
//!   (`CArchiveReader`), `PyInstaller/archive/writers.py`
//!   (`CArchiveWriter`, `ZlibArchiveWriter`) and
//!   `PyInstaller/building/api.py` (`PKG`, `EXE.assemble`); v4.10 and v3.6
//!   `writers.py` for the Python version encoding.
//! - Electron asar v4.3.1 (`02c5b08e`): `README.md` ("Format"),
//!   `src/disk.ts` (`readArchiveHeaderSync`, `validateHeader`) and
//!   `src/pickle.ts`; Electron v38.0.0 (`79433861`)
//!   `shell/common/asar/archive.cc` (`Archive::Init`,
//!   `FillFileInfoWithNode`).
//! - .NET runtime v10.0.0 (`60629d14`):
//!   `src/native/corehost/apphost/bundle_marker.cpp`,
//!   `src/native/corehost/bundle/` (`header`, `file_entry`, `file_type`,
//!   `reader`, `manifest`) and
//!   `src/installer/managed/Microsoft.NET.HostModel/Bundle/` (`Bundler.cs`,
//!   `Manifest.cs`, `FileEntry.cs`, `TargetInfo.cs`).
//!
//! Integration. An ASAR archive is a file of its own and is recognized by
//! [`detect`] from its Pickle header and JSON tree. A `PyInstaller` archive is
//! recognized by [`detect`] only when the input is the archive itself: its
//! cookie ends the file and declares the file's size, as a build
//! directory's `PKG-00.pkg` or a side-loaded `.pkg` does. In an executable
//! the archive is appended, stored in an ELF section or followed by a code
//! signature, and a .NET bundle always lives in its apphost; there the
//! host's own format (ELF, PE, Mach-O) is detected first and stays the
//! input's format. [`detect_embedded`] finds those bundles inside a host and
//! [`parse_container`] parses them in file coordinates, so that the host's
//! result can list the members; `lib.rs` has no hook that does this yet.
//!
//! None of the three formats names a processor: the Python version and
//! library name, the Electron header and the .NET target framework are not
//! ISA evidence. Every container leaves its target open, and members (Python
//! extension modules and shared libraries, native Node modules, managed and
//! native assemblies) are classified from their own bytes. Python bytecode
//! has no ISA here and is listed as opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, size_text, Codec};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt::Write;

mod asar;
mod dotnet;
mod pyinstaller;

/// An application bundle layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `PyInstaller` `CArchive`: entry data, a table of contents and an 88-byte
    /// cookie that ends the archive.
    PyInstaller,
    /// Electron ASAR archive: a Pickle-framed JSON directory tree, then the
    /// file data.
    Asar,
    /// .NET single-file bundle: files appended to an apphost, a manifest
    /// after them, and the manifest's offset in the apphost's bundle marker.
    DotnetBundle,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::PyInstaller => FileFormat::PyInstaller,
            Self::Asar => FileFormat::Asar,
            Self::DotnetBundle => FileFormat::DotnetBundle,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::PyInstaller => "PyInstaller archive",
            Self::Asar => "Electron ASAR archive",
            Self::DotnetBundle => ".NET single-file bundle",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic or a fixed framing.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition of a standalone bundle file: a `PyInstaller` cookie
/// (`MEI\x0C\x0B\x0A\x0B\x0E`) in the last 88 bytes whose package length is
/// the input's length, or an ASAR size pickle (payload 4) whose header
/// pickle, string length and padding agree and whose JSON starts with the
/// root `files` object. A .NET bundle is never standalone; see
/// [`detect_embedded`].
pub fn detect(data: &[u8]) -> Option<Layout> {
    if pyinstaller::is_standalone(data) {
        Some(Layout::PyInstaller)
    } else if asar::detect(data) {
        Some(Layout::Asar)
    } else {
        None
    }
}

/// A bundle inside a host executable, for the host's classification to
/// list as members: a .NET bundle marker with a nonzero header offset and a
/// valid manifest header, or a `PyInstaller` cookie found by a back-to-front
/// search (as the bootloader finds it) whose archive starts after the
/// host's first byte and whose table of contents ends at the cookie.
/// [`detect_format`](crate::formats::detect_format) never returns these:
/// the host's own format is the input's format.
pub fn detect_embedded(data: &[u8]) -> Option<Layout> {
    if dotnet::detect(data) {
        Some(Layout::DotnetBundle)
    } else if pyinstaller::is_embedded(data) {
        Some(Layout::PyInstaller)
    } else {
        None
    }
}

/// Parse `data` as the given layout. Offsets of members are file offsets
/// in `data`, whether the bundle is the whole input or inside a host.
///
/// # Errors
///
/// [`ClassifierError::AppBundleParseError`] for a missing or truncated
/// cookie, header or manifest, an inconsistent size or count, a table of
/// contents or directory entry that is malformed, or a member range outside
/// the bundle.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::PyInstaller => pyinstaller::parse(data),
        Layout::Asar => asar::parse(data),
        Layout::DotnetBundle => dotnet::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AppBundleParseError {
        message: message.into(),
    }
}

/// Bytes of a member that are probed for a recognized format before the
/// whole member is checked or decoded.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Most bytes of an untrusted name shown in a label, note or metadata value.
const MAX_NAME: usize = 1024;

/// Most items one note names; the rest are counted.
const MAX_LISTED: usize = 16;

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// The `N` bytes at `at`.
fn array<const N: usize>(data: &[u8], at: usize, what: &str) -> Result<[u8; N]> {
    Ok(slice(data, at, N, what)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u32(data: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at, what)?))
}

fn le_u32(data: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at, what)?))
}

fn le_i32(data: &[u8], at: usize, what: &str) -> Result<i32> {
    Ok(i32::from_le_bytes(array(data, at, what)?))
}

fn le_u64(data: &[u8], at: usize, what: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at, what)?))
}

fn le_i64(data: &[u8], at: usize, what: &str) -> Result<i64> {
    Ok(i64::from_le_bytes(array(data, at, what)?))
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// The bytes of a fixed-size text field up to its first NUL.
fn until_nul(field: &[u8]) -> &[u8] {
    let len = memchr::memchr(0, field).unwrap_or(field.len());
    &field[..len]
}

/// Display form of an untrusted name: UTF-8 (invalid sequences replaced),
/// control characters as `\xNN`, cut after [`MAX_NAME`] bytes.
fn display_name(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(MAX_NAME)];
    let mut name = String::new();
    for ch in String::from_utf8_lossy(shown).chars() {
        if ch.is_control() {
            let _ = write!(name, "\\x{:02X}", u32::from(ch));
        } else {
            name.push(ch);
        }
    }
    if bytes.len() > MAX_NAME {
        name.push_str("...");
    }
    name
}

/// `items` joined with `, `: at most [`MAX_LISTED`], then how many more.
fn bounded_list(items: &[String]) -> String {
    let shown = items[..items.len().min(MAX_LISTED)].join(", ");
    match items.len().checked_sub(MAX_LISTED) {
        Some(more) if more > 0 => format!("{shown} and {more} more"),
        _ => shown,
    }
}

/// `n` with the singular or plural noun.
fn counted(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// How a member's bytes are stored in the bundle.
#[derive(Debug)]
enum Contents<'a> {
    /// As-is in the input.
    Stored(&'a [u8]),
    /// Compressed with `codec`; `size` is the declared decoded size.
    Compressed {
        stored: &'a [u8],
        codec: Codec,
        size: usize,
    },
    /// Decoded by the caller (who charged the extraction budget) from
    /// `stored_size` bytes with `codec`.
    Decoded {
        stored_size: usize,
        data: Vec<u8>,
        codec: Codec,
    },
}

/// How much of a member is probed before it is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recognition {
    /// The first [`RECOGNITION_PREFIX`] bytes, then the whole member.
    Prefix,
    /// Only the whole member: formats keyed at the end (a nested
    /// `PyInstaller` archive) are not recognized from a prefix.
    Whole,
}

/// A member offered for listing.
#[derive(Debug)]
struct Member<'a> {
    /// Member path, for display.
    label: String,
    /// File offset of the stored bytes.
    offset: usize,
    /// The stored or decoded bytes.
    contents: Contents<'a>,
    /// How the member is probed.
    recognition: Recognition,
}

/// Lists the members of a bundle that are in a recognized format as
/// children, within [`MAX_COMPONENTS`], [`MAX_PAYLOAD`] per member and
/// [`MAX_EXTRACTED`] decoded bytes in all, and counts what it left out.
#[derive(Debug, Default)]
struct Members {
    /// Members checked for a recognized format.
    examined: usize,
    /// Members listed as children.
    listed: usize,
    /// Members not examined because [`MAX_COMPONENTS`] children were listed.
    unexamined: usize,
    /// Compressed members larger than [`MAX_PAYLOAD`], not decoded.
    too_large: usize,
    /// Compressed members not decoded because [`MAX_EXTRACTED`] was reached.
    over_budget: usize,
    /// Members whose stored bytes did not decode to their declared size.
    failed: Vec<String>,
    /// Decoded bytes so far.
    extracted: usize,
}

impl Members {
    /// Whether another child fits; counts the member as unexamined if not.
    fn has_room(&mut self, c: &Container<'_>) -> bool {
        if c.children.len() < MAX_COMPONENTS {
            return true;
        }
        self.unexamined += 1;
        false
    }

    /// Reserve `size` decoded bytes for one member, or count it as left out.
    fn charge(&mut self, size: usize) -> bool {
        if size > MAX_PAYLOAD {
            self.too_large += 1;
            return false;
        }
        match self.extracted.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.extracted = total;
                true
            }
            _ => {
                self.over_budget += 1;
                false
            }
        }
    }

    /// List `member` when it is in a recognized format: its first bytes
    /// (unless only the whole member can tell) and then its whole contents.
    /// The prefix check keeps unrecognized members from being decoded and
    /// run through every detector in full.
    fn offer<'a>(&mut self, c: &mut Container<'a>, member: Member<'a>) {
        if !self.has_room(c) {
            return;
        }
        self.examined += 1;
        let Member {
            label,
            offset,
            contents,
            recognition,
        } = member;
        match contents {
            Contents::Stored(bytes) => {
                if !is_listed(bytes, recognition) {
                    return;
                }
                c.children
                    .push(Child::stored(label, offset, bytes).if_recognized());
            }
            Contents::Compressed {
                stored,
                codec,
                size,
            } => {
                if recognition == Recognition::Prefix
                    && !self.prefix_is_recognized(&label, stored, codec, size)
                {
                    return;
                }
                if !self.charge(size) {
                    return;
                }
                let Some(data) = self.decode(&label, stored, codec, size) else {
                    return;
                };
                if !container::is_recognized(&data) {
                    return;
                }
                c.children.push(
                    Child::decoded(label, offset, stored.len(), Cow::Owned(data), codec.name())
                        .if_recognized(),
                );
            }
            Contents::Decoded {
                stored_size,
                data,
                codec,
            } => {
                if !is_listed(&data, recognition) {
                    return;
                }
                c.children.push(
                    Child::decoded(label, offset, stored_size, Cow::Owned(data), codec.name())
                        .if_recognized(),
                );
            }
        }
        self.listed += 1;
    }

    /// Whether the first decoded bytes of a compressed member are a
    /// recognized format. A stream that fails within the prefix counts as
    /// failed.
    fn prefix_is_recognized(
        &mut self,
        label: &str,
        stored: &[u8],
        codec: Codec,
        size: usize,
    ) -> bool {
        let limit = size.min(RECOGNITION_PREFIX);
        let Ok(prefix) = compressed::decode_prefix(codec, stored, limit) else {
            self.failed.push(label.to_string());
            return false;
        };
        container::is_recognized(&prefix[..prefix.len().min(limit)])
    }

    /// Decode a member whose decoded size is declared; a stream that fails
    /// or decodes to another size counts as failed.
    fn decode(&mut self, label: &str, stored: &[u8], codec: Codec, size: usize) -> Option<Vec<u8>> {
        match compressed::decode_limited(codec, stored, size) {
            Ok(decoded) if decoded.data.len() == size => Some(decoded.data),
            _ => {
                self.failed.push(label.to_string());
                None
            }
        }
    }

    /// Notes for what was examined and left out; `singular` and `plural`
    /// name the members.
    fn push_notes(&self, c: &mut Container<'_>, singular: &str, plural: &str) {
        if self.examined > 0 {
            let verb = if self.examined == 1 { "is" } else { "are" };
            c.notes.push(format!(
                "{} of {} {verb} in a recognized format and listed",
                self.listed,
                counted(self.examined, singular, plural)
            ));
        }
        if !self.failed.is_empty() {
            c.notes.push(format!(
                "{} did not decode to the declared size: {}",
                counted(self.failed.len(), singular, plural),
                bounded_list(&self.failed)
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} larger than {} not decoded",
                counted(self.too_large, singular, plural),
                size_text(MAX_PAYLOAD)
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "Extraction stopped at {} decoded; {} not decoded",
                size_text(MAX_EXTRACTED),
                counted(self.over_budget, singular, plural)
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "Member listing stopped at {MAX_COMPONENTS} components; {} not examined",
                counted(self.unexamined, singular, plural)
            ));
        }
    }
}

/// Whether member bytes are a recognized format, probed as `recognition`
/// says.
fn is_listed(bytes: &[u8], recognition: Recognition) -> bool {
    let prefix_ok = recognition == Recognition::Whole
        || container::is_recognized(&bytes[..bytes.len().min(RECOGNITION_PREFIX)]);
    prefix_ok && container::is_recognized(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_shown_as_utf8_with_controls_escaped_and_cut() {
        assert_eq!(display_name("lib/ü.so".as_bytes()), "lib/ü.so");
        assert_eq!(display_name(b"a\nb\x00"), "a\\x0Ab\\x00");
        assert_eq!(display_name(b"\xff"), "\u{fffd}");
        let long = vec![b'x'; MAX_NAME + 5];
        assert_eq!(display_name(&long).len(), MAX_NAME + 3);
        assert_eq!(until_nul(b"name\0pad"), b"name");
        assert_eq!(until_nul(b"full"), b"full");
    }

    #[test]
    fn long_lists_are_cut_and_counted() {
        let items: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        assert_eq!(bounded_list(&items[..2]), "0, 1");
        assert!(bounded_list(&items).ends_with(", 15 and 4 more"));
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(3, "file", "files"), "3 files");
    }

    #[test]
    fn ranges_report_truncation_and_overflow() {
        let data = [0u8; 8];
        assert_eq!(slice(&data, 2, 4, "field").unwrap(), &[0; 4]);
        assert_eq!(
            slice(&data, 6, 4, "field").unwrap_err().to_string(),
            "Application bundle parse error: Truncated field at 0x6 + 4 B"
        );
        assert_eq!(
            slice(&data, usize::MAX, 2, "field")
                .unwrap_err()
                .to_string(),
            format!(
                "Application bundle parse error: Invalid field range 0x{:X} + 2 B",
                usize::MAX
            )
        );
    }

    #[test]
    fn the_extraction_budget_counts_large_and_late_members() {
        let mut members = Members::default();
        assert!(!members.charge(MAX_PAYLOAD + 1));
        assert_eq!(members.too_large, 1);
        members.extracted = MAX_EXTRACTED - 10;
        assert!(members.charge(10));
        assert!(!members.charge(1));
        assert_eq!(members.over_budget, 1);
    }
}
