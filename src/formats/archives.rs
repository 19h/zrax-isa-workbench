//! Archive containers: ZIP, tar and CPIO.
//!
//! None of these formats names an ISA. Each regular-file member is a child
//! classified on its own bytes and listed only when it is a recognized
//! format, as `ar` members are.
//!
//! Sources:
//! - ZIP: PKWARE APPNOTE.TXT 6.3.10 (2022-11-01), sections 4.3-4.5 (records,
//!   flags, methods, extra fields, ZIP64), 5.8.8 (LZMA) and Appendix E (AE-x
//!   encryption); see the `zip` submodule.
//! - tar: POSIX.1-2024 `pax` ("ustar Interchange Format", "pax Interchange
//!   Format"), GNU tar 1.35 `src/tar.h`, `src/create.c` and `src/list.c`
//!   (long names, base-256 numbers), libarchive v3.7.4 `tar.5` and
//!   `archive_read_support_format_tar.c` (checksums, numeric fields); see
//!   the `tar` submodule.
//! - CPIO: libarchive v3.7.4 `cpio.5` and
//!   `archive_read_support_format_cpio.c`, POSIX.1-2024 `pax` ("cpio
//!   Interchange Format") and Linux v6.11 `init/initramfs.c`; see the `cpio`
//!   submodule.
//!
//! Member offsets and sizes are stored file coordinates; a decoded ZIP
//! member carries its decoded bytes and names its codec. A member is listed
//! only when its first `RECOGNITION_PREFIX` bytes, and then its whole
//! contents, are a recognized format. Listing stops at [`MAX_COMPONENTS`]
//! members and decoding at [`MAX_EXTRACTED`] bytes per archive (and
//! [`MAX_PAYLOAD`] per member); notes record what was left out.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::{checksum, MAX_PAYLOAD};
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt;

mod cpio;
mod tar;
mod zip;

/// Bytes at the start of a member that are checked for a recognized format
/// before the whole member is checked and listed.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Member names shown in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// Label of the child for recognized data after an archive's end.
const TRAILING_LABEL: &str = "Data after the archive";

/// An archive layout recognized by [`detect`] or [`detect_weak`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// ZIP archive that starts with a local file header, or with the end of
    /// central directory record when it has no entries.
    Zip,
    /// tar archive whose first header carries the POSIX `ustar\0` or the GNU
    /// `ustar  \0` magic at offset 257 and a valid header checksum.
    Tar,
    /// SVR4 CPIO without checksums (`070701`, "newc").
    CpioNewc,
    /// SVR4 CPIO with data checksums (`070702`, "crc").
    CpioCrc,
    /// POSIX portable ASCII CPIO (`070707`, "odc").
    CpioOdc,
    /// Old binary CPIO (`0x71C7`) in little-endian byte order.
    CpioBinaryLe,
    /// Old binary CPIO (`0x71C7`) in big-endian byte order.
    CpioBinaryBe,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Zip => FileFormat::Zip,
            Self::Tar => FileFormat::Tar,
            Self::CpioNewc
            | Self::CpioCrc
            | Self::CpioOdc
            | Self::CpioBinaryLe
            | Self::CpioBinaryBe => FileFormat::Cpio,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Zip => "ZIP archive",
            Self::Tar => "tar archive",
            Self::CpioNewc => "CPIO newc archive",
            Self::CpioCrc => "CPIO crc archive",
            Self::CpioOdc => "CPIO odc archive",
            Self::CpioBinaryLe => "CPIO binary archive (little-endian)",
            Self::CpioBinaryBe => "CPIO binary archive (big-endian)",
        }
    }

    /// Recognized from complete structure rather than a magic value: the
    /// old binary CPIO magic is two bytes.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::CpioBinaryLe | Self::CpioBinaryBe)
    }
}

/// Strong recognition: the ZIP local file header or end of central
/// directory signature at offset 0, the tar magic at offset 257 with a valid
/// header checksum, or an ASCII CPIO magic with a valid first header.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if zip::is_zip(data) {
        return Some(Layout::Zip);
    }
    if tar::is_tar(data) {
        return Some(Layout::Tar);
    }
    cpio::detect_ascii(data)
}

/// Weak recognition: an old binary CPIO archive whose every header up to
/// the `TRAILER!!!` entry is valid, followed only by padding, further CPIO
/// archives or a recognized format.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    cpio::detect_binary(data)
}

/// Parse an archive into the shared container model: one child per
/// regular-file member in a recognized format, in archive order.
///
/// # Errors
///
/// [`ClassifierError::ArchivesParseError`] for a truncated or inconsistent
/// header, directory or member range, or data after the archive that is
/// neither padding nor a recognized format.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Zip => zip::parse(data),
        Layout::Tar => tar::parse(data),
        Layout::CpioNewc
        | Layout::CpioCrc
        | Layout::CpioOdc
        | Layout::CpioBinaryLe
        | Layout::CpioBinaryBe => cpio::parse(data, layout),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ArchivesParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at file offset `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range at 0x{start:X}")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// Little-endian 16-bit field at `at`.
fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2, "archive field")?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

/// Little-endian 32-bit field at `at`.
fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4, "archive field")?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// Little-endian 64-bit field at `at`.
fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8, "archive field")?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// A fixed field of a fixed-size header record: offset and length in bytes.
#[derive(Debug, Clone, Copy)]
struct Field {
    offset: usize,
    len: usize,
}

impl Field {
    const fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    /// The field's bytes in `record`, which the caller has read at the
    /// record's full fixed size.
    fn bytes(self, record: &[u8]) -> &[u8] {
        &record[self.offset..self.offset + self.len]
    }
}

/// A number written as ASCII digits in `radix`: every byte a digit, no
/// sign or blanks. Empty fields and values beyond 64 bits are `None`.
fn ascii_number(field: &[u8], radix: u32) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    field.iter().try_fold(0u64, |value, &byte| {
        let digit = char::from(byte).to_digit(radix)?;
        value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))
    })
}

/// Round `value` up to a multiple of `alignment`, a power of two.
fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|value| value & !mask)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A member path for labels and notes. Names are bytes in these formats
/// (ZIP names without flag bit 11 are IBM CP437); invalid UTF-8 is shown
/// with replacement characters.
fn display_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// `n` followed by the singular or plural noun, for notes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Member names for a note: the first [`NOTE_NAMES`] are kept, the rest
/// only counted, so the list stays small for any archive.
#[derive(Debug, Default)]
struct NameList {
    shown: Vec<String>,
    total: usize,
}

impl NameList {
    fn push(&mut self, name: impl Into<String>) {
        if self.shown.len() < NOTE_NAMES {
            self.shown.push(name.into());
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

/// Lists an archive's recognized members as children, within the component
/// and extraction limits, and counts what it left out.
#[derive(Debug, Default)]
struct Members {
    /// Decoded bytes so far, counted against [`MAX_EXTRACTED`].
    decoded_size: usize,
    /// File members checked for a recognized format.
    examined: usize,
    /// Members listed as children.
    listed: usize,
    /// File members not examined because [`MAX_COMPONENTS`] were listed.
    unexamined: usize,
    /// Members not decoded because a limit would be exceeded.
    undecoded: NameList,
}

impl Members {
    /// Whether another member may be examined. Once [`MAX_COMPONENTS`]
    /// members are listed, the rest are counted instead of read or decoded.
    fn has_room(&mut self, c: &Container<'_>) -> bool {
        if c.children.len() < MAX_COMPONENTS {
            return true;
        }
        self.unexamined += 1;
        false
    }

    /// List `child` when its first bytes, and then its whole contents, are
    /// a recognized format. The prefix check keeps unrecognized members
    /// from being run through every detector in full.
    fn offer<'a>(&mut self, c: &mut Container<'a>, child: Child<'a>) {
        self.examined += 1;
        let prefix_len = child.data.len().min(RECOGNITION_PREFIX);
        if !container::is_recognized(&child.data[..prefix_len]) {
            return;
        }
        if !container::is_recognized(&child.data) {
            return;
        }
        c.children.push(child.if_recognized());
        self.listed += 1;
    }

    /// Reserve `size` decoded bytes for the member `name`. Returns false,
    /// and records the member as not decoded, when the member exceeds
    /// [`MAX_PAYLOAD`] or the archive would exceed [`MAX_EXTRACTED`].
    fn reserve(&mut self, name: &str, size: u64) -> bool {
        let total = usize::try_from(size)
            .ok()
            .filter(|size| *size <= MAX_PAYLOAD)
            .and_then(|size| self.decoded_size.checked_add(size))
            .filter(|total| *total <= MAX_EXTRACTED);
        let Some(total) = total else {
            self.undecoded.push(format!("{name} ({size} B)"));
            return false;
        };
        self.decoded_size = total;
        true
    }

    /// How many examined members were listed, and notes for the limits
    /// that were reached.
    fn push_notes(&self, c: &mut Container<'_>) {
        if self.examined > 0 {
            c.notes.push(format!(
                "{} of {} file members are in a recognized format and listed",
                self.listed, self.examined
            ));
        }
        if !self.undecoded.is_empty() {
            c.notes.push(format!(
                "Members over the extraction limits ({} MiB per member, {} MiB per archive) were \
                 not decoded or classified: {}",
                MAX_PAYLOAD >> 20,
                MAX_EXTRACTED >> 20,
                self.undecoded
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "Member listing stopped at {MAX_COMPONENTS} recognized members; {} not examined",
                count(
                    self.unexamined,
                    "further file member was",
                    "further file members were"
                )
            ));
        }
    }
}

/// Handle the bytes from `offset` to the end of the file, after an
/// archive's end marker: padding is accepted, a recognized format (a
/// further archive, a compressed archive as in Linux initramfs images) is
/// listed as a child, and anything else is an error.
fn push_trailing<'a>(
    data: &'a [u8],
    offset: usize,
    format_name: &str,
    c: &mut Container<'a>,
) -> Result<()> {
    let rest = data.get(offset..).unwrap_or_default();
    if is_padding(rest) {
        if !rest.is_empty() {
            c.notes
                .push(format!("{} B of padding after the archive", rest.len()));
        }
        return Ok(());
    }
    if !container::is_recognized(rest) {
        return Err(error(format!(
            "Unexpected data after the {format_name} archive at 0x{offset:X}"
        )));
    }
    c.notes.push(format!(
        "{} B after the archive at 0x{offset:X} are listed as a separate component",
        rest.len()
    ));
    c.children
        .push(Child::stored(TRAILING_LABEL, offset, rest).if_recognized());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_HEADER: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";

    #[test]
    fn layouts_report_their_format_and_strength() {
        assert_eq!(Layout::Zip.format(), FileFormat::Zip);
        assert_eq!(Layout::Tar.format(), FileFormat::Tar);
        assert_eq!(Layout::CpioOdc.format(), FileFormat::Cpio);
        assert!(Layout::CpioBinaryBe.is_weak());
        assert!(Layout::CpioBinaryLe.is_weak());
        assert!(!Layout::CpioNewc.is_weak());
        assert!(!Layout::Tar.is_weak());
        assert!(!Layout::Zip.is_weak());
    }

    #[test]
    fn ascii_numbers_need_every_byte_to_be_a_digit() {
        assert_eq!(ascii_number(b"0000ff0A", 16), Some(0xff0a));
        assert_eq!(ascii_number(b"0755", 8), Some(0o755));
        assert_eq!(ascii_number(b"0758", 8), None);
        assert_eq!(ascii_number(b"+123", 10), None);
        assert_eq!(ascii_number(b" 123", 10), None);
        assert_eq!(ascii_number(b"", 10), None);
        assert_eq!(ascii_number(b"18446744073709551615", 10), Some(u64::MAX));
        assert_eq!(ascii_number(b"18446744073709551616", 10), None);
        assert_eq!(align_up(121, 4), Some(124));
        assert_eq!(align_up(124, 4), Some(124));
        assert_eq!(align_up(usize::MAX, 2), None);
    }

    #[test]
    fn name_lists_count_the_names_they_leave_out() {
        let mut names = NameList::default();
        names.push("m0");
        names.push("m1");
        assert_eq!(names.to_string(), "m0, m1");
        for i in 2..10 {
            names.push(format!("m{i}"));
        }
        assert_eq!(names.total, 10);
        assert_eq!(names.shown.len(), NOTE_NAMES);
        assert_eq!(
            names.to_string(),
            "m0, m1, m2, m3, m4, m5, m6, m7 and 2 more"
        );
    }

    #[test]
    fn extraction_reservations_stop_at_the_limits() {
        let mut members = Members::default();
        let member = MAX_PAYLOAD as u64;
        assert!(members.reserve("a", member));
        assert!(!members.reserve("b", member + 1));
        assert!(members.reserve("c", member));
        assert!(members.reserve("d", member));
        assert!(members.reserve("e", member));
        assert!(!members.reserve("f", 1));
        assert_eq!(members.decoded_size, MAX_EXTRACTED);
        assert_eq!(members.undecoded.total, 2);
        assert!(members.undecoded.to_string().starts_with("b ("));
    }

    #[test]
    fn members_are_listed_only_when_recognized() {
        let text = b"plain text member";
        let mut c = Container::new(FileFormat::Tar, "test", "test");
        let mut members = Members::default();
        members.offer(&mut c, Child::stored("text", 0, text));
        members.offer(&mut c, Child::stored("elf", 512, ELF_HEADER));
        assert_eq!(c.children.len(), 1);
        assert_eq!(c.children[0].label, "elf");
        assert_eq!(c.children[0].offset, 512);
        assert_eq!(c.children[0].classify, container::Classify::IfRecognized);
        members.push_notes(&mut c);
        assert_eq!(
            c.notes,
            ["1 of 2 file members are in a recognized format and listed"]
        );
    }

    #[test]
    fn listing_stops_at_the_component_limit() {
        let mut c = Container::new(FileFormat::Tar, "test", "test");
        let mut members = Members::default();
        for i in 0..MAX_COMPONENTS + 3 {
            if members.has_room(&c) {
                members.offer(&mut c, Child::stored(format!("m{i}"), i, ELF_HEADER));
            }
        }
        assert_eq!(c.children.len(), MAX_COMPONENTS);
        assert_eq!(members.unexamined, 3);
        members.push_notes(&mut c);
        assert!(c.notes[1].contains("3 further file members were not examined"));
        assert_eq!(count(1, "entry", "entries"), "1 entry");
        assert_eq!(count(0, "entry", "entries"), "0 entries");
    }

    #[test]
    fn trailing_data_is_padding_a_recognized_child_or_an_error() {
        let padded = [0u8; 16];
        let mut c = Container::new(FileFormat::Tar, "test", "test");
        push_trailing(&padded, 8, "tar", &mut c).unwrap();
        assert!(c.children.is_empty());
        assert_eq!(c.notes, ["8 B of padding after the archive"]);

        let mut followed = padded.to_vec();
        followed.extend_from_slice(ELF_HEADER);
        let mut c = Container::new(FileFormat::Tar, "test", "test");
        push_trailing(&followed, 16, "tar", &mut c).unwrap();
        assert_eq!(c.children[0].label, TRAILING_LABEL);
        assert_eq!(c.children[0].offset, 16);

        let mut junk = followed.clone();
        junk.extend_from_slice(b"junk");
        let mut c = Container::new(FileFormat::Tar, "test", "test");
        let rejected = push_trailing(&junk, 32, "tar", &mut c).unwrap_err();
        assert!(rejected
            .to_string()
            .contains("Unexpected data after the tar archive at 0x20"));
    }
}
