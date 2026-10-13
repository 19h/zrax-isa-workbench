//! Firmware package wrappers: `MikroTik` `RouterOS` packages (NPK), Ubiquiti
//! firmware images (`UBNT`, `OPEN` and `GEOS` headers with `PART` records)
//! and `ChromeOS` verified-boot kernel partitions (`CHROMEOS` keyblock, kernel
//! preamble, kernel blob).
//!
//! Primary sources (pins in `docs/fwpack.md`):
//! - `MikroTik` NPK: tenable/routeros at `c5d42403` (`ls_npk/src/main.cpp`,
//!   `modify_npk/src/main.cpp`), elseif/`MikroTikPatch` at `45e9c0a6`
//!   (`npk.py`: part IDs, package info, file container entries, digest and
//!   signature layout), kost/mikrotik-npk at `d54e97ca` (`unpacknpk.py`) and
//!   botlabsDev/npkpy at `cbfc8373` (`npkpy/npk/npk.py`, `cnt_basic.py`).
//! - Ubiquiti: `OpenWrt` firmware-utils at `a1d9589f` (`src/fw.h`,
//!   `src/mkfwimage.c`, `src/mkfwimage2.c`), `OpenWrt` v24.10.0
//!   `target/linux/ath79/image/common-ubnt.mk`, and binwalk v2.3.4
//!   `src/binwalk/magic/firmware` (the `UBNT`, `GEOS`, `EXEC` and `ENDS`
//!   records).
//! - `ChromeOS`: vboot (`vboot_reference`) at `8273cc58`:
//!   `firmware/2lib/include/2struct.h` (keyblock and kernel preamble),
//!   `firmware/2lib/2struct.c` (their validity checks),
//!   `firmware/2lib/2load_kernel.c` (body offset), `futility/vb1_helper.c`
//!   and `futility/cmd_vbutil_kernel.c` (kernel blob layout and `vmlinuz`
//!   reassembly).
//!
//! None of these wrappers names a CPU. NPK architecture strings, board
//! names, load addresses and vendor strings are not ISA evidence, so every
//! container leaves its target open and the ISA comes from the components:
//! NPK files and `SquashFS` images, Ubiquiti partitions and the `ChromeOS`
//! kernel and bootloader, each classified from its own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS};
use crate::types::FileFormat;
use std::fmt::Write;

mod npk;
mod ubnt;
mod vboot;

/// A firmware package layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `MikroTik` `RouterOS` package: `0xBAD0F11E`, a size, then typed parts.
    MikrotikNpk,
    /// Ubiquiti firmware image: a 268-byte header, `PART` records and an
    /// `END.` or `ENDS` record.
    UbiquitiFirmware,
    /// `ChromeOS` kernel partition: keyblock, kernel preamble and kernel
    /// blob.
    ChromeOsKernel,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::MikrotikNpk => FileFormat::MikrotikNpk,
            Self::UbiquitiFirmware => FileFormat::UbiquitiFw,
            Self::ChromeOsKernel => FileFormat::ChromeOsKernel,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::MikrotikNpk => "MikroTik NPK package",
            Self::UbiquitiFirmware => "Ubiquiti firmware image",
            Self::ChromeOsKernel => "ChromeOS kernel partition",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition: the NPK magic with a first part header of a
/// documented type that fits the declared size; a Ubiquiti header magic
/// at 0 with the `PART` magic of the first record at 268; or the
/// `CHROMEOS` keyblock magic with keyblock header version 2. A file with
/// one of them is reported as that format even when the rest is broken,
/// so a damaged package becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if npk::detect(data) {
        Some(Layout::MikrotikNpk)
    } else if ubnt::detect(data) {
        Some(Layout::UbiquitiFirmware)
    } else if vboot::detect(data) {
        Some(Layout::ChromeOsKernel)
    } else {
        None
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::FwPackParseError`] for a truncated or inconsistent
/// header, a part, record or range outside the file, a failed CRC-32 or
/// SHA-512 check, or data after the package that is not padding.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::MikrotikNpk => npk::parse(data),
        Layout::UbiquitiFirmware => ubnt::parse(data),
        Layout::ChromeOsKernel => vboot::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::FwPackParseError {
        message: message.into(),
    }
}

/// Bytes of a member that are probed for a recognized format before the
/// whole member is checked.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Most characters of untrusted text shown in a note or metadata value.
const MAX_TEXT: usize = 256;

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// The `N` bytes at `at` of a structure that was read whole before.
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "header field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, at)?))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, at)?))
}

fn le_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Accept only padding after a package that ends at `end`.
fn expect_padding(data: &[u8], end: usize, what: &str) -> Result<()> {
    let rest = data.get(end..).unwrap_or_default();
    if is_padding(rest) {
        return Ok(());
    }
    Err(error(format!(
        "Unexpected {} after the {what} at 0x{end:X}",
        size_text(rest.len())
    )))
}

/// The bytes of a fixed-size text field up to its first NUL.
fn until_nul(field: &[u8]) -> &[u8] {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..len]
}

/// Display form of untrusted text: printable ASCII as-is, other bytes as
/// `\xNN`, cut after [`MAX_TEXT`] bytes.
fn display_text(bytes: &[u8]) -> String {
    let mut text = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if i == MAX_TEXT {
            text.push_str("...");
            break;
        }
        if (0x20..0x7f).contains(&b) {
            text.push(char::from(b));
        } else {
            let _ = write!(text, "\\x{b:02X}");
        }
    }
    text
}

/// Whether `bytes` is printable ASCII text (spaces and tabs included).
fn is_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\t')
}

/// Most items one note or metadata value names; the rest are counted.
const MAX_LISTED: usize = 16;

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

/// Lists the recognized members of a package's file area as children and
/// counts what it examined and left out.
#[derive(Debug, Default)]
struct Members {
    /// Regular files checked for a recognized format.
    examined: usize,
    /// Members listed as children.
    listed: usize,
    /// Regular files not examined because [`MAX_COMPONENTS`] children were
    /// listed.
    unexamined: usize,
}

impl Members {
    /// List the member `label` with the decoded bytes `contents` when its
    /// first bytes, and then its whole contents, are a recognized format.
    /// The prefix check keeps unrecognized members from being copied and
    /// run through every detector in full. `offset` and `stored_size` are
    /// the stored stream the member was decoded from.
    fn offer(
        &mut self,
        c: &mut Container<'_>,
        member: DecodedMember<'_>,
        offset: usize,
        stored_size: usize,
        transform: &'static str,
    ) {
        if c.children.len() >= MAX_COMPONENTS {
            self.unexamined += 1;
            return;
        }
        self.examined += 1;
        let contents = member.contents;
        let prefix_len = contents.len().min(RECOGNITION_PREFIX);
        if !container::is_recognized(&contents[..prefix_len]) || !container::is_recognized(contents)
        {
            return;
        }
        c.children.push(
            Child::decoded(
                member.label,
                offset,
                stored_size,
                std::borrow::Cow::Owned(contents.to_vec()),
                transform,
            )
            .if_recognized(),
        );
        self.listed += 1;
    }

    /// Notes for what was examined and the listing limit.
    fn push_notes(&self, c: &mut Container<'_>) {
        if self.examined > 0 {
            c.notes.push(format!(
                "{} of {} are in a recognized format and listed",
                self.listed,
                counted(self.examined, "file", "files")
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "Member listing stopped at {MAX_COMPONENTS} components; {} not examined",
                counted(self.unexamined, "further file was", "further files were")
            ));
        }
    }
}

/// A file decoded from a package's file area.
#[derive(Debug)]
struct DecodedMember<'d> {
    /// Member path, for display.
    label: String,
    /// The member's decoded bytes.
    contents: &'d [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_escapes_and_truncates() {
        assert_eq!(display_text(b"a=b\n"), "a=b\\x0A");
        let long = vec![b'x'; MAX_TEXT + 10];
        assert_eq!(display_text(&long).len(), MAX_TEXT + 3);
        assert_eq!(until_nul(b"name\0junk"), b"name");
        assert_eq!(until_nul(b"full"), b"full");
    }

    #[test]
    fn padding_after_a_package_is_accepted_and_data_is_not() {
        assert!(expect_padding(&[1, 2, 0, 0xff], 2, "package").is_ok());
        assert!(expect_padding(&[1, 2], 5, "package").is_ok());
        let message = expect_padding(&[1, 2, 3], 1, "package")
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Firmware package parse error: Unexpected 2 B after the package at 0x1"
        );
    }

    #[test]
    fn long_lists_are_cut_and_counted() {
        let items: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        assert_eq!(bounded_list(&items[..2]), "0, 1");
        assert!(bounded_list(&items).ends_with(", 15 and 4 more"));
    }

    #[test]
    fn text_is_printable_ascii() {
        assert!(is_text(b"console=ttyS0 quiet\tro"));
        assert!(!is_text(b"bad\x01"));
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(2, "file", "files"), "2 files");
    }
}
