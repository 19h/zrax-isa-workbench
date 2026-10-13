//! PC platform firmware blobs: Intel microcode updates, AMD microcode
//! containers, Intel ME/CSME flash partition tables (`$FPT`) and code
//! partition directories (`$CPD`) with their manifests, and AMD flash images
//! (the Embedded Firmware Structure and the PSP and BIOS directories it
//! leads to).
//!
//! Sources, pinned to the revisions that were read (see `docs/pcfw.md`):
//! - Intel SDM Vol. 3A, order 253668-093US (September 2026), section 12.11
//!   "Microcode Update Facilities", Tables 12-7 to 12-10; Linux v6.12
//!   `arch/x86/kernel/cpu/microcode/intel.c` and
//!   `arch/x86/include/asm/microcode.h`.
//! - Linux v6.12 `arch/x86/kernel/cpu/microcode/amd.c` (container magic,
//!   equivalence table and patch sections).
//! - coreboot 25.09 (commit `07df08836eca`): `util/cbfstool/cse_fpt.c`,
//!   `fpt_formats/fpt_hdr_20.c`, `fpt_formats/fpt_hdr_21.c`, `ifwitool.c`,
//!   `bpdt_formats/subpart_hdr_1.c`, `subpart_hdr_2.c`, `subpart_entry_1.c`
//!   and the vendored `util/me_cleaner/me_cleaner.py`; `util/amdfwtool/`
//!   `amdfwtool.h`, `amdfwtool.c` and `amdfwread.c`.
//! - Community tools where coreboot leaves a field open: `UEFITool` A75
//!   (commit `19a4dab71f1f`) `common/me.h` and `common/meparser.cpp`, and
//!   `MEAnalyzer` `MEA.py` (commit `d27ccdba0aad`) for the coverage of the
//!   `$FPT` 2.1 and `$CPD` 2 CRC-32 fields.
//!
//! No Intel ME/CSME document and no AMD PSP document was read.
//!
//! Every structure is little-endian. None of these blobs is code for an ISA
//! the classifier models: microcode updates are encrypted data for the
//! processor's own update loader, and the ME partitions and PSP directory
//! entries are firmware for separate engines that these structures do not
//! identify. Every layout therefore reports an unknown ISA, and every
//! component is opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{Child, Container, Kind, MAX_COMPONENTS};
use crate::formats::{detect_format, DetectedFormat};
use crate::types::FileFormat;

mod amd_microcode;
mod cpd;
mod fpt;
mod intel_microcode;
mod psp;

/// Prefix of the generated and format-specific metadata keys.
const KEY_PREFIX: &str = "pcfw";

/// Most per-structure detail notes (updates, patches, partitions,
/// directories) one container records; the rest are counted.
const MAX_DETAIL_NOTES: usize = 64;

/// Most names listed in one note (module names, processor signatures).
const MAX_LISTED_NAMES: usize = 32;

/// A recognized PC firmware layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// One or more Intel microcode updates back to back. The update has no
    /// magic, so it is recognized only when every update validates.
    IntelMicrocode,
    /// One or more AMD microcode containers (magic `DMA\0`).
    AmdMicrocode,
    /// An Intel ME/CSME region or image whose flash partition table
    /// (`$FPT`) is at 0x10, after a ROM bypass vector, or at 0.
    IntelFpt,
    /// A standalone ME code partition: a code partition directory (`$CPD`)
    /// at offset 0.
    IntelCpd,
    /// An AMD flash image whose Embedded Firmware Structure is at one of
    /// the offsets `amdfwread` searches. Recognized only when the structure
    /// and every directory it leads to validate.
    AmdEfs {
        /// File offset of the Embedded Firmware Structure.
        offset: usize,
    },
    /// A standalone PSP, BIOS or combo directory table at offset 0.
    AmdDirectory,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::IntelMicrocode => FileFormat::IntelMicrocode,
            Self::AmdMicrocode => FileFormat::AmdMicrocode,
            Self::IntelFpt | Self::IntelCpd => FileFormat::IntelMe,
            Self::AmdEfs { .. } | Self::AmdDirectory => FileFormat::AmdPsp,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::IntelMicrocode => "Intel microcode update",
            Self::AmdMicrocode => "AMD microcode container",
            Self::IntelFpt => "Intel ME flash partition table",
            Self::IntelCpd => "Intel ME code partition directory",
            Self::AmdEfs { .. } => "AMD flash image (Embedded Firmware Structure)",
            Self::AmdDirectory => "AMD PSP/BIOS directory table",
        }
    }

    /// Intel microcode has no magic and the EFS signature only matters with
    /// the directories it leads to, so both are recognized from complete
    /// structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::IntelMicrocode | Self::AmdEfs { .. })
    }
}

/// Strong recognition: the AMD microcode container magic at 0, `$FPT` at
/// 0x10 or 0, `$CPD` at 0, or a PSP, BIOS or combo directory cookie at 0. A
/// file recognized here and damaged later is a parse error, not raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if amd_microcode::has_magic(data) {
        Some(Layout::AmdMicrocode)
    } else if fpt::marker_offset(data).is_some() {
        Some(Layout::IntelFpt)
    } else if cpd::has_marker(data) {
        Some(Layout::IntelCpd)
    } else if psp::is_directory(data) {
        Some(Layout::AmdDirectory)
    } else {
        None
    }
}

/// Weak recognition: a file of Intel microcode updates in which every
/// update validates (header version 1, loader revision 1, a BCD date,
/// consistent sizes, zero checksums), or an Embedded Firmware Structure at
/// a documented offset that leads to at least one directory, with every
/// directory reached valid (cookie, entry table, Fletcher-32 checksum).
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    if intel_microcode::is_valid(data) {
        return Some(Layout::IntelMicrocode);
    }
    psp::find_efs(data).map(|offset| Layout::AmdEfs { offset })
}

/// Whether `data`, the contents of an Intel flash descriptor's ME region,
/// is a flash partition table that [`detect_format`] reports as Intel ME,
/// so the region can be classified as that container (whose partitions are
/// all opaque) instead of being left opaque as a whole.
pub fn is_me_partition_table(data: &[u8]) -> bool {
    fpt::marker_offset(data).is_some()
        && matches!(
            detect_format(data),
            DetectedFormat::Container {
                kind: Kind::PcFw(Layout::IntelFpt)
            }
        )
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::PcFirmwareParseError`] for a truncated or
/// inconsistent header, table or directory, or a checksum that does not
/// match where the format requires it to.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::IntelMicrocode => intel_microcode::parse(data),
        Layout::AmdMicrocode => amd_microcode::parse(data),
        Layout::IntelFpt => fpt::parse(data),
        Layout::IntelCpd => cpd::parse(data),
        Layout::AmdEfs { offset } => psp::parse_efs(data, offset),
        Layout::AmdDirectory => psp::parse_directory(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::PcFirmwareParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`, or a truncation error naming `what`.
fn field<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X}: {len} B required")))
}

/// `N` bytes at `at`; callers read fields of structures whose size
/// [`field`] has already checked.
fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    let bytes = field(data, at, N, "field")?;
    Ok(bytes.try_into().expect("field returns exactly N bytes"))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    array(data, at).map(u16::from_le_bytes)
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    array(data, at).map(u32::from_le_bytes)
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    array(data, at).map(u64::from_le_bytes)
}

/// A 32-bit size or offset field as `usize`.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds 32 bits on every supported target")
}

/// Erased flash (`0xFF`) or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xFF))
}

/// 8-bit sum with carries dropped.
fn sum8(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

/// A fixed-size name field: the bytes before the first NUL, with bytes
/// outside printable ASCII shown as `?`.
fn ascii_name(bytes: &[u8]) -> String {
    let name: String = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    if name.is_empty() {
        "(unnamed)".to_string()
    } else {
        name
    }
}

/// `"1 entry"`, `"2 entries"`.
fn plural(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// At most [`MAX_LISTED_NAMES`] items joined with `, `, and how many more
/// there are.
fn listed(items: &[String]) -> String {
    let shown = items
        .iter()
        .take(MAX_LISTED_NAMES)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > MAX_LISTED_NAMES {
        format!("{shown} and {} more", items.len() - MAX_LISTED_NAMES)
    } else {
        shown
    }
}

/// What one container has listed so far: children against
/// [`MAX_COMPONENTS`] and detail notes against [`MAX_DETAIL_NOTES`].
#[derive(Debug, Default)]
struct Listing {
    /// Components left out once [`MAX_COMPONENTS`] were listed.
    unlisted: usize,
    /// Detail notes recorded.
    detail_notes: usize,
    /// Detail notes left out at [`MAX_DETAIL_NOTES`].
    suppressed_notes: usize,
}

impl Listing {
    /// Append `child` unless [`MAX_COMPONENTS`] children are listed.
    fn push<'a>(&mut self, c: &mut Container<'a>, child: Child<'a>) {
        if c.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
        } else {
            c.children.push(child);
        }
    }

    /// Whether another detail note fits; counts the note as suppressed
    /// when it does not.
    fn admits_detail(&mut self) -> bool {
        if self.detail_notes >= MAX_DETAIL_NOTES {
            self.suppressed_notes += 1;
            false
        } else {
            self.detail_notes += 1;
            true
        }
    }

    /// Record a note about one structure, up to [`MAX_DETAIL_NOTES`].
    fn note(&mut self, c: &mut Container<'_>, note: String) {
        if self.admits_detail() {
            c.notes.push(note);
        }
    }

    /// Notes for what the limits left out.
    fn finish(&self, c: &mut Container<'_>) {
        if self.unlisted > 0 {
            c.notes.push(format!(
                "{} not listed (limit {MAX_COMPONENTS})",
                plural(self.unlisted, "further component", "further components")
            ));
        }
        if self.suppressed_notes > 0 {
            c.notes.push(format!(
                "{} left out",
                plural(
                    self.suppressed_notes,
                    "further detail note",
                    "further detail notes"
                )
            ));
        }
    }
}

/// A note for erased-flash padding after the last structure at `end`, if
/// there is any.
fn padding_note(data: &[u8], end: usize) -> Option<String> {
    let padding = data.len().checked_sub(end).filter(|&n| n > 0)?;
    Some(format!(
        "{} of erased-flash padding after 0x{end:X}",
        size_text(padding)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_stop_at_nul_and_mask_unprintable_bytes() {
        assert_eq!(ascii_name(b"FTPR"), "FTPR");
        assert_eq!(ascii_name(b"rbe\0\0\0"), "rbe");
        assert_eq!(ascii_name(&[b'A', 0x01, b'B']), "A?B");
        assert_eq!(ascii_name(b"\0\0\0\0"), "(unnamed)");
    }

    #[test]
    fn fields_report_what_was_truncated() {
        let message = field(&[0; 4], 2, 4, "$FPT header").unwrap_err().to_string();
        assert!(
            message.contains("Truncated $FPT header at 0x2: 4 B required"),
            "{message}"
        );
        assert!(field(&[0; 4], usize::MAX, 2, "x").is_err());
        assert_eq!(le_u32(&[1, 2, 3, 4], 0).unwrap(), 0x0403_0201);
    }

    #[test]
    fn listing_caps_detail_notes() {
        let mut c = Container::new(FileFormat::IntelMe, "test", KEY_PREFIX);
        let mut listing = Listing::default();
        for i in 0..MAX_DETAIL_NOTES + 3 {
            listing.note(&mut c, format!("note {i}"));
        }
        listing.finish(&mut c);
        assert_eq!(c.notes.len(), MAX_DETAIL_NOTES + 1);
        assert_eq!(c.notes.last().unwrap(), "3 further detail notes left out");
    }

    #[test]
    fn long_lists_are_cut_with_a_count() {
        let names: Vec<String> = (0..MAX_LISTED_NAMES + 2).map(|i| i.to_string()).collect();
        assert!(listed(&names).ends_with("and 2 more"));
        assert_eq!(listed(&["a".into(), "b".into()]), "a, b");
    }
}
