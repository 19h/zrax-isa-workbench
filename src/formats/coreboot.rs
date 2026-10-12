//! Chromium flash maps (FMAP) and coreboot file systems (CBFS).
//!
//! Sources, pinned to the revisions that were read:
//! - FMAP: flashmap `lib/fmap.h` and `lib/fmap.c`
//!   (`chromiumos/third_party/flashmap` commit `d56ae073fa2f`); coreboot 25.09
//!   (commit `07df08836eca`)
//!   `src/commonlib/bsd/include/commonlib/bsd/fmap_serialized.h` and
//!   `util/cbfstool/fmap_from_fmd.c`; flashrom v1.8.0 (commit `90b6b4376c74`)
//!   `fmap.c` (`is_valid_fmap`).
//! - CBFS: coreboot 25.09
//!   `src/commonlib/bsd/include/commonlib/bsd/cbfs_serialized.h`,
//!   `src/commonlib/bsd/cbfs_private.c` (`cbfs_walk`, `cbfs_find_attr`),
//!   `src/lib/cbfs.c`, `src/lib/lzma.c`, `src/commonlib/bsd/lz4_wrapper.c`,
//!   `util/cbfstool/cbfs_image.c`, `cbfs-mkstage.c` and `cbfs-mkpayload.c`;
//!   coreboot 4.13 (commit `5c186c6777c9`) `cbfs_serialized.h` for the legacy
//!   stage header; vboot (commit `8273cc58132e`)
//!   `firmware/2lib/include/2crypto.h` for the hash algorithms.
//!
//! Byte order: FMAP fields are little-endian. CBFS file headers, attributes,
//! the master header and payload segments are big-endian; the legacy stage
//! header and the master-header pointer in the last four bytes of a ROM are
//! little-endian.
//!
//! FMAP names no ISA. The CBFS master header's `architecture` is the only
//! ISA field in either format, and it becomes the container target only
//! where the value also fixes the register width. Everything else comes from
//! the contained images, each classified on its own.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::types::FileFormat;

mod cbfs;
mod fmap;

/// A recognized flash-map or CBFS layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A flash image whose FMAP header is at offset 0.
    Fmap,
    /// A flash image whose FMAP header was found past offset 0 by the
    /// bounded search.
    EmbeddedFmap {
        /// File offset of the FMAP header.
        offset: usize,
    },
    /// A CBFS region: its first file header is at offset 0.
    Cbfs,
    /// A legacy CBFS ROM, located through the master-header pointer in its
    /// last four bytes.
    MasterHeaderCbfs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Fmap | Self::EmbeddedFmap { .. } => FileFormat::Fmap,
            Self::Cbfs | Self::MasterHeaderCbfs => FileFormat::Cbfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Fmap => "FMAP flash image",
            Self::EmbeddedFmap { .. } => "FMAP flash image (map found by search)",
            Self::Cbfs => "CBFS region",
            Self::MasterHeaderCbfs => "CBFS ROM (master header pointer)",
        }
    }

    /// Recognized from a complete structure rather than a magic at offset 0.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::EmbeddedFmap { .. } | Self::MasterHeaderCbfs)
    }
}

/// Strong recognition: `__FMAP__` or `LARCHIVE` at offset 0.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(fmap::SIGNATURE) {
        return Some(Layout::Fmap);
    }
    if data.starts_with(cbfs::FILE_MAGIC) {
        return Some(Layout::Cbfs);
    }
    None
}

/// Weak recognition, for inputs no other format claims: an FMAP found by the
/// bounded search that validates completely, else a legacy CBFS ROM whose
/// end pointer reaches a valid master header and whose file headers walk
/// cleanly. The FMAP comes first because it describes the whole flash image,
/// and the CBFS inside it can carry the same end pointer.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    if let Some(offset) = fmap::find(data) {
        return Some(Layout::EmbeddedFmap { offset });
    }
    cbfs::is_master_header_rom(data).then_some(Layout::MasterHeaderCbfs)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::CorebootParseError`] for a truncated or inconsistent
/// FMAP, area table, CBFS file header, attribute or master header.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Fmap => fmap::parse(data, 0, layout),
        Layout::EmbeddedFmap { offset } => fmap::parse(data, offset, layout),
        Layout::Cbfs => cbfs::parse_region(data, layout),
        Layout::MasterHeaderCbfs => cbfs::parse_rom(data, layout),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CorebootParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`, or a truncation error naming `what`.
fn field<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X}")))
}

/// `N` bytes at `at` of a structure whose size was checked by [`field`].
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

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    array(data, at).map(u32::from_be_bytes)
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    array(data, at).map(u64::from_be_bytes)
}

/// The bytes of a NUL-terminated string field, without the terminator, or
/// `None` when the field holds no NUL.
fn c_string(field: &[u8]) -> Option<&[u8]> {
    let end = field.iter().position(|&b| b == 0)?;
    Some(&field[..end])
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Round `n` up to a multiple of `align`, a power of two.
fn align_up(n: usize, align: usize) -> Result<usize> {
    let mask = align - 1;
    n.checked_add(mask)
        .map(|n| n & !mask)
        .ok_or_else(|| error("Invalid offset: alignment overflows"))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// What one container may still hand to its children: at most
/// [`MAX_COMPONENTS`] children and [`MAX_EXTRACTED`] bytes. Decoded bytes
/// count against the byte limit, and so do stored bytes that are scanned
/// (flash-map areas may overlap, so their sum is not bounded by the file).
struct Budget {
    components: usize,
    bytes: usize,
    omitted: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            components: MAX_COMPONENTS,
            bytes: MAX_EXTRACTED,
            omitted: 0,
        }
    }

    /// Count `size` bytes as decoded or scanned. Returns false, and counts
    /// the component as omitted, once the byte limit would be passed.
    fn spend(&mut self, size: usize) -> bool {
        if size > self.bytes {
            self.omitted += 1;
            return false;
        }
        self.bytes -= size;
        true
    }

    /// Count one more child. Returns false, and counts it as omitted, once
    /// the component limit is reached.
    fn admit(&mut self) -> bool {
        if self.components == 0 {
            self.omitted += 1;
            return false;
        }
        self.components -= 1;
        true
    }

    /// A note naming what the limits left out, if anything.
    fn note(&self) -> Option<String> {
        (self.omitted > 0).then(|| {
            format!(
                "{} further components were not extracted (limits: {MAX_COMPONENTS} components, {})",
                self.omitted,
                size_text(MAX_EXTRACTED)
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_end_at_the_first_nul() {
        assert_eq!(c_string(b"COREBOOT\0\0\0"), Some(&b"COREBOOT"[..]));
        assert_eq!(c_string(b"\0"), Some(&b""[..]));
        assert_eq!(c_string(b"NOTERMINATOR"), None);
    }

    #[test]
    fn alignment_and_sizes_use_checked_arithmetic() {
        assert_eq!(align_up(65, 64).unwrap(), 128);
        assert_eq!(align_up(64, 64).unwrap(), 64);
        assert!(align_up(usize::MAX, 64).is_err());
        assert_eq!(size_text(4096), "4 KiB");
        assert_eq!(size_text(1 << 21), "2 MiB");
        assert_eq!(size_text(100), "100 B");
    }

    #[test]
    fn fields_report_the_truncated_offset() {
        let message = field(&[0; 4], 2, 4, "FMAP header").unwrap_err().to_string();
        assert!(
            message.contains("Truncated FMAP header at 0x2"),
            "{message}"
        );
        assert!(field(&[0; 4], usize::MAX, 2, "x").is_err());
    }

    #[test]
    fn budget_counts_what_the_limits_leave_out() {
        let mut budget = Budget::new();
        assert!(budget.spend(MAX_EXTRACTED - 1));
        assert!(!budget.spend(2));
        assert!(budget.spend(1));
        assert!(budget.spend(0));
        assert!(!budget.spend(1));
        for _ in 0..MAX_COMPONENTS {
            assert!(budget.admit());
        }
        assert!(!budget.admit());
        let note = budget.note().expect("two components were left out");
        assert!(note.starts_with("3 further components"), "{note}");
    }
}
