//! UEFI and PC flash images: PI firmware volumes with their FFS files and
//! sections (also when a flash device image puts leading data before the
//! first volume), standalone TE (terse executable) images, and Intel flash
//! descriptor (IFD) images whose BIOS region holds firmware volumes.
//!
//! Volumes nested in a volume (firmware volume image sections, volumes in
//! RAW sections and RAW files) are walked inside the same container, so
//! every PE32 and TE image they hold is listed as its own component and all
//! decoded sections share one extraction budget.
//!
//! Sources (pinned revisions; see `docs/uefi.md`):
//! - UEFI PI 1.8 Vol. 3 (`uefi.org/specs/PI/1.8/V3_Code_Definitions.html`,
//!   Wayback snapshot `20241217170227`): 3.2.1 `EFI_FIRMWARE_VOLUME_HEADER`,
//!   3.2.2 file system GUIDs, 3.2.3 `EFI_FFS_FILE_HEADER`, 3.2.4-3.2.5
//!   sections; Vol. 3 design discussion 2.2 (alignment, file states).
//! - UEFI PI 1.8 Vol. 1, chapter 15 (`EFI_TE_IMAGE_HEADER`).
//! - EDK2 `edk2-stable202408` (commit `b158dad150bf02879668f72ce306445250838201`):
//!   `MdePkg/Include/Pi/PiFirmwareVolume.h`, `PiFirmwareFile.h`,
//!   `IndustryStandard/PeImage.h`, `MdeModulePkg/Core/Pei/FwVol/FwVol.c`,
//!   `Core/Dxe/FwVol/Ffs.c`, `MdePkg/Library/BasePeCoffLib/BasePeCoff.c` and
//!   the LZMA, Brotli and CRC32 GUID-defined section extraction libraries.
//! - Intel flash descriptor: coreboot 25.09 `util/ifdtool`, flashrom v1.8.0
//!   `include/ich_descriptors.h` and `UEFITool` A75 `common/descriptor.h`. No
//!   Intel document was read; the descriptor layout is community-documented.
//!
//! Every structure is packed and little-endian. Firmware volumes, FFS files
//! and the flash descriptor name no ISA: the machine fields of PE32 and TE
//! images inside the files are the explicit evidence, and each image is
//! classified on its own.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, size_text, Codec};
use crate::formats::container::{self, Child, Container, Target, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;
use std::fmt;

mod ffs;
mod fv;
mod ifd;
mod section;
mod te;

/// Metadata key prefix for every layout of the family.
const KEY_PREFIX: &str = "uefi";

/// Bytes `is_recognized` inspects before a raw member is extracted from a
/// decoded stream.
const RECOGNITION_PREFIX: usize = 4096;

/// A recognized UEFI or PC flash layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A PI firmware volume at offset 0 (`_FVH` at 0x28), possibly followed
    /// by further volumes.
    FirmwareVolume,
    /// A flash device image: leading data (a reset branch or boot code),
    /// then a firmware volume on a 4 KiB boundary within the first MiB.
    /// Recognized only when the whole image parses.
    FlashDevice,
    /// A TE image with a consistent header: known machine, a plausible
    /// section count and stripped size.
    Te,
    /// A TE image whose machine is not in the PE table, recognized only
    /// because every structural check passes.
    TeStructural,
    /// An Intel flash descriptor image (signature at 0x10, or at 0x0 on
    /// chipsets before the Ibex Peak B-step).
    FlashDescriptor,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::FirmwareVolume | Self::FlashDevice => FileFormat::UefiFv,
            Self::Te | Self::TeStructural => FileFormat::UefiTe,
            Self::FlashDescriptor => FileFormat::IntelIfd,
        }
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::FirmwareVolume => "PI firmware volume",
            Self::FlashDevice => "PI flash device image",
            Self::Te => "TE image",
            Self::TeStructural => "TE image (unknown machine)",
            Self::FlashDescriptor => "Intel flash descriptor image",
        }
    }

    /// The structure-only TE layout has a two-byte signature and no known
    /// machine, and a flash device image has no signature at a fixed
    /// offset, so both are recognized from complete structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::TeStructural | Self::FlashDevice)
    }
}

/// Magic-bearing layouts: the flash descriptor signature, `_FVH` at 0x28,
/// or a TE header whose machine, section count and stripped size agree.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if ifd::has_signature(data) {
        Some(Layout::FlashDescriptor)
    } else if fv::has_signature(data) {
        Some(Layout::FirmwareVolume)
    } else if te::has_consistent_header(data) {
        Some(Layout::Te)
    } else {
        None
    }
}

/// A TE image whose machine is unknown, recognized only when every check
/// of the EDK2 loader passes and the entry point lies in section data; or a
/// flash device image, recognized only when its volumes parse completely.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    if te::is_complete_image(data) {
        return Some(Layout::TeStructural);
    }
    let parses = fv::leading_volume(data).is_some() && fv::parse(data, Layout::FlashDevice).is_ok();
    parses.then_some(Layout::FlashDevice)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::UefiParseError`] for a malformed header, a failed
/// checksum or CRC, a range outside the file or a corrupt compressed
/// section.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::FirmwareVolume | Layout::FlashDevice => fv::parse(data, layout),
        Layout::Te | Layout::TeStructural => te::parse(data, layout),
        Layout::FlashDescriptor => ifd::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::UefiParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated data at 0x{start:X} + {len} B")))
}

fn byte_at(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

/// A 24-bit little-endian size field (FFS files and sections).
fn le_u24(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 3)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// A size or offset field converted to `usize`.
fn to_usize(value: impl TryInto<usize>, what: &str) -> Result<usize> {
    value
        .try_into()
        .map_err(|_| error(format!("Invalid {what}: does not fit the address space")))
}

/// Round `value` up to a multiple of `alignment` (a power of two).
fn align_up(value: usize, alignment: usize) -> Result<usize> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or_else(|| error("Alignment overflow"))
}

/// `"1 file"`, `"2 files"`.
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Erased flash (`0xFF`) or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xFF))
}

/// 8-bit sum with carries dropped (`CalculateSum8`).
fn sum8(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

/// An `EFI_GUID`: `Data1` (u32), `Data2` and `Data3` (u16), all
/// little-endian, then `Data4` (8 bytes in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Guid([u8; 16]);

impl Guid {
    /// The GUID written `data1-data2-data3-data4[0..2]-data4[2..8]`.
    const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        let a = data1.to_le_bytes();
        let b = data2.to_le_bytes();
        let c = data3.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], data4[0], data4[1], data4[2], data4[3],
            data4[4], data4[5], data4[6], data4[7],
        ])
    }

    fn read(data: &[u8], at: usize) -> Result<Self> {
        let bytes: [u8; 16] = slice(data, at, 16)?
            .try_into()
            .expect("slice has exactly 16 bytes");
        Ok(Self(bytes))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = &self.0;
        let data1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
        let data2 = u16::from_le_bytes([g[4], g[5]]);
        let data3 = u16::from_le_bytes([g[6], g[7]]);
        write!(f, "{data1:08X}-{data2:04X}-{data3:04X}-")?;
        for byte in &g[8..10] {
            write!(f, "{byte:02X}")?;
        }
        f.write_str("-")?;
        for byte in &g[10..] {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Where decoded bytes come from: the encapsulation section stored at
/// `offset..offset + stored_size` in the input, decoded by `transform`.
#[derive(Debug, Clone, Copy)]
struct Origin {
    offset: usize,
    stored_size: usize,
    transform: &'static str,
}

/// Bytes being walked: input bytes at a file offset, or bytes a codec
/// produced from a stored encapsulation section. Children found in decoded
/// bytes keep the stored range of the outermost encapsulation, as the
/// container model requires.
#[derive(Debug, Clone, Copy)]
enum Stream<'a: 'b, 'b> {
    /// Input bytes; `base` is the file offset of `bytes[0]`.
    Stored { bytes: &'a [u8], base: usize },
    /// Decoded bytes; offsets inside them are not file offsets.
    Decoded { bytes: &'b [u8], origin: Origin },
}

impl<'a: 'b, 'b> Stream<'a, 'b> {
    // The arms cannot merge: the two bindings have different lifetimes.
    #[allow(clippy::match_same_arms)]
    fn bytes(&self) -> &'b [u8] {
        match *self {
            Self::Stored { bytes, .. } => bytes,
            Self::Decoded { bytes, .. } => bytes,
        }
    }

    /// The bytes `start..end` of this stream.
    fn sub(&self, start: usize, end: usize) -> Result<Self> {
        let range = |bytes: &[u8]| {
            if start <= end && end <= bytes.len() {
                Ok(())
            } else {
                Err(error(format!(
                    "Truncated data: 0x{start:X}..0x{end:X} beyond {} B",
                    bytes.len()
                )))
            }
        };
        match *self {
            Self::Stored { bytes, base } => {
                range(bytes)?;
                Ok(Self::Stored {
                    bytes: &bytes[start..end],
                    base: base + start,
                })
            }
            Self::Decoded { bytes, origin } => {
                range(bytes)?;
                Ok(Self::Decoded {
                    bytes: &bytes[start..end],
                    origin,
                })
            }
        }
    }

    /// Where offset `at` of this stream is, for notes and errors.
    fn place(&self, at: usize) -> String {
        match *self {
            Self::Stored { base, .. } => format!("0x{:X}", base + at),
            Self::Decoded { origin, .. } => format!(
                "0x{at:X} of the {} data decoded from the section at 0x{:X}",
                origin.transform, origin.offset
            ),
        }
    }

    /// A stream of `decoded` bytes produced by `transform` from the section
    /// at `at..at + size` of this stream.
    fn decoded<'c>(
        &self,
        at: usize,
        size: usize,
        transform: &'static str,
        decoded: &'c [u8],
    ) -> Stream<'a, 'c>
    where
        'a: 'c,
    {
        let origin = match *self {
            Self::Stored { base, .. } => Origin {
                offset: base + at,
                stored_size: size,
                transform,
            },
            Self::Decoded { origin, .. } => origin,
        };
        Stream::Decoded {
            bytes: decoded,
            origin,
        }
    }

    /// A component holding the whole stream, labeled later. Decoded bytes
    /// are copied, because they do not outlive the walk.
    fn child(&self) -> Child<'a> {
        match *self {
            Self::Stored { bytes, base } => Child::stored(String::new(), base, bytes),
            Self::Decoded { bytes, origin } => Child::decoded(
                String::new(),
                origin.offset,
                origin.stored_size,
                Cow::Owned(bytes.to_vec()),
                origin.transform,
            ),
        }
    }

    /// Whether listing this stream as an archive-style member is worth
    /// copying it: stored bytes cost nothing, decoded bytes are copied only
    /// when their prefix is a recognized format.
    fn is_listable(&self) -> bool {
        match *self {
            Self::Stored { .. } => true,
            Self::Decoded { bytes, .. } => {
                container::is_recognized(&bytes[..bytes.len().min(RECOGNITION_PREFIX)])
            }
        }
    }
}

/// Most detail notes (per volume and per section) one container records;
/// the rest are counted.
const MAX_DETAIL_NOTES: usize = 64;

/// What one container has extracted and listed so far, against
/// [`MAX_EXTRACTED`] and [`MAX_COMPONENTS`]. Nested firmware volumes are
/// walked inside the same container so that their decoded sections share
/// one budget instead of multiplying it at every nesting level.
#[derive(Debug, Default)]
struct Budget {
    /// Decoded bytes so far.
    extracted: usize,
    /// Components left out once [`MAX_COMPONENTS`] were listed.
    unlisted: usize,
    /// Encapsulated streams not decoded once [`MAX_EXTRACTED`] was
    /// reached.
    undecoded: usize,
    /// Firmware volumes walked, including nested ones.
    volumes: usize,
    /// Detail notes recorded.
    detail_notes: usize,
    /// Detail notes left out at [`MAX_DETAIL_NOTES`].
    suppressed_notes: usize,
    /// CRC32 GUID-defined sections whose CRC matched.
    crc_verified: usize,
}

impl Budget {
    /// Most bytes the next decoded section may produce: the per-section
    /// [`MAX_PAYLOAD`] limit, or less once the container is near
    /// [`MAX_EXTRACTED`].
    fn remaining(&self) -> usize {
        MAX_EXTRACTED
            .saturating_sub(self.extracted)
            .min(MAX_PAYLOAD)
    }

    /// Append `child` unless [`MAX_COMPONENTS`] children are listed.
    fn push<'a>(&mut self, c: &mut Container<'a>, child: Child<'a>) {
        if c.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
        } else {
            c.children.push(child);
        }
    }

    /// Record a note about one volume, file or section, up to
    /// [`MAX_DETAIL_NOTES`].
    fn note(&mut self, c: &mut Container<'_>, note: String) {
        if self.detail_notes >= MAX_DETAIL_NOTES {
            self.suppressed_notes += 1;
        } else {
            self.detail_notes += 1;
            c.notes.push(note);
        }
    }

    /// Notes for what the limits left out.
    fn finish(&self, c: &mut Container<'_>) {
        if self.crc_verified > 0 {
            c.notes.push(format!(
                "{}: CRC-32 verified",
                count(self.crc_verified, "CRC32 GUID-defined section")
            ));
        }
        if self.unlisted > 0 {
            c.notes.push(format!(
                "{} not listed (limit {MAX_COMPONENTS})",
                count(self.unlisted, "further component")
            ));
        }
        if self.undecoded > 0 {
            c.notes.push(format!(
                "{} not decoded: decoded size above {} per section or {} per container",
                count(self.undecoded, "encapsulated section"),
                size_text(MAX_PAYLOAD),
                size_text(MAX_EXTRACTED)
            ));
        }
        if self.suppressed_notes > 0 {
            c.notes.push(format!(
                "{} left out",
                count(self.suppressed_notes, "further volume or section note")
            ));
        }
    }
}

/// The message of a codec or UEFI error, without the family prefix, for
/// embedding in another message or note.
fn bare_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::CompressedParseError { message }
        | ClassifierError::UefiParseError { message } => message,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_print_in_registry_form() {
        let guid = Guid::new(
            0x8C8C_E578,
            0x8A3D,
            0x4F1C,
            [0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3],
        );
        assert_eq!(guid.0[..4], [0x78, 0xE5, 0x8C, 0x8C]);
        assert_eq!(guid.to_string(), "8C8CE578-8A3D-4F1C-9935-896185C32DD3");
    }

    #[test]
    fn alignment_and_sums_wrap_as_edk2_does() {
        assert_eq!(align_up(0x19, 8).unwrap(), 0x20);
        assert_eq!(align_up(0x20, 8).unwrap(), 0x20);
        assert!(align_up(usize::MAX, 8).is_err());
        assert_eq!(sum8(&[0xFF, 0x02]), 0x01);
        assert_eq!(le_u24(&[0x01, 0x02, 0x03, 0x04], 0).unwrap(), 0x0003_0201);
    }
}
