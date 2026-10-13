//! UEFI capsules: firmware update capsules that start with an
//! `EFI_CAPSULE_HEADER` (`CapsuleGuid`, `HeaderSize`, `Flags`,
//! `CapsuleImageSize`). The capsule GUID decides the layout of the body:
//! Firmware Management Protocol (FMP) capsules, nested FMP capsules, JSON
//! capsules, Windows UX capsules, capsules with `EFI_CAPSULE_GUID` (whose
//! body EDK2 `GenFv` fills with firmware volumes), and the Intel, Lenovo,
//! Toshiba and AMI Aptio vendor headers that `UEFITool` recognizes.
//!
//! Sources (pinned; see `docs/capsule.md`):
//! - UEFI Specification 2.10 (`uefi.org/specs/UEFI/2.10`, Wayback snapshots
//!   `20240919080943` and `20240428002726`): 8.5.3.1 `EFI_CAPSULE_HEADER`
//!   and its flags, 8.5.3.2 capsule definition, 8.5.5 capsule files,
//!   23.1.2 `EFI_FIRMWARE_IMAGE_AUTHENTICATION` and
//!   `EFI_FIRMWARE_IMAGE_DEP`, 23.2 dependency opcodes, 23.3 FMP capsules,
//!   23.5 JSON capsules.
//! - EDK2 `edk2-stable202408` (commit
//!   `b158dad150bf02879668f72ce306445250838201`):
//!   `MdePkg/Include/Uefi/UefiSpec.h`, `Guid/FmpCapsule.h`,
//!   `Guid/WinCertificate.h`, `Guid/ImageAuthentication.h`,
//!   `Protocol/FirmwareManagement.h`,
//!   `IndustryStandard/WindowsUxCapsule.h`;
//!   `MdeModulePkg/Library/DxeCapsuleLibFmp/DxeCapsuleLib.c`
//!   (`ValidateFmpCapsule`, `IsNestedFmpCapsule`, `DisplayCapsuleImage`);
//!   `FmpDevicePkg` `FmpPayloadHeaderLibV1` (`FMP_PAYLOAD_HEADER`, `MSS1`)
//!   and `FmpDependencyLib`; `BaseTools` `GenerateCapsule.py` and
//!   `GenFv/GenFvInternalLib.c` (`GenerateCapImage`).
//! - EDK2 `vUDK2018` (commit `3e72ffe8afdd03f1f89eba65c921cbdcb004cfee`):
//!   `IntelFrameworkPkg/Include/Guid/Capsule.h` (`EFI_CAPSULE_GUID`).
//! - `UEFITool` `A75` (commit `19a4dab71f1f994cc2a26b6808e0249e0098c366`):
//!   `common/ffs.h` and `common/ffsparser.cpp` (`parseCapsule`) for the
//!   Intel, Lenovo, Toshiba and AMI Aptio GUIDs and header layouts.
//!
//! Every structure is packed and little-endian. A capsule names no ISA:
//! its body, FMP payloads and embedded drivers are children classified from
//! their own bytes. Signatures are reported as present and never verified.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{Child, Container, MAX_COMPONENTS};
use crate::types::{FileFormat, MetadataValue};
use std::fmt;

mod fmp;
mod json;
mod payload;
mod ux;
mod vendor;

/// Metadata key prefix for every layout of the family.
const KEY_PREFIX: &str = "capsule";

/// Size of `EFI_CAPSULE_HEADER` (UEFI 2.10, 8.5.3.1).
const EFI_CAPSULE_HEADER_SIZE: usize = 28;

/// Size of `UEFITool`'s `APTIO_CAPSULE_HEADER`: `EFI_CAPSULE_HEADER`, then
/// `RomImageOffset` and `RomLayoutOffset` (u16 each).
const APTIO_CAPSULE_HEADER_SIZE: usize = 32;

// `EFI_CAPSULE_HEADER.Flags` bits 31:16, defined by UEFI 2.10 8.5.3.1.
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
const CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE: u32 = 0x0002_0000;
const CAPSULE_FLAGS_INITIATE_RESET: u32 = 0x0004_0000;

/// `Flags[15:0]`, whose meaning the capsule GUID defines.
const GUID_DEFINED_FLAGS: u32 = 0x0000_FFFF;

/// Most per-payload notes and metadata entries one capsule records; the
/// rest are counted (our bound).
const MAX_DETAIL_NOTES: usize = 32;

/// `EFI_CAPSULE_GUID` (Framework Capsule Specification 0.9), the default
/// GUID of EDK2 `GenFv` capsules.
const EFI_CAPSULE_GUID: Guid = Guid::new(
    0x3B66_86BD,
    0x0D76,
    0x4030,
    [0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0],
);

/// `EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID` (UEFI 2.10, 23.3.1).
const EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID: Guid = Guid::new(
    0x6DCB_D5ED,
    0xE82D,
    0x4C44,
    [0xBD, 0xA1, 0x71, 0x94, 0x19, 0x9A, 0xD9, 0x2A],
);

/// `EFI_JSON_CAPSULE_ID_GUID` (UEFI 2.10, 23.5.1).
const EFI_JSON_CAPSULE_ID_GUID: Guid = Guid::new(
    0x67D6_F4CD,
    0xD6B8,
    0x4573,
    [0xBF, 0x4A, 0xDE, 0x5E, 0x25, 0x2D, 0x61, 0xAE],
);

/// `WINDOWS_UX_CAPSULE_GUID` (EDK2 `WindowsUxCapsule.h`).
const WINDOWS_UX_CAPSULE_GUID: Guid = Guid::new(
    0x3B8C_8162,
    0x188C,
    0x46A4,
    [0xAE, 0xC9, 0xBE, 0x43, 0xF1, 0xD6, 0x56, 0x97],
);

/// `INTEL_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const INTEL_CAPSULE_GUID: Guid = Guid::new(
    0x5391_82B9,
    0xABB5,
    0x4391,
    [0xB6, 0x9A, 0xE3, 0xA9, 0x43, 0xF7, 0x2F, 0xCC],
);

/// `LENOVO_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const LENOVO_CAPSULE_GUID: Guid = Guid::new(
    0xE20B_AFD3,
    0x9914,
    0x4F4F,
    [0x95, 0x37, 0x31, 0x29, 0xE0, 0x90, 0xEB, 0x3C],
);

/// `LENOVO2_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const LENOVO2_CAPSULE_GUID: Guid = Guid::new(
    0x25B5_FE76,
    0x8243,
    0x4A5C,
    [0xA9, 0xBD, 0x7E, 0xE3, 0x24, 0x61, 0x98, 0xB5],
);

/// `TOSHIBA_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const TOSHIBA_CAPSULE_GUID: Guid = Guid::new(
    0x3BE0_7062,
    0x1D51,
    0x45D2,
    [0x83, 0x2B, 0xF0, 0x93, 0x25, 0x7E, 0xD4, 0x61],
);

/// `APTIO_SIGNED_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const APTIO_SIGNED_CAPSULE_GUID: Guid = Guid::new(
    0x4A3C_A68B,
    0x7723,
    0x48FB,
    [0x80, 0x3D, 0x57, 0x8C, 0xC1, 0xFE, 0xC4, 0x4D],
);

/// `APTIO_UNSIGNED_CAPSULE_GUID` (`UEFITool` `ffs.h`).
const APTIO_UNSIGNED_CAPSULE_GUID: Guid = Guid::new(
    0x14EE_BB90,
    0x890A,
    0x43DB,
    [0xAE, 0xD1, 0x5D, 0x3C, 0x45, 0x88, 0xA4, 0x18],
);

/// A recognized capsule layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `EFI_CAPSULE_GUID`: an `EFI_CAPSULE_HEADER` and an opaque-to-the-spec
    /// body (firmware volumes when EDK2 `GenFv` wrote it).
    Efi,
    /// `EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID`: embedded drivers and
    /// payload items for `EFI_FIRMWARE_MANAGEMENT_PROTOCOL.SetImage()`.
    Fmp,
    /// A capsule whose platform-defined GUID (an ESRT firmware class) wraps
    /// a complete FMP capsule, as EDK2 `IsNestedFmpCapsule` accepts it.
    /// Recognized only when the inner FMP capsule parses.
    NestedFmp,
    /// `EFI_JSON_CAPSULE_ID_GUID`: an `EFI_JSON_CAPSULE_HEADER` and a JSON
    /// payload.
    Json,
    /// `WINDOWS_UX_CAPSULE_GUID`: a `DISPLAY_DISPLAY_PAYLOAD` and an image
    /// shown during the update.
    WindowsUx,
    /// The Intel capsule GUID with an `EFI_CAPSULE_HEADER`.
    Intel,
    /// Either Lenovo capsule GUID with an `EFI_CAPSULE_HEADER`.
    Lenovo,
    /// The Toshiba capsule header (`HeaderSize`, `FullSize`, `Flags`).
    Toshiba,
    /// The AMI Aptio extended header with the signed-capsule GUID.
    AptioSigned,
    /// The AMI Aptio extended header with the unsigned-capsule GUID.
    AptioUnsigned,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::UefiCapsule
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Efi => "UEFI capsule (EFI_CAPSULE_GUID)",
            Self::Fmp => "FMP capsule",
            Self::NestedFmp => "Nested FMP capsule",
            Self::Json => "JSON capsule",
            Self::WindowsUx => "Windows UX capsule",
            Self::Intel => "Intel capsule",
            Self::Lenovo => "Lenovo capsule",
            Self::Toshiba => "Toshiba capsule",
            Self::AptioSigned => "AMI Aptio signed capsule",
            Self::AptioUnsigned => "AMI Aptio unsigned capsule",
        }
    }

    /// A nested FMP capsule has no documented GUID of its own, so it is
    /// recognized from complete structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::NestedFmp)
    }

    /// Smallest header the layout defines, in bytes.
    fn header_size(self) -> usize {
        match self {
            Self::AptioSigned | Self::AptioUnsigned => APTIO_CAPSULE_HEADER_SIZE,
            _ => EFI_CAPSULE_HEADER_SIZE,
        }
    }

    /// The header fields that locate the body and the end of the capsule.
    fn extent_fields(self) -> ExtentFields {
        match self {
            Self::Toshiba => ExtentFields {
                body: "HeaderSize",
                body_at: 0x10,
                body_width: FieldWidth::U32,
                end: "FullSize",
                end_at: 0x14,
            },
            Self::AptioSigned | Self::AptioUnsigned => ExtentFields {
                body: "RomImageOffset",
                body_at: 0x1C,
                body_width: FieldWidth::U16,
                end: "CapsuleImageSize",
                end_at: 0x18,
            },
            _ => ExtentFields {
                body: "HeaderSize",
                body_at: 0x10,
                body_width: FieldWidth::U32,
                end: "CapsuleImageSize",
                end_at: 0x18,
            },
        }
    }
}

/// A capsule GUID this family documents, with its layout and name.
struct KnownCapsule {
    guid: Guid,
    layout: Layout,
    name: &'static str,
}

/// Every capsule GUID recognized at offset 0. The nested FMP layout has no
/// GUID of its own and is not listed.
const KNOWN_CAPSULES: [KnownCapsule; 10] = [
    KnownCapsule {
        guid: EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
        layout: Layout::Fmp,
        name: "EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID",
    },
    KnownCapsule {
        guid: EFI_CAPSULE_GUID,
        layout: Layout::Efi,
        name: "EFI_CAPSULE_GUID",
    },
    KnownCapsule {
        guid: EFI_JSON_CAPSULE_ID_GUID,
        layout: Layout::Json,
        name: "EFI_JSON_CAPSULE_ID_GUID",
    },
    KnownCapsule {
        guid: WINDOWS_UX_CAPSULE_GUID,
        layout: Layout::WindowsUx,
        name: "WINDOWS_UX_CAPSULE_GUID",
    },
    KnownCapsule {
        guid: INTEL_CAPSULE_GUID,
        layout: Layout::Intel,
        name: "Intel capsule GUID",
    },
    KnownCapsule {
        guid: LENOVO_CAPSULE_GUID,
        layout: Layout::Lenovo,
        name: "Lenovo capsule GUID",
    },
    KnownCapsule {
        guid: LENOVO2_CAPSULE_GUID,
        layout: Layout::Lenovo,
        name: "second Lenovo capsule GUID",
    },
    KnownCapsule {
        guid: TOSHIBA_CAPSULE_GUID,
        layout: Layout::Toshiba,
        name: "Toshiba capsule GUID",
    },
    KnownCapsule {
        guid: APTIO_SIGNED_CAPSULE_GUID,
        layout: Layout::AptioSigned,
        name: "AMI Aptio signed capsule GUID",
    },
    KnownCapsule {
        guid: APTIO_UNSIGNED_CAPSULE_GUID,
        layout: Layout::AptioUnsigned,
        name: "AMI Aptio unsigned capsule GUID",
    },
];

/// The documented capsule whose GUID starts `data`.
fn known_capsule(data: &[u8]) -> Option<&'static KnownCapsule> {
    let guid = data.get(..16)?;
    KNOWN_CAPSULES.iter().find(|known| known.guid.0 == guid)
}

/// Strong recognition: a documented capsule GUID at offset 0 whose header
/// is complete, starts the body no earlier than the end of the layout's
/// header and no later than the end of the capsule, and lies in the file.
/// A capsule that is longer than the file is still recognized, so a
/// truncated capsule becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let layout = known_capsule(data)?.layout;
    let extent = Extent::read(Region::new(data), layout).ok()?;
    let consistent = extent.body_offset >= layout.header_size()
        && extent.body_offset <= extent.end
        && extent.body_offset <= data.len();
    consistent.then_some(layout)
}

/// A nested FMP capsule: an `EFI_CAPSULE_HEADER` with any other GUID that
/// fills the file exactly and holds, at `HeaderSize`, an FMP capsule that
/// parses completely.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    (known_capsule(data).is_none() && fmp::is_nested(data)).then_some(Layout::NestedFmp)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::CapsuleParseError`] for a header whose sizes do not
/// fit the file, non-padding bytes after the capsule, or a body whose own
/// structure (FMP item offsets and image headers, authentication and
/// dependency data, JSON or display payload headers) is malformed.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Fmp => fmp::parse(data),
        Layout::NestedFmp => fmp::parse_nested(data),
        Layout::Json => json::parse(data),
        Layout::WindowsUx => ux::parse(data),
        Layout::Efi | Layout::Intel | Layout::Lenovo => parse_plain(data, layout),
        Layout::Toshiba => vendor::parse_toshiba(data),
        Layout::AptioSigned | Layout::AptioUnsigned => vendor::parse_aptio(data, layout),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CapsuleParseError {
        message: message.into(),
    }
}

/// Input bytes and the file offset of their first byte, so that errors and
/// children name file offsets.
#[derive(Debug, Clone, Copy)]
struct Region<'a> {
    bytes: &'a [u8],
    base: usize,
}

impl<'a> Region<'a> {
    /// The whole input.
    fn new(data: &'a [u8]) -> Self {
        Self {
            bytes: data,
            base: 0,
        }
    }

    fn len(self) -> usize {
        self.bytes.len()
    }

    /// File offset of byte `at` (saturating, for an out-of-range `at` in
    /// an error message).
    fn offset(self, at: usize) -> usize {
        self.base.saturating_add(at)
    }

    /// The `len` bytes of `what` at `start`.
    fn sub(self, start: usize, len: usize, what: &str) -> Result<Region<'a>> {
        let available = self.bytes.len().saturating_sub(start);
        let bytes = start
            .checked_add(len)
            .and_then(|end| self.bytes.get(start..end))
            .ok_or_else(|| {
                error(format!(
                    "Truncated {what} at 0x{:X}: {len} B needed, {available} B present",
                    self.offset(start)
                ))
            })?;
        Ok(Self {
            bytes,
            base: self.offset(start),
        })
    }

    /// The bytes from `start` to the end.
    fn rest(self, start: usize, what: &str) -> Result<Region<'a>> {
        self.sub(start, self.len().saturating_sub(start), what)
    }

    fn array<const N: usize>(self, at: usize, what: &str) -> Result<[u8; N]> {
        Ok(self
            .sub(at, N, what)?
            .bytes
            .try_into()
            .expect("sub returns exactly N bytes"))
    }

    fn u8(self, at: usize, what: &str) -> Result<u8> {
        Ok(self.array::<1>(at, what)?[0])
    }

    fn u16(self, at: usize, what: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array(at, what)?))
    }

    fn u32(self, at: usize, what: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array(at, what)?))
    }

    fn u64(self, at: usize, what: &str) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array(at, what)?))
    }

    fn guid(self, at: usize, what: &str) -> Result<Guid> {
        Ok(Guid(self.array(at, what)?))
    }

    /// A child holding these bytes, stored as-is.
    fn child(self, label: impl Into<String>) -> Child<'a> {
        Child::stored(label, self.base, self.bytes)
    }

    /// A listed child that never reaches the code model.
    fn opaque_child(self, label: impl Into<String>) -> Child<'a> {
        Child::opaque(label, self.base, self.bytes)
    }
}

/// A size field as `usize`.
fn to_usize(value: impl Into<u64>, what: &str) -> Result<usize> {
    let value = value.into();
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
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

/// Width of a little-endian header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldWidth {
    U16,
    U32,
}

/// Names and positions of the two header fields that bound a capsule.
struct ExtentFields {
    /// Field holding the body offset.
    body: &'static str,
    body_at: usize,
    body_width: FieldWidth,
    /// Field holding the capsule size, header included.
    end: &'static str,
    end_at: usize,
}

/// Where a capsule's body starts and where the capsule ends, as byte
/// offsets from the start of the file, read from its header.
#[derive(Debug, Clone, Copy)]
struct Extent {
    body_offset: usize,
    end: usize,
}

impl Extent {
    /// `HeaderSize` and `CapsuleImageSize`; `HeaderSize` and `FullSize`
    /// for Toshiba; `RomImageOffset` and `CapsuleImageSize` for AMI Aptio.
    fn read(data: Region<'_>, layout: Layout) -> Result<Self> {
        let fields = layout.extent_fields();
        let body_offset = match fields.body_width {
            FieldWidth::U16 => u32::from(data.u16(fields.body_at, fields.body)?),
            FieldWidth::U32 => data.u32(fields.body_at, fields.body)?,
        };
        Ok(Self {
            body_offset: to_usize(body_offset, fields.body)?,
            end: to_usize(data.u32(fields.end_at, fields.end)?, fields.end)?,
        })
    }
}

/// A capsule whose header sizes have been checked against the file: the
/// bytes of the capsule itself and its body.
#[derive(Debug, Clone, Copy)]
struct Bounds<'a> {
    /// The capsule, header included, without trailing padding.
    capsule: Region<'a>,
    /// The bytes from the body offset to the end of the capsule.
    body: Region<'a>,
}

/// The capsule and body of `data` as its `layout` header bounds them. The
/// body must start at or after the end of the layout's header and at or
/// before the end of the capsule, the capsule must fit the file, and bytes
/// after it may only be erased flash or zero fill (UEFI 2.10 8.5.5 requires
/// the file size to equal `CapsuleImageSize`).
fn bounds<'a>(data: &'a [u8], layout: Layout, notes: &mut Vec<String>) -> Result<Bounds<'a>> {
    let file = Region::new(data);
    file.sub(0, layout.header_size(), layout.label())?;
    let fields = layout.extent_fields();
    let extent = Extent::read(file, layout)?;
    if extent.body_offset < layout.header_size() {
        return Err(error(format!(
            "Invalid {} {} B: smaller than the {} B header",
            fields.body,
            extent.body_offset,
            layout.header_size()
        )));
    }
    if extent.body_offset > extent.end {
        return Err(error(format!(
            "Invalid {} {} B: beyond {} {} B",
            fields.body, extent.body_offset, fields.end, extent.end
        )));
    }
    if extent.end > data.len() {
        return Err(error(format!(
            "Truncated capsule: {} {} B, file {} B",
            fields.end,
            extent.end,
            data.len()
        )));
    }
    let trailing = &data[extent.end..];
    if !trailing.is_empty() {
        if !is_padding(trailing) {
            return Err(error(format!(
                "Unexpected {} after the capsule at 0x{:X}",
                size_text(trailing.len()),
                extent.end
            )));
        }
        notes.push(format!(
            "{} of padding after the capsule at 0x{:X}",
            size_text(trailing.len()),
            extent.end
        ));
    }
    let capsule = file.sub(0, extent.end, "capsule")?;
    let body = capsule.rest(extent.body_offset, "capsule body")?;
    Ok(Bounds { capsule, body })
}

/// Erased flash (`0xFF`) or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xFF))
}

/// A container of `layout` for a capsule of `size` bytes whose GUID is
/// `guid`, with the GUID note and metadata.
fn new_container<'a>(layout: Layout, guid: Guid, size: usize) -> Container<'a> {
    let mut c = Container::new(FileFormat::UefiCapsule, layout.label(), KEY_PREFIX);
    c.consumed = size;
    let name = KNOWN_CAPSULES
        .iter()
        .find(|known| known.guid == guid)
        .map_or("platform-defined GUID", |known| known.name);
    c.notes
        .push(format!("Capsule GUID {guid} ({name}); capsule {size} B"));
    c.push_metadata("capsule_guid", "Capsule GUID", guid.to_string());
    c
}

/// Record `HeaderSize` and the `EFI_CAPSULE_HEADER` flags of `capsule`.
fn push_efi_header(c: &mut Container<'_>, capsule: Region<'_>, layout: Layout) -> Result<()> {
    let header_size = capsule.u32(0x10, "HeaderSize")?;
    let flags = capsule.u32(0x14, "Flags")?;
    c.push_metadata(
        "capsule_header_size",
        "Header size (B)",
        u64::from(header_size),
    );
    c.push_metadata("capsule_flags", "Capsule flags", MetadataValue::Hex(flags));
    c.notes.push(flags_note(flags));
    c.notes.extend(flag_rule_notes(flags, layout));
    Ok(())
}

/// `Flags 0x00050000: PERSIST_ACROSS_RESET, INITIATE_RESET`, with the
/// GUID-defined low half and any undefined spec bits.
fn flags_note(flags: u32) -> String {
    const NAMED: [(u32, &str); 3] = [
        (CAPSULE_FLAGS_PERSIST_ACROSS_RESET, "PERSIST_ACROSS_RESET"),
        (CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE, "POPULATE_SYSTEM_TABLE"),
        (CAPSULE_FLAGS_INITIATE_RESET, "INITIATE_RESET"),
    ];
    let mut parts: Vec<String> = NAMED
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let named_bits = NAMED.iter().fold(0, |bits, (bit, _)| bits | bit);
    let undefined = flags & !GUID_DEFINED_FLAGS & !named_bits;
    if undefined != 0 {
        parts.push(format!("undefined bits 0x{undefined:08X}"));
    }
    let guid_defined = flags & GUID_DEFINED_FLAGS;
    if guid_defined != 0 {
        parts.push(format!("GUID-defined bits 0x{guid_defined:04X}"));
    }
    if parts.is_empty() {
        format!("Flags 0x{flags:08X}: none set")
    } else {
        format!("Flags 0x{flags:08X}: {}", parts.join(", "))
    }
}

/// Flag combinations that UEFI 2.10 rules out: `INITIATE_RESET` and
/// `POPULATE_SYSTEM_TABLE` each require `PERSIST_ACROSS_RESET` (8.5.3.1),
/// and FMP and JSON capsules must not set `POPULATE_SYSTEM_TABLE` (23.3.3,
/// 23.5.3). A firmware rejects such a capsule; the file is still parsed.
fn flag_rule_notes(flags: u32, layout: Layout) -> Vec<String> {
    let mut notes = Vec::new();
    let persist = flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET != 0;
    for (bit, name) in [
        (CAPSULE_FLAGS_INITIATE_RESET, "INITIATE_RESET"),
        (CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE, "POPULATE_SYSTEM_TABLE"),
    ] {
        if flags & bit != 0 && !persist {
            notes.push(format!(
                "{name} is set without PERSIST_ACROSS_RESET, which UEFI 2.10 section 8.5.3.1 requires"
            ));
        }
    }
    let forbids_table = matches!(layout, Layout::Fmp | Layout::NestedFmp | Layout::Json);
    if forbids_table && flags & CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE != 0 {
        notes.push(format!(
            "POPULATE_SYSTEM_TABLE is set, which UEFI 2.10 does not allow for {} contents",
            layout.label()
        ));
    }
    notes
}

/// Components listed so far, against [`MAX_COMPONENTS`].
#[derive(Debug, Default)]
struct Listing {
    /// Components left out once [`MAX_COMPONENTS`] were listed.
    unlisted: usize,
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

    /// A note for what the limit left out.
    fn finish(&self, c: &mut Container<'_>) {
        if self.unlisted > 0 {
            c.notes.push(format!(
                "{} not listed (limit {MAX_COMPONENTS})",
                counted(self.unlisted, "further component", "further components")
            ));
        }
    }
}

/// `count` followed by the singular or plural noun.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

/// A capsule whose body is not structured by this family (`EFI_CAPSULE_GUID`,
/// Intel and Lenovo GUIDs): the body is one child classified on its own.
fn parse_plain(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, layout, &mut extra)?;
    let guid = bounds.capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(layout, guid, bounds.capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, bounds.capsule, layout)?;
    if layout != Layout::Efi {
        c.notes.push(format!(
            "{} header as UEFITool A75 reads it; the body layout is vendor-defined",
            layout.label()
        ));
    }
    push_body(&mut c, bounds.body, "Capsule body");
    Ok(c)
}

/// The body as one child classified on its own, or a note when it is empty.
fn push_body<'a>(c: &mut Container<'a>, body: Region<'a>, label: &str) {
    if body.len() == 0 {
        c.notes.push("Capsule has no body".into());
        return;
    }
    c.notes.push(format!(
        "{label}: {} at 0x{:X}",
        size_text(body.len()),
        body.base
    ));
    c.children.push(body.child(label));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_print_in_registry_form() {
        assert_eq!(
            EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID.0[..4],
            [0xED, 0xD5, 0xCB, 0x6D]
        );
        assert_eq!(
            EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID.to_string(),
            "6DCBD5ED-E82D-4C44-BDA1-7194199AD92A"
        );
        // The byte string UEFITool A75 `ffs.cpp` stores for the Aptio GUID.
        assert_eq!(
            APTIO_SIGNED_CAPSULE_GUID.0,
            *b"\x8B\xA6\x3C\x4A\x23\x77\xFB\x48\x80\x3D\x57\x8C\xC1\xFE\xC4\x4D"
        );
    }

    #[test]
    fn every_known_guid_is_distinct() {
        for (i, a) in KNOWN_CAPSULES.iter().enumerate() {
            for b in &KNOWN_CAPSULES[i + 1..] {
                assert_ne!(a.guid, b.guid, "{} and {}", a.name, b.name);
            }
        }
    }

    #[test]
    fn flags_name_spec_bits_and_report_rule_violations() {
        assert_eq!(
            flags_note(0x0005_0001),
            "Flags 0x00050001: PERSIST_ACROSS_RESET, INITIATE_RESET, GUID-defined bits 0x0001"
        );
        assert_eq!(flags_note(0), "Flags 0x00000000: none set");
        assert_eq!(
            flags_note(0x0080_0000),
            "Flags 0x00800000: undefined bits 0x00800000"
        );
        assert_eq!(
            flag_rule_notes(0x0005_0000, Layout::Fmp),
            Vec::<String>::new()
        );
        assert_eq!(flag_rule_notes(0x0004_0000, Layout::Efi).len(), 1);
        assert_eq!(flag_rule_notes(0x0003_0000, Layout::Fmp).len(), 1);
        assert_eq!(flag_rule_notes(0x0002_0000, Layout::Json).len(), 2);
    }

    #[test]
    fn regions_report_file_offsets() {
        let data = [0u8; 8];
        let tail = Region::new(&data).sub(4, 4, "tail").unwrap();
        assert_eq!(tail.offset(1), 5);
        let message = tail.u32(2, "field").unwrap_err().to_string();
        assert_eq!(
            message,
            "UEFI capsule parse error: Truncated field at 0x6: 4 B needed, 2 B present"
        );
        assert!(Region::new(&data).sub(usize::MAX, 2, "x").is_err());
    }
}
