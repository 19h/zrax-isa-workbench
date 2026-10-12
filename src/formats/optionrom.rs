//! PCI expansion ROMs (option ROMs).
//!
//! Layout from the PCI Firmware Specification 3.0, section 5.1 (ROM header,
//! PCI Data Structure) and the UEFI Specification 2.10, section 14.4.2
//! (EFI ROM header); all fields are little-endian. A ROM holds one or more
//! images, each starting with `55 AA` and pointing (at 0x18) to a `PCIR`
//! data structure that gives the image length in 512-byte units, the code
//! type and a last-image indicator. The code type is an explicit target:
//! 0 is x86 real-mode code (PC-AT compatible), 2 HP PA-RISC, 3 EFI (whose
//! header names a PE machine and compression), 1 Open Firmware `FCode`, a
//! bytecode with no ISA. Legacy x86 images carry a byte sum of zero over
//! their initialization size. ISA option ROMs without a `PCIR` structure
//! are recognized only when that checksum holds.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target, MAX_COMPONENTS};
use crate::types::{Endianness, FileFormat, Isa};

/// ROM header signature `55 AA`.
const ROM_SIGNATURE: [u8; 2] = [0x55, 0xaa];

/// ROM header fields.
const INIT_SIZE: usize = 0x02;
const EFI_SIGNATURE_OFFSET: usize = 0x04;
const EFI_SUBSYSTEM: usize = 0x08;
const EFI_MACHINE: usize = 0x0a;
const EFI_COMPRESSION: usize = 0x0c;
const EFI_IMAGE_OFFSET: usize = 0x16;
const PCIR_POINTER: usize = 0x18;

/// `EfiSignature` of an EFI image.
const EFI_SIGNATURE: u32 = 0x0ef1;

/// EFI image compression types.
const EFI_UNCOMPRESSED: u16 = 0;

/// PCI Data Structure fields.
const PCIR_SIGNATURE: &[u8; 4] = b"PCIR";
const PCIR_VENDOR: usize = 0x04;
const PCIR_DEVICE: usize = 0x06;
const PCIR_IMAGE_LENGTH: usize = 0x10;
const PCIR_CODE_TYPE: usize = 0x14;
const PCIR_INDICATOR: usize = 0x15;
const PCIR_MIN_LENGTH: usize = 0x18;

/// Indicator bit 7: this is the last image.
const LAST_IMAGE: u8 = 0x80;

/// Code types.
const CODE_X86: u8 = 0x00;
const CODE_OPEN_FIRMWARE: u8 = 0x01;
const CODE_PA_RISC: u8 = 0x02;
const CODE_EFI: u8 = 0x03;

/// Image lengths are in 512-byte units.
const BLOCK: usize = 512;

/// A recognized option ROM layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// PCI expansion ROM with `PCIR` structures.
    Pci,
    /// Legacy ISA option ROM: `55 AA`, size and a zero byte sum.
    Isa,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::PciOptionRom
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pci => "PCI expansion ROM",
            Self::Isa => "Legacy option ROM",
        }
    }

    /// ISA option ROMs have only a two-byte signature and a checksum.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Isa)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::OptionRomParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated option ROM at 0x{start:X} + {len} B")))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = slice(data, at, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Does the byte sum of `bytes` vanish modulo 256?
fn sums_to_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

/// Offset of the image's `PCIR` structure, when its pointer is valid.
fn pcir_offset(image: &[u8]) -> Option<usize> {
    let pointer = usize::from(le_u16(image, PCIR_POINTER).ok()?);
    (image.get(pointer..pointer + 4)? == PCIR_SIGNATURE).then_some(pointer)
}

/// Strong recognition: `55 AA` and a `PCIR` structure.
pub fn detect(data: &[u8]) -> Option<Layout> {
    (data.starts_with(&ROM_SIGNATURE) && pcir_offset(data).is_some()).then_some(Layout::Pci)
}

/// Weak recognition: an ISA option ROM whose initialization size fits and
/// whose bytes sum to zero, followed only by padding.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    parse_container(data, Layout::Isa)
        .is_ok()
        .then_some(Layout::Isa)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::OptionRomParseError`] for a missing signature, an
/// image beyond the file, a bad `PCIR` structure or, for ISA ROMs, a
/// nonzero checksum.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Pci => pci(data),
        Layout::Isa => isa(data),
    }
}

/// The legacy x86 image's initialization-size byte sum, as a note.
fn checksum_note(image: &[u8]) -> String {
    let size = usize::from(image.get(INIT_SIZE).copied().unwrap_or(0)) * BLOCK;
    match image.get(..size) {
        Some(initialized) if size > 0 && sums_to_zero(initialized) => {
            "x86 image checksum verified".into()
        }
        _ => "x86 image checksum does not sum to zero".into(),
    }
}

/// One image of a PCI expansion ROM as a child.
fn image_child<'a>(
    image: &'a [u8],
    offset: usize,
    index: usize,
    code_type: u8,
    notes: &mut Vec<String>,
) -> Result<Child<'a>> {
    let label = format!("Image {}", index + 1);
    let child = match code_type {
        CODE_X86 => {
            notes.push(format!(
                "{label}: x86 real-mode code; {}",
                checksum_note(image)
            ));
            Child::stored(format!("{label} (x86)"), offset, image)
                .as_code()
                .with_target(Target::new(Isa::X86, 16, Endianness::Little))
        }
        CODE_PA_RISC => Child::stored(format!("{label} (PA-RISC)"), offset, image)
            .as_code()
            .with_target(Target::new(Isa::Parisc, 32, Endianness::Big)),
        CODE_OPEN_FIRMWARE => {
            notes.push(format!(
                "{label}: Open Firmware FCode, a bytecode with no ISA"
            ));
            Child::opaque(format!("{label} (Open Firmware)"), offset, image)
        }
        CODE_EFI => efi_child(image, offset, &label, notes)?,
        other => {
            notes.push(format!("{label}: unknown code type 0x{other:02X}"));
            Child::opaque(format!("{label} (code type 0x{other:02X})"), offset, image)
        }
    };
    Ok(child)
}

/// An EFI image: the EFI ROM header names the PE machine and whether the
/// PE image at `EfiImageHeaderOffset` is compressed.
fn efi_child<'a>(
    image: &'a [u8],
    offset: usize,
    label: &str,
    notes: &mut Vec<String>,
) -> Result<Child<'a>> {
    if le_u32(image, EFI_SIGNATURE_OFFSET)? != EFI_SIGNATURE {
        return Err(error(format!(
            "Invalid EFI ROM header signature in {label}"
        )));
    }
    let subsystem = le_u16(image, EFI_SUBSYSTEM)?;
    let machine = le_u16(image, EFI_MACHINE)?;
    let compression = le_u16(image, EFI_COMPRESSION)?;
    let pe_at = usize::from(le_u16(image, EFI_IMAGE_OFFSET)?);
    let pe = image
        .get(pe_at..)
        .filter(|pe| !pe.is_empty())
        .ok_or_else(|| error(format!("Invalid EFI image offset 0x{pe_at:X} in {label}")))?;
    notes.push(format!(
        "{label}: EFI image, machine 0x{machine:04X}, subsystem {subsystem}, compression type {compression}"
    ));
    let (isa, bits, endianness, _) = crate::formats::coff::machine_to_isa(machine);
    let mut child = if compression == EFI_UNCOMPRESSED {
        Child::stored(format!("{label} (EFI)"), offset + pe_at, pe)
    } else {
        notes.push(format!("{label}: EFI-compressed image; not decoded"));
        Child::opaque(format!("{label} (EFI, compressed)"), offset + pe_at, pe)
    };
    if !matches!(isa, Isa::Unknown(_)) {
        child = child.with_target(Target::new(isa, bits, endianness));
    }
    Ok(child)
}

fn pci(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(FileFormat::PciOptionRom, Layout::Pci.label(), "optionrom");
    let mut pos = 0;
    loop {
        let header = slice(data, pos, PCIR_POINTER + 2)?;
        if header[..2] != ROM_SIGNATURE {
            return Err(error(format!("Missing option ROM signature at 0x{pos:X}")));
        }
        let rest = &data[pos..];
        let pcir = pcir_offset(rest)
            .ok_or_else(|| error(format!("Missing PCIR structure for the image at 0x{pos:X}")))?;
        slice(rest, pcir, PCIR_MIN_LENGTH)?;
        let length = usize::from(le_u16(rest, pcir + PCIR_IMAGE_LENGTH)?) * BLOCK;
        if length == 0 {
            return Err(error(format!("Invalid zero image length at 0x{pos:X}")));
        }
        let image = slice(data, pos, length)?;
        let vendor = le_u16(rest, pcir + PCIR_VENDOR)?;
        let device = le_u16(rest, pcir + PCIR_DEVICE)?;
        let code_type = rest[pcir + PCIR_CODE_TYPE];
        let indicator = rest[pcir + PCIR_INDICATOR];
        if c.children.is_empty() {
            c.notes
                .push(format!("PCI device {vendor:04X}:{device:04X}"));
        }
        let index = c.children.len();
        c.children
            .push(image_child(image, pos, index, code_type, &mut c.notes)?);
        pos += length;
        if indicator & LAST_IMAGE != 0 || c.children.len() >= MAX_COMPONENTS {
            break;
        }
    }
    c.consumed = pos;
    if !is_padding(&data[pos..]) {
        c.notes.push(format!(
            "{} B after the last image are not part of the ROM",
            data.len() - pos
        ));
    }
    c.notes.insert(
        0,
        format!("PCI expansion ROM with {} image(s)", c.children.len()),
    );
    Ok(c)
}

fn isa(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(&ROM_SIGNATURE) {
        return Err(error("Missing option ROM signature"));
    }
    let size = usize::from(*slice(data, INIT_SIZE, 1)?.first().expect("one byte")) * BLOCK;
    if size == 0 {
        return Err(error("Invalid zero option ROM size"));
    }
    let image = slice(data, 0, size)?;
    if !sums_to_zero(image) {
        return Err(error("Invalid option ROM checksum"));
    }
    if !is_padding(&data[size..]) {
        return Err(error(format!(
            "Unexpected bytes after the option ROM at 0x{size:X}"
        )));
    }
    let mut c = Container::new(FileFormat::PciOptionRom, Layout::Isa.label(), "optionrom");
    c.consumed = size;
    c.notes
        .push("Legacy option ROM without a PCIR structure; checksum verified".into());
    c.children.push(
        Child::stored("Option ROM (x86)", 0, image)
            .as_code()
            .with_target(Target::new(Isa::X86, 16, Endianness::Little)),
    );
    Ok(c)
}
