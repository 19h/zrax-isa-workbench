//! DOS MZ, NE (New Executable), and LE/LX (Linear Executable) parser.
//!
//! This module handles legacy Microsoft/IBM executable formats:
//! - MZ: Original DOS executable format (16-bit real mode)
//! - NE: New Executable for 16-bit Windows and OS/2
//! - LE/LX: Linear Executable for OS/2 32-bit and VxD drivers
//!
//! Sources for the DOS header signature, the PE signature and the linear
//! executable header without an MZ stub:
//!
//! - DOS header: Microsoft MS-DOS 2.0 source (`microsoft/MS-DOS` commit
//!   `2d04cacc5322951f187bb17e017c12920ac8ebe2`), `v2.0/source/DOSSYM.ASM`
//!   lines 571-589 (`EXE_file`, `exe_valid_signature EQU 5A4Dh`,
//!   `exe_valid_old_signature EQU 4D5Ah`) and `v2.0/source/EXEC.ASM` lines
//!   332-336, where the EXEC loader accepts both `MZ` and `ZM`.
//! - PE signature: Microsoft "PE Format" (`MicrosoftDocs/win32` commit
//!   `ca8274decead49403d70ceeed4af8d4ca74eaf11`,
//!   `desktop-src/Debug/pe-format.md`), "MS-DOS Stub (Image Only)" and
//!   "Signature (Image Only)": the offset at 0x3C points at `PE\0\0`.
//! - LX: IBM, "LX - Linear eXecutable Module Format Description", June 3,
//!   1992: Figure 2 (header), the object table and the object page table.
//! - LE: `IMAGE_VXD_HEADER` of the Windows SDK `winnt.h` (as reproduced in
//!   Wine `wine-9.0`, `include/winnt.h`), and Open Watcom
//!   (`open-watcom/open-watcom-v2` commit
//!   `08213659bcc7b4f6d3f0c3891ed8c24d29910de1`): `bld/watcom/h/exeflat.h`
//!   for the LE last page size and 4-byte page table entries,
//!   `bld/exedump/c/os2exe.c` for the LE page offsets, and
//!   `bld/exedump/c/wdmp.c`, which reads an LE/LX header at offset 0 when the
//!   file has no DOS header.
//!
//! An LE/LX header without an MZ stub has only a two-byte signature, so it is
//! recognized only when the header and its object and page tables validate
//! completely ([`detect_bare`]); its CPU type field remains the ISA
//! evidence, as it is behind a stub.

use crate::error::{ClassifierError, Result};
use crate::formats::{magic, pe, read_bytes, read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// MZ header signature.
pub const MZ_SIGNATURE: [u8; 2] = [b'M', b'Z'];
/// `exe_valid_old_signature` (4D5Ah): the byte-swapped DOS header signature
/// that the MS-DOS 2.0 EXEC loader also accepts.
pub const ZM_SIGNATURE: [u8; 2] = [b'Z', b'M'];

/// NE header signature.
pub const NE_SIGNATURE: [u8; 2] = [b'N', b'E'];

/// LE header signature.
pub const LE_SIGNATURE: [u8; 2] = [b'L', b'E'];

/// LX header signature.
pub const LX_SIGNATURE: [u8; 2] = [b'L', b'X'];

/// MZ header size.
pub const MZ_HEADER_SIZE: usize = 64;

/// NE header size.
pub const NE_HEADER_SIZE: usize = 64;

/// LE/LX header size.
pub const LE_HEADER_SIZE: usize = 196;

/// Offset of the DOS header field holding the file offset of the new (NE,
/// LE, LX or PE) header.
const E_LFANEW_OFFSET: usize = 0x3C;

/// Length of the LX header fields (IBM LX specification, Figure 2: `00h` to
/// `HEAPSIZE` at `A8h`). The LE header of Windows virtual device drivers
/// extends this to [`LE_HEADER_SIZE`] with Windows-only fields.
const LINEAR_HEADER_SIZE: usize = 0xAC;

/// `B-ORD`/`W-ORD` value for little-endian byte or word ordering.
const ORDER_LITTLE_ENDIAN: u8 = 0;

/// `B-ORD`/`W-ORD` value for big-endian byte or word ordering.
const ORDER_BIG_ENDIAN: u8 = 1;

/// Format level of the initial linear EXE format; each incompatible change
/// increments it.
const LINEAR_FORMAT_LEVEL: u32 = 0;

/// The page size of the linear EXE format: "the page size is 4Kbytes".
const LINEAR_PAGE_SIZE: u32 = 4096;

/// Module type mask of the module flags.
const MODULE_TYPE_MASK: u32 = 0x0003_8000;

/// Module type of a program module (not a library or device driver).
const MODULE_TYPE_PROGRAM: u32 = 0;

/// Module flag: library module (part of the module type).
const MODULE_LIBRARY: u32 = 0x0000_8000;

/// Module type: physical device driver.
const MODULE_PHYSICAL_DRIVER: u32 = 0x0002_0000;

/// Module type: virtual device driver.
const MODULE_VIRTUAL_DRIVER: u32 = 0x0002_8000;

/// Bytes of a linear header behind a stub that must be present: the fields
/// read by [`linear_result`], up to the EIP at `1Ch`.
const LINEAR_MINIMUM_SIZE: usize = 32;

/// Size of an object table entry: virtual size, relocation base address,
/// object flags, page table index, page table entry count and a reserved
/// word.
const OBJECT_ENTRY_SIZE: usize = 24;

/// Size of an LX object page table entry: page data offset (4), data size
/// (2) and flags (2).
const LX_PAGE_ENTRY_SIZE: usize = 8;

/// Size of an LE object page table entry (Open Watcom `le_map_entry`): a
/// 24-bit page number, most significant byte first, and a flags byte.
const LE_PAGE_ENTRY_SIZE: usize = 4;

/// Largest meaningful LX page offset shift: page data offsets are 32-bit.
const MAX_PAGE_OFFSET_SHIFT: u32 = 31;

/// Note added to a PE image whose DOS header starts with [`ZM_SIGNATURE`].
const ZM_NOTE: &str = "DOS header signature is ZM, the byte-swapped MZ that the MS-DOS \
                       loader also accepts; whether PE loaders accept it is not verified";

/// NE target OS values.
pub mod ne_os {
    pub const UNKNOWN: u8 = 0;
    pub const OS2: u8 = 1;
    pub const WINDOWS: u8 = 2;
    pub const DOS4: u8 = 3;
    pub const WINDOWS386: u8 = 4;
    pub const BOSS: u8 = 5;
}

/// LE/LX CPU types.
pub mod le_cpu {
    pub const UNKNOWN: u16 = 0;
    pub const I286: u16 = 1;
    pub const I386: u16 = 2;
    pub const I486: u16 = 3;
    pub const PENTIUM: u16 = 4;
    pub const I860: u16 = 0x20;
    pub const N11: u16 = 0x21;
    pub const MIPS1: u16 = 0x40;
    pub const MIPS2: u16 = 0x41;
    pub const MIPS3: u16 = 0x42;
}

/// LE/LX OS types.
pub mod le_os {
    pub const UNKNOWN: u16 = 0;
    pub const OS2: u16 = 1;
    pub const WINDOWS: u16 = 2;
    pub const DOS4: u16 = 3;
    pub const WINDOWS386: u16 = 4;
    pub const IBM_MVS: u16 = 5;
}

/// Detected extended executable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedType {
    /// Pure DOS MZ executable
    Mz,
    /// NE (New Executable)
    Ne { target_os: u8 },
    /// LE (Linear Executable)
    Le { cpu: u16, os: u16 },
    /// LX (Linear Executable Extended)
    Lx { cpu: u16, os: u16 },
    /// LE header at offset 0, without an MZ stub ([`detect_bare`])
    BareLe {
        /// CPU type field.
        cpu: u16,
        /// OS type field.
        os: u16,
    },
    /// LX header at offset 0, without an MZ stub ([`detect_bare`])
    BareLx {
        /// CPU type field.
        cpu: u16,
        /// OS type field.
        os: u16,
    },
}

impl ExtendedType {
    /// The format a detection reports. A file behind an MZ stub is reported
    /// by its DOS header ([`FileFormat::Mz`], with the extended header as
    /// the variant); a linear header without a stub by its own format.
    pub fn detected_format(self) -> FileFormat {
        match self {
            Self::Mz | Self::Ne { .. } | Self::Le { .. } | Self::Lx { .. } => FileFormat::Mz,
            Self::BareLe { .. } => FileFormat::Le,
            Self::BareLx { .. } => FileFormat::Lx,
        }
    }

    /// Whether the layout is recognized from its structure rather than a
    /// magic value: a header without a stub has only a two-byte signature.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::BareLe { .. } | Self::BareLx { .. })
    }
}

/// The two linear executable header signatures, which share one header
/// layout up to [`LINEAR_HEADER_SIZE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Linear {
    /// `LE`: Windows virtual device drivers and DOS extender programs.
    Le,
    /// `LX`: OS/2 2.x modules.
    Lx,
}

impl Linear {
    /// The layout a header signature names.
    fn from_signature(signature: &[u8]) -> Option<Self> {
        if signature == LE_SIGNATURE {
            Some(Self::Le)
        } else if signature == LX_SIGNATURE {
            Some(Self::Lx)
        } else {
            None
        }
    }

    /// The signature as text.
    fn name(self) -> &'static str {
        match self {
            Self::Le => "LE",
            Self::Lx => "LX",
        }
    }

    /// The format a parsed header reports.
    fn format(self) -> FileFormat {
        match self {
            Self::Le => FileFormat::Le,
            Self::Lx => FileFormat::Lx,
        }
    }

    /// Size of one object page table entry.
    fn page_entry_size(self) -> usize {
        match self {
            Self::Le => LE_PAGE_ENTRY_SIZE,
            Self::Lx => LX_PAGE_ENTRY_SIZE,
        }
    }
}

/// The fields of a validated linear executable header that classification
/// uses.
#[derive(Debug, Clone, Copy)]
struct LinearHeader {
    /// Which signature the header carries.
    layout: Linear,
    /// `B-ORD` and `W-ORD` are both little-endian (otherwise both
    /// big-endian).
    little_endian: bool,
    /// CPU type field.
    cpu: u16,
    /// OS type field.
    os: u16,
}

impl LinearHeader {
    /// The detected type of this header without a stub.
    fn extended_type(self) -> ExtendedType {
        let LinearHeader { cpu, os, .. } = self;
        match self.layout {
            Linear::Le => ExtendedType::BareLe { cpu, os },
            Linear::Lx => ExtendedType::BareLx { cpu, os },
        }
    }
}

/// Build this module's parse error.
fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::MzParseError {
        message: message.into(),
    }
}

/// The `e_lfanew` value of a DOS header when it points at a PE signature
/// (`PE\0\0`). The caller checks the DOS signature.
pub fn pe_header_offset(data: &[u8]) -> Option<u32> {
    if data.len() < MZ_HEADER_SIZE {
        return None;
    }
    let pe_offset = read_u32(data, E_LFANEW_OFFSET, true).ok()?;
    let start = usize::try_from(pe_offset).ok()?;
    let end = start.checked_add(magic::PE.len())?;
    (data.get(start..end)? == magic::PE).then_some(pe_offset)
}

/// Parse a PE image found through its DOS header; a `ZM` DOS signature is
/// noted.
///
/// # Errors
///
/// The errors of [`pe::parse`].
pub fn parse_pe(data: &[u8], pe_offset: u32) -> Result<ClassificationResult> {
    let mut result = pe::parse(data, pe_offset)?;
    if data.starts_with(&ZM_SIGNATURE) {
        result.metadata.notes.push(ZM_NOTE.to_string());
    }
    Ok(result)
}

/// Detect MZ and extended types.
pub fn detect(data: &[u8]) -> Option<ExtendedType> {
    if data.len() < MZ_HEADER_SIZE {
        return None;
    }

    // Check for MZ signature
    if data[0..2] != MZ_SIGNATURE && data[0..2] != ZM_SIGNATURE {
        return None;
    }

    // Check for extended header pointer at offset 0x3C
    let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // Check for extended header if pointer is valid
    if lfanew >= MZ_HEADER_SIZE && fits(data, lfanew, 2) {
        let sig = &data[lfanew..lfanew + 2];

        // Check for NE
        if sig == NE_SIGNATURE && lfanew + NE_HEADER_SIZE <= data.len() {
            let target_os = data[lfanew + 0x36];
            return Some(ExtendedType::Ne { target_os });
        }

        // Check for LE
        if sig == LE_SIGNATURE && lfanew + 12 <= data.len() {
            let cpu = read_u16(data, lfanew + 8, true).ok()?;
            let os = read_u16(data, lfanew + 10, true).ok()?;
            return Some(ExtendedType::Le { cpu, os });
        }

        // Check for LX
        if sig == LX_SIGNATURE && lfanew + 12 <= data.len() {
            let cpu = read_u16(data, lfanew + 8, true).ok()?;
            let os = read_u16(data, lfanew + 10, true).ok()?;
            return Some(ExtendedType::Lx { cpu, os });
        }
    }

    // Pure MZ executable
    Some(ExtendedType::Mz)
}

/// Parse pure MZ (DOS) executable.
fn parse_mz(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MZ_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: MZ_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Parse MZ header fields
    let bytes_last_page = read_u16(data, 2, true)?;
    let pages = read_u16(data, 4, true)?;
    let relocs = read_u16(data, 6, true)?;
    let header_paragraphs = read_u16(data, 8, true)?;
    let _min_alloc = read_u16(data, 10, true)?;
    let _max_alloc = read_u16(data, 12, true)?;
    let ss = read_u16(data, 14, true)?;
    let sp = read_u16(data, 16, true)?;
    let _checksum = read_u16(data, 18, true)?;
    let ip = read_u16(data, 20, true)?;
    let cs = read_u16(data, 22, true)?;
    let reloc_offset = read_u16(data, 24, true)?;
    let overlay = read_u16(data, 26, true)?;

    // Calculate file size
    let file_size = if pages > 0 {
        ((pages - 1) as u32 * 512)
            + if bytes_last_page > 0 {
                bytes_last_page as u32
            } else {
                512
            }
    } else {
        0
    };

    let mut notes = vec!["DOS MZ executable".to_string()];
    notes.push(format!("Entry: {:04X}:{:04X}", cs, ip));
    notes.push(format!("Stack: {:04X}:{:04X}", ss, sp));
    notes.push(format!("Size: {} bytes ({} pages)", file_size, pages));
    notes.push(format!(
        "Relocations: {} at offset 0x{:04X}",
        relocs, reloc_offset
    ));
    notes.push(format!("Header size: {} paragraphs", header_paragraphs));

    if overlay > 0 {
        notes.push(format!("Overlay number: {}", overlay));
    }

    let metadata = ClassificationMetadata {
        entry_point: Some(((cs as u64) << 4) + ip as u64),
        code_size: Some(file_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 16, Endianness::Little, FileFormat::Mz);
    result.variant = Variant::new("DOS real mode");
    result.metadata = metadata;

    Ok(result)
}

/// Parse NE (New Executable).
fn parse_ne(data: &[u8], target_os: u8) -> Result<ClassificationResult> {
    // Find NE header offset
    let lfanew = read_u32(data, 0x3C, true)? as usize;

    if lfanew + NE_HEADER_SIZE > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: lfanew,
            expected: NE_HEADER_SIZE,
            actual: data.len().saturating_sub(lfanew),
        });
    }

    let ne_off = lfanew;

    // Parse NE header
    let linker_major = data[ne_off + 2];
    let linker_minor = data[ne_off + 3];
    let _entry_table_off = read_u16(data, ne_off + 4, true)?;
    let _entry_table_len = read_u16(data, ne_off + 6, true)?;
    let flags = read_u16(data, ne_off + 0x0C, true)?;
    let _auto_data_seg = read_u16(data, ne_off + 0x0E, true)?;
    let _heap_size = read_u16(data, ne_off + 0x10, true)?;
    let _stack_size = read_u16(data, ne_off + 0x12, true)?;
    let entry_point = read_u32(data, ne_off + 0x14, true)?;
    let _initial_stack = read_u32(data, ne_off + 0x18, true)?;
    let segment_count = read_u16(data, ne_off + 0x1C, true)?;

    let os_name = match target_os {
        ne_os::UNKNOWN => "Unknown",
        ne_os::OS2 => "OS/2",
        ne_os::WINDOWS => "Windows",
        ne_os::DOS4 => "DOS 4.x",
        ne_os::WINDOWS386 => "Windows 386",
        ne_os::BOSS => "Borland OS Services",
        _ => "Unknown",
    };

    let module_type = if flags & 0x8000 != 0 {
        "DLL/Driver"
    } else {
        "Executable"
    };

    let mut notes = vec!["NE (New Executable)".to_string()];
    notes.push(format!("Target OS: {}", os_name));
    notes.push(format!("Type: {}", module_type));
    notes.push(format!("Linker: {}.{}", linker_major, linker_minor));
    notes.push(format!("Segments: {}", segment_count));

    if flags & 0x0008 != 0 {
        notes.push("Protected mode only".to_string());
    }

    let cs = (entry_point >> 16) as u16;
    let ip = (entry_point & 0xFFFF) as u16;
    notes.push(format!("Entry: segment {}:0x{:04X}", cs, ip));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry_point as u64),
        section_count: Some(segment_count as usize),
        flags: Some(flags as u32),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 16, Endianness::Little, FileFormat::Ne);
    result.variant = Variant::new(os_name);
    result.metadata = metadata;

    Ok(result)
}

/// Parse LE/LX (Linear Executable) behind an MZ stub.
fn parse_le_lx(data: &[u8], layout: Linear, cpu: u16, os: u16) -> Result<ClassificationResult> {
    let lfanew = read_u32(data, E_LFANEW_OFFSET, true)? as usize;

    // A partial header is accepted as long as the fields read are present.
    if !fits(data, lfanew, LINEAR_MINIMUM_SIZE) {
        return Err(ClassifierError::TruncatedData {
            offset: lfanew,
            expected: LE_HEADER_SIZE,
            actual: data.len().saturating_sub(lfanew),
        });
    }

    // Headers behind a stub are read little-endian whatever `B-ORD` says.
    linear_result(data, lfanew, layout, cpu, os, true)
}

/// Parse an LE/LX header at offset 0 without an MZ stub; the header must
/// validate as [`detect_bare`] requires.
fn parse_bare(data: &[u8], layout: Linear) -> Result<ClassificationResult> {
    let header = bare_header(data)?;
    if header.layout != layout {
        return Err(error(format!(
            "Invalid {} header: the signature is {}",
            layout.name(),
            header.layout.name()
        )));
    }
    let mut result = linear_result(data, 0, layout, header.cpu, header.os, header.little_endian)?;
    result.metadata.notes.push(format!(
        "No MZ stub; the {} header starts at offset 0x0",
        layout.name()
    ));
    Ok(result)
}

/// Classify a linear executable header at `header` from its CPU type and
/// describe its OS type, module type, pages and entry in notes.
///
/// Fields read: `B-ORD` (`02h`), `W-ORD` (`03h`), format level (`04h`),
/// module flags (`10h`), module page count (`14h`), EIP object (`18h`) and
/// EIP (`1Ch`). Truncation errors name the field offset.
fn linear_result(
    data: &[u8],
    header: usize,
    layout: Linear,
    cpu: u16,
    os: u16,
    le: bool,
) -> Result<ClassificationResult> {
    let orders = read_bytes(data, header + 2, 2)?;
    let byte_order = orders[0];
    let word_order = orders[1];
    let _format_level = read_u32(data, header + 4, le)?;
    let module_flags = read_u32(data, header + 0x10, le)?;
    let module_pages = read_u32(data, header + 0x14, le)?;
    let eip_object = read_u32(data, header + 0x18, le)?;
    let eip_offset = read_u32(data, header + 0x1C, le)?;

    // Determine ISA from CPU type
    let (isa, bitwidth) = match cpu {
        le_cpu::I286 => (Isa::X86, 16),
        le_cpu::I386 | le_cpu::I486 | le_cpu::PENTIUM => (Isa::X86, 32),
        le_cpu::MIPS1 | le_cpu::MIPS2 | le_cpu::MIPS3 => (Isa::Mips, 32),
        le_cpu::I860 => (Isa::I860, 32),
        _ => (Isa::X86, 32), // Default to i386
    };

    let os_name = match os {
        le_os::UNKNOWN => "Unknown",
        le_os::OS2 => "OS/2",
        le_os::WINDOWS => "Windows",
        le_os::DOS4 => "DOS 4.x",
        le_os::WINDOWS386 => "Windows 386",
        le_os::IBM_MVS => "IBM MVS",
        _ => "Unknown",
    };

    let cpu_name = match cpu {
        le_cpu::I286 => "80286",
        le_cpu::I386 => "80386",
        le_cpu::I486 => "80486",
        le_cpu::PENTIUM => "Pentium",
        le_cpu::MIPS1 => "MIPS-I",
        le_cpu::MIPS2 => "MIPS-II",
        le_cpu::MIPS3 => "MIPS-III",
        le_cpu::I860 => "i860",
        _ => "Unknown",
    };

    // The library bit is tested before the module type mask is applied, so
    // a virtual device driver (28000h includes 8000h) is reported as a DLL.
    let module_type = if module_flags & MODULE_LIBRARY != 0 {
        "DLL"
    } else if module_flags & MODULE_PHYSICAL_DRIVER != 0 {
        "Physical device driver"
    } else if module_flags & MODULE_VIRTUAL_DRIVER != 0 {
        "Virtual device driver"
    } else {
        "Executable"
    };

    let mut notes = vec![format!("{} (Linear Executable)", layout.name())];
    notes.push(format!("Target OS: {}", os_name));
    notes.push(format!("CPU: {}", cpu_name));
    notes.push(format!("Type: {}", module_type));
    notes.push(format!("Pages: {}", module_pages));
    notes.push(format!("Entry: object {}:0x{:08X}", eip_object, eip_offset));

    if byte_order != 0 || word_order != 0 {
        notes.push(format!(
            "Byte order: {}, Word order: {}",
            if byte_order == 0 { "LE" } else { "BE" },
            if word_order == 0 { "LE" } else { "BE" }
        ));
    }

    let metadata = ClassificationMetadata {
        entry_point: Some(eip_offset as u64),
        flags: Some(module_flags),
        section_count: Some(module_pages as usize),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, Endianness::Little, layout.format());
    result.variant = Variant::new(format!("{} {}", os_name, cpu_name));
    result.metadata = metadata;

    Ok(result)
}

/// Whether `size` bytes at `offset` lie inside `data`.
fn fits(data: &[u8], offset: usize, size: usize) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| end <= data.len())
}

/// Detect an LE or LX header at offset 0 without an MZ stub.
///
/// The signature is only two bytes, so the header, the object table and the
/// object page table must validate completely.
pub fn detect_bare(data: &[u8]) -> Option<ExtendedType> {
    bare_header(data).ok().map(LinearHeader::extended_type)
}

/// Validate an LE/LX header at offset 0 and its object and page tables.
///
/// Header (IBM LX specification, Figure 2; header-relative offsets equal
/// file offsets at offset 0): signature (2), `B-ORD` (1), `W-ORD` (1),
/// format level (4), CPU type (2), OS type (2), module version (4) and flags
/// (4) at `10h`, module page count at `14h`, EIP object and EIP at `18h`,
/// ESP object and ESP at `20h`, page size at `28h`, then the LX page offset
/// shift or the LE last page size at `2Ch`, object table offset and count at
/// `40h`, object page table offset at `48h`, iterated pages offset at `4Ch`
/// and data pages offset at `80h`.
///
/// Only the documented values are accepted: matching byte and word order,
/// format level 0, the 80286, 80386 and 80486 CPU types, OS types 0 to 4 and
/// the 4 KiB page size. The object and page tables must lie in the file,
/// every object's pages must be module pages, the entry and stack objects
/// must exist, a program module must name its entry object, and every
/// page's data must lie in the file. Checksums are not verified: the
/// specification does not define their algorithm.
fn bare_header(data: &[u8]) -> Result<LinearHeader> {
    let layout = data
        .get(..2)
        .and_then(Linear::from_signature)
        .ok_or_else(|| error("Missing LE or LX signature at offset 0x0"))?;
    let name = layout.name();
    if data.len() < LINEAR_HEADER_SIZE {
        return Err(error(format!(
            "Truncated {name} header: {} B of {LINEAR_HEADER_SIZE} B",
            data.len()
        )));
    }
    let le = match (data[2], data[3]) {
        (ORDER_LITTLE_ENDIAN, ORDER_LITTLE_ENDIAN) => true,
        (ORDER_BIG_ENDIAN, ORDER_BIG_ENDIAN) => false,
        (byte_order, word_order) => {
            return Err(error(format!(
                "Invalid {name} byte and word order 0x{byte_order:X}/0x{word_order:X}"
            )))
        }
    };
    let level = read_u32(data, 0x04, le)?;
    if level != LINEAR_FORMAT_LEVEL {
        return Err(error(format!("Unsupported {name} format level {level}")));
    }
    let cpu = read_u16(data, 0x08, le)?;
    if !matches!(cpu, le_cpu::I286 | le_cpu::I386 | le_cpu::I486) {
        return Err(error(format!("Unknown {name} CPU type 0x{cpu:X}")));
    }
    let os = read_u16(data, 0x0A, le)?;
    if os > le_os::WINDOWS386 {
        return Err(error(format!("Unknown {name} OS type 0x{os:X}")));
    }
    let page_size = read_u32(data, 0x28, le)?;
    if page_size != LINEAR_PAGE_SIZE {
        return Err(error(format!("Invalid {name} page size {page_size} B")));
    }

    let object_count = read_u32(data, 0x44, le)?;
    if object_count == 0 {
        return Err(error(format!("Missing {name} objects")));
    }
    let object_table = read_u32(data, 0x40, le)?;
    let objects = table(data, object_table, object_count, OBJECT_ENTRY_SIZE).ok_or_else(|| {
        error(format!(
            "Invalid {name} object table: {object_count} entries at 0x{object_table:X}"
        ))
    })?;
    let module_pages = read_u32(data, 0x14, le)?;
    expect_object_pages(objects, module_pages, le, name)?;
    expect_entry_objects(data, object_count, le, name)?;

    let page_table_offset = read_u32(data, 0x48, le)?;
    let page_table = table(
        data,
        page_table_offset,
        module_pages,
        layout.page_entry_size(),
    )
    .ok_or_else(|| {
        error(format!(
            "Invalid {name} object page table: {module_pages} pages at 0x{page_table_offset:X}"
        ))
    })?;
    let data_pages = read_u32(data, 0x80, le)?;
    if module_pages > 0 && u64::from(data_pages) < LINEAR_HEADER_SIZE as u64 {
        return Err(error(format!(
            "Invalid {name} data pages offset 0x{data_pages:X}"
        )));
    }
    let pages = PageArea {
        data_pages,
        page_fields: read_u32(data, 0x2C, le)?,
        module_pages,
        file_size: data.len(),
    };
    match layout {
        Linear::Lx => expect_lx_pages(page_table, pages, read_u32(data, 0x4C, le)?, le),
        Linear::Le => expect_le_pages(page_table, pages),
    }?;

    Ok(LinearHeader {
        layout,
        little_endian: le,
        cpu,
        os,
    })
}

/// The `count` entries of `entry_size` bytes at `offset`, a table that must
/// follow the header fields; `None` if it does not lie in `data`.
fn table(data: &[u8], offset: u32, count: u32, entry_size: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    if start < LINEAR_HEADER_SIZE && count > 0 {
        return None;
    }
    let size = usize::try_from(count).ok()?.checked_mul(entry_size)?;
    data.get(start..start.checked_add(size)?)
}

/// Every object's pages must be module pages: a nonzero count needs a
/// 1-based page table index whose run ends within the module page count.
fn expect_object_pages(objects: &[u8], module_pages: u32, le: bool, name: &str) -> Result<()> {
    for (i, object) in objects.chunks_exact(OBJECT_ENTRY_SIZE).enumerate() {
        let first = read_u32(object, 0x0C, le)?;
        let count = read_u32(object, 0x10, le)?;
        if count == 0 {
            continue;
        }
        let last = u64::from(first) + u64::from(count) - 1;
        if first == 0 || last > u64::from(module_pages) {
            return Err(error(format!(
                "Invalid {name} object {} pages: index {first}, {count} pages, \
                 module has {module_pages}",
                i + 1
            )));
        }
    }
    Ok(())
}

/// The EIP and ESP objects (`18h`, `20h`) must exist when set, and a program
/// module must name its entry object ("This must be a nonzero value for a
/// program module to be correctly loaded").
fn expect_entry_objects(data: &[u8], object_count: u32, le: bool, name: &str) -> Result<()> {
    let flags = read_u32(data, 0x10, le)?;
    let eip_object = read_u32(data, 0x18, le)?;
    let esp_object = read_u32(data, 0x20, le)?;
    if eip_object > object_count || esp_object > object_count {
        return Err(error(format!(
            "Invalid {name} entry objects: EIP object {eip_object}, ESP object {esp_object}, \
             {object_count} objects"
        )));
    }
    if flags & MODULE_TYPE_MASK == MODULE_TYPE_PROGRAM && eip_object == 0 {
        return Err(error(format!(
            "Missing {name} entry object for a program module"
        )));
    }
    Ok(())
}

/// Where page data lies: the fields both page table layouts need.
#[derive(Debug, Clone, Copy)]
struct PageArea {
    /// Data pages offset (`80h`), relative to the file.
    data_pages: u32,
    /// LX page offset shift or LE last page size (`2Ch`).
    page_fields: u32,
    /// Module page count (`14h`).
    module_pages: u32,
    /// Size of the file in bytes.
    file_size: usize,
}

impl PageArea {
    /// Whether `size` bytes at `offset` from the data pages lie in the file.
    fn holds(self, offset: u64, size: u64) -> bool {
        u64::from(self.data_pages) + offset + size <= self.file_size as u64
    }
}

/// LX pages: page data offset (shifted left by the page offset shift) and
/// data size, both relative to the data pages. Iterated pages are relative
/// to the iterated pages, which OS/2 2.0 requires to be 0 or the data pages
/// offset. Page flags are not checked: IDA's samples carry flag 5, which the
/// 1992 specification does not list.
fn expect_lx_pages(page_table: &[u8], pages: PageArea, iterated: u32, le: bool) -> Result<()> {
    let shift = pages.page_fields;
    if shift > MAX_PAGE_OFFSET_SHIFT {
        return Err(error(format!("Invalid LX page offset shift {shift}")));
    }
    if iterated != 0 && iterated != pages.data_pages {
        return Err(error(format!(
            "Invalid LX iterated pages offset 0x{iterated:X}: data pages are at 0x{:X}",
            pages.data_pages
        )));
    }
    for (i, entry) in page_table.chunks_exact(LX_PAGE_ENTRY_SIZE).enumerate() {
        let offset = u64::from(read_u32(entry, 0, le)?) << shift;
        let size = read_u16(entry, 4, le)?;
        if u32::from(size) > LINEAR_PAGE_SIZE || (size > 0 && !pages.holds(offset, size.into())) {
            return Err(error(format!(
                "Invalid LX page {}: {size} B at data page offset 0x{offset:X}",
                i + 1
            )));
        }
    }
    Ok(())
}

/// LE pages: each entry names a 1-based page of the data pages (0 for none),
/// pages are [`LINEAR_PAGE_SIZE`] bytes and the last one holds the last page
/// size (`2Ch`).
fn expect_le_pages(page_table: &[u8], pages: PageArea) -> Result<()> {
    let last_page_size = pages.page_fields;
    if last_page_size > LINEAR_PAGE_SIZE {
        return Err(error(format!(
            "Invalid LE last page size {last_page_size} B"
        )));
    }
    for (i, entry) in page_table.chunks_exact(LE_PAGE_ENTRY_SIZE).enumerate() {
        let number = u32::from_be_bytes([0, entry[0], entry[1], entry[2]]);
        if number > pages.module_pages {
            return Err(error(format!(
                "Invalid LE page {}: page number {number}, module has {}",
                i + 1,
                pages.module_pages
            )));
        }
    }
    if let Some(full_pages) = pages.module_pages.checked_sub(1) {
        let size = u64::from(full_pages) * u64::from(LINEAR_PAGE_SIZE) + u64::from(last_page_size);
        if !pages.holds(0, size) {
            return Err(error(format!(
                "Truncated LE data pages: {} pages at 0x{:X}",
                pages.module_pages, pages.data_pages
            )));
        }
    }
    Ok(())
}

/// Parse MZ/NE/LE/LX file.
pub fn parse(data: &[u8], ext_type: ExtendedType) -> Result<ClassificationResult> {
    match ext_type {
        ExtendedType::Mz => parse_mz(data),
        ExtendedType::Ne { target_os } => parse_ne(data, target_os),
        ExtendedType::Le { cpu, os } => parse_le_lx(data, Linear::Le, cpu, os),
        ExtendedType::Lx { cpu, os } => parse_le_lx(data, Linear::Lx, cpu, os),
        ExtendedType::BareLe { .. } => parse_bare(data, Linear::Le),
        ExtendedType::BareLx { .. } => parse_bare(data, Linear::Lx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mz_header() -> Vec<u8> {
        let mut data = vec![0u8; 128];
        // MZ signature
        data[0] = b'M';
        data[1] = b'Z';
        // Bytes on last page
        data[2..4].copy_from_slice(&256u16.to_le_bytes());
        // Pages in file
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Relocations
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        // Header paragraphs
        data[8..10].copy_from_slice(&4u16.to_le_bytes());
        // SS
        data[14..16].copy_from_slice(&0u16.to_le_bytes());
        // SP
        data[16..18].copy_from_slice(&0x100u16.to_le_bytes());
        // IP
        data[20..22].copy_from_slice(&0u16.to_le_bytes());
        // CS
        data[22..24].copy_from_slice(&0u16.to_le_bytes());
        // Reloc table offset
        data[24..26].copy_from_slice(&0x40u16.to_le_bytes());
        // lfanew = 0 (pure MZ)
        data[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    fn make_ne_header() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        // MZ stub
        data[0] = b'M';
        data[1] = b'Z';
        // lfanew pointing to NE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // NE header at 0x80
        let ne_off = 0x80;
        data[ne_off] = b'N';
        data[ne_off + 1] = b'E';
        data[ne_off + 2] = 5; // linker major
        data[ne_off + 3] = 0; // linker minor
                              // Target OS
        data[ne_off + 0x36] = ne_os::WINDOWS;
        // Segment count
        data[ne_off + 0x1C..ne_off + 0x1E].copy_from_slice(&4u16.to_le_bytes());

        data
    }

    fn make_le_header(cpu: u16, os: u16) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // MZ stub
        data[0] = b'M';
        data[1] = b'Z';
        // lfanew pointing to LE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // LE header at 0x80
        let le_off = 0x80;
        data[le_off] = b'L';
        data[le_off + 1] = b'E';
        // CPU type
        data[le_off + 8..le_off + 10].copy_from_slice(&cpu.to_le_bytes());
        // OS type
        data[le_off + 10..le_off + 12].copy_from_slice(&os.to_le_bytes());
        // Module pages
        data[le_off + 0x14..le_off + 0x18].copy_from_slice(&10u32.to_le_bytes());
        // EIP object
        data[le_off + 0x18..le_off + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        // EIP offset
        data[le_off + 0x1C..le_off + 0x20].copy_from_slice(&0x1000u32.to_le_bytes());

        data
    }

    #[test]
    fn test_detect_pure_mz() {
        let data = make_mz_header();
        let ext_type = detect(&data);
        assert!(matches!(ext_type, Some(ExtendedType::Mz)));
    }

    #[test]
    fn test_detect_ne() {
        let data = make_ne_header();
        let ext_type = detect(&data);
        assert!(matches!(
            ext_type,
            Some(ExtendedType::Ne {
                target_os: ne_os::WINDOWS
            })
        ));
    }

    #[test]
    fn test_detect_le() {
        let data = make_le_header(le_cpu::I386, le_os::OS2);
        let ext_type = detect(&data);
        assert!(matches!(
            ext_type,
            Some(ExtendedType::Le {
                cpu: le_cpu::I386,
                os: le_os::OS2
            })
        ));
    }

    #[test]
    fn test_parse_mz() {
        let data = make_mz_header();
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 16);
        assert_eq!(result.format, FileFormat::Mz);
    }

    #[test]
    fn test_parse_ne() {
        let data = make_ne_header();
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 16);
        assert_eq!(result.format, FileFormat::Ne);
    }

    #[test]
    fn test_parse_le() {
        let data = make_le_header(le_cpu::I386, le_os::OS2);
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Le);
    }

    /// A DOS header whose `e_lfanew` is `lfanew`, in a 128-byte file.
    fn dos_header(signature: [u8; 2], lfanew: u32) -> Vec<u8> {
        let mut data = make_mz_header();
        data[..2].copy_from_slice(&signature);
        data[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&lfanew.to_le_bytes());
        data
    }

    #[test]
    fn fits_rejects_ranges_that_overflow_or_pass_the_end() {
        let data = [0u8; 4];
        assert!(fits(&data, 2, 2));
        assert!(fits(&data, 4, 0));
        assert!(!fits(&data, 3, 2));
        assert!(!fits(&data, usize::MAX, 1));
    }

    #[test]
    fn pe_header_offset_needs_the_whole_signature_inside_the_file() {
        let mut data = dos_header(MZ_SIGNATURE, 0x40);
        data[0x40..0x44].copy_from_slice(&magic::PE);
        assert_eq!(pe_header_offset(&data), Some(0x40));
        assert_eq!(pe_header_offset(&data[..0x43]), None);
        assert_eq!(pe_header_offset(&dos_header(MZ_SIGNATURE, 0x7E)), None);
        assert_eq!(pe_header_offset(&dos_header(MZ_SIGNATURE, u32::MAX)), None);
    }

    #[test]
    fn extended_header_offsets_at_the_top_of_the_range_are_plain_mz() {
        for lfanew in [u32::MAX, u32::MAX - 1, 0x7F] {
            assert_eq!(
                detect(&dos_header(MZ_SIGNATURE, lfanew)),
                Some(ExtendedType::Mz)
            );
        }
    }

    #[test]
    fn linear_signatures_name_their_layout() {
        assert_eq!(Linear::from_signature(b"LE"), Some(Linear::Le));
        assert_eq!(Linear::from_signature(b"LX"), Some(Linear::Lx));
        assert_eq!(Linear::from_signature(b"NE"), None);
        assert_eq!(Linear::Le.page_entry_size(), LE_PAGE_ENTRY_SIZE);
        assert_eq!(Linear::Lx.page_entry_size(), LX_PAGE_ENTRY_SIZE);
    }

    #[test]
    fn tables_must_follow_the_header_fields_and_fit_the_file() {
        let data = vec![0u8; LINEAR_HEADER_SIZE + 2 * OBJECT_ENTRY_SIZE];
        let at = u32::try_from(LINEAR_HEADER_SIZE).expect("the header size fits");
        assert_eq!(
            table(&data, at, 2, OBJECT_ENTRY_SIZE).map(<[u8]>::len),
            Some(48)
        );
        assert_eq!(table(&data, at, 3, OBJECT_ENTRY_SIZE), None);
        assert_eq!(table(&data, 0x10, 1, OBJECT_ENTRY_SIZE), None);
        assert_eq!(table(&data, 0, 0, OBJECT_ENTRY_SIZE), Some(&[][..]));
        assert_eq!(table(&data, at, u32::MAX, OBJECT_ENTRY_SIZE), None);
        assert_eq!(table(&data, u32::MAX, 1, OBJECT_ENTRY_SIZE), None);
    }

    #[test]
    fn stubbed_and_bare_types_report_their_detection_format_and_strength() {
        let stubbed = ExtendedType::Lx { cpu: 2, os: 1 };
        let bare = ExtendedType::BareLx { cpu: 2, os: 1 };
        assert_eq!(stubbed.detected_format(), FileFormat::Mz);
        assert!(!stubbed.is_weak());
        assert_eq!(bare.detected_format(), FileFormat::Lx);
        assert!(bare.is_weak());
        assert_eq!(
            ExtendedType::BareLe { cpu: 2, os: 4 }.detected_format(),
            FileFormat::Le
        );
    }
}
