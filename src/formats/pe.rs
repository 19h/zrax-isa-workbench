//! PE/COFF (Portable Executable) parser.
//!
//! Comprehensive PE parser supporting all machine types including
//! modern architectures like ARM64, ARM64EC, and RISC-V.
//!
//! Hybrid ARM64EC and ARM64X images are told apart by the CHPE metadata
//! that the load configuration points to, as LLVM reads it (llvm-project
//! tag `llvmorg-19.1.0`, `llvm/include/llvm/Object/COFF.h`:
//! `coff_load_configuration64::CHPEMetadataPointer`, `chpe_metadata`,
//! `chpe_range_entry`, and `COFFObjectFile::getMachine`, which reports an
//! AMD64 image with CHPE metadata as ARM64EC and an ARM64 one as ARM64X).

use crate::error::{ClassifierError, Result};
use crate::formats::{field_name, read_u16, read_u32, read_u64, NamedRange};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// PE machine type constants.
pub mod machine {
    pub const UNKNOWN: u16 = 0x0000;
    pub const I386: u16 = 0x014C;
    pub const R3000: u16 = 0x0162;
    pub const R4000: u16 = 0x0166;
    pub const R10000: u16 = 0x0168;
    pub const WCEMIPSV2: u16 = 0x0169;
    pub const ALPHA: u16 = 0x0184;
    pub const SH3: u16 = 0x01A2;
    pub const SH3DSP: u16 = 0x01A3;
    pub const SH3E: u16 = 0x01A4;
    pub const SH4: u16 = 0x01A6;
    pub const SH5: u16 = 0x01A8;
    pub const ARM: u16 = 0x01C0;
    pub const THUMB: u16 = 0x01C2;
    pub const ARMNT: u16 = 0x01C4;
    pub const AM33: u16 = 0x01D3;
    pub const POWERPC: u16 = 0x01F0;
    pub const POWERPCFP: u16 = 0x01F1;
    /// Big-endian PowerPC (Xbox 360).
    pub const POWERPCBE: u16 = 0x01F2;
    pub const IA64: u16 = 0x0200;
    pub const MIPS16: u16 = 0x0266;
    pub const ALPHA64: u16 = 0x0284;
    pub const MIPSFPU: u16 = 0x0366;
    pub const MIPSFPU16: u16 = 0x0466;
    pub const TRICORE: u16 = 0x0520;
    pub const EBC: u16 = 0x0EBC;
    pub const RISCV32: u16 = 0x5032;
    pub const RISCV64: u16 = 0x5064;
    pub const RISCV128: u16 = 0x5128;
    pub const LOONGARCH32: u16 = 0x6232;
    pub const LOONGARCH64: u16 = 0x6264;
    pub const AMD64: u16 = 0x8664;
    pub const M32R: u16 = 0x9041;
    pub const ARM64EC: u16 = 0xA641;
    pub const ARM64X: u16 = 0xA64E;
    pub const ARM64: u16 = 0xAA64;
}

/// Map PE machine type to ISA.
pub fn machine_to_isa(machine: u16) -> (Isa, u8, Endianness, Option<&'static str>) {
    match machine {
        machine::UNKNOWN => (Isa::Unknown(0), 0, Endianness::Little, None),

        machine::I386 => (Isa::X86, 32, Endianness::Little, None),

        machine::R3000 => (Isa::Mips, 32, Endianness::Little, Some("R3000")),
        machine::R4000 => (Isa::Mips, 32, Endianness::Little, Some("R4000")),
        machine::R10000 => (Isa::Mips, 32, Endianness::Little, Some("R10000")),
        machine::WCEMIPSV2 => (Isa::Mips, 32, Endianness::Little, Some("WCE-v2")),
        machine::MIPS16 => (Isa::Mips, 32, Endianness::Little, Some("MIPS16")),
        machine::MIPSFPU => (Isa::Mips, 32, Endianness::Little, Some("FPU")),
        machine::MIPSFPU16 => (Isa::Mips, 32, Endianness::Little, Some("MIPS16-FPU")),

        machine::ALPHA => (Isa::Alpha, 64, Endianness::Little, None),
        machine::ALPHA64 => (Isa::Alpha, 64, Endianness::Little, Some("AXP64")),

        machine::SH3 => (Isa::Sh, 32, Endianness::Little, Some("SH-3")),
        machine::SH3DSP => (Isa::Sh, 32, Endianness::Little, Some("SH-3 DSP")),
        machine::SH3E => (Isa::Sh, 32, Endianness::Little, Some("SH-3E")),
        machine::SH4 => (Isa::Sh4, 32, Endianness::Little, Some("SH-4")),
        machine::SH5 => (Isa::Sh, 64, Endianness::Little, Some("SH-5")),

        machine::ARM => (Isa::Arm, 32, Endianness::Little, None),
        machine::THUMB => (Isa::Arm, 32, Endianness::Little, Some("Thumb")),
        machine::ARMNT => (Isa::Arm, 32, Endianness::Little, Some("Thumb-2")),

        machine::AM33 => (Isa::Unknown(0x01D3), 32, Endianness::Little, Some("AM33")),

        machine::POWERPC => (Isa::Ppc, 32, Endianness::Little, None),
        machine::POWERPCFP => (Isa::Ppc, 32, Endianness::Little, Some("FP")),
        machine::POWERPCBE => (Isa::Ppc, 32, Endianness::Big, Some("Xbox 360")),

        machine::IA64 => (Isa::Ia64, 64, Endianness::Little, None),

        machine::TRICORE => (Isa::Tricore, 32, Endianness::Little, None),

        machine::EBC => (Isa::Ebc, 64, Endianness::Little, None),

        machine::RISCV32 => (Isa::RiscV32, 32, Endianness::Little, None),
        machine::RISCV64 => (Isa::RiscV64, 64, Endianness::Little, None),
        machine::RISCV128 => (Isa::RiscV128, 128, Endianness::Little, None),

        machine::LOONGARCH32 => (Isa::LoongArch32, 32, Endianness::Little, None),
        machine::LOONGARCH64 => (Isa::LoongArch64, 64, Endianness::Little, None),

        machine::AMD64 => (Isa::X86_64, 64, Endianness::Little, None),

        machine::M32R => (Isa::M32r, 32, Endianness::Little, None),

        machine::ARM64EC => (Isa::AArch64, 64, Endianness::Little, Some("ARM64EC")),
        machine::ARM64X => (Isa::AArch64, 64, Endianness::Little, Some("ARM64X")),
        machine::ARM64 => (Isa::AArch64, 64, Endianness::Little, None),

        other => (Isa::Unknown(other as u32), 32, Endianness::Little, None),
    }
}

/// PE optional header magic values.
pub mod optional_magic {
    pub const PE32: u16 = 0x10B;
    pub const PE32PLUS: u16 = 0x20B;
    pub const ROM: u16 = 0x107;
}

/// Parse PE/COFF file.
pub fn parse(data: &[u8], pe_offset: u32) -> Result<ClassificationResult> {
    let pe_off = pe_offset as usize;

    // Verify PE signature
    if pe_off + 4 > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: pe_off,
            expected: 4,
            actual: data.len().saturating_sub(pe_off),
        });
    }

    if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
        return Err(ClassifierError::InvalidMagic {
            expected: "PE\\0\\0".to_string(),
            actual: format!("{:02X?}", &data[pe_off..pe_off + 4]),
        });
    }

    // COFF header starts at PE + 4
    let coff_off = pe_off + 4;

    if coff_off + 20 > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: coff_off,
            expected: 20,
            actual: data.len().saturating_sub(coff_off),
        });
    }

    // Read COFF header fields
    let machine = read_u16(data, coff_off, true)?;
    let num_sections = read_u16(data, coff_off + 2, true)?;
    let size_of_optional = read_u16(data, coff_off + 16, true)?;

    // Map machine to ISA
    let (isa, bitwidth, endianness, variant_note) = machine_to_isa(machine);

    // Read optional header if present
    let mut entry_point = None;
    let mut is_pe32plus = false;

    if size_of_optional > 0 {
        let opt_off = coff_off + 20;
        if opt_off + 2 <= data.len() {
            let magic = read_u16(data, opt_off, true)?;
            is_pe32plus = magic == optional_magic::PE32PLUS;

            // Entry point is at different offset based on format
            if opt_off + 24 <= data.len() {
                let ep = read_u32(data, opt_off + 16, true)?;
                entry_point = Some(ep as u64);
            }
        }
    }

    // Determine actual bitwidth from PE32+
    let actual_bitwidth = if is_pe32plus && bitwidth < 64 {
        64
    } else {
        bitwidth
    };

    // Build variant
    let variant = match variant_note {
        Some(note) => Variant::new(note),
        None => Variant::default(),
    };

    // Build metadata
    let metadata = ClassificationMetadata {
        entry_point,
        section_count: Some(num_sections as usize),
        raw_machine: Some(machine as u32),
        notes: if is_pe32plus {
            vec!["PE32+ format".to_string()]
        } else {
            vec!["PE32 format".to_string()]
        },
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, actual_bitwidth, endianness, FileFormat::Pe);
    result.variant = variant;
    result.metadata = metadata;

    // .NET: an IL-only assembly is CIL bytecode whatever the COFF machine says
    // (AnyCPU assemblies are stamped i386).
    if size_of_optional > 0 {
        match clr_flags(data, coff_off + 20, size_of_optional, num_sections, is_pe32plus) {
            Some(flags) if flags & COMIMAGE_FLAGS_ILONLY != 0 => {
                result.isa = Isa::Clr;
                result.bitwidth = 32;
                result.variant = Variant::new(".NET IL-only");
                result.metadata.notes.push(format!(
                    ".NET assembly (IL-only); PE machine is {}",
                    machine_description(machine)
                ));
            }
            Some(_) => result
                .metadata
                .notes
                .push("Mixed-mode .NET assembly (CIL plus native code)".to_string()),
            None => {}
        }
    }

    // ARM64EC images carry the AMD64 machine value so that x64 code can load
    // them, and ARM64X images the ARM64 one; CHPE metadata marks both.
    if is_pe32plus && matches!(machine, machine::AMD64 | machine::ARM64) {
        let headers = OptionalHeader {
            offset: coff_off + 20,
            size: usize::from(size_of_optional),
        };
        let sections = SectionTable {
            offset: headers.offset + headers.size,
            count: num_sections,
        };
        apply_chpe(
            &mut result,
            machine,
            chpe_metadata(data, &headers, &sections),
        );
    }

    Ok(result)
}

/// A PE32+ optional header: its file offset and `SizeOfOptionalHeader`.
struct OptionalHeader {
    offset: usize,
    size: usize,
}

/// PE32+ optional header offsets: `ImageBase`, `NumberOfRvaAndSizes` and
/// the data directories.
const PE32PLUS_IMAGE_BASE: usize = 24;
const PE32PLUS_DIRECTORY_COUNT: usize = 108;
const PE32PLUS_DIRECTORIES: usize = 112;

/// Size of a data directory entry (`VirtualAddress`, `Size`).
const DATA_DIRECTORY_SIZE: usize = 8;

/// Data directory index of the load configuration table.
const LOAD_CONFIG_DIRECTORY: usize = 10;

/// Offset of `CHPEMetadataPointer` (a virtual address) in
/// `IMAGE_LOAD_CONFIG_DIRECTORY64`, whose first field `Size` says how much
/// of the structure is present.
const LOAD_CONFIG64_CHPE_METADATA: usize = 0xC8;

/// `chpe_metadata`: `Version`, then the code map RVA and entry count.
const CHPE_CODE_MAP: usize = 4;
const CHPE_CODE_MAP_COUNT: usize = 8;

/// `chpe_range_entry`: `StartOffset`, whose two low bits hold the range
/// type, and `Length`.
const CHPE_RANGE_ENTRY_SIZE: usize = 8;
const CHPE_RANGE_TYPE_MASK: u32 = 3;

/// `chpe_range_type` values.
const CHPE_RANGE_ARM64: u32 = 0;
const CHPE_RANGE_ARM64EC: u32 = 1;
const CHPE_RANGE_AMD64: u32 = 2;

/// What the CHPE code map of a hybrid image lists, in bytes per range type.
#[derive(Debug, Default, PartialEq, Eq)]
struct ChpeCodeMap {
    version: u32,
    ranges: u32,
    arm64: u64,
    arm64ec: u64,
    amd64: u64,
}

/// The CHPE metadata of a PE32+ image.
#[derive(Debug, PartialEq, Eq)]
enum Chpe {
    /// No load configuration, one too short to hold the pointer, or a zero
    /// `CHPEMetadataPointer`: not a hybrid image.
    Absent,
    /// A nonzero pointer whose metadata or code map is not in the file.
    Unreadable {
        /// The `CHPEMetadataPointer` virtual address.
        pointer: u64,
    },
    Present(ChpeCodeMap),
}

/// The CHPE metadata the load configuration of a PE32+ image points to.
fn chpe_metadata(data: &[u8], headers: &OptionalHeader, sections: &SectionTable) -> Chpe {
    let Some(pointer) = chpe_pointer(data, headers, sections) else {
        return Chpe::Absent;
    };
    let image_base = read_u64(data, headers.offset + PE32PLUS_IMAGE_BASE, true).ok();
    let code_map = image_base
        .and_then(|base| pointer.checked_sub(base))
        .and_then(|rva| u32::try_from(rva).ok())
        .and_then(|rva| sections.file_offset(data, rva))
        .and_then(|offset| chpe_code_map(data, sections, offset));
    match code_map {
        Some(code_map) => Chpe::Present(code_map),
        None => Chpe::Unreadable { pointer },
    }
}

/// A nonzero `CHPEMetadataPointer` from the load configuration directory.
fn chpe_pointer(data: &[u8], headers: &OptionalHeader, sections: &SectionTable) -> Option<u64> {
    let count = read_u32(data, headers.offset + PE32PLUS_DIRECTORY_COUNT, true).ok()?;
    let entry = PE32PLUS_DIRECTORIES + LOAD_CONFIG_DIRECTORY * DATA_DIRECTORY_SIZE;
    if count as usize <= LOAD_CONFIG_DIRECTORY || entry + DATA_DIRECTORY_SIZE > headers.size {
        return None;
    }
    let rva = read_u32(data, headers.offset + entry, true).ok()?;
    if rva == 0 {
        return None;
    }
    let config = sections.file_offset(data, rva)?;
    let config_size = read_u32(data, config, true).ok()? as usize;
    if config_size < LOAD_CONFIG64_CHPE_METADATA + 8 {
        return None;
    }
    let pointer = read_u64(data, config.checked_add(LOAD_CONFIG64_CHPE_METADATA)?, true).ok()?;
    (pointer != 0).then_some(pointer)
}

/// The code map of the CHPE metadata at file offset `metadata`. Every
/// entry must be in the file.
fn chpe_code_map(data: &[u8], sections: &SectionTable, metadata: usize) -> Option<ChpeCodeMap> {
    let version = read_u32(data, metadata, true).ok()?;
    let map_rva = read_u32(data, metadata.checked_add(CHPE_CODE_MAP)?, true).ok()?;
    let ranges = read_u32(data, metadata.checked_add(CHPE_CODE_MAP_COUNT)?, true).ok()?;
    let mut code_map = ChpeCodeMap {
        version,
        ranges,
        ..ChpeCodeMap::default()
    };
    if ranges == 0 {
        return Some(code_map);
    }
    let map = sections.file_offset(data, map_rva)?;
    let map_size = (ranges as usize).checked_mul(CHPE_RANGE_ENTRY_SIZE)?;
    let entries = data.get(map..map.checked_add(map_size)?)?;
    for entry in entries.chunks_exact(CHPE_RANGE_ENTRY_SIZE) {
        let start = read_u32(entry, 0, true).ok()?;
        let length = u64::from(read_u32(entry, 4, true).ok()?);
        let total = match start & CHPE_RANGE_TYPE_MASK {
            CHPE_RANGE_ARM64 => &mut code_map.arm64,
            CHPE_RANGE_ARM64EC => &mut code_map.arm64ec,
            CHPE_RANGE_AMD64 => &mut code_map.amd64,
            _ => continue,
        };
        *total = total.saturating_add(length);
    }
    Some(code_map)
}

/// Report a hybrid image under its hybrid machine type, with the code map
/// in a note.
fn apply_chpe(result: &mut ClassificationResult, machine: u16, chpe: Chpe) {
    let hybrid = if machine == machine::AMD64 {
        machine::ARM64EC
    } else {
        machine::ARM64X
    };
    match chpe {
        Chpe::Absent => {}
        Chpe::Unreadable { pointer } => result.metadata.notes.push(format!(
            "CHPE metadata pointer 0x{pointer:X} does not lead to a code map in the file; \
             the image is reported by its machine field"
        )),
        Chpe::Present(code_map) => {
            let (isa, bitwidth, endianness, variant) = machine_to_isa(hybrid);
            result.isa = isa;
            result.bitwidth = bitwidth;
            result.endianness = endianness;
            result.variant = Variant::new(variant.unwrap_or_default());
            result.metadata.notes.push(format!(
                "Hybrid {} image: CHPE metadata version {}, PE machine {}; code map: \
                 {} B ARM64EC, {} B ARM64 and {} B x64 code in {} ranges",
                machine_description(hybrid),
                code_map.version,
                machine_description(machine),
                code_map.arm64ec,
                code_map.arm64,
                code_map.amd64,
                code_map.ranges
            ));
        }
    }
}

/// COR20 header flag: the image contains only CIL.
const COMIMAGE_FLAGS_ILONLY: u32 = 0x1;

/// Size of a section table entry.
const SECTION_HEADER_SIZE: usize = 40;

/// The Windows loader's section limit ("PE Format", "COFF File Header").
const MAX_SECTIONS: u16 = 96;

/// The section table: `count` headers at file offset `offset`.
struct SectionTable {
    offset: usize,
    count: u16,
}

impl SectionTable {
    /// The file offset that holds `rva`: the first section whose
    /// `VirtualAddress` to `VirtualAddress + max(VirtualSize,
    /// SizeOfRawData)` contains it, mapped through its `PointerToRawData`.
    /// Section header fields come from the file, so the sums are computed
    /// in `u64` and never wrap.
    fn file_offset(&self, data: &[u8], rva: u32) -> Option<usize> {
        (0..usize::from(self.count.min(MAX_SECTIONS))).find_map(|index| {
            let header = self.offset.checked_add(index * SECTION_HEADER_SIZE)?;
            let virtual_size = read_u32(data, header + 8, true).ok()?;
            let virtual_address = read_u32(data, header + 12, true).ok()?;
            let raw_size = read_u32(data, header + 16, true).ok()?;
            let raw_offset = read_u32(data, header + 20, true).ok()?;
            let end = u64::from(virtual_address) + u64::from(virtual_size.max(raw_size));
            if rva < virtual_address || u64::from(rva) >= end {
                return None;
            }
            let offset = u64::from(rva - virtual_address) + u64::from(raw_offset);
            usize::try_from(offset).ok()
        })
    }
}

/// Flags of the CLR (COR20) header, if the image has one.
fn clr_flags(data: &[u8], opt_off: usize, opt_size: u16, num_sections: u16, pe32plus: bool) -> Option<u32> {
    // Data directory 14 = COM descriptor.
    let dirs = opt_off + if pe32plus { 112 } else { 96 };
    let count = read_u32(data, opt_off + if pe32plus { 108 } else { 92 }, true).ok()?;
    if count <= 14 || dirs + 15 * 8 > opt_off + opt_size as usize {
        return None;
    }
    let rva = read_u32(data, dirs + 14 * 8, true).ok()?;
    let size = read_u32(data, dirs + 14 * 8 + 4, true).ok()?;
    if rva == 0 || size < 72 {
        return None;
    }
    let sections = SectionTable {
        offset: opt_off + opt_size as usize,
        count: num_sections,
    };
    let file_off = sections.file_offset(data, rva)?;
    read_u32(data, file_off.checked_add(16)?, true).ok()
}

/// `IMAGE_DIRECTORY_ENTRY_SECURITY`: the attribute certificate table. Its
/// `VirtualAddress` is a file offset, not an RVA ("PE Format", "The
/// Attribute Certificate Table (Image Only)").
const SECURITY_DIRECTORY: usize = 4;

/// PE32 optional header offsets: `NumberOfRvaAndSizes` and the data
/// directories.
const PE32_DIRECTORY_COUNT: usize = 92;
const PE32_DIRECTORIES: usize = 96;

/// `WIN_CERTIFICATE`: `dwLength` (4, including this header), `wRevision`
/// (2), `wCertificateType` (2), then `bCertificate`. Entries start on
/// 8-byte boundaries.
const WIN_CERTIFICATE_HEADER: usize = 8;
const WIN_CERTIFICATE_ALIGN: usize = 8;

/// `wCertificateType` values.
const WIN_CERT_TYPE_X509: u16 = 1;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 2;
const WIN_CERT_TYPE_RESERVED_1: u16 = 3;
const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 4;

/// Attribute certificates read from one table.
const MAX_ATTRIBUTE_CERTIFICATES: usize = 4096;

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The COFF header fields that locate the optional header, the data
/// directories and the section table.
struct ImageHeaders {
    optional: OptionalHeader,
    pe32plus: bool,
    sections: SectionTable,
}

/// COFF header at `pe_offset + 4`: `NumberOfSections` at 2 and
/// `SizeOfOptionalHeader` at 16; the optional header follows at 20 and
/// starts with its magic.
fn image_headers(data: &[u8], pe_offset: u32) -> Option<ImageHeaders> {
    let signature = usize::try_from(pe_offset).ok()?;
    let coff = signature.checked_add(4)?;
    if data.get(signature..coff)? != b"PE\0\0" {
        return None;
    }
    let count = le_u16(data, coff.checked_add(2)?)?;
    let size = usize::from(le_u16(data, coff.checked_add(16)?)?);
    let offset = coff.checked_add(20)?;
    let pe32plus = size >= 2 && le_u16(data, offset)? == optional_magic::PE32PLUS;
    Some(ImageHeaders {
        optional: OptionalHeader { offset, size },
        pe32plus,
        sections: SectionTable {
            offset: offset.checked_add(size)?,
            count,
        },
    })
}

/// Section headers with stored bytes: the 8-byte `Name` (shown as text, not
/// resolved through the COFF string table), and `PointerToRawData` and
/// `SizeOfRawData`, clipped to the input. At most 96 sections are read.
pub fn sections(data: &[u8], pe_offset: u32) -> Vec<NamedRange> {
    let Some(headers) = image_headers(data, pe_offset) else {
        return Vec::new();
    };
    let table = headers.sections;
    (0..usize::from(table.count.min(MAX_SECTIONS)))
        .filter_map(|index| {
            let header = table.offset.checked_add(index * SECTION_HEADER_SIZE)?;
            let name = data.get(header..header.checked_add(SECTION_HEADER_SIZE)?)?;
            let raw_size = le_u32(data, header + 16)?;
            let raw_offset = le_u32(data, header + 20)?;
            NamedRange::clipped(
                field_name(&name[..8]),
                u64::from(raw_offset),
                u64::from(raw_size),
                data.len(),
            )
        })
        .collect()
}

fn certificate_type_name(certificate_type: u16) -> String {
    match certificate_type {
        WIN_CERT_TYPE_X509 => "X.509".to_string(),
        WIN_CERT_TYPE_PKCS_SIGNED_DATA => "PKCS #7 SignedData".to_string(),
        WIN_CERT_TYPE_RESERVED_1 => "reserved".to_string(),
        WIN_CERT_TYPE_TS_STACK_SIGNED => "terminal server stack".to_string(),
        other => format!("type 0x{other:04X}"),
    }
}

/// The attribute certificate table, followed by each `WIN_CERTIFICATE`
/// entry in it. The table is clipped to the input; an entry whose
/// `dwLength` is shorter than its header or leaves the table ends the walk.
/// The certificates are located, not verified.
pub fn attribute_certificates(data: &[u8], pe_offset: u32) -> Vec<NamedRange> {
    let Some(headers) = image_headers(data, pe_offset) else {
        return Vec::new();
    };
    let (count_field, directories) = if headers.pe32plus {
        (PE32PLUS_DIRECTORY_COUNT, PE32PLUS_DIRECTORIES)
    } else {
        (PE32_DIRECTORY_COUNT, PE32_DIRECTORIES)
    };
    let entry = directories + SECURITY_DIRECTORY * DATA_DIRECTORY_SIZE;
    let optional = &headers.optional;
    let present = le_u32(data, optional.offset.saturating_add(count_field))
        .is_some_and(|count| count as usize > SECURITY_DIRECTORY);
    if !present || entry + DATA_DIRECTORY_SIZE > optional.size {
        return Vec::new();
    }
    let Some(offset) = le_u32(data, optional.offset + entry) else {
        return Vec::new();
    };
    let Some(size) = le_u32(data, optional.offset + entry + 4) else {
        return Vec::new();
    };
    let table = NamedRange::clipped(
        "attribute certificate table".to_string(),
        u64::from(offset),
        u64::from(size),
        data.len(),
    );
    let Some(table) = table else {
        return Vec::new();
    };
    let (Ok(mut pos), Ok(end)) = (
        usize::try_from(table.offset),
        usize::try_from(table.offset + table.size),
    ) else {
        return Vec::new();
    };
    let mut ranges = vec![table];
    while ranges.len() <= MAX_ATTRIBUTE_CERTIFICATES {
        let Some(length) = le_u32(data, pos).map(|n| n as usize) else {
            break;
        };
        let Some(entry_end) = pos.checked_add(length) else {
            break;
        };
        if length < WIN_CERTIFICATE_HEADER || entry_end > end {
            break;
        }
        let certificate_type = le_u16(data, pos + 6).unwrap_or_default();
        let kind = certificate_type_name(certificate_type);
        ranges.push(NamedRange {
            name: format!("WIN_CERTIFICATE ({kind})"),
            offset: pos as u64,
            size: length as u64,
        });
        let Some(padded) = entry_end.checked_add(WIN_CERTIFICATE_ALIGN - 1) else {
            break;
        };
        pos = padded & !(WIN_CERTIFICATE_ALIGN - 1);
    }
    ranges
}

/// Get a human-readable description of a PE machine type.
pub fn machine_description(machine: u16) -> &'static str {
    match machine {
        machine::UNKNOWN => "Unknown machine",
        machine::I386 => "Intel 386 or later",
        machine::R3000 => "MIPS R3000",
        machine::R4000 => "MIPS R4000",
        machine::R10000 => "MIPS R10000",
        machine::WCEMIPSV2 => "MIPS WCE v2",
        machine::ALPHA => "DEC Alpha",
        machine::SH3 => "Hitachi SH-3",
        machine::SH3DSP => "Hitachi SH-3 DSP",
        machine::SH3E => "Hitachi SH-3E",
        machine::SH4 => "Hitachi SH-4",
        machine::SH5 => "Hitachi SH-5",
        machine::ARM => "ARM little endian",
        machine::THUMB => "ARM Thumb",
        machine::ARMNT => "ARM Thumb-2 (WinRT)",
        machine::AM33 => "Matsushita AM33",
        machine::POWERPC => "PowerPC little endian",
        machine::POWERPCFP => "PowerPC with FPU",
        machine::IA64 => "Intel IA-64",
        machine::MIPS16 => "MIPS16",
        machine::ALPHA64 => "DEC Alpha 64-bit",
        machine::MIPSFPU => "MIPS with FPU",
        machine::MIPSFPU16 => "MIPS16 with FPU",
        machine::TRICORE => "Infineon TriCore",
        machine::EBC => "EFI Byte Code",
        machine::RISCV32 => "RISC-V 32-bit",
        machine::RISCV64 => "RISC-V 64-bit",
        machine::RISCV128 => "RISC-V 128-bit",
        machine::LOONGARCH32 => "LoongArch 32-bit",
        machine::LOONGARCH64 => "LoongArch 64-bit",
        machine::AMD64 => "AMD64 / x86-64",
        machine::M32R => "Mitsubishi M32R",
        machine::ARM64EC => "ARM64EC (x64 emulation)",
        machine::ARM64X => "ARM64X (hybrid)",
        machine::ARM64 => "ARM64 / AArch64",
        _ => "Unknown machine type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_header(machine: u16) -> Vec<u8> {
        let mut data = vec![0u8; 256];

        // DOS stub
        data[0] = b'M';
        data[1] = b'Z';

        // PE offset at 0x3C
        data[0x3C] = 0x80;

        // PE signature at 0x80
        let pe_off = 0x80;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");

        // COFF header
        let coff_off = pe_off + 4;
        data[coff_off] = (machine & 0xFF) as u8;
        data[coff_off + 1] = (machine >> 8) as u8;

        // Number of sections
        data[coff_off + 2] = 3;

        // Size of optional header
        data[coff_off + 16] = 0xF0;

        // Optional header magic (PE32+)
        let opt_off = coff_off + 20;
        data[opt_off] = 0x0B;
        data[opt_off + 1] = 0x02;

        data
    }

    #[test]
    fn test_parse_x64_pe() {
        let data = make_pe_header(machine::AMD64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64_pe() {
        let data = make_pe_header(machine::ARM64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64ec_pe() {
        let data = make_pe_header(machine::ARM64EC);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert!(result.variant.name.contains("ARM64EC"));
    }

    #[test]
    fn test_parse_riscv_pe() {
        let data = make_pe_header(machine::RISCV64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
    }

    /// A PE32+ image whose data directory 14 (COM descriptor) points at
    /// `clr_rva`, with one section header (`VirtualSize`, `VirtualAddress`,
    /// `SizeOfRawData`, `PointerToRawData`) after the 0xF0-byte optional
    /// header.
    fn pe_with_clr_directory(clr_rva: u32, section: [u32; 4]) -> Vec<u8> {
        let mut data = make_pe_header(machine::AMD64);
        data.resize(0x400, 0);
        let opt_off = 0x80 + 4 + 20;
        data[0x80 + 4 + 2] = 1;
        data[opt_off + 108..opt_off + 112].copy_from_slice(&16u32.to_le_bytes());
        let com = opt_off + 112 + 14 * 8;
        data[com..com + 4].copy_from_slice(&clr_rva.to_le_bytes());
        data[com + 4..com + 8].copy_from_slice(&72u32.to_le_bytes());
        let header = opt_off + 0xF0;
        for (i, value) in section.iter().enumerate() {
            let at = header + 8 + i * 4;
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    #[test]
    fn il_only_flags_are_read_through_the_section_table() {
        // `.text` at RVA 0x1000, stored at 0x200; the COR20 header at RVA
        // 0x1010 holds `Flags` (ILONLY) 16 bytes in.
        let mut data = pe_with_clr_directory(0x1010, [0x100, 0x1000, 0x100, 0x200]);
        data[0x210 + 16] = 1;
        let result = parse(&data, 0x80).expect("parses");
        assert_eq!(result.isa, Isa::Clr);
    }

    #[test]
    fn section_headers_that_overflow_do_not_map_an_rva() {
        // `VirtualAddress + VirtualSize` and `RVA - VirtualAddress +
        // PointerToRawData` exceed 32 bits.
        let data = pe_with_clr_directory(0xFFFF_F800, [0x2000, 0xFFFF_F000, 0, 0xFFFF_FF00]);
        let result = parse(&data, 0x80).expect("parses");
        assert_eq!(result.isa, Isa::X86_64);
    }

    const IMAGE_BASE: u64 = 0x1_4000_0000;
    /// File offsets of the load configuration, the CHPE metadata and the
    /// code map in [`hybrid_pe`].
    const LOAD_CONFIG: usize = 0x200;
    const CHPE: usize = 0x300;
    const CODE_MAP: usize = 0x380;

    /// A PE32+ image with `machine`, `ImageBase` 0x140000000, 16 data
    /// directories (load configuration at RVA 0x1000, 0x140 B) and one
    /// section (RVA 0x1000, 0x400 B, stored at 0x200). The load
    /// configuration's `Size` is 0x140 and its `CHPEMetadataPointer`
    /// `chpe_pointer`; the CHPE metadata at RVA 0x1100 has version 1 and a
    /// code map at RVA 0x1180 with three entries: 0x800 B of ARM64EC code
    /// at 0x2000, 0x200 B of x64 code at 0x2800 and 0x100 B of ARM64 code
    /// at 0x3000 (range type in the two low bits of the start).
    fn hybrid_pe(machine: u16, chpe_pointer: u64) -> Vec<u8> {
        let mut data = vec![0u8; 0x600];
        let put16 = |data: &mut Vec<u8>, at: usize, value: u16| {
            data[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };
        let put32 = |data: &mut Vec<u8>, at: usize, value: u32| {
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        data[..2].copy_from_slice(b"MZ");
        put32(&mut data, 0x3C, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut data, 0x84, machine);
        put16(&mut data, 0x86, 1);
        put16(&mut data, 0x94, 0xF0);
        let opt = 0x98;
        put16(&mut data, opt, optional_magic::PE32PLUS);
        data[opt + 24..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        put32(&mut data, opt + 108, 16);
        put32(&mut data, opt + 112 + 10 * 8, 0x1000);
        put32(&mut data, opt + 112 + 10 * 8 + 4, 0x140);
        let section = opt + 0xF0;
        put32(&mut data, section + 8, 0x400);
        put32(&mut data, section + 12, 0x1000);
        put32(&mut data, section + 16, 0x400);
        put32(&mut data, section + 20, 0x200);
        put32(&mut data, LOAD_CONFIG, 0x140);
        data[LOAD_CONFIG + 0xC8..LOAD_CONFIG + 0xD0].copy_from_slice(&chpe_pointer.to_le_bytes());
        put32(&mut data, CHPE, 1);
        put32(&mut data, CHPE + 4, 0x1180);
        put32(&mut data, CHPE + 8, 3);
        for (i, (start, length)) in [(0x2001, 0x800), (0x2802, 0x200), (0x3000, 0x100)]
            .into_iter()
            .enumerate()
        {
            put32(&mut data, CODE_MAP + i * 8, start);
            put32(&mut data, CODE_MAP + i * 8 + 4, length);
        }
        data
    }

    #[test]
    fn chpe_metadata_marks_an_amd64_image_as_arm64ec() {
        let data = hybrid_pe(machine::AMD64, IMAGE_BASE + 0x1100);
        let result = parse(&data, 0x80).expect("parses");
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.variant.name, "ARM64EC");
        assert_eq!(result.metadata.raw_machine, Some(u32::from(machine::AMD64)));
        assert!(result.metadata.notes.contains(
            &"Hybrid ARM64EC (x64 emulation) image: CHPE metadata version 1, PE machine \
              AMD64 / x86-64; code map: 2048 B ARM64EC, 256 B ARM64 and 512 B x64 code in \
              3 ranges"
                .to_string()
        ));
    }

    #[test]
    fn chpe_metadata_marks_an_arm64_image_as_arm64x() {
        let data = hybrid_pe(machine::ARM64, IMAGE_BASE + 0x1100);
        let result = parse(&data, 0x80).expect("parses");
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.variant.name, "ARM64X");
    }

    #[test]
    fn images_without_usable_chpe_metadata_keep_their_machine() {
        let plain = hybrid_pe(machine::AMD64, 0);
        let result = parse(&plain, 0x80).expect("parses");
        assert_eq!(result.isa, Isa::X86_64);
        assert!(!result.metadata.notes.iter().any(|n| n.contains("CHPE")));

        let mut short_config = hybrid_pe(machine::AMD64, IMAGE_BASE + 0x1100);
        short_config[LOAD_CONFIG..LOAD_CONFIG + 4].copy_from_slice(&0xC8u32.to_le_bytes());
        assert_eq!(parse(&short_config, 0x80).expect("parses").isa, Isa::X86_64);

        for pointer in [IMAGE_BASE + 0x9000, 0x1100, u64::MAX] {
            let result = parse(&hybrid_pe(machine::AMD64, pointer), 0x80).expect("parses");
            assert_eq!(result.isa, Isa::X86_64);
            assert!(result.metadata.notes.contains(&format!(
                "CHPE metadata pointer 0x{pointer:X} does not lead to a code map in the file; \
                 the image is reported by its machine field"
            )));
        }

        let mut far_map = hybrid_pe(machine::AMD64, IMAGE_BASE + 0x1100);
        far_map[CHPE + 8..CHPE + 12].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        assert_eq!(parse(&far_map, 0x80).expect("parses").isa, Isa::X86_64);
    }

    #[test]
    fn hybrid_image_prefixes_and_mutations_never_panic() {
        let data = hybrid_pe(machine::AMD64, IMAGE_BASE + 0x1100);
        for end in 0..data.len() {
            let _ = parse(&data[..end], 0x80);
        }
        for at in (0x80..0x200).chain(LOAD_CONFIG..CODE_MAP + 24) {
            for value in [0x00, 0xFF, data[at] ^ 0x01, data[at] ^ 0x80] {
                let mut mutated = data.clone();
                mutated[at] = value;
                let _ = parse(&mutated, 0x80);
            }
        }
    }

    #[test]
    fn test_machine_coverage() {
        assert_eq!(machine_to_isa(machine::I386).0, Isa::X86);
        assert_eq!(machine_to_isa(machine::AMD64).0, Isa::X86_64);
        assert_eq!(machine_to_isa(machine::ARM).0, Isa::Arm);
        assert_eq!(machine_to_isa(machine::ARM64).0, Isa::AArch64);
        assert_eq!(machine_to_isa(machine::RISCV32).0, Isa::RiscV32);
        assert_eq!(machine_to_isa(machine::RISCV64).0, Isa::RiscV64);
        assert_eq!(machine_to_isa(machine::LOONGARCH64).0, Isa::LoongArch64);
    }
}
