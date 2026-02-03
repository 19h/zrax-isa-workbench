//! FatELF multi-architecture container parser.
//!
//! FatELF is a proposed format for multi-architecture ELF binaries,
//! similar to macOS fat/universal binaries.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32, read_u64};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// FatELF magic (little-endian)
pub const FATELF_MAGIC: u32 = 0x1F0E70FA;

/// FatELF header size
pub const FATELF_HEADER_SIZE: usize = 8;

/// FatELF record size (per architecture)
pub const FATELF_RECORD_SIZE: usize = 24;

/// FatELF architecture record.
#[derive(Debug, Clone)]
pub struct FatElfRecord {
    pub machine: u16,
    pub osabi: u8,
    pub osabi_version: u8,
    pub word_size: u8,  // 1=32-bit, 2=64-bit
    pub byte_order: u8, // 1=LE, 2=BE
    pub offset: u64,
    pub size: u64,
}

/// Detect FatELF format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    magic == FATELF_MAGIC
}

/// Parse FatELF header and records.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < FATELF_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: FATELF_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // FatELF is little-endian
    let magic = read_u32(data, 0, true)?;
    if magic != FATELF_MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: format!("{:08X}", FATELF_MAGIC),
            actual: format!("{:08X}", magic),
        });
    }

    let version = read_u16(data, 4, true)?;
    let num_records = data[6];
    let _reserved = data[7];

    let records_size = num_records as usize * FATELF_RECORD_SIZE;
    if data.len() < FATELF_HEADER_SIZE + records_size {
        return Err(ClassifierError::TruncatedData {
            offset: FATELF_HEADER_SIZE,
            expected: records_size,
            actual: data.len().saturating_sub(FATELF_HEADER_SIZE),
        });
    }

    // Parse records
    let mut records: Vec<FatElfRecord> = Vec::new();
    let mut arch_names: Vec<String> = Vec::new();

    for i in 0..num_records as usize {
        let rec_off = FATELF_HEADER_SIZE + i * FATELF_RECORD_SIZE;

        let machine = read_u16(data, rec_off, true)?;
        let osabi = data[rec_off + 2];
        let osabi_version = data[rec_off + 3];
        let word_size = data[rec_off + 4];
        let byte_order = data[rec_off + 5];
        // 2 bytes padding
        let offset = read_u64(data, rec_off + 8, true)?;
        let size = read_u64(data, rec_off + 16, true)?;

        let arch_name = e_machine_name(machine);
        arch_names.push(arch_name.to_string());

        records.push(FatElfRecord {
            machine,
            osabi,
            osabi_version,
            word_size,
            byte_order,
            offset,
            size,
        });
    }

    let mut notes = vec!["FatELF multi-architecture container".to_string()];
    notes.push(format!("Version: {}", version));
    notes.push(format!("Architectures: {}", num_records));
    notes.push(format!("Contained: {}", arch_names.join(", ")));

    // Report details of first architecture
    if let Some(first) = records.first() {
        notes.push(format!(
            "First: {} ({}-bit, {})",
            e_machine_name(first.machine),
            if first.word_size == 2 { 64 } else { 32 },
            if first.byte_order == 1 { "LE" } else { "BE" }
        ));
    }

    let metadata = ClassificationMetadata {
        section_count: Some(num_records as usize),
        notes,
        ..Default::default()
    };

    // FatELF is a container - report first architecture's ISA
    let (isa, bitwidth, endianness) = if let Some(first) = records.first() {
        let isa = e_machine_to_isa(first.machine);
        let bits = if first.word_size == 2 { 64 } else { 32 };
        let endian = if first.byte_order == 1 {
            Endianness::Little
        } else {
            Endianness::Big
        };
        (isa, bits, endian)
    } else {
        (Isa::Unknown(0), 0, Endianness::Little)
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::FatElf);
    result.variant = Variant::new(format!("{} architectures", num_records));
    result.metadata = metadata;

    Ok(result)
}

/// Map ELF e_machine to ISA (simplified).
fn e_machine_to_isa(machine: u16) -> Isa {
    match machine {
        0x03 => Isa::X86,
        0x3E => Isa::X86_64,
        0x28 => Isa::Arm,
        0xB7 => Isa::AArch64,
        0xF3 => Isa::RiscV64,
        0x08 => Isa::Mips,
        0x14 => Isa::Ppc,
        0x15 => Isa::Ppc64,
        _ => Isa::Unknown(machine as u32),
    }
}

/// Get e_machine name.
fn e_machine_name(machine: u16) -> &'static str {
    match machine {
        0x03 => "i386",
        0x3E => "x86-64",
        0x28 => "ARM",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC64",
        0x16 => "S390",
        0x02 => "SPARC",
        0x2B => "SPARC64",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fatelf_header(num_records: u8) -> Vec<u8> {
        let mut data =
            vec![0u8; FATELF_HEADER_SIZE + num_records as usize * FATELF_RECORD_SIZE + 64];

        // Magic
        data[0..4].copy_from_slice(&FATELF_MAGIC.to_le_bytes());
        // Version
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        // Number of records
        data[6] = num_records;
        // Reserved
        data[7] = 0;

        // Add records
        for i in 0..num_records as usize {
            let rec_off = FATELF_HEADER_SIZE + i * FATELF_RECORD_SIZE;

            // Machine (alternate between x86-64 and AArch64)
            let machine = if i % 2 == 0 { 0x3Eu16 } else { 0xB7u16 };
            data[rec_off..rec_off + 2].copy_from_slice(&machine.to_le_bytes());

            // Word size (64-bit)
            data[rec_off + 4] = 2;
            // Byte order (LE)
            data[rec_off + 5] = 1;

            // Offset and size
            let offset = (FATELF_HEADER_SIZE + num_records as usize * FATELF_RECORD_SIZE) as u64;
            data[rec_off + 8..rec_off + 16].copy_from_slice(&offset.to_le_bytes());
            data[rec_off + 16..rec_off + 24].copy_from_slice(&64u64.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_detect_fatelf() {
        let data = make_fatelf_header(2);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_fatelf() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_fatelf() {
        let data = make_fatelf_header(2);
        let result = parse(&data).unwrap();
        assert_eq!(result.format, FileFormat::FatElf);
        assert_eq!(result.metadata.section_count, Some(2));
    }
}
