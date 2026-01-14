//! bFLT (Binary Flat Format) parser.
//!
//! bFLT is used by uClinux for NoMMU systems. It supports various
//! architectures: m68k, ARM, Blackfin, RISC-V, Xtensa.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// bFLT magic: "bFLT"
pub const BFLT_MAGIC: [u8; 4] = [b'b', b'F', b'L', b'T'];

/// bFLT header size.
pub const BFLT_HEADER_SIZE: usize = 64;

/// bFLT flags.
pub mod flags {
    /// Load entire program into RAM
    pub const RAM: u32 = 0x0001;
    /// PIC with GOT
    pub const GOTPIC: u32 = 0x0002;
    /// gzip compressed
    pub const GZIP: u32 = 0x0004;
    /// Only data compressed (for XIP)
    pub const GZDATA: u32 = 0x0008;
    /// Kernel tracing enabled
    pub const KTRACE: u32 = 0x0010;
    /// L1 scratch memory stack (Blackfin)
    pub const L1STK: u32 = 0x0020;
}

/// Detect bFLT format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    data[0..4] == BFLT_MAGIC
}

/// Parse bFLT file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < BFLT_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: BFLT_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // bFLT header is big-endian (network byte order)
    let rev = read_u32(data, 4, false)?;
    let entry = read_u32(data, 8, false)?;
    let data_start = read_u32(data, 12, false)?;
    let data_end = read_u32(data, 16, false)?;
    let bss_end = read_u32(data, 20, false)?;
    let stack_size = read_u32(data, 24, false)?;
    let reloc_start = read_u32(data, 28, false)?;
    let reloc_count = read_u32(data, 32, false)?;
    let bflt_flags = read_u32(data, 36, false)?;
    let _build_date = read_u32(data, 40, false)?;

    let code_size = data_start as u64;
    let data_size = data_end.saturating_sub(data_start) as u64;
    let bss_size = bss_end.saturating_sub(data_end) as u64;

    let mut notes = vec!["bFLT (Binary Flat Format)".to_string()];
    notes.push(format!("Version: {}", rev));
    notes.push(format!("Entry point: 0x{:08X}", entry));
    notes.push(format!("Code: {} bytes", code_size));
    notes.push(format!("Data: {} bytes", data_size));
    notes.push(format!("BSS: {} bytes", bss_size));
    notes.push(format!("Stack: {} bytes", stack_size));
    notes.push(format!("Relocations: {}", reloc_count));

    // Parse flags
    let mut flag_names = Vec::new();
    if bflt_flags & flags::RAM != 0 {
        flag_names.push("RAM");
    }
    if bflt_flags & flags::GOTPIC != 0 {
        flag_names.push("GOTPIC");
    }
    if bflt_flags & flags::GZIP != 0 {
        flag_names.push("GZIP");
    }
    if bflt_flags & flags::GZDATA != 0 {
        flag_names.push("GZDATA");
    }
    if bflt_flags & flags::KTRACE != 0 {
        flag_names.push("KTRACE");
    }
    if bflt_flags & flags::L1STK != 0 {
        flag_names.push("L1STK");
    }

    if !flag_names.is_empty() {
        notes.push(format!("Flags: {}", flag_names.join(", ")));
    }

    // bFLT doesn't specify architecture in header - it's determined by the kernel
    // Default to ARM as it's most common for uClinux
    // The L1STK flag indicates Blackfin
    let isa = if bflt_flags & flags::L1STK != 0 {
        Isa::Blackfin
    } else {
        Isa::Arm // Default assumption
    };

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(code_size),
        flags: Some(bflt_flags),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, 32, Endianness::Big, FileFormat::Bflt);
    result.variant = Variant::new(format!("v{}", rev));
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bflt_header() -> Vec<u8> {
        let mut data = vec![0u8; BFLT_HEADER_SIZE];

        // Magic
        data[0..4].copy_from_slice(&BFLT_MAGIC);
        // Version
        data[4..8].copy_from_slice(&4u32.to_be_bytes());
        // Entry point
        data[8..12].copy_from_slice(&0x1000u32.to_be_bytes());
        // Data start
        data[12..16].copy_from_slice(&0x2000u32.to_be_bytes());
        // Data end
        data[16..20].copy_from_slice(&0x3000u32.to_be_bytes());
        // BSS end
        data[20..24].copy_from_slice(&0x4000u32.to_be_bytes());
        // Stack size
        data[24..28].copy_from_slice(&0x1000u32.to_be_bytes());
        // Reloc count
        data[32..36].copy_from_slice(&10u32.to_be_bytes());
        // Flags
        data[36..40].copy_from_slice(&(flags::GOTPIC).to_be_bytes());

        data
    }

    #[test]
    fn test_detect_bflt() {
        let data = make_bflt_header();
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_bflt() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_bflt() {
        let data = make_bflt_header();
        let result = parse(&data).unwrap();
        assert_eq!(result.format, FileFormat::Bflt);
        assert_eq!(result.metadata.entry_point, Some(0x1000));
    }
}
