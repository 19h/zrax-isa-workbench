//! WebAssembly (.wasm) parser.
//!
//! WebAssembly is a binary instruction format for a stack-based virtual machine.
//! It's designed as a portable compilation target for programming languages.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// WebAssembly magic bytes: "\0asm"
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// WebAssembly version 1
pub const WASM_VERSION_1: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// WASM header size.
pub const WASM_HEADER_SIZE: usize = 8;

/// Section IDs.
pub mod section {
    pub const CUSTOM: u8 = 0;
    pub const TYPE: u8 = 1;
    pub const IMPORT: u8 = 2;
    pub const FUNCTION: u8 = 3;
    pub const TABLE: u8 = 4;
    pub const MEMORY: u8 = 5;
    pub const GLOBAL: u8 = 6;
    pub const EXPORT: u8 = 7;
    pub const START: u8 = 8;
    pub const ELEMENT: u8 = 9;
    pub const CODE: u8 = 10;
    pub const DATA: u8 = 11;
    pub const DATA_COUNT: u8 = 12;
}

/// Detect WebAssembly format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < WASM_HEADER_SIZE {
        return false;
    }

    data[0..4] == WASM_MAGIC
}

/// Read LEB128 unsigned integer.
fn read_leb128_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift = 0;

    loop {
        if *offset >= data.len() {
            return None;
        }

        let byte = data[*offset];
        *offset += 1;

        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            break;
        }

        if shift >= 35 {
            return None; // Overflow
        }
    }

    Some(result)
}

/// Parse WebAssembly file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < WASM_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: WASM_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Verify magic
    if data[0..4] != WASM_MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: "\\0asm".to_string(),
            actual: format!("{:02X?}", &data[0..4]),
        });
    }

    // Read version
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut notes = vec!["WebAssembly module".to_string()];
    notes.push(format!("Version: {}", version));

    // Parse sections
    let mut offset = 8;
    let mut function_count = 0u32;
    let mut memory_count = 0u32;
    let mut table_count = 0u32;
    let mut import_count = 0u32;
    let mut export_count = 0u32;
    let mut code_size = 0u64;
    let mut has_start = false;
    let mut custom_sections: Vec<String> = Vec::new();

    while offset < data.len() {
        // Read section ID
        let section_id = data[offset];
        offset += 1;

        // Read section size (LEB128)
        let section_size = match read_leb128_u32(data, &mut offset) {
            Some(s) => s as usize,
            None => break,
        };

        let section_end = offset + section_size;
        if section_end > data.len() {
            break;
        }

        match section_id {
            section::CUSTOM => {
                // Try to read custom section name
                let mut name_off = offset;
                if let Some(name_len) = read_leb128_u32(data, &mut name_off) {
                    let name_len = name_len as usize;
                    if name_off + name_len <= section_end {
                        if let Ok(name) = std::str::from_utf8(&data[name_off..name_off + name_len]) {
                            custom_sections.push(name.to_string());
                        }
                    }
                }
            }
            section::TYPE => {
                // Count type definitions
            }
            section::IMPORT => {
                if let Some(count) = read_leb128_u32(data, &mut offset.clone()) {
                    import_count = count;
                }
            }
            section::FUNCTION => {
                let mut func_off = offset;
                if let Some(count) = read_leb128_u32(data, &mut func_off) {
                    function_count = count;
                }
            }
            section::TABLE => {
                let mut table_off = offset;
                if let Some(count) = read_leb128_u32(data, &mut table_off) {
                    table_count = count;
                }
            }
            section::MEMORY => {
                let mut mem_off = offset;
                if let Some(count) = read_leb128_u32(data, &mut mem_off) {
                    memory_count = count;
                }
            }
            section::EXPORT => {
                let mut exp_off = offset;
                if let Some(count) = read_leb128_u32(data, &mut exp_off) {
                    export_count = count;
                }
            }
            section::START => {
                has_start = true;
            }
            section::CODE => {
                code_size = section_size as u64;
            }
            _ => {}
        }

        offset = section_end;
    }

    // Add statistics to notes
    if function_count > 0 {
        notes.push(format!("Functions: {}", function_count));
    }
    if import_count > 0 {
        notes.push(format!("Imports: {}", import_count));
    }
    if export_count > 0 {
        notes.push(format!("Exports: {}", export_count));
    }
    if memory_count > 0 {
        notes.push(format!("Linear memories: {}", memory_count));
    }
    if table_count > 0 {
        notes.push(format!("Tables: {}", table_count));
    }
    if has_start {
        notes.push("Has start function".to_string());
    }
    if code_size > 0 {
        notes.push(format!("Code section: {} bytes", code_size));
    }
    if !custom_sections.is_empty() {
        notes.push(format!("Custom sections: {}", custom_sections.join(", ")));
    }

    let metadata = ClassificationMetadata {
        code_size: if code_size > 0 { Some(code_size) } else { None },
        notes,
        ..Default::default()
    };

    // WebAssembly is typically wasm32, but wasm64 exists
    let bitwidth = 32;

    let mut result = ClassificationResult::from_format(
        Isa::Wasm,
        bitwidth,
        Endianness::Little,
        FileFormat::Wasm,
    );
    result.variant = Variant::new(format!("WebAssembly {}", version));
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wasm_module() -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(&WASM_MAGIC);
        // Version
        data.extend_from_slice(&WASM_VERSION_1);

        // Type section (empty)
        data.push(section::TYPE);
        data.push(1); // size
        data.push(0); // count

        // Function section
        data.push(section::FUNCTION);
        data.push(2); // size
        data.push(1); // count
        data.push(0); // type index

        // Code section
        data.push(section::CODE);
        data.push(4); // size
        data.push(1); // function count
        data.push(2); // function body size
        data.push(0); // local count
        data.push(0x0B); // end opcode

        data
    }

    #[test]
    fn test_detect_wasm() {
        let data = make_wasm_module();
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_wasm() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_wasm() {
        let data = make_wasm_module();
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Wasm);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Wasm);
    }
}
