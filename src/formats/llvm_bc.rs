//! LLVM Bitcode parser.
//!
//! LLVM bitcode is an intermediate representation used by the LLVM compiler infrastructure.
//! It's ISA-independent and can be JIT-compiled or translated to native code.

use crate::error::{ClassifierError, Result};
use crate::formats::read_u32;
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// LLVM bitcode magic: "BC" + 0xC0DE
pub const LLVM_BC_MAGIC: [u8; 4] = [b'B', b'C', 0xC0, 0xDE];

/// LLVM bitcode wrapper magic (used in archives/bundles)
pub const LLVM_WRAPPER_MAGIC: u32 = 0x0B17C0DE;

/// Clang PCH magic (precompiled header)
pub const CLANG_PCH_MAGIC: [u8; 4] = [b'C', b'P', b'C', b'H'];

/// Bitcode header size
pub const BITCODE_HEADER_SIZE: usize = 4;

/// Detected LLVM format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlvmVariant {
    /// Standard LLVM bitcode
    Bitcode,
    /// Wrapped bitcode (with metadata)
    Wrapped,
    /// Clang precompiled header
    ClangPch,
}

/// Detect LLVM bitcode format.
pub fn detect(data: &[u8]) -> Option<LlvmVariant> {
    if data.len() < 4 {
        return None;
    }

    // Check for standard bitcode magic
    if data[0..4] == LLVM_BC_MAGIC {
        return Some(LlvmVariant::Bitcode);
    }

    // Check for wrapper magic
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_le == LLVM_WRAPPER_MAGIC {
        return Some(LlvmVariant::Wrapped);
    }

    // Check for Clang PCH
    if data[0..4] == CLANG_PCH_MAGIC {
        return Some(LlvmVariant::ClangPch);
    }

    None
}

/// Parse LLVM bitcode.
pub fn parse(data: &[u8], variant: LlvmVariant) -> Result<ClassificationResult> {
    if data.len() < BITCODE_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: BITCODE_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let (variant_name, format_name) = match variant {
        LlvmVariant::Bitcode => ("Bitcode", "LLVM Bitcode"),
        LlvmVariant::Wrapped => ("Wrapped", "LLVM Wrapped Bitcode"),
        LlvmVariant::ClangPch => ("PCH", "Clang Precompiled Header"),
    };

    let mut notes = vec![format_name.to_string()];
    notes.push(format!("Size: {} bytes", data.len()));

    // Try to read some basic structure
    // LLVM bitcode uses a complex bitstream format
    // Full parsing would require significant code

    let metadata = ClassificationMetadata {
        code_size: Some(data.len() as u64),
        notes,
        ..Default::default()
    };

    // LLVM bitcode is ISA-independent
    let mut result = ClassificationResult::from_format(
        Isa::Unknown(0),
        0,
        Endianness::Little,
        FileFormat::LlvmBc,
    );
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_bitcode() {
        let data = [b'B', b'C', 0xC0, 0xDE, 0, 0, 0, 0];
        let variant = detect(&data);
        assert!(matches!(variant, Some(LlvmVariant::Bitcode)));
    }

    #[test]
    fn test_detect_wrapped() {
        let magic = LLVM_WRAPPER_MAGIC.to_le_bytes();
        let data = [magic[0], magic[1], magic[2], magic[3], 0, 0, 0, 0];
        let variant = detect(&data);
        assert!(matches!(variant, Some(LlvmVariant::Wrapped)));
    }

    #[test]
    fn test_detect_not_llvm() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(detect(&data).is_none());
    }

    #[test]
    fn test_parse_bitcode() {
        let data = [b'B', b'C', 0xC0, 0xDE, 0, 0, 0, 0];
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.format, FileFormat::LlvmBc);
    }
}
