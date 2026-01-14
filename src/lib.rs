//! ISA Classifier - Universal Binary Architecture Identification
//!
//! This library provides comprehensive binary classification capabilities
//! for identifying processor architectures, instruction set variants,
//! and ISA extensions from binary files.
//!
//! # Features
//!
//! - **Format Detection**: Automatically detects ELF, PE/COFF, Mach-O, and other formats
//! - **Complete ISA Coverage**: Supports 50+ architectures including x86, ARM, RISC-V, MIPS, PowerPC, and more
//! - **Extension Detection**: Identifies ISA extensions (AVX, SVE, Vector extensions, etc.)
//! - **Heuristic Analysis**: Classifies raw binaries without format headers
//! - **Modular Design**: Clean separation of concerns for easy extension
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use isa_classifier::{classify_file, classify_bytes};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Classify a file
//!     let result = classify_file("path/to/binary")?;
//!     println!("ISA: {}", result.isa.name());
//!     println!("Bitwidth: {}-bit", result.bitwidth);
//!     println!("Extensions: {:?}", result.extension_names());
//!
//!     // Classify raw bytes
//!     let bytes = std::fs::read("path/to/binary")?;
//!     let result = classify_bytes(&bytes)?;
//!     Ok(())
//! }
//! ```
//!
//! # Architecture Support
//!
//! The classifier supports the following architecture families:
//!
//! - **x86/x86-64**: Full support including AVX, AVX-512, AMX extensions
//! - **ARM**: ARM32, Thumb, Thumb-2, and AArch64 with NEON, SVE, SME
//! - **RISC-V**: RV32/64/128 with standard and custom extensions
//! - **MIPS**: MIPS I-V, MIPS32/64, microMIPS
//! - **PowerPC**: 32/64-bit with VMX, VSX extensions
//! - **Many more**: s390x, SPARC, Alpha, LoongArch, Hexagon, etc.
//!
//! # File Format Support
//!
//! - ELF (Linux, BSD, embedded)
//! - PE/COFF (Windows)
//! - Mach-O (macOS, iOS) including fat/universal binaries
//! - XCOFF (AIX)
//! - ECOFF (older MIPS/Alpha)
//! - Raw binary (heuristic analysis)

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

pub mod architectures;
pub mod error;
pub mod extensions;
pub mod formats;
pub mod heuristics;
pub mod types;

pub use error::{ClassifierError, Result};
pub use types::{
    ClassificationMetadata, ClassificationResult, ClassificationSource, ClassifierOptions,
    Endianness, Extension, ExtensionCategory, FileFormat, Isa, Variant,
};

use std::path::Path;

/// Classify a binary file by path.
///
/// This is the primary entry point for file-based classification.
/// It reads the file and performs comprehensive analysis.
///
/// # Arguments
///
/// * `path` - Path to the binary file
///
/// # Returns
///
/// * `Ok(ClassificationResult)` - Successful classification
/// * `Err(ClassifierError)` - If the file cannot be read or analyzed
///
/// # Example
///
/// ```rust,no_run
/// use isa_classifier::classify_file;
///
/// let result = classify_file("/bin/ls")?;
/// println!("Architecture: {}", result.isa.name());
/// # Ok::<(), isa_classifier::ClassifierError>(())
/// ```
pub fn classify_file<P: AsRef<Path>>(path: P) -> Result<ClassificationResult> {
    let data = std::fs::read(path)?;
    classify_bytes(&data)
}

/// Classify binary data from a byte slice.
///
/// This function performs comprehensive analysis on raw binary data,
/// detecting the file format and extracting architecture information.
///
/// # Arguments
///
/// * `data` - Raw binary data
///
/// # Returns
///
/// * `Ok(ClassificationResult)` - Successful classification
/// * `Err(ClassifierError)` - If analysis fails
///
/// # Example
///
/// ```rust
/// use isa_classifier::classify_bytes;
///
/// // ELF header for x86-64
/// let elf_data = [
///     0x7F, b'E', b'L', b'F', // Magic
///     2,    // 64-bit
///     1,    // Little-endian
///     1,    // ELF version
///     0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding
///     2, 0, // Executable
///     0x3E, 0, // x86-64
///     // ... (truncated for example)
/// ];
/// // Would need complete header for actual use
/// ```
pub fn classify_bytes(data: &[u8]) -> Result<ClassificationResult> {
    classify_bytes_with_options(data, &ClassifierOptions::new())
}

/// Classify binary data with custom options.
///
/// This function allows fine-grained control over the classification
/// process, including confidence thresholds and scanning depth.
///
/// # Arguments
///
/// * `data` - Raw binary data
/// * `options` - Classification options
///
/// # Example
///
/// ```rust
/// use isa_classifier::{classify_bytes_with_options, ClassifierOptions};
///
/// let options = ClassifierOptions::thorough();
/// // let result = classify_bytes_with_options(&data, &options)?;
/// ```
pub fn classify_bytes_with_options(
    data: &[u8],
    options: &ClassifierOptions,
) -> Result<ClassificationResult> {
    // Try to parse as known format first
    let format = formats::detect_format(data);

    let mut result = match format {
        formats::DetectedFormat::Elf { class, endian } => formats::elf::parse(data, class, endian)?,
        formats::DetectedFormat::Pe { pe_offset } => formats::pe::parse(data, pe_offset)?,
        formats::DetectedFormat::MachO { bits, big_endian } => {
            formats::macho::parse(data, bits, big_endian)?
        }
        formats::DetectedFormat::MachOFat { big_endian } => {
            formats::macho::parse_fat(data, big_endian)?
        }
        formats::DetectedFormat::Xcoff { bits } => {
            let isa = if bits == 64 { Isa::Ppc64 } else { Isa::Ppc };
            ClassificationResult::from_format(isa, bits, Endianness::Big, FileFormat::Xcoff)
        }
        formats::DetectedFormat::Ecoff { variant } => {
            let (isa, endian) = match variant {
                formats::EcoffVariant::MipsLe => (Isa::Mips, Endianness::Little),
                formats::EcoffVariant::MipsBe => (Isa::Mips, Endianness::Big),
                formats::EcoffVariant::Alpha => (Isa::Alpha, Endianness::Little),
            };
            let bits = if matches!(isa, Isa::Alpha) { 64 } else { 32 };
            ClassificationResult::from_format(isa, bits, endian, FileFormat::Ecoff)
        }
        formats::DetectedFormat::Raw => {
            // Fall back to heuristic analysis
            heuristics::analyze(data, options)?
        }
    };

    // Detect extensions if requested and not already done
    if options.detect_extensions && result.extensions.is_empty() {
        let code_extensions =
            extensions::detect_from_code(data, result.isa, result.endianness);
        result.extensions = code_extensions;
    }

    Ok(result)
}

/// Get version information for this library.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get the list of supported ISAs.
pub fn supported_isas() -> Vec<Isa> {
    vec![
        Isa::X86,
        Isa::X86_64,
        Isa::Arm,
        Isa::AArch64,
        Isa::RiscV32,
        Isa::RiscV64,
        Isa::Mips,
        Isa::Mips64,
        Isa::Ppc,
        Isa::Ppc64,
        Isa::S390,
        Isa::S390x,
        Isa::Sparc,
        Isa::Sparc64,
        Isa::Alpha,
        Isa::Ia64,
        Isa::M68k,
        Isa::Sh,
        Isa::Sh4,
        Isa::LoongArch32,
        Isa::LoongArch64,
        Isa::Hexagon,
        Isa::Arc,
        Isa::Xtensa,
        Isa::MicroBlaze,
        Isa::Nios2,
        Isa::OpenRisc,
        Isa::Csky,
        Isa::Avr,
        Isa::Msp430,
        Isa::Bpf,
    ]
}

/// Quick check if a file is likely a specific ISA.
///
/// This is a fast preliminary check that doesn't do full classification.
///
/// # Arguments
///
/// * `data` - Binary data
/// * `isa` - ISA to check for
///
/// # Returns
///
/// * `true` if the data likely contains code for the specified ISA
pub fn quick_check(data: &[u8], isa: Isa) -> bool {
    formats::raw::quick_check_isa(data, isa)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
    }

    #[test]
    fn test_supported_isas() {
        let isas = supported_isas();
        assert!(!isas.is_empty());
        assert!(isas.contains(&Isa::X86_64));
        assert!(isas.contains(&Isa::AArch64));
    }

    #[test]
    fn test_classify_elf_x86_64() {
        // Minimal ELF header for x86-64
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // Little-endian
        data[6] = 1; // ELF version
        data[0x12] = 0x3E; // x86-64
        data[0x13] = 0x00;

        let result = classify_bytes(&data).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.endianness, Endianness::Little);
        assert_eq!(result.format, FileFormat::Elf);
    }

    #[test]
    fn test_classify_elf_aarch64() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // Little-endian
        data[6] = 1;
        data[0x12] = 0xB7; // AArch64
        data[0x13] = 0x00;

        let result = classify_bytes(&data).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_classify_elf_riscv64() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // Little-endian
        data[6] = 1;
        data[0x12] = 0xF3; // RISC-V
        data[0x13] = 0x00;

        let result = classify_bytes(&data).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
    }

    #[test]
    fn test_options() {
        let default = ClassifierOptions::new();
        let thorough = ClassifierOptions::thorough();
        let fast = ClassifierOptions::fast();

        assert!(thorough.deep_scan);
        assert!(!fast.deep_scan);
        assert!(fast.min_confidence > default.min_confidence);
    }
}
