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
pub mod formatter;
pub mod heuristics;
pub mod types;

pub use error::{ClassifierError, Result};
pub use formatter::{
    CandidatesFormatter, HumanFormatter, JsonFormatter, PayloadFormatter, ShortFormatter,
};
pub use types::{
    ClassificationMetadata, ClassificationResult, ClassificationSource, ClassifierOptions,
    DetectionPayload, Endianness, Extension, ExtensionCategory, ExtensionDetection,
    ExtensionSource, FileFormat, FormatDetection, Isa, IsaCandidate, IsaClassification,
    MetadataEntry, MetadataKey, MetadataValue, Note, NoteLevel, Variant,
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
        formats::DetectedFormat::Coff { machine: _ } => formats::coff::parse(data)?,
        formats::DetectedFormat::Xcoff { bits } => formats::xcoff::parse(data, bits)?,
        formats::DetectedFormat::Ecoff { variant } => formats::ecoff::parse(data, variant)?,
        formats::DetectedFormat::Aout { variant } => formats::aout::parse(data, variant)?,
        formats::DetectedFormat::Mz { variant } => formats::mz::parse(data, variant)?,
        formats::DetectedFormat::Pef => formats::pef::parse(data)?,
        formats::DetectedFormat::Wasm => formats::wasm::parse(data)?,
        formats::DetectedFormat::JavaClass => formats::java::parse(data)?,
        formats::DetectedFormat::Dex { variant } => formats::dex::parse(data, variant)?,
        formats::DetectedFormat::Bflt => formats::bflt::parse(data)?,
        formats::DetectedFormat::Console { variant } => formats::console::parse(data, variant)?,
        formats::DetectedFormat::Kernel { variant } => formats::kernel::parse(data, variant)?,
        formats::DetectedFormat::Ar { variant } => formats::ar::parse(data, variant)?,
        formats::DetectedFormat::Hex { variant } => formats::hex::parse(data, variant)?,
        formats::DetectedFormat::Goff => formats::goff::parse(data)?,
        formats::DetectedFormat::LlvmBc { variant } => formats::llvm_bc::parse(data, variant)?,
        formats::DetectedFormat::FatElf => formats::fatelf::parse(data)?,
        formats::DetectedFormat::Raw => {
            // Fall back to heuristic analysis
            heuristics::analyze(data, options)?
        }
    };

    // Detect extensions if requested
    if options.detect_extensions {
        let code_extensions =
            extensions::detect_from_code(data, result.isa, result.endianness);

        // Merge code-detected extensions with format-detected extensions
        if result.extensions.is_empty() {
            result.extensions = code_extensions;
        } else if !code_extensions.is_empty() {
            // Merge, avoiding duplicates by name
            let existing: std::collections::HashSet<String> = result
                .extensions
                .iter()
                .map(|e| e.name.clone())
                .collect();
            for ext in code_extensions {
                if !existing.contains(&ext.name) {
                    result.extensions.push(ext);
                }
            }
        }
    }

    Ok(result)
}

/// Detect and analyze a binary file, returning a structured payload.
///
/// This is the primary entry point for the new payload-based API.
/// Returns a `DetectionPayload` containing all detection results
/// that can be passed to formatters for rendering.
///
/// # Arguments
///
/// * `path` - Path to the binary file
///
/// # Returns
///
/// * `Ok(DetectionPayload)` - Successful detection with all results
/// * `Err(ClassifierError)` - If the file cannot be read or analyzed
pub fn detect_file<P: AsRef<Path>>(path: P) -> Result<DetectionPayload> {
    let data = std::fs::read(path)?;
    detect_payload(&data, &ClassifierOptions::new())
}

/// Detect and analyze binary data, returning a structured payload.
///
/// # Arguments
///
/// * `data` - Raw binary data
///
/// # Returns
///
/// * `Ok(DetectionPayload)` - Successful detection with all results
/// * `Err(ClassifierError)` - If analysis fails
pub fn detect_bytes(data: &[u8]) -> Result<DetectionPayload> {
    detect_payload(data, &ClassifierOptions::new())
}

/// Detect and analyze binary data with custom options, returning a structured payload.
///
/// This is the most flexible entry point, returning comprehensive structured data
/// suitable for rendering by any formatter.
///
/// # Arguments
///
/// * `data` - Raw binary data
/// * `options` - Classification options
///
/// # Returns
///
/// * `Ok(DetectionPayload)` - Complete detection payload with:
///   - Format detection result
///   - Primary ISA classification
///   - Alternative candidates (for heuristic analysis)
///   - Detected extensions
///   - Metadata entries
///   - Analysis notes
pub fn detect_payload(data: &[u8], options: &ClassifierOptions) -> Result<DetectionPayload> {
    use types::{
        DetectionPayload, ExtensionDetection, ExtensionSource,
        IsaCandidate, IsaClassification,
    };

    // Detect file format
    let detected = formats::detect_format(data);
    let format_detection = detected_to_format(&detected);

    // Parse based on format
    let (primary, initial_extensions, metadata) = match detected {
        formats::DetectedFormat::Elf { class, endian } => {
            let result = formats::elf::parse(data, class, endian)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness)
                    .with_variant(result.variant.clone()),
                result.extensions.iter().map(|e| {
                    ExtensionDetection {
                        name: e.name.clone(),
                        category: e.category,
                        confidence: e.confidence,
                        source: ExtensionSource::FormatAttribute,
                    }
                }).collect::<Vec<_>>(),
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Pe { pe_offset } => {
            let result = formats::pe::parse(data, pe_offset)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::MachO { bits, big_endian } => {
            let result = formats::macho::parse(data, bits, big_endian)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::MachOFat { big_endian } => {
            let result = formats::macho::parse_fat(data, big_endian)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Coff { machine: _ } => {
            let result = formats::coff::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Xcoff { bits } => {
            let result = formats::xcoff::parse(data, bits)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Ecoff { variant } => {
            let result = formats::ecoff::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Aout { variant } => {
            let result = formats::aout::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Mz { variant } => {
            let result = formats::mz::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Pef => {
            let result = formats::pef::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Wasm => {
            let result = formats::wasm::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::JavaClass => {
            let result = formats::java::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Dex { variant } => {
            let result = formats::dex::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Bflt => {
            let result = formats::bflt::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Console { variant } => {
            let result = formats::console::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Kernel { variant } => {
            let result = formats::kernel::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Ar { variant } => {
            let result = formats::ar::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Hex { variant } => {
            let result = formats::hex::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Goff => {
            let result = formats::goff::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::LlvmBc { variant } => {
            let result = formats::llvm_bc::parse(data, variant)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::FatElf => {
            let result = formats::fatelf::parse(data)?;
            (
                IsaClassification::from_format(result.isa, result.bitwidth, result.endianness),
                vec![],
                extract_metadata(&result),
            )
        }
        formats::DetectedFormat::Raw => {
            // Heuristic analysis - get all candidates
            let candidates = heuristics::score_all_architectures(data, options);
            let best = candidates
                .iter()
                .max_by(|a, b| a.raw_score.cmp(&b.raw_score));

            match best {
                Some(b) if b.confidence >= options.min_confidence => {
                    let primary = IsaClassification::from_heuristics(
                        b.isa,
                        b.bitwidth,
                        b.endianness,
                        b.confidence,
                    );
                    let candidate_list: Vec<IsaCandidate> = candidates
                        .iter()
                        .filter(|c| c.raw_score > 0)
                        .take(10)
                        .map(|c| IsaCandidate::new(c.isa, c.bitwidth, c.endianness, c.raw_score, c.confidence))
                        .collect();

                    let mut payload = DetectionPayload::new(format_detection, primary)
                        .with_candidates(candidate_list);

                    // Add code-detected extensions
                    if options.detect_extensions {
                        let code_exts = extensions::detect_from_code(data, b.isa, b.endianness);
                        payload.extensions = code_exts
                            .into_iter()
                            .map(|e| ExtensionDetection {
                                name: e.name,
                                category: e.category,
                                confidence: e.confidence,
                                source: ExtensionSource::CodePattern,
                            })
                            .collect();
                    }

                    return Ok(payload);
                }
                _ => {
                    return Err(error::ClassifierError::HeuristicInconclusive {
                        confidence: best.map(|b| b.confidence * 100.0).unwrap_or(0.0),
                        threshold: options.min_confidence * 100.0,
                    });
                }
            }
        }
    };

    // Build payload
    let mut payload = DetectionPayload::new(format_detection, primary);
    payload.extensions = initial_extensions;
    payload.metadata = metadata;

    // Add code-detected extensions if requested
    if options.detect_extensions {
        let code_exts = extensions::detect_from_code(data, payload.primary.isa, payload.primary.endianness);
        let existing: std::collections::HashSet<String> = payload
            .extensions
            .iter()
            .map(|e| e.name.clone())
            .collect();

        for ext in code_exts {
            if !existing.contains(&ext.name) {
                payload.extensions.push(ExtensionDetection {
                    name: ext.name,
                    category: ext.category,
                    confidence: ext.confidence,
                    source: ExtensionSource::CodePattern,
                });
            }
        }
    }

    Ok(payload)
}

/// Convert DetectedFormat to FormatDetection.
fn detected_to_format(detected: &formats::DetectedFormat) -> FormatDetection {
    use formats::DetectedFormat;
    match detected {
        DetectedFormat::Elf { .. } => FormatDetection::new(FileFormat::Elf),
        DetectedFormat::Pe { .. } => FormatDetection::new(FileFormat::Pe),
        DetectedFormat::MachO { .. } => FormatDetection::new(FileFormat::MachO),
        DetectedFormat::MachOFat { .. } => FormatDetection::new(FileFormat::MachOFat),
        DetectedFormat::Coff { .. } => FormatDetection::new(FileFormat::Coff),
        DetectedFormat::Xcoff { .. } => FormatDetection::new(FileFormat::Xcoff),
        DetectedFormat::Ecoff { .. } => FormatDetection::new(FileFormat::Ecoff),
        DetectedFormat::Aout { variant } => {
            FormatDetection::with_variant(FileFormat::Aout, format!("{:?}", variant))
        }
        DetectedFormat::Mz { variant } => {
            FormatDetection::with_variant(FileFormat::Mz, format!("{:?}", variant))
        }
        DetectedFormat::Pef => FormatDetection::new(FileFormat::Pef),
        DetectedFormat::Wasm => FormatDetection::new(FileFormat::Wasm),
        DetectedFormat::JavaClass => FormatDetection::new(FileFormat::JavaClass),
        DetectedFormat::Dex { variant } => {
            FormatDetection::with_variant(FileFormat::Dex, format!("{:?}", variant))
        }
        DetectedFormat::Bflt => FormatDetection::new(FileFormat::Bflt),
        DetectedFormat::Console { variant } => {
            FormatDetection::with_variant(format_for_console(variant), format!("{:?}", variant))
        }
        DetectedFormat::Kernel { variant } => {
            FormatDetection::with_variant(format_for_kernel(variant), format!("{:?}", variant))
        }
        DetectedFormat::Ar { variant } => {
            FormatDetection::with_variant(FileFormat::Archive, format!("{:?}", variant))
        }
        DetectedFormat::Hex { variant } => {
            FormatDetection::with_variant(format_for_hex(variant), format!("{:?}", variant))
        }
        DetectedFormat::Goff => FormatDetection::new(FileFormat::Goff),
        DetectedFormat::LlvmBc { .. } => FormatDetection::new(FileFormat::LlvmBc),
        DetectedFormat::FatElf => FormatDetection::new(FileFormat::FatElf),
        DetectedFormat::Raw => FormatDetection::raw(),
    }
}

/// Get FileFormat for console variant.
fn format_for_console(variant: &formats::console::ConsoleFormat) -> FileFormat {
    use formats::console::ConsoleFormat;
    match variant {
        ConsoleFormat::Xbe => FileFormat::Xbe,
        ConsoleFormat::Xex { .. } => FileFormat::Xex,
        ConsoleFormat::SelfPs3 => FileFormat::SelfPs3,
        ConsoleFormat::SelfPs4 => FileFormat::SelfPs4,
        ConsoleFormat::SelfPs5 => FileFormat::SelfPs5,
        ConsoleFormat::Nso => FileFormat::Nso,
        ConsoleFormat::Nro => FileFormat::Nro,
        ConsoleFormat::Dol => FileFormat::Dol,
    }
}

/// Get FileFormat for kernel variant.
fn format_for_kernel(variant: &formats::kernel::KernelFormat) -> FileFormat {
    use formats::kernel::KernelFormat;
    match variant {
        KernelFormat::LinuxX86 { .. } => FileFormat::ZImage,
        KernelFormat::LinuxArm64 => FileFormat::ZImage,
        KernelFormat::LinuxRiscv => FileFormat::ZImage,
        KernelFormat::UImage { .. } => FileFormat::UImage,
        KernelFormat::Fit => FileFormat::Fit,
        KernelFormat::Dtb => FileFormat::Dtb,
    }
}

/// Get FileFormat for hex variant.
fn format_for_hex(variant: &formats::hex::HexVariant) -> FileFormat {
    use formats::hex::HexVariant;
    match variant {
        HexVariant::IntelHex { .. } => FileFormat::IntelHex,
        HexVariant::Srec { .. } => FileFormat::Srec,
        HexVariant::TiTxt => FileFormat::TiTxt,
    }
}

/// Extract metadata from a ClassificationResult.
fn extract_metadata(result: &ClassificationResult) -> Vec<MetadataEntry> {
    let mut entries = Vec::new();

    if let Some(entry) = result.metadata.entry_point {
        entries.push(MetadataEntry::entry_point(entry));
    }
    if let Some(sections) = result.metadata.section_count {
        entries.push(MetadataEntry::section_count(sections));
    }
    if let Some(flags) = result.metadata.flags {
        entries.push(MetadataEntry::flags(flags));
    }
    if let Some(machine) = result.metadata.raw_machine {
        entries.push(MetadataEntry::raw_machine(machine));
    }

    entries
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
