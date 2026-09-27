//! ISA Classifier - Universal Binary Architecture Identification
//!
//! Identifies the processor architecture of a binary: from container headers
//! when there is one (ELF, PE/COFF, Mach-O and ~40 other formats), and from
//! the code itself when there is not (raw firmware, memory dumps, extracted
//! sections).
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use isa_classifier::{classify_file, classify_bytes};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let result = classify_file("path/to/binary")?;
//!     println!("ISA: {}", result.isa.name());
//!     println!("Bitwidth: {}-bit", result.bitwidth);
//!     println!("Extensions: {:?}", result.extension_names());
//!
//!     let bytes = std::fs::read("path/to/binary")?;
//!     let result = classify_bytes(&bytes)?;
//!     Ok(())
//! }
//! ```
//!
//! # Headerless data
//!
//! Raw data is classified by [`heuristics`]: byte-bigram models trained on
//! ground-truth code for ~90 ISA variants, competing against models of
//! non-code data. Results carry a calibrated confidence and are rejected
//! (`HeuristicInconclusive`) when the data does not look like code of any
//! known ISA. See `scripts/build_corpus.py` and `examples/train_model.rs` for
//! how the model is built, and `examples/eval.rs` for how it is measured.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "wasm"), deny(unsafe_code))]
#![cfg_attr(feature = "wasm", warn(unsafe_code))]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

pub mod error;
pub mod extensions;
pub mod formats;
pub mod formatter;
pub mod heuristics;
pub mod types;

#[cfg(feature = "batch")]
pub mod batch;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{ClassifierError, Result};
pub use formatter::{
    CandidatesFormatter, HumanFormatter, JsonFormatter, PayloadFormatter, ShortFormatter,
};
pub use heuristics::DetectedIsa;
pub use types::{
    ClassificationMetadata, ClassificationResult, ClassificationSource, ClassifierOptions,
    ContainedArch, DetectionPayload, Endianness, Extension, ExtensionCategory, ExtensionDetection,
    ExtensionSource, FileFormat, FormatDetection, Isa, IsaCandidate, IsaClassification,
    MetadataEntry, MetadataKey, MetadataValue, Note, NoteLevel, Variant,
};

use std::path::Path;

/// Classify a binary file by path.
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

/// Classify binary data with default options.
pub fn classify_bytes(data: &[u8]) -> Result<ClassificationResult> {
    classify_bytes_with_options(data, &ClassifierOptions::new())
}

/// Classify binary data with custom options.
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
    classify(data, options).map(|c| c.result)
}

/// Detect and analyze a binary file, returning a structured payload.
pub fn detect_file<P: AsRef<Path>>(path: P) -> Result<DetectionPayload> {
    let data = std::fs::read(path)?;
    detect_payload(&data, &ClassifierOptions::new())
}

/// Detect and analyze binary data, returning a structured payload.
pub fn detect_bytes(data: &[u8]) -> Result<DetectionPayload> {
    detect_payload(data, &ClassifierOptions::new())
}

/// Detect and analyze binary data with custom options, returning the full
/// payload: format, primary ISA, candidates (for code-based results),
/// contained slices (fat binaries), extensions, metadata and notes.
///
/// This goes through exactly the same decision path as
/// [`classify_bytes_with_options`].
pub fn detect_payload(data: &[u8], options: &ClassifierOptions) -> Result<DetectionPayload> {
    let c = classify(data, options)?;
    let r = &c.result;
    let primary = IsaClassification {
        isa: r.isa,
        bitwidth: r.bitwidth,
        endianness: r.endianness,
        confidence: r.confidence,
        source: r.source,
        variant: (r.variant != Variant::default()).then(|| r.variant.clone()),
    };
    let mut payload = DetectionPayload::new(c.format, primary).with_candidates(c.candidates);
    payload.slices = c.slices;
    payload.metadata = extract_metadata(r);
    payload.extensions = c.extensions;
    payload.notes = r.metadata.notes.iter().cloned().map(Note::info).collect();
    payload.notes.extend(c.notes);
    Ok(payload)
}

/// Everything one classification produces, shared by both public APIs.
struct Classified {
    format: FormatDetection,
    result: ClassificationResult,
    candidates: Vec<IsaCandidate>,
    slices: Vec<ContainedArch>,
    extensions: Vec<ExtensionDetection>,
    notes: Vec<Note>,
}

/// Run the code model and return the result plus the ranked candidates.
fn heuristic(
    data: &[u8],
    options: &ClassifierOptions,
) -> (Result<ClassificationResult>, Vec<IsaCandidate>) {
    let quiet = ClassifierOptions {
        detect_extensions: false,
        ..options.clone()
    };
    let (result, candidates) = heuristics::analyze_detailed(data, &quiet);
    let candidates = candidates
        .into_iter()
        .filter(|c| c.raw_score > 0)
        .take(10)
        .map(|c| IsaCandidate::new(c.isa, c.bitwidth, c.endianness, c.raw_score, c.confidence))
        .collect();
    (result, candidates)
}

/// Replace a container result that does not know its ISA with the code
/// model's answer, keeping the container's format and notes.
fn adopt_heuristic(container: &ClassificationResult, mut h: ClassificationResult) -> ClassificationResult {
    h.format = container.format;
    h.source = ClassificationSource::Combined;
    h.metadata.notes = container.metadata.notes.clone();
    h.metadata
        .notes
        .push("ISA identified from the code, not the container".into());
    h
}

fn classify(data: &[u8], options: &ClassifierOptions) -> Result<Classified> {
    let detected = formats::detect_format(data);
    let format = detected_to_format(&detected);
    let mut notes = Vec::new();
    let mut candidates = Vec::new();
    let mut slices = Vec::new();

    let result = match detected {
        formats::DetectedFormat::Raw => {
            let (r, c) = heuristic(data, options);
            candidates = c;
            r?
        }
        formats::DetectedFormat::MachOFat { fat64, .. } => {
            let entries = formats::macho::parse_fat_all(data, fat64)?;
            let first = entries.first().ok_or_else(|| ClassifierError::MachOParseError {
                message: "Fat binary has no architectures".to_string(),
            })?;
            slices = entries
                .iter()
                .map(|e| ContainedArch {
                    isa: e.classification.isa,
                    bitwidth: e.classification.bitwidth,
                    endianness: e.classification.endianness,
                    variant: (e.classification.variant != Variant::default())
                        .then(|| e.classification.variant.clone()),
                    offset: e.offset,
                    size: e.size,
                    extensions: e
                        .classification
                        .extensions
                        .iter()
                        .map(|x| ExtensionDetection::from_format(&x.name, x.category))
                        .collect(),
                })
                .collect();
            notes.push(Note::info(format!(
                "Universal binary containing {} architectures",
                entries.len()
            )));
            first.classification.clone()
        }
        formats::DetectedFormat::Epr | formats::DetectedFormat::Vbf | formats::DetectedFormat::Hex { .. } => {
            // Containers whose firmware payload can be extracted: header and
            // metadata first, then the payload, then the whole file (EPR
            // detection is purely structural and can be wrong).
            let parsed = match detected {
                formats::DetectedFormat::Epr => formats::epr::parse_with_payload(data),
                formats::DetectedFormat::Hex { variant } => formats::hex::parse_with_payload(data, variant),
                _ => formats::vbf::parse_with_payload(data),
            };
            match parsed {
                Ok((r, _)) if !matches!(r.isa, Isa::Unknown(_)) => r,
                Ok((r, payload)) => {
                    let (mut h, mut c) = heuristic(if payload.is_empty() { data } else { &payload }, options);
                    if h.is_err() && !payload.is_empty() {
                        (h, c) = heuristic(data, options);
                    }
                    match h {
                        Ok(h) => {
                            candidates = c;
                            adopt_heuristic(&r, h)
                        }
                        Err(_) => {
                            notes.push(Note::warning("Container payload ISA could not be determined"));
                            r
                        }
                    }
                }
                Err(e) => fallback_to_heuristics(data, options, &format, e, &mut candidates, &mut notes)?,
            }
        }
        other => match formats::parse_detected(data, &other) {
            Ok(r) if matches!(r.isa, Isa::Unknown(_)) => {
                // The container does not name the ISA (or names one we cannot
                // map): the code may still tell.
                let (h, c) = heuristic(data, options);
                match h {
                    Ok(h) => {
                        candidates = c;
                        adopt_heuristic(&r, h)
                    }
                    Err(_) => r,
                }
            }
            Ok(r) => r,
            Err(e) => fallback_to_heuristics(data, options, &format, e, &mut candidates, &mut notes)?,
        },
    };

    let from_code = result.source == ClassificationSource::Heuristic;
    let mut extensions: Vec<ExtensionDetection> = result
        .extensions
        .iter()
        .map(|e| ExtensionDetection {
            name: e.name.clone(),
            category: e.category,
            confidence: e.confidence,
            source: if from_code {
                ExtensionSource::CodePattern
            } else {
                ExtensionSource::FormatAttribute
            },
        })
        .collect();
    let mut result = result;
    if options.detect_extensions && !matches!(result.isa, Isa::Unknown(_)) {
        for ext in extensions::detect_from_code(data, result.isa, result.endianness) {
            if !result.extensions.iter().any(|e| e.name == ext.name) {
                extensions.push(ExtensionDetection::from_code(&ext.name, ext.category, ext.confidence));
                result.extensions.push(ext);
            }
        }
    }

    Ok(Classified {
        format,
        result,
        candidates,
        slices,
        extensions,
        notes,
    })
}

/// A container was recognised but could not be parsed. The recognition may
/// have been wrong (many formats have 2-byte magics or purely structural
/// detection), so classify the bytes as code; if that fails too, the parse
/// error is the more useful one to report.
fn fallback_to_heuristics(
    data: &[u8],
    options: &ClassifierOptions,
    format: &FormatDetection,
    error: ClassifierError,
    candidates: &mut Vec<IsaCandidate>,
    notes: &mut Vec<Note>,
) -> Result<ClassificationResult> {
    let (h, c) = heuristic(data, options);
    match h {
        Ok(h) => {
            *candidates = c;
            notes.push(Note::warning(format!(
                "Looked like {:?} but did not parse ({error}); classified as raw code",
                format.format
            )));
            Ok(h)
        }
        Err(_) => Err(error),
    }
}

/// Convert internal DetectedFormat to public FormatDetection.
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
        DetectedFormat::Omf => FormatDetection::new(FileFormat::Omf),
        DetectedFormat::Som => FormatDetection::new(FileFormat::Som),
        DetectedFormat::Aof => FormatDetection::new(FileFormat::Aof),
        DetectedFormat::Epoc => FormatDetection::new(FileFormat::Epoc),
        DetectedFormat::Esp => FormatDetection::new(FileFormat::EspFirmware),
        DetectedFormat::Palm => FormatDetection::new(FileFormat::PalmPdb),
        DetectedFormat::AmigaHunk => FormatDetection::new(FileFormat::AmigaHunk),
        DetectedFormat::Tds => FormatDetection::new(FileFormat::Tds),
        DetectedFormat::Os9 => FormatDetection::new(FileFormat::Os9),
        DetectedFormat::Spc => FormatDetection::new(FileFormat::SnesSpc),
        DetectedFormat::TmObj => FormatDetection::new(FileFormat::TmObj),
        DetectedFormat::Lod => FormatDetection::new(FileFormat::DspLod),
        DetectedFormat::Goff => FormatDetection::new(FileFormat::Goff),
        DetectedFormat::LlvmBc { .. } => FormatDetection::new(FileFormat::LlvmBc),
        DetectedFormat::FatElf => FormatDetection::new(FileFormat::FatElf),
        DetectedFormat::Ols => FormatDetection::new(FileFormat::Ols),
        DetectedFormat::Epr => FormatDetection::new(FileFormat::Epr),
        DetectedFormat::Sgo => FormatDetection::new(FileFormat::Sgo),
        DetectedFormat::Vbf => FormatDetection::new(FileFormat::Vbf),
        DetectedFormat::Frf => FormatDetection::new(FileFormat::Frf),
        DetectedFormat::Bcf => FormatDetection::new(FileFormat::Bcf),
        DetectedFormat::Sox => FormatDetection::new(FileFormat::Sox),
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
        KernelFormat::LinuxX86 { .. } | KernelFormat::LinuxArm64 | KernelFormat::LinuxRiscv => {
            FileFormat::ZImage
        }
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

/// ISAs that can be recognised in headerless data (from the embedded model).
///
/// Container formats map many more ISAs from their headers.
pub fn supported_isas() -> Vec<Isa> {
    heuristics::supported_isas()
}

/// Detect multiple ISAs in a binary using windowed analysis.
///
/// Returns every ISA family that owns a meaningful share of the code windows,
/// most dominant first.
pub fn detect_multi_isa(data: &[u8], window_size: usize) -> Vec<DetectedIsa> {
    heuristics::detect_multi_isa(data, &ClassifierOptions::new(), window_size)
}

/// Quick check whether headerless data looks like code of `isa`.
///
/// Runs the code model on at most 64 KB and compares the winning ISA,
/// ignoring bitwidth/endianness differences within a family (MIPS32 code
/// satisfies `Isa::Mips64` and vice versa).
pub fn quick_check(data: &[u8], isa: Isa) -> bool {
    let options = ClassifierOptions {
        min_confidence: 0.3,
        ..ClassifierOptions::fast()
    };
    match heuristics::analyze(data, &options) {
        Ok(r) => {
            r.isa == isa
                || heuristics::family_of(r.isa).is_some_and(|f| Some(f) == heuristics::family_of(isa))
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }

    #[test]
    fn test_supported_isas() {
        let isas = supported_isas();
        assert!(isas.contains(&Isa::X86_64));
        assert!(isas.contains(&Isa::AArch64));
    }

    fn elf_header(class: u8, machine: u16) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = class;
        data[5] = 1;
        data[6] = 1;
        data[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        data
    }

    #[test]
    fn test_classify_elf_headers() {
        let r = classify_bytes(&elf_header(2, 0x3E)).unwrap();
        assert_eq!(
            (r.isa, r.bitwidth, r.endianness, r.format),
            (Isa::X86_64, 64, Endianness::Little, FileFormat::Elf)
        );
        assert_eq!(classify_bytes(&elf_header(2, 0xB7)).unwrap().isa, Isa::AArch64);
        assert_eq!(classify_bytes(&elf_header(2, 0xF3)).unwrap().isa, Isa::RiscV64);
    }

    #[test]
    fn test_payload_matches_classification() {
        let data = elf_header(2, 0x3E);
        let r = classify_bytes(&data).unwrap();
        let p = detect_bytes(&data).unwrap();
        assert_eq!(p.primary.isa, r.isa);
        assert_eq!(p.primary.confidence, r.confidence);
        assert_eq!(p.primary.source, r.source);
    }

    #[test]
    fn test_random_data_is_inconclusive() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let data: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(matches!(
            classify_bytes(&data),
            Err(ClassifierError::HeuristicInconclusive { .. })
        ));
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

    #[test]
    fn test_fat_macho_slices() {
        // Fat header with two slices: x86_64 at 64 and arm64 at 128.
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        data[4..8].copy_from_slice(&2u32.to_be_bytes());
        for (i, (cpu, sub, off)) in [(0x0100_0007u32, 3u32, 64u32), (0x0100_000C, 0, 128)]
            .into_iter()
            .enumerate()
        {
            let e = 8 + 20 * i;
            data[e..e + 4].copy_from_slice(&cpu.to_be_bytes());
            data[e + 4..e + 8].copy_from_slice(&sub.to_be_bytes());
            data[e + 8..e + 12].copy_from_slice(&off.to_be_bytes());
            data[e + 12..e + 16].copy_from_slice(&64u32.to_be_bytes());
            data[e + 16..e + 20].copy_from_slice(&14u32.to_be_bytes());
            data[off as usize..off as usize + 4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        }

        let payload = detect_payload(&data, &ClassifierOptions::new()).unwrap();
        assert_eq!(payload.format.format, FileFormat::MachOFat);
        assert_eq!(payload.slices.len(), 2);
        assert_eq!((payload.slices[0].isa, payload.slices[0].offset), (Isa::X86_64, 64));
        assert_eq!((payload.slices[1].isa, payload.slices[1].offset), (Isa::AArch64, 128));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("slices") && json.contains("x86_64"));
    }
}
