//! Zrax - Universal Binary Architecture Identification
//!
//! Identifies the processor architecture of a binary: from container headers
//! when there is one (ELF, PE/COFF, Mach-O and ~40 other formats), and from
//! the code itself when there is not (raw firmware, memory dumps, extracted
//! sections).
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use zrax::{classify_file, classify_bytes};
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
pub mod transform;
pub mod types;

#[cfg(feature = "batch")]
pub mod batch;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "wasm")]
mod workbench;

pub use error::{ClassifierError, Result};
pub use formatter::{
    CandidatesFormatter, HumanFormatter, JsonFormatter, PayloadFormatter, ShortFormatter,
};
pub use heuristics::DetectedIsa;
pub use types::{
    ClassificationMetadata, ClassificationResult, ClassificationSource, ClassifierOptions,
    ContainedArch, DecodedRange, DetectionPayload, Endianness, Extension, ExtensionCategory,
    ExtensionDetection, ExtensionSource, FileFormat, FormatDetection, Isa, IsaCandidate,
    IsaClassification, MetadataEntry, MetadataKey, MetadataValue, Note, NoteLevel, Variant,
};

use std::path::Path;

/// Classify a binary file by path.
///
/// # Example
///
/// ```rust,no_run
/// use zrax::classify_file;
///
/// let result = classify_file("/bin/ls")?;
/// println!("Architecture: {}", result.isa.name());
/// # Ok::<(), zrax::ClassifierError>(())
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
/// use zrax::{classify_bytes_with_options, ClassifierOptions};
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
    payload.metadata.extend(c.metadata);
    payload.extensions = c.extensions;
    payload.notes = r.metadata.notes.iter().cloned().map(Note::info).collect();
    payload.notes.extend(c.notes);
    Ok(payload)
}

/// Detect and analyze an image dumped as separate byte lanes, lane 0 first:
/// the even and odd 8-bit memories of a 16-bit bus, or four lanes of a
/// 32-bit bus. Offsets in the payload refer to the interleaved image.
///
/// # Errors
///
/// A lane count or size [`transform::interleave`] rejects, or the
/// classification error of the interleaved image.
pub fn detect_interleaved(
    lanes: &[&[u8]],
    options: &ClassifierOptions,
) -> Result<DetectionPayload> {
    let image = transform::interleave(lanes)?;
    let mut payload = detect_payload(&image, options)?;
    payload.notes.push(Note::info(format!(
        "Interleaved from {} byte lanes of {} B each; offsets refer to the interleaved image",
        lanes.len(),
        lanes[0].len()
    )));
    payload.metadata.push(MetadataEntry::new(
        MetadataKey::Custom("transform_lanes".into()),
        MetadataValue::Integer(lanes.len() as u64),
        "Interleaved lanes",
    ));
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
    metadata: Vec<MetadataEntry>,
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
    (result, ranked(candidates))
}

/// The ten best positive-evidence candidates of a code-model scan.
fn ranked(scores: Vec<heuristics::ArchitectureScore>) -> Vec<IsaCandidate> {
    scores
        .into_iter()
        .filter(|c| c.raw_score > 0)
        .take(10)
        .map(|c| IsaCandidate::new(c.isa, c.bitwidth, c.endianness, c.raw_score, c.confidence))
        .collect()
}

/// A raw input classified after one of the [`transform::CANDIDATES`].
struct Transformed {
    transform: transform::Transform,
    trials: usize,
    data: Vec<u8>,
    result: ClassificationResult,
    candidates: Vec<IsaCandidate>,
}

/// Try every applicable transform on an inconclusive raw input and keep the
/// most confident code-model result. Every attempt pays the union-bound
/// penalty for the number of readings tried, the original one included.
fn search_transforms(data: &[u8], options: &ClassifierOptions) -> Option<Transformed> {
    let applicable: Vec<transform::Transform> = transform::CANDIDATES
        .iter()
        .copied()
        .filter(|t| t.applies(data.len()))
        .collect();
    let trials = applicable.len() + 1;
    let quiet = ClassifierOptions {
        detect_extensions: false,
        ..options.clone()
    };
    let mut best: Option<Transformed> = None;
    for t in applicable {
        let Some(transformed) = t.apply(data) else {
            continue;
        };
        let (result, scores) =
            heuristics::analyze_detailed_with_trials(&transformed, &quiet, trials);
        let Ok(result) = result else {
            continue;
        };
        if best
            .as_ref()
            .is_some_and(|b| b.result.confidence >= result.confidence)
        {
            continue;
        }
        best = Some(Transformed {
            transform: t,
            trials,
            data: transformed,
            result,
            candidates: ranked(scores),
        });
    }
    best
}

/// Metadata recording which transform produced the analyzed bytes.
fn transform_metadata(transform: transform::Transform, trials: usize) -> Vec<MetadataEntry> {
    vec![
        MetadataEntry::new(
            MetadataKey::Custom("transform_applied".into()),
            MetadataValue::String(transform.name()),
            "Transform",
        ),
        MetadataEntry::new(
            MetadataKey::Custom("transform_trials".into()),
            MetadataValue::Integer(trials as u64),
            "Readings tried",
        ),
    ]
}

/// A container that does not parse may be a raw NAND dump with spare areas:
/// retry the same detection with each spare-area geometry removed and map
/// slice offsets back to the stored dump.
fn retry_without_spare(
    data: &[u8],
    detected: &formats::DetectedFormat,
    options: &ClassifierOptions,
    depth: usize,
) -> Option<Classified> {
    if depth != 0 || !options.try_transforms {
        return None;
    }
    let geometries: Vec<transform::Transform> = transform::CANDIDATES
        .iter()
        .copied()
        .filter(|t| matches!(t, transform::Transform::NandSpare { .. }) && t.applies(data.len()))
        .collect();
    for t in &geometries {
        let transformed = t.apply(data)?;
        let same_layout = std::mem::discriminant(&formats::detect_format(&transformed))
            == std::mem::discriminant(detected);
        if !same_layout {
            continue;
        }
        let Ok(mut inner) = classify_depth(&transformed, options, depth + 1) else {
            continue;
        };
        inner.notes.push(Note::info(format!(
            "Parsed after {}; slice offsets refer to the stored dump",
            t.name()
        )));
        inner
            .metadata
            .extend(transform_metadata(*t, geometries.len() + 1));
        for slice in &mut inner.slices {
            let (Ok(offset), Ok(size)) =
                (usize::try_from(slice.offset), usize::try_from(slice.size))
            else {
                continue;
            };
            let (offset, size) = t.stored_range(offset, size, data.len());
            if slice.decoded.is_none() {
                slice.decoded = Some(DecodedRange {
                    transform: t.name(),
                    offset: slice.offset,
                    size: slice.size,
                });
            }
            slice.offset = offset as u64;
            slice.size = size as u64;
        }
        return Some(inner);
    }
    None
}

/// Replace a container result that does not know its ISA with the code
/// model's answer, keeping the container's format and notes.
fn adopt_heuristic(
    container: &ClassificationResult,
    h: ClassificationResult,
) -> ClassificationResult {
    adopt(
        container,
        h,
        "ISA identified from the code, not the container",
    )
}

/// Take `inner`'s ISA for a container, keeping the container's format and
/// metadata, and note where the ISA came from.
fn adopt(
    container: &ClassificationResult,
    mut inner: ClassificationResult,
    note: impl Into<String>,
) -> ClassificationResult {
    inner.format = container.format;
    inner.source = ClassificationSource::Combined;
    inner.metadata = container.metadata.clone();
    inner.metadata.notes.push(note.into());
    inner
}

/// A contained component, as listed in the payload's slices.
fn component_slice(
    label: String,
    result: &ClassificationResult,
    offset: usize,
    size: usize,
    extensions: Vec<ExtensionDetection>,
) -> ContainedArch {
    ContainedArch {
        label: Some(label),
        isa: result.isa,
        bitwidth: result.bitwidth,
        endianness: result.endianness,
        variant: (result.variant != Variant::default()).then(|| result.variant.clone()),
        offset: offset as u64,
        size: size as u64,
        extensions,
        decoded: None,
    }
}

/// A TI container component, classified from its own bytes.
struct Component {
    result: ClassificationResult,
    extensions: Vec<ExtensionDetection>,
    /// Ranked alternatives that replace the container's, if the component's
    /// analysis produced (or deliberately emptied) them.
    candidates: Option<Vec<IsaCandidate>>,
}

/// Classify one TI container component on its own. Opaque components keep
/// an unknown ISA. A documented role marker (radar MSS/DSS) overrides the
/// code model; extensions are then scanned in the component's load sections.
fn classify_ti_component(
    child: &formats::ti::Child<'_>,
    container_opaque: bool,
    format: FileFormat,
    options: &ClassifierOptions,
    depth: usize,
    notes: &mut Vec<Note>,
) -> Component {
    let analyzable = !child.opaque && !container_opaque;
    let mut unknown =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, format);
    unknown.confidence = 0.0;
    let mut component = Component {
        result: unknown,
        extensions: Vec::new(),
        candidates: None,
    };
    if analyzable && depth < MAX_NESTING {
        match classify_depth(child.data, options, depth + 1) {
            Ok(inner) => {
                component.result = inner.result;
                component.extensions = inner.extensions;
                component.candidates = Some(inner.candidates);
            }
            Err(e) => notes.push(Note::warning(format!("{}: ISA unknown ({e})", child.label))),
        }
    }
    if analyzable {
        if let Some((isa, bitwidth, endianness)) = child.isa_hint {
            let r = &mut component.result;
            r.isa = isa;
            r.bitwidth = bitwidth;
            r.endianness = endianness;
            r.confidence = 1.0;
            r.source = ClassificationSource::FileFormat;
            r.variant = Variant::default();
            r.extensions.clear();
            component.extensions.clear();
            component.candidates = Some(Vec::new());
            if options.detect_extensions {
                let code = formats::ti::parse_container(child.data, formats::ti::Variant::Rprc)
                    .and_then(|image| image.payload());
                if let Ok(code) = code {
                    r.extensions = extensions::detect_from_code(&code, isa, endianness);
                    component.extensions = r
                        .extensions
                        .iter()
                        .map(|e| ExtensionDetection::from_code(&e.name, e.category, e.confidence))
                        .collect();
                }
            }
        }
    }
    notes.push(Note::info(format!(
        "{}: {} (contained {}){}",
        child.label,
        component.result.isa,
        component.result.format,
        if analyzable {
            ""
        } else {
            "; payload ISA analysis skipped"
        },
    )));
    component
}

/// Classify the load sections of a TI container without children. A
/// contiguous payload may itself be a container (an ELF or boot table in a
/// hex text file); a concatenation across gaps only goes to the code model.
fn classify_ti_payload(
    container: &formats::ti::Container<'_>,
    code: &[u8],
    options: &ClassifierOptions,
    depth: usize,
) -> Result<Classified> {
    if depth < MAX_NESTING && container.nested_payload_is_contiguous() {
        return classify_depth(code, options, depth + 1);
    }
    let (result, candidates) = heuristic(code, options);
    Ok(Classified {
        format: FormatDetection::new(FileFormat::Raw),
        result: result?,
        candidates,
        slices: Vec::new(),
        extensions: Vec::new(),
        notes: Vec::new(),
        metadata: Vec::new(),
    })
}

/// The classification of a container built on [`formats::container`],
/// merged into [`classify_depth`]'s common tail.
struct ContainerOutcome {
    result: ClassificationResult,
    candidates: Vec<IsaCandidate>,
    slices: Vec<ContainedArch>,
    notes: Vec<Note>,
    metadata: Vec<MetadataEntry>,
    /// Bytes scanned for extensions of the primary ISA.
    code: Vec<u8>,
    /// Extensions of the component that supplied the primary ISA.
    extensions: Option<Vec<ExtensionDetection>>,
}

/// Same ISA, or the same code-model family (MIPS32 and MIPS64, SH and SH-4).
fn same_family(a: Isa, b: Isa) -> bool {
    a == b || heuristics::family_of(a).is_some_and(|f| Some(f) == heuristics::family_of(b))
}

fn is_unknown(isa: Isa) -> bool {
    matches!(isa, Isa::Unknown(_))
}

/// Extensions of `isa` found in `code`, or none when detection is off.
fn code_extensions(
    code: &[u8],
    isa: Isa,
    endianness: Endianness,
    options: &ClassifierOptions,
) -> Vec<ExtensionDetection> {
    if !options.detect_extensions || is_unknown(isa) {
        return Vec::new();
    }
    extensions::detect_from_code(code, isa, endianness)
        .iter()
        .map(|e| ExtensionDetection::from_code(&e.name, e.category, e.confidence))
        .collect()
}

/// Apply an architecture a container names for a component to what the
/// component's own bytes said. The component's own header wins over the
/// container field when both are explicit; the code model never overrides
/// a field, but supplies the byte order the field leaves open.
fn apply_target(
    component: &mut Component,
    target: formats::container::Target,
    code: &[u8],
    label: &str,
    options: &ClassifierOptions,
    notes: &mut Vec<Note>,
) {
    let r = &mut component.result;
    let own_header = r.source != ClassificationSource::Heuristic && !is_unknown(r.isa);
    if !is_unknown(r.isa) && !same_family(r.isa, target.isa) {
        let evidence = if own_header {
            format!("contained {} names {}", r.format, r.isa)
        } else {
            format!("code model found {}", r.isa)
        };
        notes.push(Note::warning(format!(
            "{label}: container names {}; {evidence}",
            target.isa
        )));
        if own_header {
            return;
        }
    }
    let code_order = (same_family(r.isa, target.isa) && !is_unknown(r.isa)).then_some(r.endianness);
    let endianness = match (target.endianness, code_order) {
        (Some(field), Some(code)) if field != code => {
            let evidence = if own_header {
                format!("contained {} is {code}", r.format)
            } else {
                format!("code model found {code}")
            };
            notes.push(Note::warning(format!(
                "{label}: container byte order is {field}; {evidence}"
            )));
            field
        }
        (Some(field), _) => field,
        (None, Some(code)) => code,
        (None, None) => {
            notes.push(Note::info(format!(
                "{label}: code byte order is not encoded and could not be determined from the code"
            )));
            Endianness::BiEndian
        }
    };
    let changed = r.isa != target.isa || r.endianness != endianness;
    r.isa = target.isa;
    r.bitwidth = target.bits;
    r.endianness = endianness;
    r.confidence = 1.0;
    r.source = if code_order.is_some() && r.source == ClassificationSource::Heuristic {
        ClassificationSource::Combined
    } else {
        ClassificationSource::FileFormat
    };
    if changed {
        r.variant = Variant::default();
        component.extensions = code_extensions(code, r.isa, r.endianness, options);
        r.extensions.clear();
        component.candidates = Some(Vec::new());
    }
}

/// An unknown-ISA component of `format`.
fn unknown_component(format: FileFormat) -> Component {
    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, format);
    result.confidence = 0.0;
    Component {
        result,
        extensions: Vec::new(),
        candidates: None,
    }
}

/// Classify one child of a shared-model container from its own bytes.
/// Returns `None` for an archive member that is not a recognized format.
fn classify_child(
    child: &formats::container::Child<'_>,
    container: &formats::container::Container<'_>,
    options: &ClassifierOptions,
    depth: usize,
    notes: &mut Vec<Note>,
) -> Option<Component> {
    use formats::container::Classify;
    let member = child.classify == Classify::IfRecognized;
    if child.opaque || container.opaque {
        if !member {
            notes.push(Note::info(format!(
                "{}: opaque; payload ISA analysis skipped",
                child.label
            )));
        }
        return (!member).then(|| unknown_component(container.format));
    }
    if member
        && matches!(
            formats::detect_format(&child.data),
            formats::DetectedFormat::Raw
        )
    {
        return None;
    }
    let mut component = unknown_component(container.format);
    if depth >= MAX_NESTING {
        notes.push(Note::warning(format!(
            "{}: container nesting limit reached; not classified",
            child.label
        )));
    } else {
        match classify_depth(&child.data, options, depth + 1) {
            Ok(inner) => {
                component.result = inner.result;
                component.extensions = inner.extensions;
                component.candidates = Some(inner.candidates);
            }
            Err(e) => notes.push(Note::warning(format!("{}: ISA unknown ({e})", child.label))),
        }
    }
    if let Some(target) = child.target {
        apply_target(
            &mut component,
            target,
            &child.data,
            &child.label,
            options,
            notes,
        );
    }
    if !member {
        notes.push(Note::info(format!(
            "{}: {} (contained {})",
            child.label, component.result.isa, component.result.format
        )));
    }
    Some(component)
}

/// The slice for a classified child, in stored coordinates.
fn child_slice(child: &formats::container::Child<'_>, component: &Component) -> ContainedArch {
    let mut slice = component_slice(
        child.label.clone(),
        &component.result,
        child.offset,
        child.stored_size,
        component.extensions.clone(),
    );
    slice.decoded = child.transform.map(|transform| DecodedRange {
        transform: transform.to_string(),
        offset: 0,
        size: child.data.len() as u64,
    });
    slice
}

/// Classify a shared-model container: children on their own bytes, load
/// sections as one payload, and the container's own target over both.
fn classify_container(
    container: &formats::container::Container<'_>,
    options: &ClassifierOptions,
    depth: usize,
) -> Result<ContainerOutcome> {
    let mut out = ContainerOutcome {
        result: container.classification(),
        candidates: Vec::new(),
        slices: Vec::new(),
        notes: Vec::new(),
        metadata: container.metadata(),
        code: Vec::new(),
        extensions: None,
    };
    if container.transparent {
        classify_decoded(container, options, depth, &mut out);
        return Ok(out);
    }
    // Byte order and extensions for a named target come from the first
    // component of the same family.
    let mut target_evidence: Option<TargetEvidence> = None;
    let mut unlisted = 0usize;
    for child in &container.children {
        if out.slices.len() >= formats::container::MAX_COMPONENTS {
            unlisted += 1;
            continue;
        }
        let Some(component) = classify_child(child, container, options, depth, &mut out.notes)
        else {
            continue;
        };
        let isa = component.result.isa;
        match container.target {
            Some(target) if same_family(isa, target.isa) && target_evidence.is_none() => {
                target_evidence = Some(TargetEvidence {
                    endianness: component.result.endianness,
                    extensions: component.extensions.clone(),
                    source: child.label.clone(),
                    // The container states this child's code byte order
                    // separately (Arm BE8 instructions).
                    separate_order: child.target.is_some_and(|t| t.endianness.is_some()),
                });
            }
            None if is_unknown(out.result.isa) && !is_unknown(isa) => {
                if let Some(ranked) = &component.candidates {
                    out.candidates.clone_from(ranked);
                }
                out.extensions = Some(component.extensions.clone());
                let note = format!(
                    "Primary ISA selected from {}; other components are listed separately",
                    child.label
                );
                out.result = adopt(&out.result, component.result.clone(), note);
            }
            _ => {}
        }
        out.slices.push(child_slice(child, &component));
    }
    if unlisted > 0 {
        out.notes.push(Note::warning(format!(
            "{unlisted} further components were not classified (limit {})",
            formats::container::MAX_COMPONENTS
        )));
    }
    let payload = container.payload()?;
    if !payload.is_empty() {
        classify_sections(
            container,
            &payload,
            options,
            depth,
            &mut out,
            &mut target_evidence,
        );
    }
    if let Some(target) = container.target {
        resolve_target_order(target, target_evidence, &mut out);
    }
    if container.children.is_empty() {
        out.code = payload;
    }
    Ok(out)
}

/// Classify the concatenated load sections. One contiguous section may
/// itself be a container; a concatenation across sections only goes to the
/// code model, so it cannot manufacture a header across a gap.
fn classify_sections(
    container: &formats::container::Container<'_>,
    payload: &[u8],
    options: &ClassifierOptions,
    depth: usize,
    out: &mut ContainerOutcome,
    target_evidence: &mut Option<TargetEvidence>,
) {
    let nested = !container.code_sections && container.sections.len() == 1;
    let inner = if depth < MAX_NESTING && nested {
        classify_depth(payload, options, depth + 1)
    } else {
        let (result, candidates) = heuristic(payload, options);
        result.map(|result| Classified {
            format: FormatDetection::new(FileFormat::Raw),
            result,
            candidates,
            slices: Vec::new(),
            extensions: Vec::new(),
            notes: Vec::new(),
            metadata: Vec::new(),
        })
    };
    let Ok(inner) = inner else {
        if is_unknown(out.result.isa) && out.slices.is_empty() {
            out.notes.push(Note::warning(
                "Container payload ISA could not be determined",
            ));
        }
        return;
    };
    if is_unknown(inner.result.isa) {
        return;
    }
    match container.target {
        Some(target) => {
            if !same_family(inner.result.isa, target.isa) {
                out.notes.push(Note::warning(format!(
                    "Container names {}; the loaded code classifies as {}",
                    target.isa, inner.result.isa
                )));
            } else if target_evidence.is_none() {
                *target_evidence = Some(TargetEvidence {
                    endianness: inner.result.endianness,
                    extensions: inner.extensions,
                    source: "the loaded code".to_string(),
                    separate_order: false,
                });
            }
        }
        None if is_unknown(out.result.isa) => {
            out.result = if inner.result.format == FileFormat::Raw {
                adopt_heuristic(&out.result, inner.result)
            } else {
                let note = format!("ISA identified from contained {}", inner.result.format);
                adopt(&out.result, inner.result, note)
            };
            out.candidates = inner.candidates;
            out.extensions = Some(inner.extensions);
        }
        None => {}
    }
}

/// What the first same-family component says about a container's named
/// target.
struct TargetEvidence {
    endianness: Endianness,
    extensions: Vec<ExtensionDetection>,
    source: String,
    /// The container states this component's code byte order separately,
    /// so it cannot contradict the container's own.
    separate_order: bool,
}

/// A named target that leaves the code byte order open takes it from the
/// first same-family component; otherwise the order is reported as
/// undetermined (bi-endian).
fn resolve_target_order(
    target: formats::container::Target,
    evidence: Option<TargetEvidence>,
    out: &mut ContainerOutcome,
) {
    let Some(evidence) = evidence else {
        if target.endianness.is_none() {
            out.notes.push(Note::info(
                "Code byte order is not encoded in the header and could not be determined from the code",
            ));
        }
        return;
    };
    match target.endianness {
        None => {
            out.result.endianness = evidence.endianness;
            out.notes.push(Note::info(format!(
                "Code byte order from {}: {}",
                evidence.source, evidence.endianness
            )));
        }
        Some(field) if field != evidence.endianness && !evidence.separate_order => {
            out.notes.push(Note::warning(format!(
                "Header byte order is {field}; {} classifies as {}",
                evidence.source, evidence.endianness
            )));
        }
        Some(_) => {}
    }
    out.extensions = Some(evidence.extensions);
}

/// A codec wrapper reports its decoded content as its own: ISA, candidates,
/// extensions, slices and metadata, with slices mapped back to the stored
/// stream.
fn classify_decoded(
    container: &formats::container::Container<'_>,
    options: &ClassifierOptions,
    depth: usize,
    out: &mut ContainerOutcome,
) {
    let Some(child) = container.children.first() else {
        return;
    };
    let transform = child.transform.unwrap_or("decoded");
    if depth >= MAX_NESTING {
        out.notes.push(Note::warning(
            "Container nesting limit reached; decoded payload not classified",
        ));
        return;
    }
    let inner = match classify_depth(&child.data, options, depth + 1) {
        Ok(inner) => inner,
        Err(e) => {
            out.notes.push(Note::warning(format!(
                "Decoded payload ISA could not be determined ({e})"
            )));
            return;
        }
    };
    out.notes.push(Note::info(format!(
        "Decoded payload: {}",
        inner.format.format
    )));
    out.metadata.push(MetadataEntry::new(
        MetadataKey::Custom(format!("{}_content_format", container.key_prefix)),
        MetadataValue::String(inner.format.format.to_string()),
        "Decoded content format",
    ));
    out.metadata.extend(inner.metadata);
    out.notes.extend(inner.notes);
    out.slices = inner
        .slices
        .into_iter()
        .map(|mut slice| {
            slice.decoded = Some(DecodedRange {
                transform: transform.to_string(),
                offset: slice.offset,
                size: slice.size,
            });
            slice.offset = child.offset as u64;
            slice.size = child.stored_size as u64;
            slice
        })
        .collect();
    out.candidates = inner.candidates;
    out.extensions = Some(inner.extensions);
    if !is_unknown(inner.result.isa) {
        let mut result = inner.result;
        let mut combined = container.classification().metadata.notes;
        combined.append(&mut result.metadata.notes);
        result.metadata.notes = combined;
        result.format = container.format;
        result.source = ClassificationSource::Combined;
        out.result = result;
    }
}

/// Maximum depth of containers within containers, bounded independently of
/// attacker-controlled image counts.
const MAX_NESTING: usize = 6;

fn classify(data: &[u8], options: &ClassifierOptions) -> Result<Classified> {
    classify_depth(data, options, 0)
}

fn classify_depth(data: &[u8], options: &ClassifierOptions, depth: usize) -> Result<Classified> {
    let detected = formats::detect_format(data);
    let format = detected_to_format(&detected);
    let mut notes = Vec::new();
    let mut candidates = Vec::new();
    let mut slices = Vec::new();
    let mut metadata = Vec::new();
    let mut code_payload = None;
    let mut contained_extensions = None;

    let result = match detected {
        formats::DetectedFormat::Raw => {
            let (r, c) = heuristic(data, options);
            match r {
                Ok(r) => {
                    candidates = c;
                    r
                }
                Err(e) if depth == 0 && options.try_transforms => {
                    let Some(found) = search_transforms(data, options) else {
                        return Err(e);
                    };
                    notes.push(Note::info(format!(
                        "ISA identified after {}; the stored bytes are not in execution order",
                        found.transform.name()
                    )));
                    metadata.extend(transform_metadata(found.transform, found.trials));
                    candidates = found.candidates;
                    code_payload = Some(std::borrow::Cow::Owned(found.data));
                    found.result
                }
                Err(e) => return Err(e),
            }
        }
        formats::DetectedFormat::MachOFat { fat64, .. } => {
            let entries = formats::macho::parse_fat_all(data, fat64)?;
            let first = entries.first().ok_or_else(|| ClassifierError::MachOParseError {
                message: "Fat binary has no architectures".to_string(),
            })?;
            slices = entries
                .iter()
                .map(|e| ContainedArch {
                    label: None,
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
                    decoded: None,
                })
                .collect();
            notes.push(Note::info(format!(
                "Universal binary containing {} architectures",
                entries.len()
            )));
            first.classification.clone()
        }
        formats::DetectedFormat::TiC55xBoot => {
            let container = formats::ti_c55x::parse_container(data)?;
            metadata = container.metadata();
            container.classification()
        }
        formats::DetectedFormat::Ti { variant } => {
            let container = formats::ti::parse_container(data, variant)?;
            metadata = container.metadata();
            let mut r = container.classification();
            let code = container.payload()?;
            for child in &container.children {
                let component = classify_ti_component(
                    child,
                    container.opaque,
                    variant.format(),
                    options,
                    depth,
                    &mut notes,
                );
                if matches!(r.isa, Isa::Unknown(_)) {
                    if let Some(ranked) = component.candidates {
                        candidates = ranked;
                    }
                    if !matches!(component.result.isa, Isa::Unknown(_)) {
                        contained_extensions = Some(component.extensions.clone());
                        let note = format!(
                            "Primary ISA selected from {}; other components are listed separately",
                            child.label
                        );
                        r = adopt(&r, component.result.clone(), note);
                    }
                }
                slices.push(component_slice(
                    child.label.clone(),
                    &component.result,
                    child.offset,
                    child.data.len(),
                    component.extensions,
                ));
            }
            if matches!(r.isa, Isa::Unknown(_))
                && container.children.is_empty()
                && !container.opaque
                && !code.is_empty()
            {
                // Text and boot wrappers can themselves carry a TI table or
                // ELF. Preserve the outer format and its address metadata.
                match classify_ti_payload(&container, &code, options, depth) {
                    Ok(inner) if !matches!(inner.result.isa, Isa::Unknown(_)) => {
                        r = if inner.result.format == FileFormat::Raw {
                            adopt_heuristic(&r, inner.result)
                        } else {
                            let note =
                                format!("ISA identified from contained {}", inner.result.format);
                            adopt(&r, inner.result, note)
                        };
                        candidates = inner.candidates;
                        contained_extensions = Some(inner.extensions);
                    }
                    _ => notes.push(Note::warning("TI payload ISA could not be determined")),
                }
            }
            // Each child supplies its own ISA/extension evidence. Scanning
            // other cores or data segments using the primary ISA is invalid.
            let scanned = if container.children.is_empty() {
                code
            } else {
                Vec::new()
            };
            code_payload = Some(std::borrow::Cow::Owned(scanned));
            r
        }
        model @ (formats::DetectedFormat::Container { .. }
        | formats::DetectedFormat::Kernel { .. }
        | formats::DetectedFormat::Bflt) => {
            let container = match formats::parse_container_model(data, &model)
                .expect("container-model format")
            {
                Ok(container) => container,
                Err(e) => return retry_without_spare(data, &model, options, depth).ok_or(e),
            };
            let outcome = classify_container(&container, options, depth)?;
            candidates = outcome.candidates;
            slices = outcome.slices;
            notes = outcome.notes;
            metadata = outcome.metadata;
            code_payload = Some(std::borrow::Cow::Owned(outcome.code));
            contained_extensions = outcome.extensions;
            outcome.result
        }
        formats::DetectedFormat::Ar { variant } => {
            let mut r = formats::ar::parse(data, variant)?;
            for member in formats::ar::parse_members(data)? {
                // Only members in a recognized format are classified.
                if depth >= MAX_NESTING
                    || matches!(
                        formats::detect_format(member.data),
                        formats::DetectedFormat::Raw
                    )
                {
                    continue;
                }
                let inner = classify_depth(member.data, options, depth + 1)?;
                if matches!(r.isa, Isa::Unknown(_)) && !matches!(inner.result.isa, Isa::Unknown(_))
                {
                    contained_extensions = Some(inner.extensions.clone());
                    let mut selected = inner.result.clone();
                    selected.format = r.format;
                    selected.metadata = r.metadata.clone();
                    selected.metadata.notes.push(format!(
                        "Primary ISA from member {}; remaining object members are listed separately",
                        member.name
                    ));
                    r = selected;
                }
                slices.push(component_slice(
                    member.name,
                    &inner.result,
                    member.offset,
                    member.data.len(),
                    inner.extensions,
                ));
            }
            // Each member supplies its own extension evidence.
            code_payload = Some(std::borrow::Cow::Owned(Vec::new()));
            r
        }
        formats::DetectedFormat::D10 => {
            // CPU classification must not include FPGA/DSP data, record
            // headers, or encoded CPU bytes. A damaged D10 is an error.
            let container = formats::d10::parse_container(data)?;
            let r = container.classification();
            metadata = container.metadata();
            let code = container.cpu_code();
            let (h, c) = heuristic(&code, options);
            let result = match h {
                Ok(h) => {
                    candidates = c;
                    let mut result = adopt_heuristic(&r, h);
                    result.metadata.section_count = r.metadata.section_count;
                    result.metadata.code_size = r.metadata.code_size;
                    result
                }
                Err(_) => {
                    notes.push(Note::warning("D10 CPU payload ISA could not be determined"));
                    r
                }
            };
            slices.push(ContainedArch {
                label: Some("CPU 5:0".into()),
                isa: result.isa,
                bitwidth: result.bitwidth,
                endianness: result.endianness,
                variant: (result.variant != Variant::default()).then(|| result.variant.clone()),
                offset: container.block(5, 0).unwrap().offset as u64,
                size: code.len() as u64,
                extensions: Vec::new(),
                decoded: None,
            });
            for section in 1..=4 {
                let Some(block) = container.block(section, 0).filter(|b| !b.data.is_empty()) else {
                    continue;
                };
                let (dsp, _) = heuristic(block.data, options);
                let dsp = match dsp {
                    Ok(dsp) => dsp,
                    Err(_) => {
                        notes.push(Note::warning(format!("D10 DSP {section}:0 ISA could not be determined")));
                        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, FileFormat::D10)
                    }
                };
                let dsp_extensions = if options.detect_extensions && !matches!(dsp.isa, Isa::Unknown(_)) {
                    extensions::detect_from_code(block.data, dsp.isa, dsp.endianness)
                        .iter()
                        .map(|e| ExtensionDetection::from_code(&e.name, e.category, e.confidence))
                        .collect()
                } else { Vec::new() };
                notes.push(Note::info(format!(
                    "DSP {section}:0: {} ({}-bit, {}), classified from its own code",
                    dsp.isa, dsp.bitwidth, dsp.endianness,
                )));
                slices.push(ContainedArch {
                    label: Some(format!("DSP {section}:0")),
                    isa: dsp.isa,
                    bitwidth: dsp.bitwidth,
                    endianness: dsp.endianness,
                    variant: (dsp.variant != Variant::default()).then(|| dsp.variant.clone()),
                    offset: block.offset as u64,
                    size: block.data.len() as u64,
                    extensions: dsp_extensions,
                    decoded: None,
                });
            }
            code_payload = Some(code);
            result
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
                    // A decoded hex payload can itself be a container.
                    let nested = !payload.is_empty()
                        && depth < MAX_NESTING
                        && matches!(detected, formats::DetectedFormat::Hex { .. });
                    if nested {
                        if let Ok(inner) = classify_depth(&payload, options, depth + 1) {
                            if !matches!(inner.result.isa, Isa::Unknown(_)) {
                                return Ok(Classified {
                                    format,
                                    result: adopt(
                                        &r,
                                        inner.result,
                                        "ISA identified from decoded hex payload",
                                    ),
                                    candidates: inner.candidates,
                                    slices: Vec::new(),
                                    extensions: inner.extensions,
                                    notes,
                                    metadata,
                                });
                            }
                        }
                    }
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
    // A contained component that supplied the ISA also supplies its extensions.
    let mut extensions: Vec<ExtensionDetection> = contained_extensions.unwrap_or_else(|| {
        result
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
            .collect()
    });
    let mut result = result;
    if options.detect_extensions && !matches!(result.isa, Isa::Unknown(_)) {
        for ext in extensions::detect_from_code(code_payload.as_deref().unwrap_or(data), result.isa, result.endianness) {
            if !result.extensions.iter().any(|e| e.name == ext.name) {
                extensions.push(ExtensionDetection::from_code(&ext.name, ext.category, ext.confidence));
                result.extensions.push(ext);
            }
        }
    }

    if result.format == FileFormat::D10 {
        // The slice locates the stored CPU code; its ISA/extensions come from
        // the decoded payload. Encoded status is explicit in D10 metadata.
        slices[0].extensions = extensions.clone();
    }

    Ok(Classified {
        format,
        result,
        candidates,
        slices,
        extensions,
        notes,
        metadata,
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
        DetectedFormat::D10 => FormatDetection::new(FileFormat::D10),
        DetectedFormat::TiC55xBoot => FormatDetection::new(FileFormat::TiC55xBoot),
        DetectedFormat::Ti { variant } => {
            use formats::ti::Variant as Ti;
            let mut detection = FormatDetection::with_variant(variant.format(), variant.label());
            // Unkeyed boot tables and GP images are recognized from structure alone.
            if matches!(variant, Ti::C55xLegacy | Ti::C6000Boot | Ti::GpImage) {
                detection.confidence = 0.85;
            }
            detection
        }
        DetectedFormat::Container { kind } => {
            let mut detection = FormatDetection::with_variant(kind.format(), kind.label());
            // Weak layouts are recognized from complete structure, not a magic value.
            if kind.is_weak() {
                detection.confidence = 0.85;
            }
            detection
        }
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
    formats::kernel::file_format(*variant)
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
    if let Some(size) = result.metadata.code_size {
        entries.push(MetadataEntry::new(MetadataKey::CodeSize, MetadataValue::Integer(size), "Code Size (B)"));
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
