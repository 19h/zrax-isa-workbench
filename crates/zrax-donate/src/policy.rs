//! The donation accept rule, applied to a zrax payload.
//!
//! Source: fwdonor `src/analyze.rs`. The server applies this rule to every
//! upload and counts a rejection against the uploader's address, so a client
//! applies the same rule, with the lists the server publishes at
//! `/api/policy`, before it sends anything. Rejection reasons are shown to
//! users and compared by fwdonor's tests; they are part of the contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zrax::types::{ClassificationSource, ClassifierOptions, DetectionPayload, Isa};
use zrax::ClassifierError;

/// Characters of the revision shown in a zrax label.
const LABEL_REVISION_CHARS: usize = 7;

/// The lists and threshold the accept rule works with. Format names are
/// zrax `FileFormat` serde names (`elf`, `uimage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Heuristic or combined ISA guesses below this confidence are not
    /// trusted.
    pub min_guess_confidence: f64,
    /// Formats accepted even when zrax resolves no ISA (firmware
    /// containers).
    pub allow: Vec<String>,
    /// Formats rejected even when zrax resolves an ISA.
    pub deny: Vec<String>,
}

/// One contained architecture of an accepted file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SliceSummary {
    /// Component role or member name.
    pub label: Option<String>,
    /// zrax `Isa` serde name when concrete.
    pub isa: Option<String>,
    /// Human ISA name.
    pub isa_name: Option<String>,
    /// Register width in bits.
    pub bitwidth: u8,
    /// Byte offset in the file.
    pub offset: u64,
    /// Byte size in the file.
    pub size: u64,
}

/// One metadata entry of an accepted file, as text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetaSummary {
    /// Display label.
    pub label: String,
    /// Value, formatted by zrax.
    pub value: String,
}

/// What zrax established about an accepted file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    /// zrax `FileFormat` serde name, e.g. `elf`, `uimage`.
    pub format: String,
    /// Human format name, e.g. `ELF`, `U-Boot uImage`.
    pub format_name: String,
    /// Format variant, when zrax names one.
    pub format_variant: Option<String>,
    /// zrax `Isa` serde name when concrete, e.g. `a_arch64`.
    pub isa: Option<String>,
    /// Human ISA name, e.g. `AArch64 (ARM64)`.
    pub isa_name: Option<String>,
    /// Short ISA label for hashtags, e.g. `aarch64`.
    pub isa_tag: Option<String>,
    /// Register width in bits.
    pub bitwidth: u8,
    /// zrax `Endianness` serde name.
    pub endianness: String,
    /// Confidence of the primary classification, 0.0 to 1.0.
    pub confidence: f64,
    /// zrax `ClassificationSource` serde name.
    pub source: String,
    /// ISA variant, when zrax names one.
    pub variant: Option<String>,
    /// Contained architectures.
    pub slices: Vec<SliceSummary>,
    /// Format metadata.
    pub metadata: Vec<MetaSummary>,
    /// Why the file was accepted: `isa` or `container`.
    pub basis: String,
    /// The zrax that classified it, from [`zrax_label`].
    pub zrax: String,
}

/// The rule's answer for one file.
// One verdict exists per file and is consumed at once; boxing the summary
// would only complicate the type shared with the server.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// The server would take the file.
    Accepted(Summary),
    /// The server would refuse the file.
    Rejected {
        /// Why, in user-facing words.
        reason: String,
    },
}

impl Verdict {
    fn reject(reason: impl Into<String>) -> Self {
        Verdict::Rejected {
            reason: reason.into(),
        }
    }

    /// Whether the server would take the file.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accepted(_))
    }
}

/// `<zrax version>@<first 7 characters of the revision>`, the label a
/// [`Summary`] names its classifier with.
pub fn zrax_label(zrax_rev: &str) -> String {
    let short_rev = zrax_rev.get(..LABEL_REVISION_CHARS).unwrap_or(zrax_rev);
    format!("{}@{short_rev}", zrax::version())
}

/// Classify `data` and apply `policy`. Synchronous and CPU-bound.
pub fn evaluate(data: &[u8], policy: &Policy, zrax_label: &str) -> Verdict {
    match zrax::detect_payload(data, &ClassifierOptions::new()) {
        Ok(payload) => judge(&payload, policy, zrax_label),
        Err(
            ClassifierError::HeuristicInconclusive { .. }
            | ClassifierError::HeuristicSparseCode { .. }
            | ClassifierError::FileTooSmall { .. },
        ) => Verdict::reject("unrecognized by zrax"),
        Err(error) => Verdict::reject(format!("malformed: {error}")),
    }
}

/// The donation rule, applied to a zrax payload:
///
/// 1. a format on the deny list is rejected;
/// 2. a concrete primary ISA is accepted, unless it is a heuristic or
///    combined guess below the policy's confidence;
/// 3. a concrete ISA in any slice is accepted;
/// 4. otherwise a format on the allow list is accepted as a container;
/// 5. everything else is rejected.
pub fn judge(payload: &DetectionPayload, policy: &Policy, zrax_label: &str) -> Verdict {
    let format = serde_name(&payload.format.format).unwrap_or_else(|| "unknown".into());
    if policy.deny.contains(&format) {
        return Verdict::reject(format!("excluded format ({format})"));
    }

    let primary = &payload.primary;
    let is_guess = matches!(
        primary.source,
        ClassificationSource::Heuristic | ClassificationSource::Combined
    );
    let primary_isa = concrete_isa(primary.isa);
    let is_primary_trusted =
        primary_isa.is_some() && (!is_guess || primary.confidence >= policy.min_guess_confidence);
    let has_slice_isa = payload
        .slices
        .iter()
        .any(|slice| concrete_isa(slice.isa).is_some());

    let basis = if is_primary_trusted || has_slice_isa {
        "isa"
    } else if policy.allow.contains(&format) {
        "container"
    } else if primary_isa.is_some() {
        return Verdict::reject(format!(
            "low-confidence guess ({:.0}% < {:.0}%)",
            primary.confidence * 100.0,
            policy.min_guess_confidence * 100.0
        ));
    } else {
        return Verdict::reject(format!("no ISA found in {format}"));
    };

    Verdict::Accepted(summarize(payload, format, basis, zrax_label))
}

fn summarize(payload: &DetectionPayload, format: String, basis: &str, zrax_label: &str) -> Summary {
    let primary = &payload.primary;
    let isa = concrete_isa(primary.isa);
    Summary {
        format,
        format_name: payload.format.format.to_string(),
        format_variant: payload.format.variant_name.clone(),
        isa_name: isa.as_ref().map(|_| primary.isa.name().to_string()),
        isa_tag: isa.as_ref().map(|_| primary.isa.to_string()),
        isa,
        bitwidth: primary.bitwidth,
        endianness: serde_name(&primary.endianness).unwrap_or_default(),
        confidence: primary.confidence,
        source: serde_name(&primary.source).unwrap_or_default(),
        variant: primary.variant.as_ref().map(ToString::to_string),
        slices: payload.slices.iter().map(summarize_slice).collect(),
        metadata: payload
            .metadata
            .iter()
            .map(|entry| MetaSummary {
                label: entry.label.clone(),
                value: entry.value.to_string(),
            })
            .collect(),
        basis: basis.to_string(),
        zrax: zrax_label.to_string(),
    }
}

fn summarize_slice(slice: &zrax::types::ContainedArch) -> SliceSummary {
    let isa = concrete_isa(slice.isa);
    SliceSummary {
        label: slice.label.clone(),
        isa_name: isa.as_ref().map(|_| slice.isa.name().to_string()),
        isa,
        bitwidth: slice.bitwidth,
        offset: slice.offset,
        size: slice.size,
    }
}

/// serde name of a value that serializes to a plain string (concrete enum
/// variants); `None` for `Isa::Unknown(_)`, which serializes as an object.
fn serde_name<T: Serialize>(value: &T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        Value::String(name) => Some(name),
        _ => None,
    }
}

fn concrete_isa(isa: Isa) -> Option<String> {
    if matches!(isa, Isa::Unknown(_)) {
        return None;
    }
    serde_name(&isa)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "0.0.0@test";

    fn policy(allow: &[&str], deny: &[&str]) -> Policy {
        Policy {
            min_guess_confidence: 0.5,
            allow: allow.iter().map(ToString::to_string).collect(),
            deny: deny.iter().map(ToString::to_string).collect(),
        }
    }

    /// A minimal little-endian ELF64 header for 64-bit ARM (`e_machine` 183):
    /// `e_ident`, `e_type` (`ET_EXEC`), `e_machine`, `e_version`, then zeros up
    /// to `e_ehsize` (64) with `e_ehsize` itself filled in.
    fn aarch64_elf_header() -> Vec<u8> {
        let mut header = vec![0u8; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2; // EI_CLASS: ELFCLASS64
        header[5] = 1; // EI_DATA: little-endian
        header[6] = 1; // EI_VERSION
        header[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type
        header[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine
        header[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        header
    }

    #[test]
    fn a_format_stated_isa_is_accepted_and_summarized() {
        let verdict = evaluate(&aarch64_elf_header(), &policy(&[], &[]), LABEL);
        let Verdict::Accepted(summary) = verdict else {
            panic!("expected acceptance, got {verdict:?}");
        };
        assert_eq!(summary.format, "elf");
        assert_eq!(summary.isa.as_deref(), Some("a_arch64"));
        assert_eq!(summary.basis, "isa");
        assert_eq!(summary.zrax, LABEL);
    }

    #[test]
    fn the_deny_list_wins_over_a_resolved_isa() {
        let verdict = evaluate(&aarch64_elf_header(), &policy(&[], &["elf"]), LABEL);
        assert_eq!(verdict, Verdict::reject("excluded format (elf)"));
    }

    #[test]
    fn unrecognized_bytes_are_rejected_with_the_shared_reason() {
        let verdict = evaluate(&[0u8; 4096], &policy(&[], &[]), LABEL);
        assert_eq!(verdict, Verdict::reject("unrecognized by zrax"));
    }

    #[test]
    fn verdicts_serialize_with_a_verdict_tag() {
        let json = serde_json::to_value(Verdict::reject("why")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "verdict": "rejected", "reason": "why" })
        );
    }

    #[test]
    fn labels_carry_the_version_and_a_short_revision() {
        let label = zrax_label("42df78c37e9f3099bd7847f906d2115bc242f34b");
        assert_eq!(label, format!("{}@42df78c", zrax::version()));
        assert_eq!(zrax_label("abc"), format!("{}@abc", zrax::version()));
    }
}
