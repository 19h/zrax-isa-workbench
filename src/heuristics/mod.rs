//! Heuristic analysis for ISA identification.
//!
//! This module provides pattern-based analysis of raw binary data
//! to identify the instruction set architecture when no file format
//! header is present.

pub mod scorer;

use std::collections::HashMap;

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, ClassificationSource, ClassifierOptions, Endianness, FileFormat, Isa,
};

pub use scorer::*;

/// All supported architectures for heuristic analysis.
pub const SUPPORTED_ARCHITECTURES: &[(Isa, &str)] = &[
    (Isa::X86, "x86 (32-bit)"),
    (Isa::X86_64, "x86-64 (64-bit)"),
    (Isa::Arm, "ARM (32-bit)"),
    (Isa::AArch64, "AArch64 (64-bit)"),
    (Isa::RiscV32, "RISC-V (32-bit)"),
    (Isa::RiscV64, "RISC-V (64-bit)"),
    (Isa::Mips, "MIPS (32-bit)"),
    (Isa::Mips64, "MIPS (64-bit)"),
    (Isa::Ppc, "PowerPC (32-bit)"),
    (Isa::Ppc64, "PowerPC (64-bit)"),
    (Isa::Sparc, "SPARC (32-bit)"),
    (Isa::Sparc64, "SPARC (64-bit)"),
    (Isa::S390x, "s390x (z/Architecture)"),
    (Isa::M68k, "Motorola 68000"),
    (Isa::Sh, "SuperH"),
    (Isa::Alpha, "DEC Alpha"),
    (Isa::LoongArch64, "LoongArch (64-bit)"),
    (Isa::Hexagon, "Qualcomm Hexagon"),
    (Isa::Avr, "Atmel AVR"),
    (Isa::Msp430, "TI MSP430"),
    (Isa::Parisc, "HP PA-RISC"),
    (Isa::Arc, "Synopsys ARC"),
    (Isa::Xtensa, "Tensilica Xtensa"),
    (Isa::MicroBlaze, "Xilinx MicroBlaze"),
    (Isa::Nios2, "Altera Nios II"),
    (Isa::OpenRisc, "OpenRISC"),
    (Isa::Lanai, "Lanai"),
    (Isa::Jvm, "JVM Bytecode"),
    (Isa::Wasm, "WebAssembly"),
    (Isa::Dalvik, "Dalvik Bytecode"),
    (Isa::Blackfin, "Blackfin DSP"),
    (Isa::Ia64, "IA-64/Itanium"),
    (Isa::Vax, "DEC VAX"),
    (Isa::I860, "Intel i860"),
    (Isa::CellSpu, "Cell SPU"),
    (Isa::Tricore, "Infineon TriCore"),
    (Isa::Hcs12, "Freescale/NXP HCS12"),
    (Isa::Hc11, "Motorola 68HC11"),
    (Isa::C166, "Infineon/Siemens C166"),
    (Isa::V850, "Renesas/NEC V850"),
    (Isa::Rl78, "Renesas RL78"),
    (Isa::Rh850, "Renesas RH850"),
    (Isa::K78k0r, "NEC 78K0R"),
    (Isa::S12z, "NXP/Freescale S12Z"),
    (Isa::Fr30, "Fujitsu FR30"),
    (Isa::Fr80, "Fujitsu FR80"),
    (Isa::PpcVle, "PowerPC VLE"),
];

/// Result of heuristic scoring for a single architecture.
#[derive(Debug, Clone)]
pub struct ArchitectureScore {
    /// The ISA being scored
    pub isa: Isa,
    /// Raw score (sum of pattern matches)
    pub raw_score: i64,
    /// Normalized confidence (0.0 - 1.0)
    pub confidence: f64,
    /// Detected endianness
    pub endianness: Endianness,
    /// Bitwidth
    pub bitwidth: u8,
}

/// Analyze raw binary data and return the best classification.
pub fn analyze(data: &[u8], options: &ClassifierOptions) -> Result<ClassificationResult> {
    if data.is_empty() {
        return Err(ClassifierError::FileTooSmall {
            expected: 4,
            actual: 0,
        });
    }

    // Score all architectures
    let scores = score_all_architectures(data, options);

    if scores.is_empty() {
        return Err(ClassifierError::HeuristicInconclusive {
            confidence: 0.0,
            threshold: options.min_confidence * 100.0,
        });
    }

    // Find the best and second-best matches
    let mut sorted_scores: Vec<_> = scores.iter().collect();
    sorted_scores.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    let best = sorted_scores[0];
    let second_best = sorted_scores.get(1);

    // Calculate confidence using multiple factors:
    // 1. Share of total (original method)
    // 2. Margin over second place (how decisive is the win?)
    // 3. Absolute score threshold (does it look like real code at all?)
    let total_positive: i64 = scores.iter().map(|s| s.raw_score.max(0)).sum();

    let share_confidence = if total_positive > 0 {
        best.raw_score.max(0) as f64 / total_positive as f64
    } else {
        0.0
    };

    // Margin confidence: how much better is the winner than second place?
    let margin_confidence = if let Some(second) = second_best {
        if second.raw_score > 0 {
            // Margin as a ratio: if winner is 50% higher than second, margin = 0.5
            let margin = (best.raw_score - second.raw_score) as f64 / second.raw_score as f64;
            // Scale margin to a confidence: margin of 0.2 (20% better) → ~0.5 confidence
            // margin of 1.0 (100% better) → ~0.9 confidence
            (margin / (margin + 0.25)).min(0.95)
        } else {
            0.95 // If second place has no score, winner is very confident
        }
    } else {
        0.95
    };

    // Combined confidence: use the higher of share or margin-based confidence
    // This helps when many architectures score but one clearly dominates
    let confidence = share_confidence.max(margin_confidence * 0.8);

    if confidence < options.min_confidence {
        if let Some(fallback) = try_anchor_window_fallback(data, options) {
            return Ok(fallback);
        }

        return Err(ClassifierError::HeuristicInconclusive {
            confidence: confidence * 100.0,
            threshold: options.min_confidence * 100.0,
        });
    }

    // Build result
    let mut detected_isa = best.isa;
    if detected_isa == Isa::V850 && has_marker(data, b"RH850") {
        detected_isa = Isa::Rh850;
    }

    let mut result = ClassificationResult::from_heuristics(
        detected_isa,
        best.bitwidth,
        best.endianness,
        confidence,
    );
    result.source = ClassificationSource::Heuristic;
    result.format = FileFormat::Raw;

    // Add extensions if requested
    if options.detect_extensions {
        let extensions = crate::extensions::detect_from_code(data, best.isa, best.endianness);
        result.extensions = extensions;
    }

    Ok(result)
}

fn has_marker(data: &[u8], marker: &[u8]) -> bool {
    if marker.is_empty() || data.len() < marker.len() {
        return false;
    }
    data.windows(marker.len()).any(|w| w == marker)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum FallbackHypothesis {
    Arm,
    Arc,
    Sh,
    V850,
    Mips,
}

#[derive(Debug, Clone)]
struct FallbackEvidence {
    hypothesis: FallbackHypothesis,
    anchor_score: u32,
    strong_hits: u32,
    anchor_density_per_mb: f64,
    anchor_offsets: Vec<usize>,
    anchor_bins: HashMap<usize, u32>,
    window_hits: u32,
    evidence_score: f64,
    best_confidence: f64,
    best_isa: Option<Isa>,
    best_bitwidth: Option<u8>,
    best_endianness: Option<Endianness>,
}

impl FallbackEvidence {
    fn new(hypothesis: FallbackHypothesis) -> Self {
        Self {
            hypothesis,
            anchor_score: 0,
            strong_hits: 0,
            anchor_density_per_mb: 0.0,
            anchor_offsets: Vec::new(),
            anchor_bins: HashMap::new(),
            window_hits: 0,
            evidence_score: 0.0,
            best_confidence: 0.0,
            best_isa: None,
            best_bitwidth: None,
            best_endianness: None,
        }
    }
}

#[inline]
fn push_fallback_anchor(offsets: &mut Vec<usize>, offset: usize, min_spacing: usize) {
    const MAX_OFFSETS: usize = 64;

    if offsets.len() >= MAX_OFFSETS {
        return;
    }
    if let Some(last) = offsets.last() {
        if offset.saturating_sub(*last) < min_spacing {
            return;
        }
    }
    offsets.push(offset);
}

#[inline]
fn record_fallback_anchor(
    evidence: &mut FallbackEvidence,
    offset: usize,
    weight: u32,
    min_spacing: usize,
) {
    const ANCHOR_BIN_SIZE: usize = 64 * 1024;

    evidence.anchor_score = evidence.anchor_score.saturating_add(weight);
    push_fallback_anchor(&mut evidence.anchor_offsets, offset, min_spacing);
    let bin = offset / ANCHOR_BIN_SIZE;
    let entry = evidence.anchor_bins.entry(bin).or_insert(0);
    *entry = entry.saturating_add(weight);
}

#[inline]
fn fallback_family_match(hypothesis: FallbackHypothesis, isa: Isa) -> bool {
    match hypothesis {
        FallbackHypothesis::Arm => isa == Isa::Arm,
        FallbackHypothesis::Arc => matches!(isa, Isa::Arc | Isa::ArcCompact | Isa::ArcCompact2),
        FallbackHypothesis::Sh => matches!(isa, Isa::Sh | Isa::Sh4),
        FallbackHypothesis::V850 => matches!(isa, Isa::V850 | Isa::Rh850),
        FallbackHypothesis::Mips => matches!(isa, Isa::Mips | Isa::Mips64),
    }
}

#[inline]
fn fallback_window_size(hypothesis: FallbackHypothesis) -> usize {
    match hypothesis {
        FallbackHypothesis::Arm => 2048,
        FallbackHypothesis::Arc => 4096,
        FallbackHypothesis::Sh => 16384,
        FallbackHypothesis::V850 => 4096,
        FallbackHypothesis::Mips => 8192,
    }
}

#[inline]
fn fallback_density_threshold(hypothesis: FallbackHypothesis) -> f64 {
    match hypothesis {
        FallbackHypothesis::Arm => 2000.0,
        FallbackHypothesis::Arc => 1500.0,
        FallbackHypothesis::Sh => 10_000.0,
        FallbackHypothesis::V850 => 300.0,
        FallbackHypothesis::Mips => 3000.0,
    }
}

/// Bounded fallback for large raw blobs with sparse code islands.
///
/// Strategy:
/// 1) Fast anchor prescan for a small family of historically under-detected ISAs.
/// 2) Anchor-density gating to avoid broad false positives.
/// 3) Local window scoring around anchor offsets, then strict dominance checks.
fn try_anchor_window_fallback(
    data: &[u8],
    options: &ClassifierOptions,
) -> Option<ClassificationResult> {
    if options.fast_mode || data.len() < 256 * 1024 {
        return None;
    }

    // Bound fallback work on very large blobs.
    let scan_len = data.len().min(32 * 1024 * 1024);
    let scan = &data[..scan_len];

    // Special-case CFF container blobs: these often include text headers followed
    // by sparse RH850/V850 code payloads that whole-buffer scoring dilutes.
    if scan.len() >= 64
        && (scan.starts_with(b"CFF-")
            || has_marker(&scan[..scan.len().min(512)], b"CFF-TRANSLATOR"))
    {
        let head_len = scan_len.min(16 * 1024);
        if head_len >= 1024 {
            let head = &scan[..head_len];

            // Prefer dedicated EPR parsing when available.
            if matches!(
                crate::formats::detect_format(head),
                crate::formats::DetectedFormat::Epr
            ) {
                if let Ok(mut parsed) = crate::formats::epr::parse(head) {
                    if matches!(parsed.isa, Isa::V850 | Isa::Rh850) {
                        if parsed.confidence < options.min_confidence {
                            parsed.confidence = options.min_confidence;
                        }
                        parsed.source = ClassificationSource::Heuristic;
                        parsed.format = FileFormat::Raw;
                        if options.detect_extensions {
                            parsed.extensions = crate::extensions::detect_from_code(
                                data,
                                parsed.isa,
                                parsed.endianness,
                            );
                        }
                        return Some(parsed);
                    }
                }
            }

            let opts = ClassifierOptions {
                min_confidence: 0.01,
                deep_scan: false,
                max_scan_bytes: head_len,
                detect_extensions: false,
                fast_mode: false,
            };
            let scores = score_all_architectures_raw(head, &opts);
            if let Some(v) = scores
                .iter()
                .filter(|s| matches!(s.isa, Isa::V850 | Isa::Rh850))
                .max_by(|a, b| a.raw_score.cmp(&b.raw_score))
            {
                if v.confidence >= 0.60 {
                    let mut detected = v.isa;
                    if detected == Isa::V850 && has_marker(scan, b"RH850") {
                        detected = Isa::Rh850;
                    }
                    let confidence = v.confidence.clamp(options.min_confidence, 0.95);
                    let mut result = ClassificationResult::from_heuristics(
                        detected,
                        v.bitwidth,
                        v.endianness,
                        confidence,
                    );
                    result.source = ClassificationSource::Heuristic;
                    result.format = FileFormat::Raw;
                    if options.detect_extensions {
                        result.extensions =
                            crate::extensions::detect_from_code(data, detected, v.endianness);
                    }
                    return Some(result);
                }
            }
        }
    }

    // ARM big-endian vector-stub shortcut.
    //
    // Some firmware blobs start with classic ARM BE branch stubs
    // (e.g. repeated EAxxxxxx words) and only sparse executable islands.
    if scan_len >= 64 {
        let mut be_branch_head = 0u32;
        for off in (0..64).step_by(4) {
            let w = u32::from_be_bytes([scan[off], scan[off + 1], scan[off + 2], scan[off + 3]]);
            if (w & 0xFF000000) == 0xEA000000 || (w & 0xFF000000) == 0xEB000000 {
                be_branch_head += 1;
            }
        }

        if be_branch_head >= 6 {
            let mut be_exact = 0u32;
            let head_limit = scan_len.min(1024);
            let mut off = 0usize;
            while off + 3 < head_limit {
                let w =
                    u32::from_be_bytes([scan[off], scan[off + 1], scan[off + 2], scan[off + 3]]);
                if matches!(w, 0xE320F000 | 0xE1A00000 | 0xE12FFF1E) {
                    be_exact += 1;
                }
                off += 4;
            }

            if be_exact >= 1 {
                let confidence = 0.70f64.clamp(options.min_confidence, 0.92);
                let mut result = ClassificationResult::from_heuristics(
                    Isa::Arm,
                    32,
                    Endianness::Big,
                    confidence,
                );
                result.source = ClassificationSource::Heuristic;
                result.format = FileFormat::Raw;
                if options.detect_extensions {
                    result.extensions =
                        crate::extensions::detect_from_code(data, Isa::Arm, Endianness::Big);
                }
                return Some(result);
            }
        }
    }

    // Keep anchor offsets distributed across the scanned region.
    let anchor_spacing = (scan_len / 64).max(1024);

    let mut arm = FallbackEvidence::new(FallbackHypothesis::Arm);
    let mut arc = FallbackEvidence::new(FallbackHypothesis::Arc);
    let mut sh = FallbackEvidence::new(FallbackHypothesis::Sh);
    let mut v850 = FallbackEvidence::new(FallbackHypothesis::V850);
    let mut mips = FallbackEvidence::new(FallbackHypothesis::Mips);

    // 16-bit anchor pass (ARC / SH / V850)
    let mut i = 0usize;
    while i + 1 < scan.len() {
        let hw_le = u16::from_le_bytes([scan[i], scan[i + 1]]);
        let hw_be = u16::from_be_bytes([scan[i], scan[i + 1]]);

        // ARC anchors
        if hw_le == 0x7EE0 || hw_le == 0x7FE0 {
            record_fallback_anchor(&mut arc, i, 16, anchor_spacing);
            arc.strong_hits += 1;
        } else if hw_le == 0xC0F1 || hw_le == 0xC0D1 {
            record_fallback_anchor(&mut arc, i, 10, anchor_spacing);
            arc.strong_hits += 1;
        } else if hw_le == 0x78E0 {
            record_fallback_anchor(&mut arc, i, 4, anchor_spacing);
        }

        // SuperH anchors (BE words)
        if hw_be == 0x000B {
            record_fallback_anchor(&mut sh, i, 12, anchor_spacing);
            sh.strong_hits += 1;
        } else if hw_be == 0x0009 {
            record_fallback_anchor(&mut sh, i, 2, anchor_spacing);
        }
        if i + 3 < scan.len() && scan[i..i + 4] == [0x00, 0x0B, 0x00, 0x09] {
            record_fallback_anchor(&mut sh, i, 24, anchor_spacing);
            sh.strong_hits += 2;
        }

        // V850 anchors
        if hw_le == 0x006F {
            record_fallback_anchor(&mut v850, i, 12, anchor_spacing);
            v850.strong_hits += 1;
        }
        if i + 3 < scan.len() && scan[i..i + 4] == [0x6F, 0x00, 0x00, 0x00] {
            record_fallback_anchor(&mut v850, i, 20, anchor_spacing);
            v850.strong_hits += 2;
        }

        i += 2;
    }

    // 32-bit anchor pass (ARM / MIPS), aligned.
    let mut j = 0usize;
    while j + 3 < scan.len() {
        let w_le = u32::from_le_bytes([scan[j], scan[j + 1], scan[j + 2], scan[j + 3]]);

        // ARM anchors (exact + strong structural)
        if w_le == 0xE12FFF1E {
            record_fallback_anchor(&mut arm, j, 24, anchor_spacing);
            arm.strong_hits += 1;
        } else if w_le == 0xE320F000 {
            record_fallback_anchor(&mut arm, j, 10, anchor_spacing);
            arm.strong_hits += 1;
        } else if (w_le & 0xFFFF0000) == 0xE92D0000 || (w_le & 0xFFFF0000) == 0xE8BD0000 {
            record_fallback_anchor(&mut arm, j, 14, anchor_spacing);
        }

        // MIPS anchors (little-endian words)
        if w_le == 0x03E00008 {
            record_fallback_anchor(&mut mips, j, 20, anchor_spacing);
            mips.strong_hits += 1;
        } else {
            let upper = (w_le >> 16) as u16;
            if upper == 0x27BD || upper == 0x67BD {
                record_fallback_anchor(&mut mips, j, 4, anchor_spacing);
            } else if upper == 0xAFBF || upper == 0x8FBF {
                record_fallback_anchor(&mut mips, j, 8, anchor_spacing);
            }
        }

        j += 4;
    }

    for evidence in [&mut arm, &mut arc, &mut sh, &mut v850, &mut mips] {
        evidence.anchor_density_per_mb = if scan_len > 0 {
            evidence.anchor_score as f64 * 1_048_576.0 / scan_len as f64
        } else {
            0.0
        };
    }

    // Fast direct path: if one ISA has overwhelming anchor evidence,
    // classify immediately without local window rescoring.
    let mut direct_candidates: Vec<(f64, Isa, u8, Endianness, f64)> = Vec::new();

    if arm.strong_hits >= 8 && arm.anchor_density_per_mb >= 3000.0 {
        let score = arm.strong_hits as f64 * 1.2 + arm.anchor_density_per_mb / 3500.0;
        let confidence = 0.52 + (arm.strong_hits as f64 / 512.0).min(0.28);
        direct_candidates.push((score, Isa::Arm, 32, Endianness::Little, confidence));
    }

    if arc.strong_hits >= 64 && arc.anchor_density_per_mb >= 1800.0 {
        let score = arc.strong_hits as f64 * 0.9 + arc.anchor_density_per_mb / 1800.0;
        let confidence = 0.50 + (arc.strong_hits as f64 / 1024.0).min(0.28);
        direct_candidates.push((score, Isa::Arc, 32, Endianness::Little, confidence));
    }

    if sh.strong_hits >= 64 && sh.anchor_density_per_mb >= 8000.0 {
        let score = sh.strong_hits as f64 * 0.7 + sh.anchor_density_per_mb / 1400.0;
        let confidence = 0.56 + (sh.strong_hits as f64 / 4096.0).min(0.30);
        direct_candidates.push((score, Isa::Sh, 32, Endianness::Big, confidence));
    }

    if mips.strong_hits >= 8 && mips.anchor_density_per_mb >= 1500.0 {
        let score = mips.strong_hits as f64 * 1.3 + mips.anchor_density_per_mb / 1800.0;
        let confidence = 0.52 + (mips.strong_hits as f64 / 512.0).min(0.35);
        direct_candidates.push((score, Isa::Mips64, 64, Endianness::Little, confidence));
    }

    if !direct_candidates.is_empty() {
        direct_candidates
            .sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let best = direct_candidates[0];
        let second = direct_candidates.get(1).map(|c| c.0).unwrap_or(0.0);
        let dominance = if second > 0.0 { best.0 / second } else { 10.0 };

        if dominance >= 1.15 {
            let mut detected_isa = best.1;
            if detected_isa == Isa::V850 && has_marker(data, b"RH850") {
                detected_isa = Isa::Rh850;
            }
            let confidence = best.4.clamp(options.min_confidence, 0.92);
            let mut result =
                ClassificationResult::from_heuristics(detected_isa, best.2, best.3, confidence);
            result.source = ClassificationSource::Heuristic;
            result.format = FileFormat::Raw;
            if options.detect_extensions {
                result.extensions = crate::extensions::detect_from_code(data, detected_isa, best.3);
            }
            return Some(result);
        }
    }

    let mut hypotheses: Vec<FallbackEvidence> = vec![arm, arc, sh, v850, mips]
        .into_iter()
        .filter(|e| {
            e.anchor_score > 0
                && e.anchor_offsets.len() >= 2
                && e.anchor_density_per_mb >= fallback_density_threshold(e.hypothesis)
        })
        .collect();

    if hypotheses.is_empty() {
        return None;
    }

    // Keep fallback bounded: evaluate only the strongest anchor hypotheses.
    hypotheses.sort_by(|a, b| {
        b.anchor_density_per_mb
            .partial_cmp(&a.anchor_density_per_mb)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hypotheses.truncate(2);

    for evidence in &mut hypotheses {
        let mut offset_candidates: Vec<usize> = Vec::new();

        // Prefer densest anchor regions instead of uniformly sampling offsets.
        let mut bins: Vec<(usize, u32)> = evidence
            .anchor_bins
            .iter()
            .map(|(bin, score)| (*bin, *score))
            .collect();
        bins.sort_by(|a, b| b.1.cmp(&a.1));
        for (bin, _) in bins.into_iter().take(3) {
            let center = bin
                .saturating_mul(64 * 1024)
                .saturating_add(32 * 1024)
                .min(scan_len.saturating_sub(1));
            offset_candidates.push(center);
        }

        if offset_candidates.is_empty() {
            let stride = (evidence.anchor_offsets.len() / 3).max(1);
            for offset in evidence.anchor_offsets.iter().step_by(stride).take(3) {
                offset_candidates.push(*offset);
            }
        }

        let window_size = fallback_window_size(evidence.hypothesis);
        let opts = ClassifierOptions {
            min_confidence: 0.01,
            deep_scan: false,
            max_scan_bytes: window_size,
            detect_extensions: false,
            fast_mode: false,
        };

        for &anchor_off in &offset_candidates {
            let start = anchor_off
                .saturating_sub(window_size / 2)
                .min(scan_len.saturating_sub(1));
            let end = (start + window_size).min(scan_len);
            if end <= start || end - start < 64 {
                continue;
            }
            let window = &scan[start..end];
            if is_padding_or_empty(window) || is_string_data(window) {
                continue;
            }

            let scores = score_all_architectures_raw(window, &opts);
            let Some(overall_best) = scores.first() else {
                continue;
            };

            let family_best = scores
                .iter()
                .filter(|s| fallback_family_match(evidence.hypothesis, s.isa))
                .max_by(|a, b| a.raw_score.cmp(&b.raw_score));

            let Some(fam) = family_best else {
                continue;
            };
            if fam.raw_score <= 0 || fam.confidence < 0.20 {
                continue;
            }

            // Require local competitiveness; avoid counting weak family matches.
            let close_to_top = fam.raw_score as f64 >= overall_best.raw_score.max(1) as f64 * 0.85;
            if !close_to_top {
                continue;
            }

            evidence.window_hits += 1;
            evidence.evidence_score += fam.confidence;
            if fam.isa == overall_best.isa {
                evidence.evidence_score += 0.10;
            }
            if fam.confidence > evidence.best_confidence {
                evidence.best_confidence = fam.confidence;
                evidence.best_isa = Some(fam.isa);
                evidence.best_bitwidth = Some(fam.bitwidth);
                evidence.best_endianness = Some(fam.endianness);
            }

            // Bounded cost: each hypothesis only needs a few strong windows.
            if evidence.window_hits >= 3 && evidence.evidence_score >= 1.2 {
                break;
            }
        }
    }

    hypotheses
        .retain(|e| e.window_hits > 0 && e.evidence_score >= 0.40 && e.best_confidence >= 0.28);
    if hypotheses.is_empty() {
        return None;
    }

    hypotheses.sort_by(|a, b| {
        b.evidence_score
            .partial_cmp(&a.evidence_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = &hypotheses[0];
    let second_score = hypotheses.get(1).map(|e| e.evidence_score).unwrap_or(0.0);
    let dominance = if second_score > 0.0 {
        best.evidence_score / second_score
    } else {
        10.0
    };

    // Strict acceptance criteria to protect against false positives.
    if !(best.window_hits >= 2 || best.best_confidence >= 0.45) {
        return None;
    }
    if dominance < 1.30 {
        return None;
    }

    let detected_isa = if let Some(isa) = best.best_isa {
        if isa == Isa::V850 && has_marker(data, b"RH850") {
            Isa::Rh850
        } else {
            isa
        }
    } else {
        return None;
    };

    let bitwidth = best
        .best_bitwidth
        .unwrap_or_else(|| detected_isa.default_bitwidth());
    let endianness = best.best_endianness.unwrap_or(Endianness::Little);

    let mut confidence = best.best_confidence.max(options.min_confidence);
    if dominance >= 2.0 {
        confidence = (confidence + 0.05).min(0.90);
    }

    let mut result =
        ClassificationResult::from_heuristics(detected_isa, bitwidth, endianness, confidence);
    result.source = ClassificationSource::Heuristic;
    result.format = FileFormat::Raw;
    if options.detect_extensions {
        result.extensions = crate::extensions::detect_from_code(data, detected_isa, endianness);
    }

    Some(result)
}

/// Ignore homogeneous byte runs this large during raw heuristic scoring.
///
/// Very long contiguous single-byte regions are usually padding/erased flash,
/// not executable code. Skipping them prevents low-information data from
/// dominating ISA scoring.
const HOMOGENEOUS_RUN_SKIP_BYTES: usize = 8 * 1024;

/// Chunk size used when feeding data to architecture scorers.
const SCORE_CHUNK_SIZE: usize = 64 * 1024;

/// Collect contiguous informative spans, skipping long homogeneous byte runs.
///
/// Returns ranges as `(start, end)` offsets into `data`.
fn collect_informative_spans(
    data: &[u8],
    target_bytes: usize,
    min_homogeneous_run: usize,
) -> Vec<(usize, usize)> {
    if data.is_empty() || target_bytes == 0 {
        return Vec::new();
    }

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut kept = 0usize;
    let mut i = 0usize;

    while i < data.len() && kept < target_bytes {
        let value = data[i];
        let mut j = i + 1;
        while j < data.len() && data[j] == value {
            j += 1;
        }

        let run_len = j - i;
        let is_homogeneous = min_homogeneous_run > 0 && run_len >= min_homogeneous_run;

        if !is_homogeneous {
            let remaining = target_bytes - kept;
            let take_len = run_len.min(remaining);
            let take_end = i + take_len;

            if let Some(last) = spans.last_mut() {
                if last.1 == i {
                    last.1 = take_end;
                } else {
                    spans.push((i, take_end));
                }
            } else {
                spans.push((i, take_end));
            }

            kept += take_len;

            if take_len < run_len {
                break;
            }
        }

        i = j;
    }

    spans
}

/// Score all supported architectures.
pub fn score_all_architectures(data: &[u8], options: &ClassifierOptions) -> Vec<ArchitectureScore> {
    let target_informative_bytes = options.max_scan_bytes.min(data.len());
    let informative_spans =
        collect_informative_spans(data, target_informative_bytes, HOMOGENEOUS_RUN_SKIP_BYTES);

    if informative_spans.is_empty() {
        return Vec::new();
    }

    let mut accumulated = std::collections::HashMap::new();

    for (start, end) in informative_spans {
        let span = &data[start..end];
        for chunk in span.chunks(SCORE_CHUNK_SIZE) {
            let chunk_scores = score_all_architectures_raw(chunk, options);
            for score in chunk_scores {
                let entry = accumulated
                    .entry((score.isa.clone(), score.bitwidth, score.endianness))
                    .or_insert(0i64);
                *entry += score.raw_score;
            }
        }
    }

    let mut final_scores = Vec::new();
    for ((isa, bitwidth, endianness), raw_score) in accumulated {
        final_scores.push(ArchitectureScore {
            isa,
            raw_score,
            confidence: 0.0,
            endianness,
            bitwidth,
        });
    }

    // Sort by score to find winner and runner-up
    final_scores.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    let total_positive: i64 = final_scores.iter().map(|s| s.raw_score.max(0)).sum();

    if total_positive > 0 && !final_scores.is_empty() {
        let best_score = final_scores[0].raw_score.max(0);
        let second_score = final_scores.get(1).map(|s| s.raw_score.max(0)).unwrap_or(0);

        // Calculate margin confidence for winner
        let margin_conf = if second_score > 0 {
            let margin = (best_score - second_score) as f64 / second_score as f64;
            (margin / (margin + 0.25)).min(0.95)
        } else {
            0.95
        };

        for (i, score) in final_scores.iter_mut().enumerate() {
            let share = score.raw_score.max(0) as f64 / total_positive as f64;

            // For the top scorer, also consider margin of victory
            if i == 0 {
                score.confidence = share.max(margin_conf * 0.8);
            } else {
                score.confidence = share;
            }
        }
    }

    final_scores
}

fn score_all_architectures_raw(data: &[u8], options: &ClassifierOptions) -> Vec<ArchitectureScore> {
    let max_bytes = options.max_scan_bytes.min(data.len());
    let scan_data = &data[..max_bytes];

    let mut scores = Vec::with_capacity(SUPPORTED_ARCHITECTURES.len());

    // x86/x86-64
    let x86_32_score = scorer::score_x86(scan_data, 32);
    scores.push(ArchitectureScore {
        isa: Isa::X86,
        raw_score: x86_32_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    let x86_64_score = scorer::score_x86(scan_data, 64);
    scores.push(ArchitectureScore {
        isa: Isa::X86_64,
        raw_score: x86_64_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // ARM
    let arm_score = scorer::score_arm(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Arm,
        raw_score: arm_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // AArch64
    let aarch64_score = scorer::score_aarch64(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::AArch64,
        raw_score: aarch64_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // RISC-V
    let riscv32_score = scorer::score_riscv(scan_data, 32);
    scores.push(ArchitectureScore {
        isa: Isa::RiscV32,
        raw_score: riscv32_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    let riscv64_score = scorer::score_riscv(scan_data, 64);
    scores.push(ArchitectureScore {
        isa: Isa::RiscV64,
        raw_score: riscv64_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // MIPS 32-bit (both endiannesses)
    let (mips32_be, mips32_le) = scorer::score_mips(scan_data, false);
    let (mips32_score, mips32_endian) = if mips32_be >= mips32_le {
        (mips32_be, Endianness::Big)
    } else {
        (mips32_le, Endianness::Little)
    };
    scores.push(ArchitectureScore {
        isa: Isa::Mips,
        raw_score: mips32_score,
        confidence: 0.0,
        endianness: mips32_endian,
        bitwidth: 32,
    });

    // MIPS 64-bit (both endiannesses, separate scoring for 64-bit opcodes)
    let (mips64_be, mips64_le) = scorer::score_mips(scan_data, true);
    let (mips64_score, mips64_endian) = if mips64_be >= mips64_le {
        (mips64_be, Endianness::Big)
    } else {
        (mips64_le, Endianness::Little)
    };
    scores.push(ArchitectureScore {
        isa: Isa::Mips64,
        raw_score: mips64_score,
        confidence: 0.0,
        endianness: mips64_endian,
        bitwidth: 64,
    });

    // PowerPC (big-endian)
    let ppc_be_score = scorer::score_ppc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Ppc,
        raw_score: ppc_be_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // PowerPC 64-bit: take max of BE and LE scores
    let ppc64_le_score = scorer::score_ppc_le(scan_data);
    let (ppc64_score, ppc64_endian) = if ppc_be_score >= ppc64_le_score {
        (ppc_be_score, Endianness::Big)
    } else {
        (ppc64_le_score, Endianness::Little)
    };
    scores.push(ArchitectureScore {
        isa: Isa::Ppc64,
        raw_score: ppc64_score,
        confidence: 0.0,
        endianness: ppc64_endian,
        bitwidth: 64,
    });

    // SPARC (32-bit and 64-bit)
    let sparc_score = scorer::score_sparc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Sparc,
        raw_score: sparc_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });
    scores.push(ArchitectureScore {
        isa: Isa::Sparc64,
        raw_score: sparc_score, // Same scoring logic for 64-bit
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 64,
    });

    // s390x
    let s390x_score = scorer::score_s390x(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::S390x,
        raw_score: s390x_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 64,
    });

    // m68k
    let m68k_score = scorer::score_m68k(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::M68k,
        raw_score: m68k_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // SuperH (both endiannesses — SH-1/SH-2 are typically BE, SH-3/SH-4 typically LE)
    let (sh_be, sh_le) = scorer::score_superh(scan_data);
    let (sh_score, sh_endian) = if sh_be >= sh_le {
        (sh_be, Endianness::Big)
    } else {
        (sh_le, Endianness::Little)
    };
    scores.push(ArchitectureScore {
        isa: Isa::Sh,
        raw_score: sh_score,
        confidence: 0.0,
        endianness: sh_endian,
        bitwidth: 32,
    });

    // Alpha
    let alpha_score = scorer::score_alpha(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Alpha,
        raw_score: alpha_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // LoongArch
    let loongarch_score = scorer::score_loongarch(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::LoongArch64,
        raw_score: loongarch_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // Hexagon
    let hexagon_score = scorer::score_hexagon(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Hexagon,
        raw_score: hexagon_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // AVR
    let avr_score = scorer::score_avr(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Avr,
        raw_score: avr_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 8,
    });

    // MSP430
    let msp430_score = scorer::score_msp430(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Msp430,
        raw_score: msp430_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 16,
    });

    // PA-RISC
    let parisc_score = scorer::score_parisc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Parisc,
        raw_score: parisc_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // ARC
    let arc_score = scorer::score_arc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Arc,
        raw_score: arc_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // Xtensa
    let xtensa_score = scorer::score_xtensa(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Xtensa,
        raw_score: xtensa_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // MicroBlaze
    let microblaze_score = scorer::score_microblaze(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::MicroBlaze,
        raw_score: microblaze_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // Nios II
    let nios2_score = scorer::score_nios2(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Nios2,
        raw_score: nios2_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // OpenRISC
    let openrisc_score = scorer::score_openrisc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::OpenRisc,
        raw_score: openrisc_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // Lanai
    let lanai_score = scorer::score_lanai(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Lanai,
        raw_score: lanai_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // JVM Bytecode
    let jvm_score = scorer::score_jvm(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Jvm,
        raw_score: jvm_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32, // Stack-based, but operand stack is 32-bit slots
    });

    // WebAssembly
    let wasm_score = scorer::score_wasm(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Wasm,
        raw_score: wasm_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32, // WASM 1.0 is 32-bit memory addressing
    });

    // Dalvik Bytecode
    let dalvik_score = scorer::score_dalvik(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Dalvik,
        raw_score: dalvik_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // Blackfin DSP
    let blackfin_score = scorer::score_blackfin(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Blackfin,
        raw_score: blackfin_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // IA-64/Itanium
    let ia64_score = scorer::score_ia64(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Ia64,
        raw_score: ia64_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 64,
    });

    // DEC VAX
    let vax_score = scorer::score_vax(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Vax,
        raw_score: vax_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // Intel i860
    let i860_score = scorer::score_i860(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::I860,
        raw_score: i860_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // Cell SPU
    let cellspu_score = scorer::score_cellspu(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::CellSpu,
        raw_score: cellspu_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    // TriCore
    let tricore_score = scorer::score_tricore(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Tricore,
        raw_score: tricore_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // HCS12/HCS12X (Freescale/NXP MC68HC12 / CPU12)
    let hcs12_score = scorer::score_hcs12(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Hcs12,
        raw_score: hcs12_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 16,
    });

    // Motorola 68HC11
    let hc11_score = scorer::score_hc11(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Hc11,
        raw_score: hc11_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 8,
    });

    // C166/C167/ST10 (Infineon/Siemens)
    let c166_score = scorer::score_c166(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::C166,
        raw_score: c166_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 16,
    });

    // Renesas RL78 (successor to NEC 78K) — 8/16-bit little-endian MCU
    let rl78_score = scorer::score_rl78(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Rl78,
        raw_score: rl78_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 16,
    });

    // Renesas/NEC V850
    let v850_score = scorer::score_v850(scan_data);

    let fr30_score = scorer::score_fr30(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Fr30,
        raw_score: fr30_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    let s12z_score = scorer::score_s12z(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::S12z,
        raw_score: s12z_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 16,
    });

    let ppcvle_score = scorer::score_ppcvle(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::PpcVle,
        raw_score: ppcvle_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });
    scores.push(ArchitectureScore {
        isa: Isa::V850,
        raw_score: v850_score,
        confidence: 0.0,
        endianness: Endianness::Little,
        bitwidth: 32,
    });

    // Calculate confidence using margin-based approach
    // Sort by score to find winner and runner-up
    scores.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    let total_positive: i64 = scores.iter().map(|s| s.raw_score.max(0)).sum();

    if total_positive > 0 && !scores.is_empty() {
        let best_score = scores[0].raw_score.max(0);
        let second_score = scores.get(1).map(|s| s.raw_score.max(0)).unwrap_or(0);

        // Calculate margin confidence for winner
        let margin_conf = if second_score > 0 {
            let margin = (best_score - second_score) as f64 / second_score as f64;
            (margin / (margin + 0.25)).min(0.95)
        } else {
            0.95
        };

        for (i, score) in scores.iter_mut().enumerate() {
            let share = score.raw_score.max(0) as f64 / total_positive as f64;

            // For the top scorer, also consider margin of victory
            if i == 0 {
                score.confidence = share.max(margin_conf * 0.8);
            } else {
                score.confidence = share;
            }
        }
    }

    scores
}

/// Detected ISA from windowed analysis of firmware/multi-ISA binaries.
#[derive(Debug, Clone)]
pub struct DetectedIsa {
    /// The ISA detected
    pub isa: Isa,
    /// Number of windows where this ISA was the top scorer
    pub window_count: usize,
    /// Total bytes attributed to this ISA
    pub total_bytes: usize,
    /// Average raw score across windows
    pub avg_score: f64,
    /// Endianness
    pub endianness: Endianness,
    /// Bitwidth
    pub bitwidth: u8,
}

/// Detect multiple ISAs in a binary using sliding-window analysis.
///
/// Divides the data into fixed-size non-overlapping windows, scores each
/// window against all architectures, and aggregates which ISAs appear as
/// top scorers. Returns all ISAs that dominate at least `min_windows`
/// windows with sufficient score.
///
/// This is designed for firmware images that contain code sections from
/// multiple ISA families (e.g., AArch64 + ARM32, or Hexagon + AVR).
pub fn detect_multi_isa(
    data: &[u8],
    options: &ClassifierOptions,
    window_size: usize,
) -> Vec<DetectedIsa> {
    let min_windows: usize = 3;
    let min_bytes: usize = 2048;
    // Minimum confidence for the window winner to be counted.
    // score_all_architectures computes confidence = max(share, margin*0.8).
    // On noise data, confidence is typically 0.05-0.15 (many ISAs score similarly).
    // On real code, the correct ISA gets 0.20+ confidence.
    let min_window_confidence: f64 = 0.14;

    // Per-ISA accumulation: (raw_score, endianness, bitwidth) per window
    let mut isa_windows: HashMap<Isa, Vec<(i64, Endianness, u8)>> = HashMap::new();

    // Use window-appropriate options: scan entire window, low confidence threshold
    let window_opts = ClassifierOptions {
        min_confidence: 0.01,
        max_scan_bytes: window_size,
        deep_scan: false,
        detect_extensions: false,
        fast_mode: false,
    };

    let mut offset = 0;
    while offset + window_size <= data.len() {
        let window = &data[offset..offset + window_size];

        // Pre-filter: skip obvious non-code windows
        if is_padding_or_empty(window) || is_string_data(window) || is_high_entropy(window) {
            offset += window_size;
            continue;
        }

        // Score this window against all architectures
        let scores = score_all_architectures(window, &window_opts);

        // The scores are sorted by raw_score descending with confidence computed.
        // Only count the winner if its confidence exceeds our threshold.
        if let Some(best) = scores.first() {
            if best.raw_score > 0 && best.confidence >= min_window_confidence {
                isa_windows.entry(best.isa).or_default().push((
                    best.raw_score,
                    best.endianness,
                    best.bitwidth,
                ));
            }
        }

        offset += window_size;
    }

    // Total classified windows (those that passed confidence filter)
    let total_classified: usize = isa_windows.values().map(|w| w.len()).sum();

    // Aggregate and filter
    let mut results: Vec<DetectedIsa> = isa_windows
        .into_iter()
        .filter(|(_, windows)| {
            let count = windows.len();
            // Absolute minimum: at least 3 windows and 2KB
            if count < min_windows || count * window_size < min_bytes {
                return false;
            }
            // Relative frequency: must win at least 8% of all classified windows.
            // This eliminates noise ISAs that win a few windows by chance.
            if total_classified > 10 {
                let fraction = count as f64 / total_classified as f64;
                if fraction < 0.08 {
                    return false;
                }
            }
            true
        })
        .map(|(isa, windows)| {
            let count = windows.len();
            let total_bytes = count * window_size;
            let avg_score = windows.iter().map(|w| w.0 as f64).sum::<f64>() / count as f64;
            let endianness = windows[0].1;
            let bitwidth = windows[0].2;

            DetectedIsa {
                isa,
                window_count: count,
                total_bytes,
                avg_score,
                endianness,
                bitwidth,
            }
        })
        .collect();

    // Sort by window count descending (most dominant ISA first)
    results.sort_by(|a, b| b.window_count.cmp(&a.window_count));

    results
}

/// Check if a window is padding (all same byte or all zeros/0xFF).
fn is_padding_or_empty(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let first = data[0];
    data.iter().all(|&b| b == first)
}

/// Check if a window is mostly string/text data (>75% printable ASCII).
fn is_string_data(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| {
            b == 0 || b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7E).contains(&b)
        })
        .count();
    printable * 100 / data.len() > 75
}

/// Check if data has very high byte diversity (likely compressed/random).
/// Uses distinct byte count as a fast entropy proxy.
/// Random/compressed data uses 240-256 distinct byte values per 1KB.
/// Real machine code typically uses 100-220 distinct values.
fn is_high_entropy(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    // For 1KB windows: random data → ~250 distinct, code → 100-220
    // Scale threshold by window size: larger windows naturally see more distinct bytes
    let threshold = if data.len() >= 512 { 235 } else { 200 };
    distinct >= threshold
}

/// Get the top N architecture candidates.
pub fn top_candidates(
    data: &[u8],
    n: usize,
    options: &ClassifierOptions,
) -> Vec<ArchitectureScore> {
    let mut scores = score_all_architectures(data, options);
    scores.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));
    scores.truncate(50);
    scores
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_detection() {
        // Common x86-64 prologue with multiple distinctive patterns
        let data = [
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x48, 0x89, 0x7D, 0xF8, // mov [rbp-8], rdi
            0x48, 0x89, 0x75, 0xF0, // mov [rbp-16], rsi
            0x90, // nop
            0x90, // nop
            0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
            0x5D, // pop rbp
            0xC3, // ret
        ];

        // Use thorough options with 15% threshold for small heuristic samples
        let mut options = ClassifierOptions {
            min_confidence: 0.15,
            ..ClassifierOptions::thorough()
        };
        let result = analyze(&data, &options).unwrap();
        assert!(matches!(result.isa, Isa::X86 | Isa::X86_64));
    }

    #[test]
    fn test_aarch64_detection() {
        // AArch64 prologue with multiple distinctive patterns
        let data = [
            0xFD, 0x7B, 0xBF, 0xA9, // stp x29, x30, [sp, #-16]!
            0xFD, 0x03, 0x00, 0x91, // mov x29, sp
            0xE0, 0x03, 0x00, 0xAA, // mov x0, x0
            0xE1, 0x03, 0x01, 0xAA, // mov x1, x1
            0x1F, 0x20, 0x03, 0xD5, // nop
            0x1F, 0x20, 0x03, 0xD5, // nop
            0xFD, 0x7B, 0xC1, 0xA8, // ldp x29, x30, [sp], #16
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ];

        // Use thorough options with 15% threshold for heuristic detection
        // (lowered from 20% due to more architectures being scored)
        let mut options = ClassifierOptions {
            min_confidence: 0.15,
            ..ClassifierOptions::thorough()
        };
        let result = analyze(&data, &options).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
    }

    #[test]
    fn test_riscv_detection() {
        // RISC-V with high-scoring patterns: NOP, RET, and compressed instructions
        let data = [
            0x13, 0x00, 0x00, 0x00, // nop (addi x0, x0, 0) = 25 pts
            0x13, 0x00, 0x00, 0x00, // nop = 25 pts
            0x13, 0x00, 0x00, 0x00, // nop = 25 pts
            0x67, 0x80, 0x00, 0x00, // ret (jalr x0, x1, 0) = 30 pts
            0x01, 0x00, // c.nop = 20 pts (compressed)
            0x82, 0x80, // c.ret = 25 pts (compressed)
        ];

        // Use thorough options with 15% threshold for heuristic detection
        let mut options = ClassifierOptions {
            min_confidence: 0.15,
            ..ClassifierOptions::thorough()
        };
        let result = analyze(&data, &options).unwrap();
        assert!(matches!(result.isa, Isa::RiscV32 | Isa::RiscV64));
    }

    #[test]
    fn test_v850_rh850_marker_upgrade() {
        let mut data = vec![
            0x6F, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x6F, 0x00, // repeated JMP [r31]
            0x00, 0x00, 0x6F, 0x00, 0x00, 0x00, 0x6F, 0x00,
        ];
        data.extend_from_slice(b"RH850");

        let mut options = ClassifierOptions {
            min_confidence: 0.1,
            ..ClassifierOptions::thorough()
        };
        let result = analyze(&data, &options).unwrap();
        assert_eq!(result.isa, Isa::Rh850);
    }

    #[test]
    fn test_collect_informative_spans_skips_long_homogeneous_runs() {
        let mut data = vec![0xAA; 12];
        data.extend_from_slice(&[0x10, 0x11, 0x12, 0x13]);
        data.extend_from_slice(&vec![0x3C; 11]);
        data.extend_from_slice(&[0x20, 0x21, 0x22]);

        let spans = collect_informative_spans(&data, data.len(), 10);

        assert_eq!(spans, vec![(12, 16), (27, 30)]);
    }

    #[test]
    fn test_collect_informative_spans_reads_past_long_prefix_padding() {
        let mut data = vec![0xFF; 9000];
        data.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3]);

        let spans = collect_informative_spans(&data, 6, 8192);

        assert_eq!(spans, vec![(9000, 9006)]);
    }

    #[test]
    fn test_fallback_recovers_sparse_arm_island() {
        // Large mostly-homogeneous blob with a sparse ARM code island.
        let mut data = vec![0xFFu8; 600 * 1024];
        let base = 280 * 1024;

        // Write a compact ARM pattern repeatedly over a sparse 24KB island.
        // PUSH, NOP, BX LR
        let pat = [0xE92D4010u32, 0xE1A00000u32, 0xE12FFF1Eu32];
        for idx in 0..2048usize {
            let off = base + idx * 12;
            if off + 12 > data.len() {
                break;
            }
            data[off..off + 4].copy_from_slice(&pat[0].to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&pat[1].to_le_bytes());
            data[off + 8..off + 12].copy_from_slice(&pat[2].to_le_bytes());
        }

        let options = ClassifierOptions::new();
        let result = analyze(&data, &options).expect("fallback should classify sparse ARM island");
        assert_eq!(result.isa, Isa::Arm);
        assert!(result.confidence >= options.min_confidence);
    }

    #[test]
    fn test_fallback_arm_be_vector_stub() {
        // Build a large blob with ARM BE branch stubs at the start.
        let mut data = vec![0xFFu8; 600 * 1024];
        let branches = [
            0xEA000006u32,
            0xEA000057u32,
            0xEA000067u32,
            0xEA000070u32,
            0xEA000097u32,
            0xEA0000B8u32,
            0xEA0000C2u32,
            0xEA0000D0u32,
        ];
        for (idx, w) in branches.iter().enumerate() {
            let off = idx * 4;
            data[off..off + 4].copy_from_slice(&w.to_be_bytes());
        }
        // Include one exact ARM BE marker in the first 1KB.
        data[0x40..0x44].copy_from_slice(&0xE320F000u32.to_be_bytes());

        let options = ClassifierOptions {
            min_confidence: 0.90,
            ..ClassifierOptions::new()
        };
        let result = analyze(&data, &options).expect("fallback should classify ARM BE stub");
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.endianness, Endianness::Big);
        assert!(result.confidence >= options.min_confidence);
    }

    #[test]
    fn test_fallback_recovers_sparse_mips_island() {
        // Large mixed blob with sparse MIPS little-endian return/prologue patterns.
        let mut data = vec![0xFFu8; 700 * 1024];
        let base = 200 * 1024;

        // Repeat: addiu sp,sp,-56 ; jr ra ; nop
        //   addiu sp,sp,-56  => 0x27BDFFC8 (LE bytes C8 FF BD 27)
        //   jr ra            => 0x03E00008 (LE bytes 08 00 E0 03)
        //   nop              => 0x00000000
        for idx in 0..2048usize {
            let off = base + idx * 12;
            if off + 12 > data.len() {
                break;
            }
            data[off..off + 4].copy_from_slice(&0x27BDFFC8u32.to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&0x03E00008u32.to_le_bytes());
            data[off + 8..off + 12].copy_from_slice(&0x00000000u32.to_le_bytes());
        }

        let options = ClassifierOptions::new();
        let result = analyze(&data, &options).expect("fallback should classify sparse MIPS island");
        assert!(matches!(result.isa, Isa::Mips | Isa::Mips64));
        assert_eq!(result.endianness, Endianness::Little);
        assert!(result.confidence >= options.min_confidence);
    }

    #[test]
    fn test_analyze_inconclusive_for_large_uniform_data() {
        let data = vec![0xFF; 12 * 1024];
        let options = ClassifierOptions::new();

        let result = analyze(&data, &options);
        assert!(matches!(
            result,
            Err(ClassifierError::HeuristicInconclusive { .. })
        ));
    }
}
