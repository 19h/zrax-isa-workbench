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
        return Err(ClassifierError::HeuristicInconclusive {
            confidence: confidence * 100.0,
            threshold: options.min_confidence * 100.0,
        });
    }

    // Build result
    let mut result =
        ClassificationResult::from_heuristics(best.isa, best.bitwidth, best.endianness, confidence);
    result.source = ClassificationSource::Heuristic;
    result.format = FileFormat::Raw;

    // Add extensions if requested
    if options.detect_extensions {
        let extensions = crate::extensions::detect_from_code(data, best.isa, best.endianness);
        result.extensions = extensions;
    }

    Ok(result)
}

/// Score all supported architectures.
pub fn score_all_architectures(data: &[u8], options: &ClassifierOptions) -> Vec<ArchitectureScore> {
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
    scores.truncate(n);
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
        let options = ClassifierOptions {
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
        let options = ClassifierOptions {
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
        let options = ClassifierOptions {
            min_confidence: 0.15,
            ..ClassifierOptions::thorough()
        };
        let result = analyze(&data, &options).unwrap();
        assert!(matches!(result.isa, Isa::RiscV32 | Isa::RiscV64));
    }
}
