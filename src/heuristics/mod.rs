//! Heuristic analysis for ISA identification.
//!
//! This module provides pattern-based analysis of raw binary data
//! to identify the instruction set architecture when no file format
//! header is present.

pub mod scorer;

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
    (Isa::Jvm, "JVM Bytecode"),
    (Isa::Wasm, "WebAssembly"),
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

    // Find the best match
    let best = scores
        .iter()
        .max_by(|a, b| a.raw_score.cmp(&b.raw_score))
        .unwrap();

    // Calculate confidence
    let total_positive: i64 = scores.iter().map(|s| s.raw_score.max(0)).sum();
    let confidence = if total_positive > 0 {
        best.raw_score.max(0) as f64 / total_positive as f64
    } else {
        0.0
    };

    if confidence < options.min_confidence {
        return Err(ClassifierError::HeuristicInconclusive {
            confidence: confidence * 100.0,
            threshold: options.min_confidence * 100.0,
        });
    }

    // Build result
    let mut result = ClassificationResult::from_heuristics(
        best.isa,
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

    // MIPS (both endiannesses)
    let (mips_be_score, mips_le_score) = scorer::score_mips(scan_data);
    if mips_be_score >= mips_le_score {
        scores.push(ArchitectureScore {
            isa: Isa::Mips,
            raw_score: mips_be_score,
            confidence: 0.0,
            endianness: Endianness::Big,
            bitwidth: 32,
        });
    } else {
        scores.push(ArchitectureScore {
            isa: Isa::Mips,
            raw_score: mips_le_score,
            confidence: 0.0,
            endianness: Endianness::Little,
            bitwidth: 32,
        });
    }

    // PowerPC
    let ppc_score = scorer::score_ppc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Ppc,
        raw_score: ppc_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
    });

    let ppc64_score = scorer::score_ppc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Ppc64,
        raw_score: ppc64_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 64,
    });

    // SPARC
    let sparc_score = scorer::score_sparc(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Sparc,
        raw_score: sparc_score,
        confidence: 0.0,
        endianness: Endianness::Big,
        bitwidth: 32,
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

    // SuperH
    let sh_score = scorer::score_superh(scan_data);
    scores.push(ArchitectureScore {
        isa: Isa::Sh,
        raw_score: sh_score,
        confidence: 0.0,
        endianness: Endianness::Little,
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

    // Calculate normalized confidence
    let total_positive: i64 = scores.iter().map(|s| s.raw_score.max(0)).sum();
    if total_positive > 0 {
        for score in &mut scores {
            score.confidence = score.raw_score.max(0) as f64 / total_positive as f64;
        }
    }

    scores
}

/// Get the top N architecture candidates.
pub fn top_candidates(data: &[u8], n: usize, options: &ClassifierOptions) -> Vec<ArchitectureScore> {
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
            0x55,             // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x48, 0x89, 0x7D, 0xF8, // mov [rbp-8], rdi
            0x48, 0x89, 0x75, 0xF0, // mov [rbp-16], rsi
            0x90,             // nop
            0x90,             // nop
            0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
            0x5D,             // pop rbp
            0xC3,             // ret
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

        // Use thorough options with 20% threshold for heuristic detection
        let options = ClassifierOptions::thorough();
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
            0x01, 0x00,             // c.nop = 20 pts (compressed)
            0x82, 0x80,             // c.ret = 25 pts (compressed)
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
