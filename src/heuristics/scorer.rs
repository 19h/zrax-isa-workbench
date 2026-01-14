//! Architecture-specific instruction pattern scoring.
//!
//! This module provides a unified interface to the scoring functions
//! implemented in each architecture module. Each scoring function analyzes
//! raw bytes for patterns characteristic of a specific ISA, returning a
//! score that represents the likelihood that the data contains code for
//! that architecture.
//!
//! The actual scoring logic is implemented in `crate::architectures::*::score()`.

use crate::architectures::{
    aarch64, alpha, arc, arm, avr, blackfin, cellspu, dalvik, hexagon, i860, ia64, jvm, loongarch,
    m68k, microblaze, mips, msp430, nios2, openrisc, parisc, ppc, riscv, s390x, sparc, superh, vax,
    wasm, x86, xtensa,
};

// =============================================================================
// Delegating functions to architecture modules
// =============================================================================

/// Score likelihood of x86/x86-64 code.
///
/// Delegates to `crate::architectures::x86::score()`.
#[inline]
pub fn score_x86(data: &[u8], bits: u8) -> i64 {
    x86::score(data, bits)
}

/// Score likelihood of ARM32 code.
///
/// Delegates to `crate::architectures::arm::score()`.
#[inline]
pub fn score_arm(data: &[u8]) -> i64 {
    arm::score(data)
}

/// Score likelihood of AArch64 code.
///
/// Delegates to `crate::architectures::aarch64::score()`.
#[inline]
pub fn score_aarch64(data: &[u8]) -> i64 {
    aarch64::score(data)
}

/// Score likelihood of RISC-V code.
///
/// Delegates to `crate::architectures::riscv::score()`.
#[inline]
pub fn score_riscv(data: &[u8], bits: u8) -> i64 {
    riscv::score(data, bits)
}

/// Score likelihood of MIPS code.
///
/// Returns (big_endian_score, little_endian_score).
/// Delegates to `crate::architectures::mips::score()`.
#[inline]
pub fn score_mips(data: &[u8]) -> (i64, i64) {
    mips::score(data)
}

/// Score likelihood of PowerPC code.
///
/// Delegates to `crate::architectures::ppc::score()`.
#[inline]
pub fn score_ppc(data: &[u8]) -> i64 {
    ppc::score(data)
}

/// Score likelihood of SPARC code.
///
/// Delegates to `crate::architectures::sparc::score()`.
#[inline]
pub fn score_sparc(data: &[u8]) -> i64 {
    sparc::score(data)
}

/// Score likelihood of s390x code.
///
/// Delegates to `crate::architectures::s390x::score()`.
#[inline]
pub fn score_s390x(data: &[u8]) -> i64 {
    s390x::score(data)
}

/// Score likelihood of m68k code.
///
/// Delegates to `crate::architectures::m68k::score()`.
#[inline]
pub fn score_m68k(data: &[u8]) -> i64 {
    m68k::score(data)
}

/// Score likelihood of SuperH code.
///
/// Delegates to `crate::architectures::superh::score()`.
#[inline]
pub fn score_superh(data: &[u8]) -> i64 {
    superh::score(data)
}

/// Score likelihood of AVR code.
///
/// Delegates to `crate::architectures::avr::score()`.
#[inline]
pub fn score_avr(data: &[u8]) -> i64 {
    avr::score(data)
}

/// Score likelihood of MSP430 code.
///
/// Delegates to `crate::architectures::msp430::score()`.
#[inline]
pub fn score_msp430(data: &[u8]) -> i64 {
    msp430::score(data)
}

/// Score likelihood of LoongArch code.
///
/// Delegates to `crate::architectures::loongarch::score()`.
#[inline]
pub fn score_loongarch(data: &[u8]) -> i64 {
    loongarch::score(data)
}

/// Score likelihood of Hexagon code.
///
/// Delegates to `crate::architectures::hexagon::score()`.
#[inline]
pub fn score_hexagon(data: &[u8]) -> i64 {
    hexagon::score(data)
}

// =============================================================================
// Additional architecture delegations
// =============================================================================

/// Score likelihood of Alpha code.
///
/// Delegates to `crate::architectures::alpha::score()`.
#[inline]
pub fn score_alpha(data: &[u8]) -> i64 {
    alpha::score(data)
}

/// Score likelihood of PA-RISC code.
///
/// Delegates to `crate::architectures::parisc::score()`.
#[inline]
pub fn score_parisc(data: &[u8]) -> i64 {
    parisc::score(data)
}

/// Score likelihood of ARC code.
///
/// Delegates to `crate::architectures::arc::score()`.
#[inline]
pub fn score_arc(data: &[u8]) -> i64 {
    arc::score(data)
}

/// Score likelihood of Xtensa code.
///
/// Delegates to `crate::architectures::xtensa::score()`.
#[inline]
pub fn score_xtensa(data: &[u8]) -> i64 {
    xtensa::score(data)
}

/// Score likelihood of MicroBlaze code.
///
/// Delegates to `crate::architectures::microblaze::score()`.
#[inline]
pub fn score_microblaze(data: &[u8]) -> i64 {
    microblaze::score(data)
}

/// Score likelihood of Nios II code.
///
/// Delegates to `crate::architectures::nios2::score()`.
#[inline]
pub fn score_nios2(data: &[u8]) -> i64 {
    nios2::score(data)
}

/// Score likelihood of OpenRISC code.
///
/// Delegates to `crate::architectures::openrisc::score()`.
#[inline]
pub fn score_openrisc(data: &[u8]) -> i64 {
    openrisc::score(data)
}

// =============================================================================
// Virtual machine bytecode scoring
// =============================================================================

/// Score likelihood of JVM bytecode.
///
/// Delegates to `crate::architectures::jvm::score()`.
#[inline]
pub fn score_jvm(data: &[u8]) -> i64 {
    jvm::score(data)
}

/// Score likelihood of WebAssembly bytecode.
///
/// Delegates to `crate::architectures::wasm::score()`.
#[inline]
pub fn score_wasm(data: &[u8]) -> i64 {
    wasm::score(data)
}

/// Score likelihood of Dalvik bytecode.
///
/// Delegates to `crate::architectures::dalvik::score()`.
#[inline]
pub fn score_dalvik(data: &[u8]) -> i64 {
    dalvik::score(data)
}

// =============================================================================
// Additional legacy/specialized architecture scoring
// =============================================================================

/// Score likelihood of Blackfin DSP code.
///
/// Delegates to `crate::architectures::blackfin::score()`.
#[inline]
pub fn score_blackfin(data: &[u8]) -> i64 {
    blackfin::score(data)
}

/// Score likelihood of IA-64/Itanium code.
///
/// Delegates to `crate::architectures::ia64::score()`.
#[inline]
pub fn score_ia64(data: &[u8]) -> i64 {
    ia64::score(data)
}

/// Score likelihood of VAX code.
///
/// Delegates to `crate::architectures::vax::score()`.
#[inline]
pub fn score_vax(data: &[u8]) -> i64 {
    vax::score(data)
}

/// Score likelihood of Intel i860 code.
///
/// Delegates to `crate::architectures::i860::score()`.
#[inline]
pub fn score_i860(data: &[u8]) -> i64 {
    i860::score(data)
}

/// Score likelihood of Cell SPU code.
///
/// Delegates to `crate::architectures::cellspu::score()`.
#[inline]
pub fn score_cellspu(data: &[u8]) -> i64 {
    cellspu::score(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_scoring() {
        let code = [0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        assert!(score_x86(&code, 64) > 0);
    }

    #[test]
    fn test_aarch64_scoring() {
        let code = [
            0x1F, 0x20, 0x03, 0xD5, // NOP
            0xC0, 0x03, 0x5F, 0xD6, // RET
        ];
        assert!(score_aarch64(&code) > 0);
    }

    #[test]
    fn test_riscv_scoring() {
        let code = [
            0x13, 0x00, 0x00, 0x00, // NOP
            0x67, 0x80, 0x00, 0x00, // RET
        ];
        assert!(score_riscv(&code, 64) > 0);
    }

    #[test]
    fn test_mips_scoring() {
        let code_be = [
            0x00, 0x00, 0x00, 0x00, // NOP
            0x03, 0xE0, 0x00, 0x08, // JR $ra
        ];
        let (be_score, _) = score_mips(&code_be);
        assert!(be_score > 0);
    }

    #[test]
    fn test_avr_scoring() {
        let code = [
            0x00, 0x00, // NOP
            0x08, 0x95, // RET
        ];
        assert!(score_avr(&code) > 0);
    }

    #[test]
    fn test_msp430_scoring() {
        let code = [
            0x03, 0x43, // NOP
            0x30, 0x41, // RET
        ];
        assert!(score_msp430(&code) > 0);
    }

    #[test]
    fn test_sparc_scoring() {
        let code = [
            0x01, 0x00, 0x00, 0x00, // NOP
            0x81, 0xC3, 0xE0, 0x08, // RETL
        ];
        assert!(score_sparc(&code) > 0);
    }

    #[test]
    fn test_s390x_scoring() {
        let code = [
            0x07, 0x00, // NOP
            0x07, 0xFE, // BR R14
        ];
        assert!(score_s390x(&code) > 0);
    }

    #[test]
    fn test_m68k_scoring() {
        let code = [
            0x4E, 0x71, // NOP
            0x4E, 0x75, // RTS
        ];
        assert!(score_m68k(&code) > 0);
    }

    #[test]
    fn test_superh_scoring() {
        let code = [
            0x09, 0x00, // NOP
            0x0B, 0x00, // RTS
        ];
        assert!(score_superh(&code) > 0);
    }

    #[test]
    fn test_loongarch_scoring() {
        let code = [
            0x00, 0x00, 0x40, 0x03, // NOP
            0x20, 0x00, 0x00, 0x4C, // RET
        ];
        assert!(score_loongarch(&code) > 0);
    }

    #[test]
    fn test_parisc_scoring() {
        let code = [
            0x08, 0x00, 0x02, 0x40, // NOP
            0xE8, 0x40, 0xC0, 0x02, // BV,N 0(%rp)
        ];
        assert!(score_parisc(&code) > 0);
    }

    #[test]
    fn test_arc_scoring() {
        let code = [
            0xE0, 0x78, // NOP_S
            0xE0, 0x7E, // J_S [blink]
        ];
        assert!(score_arc(&code) > 0);
    }

    #[test]
    fn test_xtensa_scoring() {
        let code = [
            0xF0, 0x20, 0x00, // NOP
            0x80, 0x00, 0x00, // RET
        ];
        assert!(score_xtensa(&code) > 0);
    }

    #[test]
    fn test_microblaze_scoring() {
        let code = [
            0x80, 0x00, 0x00, 0x00, // NOP
            0xB6, 0x0F, 0x00, 0x08, // RTSD r15,8
        ];
        assert!(score_microblaze(&code) > 0);
    }

    #[test]
    fn test_nios2_scoring() {
        let code = [
            0x3A, 0x88, 0x01, 0x00, // NOP
            0x3A, 0x28, 0x00, 0xF8, // RET
        ];
        assert!(score_nios2(&code) > 0);
    }

    #[test]
    fn test_openrisc_scoring() {
        let code = [
            0x15, 0x00, 0x00, 0x00, // l.nop
            0x44, 0x00, 0x48, 0x00, // l.jr r9
        ];
        assert!(score_openrisc(&code) > 0);
    }

    #[test]
    fn test_jvm_scoring() {
        // Simple Java method: aload_0, invokespecial, return
        let code = [
            0x2A,       // aload_0
            0xB7, 0x00, 0x01, // invokespecial #1
            0xB1,       // return
        ];
        assert!(score_jvm(&code) > 0);
    }

    #[test]
    fn test_wasm_scoring() {
        // Simple WASM: local.get 0, i32.const 1, i32.add, end
        let code = [
            0x20, 0x00, // local.get 0
            0x41, 0x01, // i32.const 1
            0x6A,       // i32.add
            0x0B,       // end
        ];
        assert!(score_wasm(&code) > 0);
    }

    #[test]
    fn test_dalvik_scoring() {
        // Simple Dalvik: const/4, return-void
        let code = [
            0x12, 0x00, // const/4 v0, #0
            0x0E, 0x00, // return-void
        ];
        assert!(score_dalvik(&code) > 0);
    }

    #[test]
    fn test_blackfin_scoring() {
        // Blackfin: NOP, NOP, RTS
        let code = [
            0x00, 0x00, // NOP
            0x00, 0x00, // NOP
            0x10, 0x00, // RTS
        ];
        assert!(score_blackfin(&code) > 0);
    }

    #[test]
    fn test_ia64_scoring() {
        // IA-64: MMI bundle with template 0x08
        let mut bundle = [0u8; 16];
        bundle[0] = 0x08; // MMI template
        assert!(score_ia64(&bundle) > 0);
    }

    #[test]
    fn test_vax_scoring() {
        // VAX: NOP, NOP, RSB
        let code = [0x01, 0x01, 0x05]; // NOP, NOP, RSB
        assert!(score_vax(&code) > 0);
    }

    #[test]
    fn test_i860_scoring() {
        // i860: NOP pattern
        let code = [0x00, 0x00, 0x00, 0xA0]; // NOP (0xA0000000 little-endian)
        assert!(score_i860(&code) > 0);
    }

    #[test]
    fn test_cellspu_scoring() {
        // Cell SPU: NOP (big-endian)
        let mut code = Vec::new();
        let nop: u32 = 0x201 << 21; // NOP opcode
        code.extend_from_slice(&nop.to_be_bytes());
        assert!(score_cellspu(&code) > 0);
    }
}
