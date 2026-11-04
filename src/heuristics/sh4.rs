//! SH-4 instructions that SH-1, SH-2 and SH-3 code does not hold, for
//! telling SH-4 code from other SuperH code: the SH-4 runs the SH-3
//! instruction set and adds operand-cache operations, FPU register-bank and
//! transfer-size switches, and vector instructions ("SH-4 Software Manual",
//! Renesas REJ09B0318, instruction set tables).
//!
//! These instructions are rare in compiled code: 30 of 50 Debian `sh4`
//! sections hold none, each of 3,117 GCC SuperH samples at most 2 (a word
//! of a literal pool can match), and the Aristocrat MK6 game ROMs (SH7750)
//! hold 0.03 to 0.09 per 1,000 instructions in their SuperH code windows,
//! as many as SH-2 ROMs (at most 0.10: words of data inside code windows).
//! Sega NAOMI BIOS
//! ROMs (SH7091), which switch FPU modes and use the vector instructions,
//! hold 3.6 to 5.6 (MAME-identified fw1 ROMs, 2026-11-04). SH-2A and SH-3E
//! code, whose FPUs share encodings with the SH-4's, was not measured.

/// Mask that clears the `n` register field of `0000_nnnn_xxxx_xxxx` and of
/// `1111_nnmm_xxxx_xxxx`.
const REGISTER_FIELD_MASK: u16 = 0xF0FF;

/// `OCBI @Rn`, `OCBP @Rn`, `OCBWB @Rn` and `MOVCA.L R0,@Rn`, register field
/// cleared.
const CACHE_OPERATIONS: [u16; 4] = [0x0093, 0x00A3, 0x00B3, 0x00C3];

/// `FSCHG` (FPU transfer size) and `FRCHG` (FPU register bank).
const FSCHG: u16 = 0xF3FD;
const FRCHG: u16 = 0xFBFD;

/// `FIPR FVm,FVn` (`1111_nnmm_1110_1101`), register fields cleared.
const FIPR: u16 = 0xF0ED;

/// `FTRV XMTRX,FVn` (`1111_nn01_1111_1101`) and the mask that clears its
/// vector field.
const FTRV: u16 = 0xF1FD;
const FTRV_MASK: u16 = 0xF3FF;

/// `NOP`; fill words (`0x0000`, `0xFFFF`) and `NOP` are not counted as
/// instructions.
const NOP: u16 = 0x0009;

/// Whether `word` is one of the SH-4-only instructions above.
fn is_sh4_only(word: u16) -> bool {
    CACHE_OPERATIONS.contains(&(word & REGISTER_FIELD_MASK))
        || word == FSCHG
        || word == FRCHG
        || word & REGISTER_FIELD_MASK == FIPR
        || word & FTRV_MASK == FTRV
}

/// SH-4-only instructions and all instructions of a linear read of code.
pub(crate) struct Sh4OnlyCount {
    /// Instruction words that are SH-4-only instructions.
    pub(crate) sh4_only: u32,
    /// Instruction words counted (fill and `NOP` excluded).
    pub(crate) instructions: u32,
}

impl Sh4OnlyCount {
    /// SH-4-only instructions per 1,000 instructions; 0 for none.
    pub(crate) fn per_mille(&self) -> f64 {
        if self.instructions == 0 {
            0.0
        } else {
            1000.0 * f64::from(self.sh4_only) / f64::from(self.instructions)
        }
    }
}

/// SH-4-only instructions in `code`, read as 16-bit words in the given
/// byte order (`le`: little-endian).
pub(crate) fn sh4_only_count(code: &[u8], le: bool) -> Sh4OnlyCount {
    let mut count = Sh4OnlyCount {
        sh4_only: 0,
        instructions: 0,
    };
    for pair in code.chunks_exact(2) {
        let bytes = [pair[0], pair[1]];
        let word = if le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        };
        if matches!(word, 0x0000 | 0xFFFF | NOP) {
            continue;
        }
        count.instructions += 1;
        count.sh4_only += u32::from(is_sh4_only(word));
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh2_code_has_no_sh4_only_instructions() {
        // MOV.L @(4,PC),R1; JSR @R1; NOP; RTS; MOV #1,R0; STS.L PR,@-R15
        let words: [u16; 6] = [0xD101, 0x410B, 0x0009, 0x000B, 0xE001, 0x4F22];
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(sh4_only_count(&code, true).sh4_only, 0);
        assert!(sh4_only_count(&[], true).per_mille().abs() < f64::EPSILON);
    }

    #[test]
    fn sh4_cache_and_fpu_mode_instructions_are_counted_in_either_byte_order() {
        // OCBI @R4; MOVCA.L R0,@R5; FSCHG; FRCHG; FIPR FV4,FV0; FTRV XMTRX,FV8;
        // PREF @R4 (also SH-3, not counted); RTS; then NOP, which is not an
        // instruction for the count.
        let words: [u16; 9] = [
            0x0493, 0x05C3, 0xF3FD, 0xFBFD, 0xF1ED, 0xF9FD, 0x0483, 0x000B, 0x0009,
        ];
        let le: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let be: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        for count in [sh4_only_count(&le, true), sh4_only_count(&be, false)] {
            assert_eq!((count.sh4_only, count.instructions), (6, 8));
            assert!((count.per_mille() - 750.0).abs() < 1e-9);
        }
    }
}
