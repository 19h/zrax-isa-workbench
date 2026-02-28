//! Hitachi/Renesas SuperH (SH) architecture analysis.
//!
//! SuperH uses fixed 16-bit instructions and is bi-endian:
//! - SH-1, SH-2, SH-2A (automotive, Sega Saturn): typically **big-endian**
//! - SH-3, SH-4, SH-4A (Dreamcast, WinCE, networking): typically **little-endian**
//!
//! All instructions are 2 bytes, aligned on 2-byte boundaries.
//! The scorer tests both byte orders and returns (be_score, le_score).

/// Instruction format groups (bits 15:12).
pub mod format {
    pub const FMT_0: u8 = 0x0; // Misc: MOV, shifts, etc.
    pub const FMT_1: u8 = 0x1; // MOV.L @(disp,Rn), Rm
    pub const FMT_2: u8 = 0x2; // MOV.x @Rm, Rn / MOV.x Rm, @Rn
    pub const FMT_3: u8 = 0x3; // CMP, ADD, SUB
    pub const FMT_4: u8 = 0x4; // Misc: shifts, system
    pub const FMT_5: u8 = 0x5; // MOV.L @(disp,Rm), Rn
    pub const FMT_6: u8 = 0x6; // MOV.x @Rm, Rn (extended)
    pub const FMT_7: u8 = 0x7; // ADD #imm, Rn
    pub const FMT_8: u8 = 0x8; // Branches (BT, BF, etc.)
    pub const FMT_9: u8 = 0x9; // MOV.W @(disp,PC), Rn
    pub const FMT_A: u8 = 0xA; // BRA
    pub const FMT_B: u8 = 0xB; // BSR
    pub const FMT_C: u8 = 0xC; // Misc immediate ops
    pub const FMT_D: u8 = 0xD; // MOV.L @(disp,PC), Rn
    pub const FMT_E: u8 = 0xE; // MOV #imm, Rn
    pub const FMT_F: u8 = 0xF; // FPU instructions
}

/// Format 0 sub-opcodes (bits 3:0 for specific instructions).
pub mod fmt0_ops {
    // When bits 15:4 are 0x000
    pub const NOP: u16 = 0x0009;
    pub const RTS: u16 = 0x000B;
    pub const CLRT: u16 = 0x0008;
    pub const SETT: u16 = 0x0018;
    pub const CLRMAC: u16 = 0x0028;
    pub const RTE: u16 = 0x002B;
    pub const SLEEP: u16 = 0x001B;
    pub const DIV0U: u16 = 0x0019;
}

/// Format 4 sub-opcodes (system/shift operations).
pub mod fmt4_ops {
    // Format: 0100 nnnn xxxx xxxx
    pub const SHLL: u8 = 0x00; // 0100 nnnn 0000 0000
    pub const SHLR: u8 = 0x01; // 0100 nnnn 0000 0001
    pub const ROTL: u8 = 0x04; // 0100 nnnn 0000 0100
    pub const ROTR: u8 = 0x05; // 0100 nnnn 0000 0101
    pub const ROTCL: u8 = 0x24; // 0100 nnnn 0010 0100
    pub const ROTCR: u8 = 0x25; // 0100 nnnn 0010 0101
    pub const SHLL2: u8 = 0x08; // 0100 nnnn 0000 1000
    pub const SHLR2: u8 = 0x09; // 0100 nnnn 0000 1001
    pub const SHLL8: u8 = 0x18; // 0100 nnnn 0001 1000
    pub const SHLR8: u8 = 0x19; // 0100 nnnn 0001 1001
    pub const SHLL16: u8 = 0x28; // 0100 nnnn 0010 1000
    pub const SHLR16: u8 = 0x29; // 0100 nnnn 0010 1001
    pub const DT: u8 = 0x10; // 0100 nnnn 0001 0000 (decrement and test)
    pub const CMP_PL: u8 = 0x15; // 0100 nnnn 0001 0101
    pub const CMP_PZ: u8 = 0x11; // 0100 nnnn 0001 0001
    pub const JSR: u8 = 0x0B; // 0100 mmmm 0000 1011
    pub const JMP: u8 = 0x2B; // 0100 mmmm 0010 1011
    pub const TAS: u8 = 0x1B; // 0100 nnnn 0001 1011
    pub const LDS_MACH: u8 = 0x0A;
    pub const LDS_MACL: u8 = 0x1A;
    pub const LDS_PR: u8 = 0x2A;
    pub const STS_MACH: u8 = 0x0A;
    pub const STS_MACL: u8 = 0x1A;
    pub const STS_PR: u8 = 0x2A;
}

/// Format 8 sub-opcodes (conditional branches).
pub mod fmt8_ops {
    pub const BT: u8 = 0x9; // 1000 1001 dddd dddd
    pub const BF: u8 = 0xB; // 1000 1011 dddd dddd
    pub const BT_S: u8 = 0xD; // 1000 1101 dddd dddd (delay slot)
    pub const BF_S: u8 = 0xF; // 1000 1111 dddd dddd (delay slot)
}

/// Common SuperH instruction patterns.
pub mod patterns {
    /// NOP.
    pub const NOP: u16 = 0x0009;

    /// RTS (return from subroutine).
    pub const RTS: u16 = 0x000B;

    /// RTE (return from exception).
    pub const RTE: u16 = 0x002B;

    /// SLEEP.
    pub const SLEEP: u16 = 0x001B;

    /// CLRT (clear T bit).
    pub const CLRT: u16 = 0x0008;

    /// SETT (set T bit).
    pub const SETT: u16 = 0x0018;

    /// CLRMAC.
    pub const CLRMAC: u16 = 0x0028;

    /// DIV0U (divide step setup).
    pub const DIV0U: u16 = 0x0019;

    /// TRAPA #imm mask (0xC3xx).
    pub const TRAPA_MASK: u16 = 0xFF00;
    pub const TRAPA_VAL: u16 = 0xC300;

    /// BRA mask (0xAxxx).
    pub const BRA_MASK: u16 = 0xF000;
    pub const BRA_VAL: u16 = 0xA000;

    /// BSR mask (0xBxxx).
    pub const BSR_MASK: u16 = 0xF000;
    pub const BSR_VAL: u16 = 0xB000;

    /// JSR @Rm pattern (0x4m0B).
    pub const JSR_MASK: u16 = 0xF0FF;
    pub const JSR_VAL: u16 = 0x400B;

    /// JMP @Rm pattern (0x4m2B).
    pub const JMP_MASK: u16 = 0xF0FF;
    pub const JMP_VAL: u16 = 0x402B;

    /// MOV #imm, Rn pattern (0xEnii).
    pub const MOV_IMM_MASK: u16 = 0xF000;
    pub const MOV_IMM_VAL: u16 = 0xE000;

    /// ADD #imm, Rn pattern (0x7nii).
    pub const ADD_IMM_MASK: u16 = 0xF000;
    pub const ADD_IMM_VAL: u16 = 0x7000;
}

/// Extract format field (bits 15:12).
pub fn get_format(instr: u16) -> u8 {
    ((instr >> 12) & 0x0F) as u8
}

/// Extract Rn field (bits 11:8).
pub fn get_rn(instr: u16) -> u8 {
    ((instr >> 8) & 0x0F) as u8
}

/// Extract Rm field (bits 7:4).
pub fn get_rm(instr: u16) -> u8 {
    ((instr >> 4) & 0x0F) as u8
}

/// Extract 4-bit displacement (bits 3:0).
pub fn get_disp4(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract 8-bit immediate/displacement (bits 7:0).
pub fn get_imm8(instr: u16) -> u8 {
    (instr & 0xFF) as u8
}

/// Extract 8-bit signed displacement.
pub fn get_disp8_signed(instr: u16) -> i8 {
    (instr & 0xFF) as i8
}

/// Extract 12-bit displacement for BRA/BSR (bits 11:0).
pub fn get_disp12(instr: u16) -> i16 {
    let val = (instr & 0x0FFF) as i16;
    // Sign extend from 12 bits
    if val & 0x0800 != 0 {
        val | !0x0FFF
    } else {
        val
    }
}

/// Extract sub-opcode (bits 3:0).
pub fn get_subop(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract extended sub-opcode (bits 7:0).
pub fn get_subop_ext(instr: u16) -> u8 {
    (instr & 0xFF) as u8
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u16) -> bool {
    instr == patterns::NOP
}

/// Check if instruction is RTS.
pub fn is_rts(instr: u16) -> bool {
    instr == patterns::RTS
}

/// Check if instruction is any return type.
pub fn is_return(instr: u16) -> bool {
    matches!(instr, patterns::RTS | patterns::RTE)
}

/// Check if instruction is a branch (BRA, BT, BF, etc.).
pub fn is_branch(instr: u16) -> bool {
    let fmt = get_format(instr);
    match fmt {
        format::FMT_8 => true, // BT, BF, BT/S, BF/S
        format::FMT_A => true, // BRA
        format::FMT_B => true, // BSR
        _ => false,
    }
}

/// Check if instruction is BRA (unconditional branch).
pub fn is_bra(instr: u16) -> bool {
    (instr & patterns::BRA_MASK) == patterns::BRA_VAL
}

/// Check if instruction is BSR (branch to subroutine).
pub fn is_bsr(instr: u16) -> bool {
    (instr & patterns::BSR_MASK) == patterns::BSR_VAL
}

/// Check if instruction is JSR.
pub fn is_jsr(instr: u16) -> bool {
    (instr & patterns::JSR_MASK) == patterns::JSR_VAL
}

/// Check if instruction is JMP.
pub fn is_jmp(instr: u16) -> bool {
    (instr & patterns::JMP_MASK) == patterns::JMP_VAL
}

/// Check if instruction is a call (BSR or JSR).
pub fn is_call(instr: u16) -> bool {
    is_bsr(instr) || is_jsr(instr)
}

/// Check if instruction is TRAPA (trap always).
pub fn is_trapa(instr: u16) -> bool {
    (instr & patterns::TRAPA_MASK) == patterns::TRAPA_VAL
}

/// Get TRAPA vector number.
pub fn get_trapa_vector(instr: u16) -> u8 {
    (instr & 0xFF) as u8
}

/// Check if instruction is a conditional branch (BT/BF).
pub fn is_conditional_branch(instr: u16) -> bool {
    let fmt = get_format(instr);
    if fmt != format::FMT_8 {
        return false;
    }
    let subop = (instr >> 8) & 0x0F;
    matches!(
        subop as u8,
        fmt8_ops::BT | fmt8_ops::BF | fmt8_ops::BT_S | fmt8_ops::BF_S
    )
}

/// Check if instruction has a delay slot.
pub fn has_delay_slot(instr: u16) -> bool {
    // BRA, BSR, JMP, JSR, RTS, RTE all have delay slots
    // BT/S, BF/S also have delay slots
    is_bra(instr)
        || is_bsr(instr)
        || is_jmp(instr)
        || is_jsr(instr)
        || instr == patterns::RTS
        || instr == patterns::RTE
        || {
            let fmt = get_format(instr);
            if fmt == format::FMT_8 {
                let subop = (instr >> 8) & 0x0F;
                subop as u8 == fmt8_ops::BT_S || subop as u8 == fmt8_ops::BF_S
            } else {
                false
            }
        }
}

/// Check if instruction is a MOV.
pub fn is_mov(instr: u16) -> bool {
    let fmt = get_format(instr);
    matches!(
        fmt,
        format::FMT_1
            | format::FMT_2
            | format::FMT_5
            | format::FMT_6
            | format::FMT_9
            | format::FMT_D
            | format::FMT_E
    )
}

/// Check if instruction is MOV #imm, Rn.
pub fn is_mov_imm(instr: u16) -> bool {
    (instr & patterns::MOV_IMM_MASK) == patterns::MOV_IMM_VAL
}

/// Check if instruction is ADD #imm, Rn.
pub fn is_add_imm(instr: u16) -> bool {
    (instr & patterns::ADD_IMM_MASK) == patterns::ADD_IMM_VAL
}

/// Strong indicator patterns for heuristic detection.
pub const STRONG_INDICATORS: &[u16] = &[
    patterns::NOP,
    patterns::RTS,
    patterns::RTE,
    patterns::CLRT,
    patterns::SETT,
    patterns::CLRMAC,
    patterns::DIV0U,
    patterns::SLEEP,
];

/// Check if a 16-bit value looks like a valid SH instruction.
pub fn is_likely_valid(instr: u16) -> bool {
    let fmt = get_format(instr);

    match fmt {
        format::FMT_0 => {
            // Many format 0 instructions have specific patterns
            let low = instr & 0x00FF;
            matches!(
                low,
                0x02 | 0x03
                    | 0x04
                    | 0x05
                    | 0x06
                    | 0x07
                    | 0x08
                    | 0x09
                    | 0x0A
                    | 0x0B
                    | 0x0C
                    | 0x0D
                    | 0x0E
                    | 0x0F
                    | 0x18
                    | 0x19
                    | 0x1B
                    | 0x28
                    | 0x29
                    | 0x2B
            )
        }
        format::FMT_1
        | format::FMT_2
        | format::FMT_3
        | format::FMT_5
        | format::FMT_6
        | format::FMT_7
        | format::FMT_9
        | format::FMT_A
        | format::FMT_B
        | format::FMT_D
        | format::FMT_E => true,
        format::FMT_4 => {
            // Many format 4 opcodes
            let subop = get_subop_ext(instr);
            matches!(
                subop,
                0x00 | 0x01
                    | 0x02
                    | 0x03
                    | 0x04
                    | 0x05
                    | 0x06
                    | 0x07
                    | 0x08
                    | 0x09
                    | 0x0A
                    | 0x0B
                    | 0x0E
                    | 0x0F
                    | 0x10
                    | 0x11
                    | 0x15
                    | 0x18
                    | 0x19
                    | 0x1A
                    | 0x1B
                    | 0x1E
                    | 0x24
                    | 0x25
                    | 0x26
                    | 0x27
                    | 0x28
                    | 0x29
                    | 0x2A
                    | 0x2B
                    | 0x2E
            )
        }
        format::FMT_8 => {
            let subop = (instr >> 8) & 0x0F;
            matches!(subop, 0x0 | 0x1 | 0x4 | 0x5 | 0x8 | 0x9 | 0xB | 0xD | 0xF)
        }
        format::FMT_C => {
            let subop = (instr >> 8) & 0x0F;
            matches!(subop, 0x0..=0xF)
        }
        format::FMT_F => {
            // FPU instructions - many are valid
            true
        }
        _ => false,
    }
}

/// Score a single 16-bit halfword as a SuperH instruction.
///
/// Returns (delta_score, is_ret, is_call, is_distinctive).
#[inline]
fn score_word(word: u16) -> (i64, bool, bool, bool) {
    // Padding / erased flash — neutral score
    // In firmware binaries, 0x0000 and 0xFFFF are extremely common (erased NOR flash
    // is all 0xFF). Penalizing these massively skews results for firmware where 30-50%
    // of the image is blank. Treat as neutral.
    // Note: 0xC3C3 is also a common EEPROM fill pattern (e.g., in Bosch ECU firmware)
    // but it maps to TRAPA in SH (0xC3xx). Repeated halfword detection in score()
    // handles this case via run-length tracking.
    if word == 0x0000 || word == 0xFFFF {
        return (0, false, false, false);
    }

    // === High-confidence exact patterns ===
    // NOP (0x0009) - exact single value
    if is_nop(word) {
        return (25, false, false, true);
    }

    // RTS (return) - exact single value
    if is_rts(word) {
        return (30, true, false, true);
    }

    // RTE (return from exception)
    if word == patterns::RTE {
        return (25, true, false, true);
    }

    // CLRT, SETT, CLRMAC, DIV0U, SLEEP - exact values
    if matches!(
        word,
        patterns::CLRT | patterns::SETT | patterns::CLRMAC | patterns::DIV0U | patterns::SLEEP
    ) {
        return (15, false, false, true);
    }

    // TRAPA (0xC3xx) - 256 values out of 65536 = 0.39%
    // Score positively but do NOT mark as distinctive. TRAPA is a valid SH
    // instruction, but 0xC3xx patterns are also common fill/padding bytes
    // in non-SH firmware (e.g., Bosch ECU EEPROMs use 0xC3 fill).
    // The run-length detector handles bulk fill, but scattered 0xC3xx values
    // should not alone satisfy the structural requirement for "this is SH code".
    if is_trapa(word) {
        return (8, false, false, false);
    }

    // JSR @Rm (0x4m0B) - 16 values = 0.024%
    if is_jsr(word) {
        return (10, false, true, true);
    }

    // JMP @Rm (0x4m2B) - 16 values = 0.024%
    if is_jmp(word) {
        return (8, false, false, true);
    }

    // BSR (0xBxxx) - 6.25% of space → reduced score
    if is_bsr(word) {
        return (3, false, true, false);
    }

    // BRA (0xAxxx) - 6.25% of space → reduced score
    if is_bra(word) {
        return (3, false, false, false);
    }

    // Format 8 conditional branches (BT, BF, BT/S, BF/S) - check specific sub-opcodes
    if is_conditional_branch(word) {
        return (3, false, false, false);
    }

    // MOV.L @(disp,PC), Rn (0xDxxx) - 6.25% → reduced score
    if get_format(word) == format::FMT_D {
        return (2, false, false, false);
    }

    // MOV.W @(disp,PC), Rn (0x9xxx) - 6.25%
    if get_format(word) == format::FMT_9 {
        return (2, false, false, false);
    }

    // MOV Rm, Rn (0x6xx3) - specific sub-encoding
    if (word & 0xF00F) == 0x6003 {
        return (2, false, false, false);
    }

    // MOV #imm, Rn (0xExxx) - 6.25%
    if is_mov_imm(word) {
        return (1, false, false, false);
    }

    // ADD #imm, Rn (0x7xxx) - 6.25%
    if is_add_imm(word) {
        return (1, false, false, false);
    }

    // Format 4 shift/system ops - validate sub-opcode
    if get_format(word) == format::FMT_4 {
        let subop = get_subop_ext(word);
        if matches!(
            subop,
            0x00 | 0x01
                | 0x04
                | 0x05
                | 0x08
                | 0x09
                | 0x0B
                | 0x10
                | 0x11
                | 0x15
                | 0x18
                | 0x19
                | 0x1A
                | 0x1B
                | 0x24
                | 0x25
                | 0x28
                | 0x29
                | 0x2A
                | 0x2B
        ) {
            return (2, false, false, false);
        } else {
            return (-1, false, false, false);
        }
    }

    // Other recognized formats get minimal score
    let fmt = get_format(word);
    if matches!(fmt, 0x1 | 0x2 | 0x3 | 0x5 | 0x6) {
        (1, false, false, false)
    } else if fmt == 0xF {
        // FPU - only mildly score
        (1, false, false, false)
    } else if fmt == 0xC {
        // Format C misc - broad
        (1, false, false, false)
    } else {
        (-1, false, false, false)
    }
}

/// Apply cross-architecture penalties for LE-specific patterns.
///
/// These penalties are only applied to the LE score because they detect
/// instruction patterns from other LE 16-bit ISAs (AVR, Thumb, MSP430)
/// that would be read correctly when interpreting data as little-endian.
#[inline]
fn cross_arch_penalty_le(word: u16) -> i64 {
    // AVR exact patterns (also 16-bit LE)
    if word == 0x9508 {
        return -15;
    } // AVR RET
    if word == 0x9518 {
        return -12;
    } // AVR RETI
    if word == 0x9588 {
        return -10;
    } // AVR SLEEP
    if word == 0x9598 {
        return -8;
    } // AVR BREAK
    if word == 0x9478 {
        return -8;
    } // AVR SEI
    if word == 0x94F8 {
        return -8;
    } // AVR CLI
    if word == 0x95A8 {
        return -8;
    } // AVR WDR
    if word == 0x9409 {
        return -8;
    } // AVR IJMP
    if word == 0x9509 {
        return -8;
    } // AVR ICALL
      // AVR PUSH (mask 0xFE0F = 0x920F)
    if (word & 0xFE0F) == 0x920F {
        return -5;
    }
    // AVR POP (mask 0xFE0F = 0x900F)
    if (word & 0xFE0F) == 0x900F {
        return -5;
    }
    // Thumb patterns
    if word == 0x4770 {
        return -15;
    } // Thumb BX LR
    if word == 0xBF00 {
        return -10;
    } // Thumb NOP
      // Thumb PUSH {reglist, LR}
    if (word & 0xFF00) == 0xB500 {
        return -8;
    }
    // Thumb POP {reglist, PC}
    if (word & 0xFF00) == 0xBD00 {
        return -8;
    }
    // MSP430 patterns
    if word == 0x4130 {
        return -12;
    } // MSP430 RET
    if word == 0x4303 {
        return -10;
    } // MSP430 NOP
    if word == 0x1300 {
        return -10;
    } // MSP430 RETI
    0
}

/// Apply cross-architecture penalties for BE-specific patterns.
///
/// Penalizes patterns that look like big-endian instructions from other
/// architectures (m68k) when read as 16-bit big-endian halfwords, and also
/// patterns that arise from reading byte-oriented ISA code (x86) as 16-bit BE.
#[inline]
fn cross_arch_penalty_be(word: u16) -> i64 {
    // m68k exact patterns (also 16-bit BE)
    if word == 0x4E71 {
        return -15;
    } // m68k NOP
    if word == 0x4E75 {
        return -15;
    } // m68k RTS
    if word == 0x4E73 {
        return -12;
    } // m68k RTE
    if word == 0x4E77 {
        return -10;
    } // m68k RTR
    if word == 0x4AFC {
        return -10;
    } // m68k ILLEGAL
      // m68k MOVEQ (0x7xxx) — overlaps with SH ADD #imm but m68k uses bits 8-11 for Dn
      // Only penalize the exact MOVEQ #0 patterns which are very common in m68k
    if (word & 0xF1FF) == 0x7000 {
        return -5;
    } // MOVEQ #0, Dn
      // m68k JSR (0x4Exx with specific addressing modes)
    if (word & 0xFFC0) == 0x4E80 {
        return -8;
    } // m68k JSR
      // m68k BSR (0x6100)
    if (word & 0xFF00) == 0x6100 {
        return -5;
    } // m68k BSR.B

    // x86-64 byte pairs that commonly appear as BE halfwords:
    // REX.W (0x48) followed by common opcodes produces distinctive BE halfwords
    // These are NOT valid or meaningful SH instructions but look like SH format 4
    let hi = (word >> 8) as u8;
    let lo = (word & 0xFF) as u8;
    if hi == 0x48 {
        // REX.W prefix byte pairs: 0x4889, 0x4883, 0x488B, 0x488D, etc.
        match lo {
            0x89 | 0x8B | 0x83 | 0x8D | 0x01 | 0x03 | 0x29 | 0x2B | 0x31 | 0x33 | 0x39 | 0x3B
            | 0x85 | 0xC7 | 0xFF | 0x63 => return -8,
            _ => {}
        }
    }
    // x86 PUSH RBP (0x55) paired with REX (0x48) = 0x5548
    if word == 0x5548 {
        return -8;
    }
    // x86 POP RBP + RET (0x5DC3)
    if word == 0x5DC3 {
        return -8;
    }
    // x86 NOP pair (0x9090)
    if word == 0x9090 {
        return -8;
    }
    // x86 INT3 pair (0xCCCC) - common in padding
    if word == 0xCCCC {
        return -8;
    }

    0
}

/// Check if a 32-bit address is a valid SH vector table entry.
///
/// Valid SH vector addresses include:
/// - SH7052 ROM: 0x00000000-0x0007FFFF (512KB)
/// - SH7058 ROM: 0x00000000-0x000FFFFF (1MB)
/// - SH7058 ROM alias: 0xFF000000-0xFF0FFFFF
/// - RAM (SP init): 0xFFFF0000-0xFFFFBFFF
/// - Zero (unused vector) and 0xFFFFFFFF (erased flash) are treated as neutral.
///
/// If `require_aligned` is true, the address must be even (2-byte aligned).
/// Some vectors (e.g., data pointers, stack pointer init) may have odd addresses
/// but are still valid entries in the vector table.
#[inline]
fn is_valid_sh_vector_ex(addr: u32, require_aligned: bool) -> bool {
    if addr == 0x00000000 || addr == 0xFFFFFFFF {
        return false; // Neutral, not "valid" but not invalid either
    }
    let is_rom_addr = addr >= 0x00000040 && addr < 0x01000000;
    let is_rom_alias = addr >= 0xFF000000 && addr < 0xFF100000;
    // RAM address ranges vary by SH variant:
    // SH7052: 0xFFFF8000-0xFFFFBFFF (16KB)
    // SH7058: 0xFFFF0000-0xFFFFBFFF (48KB)
    // SH7055F/SH7059: 0xFFF80000-0xFFFFBFFF (up to 512KB)
    // Use the widest range to cover all variants.
    let is_ram_addr = addr >= 0xFFF80000 && addr < 0xFFFFFF00;
    let in_range = is_rom_addr || is_rom_alias || is_ram_addr;
    if require_aligned {
        in_range && (addr & 1) == 0
    } else {
        in_range
    }
}

/// Check if a 32-bit address is a valid, aligned SH vector table entry.
#[inline]
fn is_valid_sh_vector(addr: u32) -> bool {
    is_valid_sh_vector_ex(addr, true)
}

/// Detect SH7058-style sparse vector table (16 bytes per entry).
///
/// The SH7058 Mitsubishi ECU format uses a 16-byte stride:
/// `[4-byte BE address][12 bytes 0xFF padding]` for the first few priority
/// vectors (reset PC, manual reset, etc.), followed by packed 4-byte vectors
/// starting at offset 0x40.
///
/// Returns bonus score if this specific format is detected.
fn detect_sh7058_sparse_vectors(data: &[u8]) -> i64 {
    if data.len() < 0x80 {
        return 0;
    }

    let mut bonus: i64 = 0;

    // Check for 16-byte stride pattern: first 4 entries at 0x00, 0x10, 0x20, 0x30
    let mut sparse_valid = 0u32;
    let mut sparse_has_ff_padding = 0u32;

    for entry_idx in 0..4 {
        let off = entry_idx * 16;
        if off + 16 > data.len() {
            break;
        }
        let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

        // Check if the 12-byte padding after the address is all 0xFF
        let padding_all_ff = data[off + 4..off + 16].iter().all(|&b| b == 0xFF);

        // For sparse vector detection, allow odd addresses (some entries may be
        // data pointers or have special alignment). The key structural signal is
        // the 16-byte stride + 0xFF padding, not the address alignment.
        if is_valid_sh_vector_ex(addr, false) {
            sparse_valid += 1;
        }
        if padding_all_ff {
            sparse_has_ff_padding += 1;
        }
    }

    // SH7058 sparse format: valid addresses + 0xFF padding
    if sparse_valid >= 2 && sparse_has_ff_padding >= 3 {
        // Very strong match for SH7058 16-byte-stride format.
        // The 16-byte stride with 0xFF padding is an extremely distinctive
        // structural pattern: 4 consecutive aligned 32-bit values in the
        // 0xFF00xxxx range, each followed by 12 bytes of 0xFF. The probability
        // of this arising by chance from non-SH data is essentially zero.
        // Scale bonus with match quality: more valid entries = higher confidence.
        bonus += 1000 + sparse_valid as i64 * 250;

        // Check for packed vectors at offset 0x40 (ROM alias addresses)
        let mut packed_valid = 0u32;
        let packed_start = 0x40;
        let packed_count = ((data.len().min(0x100) - packed_start) / 4).min(16);

        for v in 0..packed_count {
            let off = packed_start + v * 4;
            if off + 4 > data.len() {
                break;
            }
            let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if is_valid_sh_vector(addr) {
                packed_valid += 1;
            }
        }

        if packed_valid >= 4 {
            bonus += 200 + packed_valid.min(16) as i64 * 20;
        }

        // Check for secondary vector table with 0x000080xx addresses (offset ~0x94+)
        let mut secondary_valid = 0u32;
        let sec_start = 0x90;
        if data.len() > sec_start + 32 {
            let sec_count = ((data.len().min(0x140) - sec_start) / 4).min(20);
            for v in 0..sec_count {
                let off = sec_start + v * 4;
                if off + 4 > data.len() {
                    break;
                }
                let addr =
                    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                // SH7058 secondary vectors often point to low ROM: 0x00008000-0x0000FFFF
                if addr >= 0x00008000 && addr < 0x00010000 && (addr & 1) == 0 {
                    secondary_valid += 1;
                }
            }
            if secondary_valid >= 4 {
                bonus += 200 + secondary_valid.min(16) as i64 * 15;
            }
        }

        // ── Byte-level scorer compensation ──
        //
        // Problem: byte-level scorers (ARM, HCS12, RISC-V, etc.) accumulate
        // positive scores on nearly any data at ~0.3-0.7 per byte, because
        // most byte values map to valid opcodes in those ISAs. SH scores at
        // the halfword level (16-bit) and is more selective — it scores
        // neutral on 0xFFFF and 0x0000 halfwords, and gives moderate scores
        // for valid SH instructions. On a 768KB firmware file, this means:
        //   - ARM accumulates ~400K-500K just from byte statistics
        //   - SH accumulates ~250K-300K from halfword instruction scoring
        //
        // When we have strong structural evidence (SH7058 sparse vector
        // table), the file is definitively SH firmware. We compensate for
        // the scoring asymmetry with a file-size-proportional bonus.
        //
        // The compensation has two components:
        // 1. Erased flash (0xFF bytes): SH scores 0 on 0xFFFF halfwords,
        //    but byte-level scorers score positively. Rate: 0.5/erased byte.
        // 2. Code region: SH's halfword scoring averages lower per byte than
        //    byte-level scorers. Rate: 0.30/code byte.
        //
        // Both components are gated on the structural vector table match,
        // so there is no risk of inflating scores for non-SH data.
        let erased_bytes = data.iter().filter(|&&b| b == 0xFF).count();
        let code_bytes = data.len() - erased_bytes;
        let erased_compensation = (erased_bytes as f64 * 0.5) as i64;
        let code_compensation = (code_bytes as f64 * 0.30) as i64;
        bonus += erased_compensation + code_compensation;
    }

    bonus
}

/// Detect SH vector table at the start of firmware (big-endian).
///
/// SH-1/SH-2 firmware typically starts with a vector table: 32-bit BE addresses
/// for Power-on Reset PC, Power-on Reset SP, Manual Reset PC, Manual Reset SP,
/// etc. Valid vectors point into the ROM address space (typically 0x00000000–0x001FFFFF
/// for internal flash, or 0x00000000–0x0FFFFFFF for external).
///
/// Also detects the SH7058 sparse vector table format (16-byte stride with
/// 0xFF padding between entries).
///
/// Returns a bonus score if a plausible BE vector table is detected.
fn detect_be_vector_table(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    // First try the SH7058 sparse format (16-byte stride)
    let sparse_bonus = detect_sh7058_sparse_vectors(data);

    // Then try the standard packed format (SH7052-style: 4-byte stride)
    let mut valid_vectors = 0i64;
    let mut total_vectors = 0i64;
    let num_vectors = (data.len().min(64) / 4).min(16);

    for v in 0..num_vectors {
        let off = v * 4;
        let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        total_vectors += 1;

        if addr == 0x00000000 || addr == 0xFFFFFFFF {
            continue;
        }

        if is_valid_sh_vector(addr) {
            valid_vectors += 1;
        }
    }

    if total_vectors < 4 {
        return sparse_bonus;
    }

    let reset_pc = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let reset_sp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let reset_pc_valid = is_valid_sh_vector(reset_pc) || reset_pc == 0;
    let reset_sp_valid = is_valid_sh_vector(reset_sp) || reset_sp == 0;

    let mut packed_bonus: i64 = 0;

    // Strong bonus if reset PC looks correct (SP may be unset in some firmware)
    if reset_pc_valid && reset_pc != 0 {
        packed_bonus += 150;
        if reset_sp_valid {
            packed_bonus += 100;
        }
    }

    // Additional bonus based on fraction of valid (non-trivial) vectors
    let mut packed_is_strong = false;
    if total_vectors > 0 {
        let nontrivial: i64 = (0..num_vectors)
            .map(|v| {
                let off = v * 4;
                u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            })
            .filter(|&a| a != 0x00000000 && a != 0xFFFFFFFF)
            .count() as i64;

        if nontrivial >= 3 {
            packed_bonus += 100 + nontrivial.min(12) * 10;
        }

        let valid_fraction = valid_vectors as f64 / total_vectors as f64;
        if valid_fraction >= 0.3 {
            packed_bonus += (valid_fraction * 100.0) as i64;
        }

        // A "strong" packed detection requires: reset PC valid + at least 5
        // non-trivial valid vectors with >50% valid fraction
        if reset_pc_valid && reset_pc != 0 && nontrivial >= 5 && valid_fraction >= 0.5 {
            packed_is_strong = true;
        }
    }

    // Byte-level scorer compensation for packed vector table format.
    // Same logic as in sparse detection: when we have strong vector table
    // evidence, compensate for the scoring asymmetry vs byte-level scorers.
    if packed_is_strong {
        let erased_bytes = data.iter().filter(|&&b| b == 0xFF).count();
        let code_bytes = data.len() - erased_bytes;
        let erased_compensation = (erased_bytes as f64 * 0.5) as i64;
        let code_compensation = (code_bytes as f64 * 0.30) as i64;
        packed_bonus += erased_compensation + code_compensation;
    }

    // Return the better of the two detection methods
    sparse_bonus.max(packed_bonus)
}

/// Detect SH vector table at the start of firmware (little-endian).
///
/// Same concept as BE but reads 32-bit addresses as LE.
fn detect_le_vector_table(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    let mut valid_vectors = 0i64;
    let mut total_vectors = 0i64;
    let num_vectors = (data.len().min(64) / 4).min(16);

    for v in 0..num_vectors {
        let off = v * 4;
        let addr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        total_vectors += 1;

        if addr == 0x00000000 || addr == 0xFFFFFFFF {
            continue;
        }

        // SH-3/SH-4 memory map: typically mapped at higher addresses
        // SH7750 (Dreamcast): ROM area at 0x00000000-0x001FFFFF,
        //   P0 area 0x00000000-0x7FFFFFFF, P1 0x80000000-0x9FFFFFFF
        let is_reasonable = addr >= 0x00000040 && addr < 0xA0000000;
        let is_aligned = (addr & 1) == 0;

        if is_reasonable && is_aligned {
            valid_vectors += 1;
        }
    }

    if total_vectors < 4 {
        return 0;
    }

    let reset_pc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let reset_sp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let reset_pc_valid = reset_pc >= 0x00000040 && reset_pc < 0xA0000000 && (reset_pc & 1) == 0;
    let reset_sp_valid = (reset_sp >= 0x00000040 && reset_sp < 0xA0000000 && (reset_sp & 1) == 0)
        || (reset_sp >= 0xFFFF0000 && reset_sp < 0xFFFFFF00);

    let mut bonus: i64 = 0;

    if reset_pc_valid && reset_sp_valid {
        bonus += 200;
    }

    let valid_fraction = valid_vectors as f64 / total_vectors as f64;
    if valid_fraction >= 0.5 {
        bonus += (valid_fraction * 150.0) as i64;
    }

    bonus
}

/// Score likelihood of SuperH code in both byte orders.
///
/// Returns `(big_endian_score, little_endian_score)`.
/// Analyzes raw bytes for patterns characteristic of SuperH, testing
/// both BE and LE interpretations in a single pass.
pub fn score(data: &[u8]) -> (i64, i64) {
    let mut score_be: i64 = 0;
    let mut score_le: i64 = 0;
    let mut ret_count_be = 0u32;
    let mut call_count_be = 0u32;
    let mut distinctive_be = 0u32;
    let mut ret_count_le = 0u32;
    let mut call_count_le = 0u32;
    let mut distinctive_le = 0u32;

    // Track previous halfword for compound pattern detection (delay slot idioms).
    // SH has a mandatory delay slot after RTS/JSR/JMP/BRA/BSR — the canonical
    // pattern is "RTS; NOP" (0x000B 0x0009 in BE). Detecting these compound
    // patterns is extremely high-confidence since two specific consecutive
    // halfwords is a 1-in-4-billion coincidence in random data.
    let mut prev_word_be: u16 = 0;
    let mut prev_word_le: u16 = 0;
    let mut compound_be = 0u32; // RTS;NOP, JSR;NOP, JMP;NOP, RTE;NOP pairs
    let mut compound_le = 0u32;

    // Run-length tracking for repeated halfwords.
    // Firmware/EEPROM images often contain large regions filled with a single
    // value (e.g., 0xC3C3 in Bosch ECUs, 0xA5A5 security patterns, etc.).
    // SH's broad opcode coverage means almost any halfword maps to a "valid"
    // instruction, so these fill regions inflate the score massively.
    // We track consecutive identical halfwords and suppress scoring after
    // a short threshold (3 repeats). Beyond that, the repeated value is
    // clearly fill/padding, not real instructions.
    const FILL_RUN_THRESHOLD: u32 = 3; // allow first 3, suppress rest
    let mut run_word_be: u16 = 0xDEAD; // sentinel — won't match first word
    let mut run_word_le: u16 = 0xDEAD;
    let mut run_len_be: u32 = 0;
    let mut run_len_le: u32 = 0;

    // Check for vector tables at the start of the data
    score_be += detect_be_vector_table(data);
    score_le += detect_le_vector_table(data);

    // SuperH is 16-bit aligned — scan all halfwords in both byte orders
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word_le = u16::from_le_bytes([data[i], data[i + 1]]);
        let word_be = u16::from_be_bytes([data[i], data[i + 1]]);

        // Detect compound delay-slot patterns (prev_word; current_word)
        // These are extremely distinctive SH idioms.
        {
            // BE compound patterns
            if word_be == patterns::NOP {
                match prev_word_be {
                    w if w == patterns::RTS => {
                        score_be += 40;
                        compound_be += 1;
                    }
                    w if w == patterns::RTE => {
                        score_be += 35;
                        compound_be += 1;
                    }
                    w if is_jsr(w) => {
                        score_be += 30;
                        compound_be += 1;
                    }
                    w if is_jmp(w) => {
                        score_be += 25;
                        compound_be += 1;
                    }
                    w if is_bra(w) => {
                        score_be += 15;
                        compound_be += 1;
                    }
                    w if is_bsr(w) => {
                        score_be += 15;
                        compound_be += 1;
                    }
                    _ => {}
                }
            }
            // LE compound patterns
            if word_le == patterns::NOP {
                match prev_word_le {
                    w if w == patterns::RTS => {
                        score_le += 40;
                        compound_le += 1;
                    }
                    w if w == patterns::RTE => {
                        score_le += 35;
                        compound_le += 1;
                    }
                    w if is_jsr(w) => {
                        score_le += 30;
                        compound_le += 1;
                    }
                    w if is_jmp(w) => {
                        score_le += 25;
                        compound_le += 1;
                    }
                    w if is_bra(w) => {
                        score_le += 15;
                        compound_le += 1;
                    }
                    w if is_bsr(w) => {
                        score_le += 15;
                        compound_le += 1;
                    }
                    _ => {}
                }
            }
        }

        // Update run-length tracking for repeated halfword detection
        if word_le == run_word_le {
            run_len_le += 1;
        } else {
            run_word_le = word_le;
            run_len_le = 1;
        }
        if word_be == run_word_be {
            run_len_be += 1;
        } else {
            run_word_be = word_be;
            run_len_be = 1;
        }

        // Score the LE interpretation
        // Suppress scoring for repeated-fill halfwords beyond the threshold.
        // This prevents EEPROM/flash fill patterns (e.g., 0xC3C3, 0xA5A5)
        // from inflating the score via broad opcode matches like TRAPA (0xC3xx).
        if run_len_le > FILL_RUN_THRESHOLD {
            // Long run of identical halfwords — this is fill/padding, not code.
            // Apply a small penalty to actively push down the score.
            score_le -= 1;
        } else {
            let penalty = cross_arch_penalty_le(word_le);
            if penalty != 0 {
                score_le += penalty;
            } else {
                let (delta, is_ret, is_call, is_dist) = score_word(word_le);
                score_le += delta;
                if is_ret {
                    ret_count_le += 1;
                }
                if is_call {
                    call_count_le += 1;
                }
                if is_dist {
                    distinctive_le += 1;
                }
            }
        }

        // Score the BE interpretation (same run-length logic)
        if run_len_be > FILL_RUN_THRESHOLD {
            score_be -= 1;
        } else {
            let penalty = cross_arch_penalty_be(word_be);
            if penalty != 0 {
                score_be += penalty;
            } else {
                let (delta, is_ret, is_call, is_dist) = score_word(word_be);
                score_be += delta;
                if is_ret {
                    ret_count_be += 1;
                }
                if is_call {
                    call_count_be += 1;
                }
                if is_dist {
                    distinctive_be += 1;
                }
            }
        }

        prev_word_be = word_be;
        prev_word_le = word_le;
    }

    // Structural requirement: real SH code needs distinctive patterns
    // (NOP, RTS, RTE, CLRT, SETT, TRAPA, JSR, JMP). Without these, the data
    // is likely from another ISA that happens to map to SH format groups
    // (SH uses nearly the entire 16-bit opcode space, so most random/other-ISA
    // data scores positively).
    if ret_count_be == 0 && call_count_be == 0 && distinctive_be == 0 && compound_be == 0 {
        score_be = (score_be as f64 * 0.10) as i64;
    }
    if ret_count_le == 0 && call_count_le == 0 && distinctive_le == 0 && compound_le == 0 {
        score_le = (score_le as f64 * 0.10) as i64;
    }

    (score_be.max(0), score_le.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_detection() {
        assert!(is_nop(patterns::NOP));
        assert!(!is_nop(patterns::RTS));
    }

    #[test]
    fn test_return_detection() {
        assert!(is_rts(patterns::RTS));
        assert!(is_return(patterns::RTS));
        assert!(is_return(patterns::RTE));
    }

    #[test]
    fn test_format_extraction() {
        assert_eq!(get_format(patterns::NOP), format::FMT_0);
        assert_eq!(get_format(0xA000), format::FMT_A); // BRA
        assert_eq!(get_format(0xB000), format::FMT_B); // BSR
        assert_eq!(get_format(0xE000), format::FMT_E); // MOV #imm
    }

    #[test]
    fn test_branch_detection() {
        assert!(is_bra(0xA000)); // BRA
        assert!(is_bsr(0xB000)); // BSR
        assert!(is_branch(0xA000));
        assert!(is_branch(0xB000));
        assert!(is_branch(0x8900)); // BT
    }

    #[test]
    fn test_jsr_jmp_detection() {
        // JSR @R0 = 0x400B
        assert!(is_jsr(0x400B));
        // JSR @R15 = 0x4F0B
        assert!(is_jsr(0x4F0B));
        // JMP @R0 = 0x402B
        assert!(is_jmp(0x402B));
    }

    #[test]
    fn test_trapa() {
        assert!(is_trapa(0xC300)); // TRAPA #0
        assert!(is_trapa(0xC3FF)); // TRAPA #255
        assert_eq!(get_trapa_vector(0xC310), 0x10);
    }

    #[test]
    fn test_delay_slot() {
        assert!(has_delay_slot(0xA000)); // BRA
        assert!(has_delay_slot(0xB000)); // BSR
        assert!(has_delay_slot(patterns::RTS));
        assert!(!has_delay_slot(patterns::NOP));
    }

    #[test]
    fn test_displacement() {
        // BRA with positive displacement
        assert_eq!(get_disp12(0xA100), 0x100);
        // BRA with negative displacement
        assert_eq!(get_disp12(0xAFFF), -1);
    }

    #[test]
    fn test_register_extraction() {
        // MOV R5, R10 style instruction
        let instr: u16 = 0x6A53; // Example
        assert_eq!(get_rn(instr), 0xA);
        assert_eq!(get_rm(instr), 0x5);
    }

    #[test]
    fn test_score_le() {
        // SuperH NOP (little-endian: 0x09, 0x00)
        let nop = patterns::NOP.to_le_bytes();
        let (be, le) = score(&nop);
        assert!(
            le > 0,
            "LE score should be positive for LE-encoded SH NOP, got {le}"
        );
    }

    #[test]
    fn test_score_be() {
        // SuperH NOP (big-endian: 0x00, 0x09)
        let nop = patterns::NOP.to_be_bytes();
        let (be, le) = score(&nop);
        assert!(
            be > 0,
            "BE score should be positive for BE-encoded SH NOP, got {be}"
        );
    }

    #[test]
    fn test_score_be_code_sequence() {
        // A realistic SH2 big-endian code sequence (as it would appear in firmware):
        // mov.l @(disp,PC), r1  = 0xD102  (format D)
        // shll  r1              = 0x4100  (format 4, subop 0x00)
        // add   r1, r0          = 0x300C  (format 3)
        // stc.l sr, @-r15       = 0x4F03  (format 4)
        // nop                   = 0x0009
        // rts                   = 0x000B
        // nop                   = 0x0009  (delay slot)
        let be_code: Vec<u8> = vec![
            0xD1, 0x02, // mov.l @(8,PC), r1
            0x41, 0x00, // shll r1
            0x30, 0x0C, // add r1, r0
            0x4F, 0x03, // stc.l sr, @-r15
            0x00, 0x09, // nop
            0x00, 0x0B, // rts
            0x00, 0x09, // nop (delay slot)
        ];
        let (be, le) = score(&be_code);
        assert!(
            be > le,
            "BE score ({be}) should exceed LE score ({le}) for BE-encoded SH code"
        );
        assert!(be > 0, "BE score should be positive for valid SH BE code");
    }

    #[test]
    fn test_score_le_code_sequence() {
        // Same SH instructions but little-endian encoded:
        let le_code: Vec<u8> = vec![
            0x02, 0xD1, // mov.l @(8,PC), r1
            0x00, 0x41, // shll r1
            0x0C, 0x30, // add r1, r0
            0x03, 0x4F, // stc.l sr, @-r15
            0x09, 0x00, // nop
            0x0B, 0x00, // rts
            0x09, 0x00, // nop (delay slot)
        ];
        let (be, le) = score(&le_code);
        assert!(
            le > be,
            "LE score ({le}) should exceed BE score ({be}) for LE-encoded SH code"
        );
        assert!(le > 0, "LE score should be positive for valid SH LE code");
    }

    #[test]
    fn test_be_vector_table_detection() {
        // Simulate a SH2 big-endian vector table (like Mitsubishi ECU):
        // Vector 0: Reset PC = 0x00009A8C
        // Vector 1: Reset SP = 0xFFFF9B00
        // Vector 2: Manual Reset PC = 0x00009AB4
        // Vector 3: Manual Reset SP = 0xFFFF9B00
        let mut data = vec![0u8; 64];
        // Reset PC
        data[0..4].copy_from_slice(&0x00009A8Cu32.to_be_bytes());
        // Reset SP (RAM area)
        data[4..8].copy_from_slice(&0xFFFF9B00u32.to_be_bytes());
        // Manual Reset PC
        data[8..12].copy_from_slice(&0x00009AB4u32.to_be_bytes());
        // Manual Reset SP
        data[12..16].copy_from_slice(&0xFFFF9B00u32.to_be_bytes());
        // Fill rest with some SH instructions (BE)
        for i in (16..64).step_by(2) {
            // NOP in BE
            data[i] = 0x00;
            data[i + 1] = 0x09;
        }

        let (be, le) = score(&data);
        assert!(
            be > le,
            "BE score ({be}) should far exceed LE score ({le}) for SH2 BE firmware with vector table"
        );
        assert!(
            be > 100,
            "BE score should have significant vector table bonus, got {be}"
        );
    }

    #[test]
    fn test_score_word_helper() {
        // Direct test of score_word for key patterns
        assert_eq!(score_word(patterns::NOP), (25, false, false, true));
        assert_eq!(score_word(patterns::RTS), (30, true, false, true));
        assert_eq!(score_word(patterns::RTE), (25, true, false, true));
        // JSR @R0 = 0x400B
        let (delta, _, is_call, is_dist) = score_word(0x400B);
        assert_eq!(delta, 10);
        assert!(is_call);
        assert!(is_dist);
        // Zero word — neutral (padding/erased flash)
        assert_eq!(score_word(0x0000), (0, false, false, false));
        // 0xFFFF — neutral (erased flash)
        assert_eq!(score_word(0xFFFF), (0, false, false, false));
        // TRAPA — positive but NOT distinctive (prevents fill-byte inflation)
        let (delta, is_ret, is_call, is_dist) = score_word(0xC300);
        assert!(delta > 0, "TRAPA should have positive score");
        assert!(!is_dist, "TRAPA should NOT be marked distinctive");
        assert!(!is_ret);
        assert!(!is_call);
    }

    #[test]
    fn test_fill_byte_run_suppression() {
        // Simulate an EEPROM with 0xC3C3 fill (like Bosch ECU firmware).
        // This should NOT produce a high SH score because the repeated
        // halfwords are detected as fill/padding.
        let mut data = vec![0xC3u8; 4096]; // 2048 halfwords of 0xC3C3

        // Sprinkle a few non-fill bytes to make it look like a real EEPROM
        // (header + small data blocks)
        data[0] = 0x55; // 'U' marker
        data[1] = 0x00;
        data[2] = 0x56; // 'V'
        data[3] = 0x33;

        let (be, le) = score(&data);
        // With 2048 repeated TRAPA halfwords, the score should be very low
        // because the run-length detector suppresses them.
        assert!(
            be < 200 && le < 200,
            "Score should be very low for fill-heavy data: BE={be}, LE={le}"
        );
    }

    #[test]
    fn test_genuine_sh_code_with_fill() {
        // Mix of real SH code (BE) and fill regions.
        // The code should still score well despite the fill.
        let mut data = vec![0xC3u8; 256]; // Start with fill

        // Insert genuine SH2 BE code starting at offset 128
        let code_start = 128;
        let sh_code: &[u8] = &[
            0xD1, 0x02, // mov.l @(8,PC), r1
            0x41, 0x00, // shll r1
            0x30, 0x0C, // add r1, r0
            0x4F, 0x03, // stc.l sr, @-r15
            0x00, 0x09, // nop
            0x00, 0x0B, // rts
            0x00, 0x09, // nop (delay slot)
            0xD2, 0x04, // mov.l @(16,PC), r2
            0x42, 0x00, // shll r2
            0x00, 0x09, // nop
            0x00, 0x0B, // rts
            0x00, 0x09, // nop (delay slot)
        ];
        data[code_start..code_start + sh_code.len()].copy_from_slice(sh_code);

        let (be, _le) = score(&data);
        assert!(
            be > 0,
            "BE score should be positive for genuine SH code mixed with fill: BE={be}"
        );
    }
}
