//! Hitachi/Renesas SuperH (SH) architecture analysis.
//!
//! SuperH uses fixed 16-bit instructions, typically little-endian
//! (though some variants are big-endian). All instructions are 2 bytes,
//! aligned on 2-byte boundaries.

/// Instruction format groups (bits 15:12).
pub mod format {
    pub const FMT_0: u8 = 0x0;   // Misc: MOV, shifts, etc.
    pub const FMT_1: u8 = 0x1;   // MOV.L @(disp,Rn), Rm
    pub const FMT_2: u8 = 0x2;   // MOV.x @Rm, Rn / MOV.x Rm, @Rn
    pub const FMT_3: u8 = 0x3;   // CMP, ADD, SUB
    pub const FMT_4: u8 = 0x4;   // Misc: shifts, system
    pub const FMT_5: u8 = 0x5;   // MOV.L @(disp,Rm), Rn
    pub const FMT_6: u8 = 0x6;   // MOV.x @Rm, Rn (extended)
    pub const FMT_7: u8 = 0x7;   // ADD #imm, Rn
    pub const FMT_8: u8 = 0x8;   // Branches (BT, BF, etc.)
    pub const FMT_9: u8 = 0x9;   // MOV.W @(disp,PC), Rn
    pub const FMT_A: u8 = 0xA;   // BRA
    pub const FMT_B: u8 = 0xB;   // BSR
    pub const FMT_C: u8 = 0xC;   // Misc immediate ops
    pub const FMT_D: u8 = 0xD;   // MOV.L @(disp,PC), Rn
    pub const FMT_E: u8 = 0xE;   // MOV #imm, Rn
    pub const FMT_F: u8 = 0xF;   // FPU instructions
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
    pub const SHLL: u8 = 0x00;   // 0100 nnnn 0000 0000
    pub const SHLR: u8 = 0x01;   // 0100 nnnn 0000 0001
    pub const ROTL: u8 = 0x04;   // 0100 nnnn 0000 0100
    pub const ROTR: u8 = 0x05;   // 0100 nnnn 0000 0101
    pub const ROTCL: u8 = 0x24;  // 0100 nnnn 0010 0100
    pub const ROTCR: u8 = 0x25;  // 0100 nnnn 0010 0101
    pub const SHLL2: u8 = 0x08;  // 0100 nnnn 0000 1000
    pub const SHLR2: u8 = 0x09;  // 0100 nnnn 0000 1001
    pub const SHLL8: u8 = 0x18;  // 0100 nnnn 0001 1000
    pub const SHLR8: u8 = 0x19;  // 0100 nnnn 0001 1001
    pub const SHLL16: u8 = 0x28; // 0100 nnnn 0010 1000
    pub const SHLR16: u8 = 0x29; // 0100 nnnn 0010 1001
    pub const DT: u8 = 0x10;     // 0100 nnnn 0001 0000 (decrement and test)
    pub const CMP_PL: u8 = 0x15; // 0100 nnnn 0001 0101
    pub const CMP_PZ: u8 = 0x11; // 0100 nnnn 0001 0001
    pub const JSR: u8 = 0x0B;    // 0100 mmmm 0000 1011
    pub const JMP: u8 = 0x2B;    // 0100 mmmm 0010 1011
    pub const TAS: u8 = 0x1B;    // 0100 nnnn 0001 1011
    pub const LDS_MACH: u8 = 0x0A;
    pub const LDS_MACL: u8 = 0x1A;
    pub const LDS_PR: u8 = 0x2A;
    pub const STS_MACH: u8 = 0x0A;
    pub const STS_MACL: u8 = 0x1A;
    pub const STS_PR: u8 = 0x2A;
}

/// Format 8 sub-opcodes (conditional branches).
pub mod fmt8_ops {
    pub const BT: u8 = 0x9;    // 1000 1001 dddd dddd
    pub const BF: u8 = 0xB;    // 1000 1011 dddd dddd
    pub const BT_S: u8 = 0xD;  // 1000 1101 dddd dddd (delay slot)
    pub const BF_S: u8 = 0xF;  // 1000 1111 dddd dddd (delay slot)
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
        format::FMT_8 => true,   // BT, BF, BT/S, BF/S
        format::FMT_A => true,   // BRA
        format::FMT_B => true,   // BSR
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
    matches!(subop as u8, fmt8_ops::BT | fmt8_ops::BF | fmt8_ops::BT_S | fmt8_ops::BF_S)
}

/// Check if instruction has a delay slot.
pub fn has_delay_slot(instr: u16) -> bool {
    // BRA, BSR, JMP, JSR, RTS, RTE all have delay slots
    // BT/S, BF/S also have delay slots
    is_bra(instr) || is_bsr(instr) || is_jmp(instr) || is_jsr(instr) ||
    instr == patterns::RTS || instr == patterns::RTE ||
    {
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
    matches!(fmt,
        format::FMT_1 | format::FMT_2 | format::FMT_5 | format::FMT_6 |
        format::FMT_9 | format::FMT_D | format::FMT_E
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
            matches!(low,
                0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 |
                0x0A | 0x0B | 0x0C | 0x0D | 0x0E | 0x0F | 0x18 | 0x19 |
                0x1B | 0x28 | 0x29 | 0x2B
            )
        }
        format::FMT_1 | format::FMT_2 | format::FMT_3 | format::FMT_5 |
        format::FMT_6 | format::FMT_7 | format::FMT_9 | format::FMT_A |
        format::FMT_B | format::FMT_D | format::FMT_E => true,
        format::FMT_4 => {
            // Many format 4 opcodes
            let subop = get_subop_ext(instr);
            matches!(subop,
                0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 |
                0x08 | 0x09 | 0x0A | 0x0B | 0x0E | 0x0F | 0x10 | 0x11 |
                0x15 | 0x18 | 0x19 | 0x1A | 0x1B | 0x1E | 0x24 | 0x25 |
                0x26 | 0x27 | 0x28 | 0x29 | 0x2A | 0x2B | 0x2E
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

/// Score likelihood of SuperH code.
///
/// Analyzes raw bytes for patterns characteristic of SuperH.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // SuperH is 16-bit aligned
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // NOP
        if is_nop(word) {
            score += 25;
        }

        // RTS (return)
        if is_rts(word) {
            score += 30;
        }

        // TRAPA
        if is_trapa(word) {
            score += 15;
        }

        // BRA
        if is_bra(word) {
            score += 8;
        }

        // BSR
        if is_bsr(word) {
            score += 8;
        }

        // MOV.L @(disp,PC), Rn (common pattern)
        if get_format(word) == format::FMT_D {
            score += 5;
        }

        // MOV Rm, Rn - check for MOV instruction
        if is_mov(word) && (word & 0xF00F) == 0x6003 {
            score += 3;
        }

        // Invalid
        if word == 0x0000 || word == 0xFFFF {
            score -= 5;
        }
    }

    score.max(0)
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
    fn test_score() {
        // SuperH NOP (little-endian)
        let nop = patterns::NOP.to_le_bytes();
        assert!(score(&nop) > 0);
    }
}
