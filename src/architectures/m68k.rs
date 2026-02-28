//! Motorola 68000 (m68k) architecture analysis.
//!
//! m68k uses variable-length instructions (2-10 bytes), big-endian,
//! 16-bit aligned. The first word determines the instruction type.

/// First word opcode groups (bits 15:12).
pub mod opcode_group {
    pub const BITOP_MOVEP_IMM: u8 = 0x0; // Bit operations, MOVEP, immediate
    pub const MOVE_BYTE: u8 = 0x1; // MOVE.B
    pub const MOVE_LONG: u8 = 0x2; // MOVE.L
    pub const MOVE_WORD: u8 = 0x3; // MOVE.W
    pub const MISC: u8 = 0x4; // Miscellaneous
    pub const ADDQ_SUBQ_SCC_DBCC: u8 = 0x5; // Quick add/sub, set/branch on condition
    pub const BCC_BSR_BRA: u8 = 0x6; // Branches
    pub const MOVEQ: u8 = 0x7; // MOVEQ
    pub const OR_DIV_SBCD: u8 = 0x8; // OR, DIV, SBCD
    pub const SUB_SUBX: u8 = 0x9; // SUB, SUBX
    pub const RESERVED_A: u8 = 0xA; // A-line (unassigned/emulator)
    pub const CMP_EOR: u8 = 0xB; // CMP, EOR
    pub const AND_MUL_ABCD_EXG: u8 = 0xC; // AND, MUL, ABCD, EXG
    pub const ADD_ADDX: u8 = 0xD; // ADD, ADDX
    pub const SHIFT_ROTATE: u8 = 0xE; // Shift and rotate
    pub const RESERVED_F: u8 = 0xF; // F-line (coprocessor/emulator)
}

/// Group 4 (miscellaneous) operations.
pub mod misc_ops {
    // These are identified by bits 11:6 of the first word
    pub const NEGX: u16 = 0x4000;
    pub const CLR: u16 = 0x4200;
    pub const NEG: u16 = 0x4400;
    pub const NOT: u16 = 0x4600;
    pub const EXT_WORD: u16 = 0x4880;
    pub const EXT_LONG: u16 = 0x48C0;
    pub const NBCD: u16 = 0x4800;
    pub const SWAP: u16 = 0x4840;
    pub const PEA: u16 = 0x4840;
    pub const ILLEGAL: u16 = 0x4AFC;
    pub const TAS: u16 = 0x4AC0;
    pub const TST: u16 = 0x4A00;
    pub const TRAP: u16 = 0x4E40;
    pub const LINK: u16 = 0x4E50;
    pub const UNLK: u16 = 0x4E58;
    pub const MOVE_USP: u16 = 0x4E60;
    pub const RESET: u16 = 0x4E70;
    pub const NOP: u16 = 0x4E71;
    pub const STOP: u16 = 0x4E72;
    pub const RTE: u16 = 0x4E73;
    pub const RTD: u16 = 0x4E74;
    pub const RTS: u16 = 0x4E75;
    pub const TRAPV: u16 = 0x4E76;
    pub const RTR: u16 = 0x4E77;
    pub const JSR: u16 = 0x4E80;
    pub const JMP: u16 = 0x4EC0;
    pub const MOVEM_TO_MEM: u16 = 0x4880;
    pub const MOVEM_FROM_MEM: u16 = 0x4C80;
    pub const LEA: u16 = 0x41C0;
    pub const CHK: u16 = 0x4180;
}

/// Common m68k instruction patterns.
pub mod patterns {
    /// NOP.
    pub const NOP: u16 = 0x4E71;

    /// RTS (return from subroutine).
    pub const RTS: u16 = 0x4E75;

    /// RTE (return from exception).
    pub const RTE: u16 = 0x4E73;

    /// RTR (return and restore CCR).
    pub const RTR: u16 = 0x4E77;

    /// ILLEGAL instruction.
    pub const ILLEGAL: u16 = 0x4AFC;

    /// TRAP #0.
    pub const TRAP_0: u16 = 0x4E40;

    /// RESET.
    pub const RESET: u16 = 0x4E70;

    /// STOP.
    pub const STOP: u16 = 0x4E72;

    /// TRAPV.
    pub const TRAPV: u16 = 0x4E76;

    /// JSR (absolute long) mask.
    pub const JSR_MASK: u16 = 0xFFC0;
    pub const JSR_VAL: u16 = 0x4E80;

    /// JMP (absolute long) mask.
    pub const JMP_MASK: u16 = 0xFFC0;
    pub const JMP_VAL: u16 = 0x4EC0;

    /// LEA mask.
    pub const LEA_MASK: u16 = 0xF1C0;
    pub const LEA_VAL: u16 = 0x41C0;

    /// LINK mask.
    pub const LINK_MASK: u16 = 0xFFF8;
    pub const LINK_VAL: u16 = 0x4E50;

    /// UNLK mask.
    pub const UNLK_MASK: u16 = 0xFFF8;
    pub const UNLK_VAL: u16 = 0x4E58;

    /// BSR (branch to subroutine) - 8-bit displacement.
    pub const BSR_BYTE: u16 = 0x6100;
    /// BSR with 16-bit displacement marker.
    pub const BSR_WORD: u16 = 0x6100;

    /// BRA (branch always) - 8-bit displacement.
    pub const BRA_BYTE: u16 = 0x6000;

    /// MOVEM to memory mask.
    pub const MOVEM_TO_MEM_MASK: u16 = 0xFB80;
    pub const MOVEM_TO_MEM_VAL: u16 = 0x4880;

    /// MOVEM from memory mask.
    pub const MOVEM_FROM_MEM_MASK: u16 = 0xFB80;
    pub const MOVEM_FROM_MEM_VAL: u16 = 0x4C80;
}

/// Condition codes for Bcc/DBcc/Scc instructions.
pub mod condition {
    pub const TRUE: u8 = 0x0; // T (always true)
    pub const FALSE: u8 = 0x1; // F (always false)
    pub const HI: u8 = 0x2; // Higher (unsigned >)
    pub const LS: u8 = 0x3; // Lower or same (unsigned <=)
    pub const CC: u8 = 0x4; // Carry clear (HI or same)
    pub const CS: u8 = 0x5; // Carry set (LO)
    pub const NE: u8 = 0x6; // Not equal
    pub const EQ: u8 = 0x7; // Equal
    pub const VC: u8 = 0x8; // Overflow clear
    pub const VS: u8 = 0x9; // Overflow set
    pub const PL: u8 = 0xA; // Plus (positive)
    pub const MI: u8 = 0xB; // Minus (negative)
    pub const GE: u8 = 0xC; // Greater or equal (signed)
    pub const LT: u8 = 0xD; // Less than (signed)
    pub const GT: u8 = 0xE; // Greater than (signed)
    pub const LE: u8 = 0xF; // Less or equal (signed)
}

/// Addressing mode encodings.
pub mod addr_mode {
    pub const DATA_REG: u8 = 0b000; // Dn
    pub const ADDR_REG: u8 = 0b001; // An
    pub const ADDR_IND: u8 = 0b010; // (An)
    pub const ADDR_IND_POST: u8 = 0b011; // (An)+
    pub const ADDR_IND_PRE: u8 = 0b100; // -(An)
    pub const ADDR_IND_DISP: u8 = 0b101; // (d16,An)
    pub const ADDR_IND_INDEX: u8 = 0b110; // (d8,An,Xn)
    pub const SPECIAL: u8 = 0b111; // Special modes (reg field determines)

    // Special mode register field values
    pub const ABS_SHORT: u8 = 0b000; // (xxx).W
    pub const ABS_LONG: u8 = 0b001; // (xxx).L
    pub const PC_DISP: u8 = 0b010; // (d16,PC)
    pub const PC_INDEX: u8 = 0b011; // (d8,PC,Xn)
    pub const IMMEDIATE: u8 = 0b100; // #<data>
}

/// Extract opcode group (bits 15:12).
pub fn get_opcode_group(instr: u16) -> u8 {
    ((instr >> 12) & 0x0F) as u8
}

/// Extract source mode (bits 5:3).
pub fn get_src_mode(instr: u16) -> u8 {
    ((instr >> 3) & 0x07) as u8
}

/// Extract source register (bits 2:0).
pub fn get_src_reg(instr: u16) -> u8 {
    (instr & 0x07) as u8
}

/// Extract destination mode (bits 8:6).
pub fn get_dst_mode(instr: u16) -> u8 {
    ((instr >> 6) & 0x07) as u8
}

/// Extract destination register (bits 11:9).
pub fn get_dst_reg(instr: u16) -> u8 {
    ((instr >> 9) & 0x07) as u8
}

/// Extract condition code (bits 11:8) for Bcc/DBcc/Scc.
pub fn get_condition(instr: u16) -> u8 {
    ((instr >> 8) & 0x0F) as u8
}

/// Extract 8-bit displacement from Bcc.
pub fn get_disp8(instr: u16) -> i8 {
    (instr & 0xFF) as i8
}

/// Extract TRAP vector number (bits 3:0).
pub fn get_trap_vector(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract MOVEQ immediate data (bits 7:0).
pub fn get_moveq_data(instr: u16) -> i8 {
    (instr & 0xFF) as i8
}

/// Extract ADDQ/SUBQ data (bits 11:9, 0 means 8).
pub fn get_quick_data(instr: u16) -> u8 {
    let data = ((instr >> 9) & 0x07) as u8;
    if data == 0 {
        8
    } else {
        data
    }
}

/// Determine instruction length (basic, not accounting for all extensions).
/// Returns minimum length; actual length may be longer due to extension words.
pub fn base_instruction_length(instr: u16) -> usize {
    let group = get_opcode_group(instr);

    match group {
        opcode_group::MISC => {
            // Many misc instructions are 2 bytes, but some have extensions
            if instr == patterns::NOP
                || instr == patterns::RTS
                || instr == patterns::RTE
                || instr == patterns::RTR
                || instr == patterns::ILLEGAL
                || instr == patterns::RESET
                || instr == patterns::TRAPV
            {
                2
            } else if (instr & 0xFFF0) == patterns::TRAP_0 {
                2
            } else {
                // Default to 2, but may have extension words
                2
            }
        }
        opcode_group::BCC_BSR_BRA => {
            let disp = get_disp8(instr);
            if disp == 0 {
                4 // 16-bit displacement follows
            } else if disp == -1i8 as u8 as i8 {
                6 // 32-bit displacement (68020+)
            } else {
                2 // 8-bit displacement in instruction
            }
        }
        opcode_group::MOVEQ => 2,
        _ => 2, // Minimum size
    }
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u16) -> bool {
    instr == patterns::NOP
}

/// Check if instruction is RTS (return).
pub fn is_rts(instr: u16) -> bool {
    instr == patterns::RTS
}

/// Check if instruction is any return type.
pub fn is_return(instr: u16) -> bool {
    matches!(instr, patterns::RTS | patterns::RTE | patterns::RTR)
}

/// Check if instruction is a branch (Bcc, BRA, BSR).
pub fn is_branch(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::BCC_BSR_BRA
}

/// Check if instruction is BSR (call).
pub fn is_bsr(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::BCC_BSR_BRA && get_condition(instr) == 0x01
    // BSR uses condition code 0001
}

/// Check if instruction is BRA (unconditional branch).
pub fn is_bra(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::BCC_BSR_BRA && get_condition(instr) == 0x00
    // BRA uses condition code 0000
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

/// Check if instruction is TRAP.
pub fn is_trap(instr: u16) -> bool {
    (instr & 0xFFF0) == patterns::TRAP_0
}

/// Check if instruction is LINK.
pub fn is_link(instr: u16) -> bool {
    (instr & patterns::LINK_MASK) == patterns::LINK_VAL
}

/// Check if instruction is UNLK.
pub fn is_unlk(instr: u16) -> bool {
    (instr & patterns::UNLK_MASK) == patterns::UNLK_VAL
}

/// Check if instruction is LEA.
pub fn is_lea(instr: u16) -> bool {
    (instr & patterns::LEA_MASK) == patterns::LEA_VAL
}

/// Check if instruction is a MOVE.
pub fn is_move(instr: u16) -> bool {
    let group = get_opcode_group(instr);
    matches!(
        group,
        opcode_group::MOVE_BYTE | opcode_group::MOVE_WORD | opcode_group::MOVE_LONG
    )
}

/// Check if instruction is MOVEQ.
pub fn is_moveq(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::MOVEQ && (instr & 0x0100) == 0
}

/// Check if instruction is MOVEM.
pub fn is_movem(instr: u16) -> bool {
    ((instr & patterns::MOVEM_TO_MEM_MASK) == patterns::MOVEM_TO_MEM_VAL)
        || ((instr & patterns::MOVEM_FROM_MEM_MASK) == patterns::MOVEM_FROM_MEM_VAL)
}

/// Check if instruction is ILLEGAL.
pub fn is_illegal(instr: u16) -> bool {
    instr == patterns::ILLEGAL
}

/// Check if instruction is A-line trap (emulator).
pub fn is_a_line(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::RESERVED_A
}

/// Check if instruction is F-line trap (coprocessor).
pub fn is_f_line(instr: u16) -> bool {
    get_opcode_group(instr) == opcode_group::RESERVED_F
}

/// Valid first-word patterns for heuristic detection.
/// These are instruction patterns that strongly indicate m68k code.
pub const STRONG_INDICATORS: &[u16] = &[
    patterns::NOP,
    patterns::RTS,
    patterns::RTE,
    patterns::RTR,
    patterns::RESET,
    patterns::TRAPV,
];

/// Score likelihood of m68k code.
///
/// Analyzes raw bytes for patterns characteristic of m68k.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    // Cross-architecture penalties for LE 16-bit ISAs
    // m68k is BE; LE data from AVR/Thumb/MSP430 should be penalized
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw_le = u16::from_le_bytes([data[j], data[j + 1]]);
            // AVR distinctive patterns
            if hw_le == 0x9508 {
                score -= 12;
            } // AVR RET
            if hw_le == 0x9518 {
                score -= 10;
            } // AVR RETI
            if hw_le == 0x9588 {
                score -= 8;
            } // AVR SLEEP
            if hw_le == 0x95A8 {
                score -= 8;
            } // AVR WDR
            if hw_le == 0x9409 {
                score -= 6;
            } // AVR IJMP
            if hw_le == 0x9509 {
                score -= 6;
            } // AVR ICALL
              // Thumb
            if hw_le == 0x4770 {
                score -= 10;
            } // Thumb BX LR
            if hw_le == 0xBF00 {
                score -= 6;
            } // Thumb NOP
            if (hw_le & 0xFF00) == 0xB500 {
                score -= 5;
            } // Thumb PUSH {.., LR}
            if (hw_le & 0xFF00) == 0xBD00 {
                score -= 5;
            } // Thumb POP {.., PC}
              // MSP430
            if hw_le == 0x4130 {
                score -= 10;
            } // MSP430 RET
            if hw_le == 0x4303 {
                score -= 6;
            } // MSP430 NOP
            j += 2;
        }
    }

    // m68k is big-endian
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);

        // Invalid/padding
        if word == 0x0000 || word == 0xFFFF {
            score -= 5;
            continue;
        }

        // --- Cross-architecture penalties (BE 16-bit) ---
        // S390x: BR %r14
        if word == 0x07FE {
            score -= 12;
            continue;
        }
        // SPARC NOP top halfword
        if word == 0x0100 {
            score -= 5;
            continue;
        }

        // NOP
        if is_nop(word) {
            score += 25;
            continue;
        }

        // RTS (return)
        if is_rts(word) {
            score += 30;
            ret_count += 1;
            continue;
        }

        // RTE (return from exception)
        if word == patterns::RTE {
            score += 15;
            ret_count += 1;
            continue;
        }

        // TRAP
        if is_trap(word) {
            score += 15;
            continue;
        }

        // JSR
        if is_jsr(word) {
            score += 10;
            call_count += 1;
            continue;
        }

        // JMP
        if is_jmp(word) {
            score += 8;
            branch_count += 1;
            continue;
        }

        // BSR (call)
        if is_bsr(word) {
            score += 8;
            call_count += 1;
            continue;
        }

        // Bcc (conditional branches)
        if is_branch(word) && !is_bra(word) && !is_bsr(word) {
            score += 3;
            branch_count += 1;
            continue;
        }

        // BRA
        if is_bra(word) {
            score += 3;
            branch_count += 1;
            continue;
        }

        // LINK/UNLK (function prologue/epilogue)
        if is_link(word) {
            score += 8;
            call_count += 1;
            continue;
        }
        if is_unlk(word) {
            score += 8;
            ret_count += 1;
            continue;
        }

        let group = get_opcode_group(word);
        let mut matched = true;
        match group {
            // MOVE.L (most common)
            opcode_group::MOVE_LONG => score += 3,
            // MOVE.W
            opcode_group::MOVE_WORD => score += 2,
            // MOVE.B
            opcode_group::MOVE_BYTE => score += 2,
            // MOVEQ
            opcode_group::MOVEQ if is_moveq(word) => score += 5,
            // LEA
            opcode_group::MISC if is_lea(word) => score += 5,
            // MOVEM
            opcode_group::MISC if is_movem(word) => score += 5,
            // ADD/ADDX
            opcode_group::ADD_ADDX => score += 2,
            // SUB/SUBX
            opcode_group::SUB_SUBX => score += 2,
            // CMP/EOR
            opcode_group::CMP_EOR => score += 2,
            // AND/MUL
            opcode_group::AND_MUL_ABCD_EXG => score += 2,
            // OR/DIV
            opcode_group::OR_DIV_SBCD => score += 2,
            // ADDQ/SUBQ
            opcode_group::ADDQ_SUBQ_SCC_DBCC => score += 2,
            // Shift/rotate
            opcode_group::SHIFT_ROTATE => score += 2,
            // Bit operations/immediate
            opcode_group::BITOP_MOVEP_IMM => score += 1,
            // A-line and F-line are reserved/trap
            opcode_group::RESERVED_A | opcode_group::RESERVED_F => {
                score -= 3;
                matched = false;
            }
            _ => {
                matched = false;
            }
        }

        if !matched {
            score -= 1;
        }
    }

    // Structural requirement
    let num_halfwords = data.len() / 2;
    if num_halfwords > 40 {
        let distinctive = ret_count + call_count;
        if distinctive == 0 && branch_count == 0 {
            score = (score as f64 * 0.10) as i64;
        } else if distinctive == 0 {
            score = (score as f64 * 0.25) as i64;
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
        assert!(is_return(patterns::RTR));
    }

    #[test]
    fn test_opcode_group() {
        assert_eq!(get_opcode_group(patterns::NOP), opcode_group::MISC);
        assert_eq!(get_opcode_group(0x6000), opcode_group::BCC_BSR_BRA); // BRA
        assert_eq!(get_opcode_group(0x7000), opcode_group::MOVEQ);
    }

    #[test]
    fn test_branch_detection() {
        assert!(is_branch(0x6000)); // BRA
        assert!(is_branch(0x6100)); // BSR
        assert!(is_branch(0x6700)); // BEQ
        assert!(!is_branch(patterns::NOP));
    }

    #[test]
    fn test_bsr_detection() {
        assert!(is_bsr(0x6100)); // BSR.S
        assert!(is_bsr(0x6100)); // BSR.W (with 0 displacement)
        assert!(!is_bsr(0x6000)); // BRA
    }

    #[test]
    fn test_jsr_detection() {
        // JSR (A0) = 0x4E90
        assert!(is_jsr(0x4E90));
        // JSR (xxx).L = 0x4EB9
        assert!(is_jsr(0x4EB9));
    }

    #[test]
    fn test_trap_detection() {
        assert!(is_trap(0x4E40)); // TRAP #0
        assert!(is_trap(0x4E4F)); // TRAP #15
        assert!(!is_trap(patterns::NOP));
    }

    #[test]
    fn test_moveq() {
        // MOVEQ #0, D0 = 0x7000
        assert!(is_moveq(0x7000));
        assert_eq!(get_moveq_data(0x7000), 0);
        // MOVEQ #-1, D0 = 0x70FF
        assert!(is_moveq(0x70FF));
        assert_eq!(get_moveq_data(0x70FF), -1);
    }

    #[test]
    fn test_instruction_length() {
        assert_eq!(base_instruction_length(patterns::NOP), 2);
        assert_eq!(base_instruction_length(patterns::RTS), 2);
        assert_eq!(base_instruction_length(0x6000), 4); // BRA.W (disp=0)
        assert_eq!(base_instruction_length(0x6002), 2); // BRA.S (disp=2)
    }

    #[test]
    fn test_score() {
        // m68k NOP (big-endian)
        let nop = patterns::NOP.to_be_bytes();
        assert!(score(&nop) > 0);
    }
}
