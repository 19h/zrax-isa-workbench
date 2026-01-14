//! LoongArch architecture analysis.
//!
//! LoongArch uses fixed 32-bit instructions with little-endian encoding.
//! It is a RISC architecture developed by Loongson Technology.

/// Major opcode groups (bits 31:26).
pub mod opcode {
    // Basic integer operations
    pub const ADD_W: u32 = 0x00100000;     // ADD.W
    pub const ADD_D: u32 = 0x00108000;     // ADD.D
    pub const SUB_W: u32 = 0x00110000;     // SUB.W
    pub const SUB_D: u32 = 0x00118000;     // SUB.D
    pub const ADDI_W: u32 = 0x02800000;    // ADDI.W
    pub const ADDI_D: u32 = 0x02C00000;    // ADDI.D
    pub const ANDI: u32 = 0x03400000;      // ANDI (NOP when all zeros)
    pub const ORI: u32 = 0x03800000;       // ORI
    pub const XORI: u32 = 0x03C00000;      // XORI
    
    // Load/Store
    pub const LD_B: u32 = 0x28000000;      // LD.B
    pub const LD_H: u32 = 0x28400000;      // LD.H
    pub const LD_W: u32 = 0x28800000;      // LD.W
    pub const LD_D: u32 = 0x28C00000;      // LD.D
    pub const ST_B: u32 = 0x29000000;      // ST.B
    pub const ST_H: u32 = 0x29400000;      // ST.H
    pub const ST_W: u32 = 0x29800000;      // ST.W
    pub const ST_D: u32 = 0x29C00000;      // ST.D
    pub const LD_BU: u32 = 0x2A000000;     // LD.BU
    pub const LD_HU: u32 = 0x2A400000;     // LD.HU
    pub const LD_WU: u32 = 0x2A800000;     // LD.WU
    
    // Branches
    pub const BEQZ: u32 = 0x40000000;      // BEQZ
    pub const BNEZ: u32 = 0x44000000;      // BNEZ
    pub const JIRL: u32 = 0x4C000000;      // JIRL (includes RET)
    pub const B: u32 = 0x50000000;         // B (unconditional)
    pub const BL: u32 = 0x54000000;        // BL (branch and link)
    pub const BEQ: u32 = 0x58000000;       // BEQ
    pub const BNE: u32 = 0x5C000000;       // BNE
    pub const BLT: u32 = 0x60000000;       // BLT
    pub const BGE: u32 = 0x64000000;       // BGE
    pub const BLTU: u32 = 0x68000000;      // BLTU
    pub const BGEU: u32 = 0x6C000000;      // BGEU
    
    // System
    pub const SYSCALL: u32 = 0x002B0000;   // SYSCALL
    pub const BREAK: u32 = 0x002A0000;     // BREAK
    
    // Multiply/Divide
    pub const MUL_W: u32 = 0x001C0000;     // MUL.W
    pub const MUL_D: u32 = 0x001D8000;     // MUL.D
    pub const DIV_W: u32 = 0x00200000;     // DIV.W
    pub const DIV_D: u32 = 0x00220000;     // DIV.D
    
    // Shifts
    pub const SLL_W: u32 = 0x00170000;     // SLL.W
    pub const SRL_W: u32 = 0x00178000;     // SRL.W
    pub const SRA_W: u32 = 0x00180000;     // SRA.W
    pub const SLL_D: u32 = 0x00188000;     // SLL.D
    pub const SRL_D: u32 = 0x00190000;     // SRL.D
    pub const SRA_D: u32 = 0x00198000;     // SRA.D
    
    // Logical
    pub const AND: u32 = 0x00148000;       // AND
    pub const OR: u32 = 0x00150000;        // OR
    pub const XOR: u32 = 0x00158000;       // XOR
    pub const NOR: u32 = 0x00140000;       // NOR
    
    // Floating point load/store
    pub const FLD_S: u32 = 0x2B000000;     // FLD.S
    pub const FST_S: u32 = 0x2B400000;     // FST.S
    pub const FLD_D: u32 = 0x2B800000;     // FLD.D
    pub const FST_D: u32 = 0x2BC00000;     // FST.D
    
    // Vector (LSX - 128-bit)
    pub const VLD: u32 = 0x2C000000;       // VLD
    pub const VST: u32 = 0x2C400000;       // VST
    
    // Vector (LASX - 256-bit)
    pub const XVLD: u32 = 0x2C800000;      // XVLD
    pub const XVST: u32 = 0x2CC00000;      // XVST
}

/// Common LoongArch instruction patterns.
pub mod patterns {
    /// NOP (ANDI $zero, $zero, 0).
    pub const NOP: u32 = 0x03400000;
    
    /// RET (JIRL $zero, $ra, 0).
    pub const RET: u32 = 0x4C000020;
    
    /// SYSCALL 0.
    pub const SYSCALL_0: u32 = 0x002B0000;
    
    /// BREAK 0.
    pub const BREAK_0: u32 = 0x002A0000;
    
    /// Masks for instruction decoding.
    pub const OPCODE_MASK_26: u32 = 0xFC000000;  // Top 6 bits
    pub const OPCODE_MASK_22: u32 = 0xFFC00000;  // Top 10 bits
    pub const OPCODE_MASK_17: u32 = 0xFFFF8000;  // Top 17 bits
    pub const OPCODE_MASK_15: u32 = 0xFFFE0000;  // Top 15 bits
}

/// Register indices.
pub mod reg {
    pub const ZERO: u8 = 0;   // $zero - always zero
    pub const RA: u8 = 1;     // $ra - return address
    pub const TP: u8 = 2;     // $tp - thread pointer
    pub const SP: u8 = 3;     // $sp - stack pointer
    pub const A0: u8 = 4;     // $a0 - argument/return
    pub const A1: u8 = 5;     // $a1
    pub const A2: u8 = 6;     // $a2
    pub const A3: u8 = 7;     // $a3
    pub const A4: u8 = 8;     // $a4
    pub const A5: u8 = 9;     // $a5
    pub const A6: u8 = 10;    // $a6
    pub const A7: u8 = 11;    // $a7
    pub const T0: u8 = 12;    // $t0 - temporary
    pub const T1: u8 = 13;    // $t1
    pub const T2: u8 = 14;    // $t2
    pub const T3: u8 = 15;    // $t3
    pub const T4: u8 = 16;    // $t4
    pub const T5: u8 = 17;    // $t5
    pub const T6: u8 = 18;    // $t6
    pub const T7: u8 = 19;    // $t7
    pub const T8: u8 = 20;    // $t8
    pub const FP: u8 = 22;    // $fp - frame pointer (also $s9)
    pub const S0: u8 = 23;    // $s0 - saved
    pub const S1: u8 = 24;    // $s1
    pub const S2: u8 = 25;    // $s2
    pub const S3: u8 = 26;    // $s3
    pub const S4: u8 = 27;    // $s4
    pub const S5: u8 = 28;    // $s5
    pub const S6: u8 = 29;    // $s6
    pub const S7: u8 = 30;    // $s7
    pub const S8: u8 = 31;    // $s8
}

/// Extract rd field (bits 4:0).
pub fn get_rd(instr: u32) -> u8 {
    (instr & 0x1F) as u8
}

/// Extract rj field (bits 9:5).
pub fn get_rj(instr: u32) -> u8 {
    ((instr >> 5) & 0x1F) as u8
}

/// Extract rk field (bits 14:10).
pub fn get_rk(instr: u32) -> u8 {
    ((instr >> 10) & 0x1F) as u8
}

/// Extract 12-bit signed immediate (bits 21:10).
pub fn get_si12(instr: u32) -> i16 {
    let val = ((instr >> 10) & 0xFFF) as i16;
    // Sign extend from 12 bits
    if val & 0x800 != 0 {
        val | !0xFFF
    } else {
        val
    }
}

/// Extract 12-bit unsigned immediate (bits 21:10).
pub fn get_ui12(instr: u32) -> u16 {
    ((instr >> 10) & 0xFFF) as u16
}

/// Extract 16-bit signed immediate (bits 25:10).
pub fn get_si16(instr: u32) -> i32 {
    let val = ((instr >> 10) & 0xFFFF) as i32;
    // Sign extend from 16 bits
    if val & 0x8000 != 0 {
        val | !0xFFFF
    } else {
        val
    }
}

/// Extract 20-bit signed immediate (bits 24:5).
pub fn get_si20(instr: u32) -> i32 {
    let val = ((instr >> 5) & 0xFFFFF) as i32;
    // Sign extend from 20 bits
    if val & 0x80000 != 0 {
        val | !0xFFFFF
    } else {
        val
    }
}

/// Extract 26-bit offset for B/BL (bits 25:10 | bits 9:0).
pub fn get_offs26(instr: u32) -> i32 {
    let low = (instr & 0x3FF) as i32;
    let high = ((instr >> 10) & 0xFFFF) as i32;
    let val = (high << 10) | low;
    // Sign extend from 26 bits
    if val & 0x2000000 != 0 {
        val | !0x3FFFFFF
    } else {
        val
    }
}

/// Extract 21-bit offset for conditional branches.
pub fn get_offs21(instr: u32) -> i32 {
    let low = (instr & 0x1F) as i32;
    let high = ((instr >> 10) & 0xFFFF) as i32;
    let val = (high << 5) | low;
    // Sign extend from 21 bits
    if val & 0x100000 != 0 {
        val | !0x1FFFFF
    } else {
        val
    }
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u32) -> bool {
    instr == patterns::NOP
}

/// Check if instruction is RET.
pub fn is_ret(instr: u32) -> bool {
    // JIRL $zero, $ra, 0
    instr == patterns::RET
}

/// Check if instruction is a return (JIRL to $zero).
pub fn is_return(instr: u32) -> bool {
    // JIRL with rd=$zero
    let masked = instr & patterns::OPCODE_MASK_26;
    masked == opcode::JIRL && get_rd(instr) == reg::ZERO
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_26;
    matches!(op,
        opcode::BEQZ | opcode::BNEZ | opcode::B | opcode::BL |
        opcode::BEQ | opcode::BNE | opcode::BLT | opcode::BGE |
        opcode::BLTU | opcode::BGEU | opcode::JIRL
    )
}

/// Check if instruction is unconditional branch (B).
pub fn is_b(instr: u32) -> bool {
    (instr & patterns::OPCODE_MASK_26) == opcode::B
}

/// Check if instruction is BL (branch and link - call).
pub fn is_bl(instr: u32) -> bool {
    (instr & patterns::OPCODE_MASK_26) == opcode::BL
}

/// Check if instruction is JIRL.
pub fn is_jirl(instr: u32) -> bool {
    (instr & patterns::OPCODE_MASK_26) == opcode::JIRL
}

/// Check if instruction is a call (BL or JIRL with rd=$ra).
pub fn is_call(instr: u32) -> bool {
    if is_bl(instr) {
        return true;
    }
    // JIRL with rd=$ra (link register)
    if is_jirl(instr) && get_rd(instr) == reg::RA {
        return true;
    }
    false
}

/// Check if instruction is SYSCALL.
pub fn is_syscall(instr: u32) -> bool {
    (instr & 0xFFFF8000) == opcode::SYSCALL
}

/// Check if instruction is BREAK.
pub fn is_break(instr: u32) -> bool {
    (instr & 0xFFFF8000) == opcode::BREAK
}

/// Check if instruction is a load.
pub fn is_load(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_22;
    matches!(op,
        opcode::LD_B | opcode::LD_H | opcode::LD_W | opcode::LD_D |
        opcode::LD_BU | opcode::LD_HU | opcode::LD_WU |
        opcode::FLD_S | opcode::FLD_D
    )
}

/// Check if instruction is a store.
pub fn is_store(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_22;
    matches!(op,
        opcode::ST_B | opcode::ST_H | opcode::ST_W | opcode::ST_D |
        opcode::FST_S | opcode::FST_D
    )
}

/// Check if instruction is a vector (LSX) instruction.
pub fn is_lsx(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_22;
    op == opcode::VLD || op == opcode::VST
}

/// Check if instruction is a vector (LASX) instruction.
pub fn is_lasx(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_22;
    op == opcode::XVLD || op == opcode::XVST
}

/// Strong indicator patterns for heuristic detection.
pub const STRONG_INDICATORS: &[u32] = &[
    patterns::NOP,
    patterns::RET,
];

/// Valid opcode prefixes for heuristic detection.
pub const VALID_OPCODE_PREFIXES: &[u32] = &[
    0x00100000, // ADD.W
    0x00108000, // ADD.D
    0x02800000, // ADDI.W
    0x02C00000, // ADDI.D
    0x03400000, // ANDI
    0x03800000, // ORI
    0x28000000, // LD.B
    0x28800000, // LD.W
    0x28C00000, // LD.D
    0x29000000, // ST.B
    0x29800000, // ST.W
    0x29C00000, // ST.D
    0x4C000000, // JIRL
    0x50000000, // B
    0x54000000, // BL
    0x58000000, // BEQ
    0x5C000000, // BNE
];

/// Score likelihood of LoongArch code.
///
/// Analyzes raw bytes for patterns characteristic of LoongArch.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // LoongArch is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // NOP
        if is_nop(word) {
            score += 25;
        }

        // RET
        if is_ret(word) {
            score += 30;
        }

        // SYSCALL
        if is_syscall(word) {
            score += 20;
        }

        // BREAK
        if is_break(word) {
            score += 15;
        }

        // Check for valid instruction patterns
        if is_branch(word) {
            score += 3;
        }

        if is_load(word) || is_store(word) {
            score += 3;
        }

        // BL (call)
        if is_bl(word) {
            score += 5;
        }

        // B (unconditional branch)
        if is_b(word) {
            score += 5;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
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
        assert!(!is_nop(patterns::RET));
    }

    #[test]
    fn test_ret_detection() {
        assert!(is_ret(patterns::RET));
        assert!(is_return(patterns::RET));
    }

    #[test]
    fn test_branch_detection() {
        assert!(is_b(opcode::B));
        assert!(is_bl(opcode::BL));
        assert!(is_branch(opcode::B));
        assert!(is_branch(opcode::BL));
        assert!(is_branch(opcode::BEQ));
    }

    #[test]
    fn test_call_detection() {
        assert!(is_call(opcode::BL));
        // JIRL $ra, $t0, 0 = JIRL with rd=1
        let jirl_call = opcode::JIRL | 0x01; // rd=$ra
        assert!(is_call(jirl_call));
    }

    #[test]
    fn test_register_extraction() {
        // ADD.W $a0, $a1, $a2 - rd=4, rj=5, rk=6
        let add_instr = 0x00100000 | (6 << 10) | (5 << 5) | 4;
        assert_eq!(get_rd(add_instr), 4);
        assert_eq!(get_rj(add_instr), 5);
        assert_eq!(get_rk(add_instr), 6);
    }

    #[test]
    fn test_immediate_extraction() {
        // ADDI.W $t0, $t1, 100
        let addi = 0x02800000 | (100 << 10) | (13 << 5) | 12;
        assert_eq!(get_si12(addi), 100);
        
        // ADDI.W $t0, $t1, -1
        let addi_neg = 0x02800000 | (0xFFF << 10) | (13 << 5) | 12;
        assert_eq!(get_si12(addi_neg), -1);
    }

    #[test]
    fn test_load_store() {
        assert!(is_load(opcode::LD_W));
        assert!(is_load(opcode::LD_D));
        assert!(is_store(opcode::ST_W));
        assert!(is_store(opcode::ST_D));
    }

    #[test]
    fn test_syscall_break() {
        assert!(is_syscall(patterns::SYSCALL_0));
        assert!(is_break(patterns::BREAK_0));
    }

    #[test]
    fn test_score() {
        // LoongArch NOP (little-endian)
        let nop = patterns::NOP.to_le_bytes();
        assert!(score(&nop) > 0);
    }
}
