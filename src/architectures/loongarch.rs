//! LoongArch architecture analysis.
//!
//! LoongArch uses fixed 32-bit instructions with little-endian encoding.
//! It is a RISC architecture developed by Loongson Technology.

/// Major opcode groups (bits 31:26).
pub mod opcode {
    // Basic integer operations
    pub const ADD_W: u32 = 0x00100000; // ADD.W
    pub const ADD_D: u32 = 0x00108000; // ADD.D
    pub const SUB_W: u32 = 0x00110000; // SUB.W
    pub const SUB_D: u32 = 0x00118000; // SUB.D
    pub const ADDI_W: u32 = 0x02800000; // ADDI.W
    pub const ADDI_D: u32 = 0x02C00000; // ADDI.D
    pub const ANDI: u32 = 0x03400000; // ANDI (NOP when all zeros)
    pub const ORI: u32 = 0x03800000; // ORI
    pub const XORI: u32 = 0x03C00000; // XORI

    // Load/Store
    pub const LD_B: u32 = 0x28000000; // LD.B
    pub const LD_H: u32 = 0x28400000; // LD.H
    pub const LD_W: u32 = 0x28800000; // LD.W
    pub const LD_D: u32 = 0x28C00000; // LD.D
    pub const ST_B: u32 = 0x29000000; // ST.B
    pub const ST_H: u32 = 0x29400000; // ST.H
    pub const ST_W: u32 = 0x29800000; // ST.W
    pub const ST_D: u32 = 0x29C00000; // ST.D
    pub const LD_BU: u32 = 0x2A000000; // LD.BU
    pub const LD_HU: u32 = 0x2A400000; // LD.HU
    pub const LD_WU: u32 = 0x2A800000; // LD.WU

    // Branches
    pub const BEQZ: u32 = 0x40000000; // BEQZ
    pub const BNEZ: u32 = 0x44000000; // BNEZ
    pub const JIRL: u32 = 0x4C000000; // JIRL (includes RET)
    pub const B: u32 = 0x50000000; // B (unconditional)
    pub const BL: u32 = 0x54000000; // BL (branch and link)
    pub const BEQ: u32 = 0x58000000; // BEQ
    pub const BNE: u32 = 0x5C000000; // BNE
    pub const BLT: u32 = 0x60000000; // BLT
    pub const BGE: u32 = 0x64000000; // BGE
    pub const BLTU: u32 = 0x68000000; // BLTU
    pub const BGEU: u32 = 0x6C000000; // BGEU

    // System
    pub const SYSCALL: u32 = 0x002B0000; // SYSCALL
    pub const BREAK: u32 = 0x002A0000; // BREAK

    // Multiply/Divide
    pub const MUL_W: u32 = 0x001C0000; // MUL.W
    pub const MUL_D: u32 = 0x001D8000; // MUL.D
    pub const DIV_W: u32 = 0x00200000; // DIV.W
    pub const DIV_D: u32 = 0x00220000; // DIV.D

    // Shifts
    pub const SLL_W: u32 = 0x00170000; // SLL.W
    pub const SRL_W: u32 = 0x00178000; // SRL.W
    pub const SRA_W: u32 = 0x00180000; // SRA.W
    pub const SLL_D: u32 = 0x00188000; // SLL.D
    pub const SRL_D: u32 = 0x00190000; // SRL.D
    pub const SRA_D: u32 = 0x00198000; // SRA.D

    // Logical
    pub const AND: u32 = 0x00148000; // AND
    pub const OR: u32 = 0x00150000; // OR
    pub const XOR: u32 = 0x00158000; // XOR
    pub const NOR: u32 = 0x00140000; // NOR

    // Floating point load/store
    pub const FLD_S: u32 = 0x2B000000; // FLD.S
    pub const FST_S: u32 = 0x2B400000; // FST.S
    pub const FLD_D: u32 = 0x2B800000; // FLD.D
    pub const FST_D: u32 = 0x2BC00000; // FST.D

    // Vector (LSX - 128-bit)
    pub const VLD: u32 = 0x2C000000; // VLD
    pub const VST: u32 = 0x2C400000; // VST

    // Vector (LASX - 256-bit)
    pub const XVLD: u32 = 0x2C800000; // XVLD
    pub const XVST: u32 = 0x2CC00000; // XVST
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
    pub const OPCODE_MASK_26: u32 = 0xFC000000; // Top 6 bits
    pub const OPCODE_MASK_22: u32 = 0xFFC00000; // Top 10 bits
    pub const OPCODE_MASK_17: u32 = 0xFFFF8000; // Top 17 bits
    pub const OPCODE_MASK_15: u32 = 0xFFFE0000; // Top 15 bits
}

/// Register indices.
pub mod reg {
    pub const ZERO: u8 = 0; // $zero - always zero
    pub const RA: u8 = 1; // $ra - return address
    pub const TP: u8 = 2; // $tp - thread pointer
    pub const SP: u8 = 3; // $sp - stack pointer
    pub const A0: u8 = 4; // $a0 - argument/return
    pub const A1: u8 = 5; // $a1
    pub const A2: u8 = 6; // $a2
    pub const A3: u8 = 7; // $a3
    pub const A4: u8 = 8; // $a4
    pub const A5: u8 = 9; // $a5
    pub const A6: u8 = 10; // $a6
    pub const A7: u8 = 11; // $a7
    pub const T0: u8 = 12; // $t0 - temporary
    pub const T1: u8 = 13; // $t1
    pub const T2: u8 = 14; // $t2
    pub const T3: u8 = 15; // $t3
    pub const T4: u8 = 16; // $t4
    pub const T5: u8 = 17; // $t5
    pub const T6: u8 = 18; // $t6
    pub const T7: u8 = 19; // $t7
    pub const T8: u8 = 20; // $t8
    pub const FP: u8 = 22; // $fp - frame pointer (also $s9)
    pub const S0: u8 = 23; // $s0 - saved
    pub const S1: u8 = 24; // $s1
    pub const S2: u8 = 25; // $s2
    pub const S3: u8 = 26; // $s3
    pub const S4: u8 = 27; // $s4
    pub const S5: u8 = 28; // $s5
    pub const S6: u8 = 29; // $s6
    pub const S7: u8 = 30; // $s7
    pub const S8: u8 = 31; // $s8
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
    matches!(
        op,
        opcode::BEQZ
            | opcode::BNEZ
            | opcode::B
            | opcode::BL
            | opcode::BEQ
            | opcode::BNE
            | opcode::BLT
            | opcode::BGE
            | opcode::BLTU
            | opcode::BGEU
            | opcode::JIRL
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
    matches!(
        op,
        opcode::LD_B
            | opcode::LD_H
            | opcode::LD_W
            | opcode::LD_D
            | opcode::LD_BU
            | opcode::LD_HU
            | opcode::LD_WU
            | opcode::FLD_S
            | opcode::FLD_D
    )
}

/// Check if instruction is a store.
pub fn is_store(instr: u32) -> bool {
    let op = instr & patterns::OPCODE_MASK_22;
    matches!(
        op,
        opcode::ST_B | opcode::ST_H | opcode::ST_W | opcode::ST_D | opcode::FST_S | opcode::FST_D
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
pub const STRONG_INDICATORS: &[u32] = &[patterns::NOP, patterns::RET];

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
    let mut valid_count = 0u32;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;
    let mut prologue_count = 0u32;
    let mut prev_word: u32 = 0;

    // LoongArch is little-endian, 4-byte aligned
    let mut i = 0;
    while i + 3 < data.len() {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Skip padding
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 3;
            i += 4;
            continue;
        }

        // --- Cross-architecture penalties ---

        // ARM32 (LE) patterns: condition 0xE in top 4 bits
        {
            let arm_cond = (word >> 28) & 0xF;
            if arm_cond == 0xE {
                let arm_type = (word >> 24) & 0xF;
                // ARM data processing (0xE0-0xE3)
                if arm_type <= 3 {
                    score -= 3;
                }
                // ARM BL (0xEB)
                if arm_type == 0xB {
                    score -= 5;
                }
            }
            // ARM NOP
            if word == 0xE1A00000 || word == 0xE320F000 {
                score -= 15;
                i += 4;
                continue;
            }
            // ARM BX LR
            if word == 0xE12FFF1E {
                score -= 20;
                i += 4;
                continue;
            }
            // ARM PUSH/POP
            if (word & 0xFFFF0000) == 0xE92D0000 || (word & 0xFFFF0000) == 0xE8BD0000 {
                score -= 10;
                i += 4;
                continue;
            }
        }

        // RISC-V (LE) patterns
        {
            if word == 0x00000013 {
                score -= 10;
                i += 4;
                continue;
            } // RV NOP
            if word == 0x00008067 {
                score -= 15;
                i += 4;
                continue;
            } // RV RET
        }

        // MIPS LE patterns
        {
            if word == 0x03E00008 {
                score -= 15;
                i += 4;
                continue;
            } // MIPS JR $ra (LE)
        }

        // Hexagon (LE) patterns
        {
            // Hexagon NOP (upper 16 bits = 0x7F00)
            if (word & 0xFFFF0000) == 0x7F000000 {
                score -= 10;
                i += 4;
                continue;
            }
            // Hexagon DEALLOC_RETURN
            if word == 0x961EC01E {
                score -= 15;
                i += 4;
                continue;
            }
            // Hexagon ALLOCFRAME
            if (word & 0xFFFFE000) == 0xA09DC000 {
                score -= 10;
                i += 4;
                continue;
            }
        }

        // 16-bit LE cross-architecture penalties
        {
            let hw0 = u16::from_le_bytes([data[i], data[i + 1]]);
            let hw1 = if i + 3 < data.len() {
                u16::from_le_bytes([data[i + 2], data[i + 3]])
            } else {
                0
            };
            // Thumb BX LR
            if hw0 == 0x4770 || hw1 == 0x4770 {
                score -= 8;
            }
            // Thumb PUSH{LR} / POP{PC}
            if (hw0 & 0xFF00) == 0xB500 || (hw1 & 0xFF00) == 0xB500 {
                score -= 5;
            }
            if (hw0 & 0xFF00) == 0xBD00 || (hw1 & 0xFF00) == 0xBD00 {
                score -= 5;
            }
            // AVR RET / RETI
            if hw0 == 0x9508 || hw1 == 0x9508 {
                score -= 8;
            }
            if hw0 == 0x9518 || hw1 == 0x9518 {
                score -= 6;
            }
            // MSP430 RET
            if hw0 == 0x4130 || hw1 == 0x4130 {
                score -= 10;
            }
            // MSP430 NOP
            if hw0 == 0x4303 || hw1 == 0x4303 {
                score -= 6;
            }
            // SH RTS / NOP
            if hw0 == 0x000B || hw1 == 0x000B {
                score -= 8;
            }
        }

        // AArch64 (LE) patterns
        {
            let top8 = word >> 24;
            // AArch64 RET (D65F03C0)
            if word == 0xD65F03C0 {
                score -= 20;
                i += 4;
                continue;
            }
            // AArch64 NOP (D503201F)
            if word == 0xD503201F {
                score -= 15;
                i += 4;
                continue;
            }
            // AArch64 STP/LDP with x29,x30 (common prologue/epilogue)
            if (word & 0xFFC003E0) == 0xA90003E0 || (word & 0xFFC003E0) == 0xA94003E0 {
                score -= 8;
                i += 4;
                continue;
            }
        }

        // x86-64 patterns (byte-oriented, check common multi-byte sequences as LE words)
        {
            let b0 = (word & 0xFF) as u8;
            let b01 = word & 0xFFFF;
            // REX.W + MOV (0x48 89 or 0x48 8B) - extremely common x86-64 pattern
            if b01 == 0x8948 || b01 == 0x8B48 {
                score -= 8;
            }
            // x86-64 PUSH RBP (0x55) followed by REX.W MOV (0x48 89 E5 = mov rbp,rsp)
            if word == 0x8948_5500 || word == 0xE589_4855 {
                score -= 15;
            }
            // x86-64 RET (0xC3) as first byte
            if b0 == 0xC3 {
                score -= 5;
            }
            // x86-64 NOP (0x90) as first byte
            if b0 == 0x90 {
                score -= 3;
            }
            // x86-64 INT3 (0xCC) as first byte
            if b0 == 0xCC {
                score -= 4;
            }
        }

        // LoongArch function prologue: ADDI.D $sp,$sp,-N followed by ST.D $ra,$sp,M
        // ADDI.D $sp,$sp: top10=0x00B, rj=$sp(3), rd=$sp(3) → (word & 0xFFC003FF) == 0x02C00063
        // ST.D $ra,$sp: top10=0x0A7, rj=$sp(3), rd=$ra(1) → (word & 0xFFC003FF) == 0x29C00061
        if (prev_word & 0xFFC003FF) == 0x02C00063 && (word & 0xFFC003FF) == 0x29C00061 {
            score += 40;
            prologue_count += 1;
        }
        // Epilogue: LD.D $ra,$sp,N followed by ADDI.D $sp,$sp,+M
        if (prev_word & 0xFFC003FF) == 0x28C00061 && (word & 0xFFC003FF) == 0x02C00063 {
            score += 40;
            prologue_count += 1;
        }
        // PC-relative addressing: PCADDU12I followed by ADDI.D/LD.D with same register
        // PCADDU12I: (word & 0xFE000000) == 0x1C000000, rd = word & 0x1F
        if (prev_word & 0xFE000000) == 0x1C000000 {
            let prev_rd = prev_word & 0x1F;
            let curr_rj = (word >> 5) & 0x1F;
            if prev_rd == curr_rj {
                let top10 = (word >> 22) & 0x3FF;
                if matches!(top10, 0x00B | 0x0A3 | 0x0A0) {
                    // ADDI.D, LD.D, LD.B
                    score += 30;
                }
            }
        }

        // --- Exact match patterns (high confidence) ---
        if is_nop(word) {
            score += 25;
            valid_count += 1;
            i += 4;
            continue;
        }
        if is_ret(word) {
            score += 30;
            ret_count += 1;
            valid_count += 1;
            i += 4;
            continue;
        }
        if is_syscall(word) {
            score += 20;
            valid_count += 1;
            i += 4;
            continue;
        }
        if is_break(word) {
            score += 15;
            valid_count += 1;
            i += 4;
            continue;
        }

        // --- Instruction-class scoring ---
        let top6 = (word >> 26) & 0x3F;
        let top7 = (word >> 25) & 0x7F;
        let top10 = (word >> 22) & 0x3FF;
        let top17 = (word >> 15) & 0x1FFFF;

        let mut matched = false;

        // Address formation (very distinctive, 7-bit opcode)
        // LU12I.W: 0x14000000, mask 0xFE000000 -> top7 = 0x0A
        // LU32I.D: 0x16000000, mask 0xFE000000 -> top7 = 0x0B
        // PCALAU12I: 0x1A000000, mask 0xFE000000 -> top7 = 0x0D
        // PCADDU12I: 0x1C000000, mask 0xFE000000 -> top7 = 0x0E
        if matches!(top7, 0x0A | 0x0B | 0x0D | 0x0E) {
            score += 6;
            valid_count += 1;
            matched = true;
        }

        // ALU 3-register ops (17-bit opcode)
        if !matched {
            let alu_match = matches!(
                top17,
                0x00020 | // ADD.W
                0x00021 | // ADD.D
                0x00022 | // SUB.W
                0x00023 | // SUB.D
                0x00024 | // SLT
                0x00025 | // SLTU
                0x00029 | // AND
                0x0002A | // OR
                0x0002B | // XOR
                0x00028 | // NOR
                0x0002C | // ORN
                0x0002D | // ANDN
                0x0002E | // SLL.W
                0x0002F | // SRL.W
                0x00030 | // SRA.W
                0x00031 | // SLL.D
                0x00032 | // SRL.D
                0x00033 | // SRA.D
                0x00038 | // MUL.W
                0x0003B | // MUL.D
                0x00040 | // DIV.W
                0x00044 // DIV.D
            );
            if alu_match {
                score += 4;
                valid_count += 1;
                matched = true;
            }
        }

        // MASKEQZ/MASKNEZ - highly distinctive to LoongArch
        if !matched && matches!(top17, 0x00026 | 0x00027) {
            score += 8;
            valid_count += 1;
            matched = true;
        }

        // FP arithmetic 3R: FADD, FSUB, FMUL, FDIV, FMAX, FMIN, FSCALEB, FCOPYSIGN
        if !matched && (0x00201..=0x00214).contains(&top17) {
            score += 5;
            valid_count += 1;
            matched = true;
        }

        // FP move/conversion 2R: FABS, FNEG, FSQRT, FMOV, MOVGR2FR, MOVFR2GR, FCVT, FTINT, FFINT
        if !matched && (0x00228..=0x0023A).contains(&top17) {
            score += 5;
            valid_count += 1;
            matched = true;
        }

        // Shift immediates: SLLI, SRLI, SRAI, ROTRI (W and D variants)
        if !matched
            && matches!(
                top17,
                0x00081 |             // SLLI.W
            0x00082 | 0x00083 |   // SLLI.D (6-bit imm spans 2 top17 values)
            0x00089 |             // SRLI.W
            0x0008A | 0x0008B |   // SRLI.D
            0x00091 |             // SRAI.W
            0x00092 | 0x00093 |   // SRAI.D
            0x00099 |             // ROTRI.W
            0x0009A | 0x0009B // ROTRI.D
            )
        {
            score += 4;
            valid_count += 1;
            matched = true;
        }

        // Immediate ALU ops (10-bit opcode)
        if !matched {
            let imm_match = matches!(
                top10,
                0x008 | // SLTI
                0x009 | // SLTUI
                0x00A | // ADDI.W
                0x00B | // ADDI.D
                0x00C | // LU52I.D
                0x00D | // ANDI
                0x00E | // ORI
                0x00F // XORI
            );
            if imm_match {
                score += 4;
                valid_count += 1;
                matched = true;
            }
        }

        // BSTRINS.D / BSTRPICK.D (bit-field operations)
        if !matched && matches!(top10, 0x002 | 0x003) {
            score += 4;
            valid_count += 1;
            matched = true;
        }

        // FP fused multiply-add 4R: FMADD, FMSUB, FNMADD, FNMSUB
        if !matched && matches!(top10, 0x020 | 0x021 | 0x022 | 0x023) {
            score += 5;
            valid_count += 1;
            matched = true;
        }

        // FP comparison: FCMP.cond.S/D
        if !matched && top10 == 0x030 {
            score += 5;
            valid_count += 1;
            matched = true;
        }

        // Load/Store (10-bit opcode)
        if !matched && (is_load(word) || is_store(word)) {
            score += 4;
            valid_count += 1;
            matched = true;
        }

        // FP Load/Store
        if !matched {
            let fp_match = matches!(
                top10,
                0x0AC | // FLD.S (0x2B000000 >> 22)
                0x0AD | // FST.S
                0x0AE | // FLD.D
                0x0AF // FST.D
            );
            if fp_match {
                score += 4;
                valid_count += 1;
                matched = true;
            }
        }

        // Vector load/store
        if !matched && (is_lsx(word) || is_lasx(word)) {
            score += 5;
            valid_count += 1;
            matched = true;
        }

        // LSX/LASX vector compute (beyond VLD/VST): top6 = 0x1C-0x1F
        if !matched && matches!(top6, 0x1C | 0x1D | 0x1E | 0x1F) {
            score += 4;
            valid_count += 1;
            matched = true;
        }

        // Branches (6-bit opcode in top 6 bits)
        if !matched {
            if is_call(word) {
                score += 8;
                call_count += 1;
                valid_count += 1;
                matched = true;
            } else if is_return(word) {
                score += 10;
                ret_count += 1;
                valid_count += 1;
                matched = true;
            } else if is_branch(word) {
                // Conditional branches
                score += 4;
                branch_count += 1;
                valid_count += 1;
                matched = true;
            }
        }

        // Unrecognized instruction - small penalty
        if !matched {
            score -= 1;
        }

        prev_word = word;
        i += 4;
    }

    // Structural bonus: real code has returns and calls/branches
    if ret_count > 0 && (call_count > 0 || branch_count > 0) {
        score += 15;
    }

    // Structural requirement: if we processed many words but found no
    // distinctive LoongArch patterns, reduce score.
    // LoongArch ALU/load/store opcodes cover a significant portion of the
    // instruction space, so random data can accumulate positive scores.
    let total_words = data.len() / 4;
    if total_words > 20 {
        let distinctive = ret_count + call_count + prologue_count;
        if valid_count == 0 {
            score = (score as f64 * 0.08) as i64;
        } else if distinctive == 0 {
            // No returns or calls at all — not code
            score = (score as f64 * 0.20) as i64;
        } else if ret_count == 0 && branch_count < 2 {
            // Calls but no returns and barely any branches
            score = (score as f64 * 0.40) as i64;
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
