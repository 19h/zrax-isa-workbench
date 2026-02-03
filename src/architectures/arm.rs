//! ARM32 architecture analysis.

/// ARM condition codes.
pub mod condition {
    pub const EQ: u8 = 0x0; // Equal
    pub const NE: u8 = 0x1; // Not equal
    pub const CS: u8 = 0x2; // Carry set / unsigned higher or same
    pub const CC: u8 = 0x3; // Carry clear / unsigned lower
    pub const MI: u8 = 0x4; // Negative
    pub const PL: u8 = 0x5; // Positive or zero
    pub const VS: u8 = 0x6; // Overflow
    pub const VC: u8 = 0x7; // No overflow
    pub const HI: u8 = 0x8; // Unsigned higher
    pub const LS: u8 = 0x9; // Unsigned lower or same
    pub const GE: u8 = 0xA; // Signed greater or equal
    pub const LT: u8 = 0xB; // Signed less than
    pub const GT: u8 = 0xC; // Signed greater than
    pub const LE: u8 = 0xD; // Signed less or equal
    pub const AL: u8 = 0xE; // Always
    pub const NV: u8 = 0xF; // Never / unconditional
}

/// ARM instruction patterns.
pub mod patterns {
    pub const NOP: u32 = 0xE1A00000; // MOV R0, R0
    pub const NOP_HINT: u32 = 0xE320F000; // NOP (hint)
    pub const BX_LR: u32 = 0xE12FFF1E; // BX LR (return)
    pub const SVC_BASE: u32 = 0xEF000000; // SVC #0
    pub const BKPT_BASE: u32 = 0xE1200070; // BKPT
}

/// Extract condition code from ARM32 instruction.
pub fn get_condition(instr: u32) -> u8 {
    ((instr >> 28) & 0xF) as u8
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let cond = get_condition(instr);
    if cond == 0xF {
        // Unconditional instructions
        return (instr & 0x0E000000) == 0x0A000000;
    }

    let op = (instr >> 24) & 0xF;
    op == 0xA || op == 0xB
}

/// Check if instruction is BL (branch with link).
pub fn is_bl(instr: u32) -> bool {
    let cond = get_condition(instr);
    if cond > 0xE {
        return false;
    }

    (instr & 0x0F000000) == 0x0B000000
}

/// Check if this is a PUSH instruction.
pub fn is_push(instr: u32) -> bool {
    (instr & 0xFFFF0000) == 0xE92D0000
}

/// Check if this is a POP instruction.
pub fn is_pop(instr: u32) -> bool {
    (instr & 0xFFFF0000) == 0xE8BD0000
}

/// Thumb-2 instruction length detection.
pub fn thumb_instruction_length(first_halfword: u16) -> usize {
    let top5 = (first_halfword >> 11) & 0x1F;
    if top5 == 0x1D || top5 == 0x1E || top5 == 0x1F {
        4 // 32-bit Thumb-2 instruction
    } else {
        2 // 16-bit Thumb instruction
    }
}

/// Score likelihood of ARM32 code (ARM mode only).
///
/// Analyzes raw bytes for patterns characteristic of ARM32:
/// - Condition codes in bits [31:28]
/// - Common instructions (NOP, BX LR, PUSH, POP)
/// - Data processing patterns
fn score_arm32(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_zeros = 0u32;

    // ARM32 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Track consecutive zero words
        if word == 0x00000000 {
            consecutive_zeros += 1;
            if consecutive_zeros > 2 {
                score -= 5; // Penalize long zero runs
            }
            continue;
        }
        consecutive_zeros = 0;

        // Check condition code
        let cond = get_condition(word);

        // AL (always) condition is most common
        if cond == condition::AL {
            score += 3;
        } else if cond <= condition::LE {
            // Valid condition codes
            score += 1;
        } else if cond == condition::NV {
            // Unconditional - less common but valid
            score += 1;
        }

        // NOP (MOV R0, R0)
        if word == patterns::NOP {
            score += 20;
        }

        // NOP.W (ARMv6K+)
        if word == patterns::NOP_HINT {
            score += 20;
        }

        // BX LR (return)
        if word == patterns::BX_LR {
            score += 25;
        }

        // PUSH
        if is_push(word) {
            score += 15;
        }

        // POP
        if is_pop(word) {
            score += 15;
        }

        // BL (branch with link)
        if is_bl(word) {
            score += 8;
        }

        // LDR/STR
        if (word & 0x0E000000) == 0x04000000 && cond <= condition::AL {
            score += 3;
        }

        // Data processing (AND, EOR, SUB, ADD, etc.)
        if (word & 0x0C000000) == 0x00000000 && cond <= condition::AL {
            score += 2;
        }

        // SVC/SWI (system call)
        if (word & 0x0F000000) == 0x0F000000 && cond == condition::AL {
            score += 15;
        }

        // All ones is invalid
        if word == 0xFFFFFFFF {
            score -= 10;
        }
    }

    score.max(0)
}

/// Score likelihood of Thumb/Thumb-2 code.
///
/// Analyzes raw bytes for patterns characteristic of Thumb/Thumb-2:
/// - 16-bit Thumb instructions (PUSH, POP, BX LR, MOV, ADD, etc.)
/// - 32-bit Thumb-2 instructions (BL, LDR.W, STR.W, etc.)
fn score_thumb(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_zeros = 0u32;
    let mut last_hw: u16 = 0;
    let mut repeat_count = 0u32;
    let mut i = 0;

    while i + 1 < data.len() {
        let hw = u16::from_le_bytes([data[i], data[i + 1]]);

        // Track consecutive zero halfwords
        if hw == 0x0000 {
            consecutive_zeros += 1;
            if consecutive_zeros > 4 {
                score -= 3; // Penalize long zero runs
            }
            i += 2;
            last_hw = hw;
            continue;
        }
        consecutive_zeros = 0;

        // Track repeated halfwords (padding detection)
        if hw == last_hw {
            repeat_count += 1;
            if repeat_count > 8 {
                // Long runs of identical values are likely padding, not code
                score -= 2;
                i += 2;
                continue;
            }
        } else {
            repeat_count = 0;
        }
        last_hw = hw;

        // Common padding patterns - penalize
        if hw == 0x5A5A || hw == 0xDEAD || hw == 0xBEEF || hw == 0xCAFE || hw == 0xFEED {
            score -= 5;
            i += 2;
            continue;
        }

        // Check if this is a 32-bit Thumb-2 instruction
        let top5 = (hw >> 11) & 0x1F;
        let is_thumb2 = matches!(top5, 0x1D | 0x1E | 0x1F);

        if is_thumb2 && i + 3 < data.len() {
            // 32-bit Thumb-2 instruction
            let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            let word = ((hw as u32) << 16) | (hw2 as u32);

            // BL/BLX - Branch with Link (very common in Thumb-2)
            // Encoding: 11110Sxxxxxxxxxx 11J1Jxxxxxxxxxxx
            if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000 {
                score += 25; // BL is a strong indicator
            }
            // B.W - Unconditional branch (32-bit)
            else if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000 {
                score += 15;
            }
            // LDR.W / STR.W (32-bit load/store)
            else if (hw & 0xFFF0) == 0xF8D0 || (hw & 0xFFF0) == 0xF8C0 {
                score += 12; // LDR.W Rt, [Rn, #imm12] / STR.W
            }
            // LDR.W / STR.W with register offset
            else if (hw & 0xFFF0) == 0xF850 || (hw & 0xFFF0) == 0xF840 {
                score += 12;
            }
            // PUSH.W / POP.W (multiple registers)
            else if (word & 0xFFFFE000) == 0xE92D0000 {
                score += 30; // PUSH.W {reglist}
            } else if (word & 0xFFFFE000) == 0xE8BD0000 {
                score += 30; // POP.W {reglist}
            }
            // MOV.W / MOVT
            else if (hw & 0xFBF0) == 0xF240 || (hw & 0xFBF0) == 0xF2C0 {
                score += 10; // MOVW / MOVT
            }
            // ADD.W / SUB.W with immediate
            else if (hw & 0xFBE0) == 0xF100 || (hw & 0xFBE0) == 0xF1A0 {
                score += 8;
            }
            // CMP.W
            else if (hw & 0xFBF0) == 0xF1B0 {
                score += 8;
            }
            // TST.W / TEQ.W
            else if (hw & 0xFBF0) == 0xF010 || (hw & 0xFBF0) == 0xF090 {
                score += 6;
            }
            // MRS / MSR (system register access - common in firmware)
            else if (word & 0xFFE0F0FF) == 0xF3EF8000 {
                score += 35; // MRS Rd, spec_reg
            } else if (word & 0xFFF0F0FF) == 0xF3808800 {
                score += 35; // MSR spec_reg, Rn
            }
            // DMB / DSB / ISB (memory barriers)
            else if (word & 0xFFFFFFF0) == 0xF3BF8F50 {
                score += 25; // DMB
            } else if (word & 0xFFFFFFF0) == 0xF3BF8F40 {
                score += 25; // DSB
            } else if word == 0xF3BF8F6F {
                score += 25; // ISB
            }
            // CPSIE / CPSID (interrupt control)
            else if (word & 0xFFFFFF00) == 0xF3AF8600 || (word & 0xFFFFFF00) == 0xF3AF8700 {
                score += 30; // CPSIE/CPSID - very firmware specific
            }
            // IT block handling (If-Then)
            else if (hw & 0xFF00) == 0xBF00 && (hw & 0x00FF) != 0x00 {
                score += 15; // IT instruction
            }
            // Generic valid 32-bit Thumb-2 instruction prefix
            else {
                score += 5;
            }

            i += 4;
        } else {
            // 16-bit Thumb instruction

            // BX LR - Return from function (very common)
            if hw == 0x4770 {
                score += 30;
            }
            // BX Rn (other register)
            else if (hw & 0xFF87) == 0x4700 {
                score += 15;
            }
            // PUSH {reglist} with LR
            else if (hw & 0xFE00) == 0xB400 {
                let has_lr = (hw & 0x0100) != 0;
                score += if has_lr { 25 } else { 15 }; // PUSH with LR is function prologue
            }
            // POP {reglist} with PC
            else if (hw & 0xFE00) == 0xBC00 {
                let has_pc = (hw & 0x0100) != 0;
                score += if has_pc { 25 } else { 15 }; // POP with PC is function return
            }
            // NOP.N
            else if hw == 0xBF00 {
                score += 8;
            }
            // MOV Rd, Rn (low registers)
            else if (hw & 0xFFC0) == 0x0000 && hw != 0x0000 {
                // Actually LSL Rd, Rm, #0 = MOV
                score += 5;
            }
            // MOV Rd, Rn (high registers)
            else if (hw & 0xFF00) == 0x4600 {
                score += 8;
            }
            // ADD/SUB with immediate (common)
            else if (hw & 0xF800) == 0x3000 || (hw & 0xF800) == 0x3800 {
                score += 6; // ADD Rn, #imm8 / SUB Rn, #imm8
            }
            // ADD/SUB (register)
            else if (hw & 0xFE00) == 0x1800 || (hw & 0xFE00) == 0x1A00 {
                score += 5;
            }
            // CMP with immediate
            else if (hw & 0xF800) == 0x2800 {
                score += 6;
            }
            // CMP (register, low)
            else if (hw & 0xFFC0) == 0x4280 {
                score += 5;
            }
            // CMP (register, high)
            else if (hw & 0xFF00) == 0x4500 {
                score += 5;
            }
            // LDR Rt, [PC, #imm] (literal pool)
            else if (hw & 0xF800) == 0x4800 {
                score += 10; // Very common pattern
            }
            // LDR/STR with register offset
            else if (hw & 0xF000) == 0x5000 {
                score += 6;
            }
            // LDR/STR with immediate offset
            else if (hw & 0xE000) == 0x6000 {
                score += 6;
            }
            // LDRB/STRB with immediate offset
            else if (hw & 0xF000) == 0x7000 {
                score += 5;
            }
            // LDRH/STRH with immediate offset
            else if (hw & 0xF000) == 0x8000 {
                score += 5;
            }
            // LDR/STR (SP-relative)
            else if (hw & 0xF000) == 0x9000 {
                score += 7;
            }
            // ADD Rd, PC/SP, #imm
            else if (hw & 0xF000) == 0xA000 {
                score += 7;
            }
            // Conditional branch B<cond>
            else if (hw & 0xF000) == 0xD000 && (hw & 0x0F00) != 0x0E00 && (hw & 0x0F00) != 0x0F00
            {
                score += 8;
            }
            // Unconditional branch B
            else if (hw & 0xF800) == 0xE000 {
                score += 6;
            }
            // CBZ / CBNZ (Thumb-2)
            else if (hw & 0xF500) == 0xB100 || (hw & 0xF500) == 0xB900 {
                score += 12; // Compare and Branch - Thumb-2 specific
            }
            // SVC (Supervisor Call)
            else if (hw & 0xFF00) == 0xDF00 {
                score += 15;
            }
            // BKPT (Breakpoint)
            else if (hw & 0xFF00) == 0xBE00 {
                score += 10;
            }
            // ADR (load address)
            else if (hw & 0xF800) == 0xA000 {
                score += 6;
            }
            // Logical ops (AND, EOR, LSL, LSR, ASR, ADC, SBC, ROR, TST, RSB, etc.)
            else if (hw & 0xFC00) == 0x4000 {
                score += 4;
            }
            // SXTH, SXTB, UXTH, UXTB
            else if (hw & 0xFF00) == 0xB200 {
                score += 6;
            }
            // REV, REV16, REVSH
            else if (hw & 0xFFC0) == 0xBA00 || (hw & 0xFFC0) == 0xBA40 || (hw & 0xFFC0) == 0xBAC0
            {
                score += 6;
            }
            // UDF (Undefined) - often used as assertions
            else if (hw & 0xFF00) == 0xDE00 {
                score += 3;
            }
            // All ones is padding/invalid
            else if hw == 0xFFFF {
                score -= 3;
            }

            i += 2;
        }
    }

    score.max(0)
}

/// Detect Cortex-M vector table pattern.
/// Vector tables have addresses with odd LSB (Thumb mode indicator) pointing within firmware.
fn score_cortex_m_vector_table(data: &[u8]) -> i64 {
    if data.len() < 64 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut valid_vectors = 0u32;

    // Check first 16 vectors (64 bytes)
    for i in (0..64).step_by(4) {
        let addr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Skip first entry (Initial SP) - should be even, in RAM range
        if i == 0 {
            // SP typically in 0x20000000-0x20FFFFFF (SRAM) range
            if (addr & 0xF0000000) == 0x20000000 || (addr & 0xFFF00000) == 0x10000000 {
                score += 20;
            }
            continue;
        }

        // Other entries are code addresses with Thumb bit set (odd)
        if addr == 0 {
            continue; // Reserved/unused vector
        }

        // Must be odd (Thumb mode)
        if (addr & 1) == 1 {
            // Must be in reasonable code range (typically 0x00000000-0x20000000 for flash)
            let code_addr = addr & !1;
            if code_addr < 0x20000000 && code_addr >= 0x100 {
                valid_vectors += 1;
            }
        }
    }

    if valid_vectors >= 8 {
        score += 100; // Strong indicator of Cortex-M binary
    } else if valid_vectors >= 4 {
        score += 50;
    }

    score
}

/// Score likelihood of ARM32 code (ARM mode or Thumb mode).
///
/// This scores both ARM32 and Thumb modes and returns the higher score.
pub fn score(data: &[u8]) -> i64 {
    let arm32_score = score_arm32(data);
    let thumb_score = score_thumb(data);
    let vector_table_score = score_cortex_m_vector_table(data);

    // Take the best score, with vector table as a bonus
    let base_score = arm32_score.max(thumb_score);

    // If we detected a vector table, add that bonus but cap it
    let final_score = base_score + vector_table_score.min(base_score / 2);

    final_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_extraction() {
        assert_eq!(get_condition(0xE1A00000), condition::AL);
        assert_eq!(get_condition(0x01A00000), condition::EQ);
    }

    #[test]
    fn test_branch_detection() {
        assert!(is_bl(0xEB000000));
        assert!(!is_bl(0xEA000000));
    }

    #[test]
    fn test_thumb_length() {
        assert_eq!(thumb_instruction_length(0xBF00), 2); // NOP.N
        assert_eq!(thumb_instruction_length(0xF3AF), 4); // NOP.W prefix
    }

    #[test]
    fn test_score() {
        // ARM NOP
        let nop = 0xE1A00000u32.to_le_bytes();
        assert!(score(&nop) > 0);
        // BX LR (return)
        let ret = 0xE12FFF1Eu32.to_le_bytes();
        assert!(score(&ret) > 0);
    }
}
